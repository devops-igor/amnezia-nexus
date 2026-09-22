package loadbalancer

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// StickyStore is the DB surface HandleFailover needs. It exists so the
// failover path can be tested with wrapped/failing DB handles without
// changing the concrete database.DB type anywhere else.
type StickyStore interface {
	GetActiveVPNSessions(ctx context.Context) ([]models.VPNSession, error)
	CreateVPNSession(ctx context.Context, s *models.VPNSession) error
}

type affinityRecord struct {
	tunnelID int64
	lastSeen time.Time
}

// DefaultAffinityTTL is the fallback duration for sticky session affinity.
const DefaultAffinityTTL = 30 * time.Minute

// StickySessionManager manages session affinity and handles automatic failover.
type StickySessionManager struct {
	mu           sync.RWMutex
	db           StickyStore
	baseBalancer LoadBalancer
	caps         CapacityConfig
	affinityTTL  time.Duration
	nowFunc      func() time.Time
	userAffinity map[string]affinityRecord // userID -> affinityRecord
	peerAffinity map[string]affinityRecord // peerPublicKey -> affinityRecord

	// skipCounter counts peers whose migration was skipped during failover
	// (backend selection failed for them). Issue #85: skips must never be
	// silent - this counter plus the SkippedPeers result field make stranding
	// observable so callers can retry or alert.
	skipCounter atomic.Int64
}

// NewStickySessionManager creates a new StickySessionManager wrapping a base load balancer.
func NewStickySessionManager(db StickyStore, baseBalancer LoadBalancer, caps CapacityConfig) *StickySessionManager {
	ttl := caps.AffinityTTL
	if ttl <= 0 {
		ttl = DefaultAffinityTTL
	}
	return &StickySessionManager{
		db:           db,
		baseBalancer: baseBalancer,
		caps:         caps,
		affinityTTL:  ttl,
		userAffinity: make(map[string]affinityRecord),
		peerAffinity: make(map[string]affinityRecord),
	}
}

// SetNowFunc overrides the time source used for TTL calculations (used in tests).
func (sm *StickySessionManager) SetNowFunc(fn func() time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.nowFunc = fn
}

// now returns the current time, using nowFunc if set.
// Note: caller should hold sm.mu (Lock or RLock).
func (sm *StickySessionManager) now() time.Time {
	if sm.nowFunc != nil {
		return sm.nowFunc()
	}
	return time.Now().UTC()
}

// SkippedMigrationsTotal returns how many peer migrations have been skipped
// across all failovers (issue #85: no silent stranding - every skip is
// counted here, logged at skip time, and reported per-failover in the result).
func (sm *StickySessionManager) SkippedMigrationsTotal() int64 {
	return sm.skipCounter.Load()
}

// GetOrAssignBackend retrieves the sticky backend for a request or assigns an optimal healthy backend.
func (sm *StickySessionManager) GetOrAssignBackend(ctx context.Context, req *RoutingRequest) (*models.BackendTunnel, bool, error) {
	if req == nil {
		return nil, false, fmt.Errorf("routing request is nil")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := sm.now()

	// Check existing affinity by peerPublicKey first, then by userID
	var targetTunnelID int64
	var hasAffinity bool

	if req.PeerPublicKey != "" {
		if rec, ok := sm.peerAffinity[req.PeerPublicKey]; ok {
			if now.Sub(rec.lastSeen) > sm.affinityTTL {
				delete(sm.peerAffinity, req.PeerPublicKey)
			} else {
				targetTunnelID = rec.tunnelID
				hasAffinity = true
			}
		}
	}
	if !hasAffinity && req.UserID != "" {
		if rec, ok := sm.userAffinity[req.UserID]; ok {
			if now.Sub(rec.lastSeen) > sm.affinityTTL {
				delete(sm.userAffinity, req.UserID)
			} else {
				targetTunnelID = rec.tunnelID
				hasAffinity = true
			}
		}
	}

	// Verify if the sticky backend is still active and within capacity
	if hasAffinity {
		for _, t := range req.AvailableTunnels {
			if t.ID == targetTunnelID && strings.EqualFold(t.Status, "active") {
				if sm.caps.MaxPeersPerBackend <= 0 || t.ActiveConnections < sm.caps.MaxPeersPerBackend {
					// Sticky affinity preserved: refresh lastSeen
					rec := affinityRecord{tunnelID: targetTunnelID, lastSeen: now}
					if req.PeerPublicKey != "" {
						sm.peerAffinity[req.PeerPublicKey] = rec
					}
					if req.UserID != "" {
						sm.userAffinity[req.UserID] = rec
					}
					return t, false, nil
				}
			}
		}
	}

	// Affinity missed or assigned backend degraded -> select new backend
	selected, err := sm.baseBalancer.SelectBackend(ctx, req)
	if err != nil {
		return nil, false, err
	}

	rec := affinityRecord{tunnelID: selected.ID, lastSeen: now}
	if req.UserID != "" {
		sm.userAffinity[req.UserID] = rec
	}
	if req.PeerPublicKey != "" {
		sm.peerAffinity[req.PeerPublicKey] = rec
	}

	return selected, true, nil
}

// AssignAffinity records an explicit affinity for a user.
func (sm *StickySessionManager) AssignAffinity(userID string, tunnelID int64) {
	if userID == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.userAffinity[userID] = affinityRecord{tunnelID: tunnelID, lastSeen: sm.now()}
}

// AssignPeerAffinity records an explicit affinity for a peer public key.
func (sm *StickySessionManager) AssignPeerAffinity(peerKey string, tunnelID int64) {
	if peerKey == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.peerAffinity[peerKey] = affinityRecord{tunnelID: tunnelID, lastSeen: sm.now()}
}

// ClearAffinity removes sticky affinity for a user.
func (sm *StickySessionManager) ClearAffinity(userID string) {
	if userID == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.userAffinity, userID)
}

// ClearPeerAffinity removes sticky affinity for a peer public key.
func (sm *StickySessionManager) ClearPeerAffinity(peerKey string) {
	if peerKey == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.peerAffinity, peerKey)
}

// GetAffinity returns the assigned backend tunnel ID for a user.
func (sm *StickySessionManager) GetAffinity(userID string) (int64, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	rec, ok := sm.userAffinity[userID]
	if !ok {
		return 0, false
	}
	if sm.now().Sub(rec.lastSeen) > sm.affinityTTL {
		return 0, false
	}
	return rec.tunnelID, true
}

// GetPeerAffinity returns the assigned backend tunnel ID for a peer public key.
func (sm *StickySessionManager) GetPeerAffinity(peerKey string) (int64, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	rec, ok := sm.peerAffinity[peerKey]
	if !ok {
		return 0, false
	}
	if sm.now().Sub(rec.lastSeen) > sm.affinityTTL {
		return 0, false
	}
	return rec.tunnelID, true
}

// FailoverMigration describes one session migrated off a degraded tunnel.
type FailoverMigration struct {
	PeerPublicKey      string
	UserID             string
	NewBackendTunnelID int64
}

// FailoverSkippedPeer describes a peer that could NOT be migrated off the
// degraded backend during failover (issue #85). Skips are never silent: each
// one is logged, counted in SkippedMigrationsTotal, and reported here so the
// caller can retry or alert. The session remains routed to the disabled
// backend - that is exactly the state this reporting makes explicit.
type FailoverSkippedPeer struct {
	PeerPublicKey string
	UserID        string
	Reason        string
}

// FailoverResult is the outcome of one HandleFailover run.
type FailoverResult struct {
	// Migrations lists the sessions successfully moved off the degraded
	// backend, sorted by peer public key (stable contract preserved).
	Migrations []FailoverMigration
	// Skipped lists the peers left behind, each with the reason. Empty list
	// means every degraded-backend peer was migrated.
	Skipped []FailoverSkippedPeer
}

// stickyPeerTarget pairs an in-memory peer affinity snapshot entry with the
// user ID the failover should attribute the migration to.
type stickyPeerTarget struct {
	peerKey string
	userID  string
}

// HandleFailover migrates all sessions assigned to degradedTunnelID to healthy available backends.
//
// Structure (issue #85): SNAPSHOT in-memory state under sm.mu, RELEASE the
// mutex, then do all DB I/O and backend selection against the snapshot, then
// APPLY the computed new affinities under a short re-lock with a re-check.
// GetAffinity readers are never blocked behind failover DB latency, and no
// DB call runs while sm.mu is held.
//
// Concurrency contract: the primary caller (Service.disableBackendLocked)
// holds Service.mu, serializing failovers against each other; concurrent
// peers may re-assign their own affinity between snapshot and apply. The
// apply phase therefore only overwrites entries whose value is still the
// degraded backend - a peer that moved on in the meantime keeps its newer
// assignment.
//
// No silent stranding: peers whose backend selection fails are logged,
// counted, and returned in Result.Skipped; DB persist failures are retried
// once, then the in-memory migration is marked un-persisted in the result -
// the reconcilable state stays explicit.
func (sm *StickySessionManager) HandleFailover(ctx context.Context, degradedTunnelID int64, availableTunnels []*models.BackendTunnel) (*FailoverResult, error) {
	sm.mu.RLock()
	healthy := FilterHealthy(availableTunnels, sm.caps.MaxPeersPerBackend)
	if len(healthy) == 0 {
		sm.mu.RUnlock()
		return nil, ErrNoActiveBackends
	}

	// --- SNAPSHOT: minimal in-memory state, no DB I/O under sm.mu. ---
	degradedUsers := make([]string, 0)
	for uID, rec := range sm.userAffinity {
		if rec.tunnelID == degradedTunnelID {
			degradedUsers = append(degradedUsers, uID)
		}
	}
	sort.Strings(degradedUsers)

	degradedPeers := make([]stickyPeerTarget, 0)
	for pKey, rec := range sm.peerAffinity {
		if rec.tunnelID == degradedTunnelID {
			degradedPeers = append(degradedPeers, stickyPeerTarget{peerKey: pKey})
		}
	}
	// Stable ordering: failover output must be deterministic run to run
	// (redirected forwarder routes, connection-count moves).
	sort.Slice(degradedPeers, func(i, j int) bool {
		return degradedPeers[i].peerKey < degradedPeers[j].peerKey
	})
	sm.mu.RUnlock()

	result := &FailoverResult{}

	// --- COMPUTE: DB reads + backend selection, mutex NOT held. ---

	// Resolve user IDs for degraded peers from the DB session rows (also
	// yields the full set of connected sessions stuck on the degraded
	// backend, including peers with no in-memory affinity).
	var activeSessions []models.VPNSession
	if sm.db != nil {
		sessions, err := sm.db.GetActiveVPNSessions(ctx)
		if err != nil {
			// DB read failure is not fatal for the in-memory migration, but
			// it IS observable: log it and continue with the snapshot-only
			// peers. The DB-session loop below is skipped.
			log.Printf("[vpn] sticky failover: DB session lookup failed, migrating in-memory affinities only: %v", err)
		} else {
			activeSessions = sessions
			sessionByPeer := make(map[string]string, len(sessions))
			for i := range sessions {
				sessionByPeer[sessions[i].PeerPublicKey] = sessions[i].UserID
			}
			for i := range degradedPeers {
				degradedPeers[i].userID = sessionByPeer[degradedPeers[i].peerKey]
			}
		}
	}

	// Compute one target backend per degraded peer via the base balancer.
	// A selection failure for ONE peer must not strand the others: the
	// failing peer is skipped (logged, counted, reported) and the loop
	// continues.
	moves := make([]peerMove, 0, len(degradedPeers))
	skippedSeen := make(map[string]bool)
	for _, dp := range degradedPeers {
		req := &RoutingRequest{
			UserID:           dp.userID,
			PeerPublicKey:    dp.peerKey,
			AvailableTunnels: healthy,
		}
		newBackend, err := sm.baseBalancer.SelectBackend(ctx, req)
		if err != nil {
			sm.skipCounter.Add(1)
			skippedSeen[dp.peerKey] = true
			log.Printf("[vpn] sticky failover: peer %s left on degraded backend %d: backend selection failed: %v", dp.peerKey, degradedTunnelID, err)
			result.Skipped = append(result.Skipped, FailoverSkippedPeer{
				PeerPublicKey: dp.peerKey,
				UserID:        dp.userID,
				Reason:        fmt.Sprintf("backend selection failed: %v", err),
			})
			continue
		}
		moves = append(moves, peerMove{peerKey: dp.peerKey, userID: dp.userID, newID: newBackend.ID})
	}

	// DB rows for EVERY connected session on the degraded backend must be
	// updated: peers with a computed in-memory move reuse that target; peers
	// without one get a fresh selection here (mutex still not held).
	dbMoves := sm.planDBSessionMoves(ctx, degradedTunnelID, activeSessions, moves, skippedSeen, healthy, result)

	// --- APPLY: short re-lock, re-check, apply. ---
	sm.mu.Lock()
	now := sm.now()
	for _, uID := range degradedUsers {
		if sm.userAffinity[uID].tunnelID == degradedTunnelID {
			delete(sm.userAffinity, uID)
		}
	}
	for _, mv := range moves {
		// Re-check: only overwrite if the peer is still on the degraded
		// backend (it may have re-assigned between snapshot and apply).
		current, exists := sm.peerAffinity[mv.peerKey]
		if !exists || current.tunnelID == degradedTunnelID || current.tunnelID == 0 {
			sm.peerAffinity[mv.peerKey] = affinityRecord{
				tunnelID: mv.newID,
				lastSeen: now,
			}
		}
		result.Migrations = append(result.Migrations, FailoverMigration{
			PeerPublicKey:      mv.peerKey,
			UserID:             mv.userID,
			NewBackendTunnelID: mv.newID,
		})
	}
	sm.mu.Unlock()

	// --- PERSIST: DB session updates, mutex NOT held. Persist errors are
	// retried once, then surfaced: the in-memory migration already happened,
	// so the result must mark the row as un-persisted (reconcilable) rather
	// than silently dropping the write (issue #85: `_ = CreateVPNSession`). ---
	persistFailures := make(map[string]bool)
	for _, dm := range dbMoves {
		sess := dm.sess
		sess.BackendTunnelID = dm.newID
		if err := sm.persistSession(ctx, &sess); err != nil {
			sm.skipCounter.Add(1)
			persistFailures[sess.PeerPublicKey] = true
			log.Printf("[vpn] sticky failover: session %s (peer %s) migrated in memory to backend %d but DB row NOT updated after retry: %v (un-persisted, reconcilable)", sess.ID, sess.PeerPublicKey, dm.newID, err)
			result.Skipped = append(result.Skipped, FailoverSkippedPeer{
				PeerPublicKey: sess.PeerPublicKey,
				UserID:        sess.UserID,
				Reason:        fmt.Sprintf("DB persist failed after retry: %v", err),
			})
		}
	}
	// Migration records: one per peer, from the affinity pass; DB-session-only
	// peers get their record here. A peer whose persist failed still HAS its
	// in-memory migration, but the DB/memory divergence is reported via
	// Skipped above (never silently dropped).
	migratedPeers := make(map[string]bool, len(result.Migrations))
	for _, m := range result.Migrations {
		migratedPeers[m.PeerPublicKey] = true
	}
	for _, dm := range dbMoves {
		if persistFailures[dm.sess.PeerPublicKey] || migratedPeers[dm.sess.PeerPublicKey] {
			continue
		}
		result.Migrations = append(result.Migrations, FailoverMigration{
			PeerPublicKey:      dm.sess.PeerPublicKey,
			UserID:             dm.sess.UserID,
			NewBackendTunnelID: dm.newID,
		})
	}

	// Stable contract: records are returned sorted by peer public key.
	sort.SliceStable(result.Migrations, func(i, j int) bool {
		return result.Migrations[i].PeerPublicKey < result.Migrations[j].PeerPublicKey
	})

	return result, nil
}

// peerMove pairs one degraded-peer affinity snapshot entry with its selected
// target backend.
type peerMove struct {
	peerKey string
	userID  string
	newID   int64
}

// dbMove pairs one connected DB session on the degraded backend with its
// computed target backend.
type dbMove struct {
	sess  models.VPNSession
	newID int64
}

// planDBSessionMoves computes target backends for every connected DB session
// still on the degraded backend (issue #85). Peers with an in-memory move
// reuse that target; peers without one get a fresh selection. Selection
// failures are logged, counted, and appended to result.Skipped - never
// silently dropped. Runs WITHOUT sm.mu held.
func (sm *StickySessionManager) planDBSessionMoves(ctx context.Context, degradedTunnelID int64, activeSessions []models.VPNSession, moves []peerMove, skippedSeen map[string]bool, healthy []*models.BackendTunnel, result *FailoverResult) []dbMove {
	dbMoves := make([]dbMove, 0)
	if len(activeSessions) == 0 {
		return dbMoves
	}
	moveByPeer := make(map[string]int64, len(moves))
	for _, mv := range moves {
		moveByPeer[mv.peerKey] = mv.newID
	}
	for i := range activeSessions {
		sess := activeSessions[i]
		if sess.BackendTunnelID != degradedTunnelID {
			continue
		}
		if skippedSeen[sess.PeerPublicKey] {
			// Already reported as skipped via the affinity pass.
			continue
		}
		if newID, ok := moveByPeer[sess.PeerPublicKey]; ok {
			dbMoves = append(dbMoves, dbMove{sess: sess, newID: newID})
			continue
		}
		req := &RoutingRequest{
			UserID:           sess.UserID,
			PeerPublicKey:    sess.PeerPublicKey,
			AvailableTunnels: healthy,
		}
		newBackend, err := sm.baseBalancer.SelectBackend(ctx, req)
		if err != nil {
			sm.skipCounter.Add(1)
			skippedSeen[sess.PeerPublicKey] = true
			log.Printf("[vpn] sticky failover: DB session %s (peer %s) left on degraded backend %d: backend selection failed: %v", sess.ID, sess.PeerPublicKey, degradedTunnelID, err)
			result.Skipped = append(result.Skipped, FailoverSkippedPeer{
				PeerPublicKey: sess.PeerPublicKey,
				UserID:        sess.UserID,
				Reason:        fmt.Sprintf("backend selection failed: %v", err),
			})
			continue
		}
		dbMoves = append(dbMoves, dbMove{sess: sess, newID: newBackend.ID})
	}
	return dbMoves
}

// persistSession writes the migrated session row, retrying once on failure
// (issue #85: persist errors surfaced, never silently dropped).
func (sm *StickySessionManager) persistSession(ctx context.Context, sess *models.VPNSession) error {
	if sm.db == nil {
		return nil
	}
	err := sm.db.CreateVPNSession(ctx, sess)
	if err == nil {
		return nil
	}
	// One retry: transient SQLite write contention during failover is
	// plausible; a second failure is surfaced to the caller.
	log.Printf("[vpn] sticky failover: persist of session %s failed, retrying once: %v", sess.ID, err)
	return sm.db.CreateVPNSession(ctx, sess)
}
