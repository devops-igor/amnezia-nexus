package endpoint

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

var (
	ErrSessionNotFound = errors.New("vpn session not found")
)

// ReplacementHook is invoked when CreateSession replaces an existing session
// for the same peer (client rekey/reconnect). old is the removed session; new
// is the replacement, or nil when the replacement itself failed to persist.
// The VPN service registers a hook that migrates the pool connection counter
// off the old backend (issue #78): without it every rekey leaked +1 on the
// old backend's ActiveConnections gauge.
type ReplacementHook func(ctx context.Context, old, new *models.VPNSession)

// SessionMetrics instruments the session-lifecycle paths so counter-leak
// paths are distinguishable in production (issue #78 direction item 2):
// replacements_total counts session replacements, and the paired
// counter-migration / teardown-error counters show whether each replacement
// actually moved the pool gauge or left drift behind.
type SessionMetrics struct {
	ReplacementsTotal                 atomic.Int64
	ReplacementCounterMigrationsTotal atomic.Int64
	ReplacementDBTeardownErrorsTotal  atomic.Int64
	ReplacementsPersistFailedTotal    atomic.Int64
}

// snapshot returns a plain map copy of the counters for stats exposure.
func (m *SessionMetrics) snapshot() map[string]int64 {
	return map[string]int64{
		"replacements_total":                   m.ReplacementsTotal.Load(),
		"replacement_counter_migrations_total": m.ReplacementCounterMigrationsTotal.Load(),
		"replacement_db_teardown_errors_total": m.ReplacementDBTeardownErrorsTotal.Load(),
		"replacements_persist_failed_total":    m.ReplacementsPersistFailedTotal.Load(),
	}
}

// SessionManager tracks active VPN peer sessions in memory and SQLite.
type SessionManager struct {
	mu               sync.RWMutex
	db               *database.DB
	ipam             *IPAM
	sessionsByPeer   map[string]*models.VPNSession // peerPublicKey -> session
	sessionsByID     map[string]*models.VPNSession // sessionID -> session
	activeCount      atomic.Int64
	lifecycleVersion atomic.Uint64
	metrics          SessionMetrics
	replacementHook  ReplacementHook
}

// NewSessionManager initializes a new VPN Session Manager.
func NewSessionManager(db *database.DB, ipam *IPAM) *SessionManager {
	return &SessionManager{
		db:             db,
		ipam:           ipam,
		sessionsByPeer: make(map[string]*models.VPNSession),
		sessionsByID:   make(map[string]*models.VPNSession),
	}
}

// SetReplacementHook registers the session-replacement callback (issue #78).
// Must be called before Start accepts traffic; the hook runs while sm.mu is
// held, so it must only touch the pool counter and DB - never re-enter the
// session manager.
func (sm *SessionManager) SetReplacementHook(fn ReplacementHook) {
	sm.mu.Lock()
	sm.replacementHook = fn
	sm.mu.Unlock()
}

// MetricsSnapshot returns a copy of the session lifecycle counters so the
// leak paths (issue #78) stay distinguishable in production telemetry.
func (sm *SessionManager) MetricsSnapshot() map[string]int64 {
	return sm.metrics.snapshot()
}

// LifecycleVersion returns the monotonically increasing session lifecycle version.
func (sm *SessionManager) LifecycleVersion() uint64 {
	return sm.lifecycleVersion.Load()
}

// BumpLifecycleVersion manually increments and returns the session lifecycle version.
func (sm *SessionManager) BumpLifecycleVersion() uint64 {
	return sm.lifecycleVersion.Add(1)
}

// LockLifecycle acquires an exclusive lock on the session manager to fence
// lifecycle mutations against atomic operations like gauge reconciliation.
func (sm *SessionManager) LockLifecycle() {
	sm.mu.Lock()
}

// UnlockLifecycle releases the exclusive lock on the session manager.
func (sm *SessionManager) UnlockLifecycle() {
	sm.mu.Unlock()
}

// CreateSession allocates a new VPN session and persists it. When a session
// already exists for the same peer (client rekey/reconnect), the old session
// is fully replaced: removed from memory, its DB row closed, and the
// replacement hook fires so the caller can migrate the pool counter and
// redirect live routes (issue #78 - every rekey previously leaked +1 on the
// old backend's ActiveConnections gauge because neither the pool decrement
// nor a teardown for the old ID ever ran).
// connectionName is the user-facing config name resolved by the caller's
// authentication lookup; it is stored on the session (memory + DB row) and
// deliberately carried onto every replacement of the same peer (a rekey
// re-authenticates the same user_connection, so the fresh name is passed in).
func (sm *SessionManager) CreateSession(ctx context.Context, userID, peerPublicKey, assignedIP string, backendTunnelID int64, connectionName string, generation ...uint64) (*models.VPNSession, error) {
	if userID == "" || peerPublicKey == "" || assignedIP == "" {
		return nil, errors.New("missing required session fields")
	}

	var gen uint64
	if len(generation) > 0 {
		gen = generation[0]
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// If session already exists for this peer, close it before creating a new
	// one. The DB row is deleted here (same primitive the clean-disconnect
	// path uses) so no orphan row for a dead session ID survives - a later
	// DisconnectSession(oldID) would otherwise return ErrSessionNotFound and
	// its mirror-decrement would never run.
	var replaced *models.VPNSession
	if oldSess, ok := sm.sessionsByPeer[peerPublicKey]; ok {
		replaced = oldSess
		delete(sm.sessionsByID, oldSess.ID)
		delete(sm.sessionsByPeer, peerPublicKey)
		sm.activeCount.Add(-1)
		sm.lifecycleVersion.Add(1)
		sm.metrics.ReplacementsTotal.Add(1)
		if sm.db != nil {
			// Same teardown primitive as CloseSession: the row must go, or
			// the gauge reconcile (issue #54/#78) would keep counting it.
			if err := sm.db.CloseVPNSession(ctx, oldSess.ID); err != nil {
				sm.metrics.ReplacementDBTeardownErrorsTotal.Add(1)
				log.Printf("[endpoint] warning: session replacement teardown for peer %s: failed to close old DB session %s: %v", peerPublicKey, oldSess.ID, err)
			}
		}
		// NOTE: the old session's IPAM allocation is intentionally NOT
		// released here - the replacement reuses the same peer IP (the
		// caller re-resolved the allocation just before CreateSession), so
		// releasing would drop a still-valid reservation.
	}

	uuidBytes := make([]byte, 16)
	_, _ = rand.Read(uuidBytes)
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	sessionID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuidBytes[0:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:16])

	now := time.Now().UTC()
	sess := &models.VPNSession{
		ID:              sessionID,
		UserID:          userID,
		BackendTunnelID: backendTunnelID,
		PeerPublicKey:   peerPublicKey,
		AssignedIP:      assignedIP,
		ConnectedAt:     now,
		LastSeen:        now,
		RxBytes:         0,
		TxBytes:         0,
		Status:          "connected",
		ConnectionName:  connectionName,
		Generation:      gen,
	}

	if sm.db != nil {
		if err := sm.db.CreateVPNSession(ctx, sess); err != nil {
			if replaced != nil {
				// The replacement is lost; keep the leak observable - the
				// caller's pool counter for the old backend is still holding
				// the previous session's count and the hook below will not
				// run with a usable new session.
				sm.metrics.ReplacementsPersistFailedTotal.Add(1)
				log.Printf("[endpoint] error: session replacement for peer %s: failed to persist replacement session: %v", peerPublicKey, err)
			}
			return nil, fmt.Errorf("failed to persist vpn session: %w", err)
		}
	}

	sm.sessionsByPeer[peerPublicKey] = sess
	sm.sessionsByID[sessionID] = sess
	sm.activeCount.Add(1)
	sm.lifecycleVersion.Add(1)

	// Fire the replacement hook AFTER the new session is fully registered so
	// the caller sees a consistent old→new transition. The hook migrates the
	// pool connection counter (decrement old backend, increment new) and
	// updates forwarder/sticky state; it must not re-enter this manager.
	if replaced != nil && sm.replacementHook != nil {
		sm.metrics.ReplacementCounterMigrationsTotal.Add(1)
		sm.replacementHook(ctx, replaced, sess)
	}

	return sess, nil
}

// GetSession retrieves a session by peer public key.
func (sm *SessionManager) GetSession(peerPublicKey string) (*models.VPNSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessionsByPeer[peerPublicKey]
	return sess, ok
}

// GetSessionByPeer retrieves an active session by peer public key.
func (sm *SessionManager) GetSessionByPeer(ctx context.Context, peerPublicKey string) (*models.VPNSession, error) {
	if sm == nil {
		return nil, errors.New("nil session manager")
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessionsByPeer[peerPublicKey]
	if !ok || sess == nil {
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// GetSessionByID retrieves a session by session ID.
func (sm *SessionManager) GetSessionByID(sessionID string) (*models.VPNSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessionsByID[sessionID]
	return sess, ok
}

// GetSessionSnapshotByID retrieves a copy of the session for a session ID.
// Unlike GetSessionByID (which exposes the live *VPNSession pointer and is
// racy for readers that inspect the struct after unlock), the returned
// value is copied under sm.mu.RLock, mirroring ListActiveSessions' convention.
// Use this for any code that reads session fields outside the manager's lock.
func (sm *SessionManager) GetSessionSnapshotByID(sessionID string) (models.VPNSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessionsByID[sessionID]
	if !ok {
		return models.VPNSession{}, false
	}
	return *sess, true
}

// GetSessionsByUserID retrieves all active sessions belonging to a user ID.
func (sm *SessionManager) GetSessionsByUserID(userID string) []*models.VPNSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []*models.VPNSession
	for _, sess := range sm.sessionsByID {
		if sess.UserID == userID && sess.Status == "connected" {
			result = append(result, sess)
		}
	}
	return result
}

// UpdateActivity updates traffic counters and last seen timestamp for a session in memory.
func (sm *SessionManager) UpdateActivity(peerPublicKey string, rxBytes, txBytes int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sess, ok := sm.sessionsByPeer[peerPublicKey]; ok {
		sess.RxBytes += rxBytes
		sess.TxBytes += txBytes
		sess.LastSeen = time.Now().UTC()
	}
}

// TouchSession refreshes the last seen timestamp of a session.
func (sm *SessionManager) TouchSession(peerPublicKey string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sess, ok := sm.sessionsByPeer[peerPublicKey]; ok {
		sess.LastSeen = time.Now().UTC()
	}
}

// SetSessionLastSeen sets the last seen timestamp of a session.
func (sm *SessionManager) SetSessionLastSeen(peerPublicKey string, t time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sess, ok := sm.sessionsByPeer[peerPublicKey]; ok {
		sess.LastSeen = t
	}
}

// CloseSession ends a session. Its persisted client address stays reserved
// until the client connection is removed, including across idle disconnects.
func (sm *SessionManager) CloseSession(ctx context.Context, sessionID string, status string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessionsByID[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	if status == "" {
		status = "disconnected"
	}

	sess.Status = status
	sess.LastSeen = time.Now().UTC()

	if sm.db != nil {
		_ = sm.db.CloseVPNSession(ctx, sess.ID)
	}
	sm.releaseUnpersistedLease(ctx, sess.PeerPublicKey)

	delete(sm.sessionsByID, sessionID)
	delete(sm.sessionsByPeer, sess.PeerPublicKey)
	sm.activeCount.Add(-1)
	sm.lifecycleVersion.Add(1)

	return nil
}

// UpdateSessionBackend safely updates a session's backend tunnel ID and status in memory (issue #289).
// It returns the previous backend tunnel ID, peer public key, and previous status.
func (sm *SessionManager) UpdateSessionBackend(sessionID string, newBackendTunnelID int64, newStatus string) (oldBackendID int64, peerKey string, oldStatus string, err error) {
	if sm == nil {
		return 0, "", "", errors.New("nil session manager")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessionsByID[sessionID]
	if !ok || sess == nil {
		return 0, "", "", ErrSessionNotFound
	}

	oldBackendID = sess.BackendTunnelID
	peerKey = sess.PeerPublicKey
	oldStatus = sess.Status

	sess.BackendTunnelID = newBackendTunnelID
	if newStatus != "" {
		sess.Status = newStatus
	}
	sm.lifecycleVersion.Add(1)
	return oldBackendID, peerKey, oldStatus, nil
}

// RollbackSessionBackend safely restores a session's previous backend tunnel ID and status in memory (issue #289).
func (sm *SessionManager) RollbackSessionBackend(sessionID string, oldBackendTunnelID int64, oldStatus string) error {
	if sm == nil {
		return errors.New("nil session manager")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sess, ok := sm.sessionsByID[sessionID]
	if !ok || sess == nil {
		return ErrSessionNotFound
	}

	sess.BackendTunnelID = oldBackendTunnelID
	if oldStatus != "" {
		sess.Status = oldStatus
	} else {
		sess.Status = "connected"
	}
	sm.lifecycleVersion.Add(1)
	return nil
}

// CheckTimeouts checks for sessions that have exceeded the idleTimeout and closes them.
func (sm *SessionManager) CheckTimeouts(ctx context.Context, idleTimeout time.Duration) ([]*models.VPNSession, error) {
	if idleTimeout <= 0 {
		return nil, nil
	}

	sm.mu.Lock()
	var timedOut []*models.VPNSession
	now := time.Now().UTC()

	for _, sess := range sm.sessionsByID {
		if now.Sub(sess.LastSeen) > idleTimeout {
			timedOut = append(timedOut, sess)
		}
	}

	for _, sess := range timedOut {
		sess.TimedOutAt = now
		sess.Status = "disconnected"
		if sm.db != nil {
			_ = sm.db.CloseVPNSession(ctx, sess.ID)
		}
		sm.releaseUnpersistedLease(ctx, sess.PeerPublicKey)
		delete(sm.sessionsByID, sess.ID)
		delete(sm.sessionsByPeer, sess.PeerPublicKey)
		sm.activeCount.Add(-1)
	}
	if len(timedOut) > 0 {
		sm.lifecycleVersion.Add(1)
	}
	sm.mu.Unlock()

	return timedOut, nil
}

// releaseUnpersistedLease keeps configured addresses reserved even when a
// session ends; standalone sessions without a durable connection still free
// their temporary lease. Called with sm.mu held.
func (sm *SessionManager) releaseUnpersistedLease(ctx context.Context, peerKey string) {
	if sm.ipam == nil {
		return
	}
	if sm.db != nil {
		conn, err := sm.db.GetConnectionByClientID(ctx, peerKey, 0)
		if err != nil {
			log.Printf("[endpoint] preserving lease for peer %s: cannot check durable assignment: %v", peerKey, err)
			return
		}
		if conn != nil {
			if ip, ok := sm.ipam.GetAssignedIP(peerKey); ok && conn.ClientParams["assigned_ip"] == ip.String() {
				return
			}
		}
	}
	_ = sm.ipam.Release(peerKey)
}

// Drain marks all active sessions as draining.
func (sm *SessionManager) Drain(ctx context.Context, timeout time.Duration) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, sess := range sm.sessionsByID {
		sess.Status = "draining"
		if sm.db != nil {
			_ = sm.db.CreateVPNSession(ctx, sess)
		}
	}
	if len(sm.sessionsByID) > 0 {
		sm.lifecycleVersion.Add(1)
	}
	return nil
}

// ListActiveSessions returns a copy of all active sessions.
func (sm *SessionManager) ListActiveSessions() []*models.VPNSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []*models.VPNSession
	for _, s := range sm.sessionsByID {
		copySess := *s
		result = append(result, &copySess)
	}
	return result
}

// ListActiveSessionsSnapshot returns value copies of all active sessions,
// taken under sm.mu.RLock and sorted deterministically:
// Primary: ConnectedAt DESC (newer sessions first).
// Secondary tie-breaker: ID ASC (lexicographical on session ID).
// Lock contention is minimized by releasing sm.mu.RLock before sorting.
// Unlike ListActiveSessions (pointers to copies - safe from manager
// mutation, but callers still share one struct per entry), each element
// here is an independent copy, so the slice can be enriched and rendered
// without any aliasing against the live set. This is the source of truth
// for the memory-authoritative admin session table (issue #189 improvement
// round): the card count and the table rows are derived from the same
// in-memory set by construction.
func (sm *SessionManager) ListActiveSessionsSnapshot() []models.VPNSession {
	sm.mu.RLock()
	result := make([]models.VPNSession, 0, len(sm.sessionsByID))
	for _, s := range sm.sessionsByID {
		result = append(result, *s)
	}
	sm.mu.RUnlock()

	sort.Slice(result, func(i, j int) bool {
		if !result[i].ConnectedAt.Equal(result[j].ConnectedAt) {
			return result[i].ConnectedAt.After(result[j].ConnectedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

// ActiveCount returns the number of active sessions.
func (sm *SessionManager) ActiveCount() int {
	return int(sm.activeCount.Load())
}
