package endpoint

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
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
	mu              sync.RWMutex
	db              *database.DB
	ipam            *IPAM
	sessionsByPeer  map[string]*models.VPNSession // peerPublicKey -> session
	sessionsByID    map[string]*models.VPNSession // sessionID -> session
	activeCount     atomic.Int64
	metrics         SessionMetrics
	replacementHook ReplacementHook
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
// held, so it must only touch the pool counter and DB — never re-enter the
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

// CreateSession allocates a new VPN session and persists it. When a session
// already exists for the same peer (client rekey/reconnect), the old session
// is fully replaced: removed from memory, its DB row closed, and the
// replacement hook fires so the caller can migrate the pool counter and
// redirect live routes (issue #78 — every rekey previously leaked +1 on the
// old backend's ActiveConnections gauge because neither the pool decrement
// nor a teardown for the old ID ever ran).
func (sm *SessionManager) CreateSession(ctx context.Context, userID, peerPublicKey, assignedIP string, backendTunnelID int64) (*models.VPNSession, error) {
	if userID == "" || peerPublicKey == "" || assignedIP == "" {
		return nil, errors.New("missing required session fields")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// If session already exists for this peer, close it before creating a new
	// one. The DB row is deleted here (same primitive the clean-disconnect
	// path uses) so no orphan row for a dead session ID survives — a later
	// DisconnectSession(oldID) would otherwise return ErrSessionNotFound and
	// its mirror-decrement would never run.
	var replaced *models.VPNSession
	if oldSess, ok := sm.sessionsByPeer[peerPublicKey]; ok {
		replaced = oldSess
		delete(sm.sessionsByID, oldSess.ID)
		delete(sm.sessionsByPeer, peerPublicKey)
		sm.activeCount.Add(-1)
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
		// released here — the replacement reuses the same peer IP (the
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
	}

	if sm.db != nil {
		if err := sm.db.CreateVPNSession(ctx, sess); err != nil {
			if replaced != nil {
				// The replacement is lost; keep the leak observable — the
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

// GetSessionByID retrieves a session by session ID.
func (sm *SessionManager) GetSessionByID(sessionID string) (*models.VPNSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessionsByID[sessionID]
	return sess, ok
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

// CloseSession transitions a session to the specified status and releases IPAM allocation.
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

	if sm.ipam != nil {
		_ = sm.ipam.Release(sess.PeerPublicKey)
	}

	delete(sm.sessionsByID, sessionID)
	delete(sm.sessionsByPeer, sess.PeerPublicKey)
	sm.activeCount.Add(-1)

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
		sess.Status = "disconnected"
		if sm.db != nil {
			_ = sm.db.CloseVPNSession(ctx, sess.ID)
		}
		if sm.ipam != nil {
			_ = sm.ipam.Release(sess.PeerPublicKey)
		}
		delete(sm.sessionsByID, sess.ID)
		delete(sm.sessionsByPeer, sess.PeerPublicKey)
		sm.activeCount.Add(-1)
	}
	sm.mu.Unlock()

	return timedOut, nil
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

// ActiveCount returns the number of active sessions.
func (sm *SessionManager) ActiveCount() int {
	return int(sm.activeCount.Load())
}

// SyncFromDB restores active sessions from the database on startup.
func (sm *SessionManager) SyncFromDB(ctx context.Context) error {
	if sm.db == nil {
		return nil
	}

	sessions, err := sm.db.GetActiveVPNSessions(ctx)
	if err != nil {
		return fmt.Errorf("failed to load active sessions: %w", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for i := range sessions {
		sess := sessions[i]
		sm.sessionsByID[sess.ID] = &sess
		sm.sessionsByPeer[sess.PeerPublicKey] = &sess
		sm.activeCount.Add(1)

		if sm.ipam != nil && sess.AssignedIP != "" {
			if ip := net.ParseIP(sess.AssignedIP); ip != nil {
				_ = sm.ipam.Reserve(ip, sess.PeerPublicKey)
			}
		}
	}

	return nil
}
