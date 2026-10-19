package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
)

// SetReconcilePostSnapshotHook registers a test hook called immediately after
// reading the active session snapshot in reconcileConnectionCounts, before s.mu is acquired.
func (s *Service) SetReconcilePostSnapshotHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcilePostSnapshotHook = fn
}

// SetReconcilePreApplyHook registers a test hook called under s.mu before
// the tunnel reconciliation apply phase in reconcileConnectionCounts.
func (s *Service) SetReconcilePreApplyHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcilePreApplyHook = fn
}

// SetReconcilePreCommitHook registers a test hook called under s.mu and sm.LockLifecycle
// immediately before applying changes in reconcileConnectionCounts.
func (s *Service) SetReconcilePreCommitHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reconcilePreCommitHook = fn
}

// DisconnectUser disconnects all active VPN sessions for a user.
func (s *Service) DisconnectUser(ctx context.Context, userID string) error {
	var retirements []forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		for _, retirement := range retirements {
			retirement.Wait()
		}
	}()

	if s.sessionMgr == nil {
		return nil
	}

	sessions := s.sessionMgr.GetSessionsByUserID(userID)
	for _, sess := range sessions {
		_ = s.sessionMgr.CloseSession(ctx, sess.ID, "disconnected")
		if s.forwarder != nil {
			retirements = append(retirements, s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID))
		}
		if s.stickyMgr != nil {
			s.stickyMgr.ClearAffinity(userID)
			s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
		}
		// The counter feeds least-connections and capacity filtering; without
		// the decrement it becomes a lifetime cumulative count and backends
		// eventually look permanently full.
		s.pool.DecrementConnections(sess.BackendTunnelID)
	}

	return nil
}

// reapSession tears down an idle-timed-out session routing-only:
// forwarder route retirement and guarded pool decrement.
func (s *Service) reapSession(ctx context.Context, sess *models.VPNSession) {
	if sess == nil {
		return
	}
	s.reapIngressSession(sess)
}

// reapIngressSession performs the routing-only teardown of an idle upstream
// backend session (issue #390 part 1). It holds the same s.mu admission
// serialization regime reapSession always held, retires the forwarder route
// with the session-identity guard (a recreated session's route is never
// removed by an old reap — the forwarder's generation-bounded delete holds),
// and applies the same reconciliation-guarded pool decrement as the legacy
// path. It MUST NOT touch endpoint transport state or generation fences, and
// it never removes the configured upstream peer (durable user_connections /
// clientawg identity): the peer stays configured and idle after its backend
// routing session is retired; the peer's crypto state outlives any number of
// Nexus backend sessions.
//
// Liveness guard: CheckTimeouts removes the session it reaps, so a live
// session for the peer under s.mu means a concurrent admission raced this
// reap. Two sub-cases:
//
//   - Same ID still live: the admission's LastSeen-based reuse refreshed the
//     session (traffic won the race); it still owns its route and pool
//     count — this reap is a full no-op.
//   - Different live ID: the admission created a fresh session (CheckTimeouts
//     had already removed this one, so no replacement hook moved its count).
//     This reap still owns the OLD pool decrement, but must not touch the
//     route — the new session's registration owns it now.
//
// Without the same-ID no-op, a reused session's freshly re-validated route
// could be retired by the racing reap (route == "" while the session reports
// connected — every return packet lost; found by the reap/recreate race
// test). Without the different-ID decrement, the old session's count leaks
// (gauge sum 2 for one live session; found by the same test pair).
func (s *Service) reapIngressSession(sess *models.VPNSession) {
	var retirement forwarder.Retirement
	var reaped bool
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if reaped {
			log.Printf("[vpn/service] reaped idle upstream session (routing-only): id=%s peer=%s user=%s ip=%s tunnel_id=%d",
				sess.ID, sess.PeerPublicKey, sess.UserID, sess.AssignedIP, sess.BackendTunnelID)
		}
	}()

	skipRoute := false
	if live, exists := s.sessionMgr.GetSessionSnapshotByPeer(sess.PeerPublicKey); exists {
		if live.ID == sess.ID {
			// Refreshed/reuse won the race: still live, owns everything.
			log.Printf("[vpn/service] skip idle reap of upstream session id=%s peer=%s: session is live again",
				sess.ID, sess.PeerPublicKey)
			return
		}
		// Fresh-creation replacement won: skip route retirement, keep the
		// old session's pool decrement (no hook moved it).
		skipRoute = true
		log.Printf("[vpn/service] reap of upstream session id=%s peer=%s: peer already re-admitted as %s; retiring the old count only",
			sess.ID, sess.PeerPublicKey, live.ID)
	}

	reaped = true

	if !skipRoute && s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}

	if s.pool != nil {
		shouldDecrement := true
		var tunReconcileTime time.Time
		if s.lastReconcileByTunnel != nil {
			tunReconcileTime = s.lastReconcileByTunnel[sess.BackendTunnelID]
		}
		if !sess.TimedOutAt.IsZero() && !tunReconcileTime.IsZero() && tunReconcileTime.After(sess.TimedOutAt) {
			shouldDecrement = false
		}
		if shouldDecrement {
			s.pool.DecrementConnections(sess.BackendTunnelID)
		}
	}
}

// PruneExpiredAffinity scans and removes expired sticky affinity records
// from the load balancer. It acquires s.mu with RLock only long enough to
// retrieve stickyMgr, then executes pruning outside s.mu to eliminate
// lock contention during mass session reap sweeps.
func (s *Service) PruneExpiredAffinity() int {
	s.mu.RLock()
	sm := s.stickyMgr
	s.mu.RUnlock()
	if sm == nil {
		return 0
	}
	return sm.PruneExpired()
}

// DisconnectSession disconnects a specific VPN session by ID routing-only.
func (s *Service) DisconnectSession(ctx context.Context, sessionID string) error {
	var retirement forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
	}()

	if s.sessionMgr == nil {
		return nil
	}

	sess, ok := s.sessionMgr.GetSessionByID(sessionID)
	if !ok {
		return session.ErrSessionNotFound
	}

	_ = s.sessionMgr.CloseSession(ctx, sessionID, "disconnected")
	if s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}
	if s.stickyMgr != nil {
		s.stickyMgr.ClearAffinity(sess.UserID)
		s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
	}
	if s.pool != nil {
		s.pool.DecrementConnections(sess.BackendTunnelID)
	}

	return nil
}

// RevokeUpstreamPeerSession performs immediate routing-only teardown for an
// upstream peer whose durable connection was removed or disabled (issue #391).
// It closes the active session in SessionManager with reason "revoked", retires
// the forwarder route, clears sticky affinity, and decrements backend pool
// active connections. It does NOT advance endpoint peer generations, touch
// upstream transport keys, or release the peer's durable IP allocation.
func (s *Service) RevokeUpstreamPeerSession(ctx context.Context, peerKey string) error {
	if s == nil || s.sessionMgr == nil {
		return nil
	}
	var retirement forwarder.Retirement
	var reapedSess *models.VPNSession
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
		if reapedSess != nil {
			log.Printf("[vpn/service] revoked upstream peer session (routing-only): id=%s peer=%s user=%s ip=%s tunnel_id=%d",
				reapedSess.ID, reapedSess.PeerPublicKey, reapedSess.UserID, reapedSess.AssignedIP, reapedSess.BackendTunnelID)
		}
	}()

	sess, ok := s.sessionMgr.GetSession(peerKey)
	if !ok {
		return nil
	}
	if s.preRevokeCloseHookForTest != nil {
		s.preRevokeCloseHookForTest(sess.PeerPublicKey, sess.ID)
	}
	if err := s.sessionMgr.CloseSession(ctx, sess.ID, "revoked"); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			// The session was already evicted (e.g. by CheckTimeouts); the idle reaper owns teardown.
			return nil
		}
		return fmt.Errorf("close revoked session %s: %w", sess.ID, err)
	}
	reapedSess = sess
	if s.forwarder != nil {
		retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
	}
	if s.stickyMgr != nil {
		s.stickyMgr.ClearAffinity(sess.UserID)
		s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
	}
	if s.pool != nil {
		s.pool.DecrementConnections(sess.BackendTunnelID)
	}
	return nil
}

// SetPreRevokeCloseHookForTest sets a test hook called under s.mu in RevokeUpstreamPeerSession
// immediately after GetSession and before CloseSession to deterministically test eviction races.
func (s *Service) SetPreRevokeCloseHookForTest(fn func(peerKey, sessionID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preRevokeCloseHookForTest = fn
}

// SetPreAdoptHookForTest sets a test hook called under s.mu in ensureBackendSessionForIngress
// immediately before calling AdoptSessionForIngress (issue #390).
func (s *Service) SetPreAdoptHookForTest(fn func(peerKey, sessionID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preAdoptHookForTest = fn
}

// SetPreIngressRouteRegistrationHookForTest sets a test hook called under s.mu
// in ensureBackendSessionForIngress immediately before forwarder route registration.
func (s *Service) SetPreIngressRouteRegistrationHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preIngressRouteRegistrationHookForTest = fn
}

// ReleaseClient releases IPAM allocations and disconnects any active sessions for the client.
func (s *Service) ReleaseClient(ctx context.Context, clientPub string) error {
	var retirement forwarder.Retirement
	s.mu.Lock()
	defer func() {
		s.mu.Unlock()
		retirement.Wait()
	}()

	if s.sessionMgr != nil && clientPub != "" {
		if sess, ok := s.sessionMgr.GetSession(clientPub); ok {
			_ = s.sessionMgr.CloseSession(ctx, sess.ID, "client_deleted")
			if s.forwarder != nil {
				retirement = s.forwarder.BeginUnregisterSession(sess.PeerPublicKey, sess.ID)
			}
			if s.stickyMgr != nil {
				s.stickyMgr.ClearPeerAffinity(sess.PeerPublicKey)
			}
			if s.pool != nil {
				s.pool.DecrementConnections(sess.BackendTunnelID)
			}
		}
	}

	if s.ipam != nil && clientPub != "" {
		_ = s.ipam.Release(clientPub)
	}

	return nil
}

// SetSessionReaperHookForTest sets a test hook invoked by SweepTimedOutSessions for each reaped session.
func (s *Service) SetSessionReaperHookForTest(fn func(context.Context, *models.VPNSession)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reaperHook = fn
}

// SweepTimedOutSessions sweeps for idle-timed-out sessions and invokes reapSession
// (or the test reaper hook) for each timed-out session.
func (s *Service) SweepTimedOutSessions(ctx context.Context) ([]*models.VPNSession, error) {
	if s == nil || s.sessionMgr == nil {
		return nil, nil
	}
	timeout := 3 * time.Minute
	timedOut, err := s.sessionMgr.CheckTimeouts(ctx, timeout)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	hook := s.reaperHook
	s.mu.RUnlock()
	for _, sess := range timedOut {
		if hook != nil {
			hook(ctx, sess)
		} else {
			s.reapSession(ctx, sess)
		}
	}
	return timedOut, nil
}
