package vpn

import (
	"context"
	"log"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// revokeDispatcher subscribes to committed durable access revocations before
// the service is fully constructed and forwards them once the service exists.
// Forwarding is non-blocking: it runs the immediate live-session teardown
// (revokeDurableAccess / RevokeUserSessions), which take and release the
// runtime locks themselves and never wait on runtime device I/O under a held
// lock (issue #391 round 4a, findings 2 and 3).
type revokeDispatcher struct {
	ready chan struct{}
	svc   *Service
}

func newRevokeDispatcher() *revokeDispatcher {
	return &revokeDispatcher{ready: make(chan struct{})}
}

// bind connects the dispatcher to its service.
func (rd *revokeDispatcher) bind(svc *Service) {
	if rd == nil {
		return
	}
	rd.svc = svc
	close(rd.ready)
}

// RecordPeerRevoke implements database.PeerRevokeRecorder.
func (rd *revokeDispatcher) RecordPeerRevoke(ctx context.Context, event database.PeerRevokeEvent) {
	if rd == nil {
		return
	}
	select {
	case <-rd.ready:
	default:
		// The service is not constructed yet: nothing live to revoke.
		return
	}
	svc := rd.svc
	if svc == nil {
		return
	}
	svc.runPostCommitRevoke(ctx, event)
}

// Service-side live-session revocation for durable access changes (issue #391
// round 4a, finding 3). When a durable disable/revoke/delete commits, the
// database notification path must not leave established traffic forwarding in
// EITHER engine mode: upstream-engine sessions are torn down routing-only via
// RevokeUpstreamPeerSession (the reconcile worker performs the same teardown
// shortly after commit; this direct path enforces immediately), legacy
// listener sessions are fenced and pruned like DisconnectSession. Durable IP
// allocations are never released and other peers' upstream crypto state is
// untouched. A peer with no live session is a no-op.
//
// Callers run on the DB commit goroutine AFTER the durable change committed
// but WITHOUT Service.mu held. The dispatch itself takes s.mu only long
// enough to snapshot and mark the session; in-flight device writes are joined
// and transport state pruned after s.mu is released, mirroring the
// DisconnectUser/DisconnectSession unlock-then-wait discipline.

// revokeDurableAccess performs the engine-aware live teardown for one peer
// whose durable access was just revoked. Engine-aware dispatch (issue #391
// round 4a, finding 3): upstream-admitted sessions get the routing-only
// revocation, legacy (handshake-admitted) sessions get generation fencing
// plus transport pruning exactly once, the routing session is closed with
// reason "revoked", the forwarder route is retired, and the backend pool
// counter is decremented exactly once (the round-3 ownership guard shows the
// pattern: CloseSession failure yields teardown ownership). No live session
// means no live traffic: a no-op.
func (s *Service) revokeDurableAccess(ctx context.Context, peerKey string) {
	if s == nil || s.sessionMgr == nil {
		return
	}
	sess, ok := s.sessionMgr.GetSession(peerKey)
	if !ok {
		return
	}
	if sess.AdmittedVia == models.SessionAdmissionIngress {
		// The upstream engine owns this session: routing-only teardown.
		// Failure must not fail the durable operation; the reconcile
		// worker retries enforcement and PeerSyncStatus reports drift.
		if err := s.RevokeUpstreamPeerSession(ctx, peerKey); err != nil {
			log.Printf("[vpn/service] durable access revocation of upstream session for peer %s failed (reconcile will retry): %v", peerKey, err)
		}
		return
	}
	var retirement forwarder.Retirement
	var prunePeer, pruneSession string
	var fenceGen uint64
	s.mu.Lock()
	// CloseSession removed the session exactly once, so nobody else tears
	// this session down concurrently; the reserved fence rejects any
	// in-flight or pending handshake of the old generation.
	if s.peerGenerations == nil {
		s.peerGenerations = make(map[string]uint64)
	}
	s.peerGenerations[sess.PeerPublicKey]++
	fenceGen = s.peerGenerations[sess.PeerPublicKey]
	prunePeer, pruneSession = sess.PeerPublicKey, sess.ID
	if s.endpoint != nil {
		s.endpoint.FencePeerGeneration(prunePeer, fenceGen)
	}
	if err := s.sessionMgr.CloseSession(ctx, sess.ID, "revoked"); err != nil {
		s.mu.Unlock()
		// Another teardown path owns this session lifecycle (idle
		// reaper evicted it first); never double-decrement.
		log.Printf("[vpn/service] durable access revocation skipped for peer %s: %v", peerKey, err)
		return
	}
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
	s.mu.Unlock()
	retirement.Wait()
	if prunePeer != "" && s.endpoint != nil {
		s.endpoint.PrunePeerTransportStateIfSession(prunePeer, pruneSession, fenceGen)
	}
	log.Printf("[vpn/service] revoked legacy session after durable access change: id=%s peer=%s user=%s ip=%s tunnel_id=%d",
		sess.ID, sess.PeerPublicKey, sess.UserID, sess.AssignedIP, sess.BackendTunnelID)
}

// RevokeUserSessions performs immediate engine-aware live teardown for every
// PORTAL-scope session of one user after a durable user-level access
// revocation committed (disable or delete). Sessions of regular server peers
// and legacy server tunnels are skipped: they are outside the ingress
// engine's domain and their lifecycle has its own pre-existing delete paths.
// It never touches durable IP allocations.
func (s *Service) RevokeUserSessions(ctx context.Context, userID string) {
	s.revokeUserSessions(ctx, userID, nil)
}

// revokeUserSessions is the shared body of the user-level revocation. When
// captured is non-empty it is the authoritative set of PORTAL-scope peer keys
// the database captured BEFORE the deleting statement destroyed their rows
// (issue #391 round 4b, finding 1): the durable connection is already gone, so
// portalSession cannot classify those sessions any more and the per-session
// durable lookup is both useless and wrong to rely on. Sessions outside the
// captured set are still resolved against their own durable connection, which
// keeps the user-disable path (no rows deleted, captured empty) working
// exactly as before.
func (s *Service) revokeUserSessions(ctx context.Context, userID string, captured []string) {
	if s == nil || s.sessionMgr == nil {
		return
	}
	capturedSet := make(map[string]struct{}, len(captured))
	for _, key := range captured {
		if key != "" {
			capturedSet[key] = struct{}{}
		}
	}
	sessions := s.sessionMgr.GetSessionsByUserID(userID)
	for _, sess := range sessions {
		if _, ok := capturedSet[sess.PeerPublicKey]; ok {
			// The durable row is gone; the captured identity is the
			// authority. This is the ingress engine's domain by
			// construction: only portal-scope keys were captured.
			s.revokeDurableAccess(ctx, sess.PeerPublicKey)
			continue
		}
		if len(capturedSet) != 0 {
			// A bulk delete captured the user's portal identities: a
			// session whose peer is NOT among them is either a regular
			// server peer, a legacy server tunnel, or a connection that
			// was never captured. All are outside this path's domain.
			continue
		}
		if !s.portalSession(ctx, sess) {
			continue
		}
		s.revokeDurableAccess(ctx, sess.PeerPublicKey)
	}
}

// RecordPeerRevoke implements database.PeerRevokeRecorder: it performs the
// immediate engine-aware live-session teardown for one committed durable
// access revocation (issue #391 round 4a, finding 3). It runs on the DB
// commit goroutine, which never holds Service.mu here; revokeDurableAccess
// and revokePortalUserSessions take and release the runtime locks
// themselves.
func (s *Service) RecordPeerRevoke(ctx context.Context, event database.PeerRevokeEvent) {
	s.runPostCommitRevoke(ctx, event)
}

// SetPostCommitRevokeHookForTest installs a test seam invoked by the durable
// access-revoking DB paths (toggle-to-disabled, delete by id and by client
// id, user disable, user delete) immediately after the commit, before
// notification. Tests use it to make live-session revocation observable;
// production leaves it nil.
func (s *Service) SetPostCommitRevokeHookForTest(fn func(kind database.PeerRevokeKind, userID string, clientID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postCommitRevokeHookForTest = fn
}

// runPostCommitRevoke executes the immediate enforcement hooks for one
// committed durable access revocation: the live-session teardown (never
// inline from under Service.mu; these paths run on DB commit goroutines) and
// the test seam. Safe on every revoking path; a no-op without sessions.
//
// Portal scoping (issue #391 round 4a, finding 3): the dispatcher owns only
// PORTAL-scope sessions, the ingress engine's domain. A connection-level
// event is already classified by the database layer, which saw the row
// before the commit deleted it. A user-level event that DELETES rows carries
// the same pre-commit classification in PortalPeers (issue #391 round 4b,
// finding 1), because there is nothing left to classify against afterwards.
// A user-level event that leaves the rows in place (user disable) cannot
// classify in the database, so each candidate session is classified here
// against its own durable connection (server_id 0, awg) and sessions of
// regular server peers or legacy server tunnels are left untouched: their
// lifecycle has its own pre-existing delete paths.
func (s *Service) runPostCommitRevoke(ctx context.Context, event database.PeerRevokeEvent) {
	s.mu.RLock()
	hook := s.postCommitRevokeHookForTest
	s.mu.RUnlock()
	if hook != nil {
		hook(event.Kind, event.UserID, event.ClientID)
	}
	switch event.Kind {
	case database.PeerRevokeConnection:
		if event.ClientID != "" && event.PortalScope {
			s.revokeDurableAccess(ctx, event.ClientID)
		}
	case database.PeerRevokeUser:
		if event.UserID != "" {
			s.revokeUserSessions(ctx, event.UserID, event.PortalPeers)
		}
	}
}

// portalSession reports whether one live session is portal-scope: its peer
// owns a durable portal connection (server_id 0, awg). Regular server peers
// and legacy server tunnels are excluded, so their sessions are never torn
// down by the engine-aware dispatcher. A database read failure is treated as
// not portal-scope (fail-safe toward not disturbing foreign sessions); the
// reconciliation worker and the pre-existing delete paths still converge.
func (s *Service) portalSession(ctx context.Context, sess *models.VPNSession) bool {
	if sess == nil || sess.PeerPublicKey == "" || s.db == nil {
		return false
	}
	conn, err := s.db.GetConnectionByClientID(ctx, sess.PeerPublicKey, 0)
	if err != nil || conn == nil {
		return false
	}
	return conn.ServerID == 0 && models.NormalizeProtocol(conn.Protocol) == "awg"
}
