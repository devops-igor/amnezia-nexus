package vpn

// Regression tests for issue #388 rework C: exactly-once backend accounting
// across ingress session replacement. The admission path must apply the new
// backend's ActiveConnections count EXACTLY once per routing session in all
// four cases — fresh admission, same-backend replacement, different-backend
// replacement, and different-backend replacement whose route registration
// fails — with no phantom counts and no leaked session/sticky/route state.

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// backendCounts maps every pooled backend tunnel to its live gauge value.
func backendCounts(t *testing.T, svc *Service) map[int64]int {
	t.Helper()
	counts := make(map[int64]int)
	for _, tun := range svc.pool.ListTunnels() {
		live, err := svc.pool.GetTunnelByID(tun.ID)
		if err != nil {
			t.Fatalf("live backend %d: %v", tun.ID, err)
		}
		counts[tun.ID] = live.ActiveConnections
	}
	return counts
}

// sessionBackend finds the backend tunnel of the (single) session a peer owns.
func sessionBackend(t *testing.T, svc *Service, peerKey string) int64 {
	t.Helper()
	for _, s := range svc.sessionMgr.ListActiveSessions() {
		if s.PeerPublicKey == peerKey {
			return s.BackendTunnelID
		}
	}
	t.Fatalf("peer %q has no active session", peerKey)
	return 0
}

// adminDisableBackend makes one backend administratively ineligible (issue
// #90: Enabled=false with runtime health untouched), exactly like the panel's
// disable action, so the live-reuse branch refuses it and admission must
// select a different backend.
func adminDisableBackend(t *testing.T, svc *Service, serverID int64) {
	t.Helper()
	if err := svc.pool.SetTunnelEnabled(context.Background(), serverID, false, models.DisableReasonAdmin); err != nil {
		t.Fatalf("disable backend %d: %v", serverID, err)
	}
}

// serverTunnelID returns the single backend tunnel of a test server.
func serverTunnelID(t *testing.T, svc *Service, serverID int64) int64 {
	t.Helper()
	for _, tun := range svc.pool.ListTunnels() {
		if tun.ServerID == serverID {
			return tun.ID
		}
	}
	t.Fatalf("server %d has no backend tunnel", serverID)
	return 0
}

// TestIngressDifferentBackendReplacementExactlyOnce is regression test 1 of
// the rework-C verdict: a peer whose live session sits on backend A, with A
// made administratively ineligible, is admitted onto backend B. The
// replacement hook performs the whole transfer (Dec A, Inc B), so the
// admission must NOT increment B again: exactly one active session, A count
// 0, B count 1, forwarder route and sticky affinity both pointing at B.
// Before the fix this left B=2 (hook Inc + admission Inc) — the single HIGH
// blocker of review REQUEST CHANGES #2.
func TestIngressDifferentBackendReplacementExactlyOnce(t *testing.T) {
	db := setupTestDB(t)
	svc, serverA, serverB, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backendA := serverTunnelID(t, svc, serverA)
	backendB := serverTunnelID(t, svc, serverB)

	peer := seedIngressPeer(t, db, "ingress-repl-alice", "ingress-peer-bbbbbbbbbb1", "10.100.4.2")

	// 1. Establish the session on backend A.
	sessA, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}
	if sessA.BackendTunnelID != backendA {
		t.Fatalf("first admission landed on backend %d, want backend A (%d)", sessA.BackendTunnelID, backendA)
	}
	if counts := backendCounts(t, svc); counts[backendA] != 1 {
		t.Fatalf("precondition: backend A count = %d, want 1", counts[backendA])
	}

	// 2. Make A ineligible so the live-reuse branch refuses it.
	adminDisableBackend(t, svc, serverA)

	// 3. Re-admit: a live session exists but its backend is gone →
	// replacement through CreateSession, which selects the surviving
	// backend B (sticky follows A is stale and ineligible too).
	sessB, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("replacement admission: %v", err)
	}
	if sessB.BackendTunnelID != backendB || backend.ID != backendB {
		t.Fatalf("replacement landed on (%d, %d), want backend B (%d)", sessB.BackendTunnelID, backend.ID, backendB)
	}
	if sessB.ID == sessA.ID {
		t.Fatal("replacement reused the old session ID; expected a new session")
	}

	// Exactly one active session for this peer.
	active := 0
	for _, s := range svc.sessionMgr.ListActiveSessions() {
		if s.PeerPublicKey == peer.peerKey {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("peer has %d active sessions after replacement, want 1", active)
	}

	// The accounting contract itself: A count 0, B count 1.
	counts := backendCounts(t, svc)
	if counts[backendA] != 0 {
		t.Fatalf("backend A count = %d after transfer, want 0", counts[backendA])
	}
	if counts[backendB] != 1 {
		t.Fatalf("backend B count = %d after transfer, want 1 (exactly-once; 2 means the admission double-incremented the hook's transfer)", counts[backendB])
	}

	// Forwarder route points at B for the new session.
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != sessB.ID {
		t.Fatalf("route session %q, want replacement session %q", got, sessB.ID)
	}
	// Sticky affinity points at B.
	if tunID, ok := svc.stickyMgr.GetPeerAffinity(peer.peerKey); !ok || tunID != backendB {
		t.Fatalf("sticky affinity = (%d, %v), want (%d, true)", tunID, ok, backendB)
	}
}

// TestIngressDifferentBackendReplacementRollbackNoPhantom is regression test
// 2 of the rework-C verdict: the same A→B replacement, but the route
// registration is forced to fail. Nothing of the failed admission may
// survive — no session, no route, no sticky entry — and the counters must be
// internally consistent: A=0 (the old session's own teardown stands), B=0
// (the hook's transfer increment is mirrored back with the admission).
// Before the fix B kept a phantom +1 here.
func TestIngressDifferentBackendReplacementRollbackNoPhantom(t *testing.T) {
	db := setupTestDB(t)
	svc, serverA, serverB, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backendA := serverTunnelID(t, svc, serverA)
	backendB := serverTunnelID(t, svc, serverB)

	peer := seedIngressPeer(t, db, "ingress-repl-bob", "ingress-peer-bbbbbbbbbb2", "10.100.4.3")

	sessA, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}
	if sessA.BackendTunnelID != backendA {
		t.Fatalf("first admission landed on backend %d, want backend A (%d)", sessA.BackendTunnelID, backendA)
	}

	// Force the next registration to fail deterministically. Route budget
	// first (a size change is refused while sessions are active, so it is
	// pinned while exactly one route exists), then swap WHICH route fills
	// the budget: the peer's own route is removed the way a transport
	// teardown would (the ingress path has none) and a scaffold route takes
	// its slot. With the budget full and the peer route absent, the
	// replacement's TryRegisterSessionWithLimit counts as a NEW route and
	// fails with ErrRouteCapacityExhausted AFTER the replacement hook
	// already moved the counter A→B.
	_, capacity, _ := svc.forwarder.AggregateQueueStats()
	if _, _, routes := svc.forwarder.GetStats(); routes != 1 {
		t.Fatalf("precondition: %d routes after one admission, want 1", routes)
	}
	if err := svc.forwarder.ReconfigureClientQueueConfig(capacity, 1); err != nil {
		t.Fatalf("shrink route budget to 1: %v", err)
	}
	svc.forwarder.UnregisterSession(peer.peerKey)
	if _, err := svc.forwarder.TryRegisterSessionWithLimit("scaffold-session", "scaffold-conn", "scaffold-peer", "10.100.4.9", backendB, 0, 0); err != nil {
		t.Fatalf("scaffold route: %v", err)
	}
	if _, _, routes := svc.forwarder.GetStats(); routes != 1 {
		t.Fatalf("precondition: %d routes after the swap, want 1 (budget full, peer route absent)", routes)
	}

	// 2. Make A ineligible so admission must replace onto B.
	adminDisableBackend(t, svc, serverA)

	// 3. Admit again: the replacement onto B succeeds (hook: Dec A, Inc B),
	// then route registration fails against the full budget and the full
	// rollback runs.
	_, _, _, err = svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err == nil {
		t.Fatal("replacement admission succeeded past the forced registration failure; harness broken")
	}
	if !errors.Is(err, forwarder.ErrRouteCapacityExhausted) {
		t.Fatalf("replacement admission error = %v, want wrapped ErrRouteCapacityExhausted", err)
	}

	// No session survives for the peer.
	for _, s := range svc.sessionMgr.ListActiveSessions() {
		if s.PeerPublicKey == peer.peerKey {
			t.Fatalf("replacement session %s leaked after failed registration", s.ID)
		}
	}

	// Exact pool counters: A=0 (old session teardown stands), B=0 (no
	// phantom — the hook's transfer increment was mirrored back). The
	// scaffold route holds no pool count.
	counts := backendCounts(t, svc)
	if counts[backendA] != 0 {
		t.Fatalf("backend A count = %d, want 0 (old session's own teardown)", counts[backendA])
	}
	if counts[backendB] != 0 {
		t.Fatalf("backend B count = %d, want 0 (no phantom after rollback)", counts[backendB])
	}

	// Sticky stays internally consistent: the affinity pre-existed this
	// admission (the first admission created it), so the rollback must NOT
	// clear it (hadSticky) — and the hook re-pointed it at the replacement
	// backend B before the failure, which stands.
	if tunID, ok := svc.stickyMgr.GetPeerAffinity(peer.peerKey); !ok || tunID != backendB {
		t.Fatalf("sticky affinity = (%d, %v), want pre-existing affinity preserved at replacement backend %d", tunID, ok, backendB)
	}
	// The peer's own route is gone; only the scaffold route remains.
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != "" {
		t.Fatalf("route leaked after failed registration: %q", got)
	}
}

// TestIngressSameBackendReplacementNetOne pins case 2 of the four-case
// contract: when CreateSession replaces a session whose backend is unchanged
// (A==B), the hook releases the old count and the admission restores it, so
// the backend's gauge nets out at exactly 1.
func TestIngressSameBackendReplacementNetOne(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	peer := seedIngressPeer(t, db, "ingress-repl-carol", "ingress-peer-bbbbbbbbbb3", "10.100.4.4")

	sess1, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}
	backendID := sessionBackend(t, svc, peer.peerKey)

	// Force re-admission onto the SAME backend: strip the live forwarder
	// route (the reuse branch's identity check fails) while the backend
	// stays fully eligible and sticky keeps pointing at it, so selection
	// re-picks the same tunnel.
	svc.forwarder.UnregisterSession(peer.peerKey)

	sess2, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("replacement admission: %v", err)
	}
	if sess2.ID == sess1.ID {
		t.Fatal("expected a replaced session, got the same ID")
	}
	if got := sessionBackend(t, svc, peer.peerKey); got != backendID {
		t.Fatalf("same-backend replacement moved the peer to backend %d, want %d", got, backendID)
	}

	counts := backendCounts(t, svc)
	if counts[backendID] != 1 {
		t.Fatalf("same-backend replacement left count %d, want net 1", counts[backendID])
	}
}
