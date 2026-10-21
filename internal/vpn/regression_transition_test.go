package vpn

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// regression_transition_test.go pins the four round-4a behaviors from the
// consolidated review: fail-closed ownership handoff during key replacement,
// deadlock-free legacy admission with a subscribed peer-change listener,
// immediate forwarding stop on durable disable in legacy mode, and
// exactly-once Nexus-side cleanup for peers that already vanished upstream.

// TestRegressionReplacementOwnershipHandoffIsFailClosed drives a key
// replacement through a fake portal with a real Resolver: while the retired
// key's removal is in flight, a packet from the old peer must not be admitted
// under the replacement identity, and the IP stays unauthorized until the
// replacement is installed and verified.
func TestRegressionReplacementOwnershipHandoffIsFailClosed(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	peer, _ := newEnginePeer(t, svc, db, "regr-replace")
	e, err := svc.NewIngressEngine(ctx, "regr-replace-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })

	// Real Resolver installed in a real router: Lookup and packet admission
	// answers come from production code, not test doubles.
	router := e.Router()
	ip := netip.MustParseAddr(peer.assignedIP)
	before := router.StatsSnapshot()

	// Swap the durable client identity under the SAME assigned IP.
	conn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	_, newKey := engineKeys(t)
	if ok, err := db.UpdateConnection(ctx, conn.ID, map[string]any{"client_id": newKey}); !ok || err != nil {
		t.Fatalf("durable key replacement: %v", err)
	}

	// Hold the SECOND Status call (the verifyPeers read) so the whole
	// retirement (old key withdrawn and removed, replacement not yet
	// verified) sits inside one reconcile. The first Status must pass so
	// classification and resolver withdrawal actually run.
	gate := make(chan struct{})
	calls := new(atomic.Int64)
	e.peerSync.setPortalDeviceForTest(secondStatusGate{real: e.Portal(), release: gate, calls: calls})
	reconciled := make(chan error, 1)
	go func() { reconciled <- e.peerSync.reconcileNow(ctx) }()

	// The retired key's ownership must be gone before verification.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, tracked := e.Resolver().Lookup(ip); !tracked {
			break
		}
		select {
		case <-reconciled:
			close(gate)
			t.Fatal("reconcile finished before the gate opened")
		case <-time.After(time.Millisecond):
		}
	}
	if _, tracked := e.Resolver().Lookup(ip); tracked {
		close(gate)
		t.Fatal("retired key kept plaintext ownership through the transition")
	}
	// Mid-transition admission attempt: with the IP unmapped the router
	// cannot attribute the packet to any identity, the old key included.
	_ = router.HandlePacket(engineUDPPacket(ip, netip.MustParseAddr("10.0.0.1"), 1))
	mid := router.StatsSnapshot()
	if mid.UnmappedSourceIPDrops != before.UnmappedSourceIPDrops+1 {
		t.Fatalf("mid-transition packet was not dropped as unmapped: %+v", mid)
	}

	// Verification cannot succeed while the gate holds the post-removal
	// snapshot, so the reconcile must still be blocked; open it and let the
	// replacement install.
	select {
	case err := <-reconciled:
		close(gate)
		t.Fatalf("reconcile completed without a fresh Status: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(gate)
	if err := <-reconciled; err != nil {
		t.Fatalf("post-gate reconcile: %v", err)
	}
	owner, ok := e.Resolver().Lookup(ip)
	if !ok || owner.PeerPublicKey != newKey {
		t.Fatalf("replacement identity not installed after verification: ok=%v owner=%+v", ok, owner)
	}
	// A packet from the replacement identity is now admitted under the new
	// key, proving attribution followed the durable swap.
	if err := router.HandlePacket(engineUDPPacket(ip, netip.MustParseAddr("10.0.0.1"), 2)); err != nil {
		t.Fatalf("post-install admission failed: %v", err)
	}
	after := router.StatsSnapshot()
	if after.AdmittedSessions < before.AdmittedSessions+1 {
		t.Fatalf("replacement peer packet was not admitted after install: %+v", after)
	}
	if after.UnmappedSourceIPDrops != mid.UnmappedSourceIPDrops {
		t.Fatalf("post-install admission regressed to unmapped drop: %+v", after)
	}
}

// TestRegressionLegacyAdmissionWithListenerCompletes proves legacy admission
// (HandleIncomingPeer) completes while a REAL engine has armed the
// post-commit notification wiring: the UpdateConnection inside
// resolveOrAllocatePeerIP notifies the listener from under Service.mu, which
// must only enqueue. The old inline chain re-entered Service.mu through
// removeDriftedPeers -> revokeSession and deadlocked; the watchdog fails
// long before the test timeout if any inline reconcile ever comes back.
func TestRegressionLegacyAdmissionWithListenerCompletes(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "regr-admission", Role: "user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const peerKey = "peer-admission-watchdog"
	// No assigned_ip: admission takes the allocate-and-persist path, which
	// is the one that notifies from under Service.mu.
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   userID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKey,
		Name:     "admission watchdog peer",
	}); err != nil {
		t.Fatal(err)
	}
	// Constructing the engine arms the production notification listener.
	e, err := svc.NewIngressEngine(ctx, "regr-admission-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })

	watchdog := time.AfterFunc(5*time.Second, func() {
		panic("HandleIncomingPeer blocked: notification path reconciled inline under Service.mu")
	})
	defer watchdog.Stop()
	sess, _, err := svc.HandleIncomingPeerForTest(ctx, peerKey)
	if err != nil {
		t.Fatalf("legacy admission with armed listener: %v", err)
	}
	watchdog.Stop()
	if sess == nil || sess.PeerPublicKey != peerKey {
		t.Fatalf("admission returned wrong session: %+v", sess)
	}
}

// TestRegressionLegacyDisableStopsForwarding proves the durable-disable
// contract in the production-default legacy mode: after a committed disable,
// the live-session revocation fires immediately (session closed, route
// retired, backend counter decremented exactly once) while the engine stays
// dormant and untouched.
func TestRegressionLegacyDisableStopsForwarding(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backend := svc.pool.GetActiveTunnels()[0]

	// A real enabled user with a real issued connection: the durable toggle
	// below revokes exactly this peer.
	peerKey, connID := issueDurablePeer(t, svc, db, "regr-legacy-disable")
	sess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userIDFor(t, db, connID), peerKey, "10.100.8.7", backend.ID, "ingress-device", models.SessionAdmissionDirect)
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.IncrementConnections(backend.ID)
	if r := svc.forwarder.BeginRegisterSessionWithLimit(sess.ID, connID, peerKey, sess.AssignedIP, backend.ID, 0, 0); true {
		r.Wait()
	}

	revoked := make(chan struct{})
	svc.SetPostCommitRevokeHookForTest(func(kind database.PeerRevokeKind, userID, clientID string) {
		if kind == database.PeerRevokeConnection && clientID == peerKey {
			close(revoked)
		}
	})
	t.Cleanup(func() { svc.SetPostCommitRevokeHookForTest(nil) })

	if ok, err := db.ToggleConnection(ctx, connID, false); !ok || err != nil {
		t.Fatalf("durable disable: %v", err)
	}
	select {
	case <-revoked:
	case <-time.After(2 * time.Second):
		t.Fatal("committed disable did not trigger live-session revocation")
	}
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); ok {
		t.Fatalf("disabled session survived: %+v", snap)
	}
	if route := svc.forwarder.RouteSessionID(peerKey); route != "" {
		t.Fatalf("disabled session kept its forwarder route: %q", route)
	}
	after, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil || after.ActiveConnections != 0 {
		t.Fatalf("backend counter after disable = %d, want 0 (err: %v)", after.ActiveConnections, err)
	}
}

// issueDurablePeer issues one real connection through the production path
// and returns its peer key and connection id.
func issueDurablePeer(t *testing.T, svc *Service, db interface {
	CreateUser(ctx context.Context, u *models.User) (string, error)
	GetConnectionsByUserID(ctx context.Context, userID string) ([]models.UserConnection, error)
}, name string) (string, string) {
	t.Helper()
	userID, err := db.CreateUser(t.Context(), &models.User{Username: name, Role: "user", Enabled: true})
	if err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	if _, _, err := svc.GenerateClientConfig(t.Context(), userID); err != nil {
		t.Fatalf("issue config for %s: %v", name, err)
	}
	conns, err := db.GetConnectionsByUserID(t.Context(), userID)
	if err != nil || len(conns) != 1 {
		t.Fatalf("connections for %s: %d rows, %v", name, len(conns), err)
	}
	return conns[0].ClientID, conns[0].ID
}

// userIDFor resolves the owning user of one connection row.
func userIDFor(t *testing.T, db interface {
	GetConnection(ctx context.Context, id string) (*models.UserConnection, error)
}, connID string) string {
	t.Helper()
	conn, err := db.GetConnection(t.Context(), connID)
	if err != nil || conn == nil {
		t.Fatalf("connection %s: %v", connID, err)
	}
	return conn.UserID
}

// TestRegressionMissingUpstreamCleanupExactlyOnce proves the finding-4
// invariant: a live Nexus session whose upstream peer already vanished is
// cleaned exactly once (session, route, counter) by reconcile's Nexus-side
// enumeration.
func TestRegressionMissingUpstreamCleanupExactlyOnce(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backend := svc.pool.GetActiveTunnels()[0]

	peerKey, connID := issueDurablePeer(t, svc, db, "regr-missing-upstream")
	e, err := svc.NewIngressEngine(ctx, "regr-missing-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	userID := userIDFor(t, db, connID)
	conn, err := db.GetConnection(ctx, connID)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	assignedIP := conn.ClientParams["assigned_ip"].(string)

	sess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, peerKey, assignedIP, backend.ID, "ingress-device", models.SessionAdmissionIngress)
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.IncrementConnections(backend.ID)
	if r := svc.forwarder.BeginRegisterSessionWithLimit(sess.ID, connID, peerKey, assignedIP, backend.ID, 0, 0); true {
		r.Wait()
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); !ok {
		t.Fatal("setup: live session missing")
	}

	// Durable disable commits FIRST: the dispatcher runs the immediate
	// teardown, which is the path under test for exactly-once ownership.
	// Detach the dispatcher for the call so the hook counts teardowns from
	// this disable alone (the engine's DB listener is left armed to prove
	// the enqueue path does not tear down again).
	revokes := map[string]int{}
	var revMu sync.Mutex
	svc.SetPreRevokeCloseHookForTest(func(peer, session string) {
		if peer == peerKey {
			revMu.Lock()
			revokes[peer]++
			revMu.Unlock()
		}
	})
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })
	unsubscribeRevokes := db.SubscribePeerRevokes(revokeDispatcherRecorderFunc(func(ctx context.Context, event database.PeerRevokeEvent) {}))
	defer unsubscribeRevokes()

	if ok, err := db.ToggleConnection(ctx, connID, false); !ok || err != nil {
		t.Fatalf("durable disable: %v", err)
	}
	// The upstream peer is already gone as well: the reconcile must clean
	// the Nexus side regardless of upstream presence (finding 4).
	if err := e.Portal().RemovePeer(peerKey); err != nil {
		t.Fatal(err)
	}
	if err := e.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile with missing upstream peer: %v", err)
	}
	revMu.Lock()
	count := revokes[peerKey]
	revMu.Unlock()
	if count != 1 {
		t.Fatalf("routing teardown ran %d times, want exactly 1", count)
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); ok {
		t.Fatal("orphaned routing session survived")
	}
	if route := svc.forwarder.RouteSessionID(peerKey); route != "" {
		t.Fatalf("orphaned forwarder route survived: %q", route)
	}
	tunAfter, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Fatalf("backend counter after orphan cleanup = %d, want 0 (err: %v)", tunAfter.ActiveConnections, err)
	}
	// A second reconcile finds nothing left to tear down: exactly-once.
	if err := e.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	revMu.Lock()
	count = revokes[peerKey]
	revMu.Unlock()
	if count != 1 {
		t.Fatalf("second reconcile re-ran teardown: %d total, want still 1", count)
	}
	// Restore the production dispatcher before the deferred unsubscribe
	// runs: the unsubscribe matches the LAST installed recorder, and the
	// dispatcher's own cleanup path must keep working after this test.
	svc.mu.Lock()
	db.SubscribePeerRevokes(svc)
	svc.mu.Unlock()
}

// revokeDispatcherRecorderFunc adapts a function to PeerRevokeRecorder.
type revokeDispatcherRecorderFunc func(ctx context.Context, event database.PeerRevokeEvent)

func (f revokeDispatcherRecorderFunc) RecordPeerRevoke(ctx context.Context, event database.PeerRevokeEvent) {
	f(ctx, event)
}

// secondStatusGate passes the first Status through and blocks the second one
// (the verifyPeers read) until released. Methods use value receivers so the
// zero-value copy still satisfies portalPeerDevice; the counter is shared
// through the pointer embedded in the copies.
type secondStatusGate struct {
	real    portalPeerDevice
	release chan struct{}
	calls   *atomic.Int64
}

func (d secondStatusGate) Status() (clientawg.Status, error) {
	if d.calls.Add(1) > 1 {
		<-d.release
	}
	return d.real.Status()
}

func (d secondStatusGate) AddPeer(peer clientawg.Peer) error { return d.real.AddPeer(peer) }

func (d secondStatusGate) RemovePeer(key string) error { return d.real.RemovePeer(key) }
