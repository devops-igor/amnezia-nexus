package vpn

import (
	"context"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// regression_deletion_test.go pins the two round-4b deletion-path invariants:
//
//   - Finding 1: a user's PORTAL-scope peer identity is captured BEFORE the
//     deleting statement destroys its row, and the post-commit revoke event
//     carries it, so deleting a user tears the established session, its
//     forwarder route, its legacy transport state and its backend accounting
//     down exactly once.
//   - S1: Nexus routing cleanup reconciles LIVE SESSIONS against the desired
//     durable peers, so a DELETED connection whose upstream peer also vanished
//     is still torn down exactly once.
//
// Both are deletion-specific: the pre-existing round-4a regression
// (TestRegressionMissingUpstreamCleanupExactlyOnce) exercises
// ToggleConnection(..., false), where the durable row survives, and therefore
// never covered either path.

// TestRegressionUserDeleteTearsDownPortalSession proves finding 1: live
// handshake-admitted portal sessions whose owner's connections are DELETED (not
// toggled) are torn down by the post-commit revoke path — session absent,
// forwarder route absent, legacy transport state pruned, backend
// ActiveConnections decremented exactly once.
//
// Without the captured identity, portalSession cannot classify the session
// after the row is gone and the whole session leaks while the user and the
// connection are already absent from durable state.
//
// Exactly-once is observed through a SECOND live session on the same backend
// that must survive: the counter starts at 2 and must land on 1, so a
// mirror-decrement is visible (it would land on 0) while the pool's own
// clamp-at-zero would hide a lone double decrement.
func TestRegressionUserDeleteTearsDownPortalSession(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backend := svc.pool.GetActiveTunnels()[0]

	peerKey, connID := issueDurablePeer(t, svc, db, "regr-user-delete")
	userID := userIDFor(t, db, connID)
	conn, err := db.GetConnection(ctx, connID)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	assignedIP, _ := conn.ClientParams["assigned_ip"].(string)

	// A second user with its own live portal session: untouched by the
	// deleted user's revocation, and the witness for exactly-once.
	survivorKey, survivorConnID := issueDurablePeer(t, svc, db, "regr-user-delete-bystander")
	survivorConn, err := db.GetConnection(ctx, survivorConnID)
	if err != nil || survivorConn == nil {
		t.Fatalf("bystander connection: %v", err)
	}
	survivorIP, _ := survivorConn.ClientParams["assigned_ip"].(string)

	// Real established portal sessions: direct admission, registered forwarder routes
	// and live backend allocations.
	sess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, peerKey, assignedIP, backend.ID, conn.Name, models.SessionAdmissionDirect)
	if err != nil {
		t.Fatal(err)
	}
	survivorSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userIDFor(t, db, survivorConnID), survivorKey, survivorIP, backend.ID, survivorConn.Name, models.SessionAdmissionDirect)
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.SetConnectionCount(ctx, backend.ID, 2)
	for _, s := range []struct {
		sess *models.VPNSession
		conn string
		key  string
		ip   string
	}{
		{sess, connID, peerKey, assignedIP},
		{survivorSess, survivorConnID, survivorKey, survivorIP},
	} {
		if r := svc.forwarder.BeginRegisterSessionWithLimit(s.sess.ID, s.conn, s.key, s.ip, backend.ID, 0, 0); true {
			r.Wait()
		}
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); !ok {
		t.Fatal("setup: live session missing")
	}
	if svc.forwarder.RouteSessionID(peerKey) == "" {
		t.Fatal("setup: forwarder route missing")
	}

	// The production handler order: delete the user's connections, then the
	// user. The first call destroys the row the second dispatcher's
	// classification would otherwise have needed.
	if n, err := db.DeleteConnectionsByUser(ctx, userID); err != nil || n != 1 {
		t.Fatalf("delete user connections: n=%d err=%v", n, err)
	}
	if ok, err := db.DeleteUser(ctx, userID); !ok || err != nil {
		t.Fatalf("delete user: ok=%v err=%v", ok, err)
	}

	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); ok {
		t.Fatalf("portal session of a deleted user survived: %+v", snap)
	}
	if route := svc.forwarder.RouteSessionID(peerKey); route != "" {
		t.Fatalf("deleted user's session kept its forwarder route: %q", route)
	}
	after, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil || after.ActiveConnections != 1 {
		t.Fatalf("backend counter after user delete = %d, want 1 (one survivor, exactly one decrement; err: %v)", after.ActiveConnections, err)
	}
	// The bystander user is completely unaffected.
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(survivorKey); !ok {
		t.Fatal("another user's portal session was torn down by this user's deletion")
	}
	if route := svc.forwarder.RouteSessionID(survivorKey); route == "" {
		t.Fatal("another user's forwarder route was retired by this user's deletion")
	}
}

// TestRegressionConnectionDeleteCleansUpRouting proves S1: with the durable
// connection DELETED and the upstream peer also gone, reconciliation still
// performs exactly-once Nexus-side teardown of the live session, its forwarder
// route and its backend accounting.
//
// The pre-existing round-4a regression used ToggleConnection(..., false),
// where the user_connections row survives and the durable enumeration still
// sees the peer key. With a deleted row the durable enumeration is blind AND
// removeDriftedPeers is blind (it walks the upstream device), so the session
// leaked while reconciliation reported success.
//
// The revoke dispatcher is detached for the call on purpose: the deletion's own
// post-commit event is not what is under test here, so only reconciliation may
// perform the teardown. That is what makes the test fail on the unfixed tree.
func TestRegressionConnectionDeleteCleansUpRouting(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backend := svc.pool.GetActiveTunnels()[0]

	peerKey, connID := issueDurablePeer(t, svc, db, "regr-conn-delete")
	e, err := svc.NewIngressEngine(ctx, "regr-conn-delete-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	userID := userIDFor(t, db, connID)
	conn, err := db.GetConnection(ctx, connID)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	assignedIP, _ := conn.ClientParams["assigned_ip"].(string)

	// A live routing session, as the engine admits it.
	sess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, peerKey, assignedIP, backend.ID, conn.Name, models.SessionAdmissionIngress)
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

	// The upstream peer drifts away first, so removeDriftedPeers cannot see
	// it either: the durable row AND the upstream peer are both gone.
	if err := e.Portal().RemovePeer(peerKey); err != nil {
		t.Fatal(err)
	}

	teardowns := 0
	var teardownMu sync.Mutex
	svc.SetPreRevokeCloseHookForTest(func(peer, _ string) {
		if peer != peerKey {
			return
		}
		teardownMu.Lock()
		teardowns++
		teardownMu.Unlock()
	})
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })
	detach := db.SubscribePeerRevokes(revokeDispatcherRecorderFunc(func(context.Context, database.PeerRevokeEvent) {}))
	t.Cleanup(func() {
		// Restore the production dispatcher before the engine's own teardown
		// path runs: the unsubscribe closure only clears the slot when the
		// LAST installed recorder is still the one it installed.
		svc.mu.Lock()
		db.SubscribePeerRevokes(svc)
		svc.mu.Unlock()
		detach()
	})

	// DELETION, not a toggle. The connection is gone from durable state
	// before the reconcile, so cleanup can only find the session by walking
	// the live session set.
	if ok, err := db.DeleteConnection(ctx, connID); !ok || err != nil {
		t.Fatalf("delete connection: ok=%v err=%v", ok, err)
	}
	if _, err := db.GetConnection(ctx, connID); err != nil {
		t.Fatalf("connection must be gone from durable state: %v", err)
	}
	if err := e.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile with deleted connection and missing upstream peer: %v", err)
	}

	teardownMu.Lock()
	count := teardowns
	teardownMu.Unlock()
	if count != 1 {
		t.Fatalf("routing teardown ran %d times for the deleted connection, want exactly 1", count)
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); ok {
		t.Fatal("session of a deleted connection survived routing cleanup")
	}
	if route := svc.forwarder.RouteSessionID(peerKey); route != "" {
		t.Fatalf("deleted connection's session kept its forwarder route: %q", route)
	}
	tunAfter, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Fatalf("backend counter after deleted-connection cleanup = %d, want 0 (err: %v)", tunAfter.ActiveConnections, err)
	}
	// A second reconcile finds nothing left: exactly-once.
	if err := e.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	teardownMu.Lock()
	count = teardowns
	teardownMu.Unlock()
	if count != 1 {
		t.Fatalf("second reconcile re-ran teardown: %d total, want still 1", count)
	}
}

// TestRegressionDeletionPathsSpareForeignSessions is the non-regression half:
// neither deletion path may touch a regular server peer (server_id != 0) or a
// legacy server tunnel session. Both are outside the ingress engine's domain
// and keep their own pre-existing lifecycle.
func TestRegressionDeletionPathsSpareForeignSessions(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backend := svc.pool.GetActiveTunnels()[0]

	// A portal peer: the one that MUST be cleaned up.
	portalKey, portalConnID := issueDurablePeer(t, svc, db, "regr-spare-portal")
	// A regular server peer and a legacy server tunnel: the ones that must NOT.
	foreignUserID, err := db.CreateUser(ctx, &models.User{Username: "regr-spare-foreign", Role: "user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	serverConnID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   foreignUserID,
		ServerID: 1, // regular server peer, not the portal
		Protocol: "awg",
		ClientID: "regr-spare-server-peer",
		Name:     "server peer",
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnelConnID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   foreignUserID,
		ServerID: 2, // legacy server tunnel
		Protocol: "awg",
		ClientID: "regr-spare-server-tunnel",
		Name:     "server tunnel",
	})
	if err != nil {
		t.Fatal(err)
	}

	e, err := svc.NewIngressEngine(ctx, "regr-spare-portal-tun", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })

	portalConn, err := db.GetConnection(ctx, portalConnID)
	if err != nil || portalConn == nil {
		t.Fatalf("portal connection: %v", err)
	}
	portalIP, _ := portalConn.ClientParams["assigned_ip"].(string)

	// Three live sessions on one backend: the portal peer and the two
	// foreign ones.
	portalSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userIDFor(t, db, portalConnID), portalKey, portalIP, backend.ID, portalConn.Name, models.SessionAdmissionIngress)
	if err != nil {
		t.Fatal(err)
	}
	serverSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, foreignUserID, "regr-spare-server-peer", "10.100.9.11", backend.ID, "server peer", models.SessionAdmissionDirect)
	if err != nil {
		t.Fatal(err)
	}
	tunnelSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, foreignUserID, "regr-spare-server-tunnel", "10.100.9.12", backend.ID, "server tunnel", models.SessionAdmissionDirect)
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.SetConnectionCount(ctx, backend.ID, 3)
	for _, s := range []struct {
		sess *models.VPNSession
		conn string
		key  string
		ip   string
	}{
		{portalSess, portalConnID, portalKey, portalIP},
		{serverSess, serverConnID, "regr-spare-server-peer", "10.100.9.11"},
		{tunnelSess, tunnelConnID, "regr-spare-server-tunnel", "10.100.9.12"},
	} {
		if r := svc.forwarder.BeginRegisterSessionWithLimit(s.sess.ID, s.conn, s.key, s.ip, backend.ID, 0, 0); true {
			r.Wait()
		}
	}

	// Path 1 (finding 1): the foreign user's connections are DELETED. Only
	// PORTAL-scope identities are captured, so both foreign sessions must be
	// left alone.
	if n, err := db.DeleteConnectionsByUser(ctx, foreignUserID); err != nil || n != 2 {
		t.Fatalf("delete foreign user connections: n=%d err=%v", n, err)
	}
	// Path 2 (S1): the upstream portal peer of the portal connection is gone
	// AND its durable row is deleted, so only the live session set can find
	// it. The foreign sessions must not be collateral.
	_ = e.Portal().RemovePeer(portalKey)
	if ok, err := db.DeleteConnection(ctx, portalConnID); !ok || err != nil {
		t.Fatalf("delete portal connection: ok=%v err=%v", ok, err)
	}
	if err := e.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer("regr-spare-server-peer"); !ok {
		t.Fatal("regular server peer session was torn down by a deletion path")
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer("regr-spare-server-tunnel"); !ok {
		t.Fatal("legacy server tunnel session was torn down by a deletion path")
	}
	if svc.forwarder.RouteSessionID("regr-spare-server-peer") == "" {
		t.Fatal("regular server peer lost its forwarder route to a deletion path")
	}
	if svc.forwarder.RouteSessionID("regr-spare-server-tunnel") == "" {
		t.Fatal("legacy server tunnel lost its forwarder route to a deletion path")
	}
	// The portal session, in contrast, is gone: this is the positive half of
	// the same reconciliation.
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(portalKey); ok {
		t.Fatal("deleted portal connection's session survived routing cleanup")
	}
	// Only the portal session's allocation was released: 3 live allocations
	// before, 2 foreign ones survive.
	tunAfter, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil || tunAfter.ActiveConnections != 2 {
		t.Fatalf("backend counter after foreign-sparing cleanup = %d, want 2 (err: %v)", tunAfter.ActiveConnections, err)
	}
}
