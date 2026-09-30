package vpn

// Regression coverage for issue #391 PR #400 round 4c, batch F.
//
// F1 — a routing-ownership transition. Reassigning a LIVE connection to
// another user, or recreating its durable row under a new connection id,
// leaves the upstream key and AllowedIP identical, so the reconciler's
// AllowedIP-only classification called the peer stable and the previous
// owner's Nexus routing session survived the move. The router's fast-path
// memo then kept admitting that session, because it compared only the
// assigned IP and the connection id.
//
// F2 — a fail-open upstream status failure. A device-status error returned
// from reconcileNow BEFORE any resolver withdrawal, so a peer the durable
// state no longer considers eligible kept its authorization and its routing
// session for as long as the device stayed unreachable.
//
// Both fixes are proven here through the real production path: the real
// resolver, the real router, the real admission primitive, the real
// forwarder and the real peer synchronizer. F1's headline test drives a
// real upstream client engine so the reassignment is proven end to end.

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// statusFailDevice fails ONLY the upstream status read and leaves peer
// edits working. It models a portal device whose status endpoint is
// unavailable while the rest of the control plane still works, so a
// reconcile in that state knows the durable desired set but not the
// upstream one — exactly the condition F2 must survive.
type statusFailDevice struct{ real portalPeerDevice }

func (d statusFailDevice) Status() (clientawg.Status, error) {
	return clientawg.Status{}, errors.New("injected device status failure")
}

func (d statusFailDevice) AddPeer(peer clientawg.Peer) error { return d.real.AddPeer(peer) }

func (d statusFailDevice) RemovePeer(key string) error { return d.real.RemovePeer(key) }

// countingDevice records every peer edit the reconciler makes, so a test can
// assert that a routing-ownership handoff causes NO upstream churn. The
// handoff's whole point is that the upstream peer is already exactly right.
type countingDevice struct {
	real     portalPeerDevice
	mu       sync.Mutex
	added    []string
	removed  []string
	statuses int
}

func (d *countingDevice) Status() (clientawg.Status, error) {
	d.mu.Lock()
	d.statuses++
	d.mu.Unlock()
	return d.real.Status()
}

func (d *countingDevice) AddPeer(peer clientawg.Peer) error {
	d.mu.Lock()
	d.added = append(d.added, peer.PublicKey)
	d.mu.Unlock()
	return d.real.AddPeer(peer)
}

func (d *countingDevice) RemovePeer(key string) error {
	d.mu.Lock()
	d.removed = append(d.removed, key)
	d.mu.Unlock()
	return d.real.RemovePeer(key)
}

func (d *countingDevice) churn() (added, removed []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.added...), append([]string(nil), d.removed...)
}

// revokeCounter counts the routing teardowns of one peer key, so a test can
// assert EXACTLY-once accounting instead of merely observing a teardown.
type revokeCounter struct {
	mu     sync.Mutex
	peer   string
	counts map[string]int
}

func newRevokeCounter(peerKey string) *revokeCounter {
	return &revokeCounter{peer: peerKey, counts: map[string]int{}}
}

func (c *revokeCounter) hook(peerKey, _ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if peerKey == c.peer {
		c.counts[peerKey]++
	}
}

func (c *revokeCounter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[c.peer]
}

// assertBackendCount reads one backend's live-session gauge.
func assertBackendCount(t *testing.T, svc *Service, backendID int64, want int) {
	t.Helper()
	tun, err := svc.pool.GetTunnelByID(backendID)
	if err != nil {
		t.Fatalf("backend %d: %v", backendID, err)
	}
	if tun.ActiveConnections != want {
		t.Fatalf("backend %d ActiveConnections = %d, want %d", backendID, tun.ActiveConnections, want)
	}
}

// assertTotalBackendCount sums the live-session gauge across every backend
// in the pool, so an assertion holds regardless of which backend admission
// selected for a peer.
func assertTotalBackendCount(t *testing.T, svc *Service, want int) {
	t.Helper()
	total := 0
	for _, tun := range svc.pool.ListTunnels() {
		live, err := svc.pool.GetTunnelByID(tun.ID)
		if err != nil {
			t.Fatalf("backend %d: %v", tun.ID, err)
		}
		total += live.ActiveConnections
	}
	if total != want {
		t.Fatalf("total live backend sessions = %d, want %d", total, want)
	}
}

// assertNoLiveSessionFor reports any live session still attributed to a
// superseded user for the peer.
func assertNoLiveSessionFor(t *testing.T, svc *Service, peerKey, userID string) {
	t.Helper()
	for _, sess := range svc.sessionMgr.ListActiveSessionsSnapshot() {
		if sess.PeerPublicKey == peerKey && sess.UserID == userID {
			t.Fatalf("a routing session is still attributed to the previous owner %s: %+v", userID, sess)
		}
	}
}

// admitThroughRouter drives one plaintext packet through the engine's REAL
// router, producing a real ingress-admitted session through the real
// admission primitive without a full upstream crypto handshake.
func admitThroughRouter(t *testing.T, svc *Service, engine *IngressEngine, ip netip.Addr, marker uint32) models.VPNSession {
	t.Helper()
	pkt := engineUDPPacket(ip, netip.MustParseAddr("198.51.100.7"), marker)
	if err := engine.Router().HandlePacket(pkt); err != nil {
		t.Fatalf("ingress admission for %s: %v", ip, err)
	}
	sess, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKeyOf(t, svc, ip))
	if !ok {
		t.Fatalf("ingress admission did not create a session for %s", ip)
	}
	return sess
}

// peerKeyOf resolves the peer key the durable lease for ip is issued to.
func peerKeyOf(t *testing.T, svc *Service, ip netip.Addr) string {
	t.Helper()
	assignments, err := svc.db.GetVPNClientIPAssignments(t.Context())
	if err != nil {
		t.Fatalf("read client IP assignments: %v", err)
	}
	for _, a := range assignments {
		parsed, err := netip.ParseAddr(a.AssignedIP)
		if err == nil && parsed == ip {
			return a.PeerKey
		}
	}
	t.Fatalf("no durable lease for %s", ip)
	return ""
}

// portalConnOf returns the durable portal connection that owns a peer key.
func portalConnOf(t *testing.T, db *database.DB, peerKey string) models.UserConnection {
	t.Helper()
	conn, err := db.GetConnectionByClientID(t.Context(), peerKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection for %s: %v", peerKey, err)
	}
	return *conn
}

// createPeerForUser issues one real portal peer owned by a fresh user and
// returns it with its rendered config, its durable owner and its row id.
func createPeerForUser(t *testing.T, svc *Service, db *database.DB, username string) (enginePeer, string, string, string) {
	t.Helper()
	peer, saved := newEnginePeer(t, svc, db, username)
	conn := portalConnOf(t, db, peer.publicKey)
	return peer, saved, conn.UserID, conn.ID
}

// TestPeerSyncUserReassignmentRetiresOwnershipAndReadmits is F1's headline
// case, driven end to end through a REAL upstream client engine: a live
// ingress session for user A, then UpdateConnection moves the connection to
// user B with the same key and the same assigned IP.
//
// The previous owner's session must be retired, fresh admission must happen
// under user B, the routing attribution must follow the move, and the
// backend gauge must be decremented for A exactly once and incremented for
// B exactly once. Nothing may remain attributed to A.
func TestPeerSyncUserReassignmentRetiresOwnershipAndReadmits(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, saved, oldUser, connID := createPeerForUser(t, svc, db, "reassign-source")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "reassign-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	// Live traffic for user A over a real upstream client.
	want := engineUDPPacket(ip, netip.MustParseAddr("198.51.100.7"), 0x391F0001)
	uc := startEngineUpstreamClient(t, saved, "reassign-client")
	uc.inject(t, want)
	stopPump := pumpEnginePacketUntil(t, uc, want, nil)
	oldSess, ok := waitForSession(t, svc, peer.publicKey)
	if !ok {
		t.Fatal("initial ingress admission never ran for user A")
	}
	queue, ok := svc.forwarder.GetBackendPacketChannel(oldSess.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing", oldSess.BackendTunnelID)
	}
	awaitEngineBackendPacket(t, queue, want)
	// The peer goes quiet from here: no pump means nothing can re-admit
	// behind the reconciler's back, so every assertion below is about the
	// reconciler's own doing.
	stopPump()

	backendID := oldSess.BackendTunnelID
	assertBackendCount(t, svc, backendID, 1)
	if got := svc.freshSessionRegistrations.Load(); got != 1 {
		t.Fatalf("fresh session registrations = %d, want 1", got)
	}
	revokes := newRevokeCounter(peer.publicKey)
	svc.SetPreRevokeCloseHookForTest(revokes.hook)
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

	// The durable move: same connection row, same key, same IP, new owner.
	newUser, err := db.CreateUser(ctx, &models.User{Username: "reassign-target", Role: "user", Enabled: true})
	if err != nil {
		t.Fatalf("create target user: %v", err)
	}
	if ok, err := db.UpdateConnection(ctx, connID, map[string]any{"user_id": newUser}); !ok || err != nil {
		t.Fatalf("durable reassignment: ok=%v err=%v", ok, err)
	}
	// Count every upstream peer edit from here: a handoff must cost one
	// Nexus-side re-admission, never an AWG protocol churn.
	counter := &countingDevice{real: engine.Portal()}
	engine.peerSync.setPortalDeviceForTest(counter)
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile after reassignment: %v", err)
	}
	if added, removed := counter.churn(); len(added) != 0 || len(removed) != 0 {
		t.Fatalf("a pure user reassignment churned upstream AWG state: added=%v removed=%v", added, removed)
	}

	// Fail-closed hand-off: the lease now resolves to the new owner.
	owner, tracked := engine.Resolver().Lookup(ip)
	if !tracked || owner.UserID != newUser || owner.ConnectionID != connID {
		t.Fatalf("resolver did not hand the lease to the new owner: tracked=%v owner=%+v", tracked, owner)
	}
	// The previous owner's session is gone, torn down exactly once, and the
	// backend gauge released exactly once.
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("previous owner's routing session survived the reassignment: %+v", snap)
	}
	if got := revokes.get(); got != 1 {
		t.Fatalf("routing teardown ran %d times, want exactly 1", got)
	}
	assertBackendCount(t, svc, backendID, 0)
	assertNoLiveSessionFor(t, svc, peer.publicKey, oldUser)
	if route := svc.forwarder.RouteSessionID(peer.publicKey); route != "" {
		t.Fatalf("previous owner's forwarder route survived: %q", route)
	}

	// Fresh admission under the new durable owner, on the untouched upstream
	// peer (the reassignment must not churn AWG protocol state).
	fresh := engineUDPPacket(ip, netip.MustParseAddr("198.51.100.7"), 0x391F0002)
	uc.inject(t, fresh)
	stopPump = pumpEnginePacketUntil(t, uc, fresh, nil)
	newSess, ok := waitForSession(t, svc, peer.publicKey)
	if !ok {
		t.Fatal("fresh admission under the new owner never ran")
	}
	freshQueue, ok := svc.forwarder.GetBackendPacketChannel(newSess.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing after reassignment", newSess.BackendTunnelID)
	}
	awaitEngineBackendPacket(t, freshQueue, fresh)
	stopPump()

	if newSess.ID == oldSess.ID {
		t.Fatal("reassignment reused the previous owner's routing session")
	}
	if newSess.UserID != newUser {
		t.Fatalf("fresh session attributed to %s, want the new owner %s", newSess.UserID, newUser)
	}
	if newSess.AssignedIP != peer.assignedIP {
		t.Fatalf("fresh session IP %q, want the unchanged durable lease %q", newSess.AssignedIP, peer.assignedIP)
	}
	if got := svc.forwarder.RouteSessionID(peer.publicKey); got != newSess.ID {
		t.Fatalf("route session %q, want the fresh session %q", got, newSess.ID)
	}
	// Exactly one increment for the new owner, and no second teardown.
	assertBackendCount(t, svc, newSess.BackendTunnelID, 1)
	if got := svc.freshSessionRegistrations.Load(); got != 2 {
		t.Fatalf("fresh session registrations = %d, want exactly 2 (one per owner)", got)
	}
	if got := revokes.get(); got != 1 {
		t.Fatalf("re-admission re-ran the teardown: %d total, want still 1", got)
	}
	assertNoLiveSessionFor(t, svc, peer.publicKey, oldUser)
}

// TestPeerSyncConnectionIDReassignmentRetiresOwnership proves the same
// invariant for a durable connection-ID change: the row is recreated with a
// new id and the same key and IP, so neither AllowedIP nor the peer key
// moves, yet the previous owner's routing session must still be retired and
// fresh admission required.
//
// The notify worker is stopped and the immediate revoke dispatcher detached
// for the row surgery, so the ONLY actor that can retire the session is the
// reconciler under test.
func TestPeerSyncConnectionIDReassignmentRetiresOwnership(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _, oldUser, oldConnID := createPeerForUser(t, svc, db, "reconn-source")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "reconn-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	oldSess := admitThroughRouter(t, svc, engine, ip, 0x391F0011)
	backendID := oldSess.BackendTunnelID
	assertBackendCount(t, svc, backendID, 1)

	revokes := newRevokeCounter(peer.publicKey)
	svc.SetPreRevokeCloseHookForTest(revokes.hook)
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

	// Isolate the reconciler: no async pass may observe the row surgery, and
	// the delete's immediate post-commit revoke must not do the teardown the
	// test is measuring.
	if err := engine.stopPeerSyncWorker(); err != nil {
		t.Fatalf("stop notify worker: %v", err)
	}
	detachRevokes := db.SubscribePeerRevokes(revokeDispatcherRecorderFunc(func(context.Context, database.PeerRevokeEvent) {}))
	defer detachRevokes()
	t.Cleanup(func() {
		svc.mu.Lock()
		db.SubscribePeerRevokes(svc)
		svc.mu.Unlock()
	})

	const newConnID = "391-round4c-recreated-connection"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:           newConnID,
		UserID:       oldUser,
		ServerID:     0,
		Protocol:     "awg",
		ClientID:     peer.publicKey,
		Name:         "recreated connection",
		ClientParams: map[string]any{"assigned_ip": peer.assignedIP},
	}); err != nil {
		t.Fatalf("create replacement connection row: %v", err)
	}
	if ok, err := db.DeleteConnection(ctx, oldConnID); !ok || err != nil {
		t.Fatalf("delete superseded connection row: ok=%v err=%v", ok, err)
	}
	if err := engine.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile after connection-id reassignment: %v", err)
	}

	owner, tracked := engine.Resolver().Lookup(ip)
	if !tracked || owner.ConnectionID != newConnID || owner.UserID != oldUser {
		t.Fatalf("resolver did not publish the recreated connection: tracked=%v owner=%+v", tracked, owner)
	}
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("session of the superseded connection survived: %+v", snap)
	}
	if got := revokes.get(); got != 1 {
		t.Fatalf("routing teardown ran %d times, want exactly 1", got)
	}
	assertBackendCount(t, svc, backendID, 0)
	assertNoLiveSessionFor(t, svc, peer.publicKey, oldUser)
	if route := svc.forwarder.RouteSessionID(peer.publicKey); route != "" {
		t.Fatalf("superseded connection's forwarder route survived: %q", route)
	}

	// Fresh admission binds to the recreated connection.
	newSess := admitThroughRouter(t, svc, engine, ip, 0x391F0012)
	if newSess.ID == oldSess.ID {
		t.Fatal("connection-id reassignment reused the superseded session")
	}
	if newSess.UserID != oldUser {
		t.Fatalf("fresh session attributed to %s, want %s", newSess.UserID, oldUser)
	}
	if !svc.forwarder.HasSessionRoute(peer.publicKey, newSess.ID, newConnID, peer.assignedIP, newSess.BackendTunnelID) {
		t.Fatal("fresh route is not bound to the recreated connection id")
	}
	assertBackendCount(t, svc, newSess.BackendTunnelID, 1)
	if got := revokes.get(); got != 1 {
		t.Fatalf("re-admission re-ran the teardown: %d total, want still 1", got)
	}
}

// TestPeerSyncUnchangedOwnershipKeepsSession is F1's no-churn
// non-regression: a connection whose user and connection id are untouched
// must keep its live session, its route and its backend gauge. The
// ownership logic must not turn ordinary reconciles into churn.
func TestPeerSyncUnchangedOwnershipKeepsSession(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _, user, _ := createPeerForUser(t, svc, db, "reassign-stable")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "reassign-stable-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	sess := admitThroughRouter(t, svc, engine, ip, 0x391F0021)
	backendID := sess.BackendTunnelID
	assertBackendCount(t, svc, backendID, 1)
	registrations := svc.freshSessionRegistrations.Load()
	revokes := newRevokeCounter(peer.publicKey)
	svc.SetPreRevokeCloseHookForTest(revokes.hook)
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

	for range 3 {
		if err := engine.peerSync.reconcileNow(ctx); err != nil {
			t.Fatalf("steady-state reconcile: %v", err)
		}
	}

	after, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
	if !ok {
		t.Fatal("an unchanged connection lost its routing session to the ownership logic")
	}
	if after.ID != sess.ID {
		t.Fatalf("session churned across a no-op reconcile: %s -> %s", sess.ID, after.ID)
	}
	if after.UserID != user || after.AssignedIP != peer.assignedIP {
		t.Fatalf("stable session attribution drifted: %+v", after)
	}
	if got := svc.forwarder.RouteSessionID(peer.publicKey); got != sess.ID {
		t.Fatalf("route session %q, want the unchanged %q", got, sess.ID)
	}
	if got := svc.freshSessionRegistrations.Load(); got != registrations {
		t.Fatalf("fresh session registrations moved from %d to %d on a no-op reconcile", registrations, got)
	}
	if got := revokes.get(); got != 0 {
		t.Fatalf("a no-op reconcile tore the session down %d times", got)
	}
	assertBackendCount(t, svc, backendID, 1)
	owner, tracked := engine.Resolver().Lookup(ip)
	if !tracked || owner.UserID != user {
		t.Fatalf("stable resolver attribution drifted: tracked=%v owner=%+v", tracked, owner)
	}
}

// TestPeerSyncOwnershipTransitionSparesForeignSessions is F1's scope
// non-regression: the ownership logic belongs to the portal alone. A
// regular server peer and a legacy server tunnel sharing the backend must
// survive a portal connection's reassignment untouched — session, route and
// gauge — while the portal session itself is retired.
func TestPeerSyncOwnershipTransitionSparesForeignSessions(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backend := svc.pool.GetActiveTunnels()[0]

	portalPeer, _, portalUser, portalConnID := createPeerForUser(t, svc, db, "reassign-portal-scope")
	portalIP := portalPeer.assignedIP
	foreignUser, err := db.CreateUser(ctx, &models.User{Username: "reassign-foreign", Role: "user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const serverPeerKey = "reassign-server-peer"
	const tunnelKey = "reassign-server-tunnel"
	for _, c := range []*models.UserConnection{
		{UserID: foreignUser, ServerID: 1, Protocol: "awg", ClientID: serverPeerKey, Name: "server peer"},
		{UserID: foreignUser, ServerID: 2, Protocol: "awg", ClientID: tunnelKey, Name: "server tunnel"},
	} {
		if _, err := db.CreateConnection(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := svc.NewIngressEngine(ctx, "reassign-scope-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	portalSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, portalUser, portalPeer.publicKey, portalIP, backend.ID, "portal", models.SessionAdmissionIngress)
	if err != nil {
		t.Fatal(err)
	}
	serverSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, foreignUser, serverPeerKey, "10.100.9.41", backend.ID, "server peer", models.SessionAdmissionHandshake)
	if err != nil {
		t.Fatal(err)
	}
	tunnelSess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, foreignUser, tunnelKey, "10.100.9.42", backend.ID, "server tunnel", models.SessionAdmissionHandshake)
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.SetConnectionCount(ctx, backend.ID, 3)
	for _, live := range []struct {
		sess *models.VPNSession
		conn string
		key  string
		ip   string
	}{
		{portalSess, portalConnID, portalPeer.publicKey, portalIP},
		{serverSess, "reassign-server-conn", serverPeerKey, "10.100.9.41"},
		{tunnelSess, "reassign-tunnel-conn", tunnelKey, "10.100.9.42"},
	} {
		if r := svc.forwarder.BeginRegisterSessionWithLimit(live.sess.ID, live.conn, live.key, live.ip, backend.ID, 0, 0); true {
			r.Wait()
		}
	}

	newUser, err := db.CreateUser(ctx, &models.User{Username: "reassign-portal-next", Role: "user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.UpdateConnection(ctx, portalConnID, map[string]any{"user_id": newUser}); !ok || err != nil {
		t.Fatalf("durable reassignment: ok=%v err=%v", ok, err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile after reassignment: %v", err)
	}

	// Foreign sessions are not this engine's domain.
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(serverPeerKey); !ok {
		t.Fatal("regular server peer was torn down by a portal ownership transition")
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(tunnelKey); !ok {
		t.Fatal("legacy server tunnel was torn down by a portal ownership transition")
	}
	if svc.forwarder.RouteSessionID(serverPeerKey) == "" || svc.forwarder.RouteSessionID(tunnelKey) == "" {
		t.Fatal("a foreign session lost its forwarder route to a portal ownership transition")
	}
	// Only the portal session's allocation was released.
	assertBackendCount(t, svc, backend.ID, 2)
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(portalPeer.publicKey); ok {
		t.Fatal("the reassigned portal session was not retired")
	}
}

// TestPeerSyncStatusFailureStillRevokesIneligibleLivePeer is F2's headline
// case, over a real upstream client: an established peer with live traffic,
// a user whose traffic quota is exhausted so the peer becomes ineligible,
// and a device whose status read fails. The reconcile must still withdraw
// the peer's authorization and retire its routing session — the device
// being unreachable must never be the reason stale authorization survives.
func TestPeerSyncStatusFailureStillRevokesIneligibleLivePeer(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, saved, _, _ := createPeerForUser(t, svc, db, "status-fail-live")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "status-fail-live-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	want := engineUDPPacket(ip, netip.MustParseAddr("198.51.100.7"), 0x391F0031)
	uc := startEngineUpstreamClient(t, saved, "status-fail-live-client")
	uc.inject(t, want)
	stopPump := pumpEnginePacketUntil(t, uc, want, nil)
	sess, ok := waitForSession(t, svc, peer.publicKey)
	if !ok {
		t.Fatal("initial ingress admission never ran")
	}
	queue, ok := svc.forwarder.GetBackendPacketChannel(sess.BackendTunnelID)
	if !ok {
		t.Fatalf("backend %d queue missing", sess.BackendTunnelID)
	}
	awaitEngineBackendPacket(t, queue, want)
	stopPump()
	backendID := sess.BackendTunnelID
	assertBackendCount(t, svc, backendID, 1)

	conn := portalConnOf(t, db, peer.publicKey)
	revokes := newRevokeCounter(peer.publicKey)
	svc.SetPreRevokeCloseHookForTest(revokes.hook)
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

	// The device's status read starts failing BEFORE the durable change, so
	// the enforcement pass for that change runs into the failure.
	engine.peerSync.setPortalDeviceForTest(statusFailDevice{real: engine.Portal()})
	if ok, err := db.UpdateUser(ctx, conn.UserID, map[string]any{"traffic_limit": int64(10)}); !ok || err != nil {
		t.Fatalf("set quota: %v", err)
	}
	if _, err := db.AddUserTraffic(ctx, conn.UserID, 6, 4); err != nil {
		t.Fatalf("cross quota: %v", err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err == nil {
		t.Fatal("reconcile reported success while the device status read was failing")
	}

	// Fail-closed: authorization withdrawn and the routing session retired
	// even though the upstream peer set could not be read.
	if _, tracked := engine.Resolver().Lookup(ip); tracked {
		t.Fatal("a status failure left the ineligible peer authorized")
	}
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("a status failure left the ineligible peer's routing session alive: %+v", snap)
	}
	if got := revokes.get(); got != 1 {
		t.Fatalf("routing teardown ran %d times, want exactly 1", got)
	}
	assertBackendCount(t, svc, backendID, 0)
	// The peer's own traffic no longer resolves to any owner, so the fast
	// path cannot keep forwarding it.
	before := engine.Router().StatsSnapshot()
	_ = engine.Router().HandlePacket(engineUDPPacket(ip, netip.MustParseAddr("198.51.100.7"), 0x391F0032))
	after := engine.Router().StatsSnapshot()
	if after.UnmappedSourceIPDrops != before.UnmappedSourceIPDrops+1 {
		t.Fatalf("traffic from the revoked peer was not dropped as unmapped: %+v", after)
	}
	// The upstream peer itself is untouched: the reconciler must not guess
	// about a peer set it could not read. The next successful pass removes it.
	if !syncHasPeer(t, engine, peer.publicKey, peer.assignedIP) {
		t.Fatal("the status-failure pass mutated the upstream peer set it could not read")
	}
}

// TestPeerSyncStatusFailureWithdrawsReassignedOwnership covers the other
// half of the fail-closed pass: a durable owner move observed while the
// device status read fails must still retire the previous owner's session
// and drop the stale resolver entry. The new owner is not published — it
// cannot be verified without a status — but the old one stops authorizing.
func TestPeerSyncStatusFailureWithdrawsReassignedOwnership(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _, oldUser, connID := createPeerForUser(t, svc, db, "status-fail-reassign")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "status-fail-reassign-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})

	sess := admitThroughRouter(t, svc, engine, ip, 0x391F0041)
	backendID := sess.BackendTunnelID
	assertBackendCount(t, svc, backendID, 1)
	revokes := newRevokeCounter(peer.publicKey)
	svc.SetPreRevokeCloseHookForTest(revokes.hook)
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

	engine.peerSync.setPortalDeviceForTest(statusFailDevice{real: engine.Portal()})
	newUser, err := db.CreateUser(ctx, &models.User{Username: "status-fail-reassign-next", Role: "user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.UpdateConnection(ctx, connID, map[string]any{"user_id": newUser}); !ok || err != nil {
		t.Fatalf("durable reassignment: ok=%v err=%v", ok, err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err == nil {
		t.Fatal("reconcile reported success while the device status read was failing")
	}

	if _, tracked := engine.Resolver().Lookup(ip); tracked {
		t.Fatal("the previous owner's authorization survived a status failure across a reassignment")
	}
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("the previous owner's session survived a status failure across a reassignment: %+v", snap)
	}
	if got := revokes.get(); got != 1 {
		t.Fatalf("routing teardown ran %d times, want exactly 1", got)
	}
	assertBackendCount(t, svc, backendID, 0)
	assertNoLiveSessionFor(t, svc, peer.publicKey, oldUser)
}

// TestPeerSyncStatusFailureWithdrawsMovedAddress is the cross-user
// attribution guard for the fail-closed withdrawal: a published record whose
// ASSIGNED ADDRESS the durable state has since given to a different peer must
// be withdrawn even when its key, connection and user all still match the
// desired set. Comparing user and connection alone left the previous owner
// authorized on an IP the durable state had reassigned to someone else — the
// same class of defect as F1, reached through F2's path.
func TestPeerSyncStatusFailureWithdrawsMovedAddress(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _, oldUser, connID := createPeerForUser(t, svc, db, "status-fail-moved")
	ip := netip.MustParseAddr(peer.assignedIP)
	engine := startEngine(t, svc, "status-fail-moved-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	admitThroughRouter(t, svc, engine, ip, 0x391F0071)

	// The device stops answering, so the withdrawal must come from durable
	// state alone.
	engine.peerSync.setPortalDeviceForTest(statusFailDevice{real: engine.Portal()})

	// The durable lease for this peer's KEY moves to a different address,
	// and the address it used to hold is now leased to a different user.
	// Key, connection and user are untouched — only the address moves.
	movedIP := "10.100.0.77"
	conn, err := db.GetConnection(ctx, connID)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	params := map[string]any{}
	for k, v := range conn.ClientParams {
		params[k] = v
	}
	params["assigned_ip"] = movedIP
	if ok, err := db.UpdateConnection(ctx, connID, map[string]any{"client_params": params}); !ok || err != nil {
		t.Fatalf("durable lease move: ok=%v err=%v", ok, err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err == nil {
		t.Fatal("reconcile reported success while the device status read was failing")
	}

	// The old address must no longer answer for the previous owner.
	if owner, tracked := engine.Resolver().Lookup(ip); tracked {
		t.Fatalf("the previous owner is still authorized on an address the durable state reassigned: %+v", owner)
	}
	// The peer's new address is not published either: without a readable
	// device the reconciler must not grant authorization it cannot verify.
	if owner, tracked := engine.Resolver().Lookup(netip.MustParseAddr(movedIP)); tracked {
		t.Fatalf("an unverifiable new address was granted authorization: %+v", owner)
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatal("the previous owner's routing session survived a status failure across a lease move")
	}
	assertNoLiveSessionFor(t, svc, peer.publicKey, oldUser)
	// The upstream peer set was not touched: a pass that could not read it
	// must not mutate it.
	if !syncHasPeer(t, engine, peer.publicKey, peer.assignedIP) {
		t.Fatal("the status-failure pass mutated the upstream peer set it could not read")
	}
}

// TestPeerSyncStatusFailureSparesEligiblePeers is F2's no-over-correction
// non-regression: a device-status failure must not disconnect peers the
// durable state still considers eligible. With two established portal
// peers, revoking one must leave the other's session, route, resolver entry
// and gauge share completely intact.
func TestPeerSyncStatusFailureSparesEligiblePeers(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	kept, _, _, keptConnID := createPeerForUser(t, svc, db, "status-fail-kept")
	revoked, _, _, revokedConnID := createPeerForUser(t, svc, db, "status-fail-revoked")
	keptIP := netip.MustParseAddr(kept.assignedIP)
	revokedIP := netip.MustParseAddr(revoked.assignedIP)
	engine := startEngine(t, svc, "status-fail-spare-portal", []clientawg.Peer{
		{PublicKey: kept.publicKey, AllowedIP: netip.PrefixFrom(keptIP, 32)},
		{PublicKey: revoked.publicKey, AllowedIP: netip.PrefixFrom(revokedIP, 32)},
	})

	keptSess := admitThroughRouter(t, svc, engine, keptIP, 0x391F0051)
	revokedSess := admitThroughRouter(t, svc, engine, revokedIP, 0x391F0052)
	assertTotalBackendCount(t, svc, 2)
	_ = revokedSess

	revokes := newRevokeCounter(revoked.publicKey)
	svc.SetPreRevokeCloseHookForTest(revokes.hook)
	t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

	engine.peerSync.setPortalDeviceForTest(statusFailDevice{real: engine.Portal()})
	if ok, err := db.ToggleConnection(ctx, revokedConnID, false); !ok || err != nil {
		t.Fatalf("durable disable: %v", err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err == nil {
		t.Fatal("reconcile reported success while the device status read was failing")
	}

	// The ineligible peer is gone from the authorization map...
	if _, tracked := engine.Resolver().Lookup(revokedIP); tracked {
		t.Fatal("the ineligible peer kept its authorization across a status failure")
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(revoked.publicKey); ok {
		t.Fatal("the ineligible peer's routing session survived a status failure")
	}
	// ...and the eligible peer is untouched: a fail-closed fix that
	// disconnects everyone is not a fix.
	keptAfter, ok := svc.sessionMgr.GetSessionSnapshotByPeer(kept.publicKey)
	if !ok {
		t.Fatal("a status failure tore down a still-eligible peer's routing session")
	}
	if keptAfter.ID != keptSess.ID {
		t.Fatalf("a status failure churned a still-eligible peer's session: %s -> %s", keptSess.ID, keptAfter.ID)
	}
	owner, tracked := engine.Resolver().Lookup(keptIP)
	if !tracked || owner.UserID != keptAfter.UserID || owner.ConnectionID != keptConnID {
		t.Fatalf("a status failure disturbed an eligible peer's ownership: tracked=%v owner=%+v", tracked, owner)
	}
	if got := svc.forwarder.RouteSessionID(kept.publicKey); got != keptSess.ID {
		t.Fatalf("a status failure disturbed an eligible peer's route: %q, want %q", got, keptSess.ID)
	}
	if err := engine.Router().HandlePacket(engineUDPPacket(keptIP, netip.MustParseAddr("198.51.100.7"), 0x391F0053)); err != nil {
		t.Fatalf("a status failure broke the still-eligible peer's forwarding: %v", err)
	}
	assertTotalBackendCount(t, svc, 1)
	if got := revokes.get(); got != 1 {
		t.Fatalf("teardown ran %d times, want exactly 1", got)
	}
}

// TestPeerSyncStatusFailureRecoversOnNextReconcile is F2's recovery case:
// after a status failure the pass must not leave a permanently-broken peer
// set. Once the device answers again, one reconcile converges the
// authorization map, the upstream device and the routing sessions in both
// directions — the revoked peer disappears, the eligible peer keeps
// working, and a re-enabled peer comes back with fresh admission.
func TestPeerSyncStatusFailureRecoversOnNextReconcile(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	kept, _, _, keptConnID := createPeerForUser(t, svc, db, "status-fail-recover-kept")
	revoked, _, _, revokedConnID := createPeerForUser(t, svc, db, "status-fail-recover-revoked")
	keptIP := netip.MustParseAddr(kept.assignedIP)
	revokedIP := netip.MustParseAddr(revoked.assignedIP)
	engine := startEngine(t, svc, "status-fail-recover-portal", []clientawg.Peer{
		{PublicKey: kept.publicKey, AllowedIP: netip.PrefixFrom(keptIP, 32)},
		{PublicKey: revoked.publicKey, AllowedIP: netip.PrefixFrom(revokedIP, 32)},
	})

	keptSess := admitThroughRouter(t, svc, engine, keptIP, 0x391F0061)
	admitThroughRouter(t, svc, engine, revokedIP, 0x391F0062)

	engine.peerSync.setPortalDeviceForTest(statusFailDevice{real: engine.Portal()})
	if ok, err := db.ToggleConnection(ctx, revokedConnID, false); !ok || err != nil {
		t.Fatalf("durable disable: %v", err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err == nil {
		t.Fatal("reconcile reported success while the device status read was failing")
	}
	if _, tracked := engine.Resolver().Lookup(revokedIP); tracked {
		t.Fatal("the ineligible peer kept its authorization across a status failure")
	}

	// The device comes back.
	engine.peerSync.setPortalDeviceForTest(engine.Portal())
	if err := engine.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("recovery reconcile: %v", err)
	}
	if _, tracked := engine.Resolver().Lookup(revokedIP); tracked {
		t.Fatal("the recovery pass did not converge the ineligible peer out of the map")
	}
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(revoked.publicKey); ok {
		t.Fatal("the recovery pass left the ineligible peer's routing session behind")
	}
	if syncHasPeer(t, engine, revoked.publicKey, "") {
		t.Fatal("the recovery pass did not remove the ineligible peer upstream")
	}
	if _, tracked := engine.Resolver().Lookup(keptIP); !tracked {
		t.Fatal("the recovery pass dropped a still-eligible peer from the map")
	}
	if !syncHasPeer(t, engine, kept.publicKey, kept.assignedIP) {
		t.Fatal("the recovery pass did not keep the eligible peer installed upstream")
	}
	keptAfter, ok := svc.sessionMgr.GetSessionSnapshotByPeer(kept.publicKey)
	if !ok || keptAfter.ID != keptSess.ID {
		t.Fatalf("the recovery pass churned the eligible peer's session: ok=%v sess=%+v", ok, keptAfter)
	}
	if owner, tracked := engine.Resolver().Lookup(keptIP); !tracked || owner.ConnectionID != keptConnID {
		t.Fatalf("the recovery pass disturbed the eligible peer's ownership: tracked=%v owner=%+v", tracked, owner)
	}
	if err := engine.Router().HandlePacket(engineUDPPacket(keptIP, netip.MustParseAddr("198.51.100.7"), 0x391F0063)); err != nil {
		t.Fatalf("the eligible peer does not forward after recovery: %v", err)
	}

	// Convergence runs both ways: re-enabling brings the peer back with a
	// fresh admission under the durable lease.
	if ok, err := db.ToggleConnection(ctx, revokedConnID, true); !ok || err != nil {
		t.Fatalf("durable re-enable: %v", err)
	}
	engine.peerSync.quiesceNotifyWorker()
	if err := engine.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("re-enable reconcile: %v", err)
	}
	if !syncHasPeer(t, engine, revoked.publicKey, revoked.assignedIP) {
		t.Fatal("the re-enabled peer was not reinstalled upstream")
	}
	owner, tracked := engine.Resolver().Lookup(revokedIP)
	if !tracked || owner.ConnectionID != revokedConnID {
		t.Fatalf("the re-enabled peer did not get fresh ownership: tracked=%v owner=%+v", tracked, owner)
	}
	backAgain := admitThroughRouter(t, svc, engine, revokedIP, 0x391F0064)
	if backAgain.AssignedIP != revoked.assignedIP {
		t.Fatalf("re-enabled peer's fresh session IP %q, want the durable lease %q", backAgain.AssignedIP, revoked.assignedIP)
	}
}
