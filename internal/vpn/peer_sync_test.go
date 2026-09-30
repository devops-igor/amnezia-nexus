package vpn

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

type failingRemovePeerDevice struct{ real *clientawg.ClientAWGDevice }

func (d failingRemovePeerDevice) Status() (clientawg.Status, error) { return d.real.Status() }
func (d failingRemovePeerDevice) AddPeer(peer clientawg.Peer) error { return d.real.AddPeer(peer) }
func (d failingRemovePeerDevice) RemovePeer(string) error {
	return errors.New("injected remove failure")
}

func syncHasPeer(t *testing.T, e *IngressEngine, key string, ip string) bool {
	t.Helper()
	status, err := e.Portal().Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range status.Peers {
		if peer.PublicKey == key {
			if ip != "" && peer.AllowedIP != netip.PrefixFrom(netip.MustParseAddr(ip), 32) {
				t.Fatalf("peer has AllowedIP %s, want %s/32", peer.AllowedIP, ip)
			}
			return true
		}
	}
	return false
}

func TestPeerSyncDurableLifecycleAndDrift(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	first, _ := newEnginePeer(t, svc, db, "sync-first")
	e, err := svc.NewIngressEngine(ctx, "sync-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if !syncHasPeer(t, e, first.publicKey, first.assignedIP) {
		t.Fatal("startup did not install durable peer")
	}
	second, _ := newEnginePeer(t, svc, db, "sync-second")
	e.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, e, second.publicKey, second.assignedIP) {
		t.Fatal("connection creation did not add peer")
	}
	conn, err := db.GetConnectionByClientID(ctx, second.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("second durable connection: %v", err)
	}
	if ok, err := db.ToggleConnection(ctx, conn.ID, false); !ok || err != nil {
		t.Fatalf("disable connection: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if syncHasPeer(t, e, second.publicKey, "") {
		t.Fatal("disabled connection still has runtime peer")
	}
	if ok, err := db.ToggleConnection(ctx, conn.ID, true); !ok || err != nil {
		t.Fatalf("enable connection: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, e, second.publicKey, second.assignedIP) {
		t.Fatal("enabled connection did not restore peer")
	}
	newIP := "10.100.7.99"
	conn.ClientParams["assigned_ip"] = newIP
	if ok, err := db.UpdateConnection(ctx, conn.ID, map[string]any{"client_params": conn.ClientParams}); !ok || err != nil {
		t.Fatalf("durable IP replacement: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, e, second.publicKey, newIP) {
		t.Fatal("runtime AllowedIP did not follow durable update")
	}
	if _, ok := e.Resolver().Lookup(netip.MustParseAddr(second.assignedIP)); ok {
		t.Fatal("old plaintext route survived IP replacement")
	}
	if owner, ok := e.Resolver().Lookup(netip.MustParseAddr(newIP)); !ok || owner.PeerPublicKey != second.publicKey {
		t.Fatal("new plaintext route missing")
	}
	if ok, err := db.ToggleUser(ctx, conn.UserID, false); !ok || err != nil {
		t.Fatalf("disable user: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if syncHasPeer(t, e, second.publicKey, "") {
		t.Fatal("disabled user's peer remains active")
	}
	if ok, err := db.ToggleUser(ctx, conn.UserID, true); !ok || err != nil {
		t.Fatalf("enable user: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, e, second.publicKey, newIP) {
		t.Fatal("enabled user's peer missing")
	}
	if err := e.Portal().RemovePeer(second.publicKey); err != nil {
		t.Fatal(err)
	}
	if err := e.ReconcilePeers(ctx); err != nil {
		t.Fatalf("repair runtime drift: %v", err)
	}
	if !syncHasPeer(t, e, second.publicKey, newIP) {
		t.Fatal("drift repair failed")
	}
	if ok, err := db.DeleteConnection(ctx, conn.ID); !ok || err != nil {
		t.Fatalf("delete connection: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if syncHasPeer(t, e, second.publicKey, "") {
		t.Fatal("deleted connection still active")
	}
	stats := e.PeerSyncStatus()
	if stats.DesiredPeers != 1 || stats.ActualPeers != 1 || stats.LastSuccessfulReconcile.IsZero() || stats.SyncFailures != 0 {
		t.Fatalf("unexpected sync status: %+v", stats)
	}
	if err := e.Stop(); err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
		t.Fatal(err)
	}
	restarted, err := svc.NewIngressEngine(ctx, "sync-restart-portal", nil)
	if err != nil {
		t.Fatalf("reconstruct after restart: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Stop() })
	if !syncHasPeer(t, restarted, first.publicKey, first.assignedIP) || syncHasPeer(t, restarted, second.publicKey, "") {
		t.Fatal("restart peer set differs from durable registry")
	}
}

func TestPeerSyncCommittedRevocationFailureAndRestartRecovery(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-failure")
	conn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	e, err := svc.NewIngressEngine(ctx, "sync-failure-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	// The injected runtime failure leaves the peer active after DB commit.
	// Post-commit enforcement is asynchronous (issue #391 round 4a,
	// finding 2): the durable commit reports success, the notification
	// enqueues the reconcile, and the enforcement failure surfaces in
	// peer sync status for the periodic loop to retry.
	e.peerSync.setPortalDeviceForTest(failingRemovePeerDevice{real: e.Portal()})
	ok, err := db.ToggleUser(ctx, conn.UserID, false)
	if !ok || err != nil {
		t.Fatalf("revocation commit must succeed durably: ok=%v err=%v", ok, err)
	}
	user, err := db.GetUser(ctx, conn.UserID)
	if err != nil || user == nil || user.Enabled {
		t.Fatalf("revocation was not durable: user=%+v err=%v", user, err)
	}
	e.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, e, peer.publicKey, peer.assignedIP) {
		t.Fatal("failure injection did not leave runtime peer active")
	}
	if _, ok := e.Resolver().Lookup(netip.MustParseAddr(peer.assignedIP)); ok {
		t.Fatal("revoked peer kept its plaintext route")
	}
	stats := e.PeerSyncStatus()
	if stats.SyncFailures == 0 || stats.RemoveFailures == 0 || stats.LastError == "" {
		t.Fatalf("runtime failure not observable: %+v", stats)
	}
	// The periodic reconcile loop's retry path keeps reporting the failure
	// while it persists (and keeps the IP withdrawn), then converges once
	// the injection is cleared.
	if err := e.peerSync.reconcileNow(ctx); err == nil {
		t.Fatal("retry did not report the persistent removal failure")
	}
	if !syncHasPeer(t, e, peer.publicKey, peer.assignedIP) {
		t.Fatal("peer disappeared despite injected removal failure")
	}
	e.peerSync.setPortalDeviceForTest(e.Portal())
	if err := e.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("recovery reconcile after clearing injection: %v", err)
	}
	if syncHasPeer(t, e, peer.publicKey, "") {
		t.Fatal("reconcile did not remove revoked peer after injection cleared")
	}
	_ = e.Stop()
	restarted, err := svc.NewIngressEngine(ctx, "sync-recovered-portal", nil)
	if err != nil {
		t.Fatalf("restart recovery: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Stop() })
	if syncHasPeer(t, restarted, peer.publicKey, "") {
		t.Fatal("revoked peer recovered after restart")
	}
	if ok, err := db.ToggleUser(ctx, conn.UserID, true); !ok || err != nil {
		t.Fatalf("restore user: %v", err)
	}
	restarted.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, restarted, peer.publicKey, peer.assignedIP) {
		t.Fatal("durable re-enable did not restore peer")
	}
}

func TestPeerSyncPortalParametersRequireRestart(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	e, err := svc.NewIngressEngine(ctx, "sync-param-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	cfg, err := svc.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldS1 := cfg.S1
	cfg.S1++
	if err := svc.UpdateConfig(ctx, cfg); err == nil || !strings.Contains(err.Error(), "require stopping") {
		t.Fatalf("live portal parameter change should require restart: %v", err)
	}
	stored, err := db.GetVPNConfig(ctx)
	if err != nil || stored.S1 != oldS1 {
		t.Fatalf("rejected parameter change reached DB: %+v err=%v", stored, err)
	}
	_ = e.Stop()
	if err := svc.UpdateConfig(ctx, cfg); err != nil {
		t.Fatalf("parameter change after stop: %v", err)
	}
}

func TestPeerSyncExcludesConflictingDurableRowsWithoutChangingIdentity(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	userID, err := db.CreateUser(ctx, &models.User{Username: "sync-conflict", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const ip = "10.100.3.45"
	keys := make([]string, 2)
	for i := range keys {
		_, keys[i] = engineKeys(t)
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			UserID: userID, ServerID: 0, Protocol: "awg", ClientID: keys[i],
			ClientParams: map[string]any{"assigned_ip": ip},
		}); err != nil {
			t.Fatal(err)
		}
	}
	e, err := svc.NewIngressEngine(ctx, "sync-conflict-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if status := e.PeerSyncStatus(); status.InvalidRows < 2 || status.DesiredPeers != 0 || status.ActualPeers != 0 {
		t.Fatalf("collision was not excluded: %+v", status)
	}
	for _, key := range keys {
		row, err := db.GetConnectionByClientID(ctx, key, 0)
		if err != nil || row == nil || row.ClientID != key || row.ClientParams["assigned_ip"] != ip {
			t.Fatalf("reconciliation changed durable identity: %+v err=%v", row, err)
		}
	}
}

func TestPeerSyncQuotaBoundaryRevokesAndRestores(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-quota")
	conn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	e, err := svc.NewIngressEngine(ctx, "sync-quota-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if ok, err := db.UpdateUser(ctx, conn.UserID, map[string]any{"traffic_limit": int64(10)}); !ok || err != nil {
		t.Fatalf("set quota: %v", err)
	}
	if _, err := db.AddUserTraffic(ctx, conn.UserID, 6, 4); err != nil {
		t.Fatalf("cross quota: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if syncHasPeer(t, e, peer.publicKey, "") {
		t.Fatal("peer survived quota boundary")
	}
	if ok, err := db.UpdateUser(ctx, conn.UserID, map[string]any{"traffic_used": int64(0)}); !ok || err != nil {
		t.Fatalf("reset quota: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	if !syncHasPeer(t, e, peer.publicKey, peer.assignedIP) {
		t.Fatal("quota reset did not restore peer")
	}
}

func TestPeerSyncPeriodicDriftRepair(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-periodic")
	e, err := svc.NewIngressEngine(ctx, "sync-periodic-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	e.peerSyncInterval = 10 * time.Millisecond
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if err := e.Portal().RemovePeer(peer.publicKey); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syncHasPeer(t, e, peer.publicKey, peer.assignedIP) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("periodic reconciliation did not restore drifted peer")
}

func TestPeerSyncConcurrentRevokeAndClientTraffic(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, saved := newEnginePeer(t, svc, db, "sync-race")
	e, err := svc.NewIngressEngine(ctx, "sync-race-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	uc := startEngineUpstreamClient(t, saved, "sync-race-client")
	conn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(0); i < 100; i++ {
			_ = uc.vt.InjectInbound(engineUDPPacket(netip.MustParseAddr(peer.assignedIP), netip.MustParseAddr("198.51.100.1"), i))
		}
	}()
	if ok, err := db.ToggleUser(ctx, conn.UserID, false); !ok || err != nil {
		t.Fatalf("concurrent revocation: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()
	wg.Wait()
	if err := e.ReconcilePeers(ctx); err != nil {
		t.Fatal(err)
	}
	if syncHasPeer(t, e, peer.publicKey, "") {
		t.Fatal("peer active after concurrent revoke")
	}
}

func TestPeerSyncConcurrentRevokeTrafficRekey(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	peer, saved := newEnginePeer(t, svc, db, "sync-rekey-user")
	conn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}

	e, err := svc.NewIngressEngine(ctx, "sync-rekey-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}

	uc := startEngineUpstreamClient(t, saved, "sync-rekey-client")
	if err := uc.dev.IpcSet("rekey_after_time=1\nrekey_timeout=1\n"); err != nil {
		t.Fatalf("IpcSet test rekey timing: %v", err)
	}

	// Initial packet admits backend session and establishes route
	firstPkt := engineUDPPacket(netip.MustParseAddr(peer.assignedIP), netip.MustParseAddr("10.0.0.1"), 1)
	uc.inject(t, firstPkt)
	var sess models.VPNSession
	var ok bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s, found := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); found && s.Status == "connected" {
			sess = s
			ok = true
			break
		}
		time.Sleep(50 * time.Millisecond)
		_ = uc.vt.InjectInbound(firstPkt)
	}
	if !ok {
		t.Fatal("session not admitted before concurrent test")
	}
	if route := svc.forwarder.RouteSessionID(peer.publicKey); route != sess.ID {
		t.Fatalf("route session mismatch: got %q, want %q", route, sess.ID)
	}
	tun, err := svc.pool.GetTunnelByID(sess.BackendTunnelID)
	if err != nil || tun.ActiveConnections != 1 {
		t.Fatalf("active connections before revoke = %d, want 1", tun.ActiveConnections)
	}

	portalStatus, err := e.Portal().Status()
	if err != nil {
		t.Fatalf("get portal status before streaming: %v", err)
	}
	var initialHandshake time.Time
	for _, p := range portalStatus.Peers {
		if p.PublicKey == peer.publicKey {
			initialHandshake = p.LastHandshake
			break
		}
	}
	if initialHandshake.IsZero() {
		t.Fatal("initial handshake timestamp was not observed before streaming")
	}

	// Concurrently stream packets while rekeying via test timing
	var stopStreaming atomic.Bool
	var streamWg sync.WaitGroup
	streamWg.Add(1)
	go func() {
		defer streamWg.Done()
		var seq uint32 = 2
		for !stopStreaming.Load() {
			_ = uc.vt.InjectInbound(engineUDPPacket(netip.MustParseAddr(peer.assignedIP), netip.MustParseAddr("10.0.0.1"), seq))
			seq++
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Poll until the rekey is observed via LastHandshake advancing
	var rekeyObserved bool
	rekeyDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(rekeyDeadline) {
		st, err := e.Portal().Status()
		if err == nil {
			for _, p := range st.Peers {
				if p.PublicKey == peer.publicKey && p.LastHandshake.After(initialHandshake) {
					rekeyObserved = true
					break
				}
			}
		}
		if rekeyObserved {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !rekeyObserved {
		t.Fatal("rekey was not observed during active streaming traffic")
	}

	// Concurrently invoke durable revocation
	if ok, err := db.ToggleConnection(ctx, conn.ID, false); !ok || err != nil {
		t.Fatalf("ToggleConnection disable failed: %v", err)
	}
	e.peerSync.quiesceNotifyWorker()

	stopStreaming.Store(true)
	streamWg.Wait()

	if err := e.ReconcilePeers(ctx); err != nil {
		t.Fatal(err)
	}

	// Assert: peer removed from portal device
	if syncHasPeer(t, e, peer.publicKey, "") {
		t.Fatal("peer still present on portal device after revocation")
	}

	// Assert: peer unauthorized in resolver
	if _, ok := e.Resolver().Lookup(netip.MustParseAddr(peer.assignedIP)); ok {
		t.Fatal("peer still authorized in plaintext resolver")
	}

	// Assert: routing session closed/absent from SessionManager
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("routing session still exists in SessionManager: %+v", snap)
	}

	// Assert: forwarder route absent
	if route := svc.forwarder.RouteSessionID(peer.publicKey); route != "" {
		t.Fatalf("forwarder route survived revocation: %q", route)
	}

	// Assert: backend active connection count decremented back to 0
	tunAfter, err := svc.pool.GetTunnelByID(sess.BackendTunnelID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Fatalf("backend active connections = %d, want 0", tunAfter.ActiveConnections)
	}

	// Assert: additional packets do NOT resurrect session or route
	_ = uc.vt.InjectInbound(engineUDPPacket(netip.MustParseAddr(peer.assignedIP), netip.MustParseAddr("10.0.0.1"), 99999))
	time.Sleep(50 * time.Millisecond)
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("packet resurrected session: %+v", snap)
	}
	if route := svc.forwarder.RouteSessionID(peer.publicKey); route != "" {
		t.Fatalf("packet resurrected route: %q", route)
	}
}

// TestRevokeUpstreamPeerSessionRacesTimeoutReaperWithoutDoubleDecrement proves that
// when RevokeUpstreamPeerSession races with an idle reap eviction (CheckTimeouts),
// teardown ownership is strictly exclusive: RevokeUpstreamPeerSession yields ownership
// when CloseSession returns ErrSessionNotFound (or session already evicted), and the
// subsequent reapIngressSession decrements the backend capacity exactly once (2 -> 1,
// never double-decremented to 0). Issue #391 finding 1 regression test.
func TestRevokeUpstreamPeerSessionRacesTimeoutReaperWithoutDoubleDecrement(t *testing.T) {
	t.Run("CheckTimeoutsEvictsBeforeRevoke", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, userID, _ := setupTestVPNService(t, db)
		ctx := t.Context()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		tunnels := svc.pool.GetActiveTunnels()
		if len(tunnels) == 0 {
			t.Fatal("no active tunnels")
		}
		backend := tunnels[0]

		sessA, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, "peer-race-A", "10.100.9.1", backend.ID, "ingress-device", models.SessionAdmissionIngress)
		if err != nil {
			t.Fatal(err)
		}
		svc.pool.IncrementConnections(backend.ID)
		if svc.forwarder != nil {
			_ = svc.forwarder.BeginRegisterSessionWithLimit(sessA.ID, "conn-race-A", sessA.PeerPublicKey, sessA.AssignedIP, backend.ID, 0, 0)
		}

		sessB, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, "peer-race-B", "10.100.9.2", backend.ID, "ingress-device", models.SessionAdmissionIngress)
		if err != nil {
			t.Fatal(err)
		}
		svc.pool.IncrementConnections(backend.ID)
		if svc.forwarder != nil {
			_ = svc.forwarder.BeginRegisterSessionWithLimit(sessB.ID, "conn-race-B", sessB.PeerPublicKey, sessB.AssignedIP, backend.ID, 0, 0)
		}

		tun, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || tun.ActiveConnections != 2 {
			t.Fatalf("setup: expected 2 active connections, got %d (err: %v)", tun.ActiveConnections, err)
		}

		// Simulate timeout eviction of sessA via CheckTimeouts returning sessA for reap
		svc.sessionMgr.SetSessionLastSeen(sessA.PeerPublicKey, time.Now().UTC().Add(-2*time.Hour))
		timedOut, err := svc.sessionMgr.CheckTimeouts(ctx, 1*time.Hour)
		if err != nil {
			t.Fatalf("CheckTimeouts failed: %v", err)
		}
		if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
			t.Fatalf("expected 1 timed out session %s, got %d", sessA.ID, len(timedOut))
		}

		// Call RevokeUpstreamPeerSession for sessA. It must return nil and NOT decrement pool.
		if err := svc.RevokeUpstreamPeerSession(ctx, sessA.PeerPublicKey); err != nil {
			t.Fatalf("RevokeUpstreamPeerSession returned error: %v", err)
		}

		tunMid, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || tunMid.ActiveConnections != 2 {
			t.Fatalf("active connections after revoke = %d, want 2 (no decrement on already-evicted session)", tunMid.ActiveConnections)
		}

		// Call reapIngressSession for sessA (the idle reaper).
		svc.reapIngressSession(timedOut[0])

		// Assert ActiveConnections is exactly 1 (no duplicate decrement).
		tunFinal, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || tunFinal.ActiveConnections != 1 {
			t.Fatalf("final active connections = %d, want 1 (prevented double-decrement)", tunFinal.ActiveConnections)
		}
	})

	t.Run("CheckTimeoutsRacesBetweenGetAndCloseSession", func(t *testing.T) {
		db := setupTestDB(t)
		svc, _, _, userID, _ := setupTestVPNService(t, db)
		ctx := t.Context()
		if err := svc.pool.SyncFromDB(ctx); err != nil {
			t.Fatal(err)
		}
		tunnels := svc.pool.GetActiveTunnels()
		if len(tunnels) == 0 {
			t.Fatal("no active tunnels")
		}
		backend := tunnels[0]

		sessA, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, "peer-race-C", "10.100.9.3", backend.ID, "ingress-device", models.SessionAdmissionIngress)
		if err != nil {
			t.Fatal(err)
		}
		svc.pool.IncrementConnections(backend.ID)
		if svc.forwarder != nil {
			_ = svc.forwarder.BeginRegisterSessionWithLimit(sessA.ID, "conn-race-C", sessA.PeerPublicKey, sessA.AssignedIP, backend.ID, 0, 0)
		}

		sessB, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, "peer-race-D", "10.100.9.4", backend.ID, "ingress-device", models.SessionAdmissionIngress)
		if err != nil {
			t.Fatal(err)
		}
		svc.pool.IncrementConnections(backend.ID)
		if svc.forwarder != nil {
			_ = svc.forwarder.BeginRegisterSessionWithLimit(sessB.ID, "conn-race-D", sessB.PeerPublicKey, sessB.AssignedIP, backend.ID, 0, 0)
		}

		tun, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || tun.ActiveConnections != 2 {
			t.Fatalf("setup: expected 2 active connections, got %d (err: %v)", tun.ActiveConnections, err)
		}

		var timedOut []*models.VPNSession
		// Hook runs after GetSession finds sessA under s.mu, but before CloseSession runs.
		// CheckTimeouts does not acquire s.mu, so it successfully evicts sessA.
		svc.SetPreRevokeCloseHookForTest(func(peerKey, sessionID string) {
			if peerKey == sessA.PeerPublicKey {
				svc.sessionMgr.SetSessionLastSeen(sessA.PeerPublicKey, time.Now().UTC().Add(-2*time.Hour))
				var timeoutErr error
				timedOut, timeoutErr = svc.sessionMgr.CheckTimeouts(ctx, 1*time.Hour)
				if timeoutErr != nil {
					t.Errorf("CheckTimeouts inside hook failed: %v", timeoutErr)
				}
			}
		})
		t.Cleanup(func() { svc.SetPreRevokeCloseHookForTest(nil) })

		// RevokeUpstreamPeerSession gets sessA, then hook evicts sessA, then CloseSession
		// returns ErrSessionNotFound. RevokeUpstreamPeerSession must yield ownership (return nil,
		// zero pool decrement).
		if err := svc.RevokeUpstreamPeerSession(ctx, sessA.PeerPublicKey); err != nil {
			t.Fatalf("RevokeUpstreamPeerSession returned error: %v", err)
		}

		tunMid, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || tunMid.ActiveConnections != 2 {
			t.Fatalf("active connections after revoke = %d, want 2 (no decrement on ErrSessionNotFound)", tunMid.ActiveConnections)
		}

		if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
			t.Fatalf("expected hook to evict sessA %s, got %+v", sessA.ID, timedOut)
		}

		// Idle reaper reaps the evicted session.
		svc.reapIngressSession(timedOut[0])

		tunFinal, err := svc.pool.GetTunnelByID(backend.ID)
		if err != nil || tunFinal.ActiveConnections != 1 {
			t.Fatalf("final active connections = %d, want 1 (prevented double-decrement on race)", tunFinal.ActiveConnections)
		}
	})
}

// TestPeerSyncStopDrainsQueuedNotification re-creates the goroutine dump from
// the round-4a session: a commit enqueues a reconcile, Stop runs while the
// worker is mid-reconcile, and the drain must still complete. It pins the
// channel fix (a stop channel the worker selects on instead of a notify
// variable rewritten to nil under the running range) and the bounded drain.
func TestPeerSyncStopDrainsQueuedNotification(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	// newEnginePeer fatals internally on failure.
	_, _ = newEnginePeer(t, svc, db, "sync-drain")
	e, err := svc.NewIngressEngine(ctx, "sync-drain-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	// Enqueue a reconcile and immediately stop: the drain must complete
	// whether or not the worker is mid-reconcile.
	e.peerSync.notifyListener()
	if err := e.Stop(); err != nil {
		t.Fatalf("stop did not drain cleanly: %v", err)
	}
	e2, err := svc.NewIngressEngine(ctx, "sync-drain-portal2", nil)
	if err != nil {
		t.Fatalf("reconstruct after drained stop: %v", err)
	}
	t.Cleanup(func() { _ = e2.Stop() })
	if err := e2.peerSync.reconcileNow(ctx); err != nil {
		t.Fatalf("reconcile after stop: %v", err)
	}
}

// TestPeerSyncStopDoesNotConsumeEnqueueFailure proves a commit that arrives
// while the worker is stopping is visible, never silent: the enqueue is
// counted, the reason recorded, and Stop still completes.
func TestPeerSyncStopDoesNotConsumeEnqueueFailure(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	// newEnginePeer fatals internally on failure.
	_, _ = newEnginePeer(t, svc, db, "sync-stop-fail")
	e, err := svc.NewIngressEngine(ctx, "sync-stop-fail-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(); err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
		t.Fatalf("stop: %v", err)
	}
	e.peerSync.enqueuePeerReconcile()
	failures, reason := e.peerSync.EnqueueFailures()
	if failures == 0 || reason == "" {
		t.Fatalf("post-stop enqueue was silent: count=%d reason=%q", failures, reason)
	}
}

// TestPeerSyncQuiesceCoversRunningReconcile pins the quiesce contract that
// makes every async assertion in this file deterministic: when quiesce
// returns, no reconcile is running, not merely one that already decremented
// its queue entry.
func TestPeerSyncQuiesceCoversRunningReconcile(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	peer, _ := newEnginePeer(t, svc, db, "sync-quiesce")
	e, err := svc.NewIngressEngine(ctx, "sync-quiesce-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || conn == nil {
		t.Fatalf("durable connection: %v", err)
	}
	hanging := hangingStatusDevice{release: make(chan struct{})}
	e.peerSync.setPortalDeviceForTest(hanging)
	if ok, err := db.ToggleConnection(ctx, conn.ID, false); !ok || err != nil {
		t.Fatalf("disable: %v", err)
	}
	// Wait until the worker provably sits inside reconcileNow, then prove
	// quiesce does not return early while running is set.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !e.peerSync.running.Load() {
		time.Sleep(time.Millisecond)
	}
	if !e.peerSync.running.Load() {
		t.Fatal("worker never entered reconcile")
	}
	quiesced := make(chan struct{})
	go func() {
		e.peerSync.quiesceNotifyWorker()
		close(quiesced)
	}()
	select {
	case <-quiesced:
		t.Fatal("quiesce returned while a reconcile was running")
	case <-time.After(50 * time.Millisecond):
	}
	// Release the portal, and only then let teardowns (which run after the
	// explicit close below) see the closed channel idempotently.
	close(hanging.release)
	e.peerSync.setPortalDeviceForTest(e.Portal())
	select {
	case <-quiesced:
	case <-time.After(2 * time.Second):
		t.Fatal("quiesce did not return after the reconcile finished")
	}
	if e.peerSync.running.Load() {
		t.Fatal("running still set after quiesce")
	}
}

// hangingStatusDevice blocks Status until its release channel closes; it
// models a portal device wedged mid-call so tests can hold the worker inside
// reconcileNow deterministically.
type hangingStatusDevice struct {
	release chan struct{}
}

func (d hangingStatusDevice) Status() (clientawg.Status, error) {
	<-d.release
	return clientawg.Status{}, errors.New("portal unavailable")
}

func (d hangingStatusDevice) AddPeer(clientawg.Peer) error { return errors.New("portal unavailable") }

func (d hangingStatusDevice) RemovePeer(string) error { return errors.New("portal unavailable") }
