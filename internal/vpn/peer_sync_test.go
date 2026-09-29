package vpn

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
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
	if syncHasPeer(t, e, second.publicKey, "") {
		t.Fatal("disabled connection still has runtime peer")
	}
	if ok, err := db.ToggleConnection(ctx, conn.ID, true); !ok || err != nil {
		t.Fatalf("enable connection: %v", err)
	}
	if !syncHasPeer(t, e, second.publicKey, second.assignedIP) {
		t.Fatal("enabled connection did not restore peer")
	}
	newIP := "10.100.7.99"
	conn.ClientParams["assigned_ip"] = newIP
	if ok, err := db.UpdateConnection(ctx, conn.ID, map[string]any{"client_params": conn.ClientParams}); !ok || err != nil {
		t.Fatalf("durable IP replacement: %v", err)
	}
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
	if syncHasPeer(t, e, second.publicKey, "") {
		t.Fatal("disabled user's peer remains active")
	}
	if ok, err := db.ToggleUser(ctx, conn.UserID, true); !ok || err != nil {
		t.Fatalf("enable user: %v", err)
	}
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
	// The resolver still revokes its plaintext route immediately.
	e.peerSync.portal = failingRemovePeerDevice{real: e.Portal()}
	ok, err := db.ToggleUser(ctx, conn.UserID, false)
	if !ok || !errors.Is(err, database.ErrPeerRuntimeSync) {
		t.Fatalf("revocation must report committed/runtime failure: ok=%v err=%v", ok, err)
	}
	user, err := db.GetUser(ctx, conn.UserID)
	if err != nil || user == nil || user.Enabled {
		t.Fatalf("revocation was not durable: user=%+v err=%v", user, err)
	}
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
	e.peerSync.portal = e.Portal()
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
	if syncHasPeer(t, e, peer.publicKey, "") {
		t.Fatal("peer survived quota boundary")
	}
	if ok, err := db.UpdateUser(ctx, conn.UserID, map[string]any{"traffic_used": int64(0)}); !ok || err != nil {
		t.Fatalf("reset quota: %v", err)
	}
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
	wg.Wait()
	if err := e.ReconcilePeers(ctx); err != nil {
		t.Fatal(err)
	}
	if syncHasPeer(t, e, peer.publicKey, "") {
		t.Fatal("peer active after concurrent revoke")
	}
}
