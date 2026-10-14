package vpn

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestStart_AdminDisabledBackendStaysDetachedWhileEnabledBackendReprobes(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pub1, priv1, _ := tunnel.GenerateCurve25519KeyPair()
	pub2, priv2, _ := tunnel.GenerateCurve25519KeyPair()

	s1ID, err := db.CreateServer(ctx, &models.Server{
		Name: "Restore Srv 1",
		Host: "198.51.100.51",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub1,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer 1 failed: %v", err)
	}

	s2ID, err := db.CreateServer(ctx, &models.Server{
		Name: "Restore Srv 2",
		Host: "198.51.100.52",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub2,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer 2 failed: %v", err)
	}

	// Create active tunnel for server 1
	now := time.Now().UTC()
	tun1 := &models.BackendTunnel{
		ServerID:      s1ID,
		InterfaceName: fmt.Sprintf("awg-be-%d", s1ID),
		PublicKey:     pub1,
		PrivateKey:    priv1,
		Endpoint:      "198.51.100.51:51820",
		Status:        TunnelStatusActive,
		CreatedAt:     now,
	}
	tun1ID, err := db.CreateBackendTunnel(ctx, tun1)
	if err != nil {
		t.Fatalf("CreateBackendTunnel 1 failed: %v", err)
	}
	tun1.ID = tun1ID

	// Create administratively disabled tunnel for server 2. Its runtime
	// health snapshot is intentionally active and must remain untouched.
	tun2 := &models.BackendTunnel{
		ServerID:      s2ID,
		InterfaceName: fmt.Sprintf("awg-be-%d", s2ID),
		PublicKey:     pub2,
		PrivateKey:    priv2,
		Endpoint:      "198.51.100.52:51820",
		Enabled:       false,
		Status:        TunnelStatusActive,
		DisableReason: models.DisableReasonAdmin,
		CreatedAt:     now,
	}
	tun2ID, err := db.CreateBackendTunnel(ctx, tun2)
	if err != nil {
		t.Fatalf("CreateBackendTunnel 2 failed: %v", err)
	}
	tun2.ID = tun2ID

	// Start fresh Service
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	// Avoid 3-second network probe timeouts on unreachable test endpoints during background health loop
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Enabled tunnel 1 is reset to unknown health and then probed. Wait for
	// the successful startup probe to attach its device.
	deadline := time.Now().Add(2 * time.Second)
	for svc.GetBackendDeviceForTest(tun1ID) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	dev1 := svc.GetBackendDeviceForTest(tun1ID)
	if dev1 == nil {
		t.Fatalf("enabled backend %d was not attached after fresh startup probe", tun1ID)
	}

	// Administratively disabled tunnel 2 is never probed or attached.
	if dev2 := svc.GetBackendDeviceForTest(tun2ID); dev2 != nil {
		t.Errorf("expected no backend device for admin-disabled tunnel %d on Start, got %+v", tun2ID, dev2)
	}
	disabledTun, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel 2 failed: %v", err)
	}
	if disabledTun.Enabled || disabledTun.Status != TunnelStatusActive || disabledTun.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("startup changed admin-disabled backend dimensions: %+v", disabledTun)
	}
}

func TestStart_RestoresBackendDevices_DegradesOnAttachFailure(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Degrade Srv", "198.51.100.99")

	now := time.Now().UTC()
	tun := &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: fmt.Sprintf("awg-be-%d", sID),
		PublicKey:     pub,
		PrivateKey:    priv,
		Endpoint:      "198.51.100.99:999999", // invalid port causes attach to fail
		Status:        TunnelStatusActive,
		CreatedAt:     now,
	}
	tunID, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// Device should not be present
	dev := svc.GetBackendDeviceForTest(tunID)
	if dev != nil {
		t.Errorf("expected nil device when restore fails, got %+v", dev)
	}

	// The initial startup probe succeeds, but data-plane attachment fails,
	// so health must eventually become degraded rather than trusting the
	// persisted active snapshot.
	deadline := time.Now().Add(2 * time.Second)
	var tStatus *models.BackendTunnel
	for time.Now().Before(deadline) {
		tStatus, err = svc.pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tStatus.Status == TunnelStatusDegraded {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if tStatus == nil || tStatus.Status != TunnelStatusDegraded {
		t.Fatalf("expected tunnel status degraded after attach failure, got %+v", tStatus)
	}
}

func TestService_GetStatus_ExposesDroppedPackets(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Drops Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-drops", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	dev := &testBackendDevice{
		AWGClientDevice: realDev,
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Initially 0 drops
	st, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if st.DroppedPackets != 0 {
		t.Errorf("expected 0 dropped packets initially, got %d", st.DroppedPackets)
	}
	if svc.TotalDroppedPackets() != 0 {
		t.Errorf("expected 0 total dropped packets, got %d", svc.TotalDroppedPackets())
	}

	// Simulate 42 drops
	dev.dropCount.Add(42)

	st, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if st.DroppedPackets != 42 {
		t.Errorf("expected 42 dropped packets in status, got %d", st.DroppedPackets)
	}
	if svc.TotalDroppedPackets() != 42 {
		t.Errorf("expected 42 total dropped packets from helper, got %d", svc.TotalDroppedPackets())
	}

	// Simulate 100 more drops to trigger rate-limited log
	dev.dropCount.Add(100)
	st, err = svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if st.DroppedPackets != 142 {
		t.Errorf("expected 142 dropped packets in status, got %d", st.DroppedPackets)
	}
}

func TestStart_RequiresFreshProbeBeforeRestoringBackendDevice(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pub, priv, _ := tunnel.GenerateCurve25519KeyPair()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Degraded Srv",
		Host: "198.51.100.77",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": pub,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Persist stale degraded health. Service.Start must not trust it.
	now := time.Now().UTC()
	tun := &models.BackendTunnel{
		ServerID:        sID,
		InterfaceName:   fmt.Sprintf("awg-be-%d", sID),
		PublicKey:       pub,
		PrivateKey:      priv,
		Endpoint:        "198.51.100.77:51820",
		Status:          TunnelStatusDegraded,
		LastHealthCheck: &now,
		LatencyMS:       444,
		CreatedAt:       now,
	}
	tunID, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	var once sync.Once
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		once.Do(func() { close(probeStarted) })
		select {
		case <-releaseProbe:
			return 10 * time.Millisecond, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})

	startDone := make(chan error, 1)
	go func() {
		startDone <- svc.Start(ctx)
	}()
	defer func() {
		select {
		case <-releaseProbe:
		default:
			close(releaseProbe)
		}
		_ = svc.Stop()
	}()

	select {
	case <-probeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("startup health probe did not begin")
	}
	select {
	case err := <-startDone:
		t.Fatalf("Start returned before fresh health was established: %v", err)
	default:
	}

	// While the fresh probe is unresolved, stale health must not be routable
	// and no backend device may be restored from the persisted snapshot.
	startingTun, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if !startingTun.Enabled || startingTun.Status != TunnelStatusConnecting {
		t.Fatalf("expected enabled backend with unknown startup health, got %+v", startingTun)
	}
	if startingTun.LastHealthCheck != nil || startingTun.LatencyMS != 0 {
		t.Fatalf("stale health metadata survived startup reset: %+v", startingTun)
	}
	if dev := svc.GetBackendDeviceForTest(tunID); dev != nil {
		t.Fatalf("stale backend device restored before fresh probe: %v", dev)
	}

	close(releaseProbe)

	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start failed after fresh probe: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not complete after fresh probe")
	}

	probedTun, getErr := svc.pool.GetTunnel(sID)
	if getErr != nil {
		t.Fatalf("GetTunnel after startup probe failed: %v", getErr)
	}
	if probedTun.Status != TunnelStatusActive || svc.GetBackendDeviceForTest(tunID) == nil {
		t.Fatalf("fresh startup probe did not activate backend and attach device: tunnel=%+v device=%v",
			probedTun, svc.GetBackendDeviceForTest(tunID))
	}
}

func TestService_ReapSession_DoesNotPruneExpiredAffinity(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tunID = tun.ID
			break
		}
	}

	// 1. Establish session A for Alice (active, unexpired)
	sessID := "sess-prune-test-a"
	assignedIP := "10.100.0.199"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-a", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 2. Add an expired affinity record for an older peer/user (Bob)
	uIDBob := "user-bob-expired"
	peerKeyBob := "peer-bob-expired"
	vpnSvc.stickyMgr.AssignAffinity(uIDBob, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyBob, tunID)

	uCount, pCount := vpnSvc.stickyMgr.AffinityCount()
	if uCount != 2 || pCount != 2 {
		t.Fatalf("expected initial AffinityCount=(2, 2), got (%d, %d)", uCount, pCount)
	}

	// Override clock: Bob was assigned 35m ago (> 30m AffinityTTL)
	tNow := time.Now().UTC().Add(35 * time.Minute)
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time { return tNow })

	// Refresh Alice's affinity timestamp to tNow (unexpired)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)

	// 3. Trigger reapSession for session A
	sessA.LastSeen = tNow.Add(-10 * time.Minute) // aged past IdleTimeout (3m)
	vpnSvc.reapSession(ctx, sessA)

	// 4. reapSession must NOT prune affinity records (eliminates O(K*N) lock contention under Service.mu)
	uCountAfterReap, pCountAfterReap := vpnSvc.stickyMgr.AffinityCount()
	if uCountAfterReap != 2 || pCountAfterReap != 2 {
		t.Fatalf("expected AffinityCount=(2, 2) after reapSession (no per-session pruning), got (%d, %d)", uCountAfterReap, pCountAfterReap)
	}

	// 5. Calling PruneExpiredAffinity explicitly prunes the expired records
	pruned := vpnSvc.PruneExpiredAffinity()
	if pruned != 2 {
		t.Fatalf("expected 2 pruned records, got %d", pruned)
	}

	uCountAfterPrune, pCountAfterPrune := vpnSvc.stickyMgr.AffinityCount()
	if uCountAfterPrune != 1 || pCountAfterPrune != 1 {
		t.Fatalf("expected AffinityCount=(1, 1) after PruneExpiredAffinity, got (%d, %d)", uCountAfterPrune, pCountAfterPrune)
	}

	// Alice's affinity is preserved within AffinityTTL
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Errorf("expected Alice's user affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Errorf("expected Alice's peer affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}
}

func TestService_PruneExpiredAffinity_ExecutesOutsideServiceMutex(t *testing.T) {
	db := setupTestDB(t)
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	tNow := time.Now().UTC()
	vpnSvc.stickyMgr.AssignAffinity(uID, 1)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, 1)

	// Setup synchronization channels
	insidePrune := make(chan struct{})
	proceedPrune := make(chan struct{})

	vpnSvc.stickyMgr.SetNowFunc(func() time.Time {
		select {
		case <-insidePrune:
		default:
			close(insidePrune)
		}
		<-proceedPrune
		return tNow.Add(1 * time.Hour) // force expiry
	})

	doneCh := make(chan int)
	go func() {
		doneCh <- vpnSvc.PruneExpiredAffinity()
	}()

	// Wait until sm.PruneExpired() begins executing inside StickySessionManager
	select {
	case <-insidePrune:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PruneExpired to execute")
	}

	// While PruneExpired is executing, Service.mu MUST NOT be held.
	// We verify that TryLock on vpnSvc.mu succeeds immediately.
	acquired := vpnSvc.mu.TryLock()
	if !acquired {
		t.Errorf("expected Service.mu to be available while PruneExpired executes, but TryLock failed")
	} else {
		vpnSvc.mu.Unlock()
	}

	// Allow PruneExpired to finish
	close(proceedPrune)

	select {
	case pruned := <-doneCh:
		if pruned != 2 {
			t.Fatalf("expected 2 pruned records, got %d", pruned)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PruneExpiredAffinity to return")
	}
}

func TestService_PostSweepHook_PrunesExpiredAffinity(t *testing.T) {
	db := setupTestDB(t)
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	tNow := time.Now().UTC()
	vpnSvc.stickyMgr.AssignAffinity(uID, 1)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, 1)

	// Advance time past TTL
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time { return tNow.Add(1 * time.Hour) })

	uCount, pCount := vpnSvc.stickyMgr.AffinityCount()
	if uCount != 1 || pCount != 1 {
		t.Fatalf("expected initial AffinityCount=(1, 1), got (%d, %d)", uCount, pCount)
	}

	// Trigger listener's postSweepHook
	vpnSvc.PruneExpiredAffinity()

	uCountAfter, pCountAfter := vpnSvc.stickyMgr.AffinityCount()
	if uCountAfter != 0 || pCountAfter != 0 {
		t.Fatalf("expected AffinityCount=(0, 0) after pruning, got (%d, %d)", uCountAfter, pCountAfter)
	}
}

func TestService_StartedAt_LifecycleAndFailure(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	defer func() { _ = svc.Stop() }()

	// 1. Before Start: startedAt is zero
	svc.mu.RLock()
	if !svc.startedAt.IsZero() {
		t.Fatalf("expected startedAt to be zero before Start, got %v", svc.startedAt)
	}
	svc.mu.RUnlock()

	// 2. Start failure: canceled context guarantees Start fails during sync/invalidation
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.Start(ctxCancel)
	if err == nil {
		t.Fatal("expected Start with canceled context to fail")
	}

	svc.mu.RLock()
	if !svc.startedAt.IsZero() {
		t.Fatalf("expected startedAt to remain zero after Start failure, got %v", svc.startedAt)
	}
	if svc.running {
		t.Fatal("expected running to be false after Start failure")
	}
	svc.mu.RUnlock()

	// 3. Start success: with active context
	ctx := context.Background()
	svc.mu.Lock()
	svc.retiredIngressLosses.router.MalformedPacketDrops = 500
	svc.retiredBackendDeviceDrops.ClientQueueFull = 100
	svc.mu.Unlock()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("expected Start to succeed, got %v", err)
	}

	svc.mu.RLock()
	if svc.startedAt.IsZero() {
		t.Fatal("expected startedAt to be non-zero after successful Start")
	}
	if !svc.running {
		t.Fatal("expected running to be true after successful Start")
	}
	if svc.retiredIngressLosses.router.MalformedPacketDrops != 0 {
		t.Errorf("expected retiredIngressLosses to be reset on Start, got %d", svc.retiredIngressLosses.router.MalformedPacketDrops)
	}
	if svc.retiredBackendDeviceDrops.ClientQueueFull != 0 {
		t.Errorf("expected retiredBackendDeviceDrops to be reset on Start, got %d", svc.retiredBackendDeviceDrops.ClientQueueFull)
	}
	svc.mu.RUnlock()

	// 4. Stop: resets startedAt to zero
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	svc.mu.RLock()
	if !svc.startedAt.IsZero() {
		t.Fatalf("expected startedAt to be zero after Stop, got %v", svc.startedAt)
	}
	if svc.running {
		t.Fatal("expected running to be false after Stop")
	}
	svc.mu.RUnlock()
}

func TestSessionsLive_IncludesConnectionID(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Live Server", Host: "198.51.100.5"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: "bob", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	peerKey := "bob-awg-peer-public-key"
	connID := "conn-bob-live-123"

	// Create user_connection with explicit ID and peer client_id
	_, err = db.SQLDB().ExecContext(ctx,
		`INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, name) VALUES (?, ?, ?, 'awg', ?, 'bob-laptop')`,
		connID, uID, sID, peerKey)
	if err != nil {
		t.Fatalf("failed to insert user_connection: %v", err)
	}

	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-live",
		PublicKey:     "pub-live",
		PrivateKey:    "priv-live",
		Endpoint:      "198.51.100.5:51820",
		Status:        "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	svc, err := NewVPNService(db, &models.VPNConfig{
		Algorithm:          models.LBLeastConnections,
		ListenPort:         51822,
		SubnetCIDR:         "10.100.0.0/16",
		HealthThresholdMS:  500,
		MaxTotalPeers:      100,
		MaxPeersPerBackend: 50,
	})
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, "10.100.1.5", tID, "bob-laptop")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	live, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("SessionsLive failed: %v", err)
	}

	if len(live) != 1 {
		t.Fatalf("expected 1 live session, got %d", len(live))
	}

	got := live[0]
	if got.ID != sess.ID {
		t.Errorf("session ID: got %q, want %q", got.ID, sess.ID)
	}
	if got.Username != "bob" {
		t.Errorf("username: got %q, want 'bob'", got.Username)
	}
	if got.ConnectionID != connID {
		t.Errorf("connection_id: got %q, want %q", got.ConnectionID, connID)
	}
	if got.ConnectionName != "bob-laptop" {
		t.Errorf("connection_name: got %q, want 'bob-laptop'", got.ConnectionName)
	}
}
