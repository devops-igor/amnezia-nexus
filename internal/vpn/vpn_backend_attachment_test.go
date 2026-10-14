package vpn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestAttachBackendForwarder_IdempotentClosesOldDevice(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Idempotent Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("first attachBackendForwarder failed: %v", err)
	}

	dev1 := svc.GetBackendDeviceForTest(tun.ID)
	if dev1 == nil {
		t.Fatal("expected dev1 to be attached, got nil")
	}
	if dev1.IsClosed() {
		t.Error("expected dev1 to be open initially")
	}

	// Re-attach device for the same tunnel ID
	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("second attachBackendForwarder failed: %v", err)
	}

	dev2 := svc.GetBackendDeviceForTest(tun.ID)
	if dev2 == nil {
		t.Fatal("expected dev2 to be attached, got nil")
	}
	if dev2 == dev1 {
		t.Error("expected new device instance to replace dev1")
	}
	if !dev1.IsClosed() {
		t.Error("expected old dev1 to be closed after re-attaching")
	}
	if dev2.IsClosed() {
		t.Error("expected new dev2 to remain open")
	}

	// Reading from old closed device returns error, ensuring read goroutine terminates
	buf := make([]byte, 100)
	_, readErr := dev1.Read(buf)
	if readErr == nil {
		t.Error("expected read on closed dev1 to fail, got nil")
	}

	_ = dev2.Close()
}

func TestUpdateBackendServerHost(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Update Host Srv", "198.51.100.1")

	// 1. Initial state: server.Host = old_host, tun.Endpoint = old_host:port, backend_tunnels.endpoint = old_host:port
	tun, err := svc.pool.AddTunnel(ctx, sID, "198.51.100.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	dev1 := svc.GetBackendDeviceForTest(tun.ID)
	if dev1 == nil {
		t.Fatal("expected dev1 to be attached, got nil")
	}

	// 2. Host updated: server.Host = new_host
	if err := db.UpdateServer(ctx, sID, map[string]any{"host": "198.51.100.2"}); err != nil {
		t.Fatalf("UpdateServer failed: %v", err)
	}

	// Call UpdateBackendServerHost
	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.2"); err != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", err)
	}

	// 3. Assert tun.Endpoint == new_host:port in memory
	tunMem, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunMem.Endpoint != "198.51.100.2:51820" {
		t.Errorf("expected memory tunnel endpoint '198.51.100.2:51820', got %q", tunMem.Endpoint)
	}

	// 4. Assert backend_tunnels.endpoint == new_host:port in DB
	tunnelsDB, err := db.GetBackendTunnels(ctx)
	if err != nil {
		t.Fatalf("GetBackendTunnels failed: %v", err)
	}
	var foundInDB *models.BackendTunnel
	for i := range tunnelsDB {
		if tunnelsDB[i].ServerID == sID {
			foundInDB = &tunnelsDB[i]
			break
		}
	}
	if foundInDB == nil {
		t.Fatalf("tunnel for server %d not found in DB", sID)
	}
	if foundInDB.Endpoint != "198.51.100.2:51820" {
		t.Errorf("expected DB backend tunnel endpoint '198.51.100.2:51820', got %q", foundInDB.Endpoint)
	}

	// Verify old device was closed and replaced
	if !dev1.IsClosed() {
		t.Error("expected old dev1 to be closed after endpoint update")
	}
	dev2 := svc.GetBackendDeviceForTest(tun.ID)
	if dev2 == nil {
		t.Fatal("expected dev2 to be attached after endpoint update, got nil")
	}
	if dev2 == dev1 {
		t.Error("expected dev2 to be a newly attached device instance")
	}

	// 5. Assert admin-disabled tunnel remains disabled with updated endpoint
	if err := svc.DisableBackend(ctx, sID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	disabledTun, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel after disable failed: %v", err)
	}
	if disabledTun.Enabled || disabledTun.Status != TunnelStatusActive || disabledTun.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected enabled=false with preserved active health, got enabled=%v status=%s reason=%s", disabledTun.Enabled, disabledTun.Status, disabledTun.DisableReason)
	}

	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.3"); err != nil {
		t.Fatalf("UpdateBackendServerHost on disabled tunnel failed: %v", err)
	}
	disabledTunUpdated, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel after second host update failed: %v", err)
	}
	if disabledTunUpdated.Endpoint != "198.51.100.3:51820" {
		t.Errorf("expected disabled tunnel endpoint '198.51.100.3:51820', got %q", disabledTunUpdated.Endpoint)
	}
	if disabledTunUpdated.Enabled || disabledTunUpdated.Status != TunnelStatusActive || disabledTunUpdated.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected tunnel to remain admin-disabled with preserved health, got enabled=%v status=%s reason=%s", disabledTunUpdated.Enabled, disabledTunUpdated.Status, disabledTunUpdated.DisableReason)
	}
	if dev := svc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Errorf("expected no device attached for admin-disabled tunnel, got %+v", dev)
	}

	// 6. Re-enable administrative intent, then assert restart restores the device.
	if err := svc.pool.SetTunnelEnabled(ctx, sID, true, models.DisableReasonNone); err != nil {
		t.Fatalf("SetTunnelEnabled failed: %v", err)
	}
	if err := svc.pool.SetTunnelStatusWithReason(ctx, sID, TunnelStatusActive, models.DisableReasonNone, 10); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}
	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.4"); err != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", err)
	}
	_ = svc.Stop()

	newSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService (restart) failed: %v", err)
	}
	newSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	if err := newSvc.Start(ctx); err != nil {
		t.Fatalf("newSvc.Start failed: %v", err)
	}
	defer func() { _ = newSvc.Stop() }()

	restartedTun, err := newSvc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel on restarted service failed: %v", err)
	}
	if restartedTun.Endpoint != "198.51.100.4:51820" {
		t.Errorf("expected restarted tunnel endpoint '198.51.100.4:51820', got %q", restartedTun.Endpoint)
	}
	restartedDev := newSvc.GetBackendDeviceForTest(tun.ID)
	if restartedDev == nil {
		t.Error("expected restored backend device on restarted service, got nil")
	}

	// 7. Unmanaged server (not in pool) is a no-op returning nil
	if err := newSvc.UpdateBackendServerHost(ctx, 99999, "198.51.100.99"); err != nil {
		t.Errorf("expected nil for unmanaged server, got: %v", err)
	}

	// 8. Same endpoint is a no-op returning nil
	if err := newSvc.UpdateBackendServerHost(ctx, sID, "198.51.100.4"); err != nil {
		t.Errorf("expected nil for unchanged endpoint, got: %v", err)
	}
}

func TestUpdateBackendServerHost_RaceWithDisableBackend(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Race Server", "198.51.100.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "198.51.100.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if err := svc.pool.SetTunnelStatusWithReason(ctx, sID, TunnelStatusActive, models.DisableReasonNone, 10); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	// Verify device is attached initially
	if svc.GetBackendDeviceForTest(tun.ID) == nil {
		t.Fatal("expected device to be attached initially")
	}

	// Set hook before acquiring s.mu in UpdateBackendServerHost to simulate concurrent DisableBackend
	hookCalled := false
	svc.SetUpdateBackendServerHostPreLockHook(func() {
		hookCalled = true
		if err := svc.DisableBackend(ctx, sID); err != nil {
			t.Errorf("DisableBackend in hook failed: %v", err)
		}
	})

	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.2"); err != nil {
		t.Fatalf("UpdateBackendServerHost failed: %v", err)
	}

	if !hookCalled {
		t.Fatal("expected pre-lock hook to be called")
	}

	// Assert administrative disable won while runtime health stayed active.
	tunAfter, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfter.Enabled || tunAfter.Status != TunnelStatusActive || tunAfter.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected enabled=false with active health and admin reason, got enabled=%v status=%q reason=%q",
			tunAfter.Enabled, tunAfter.Status, tunAfter.DisableReason)
	}

	// Assert forwarder device is detached / not reattached
	if dev := svc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Errorf("expected forwarder device to be detached, got %+v", dev)
	}

	// Assert no data-plane device is registered for the disabled tunnel in s.backendDevices
	svc.mu.RLock()
	_, hasDev := svc.backendDevices[tun.ID]
	svc.mu.RUnlock()
	if hasDev {
		t.Errorf("expected no device in backendDevices for disabled tunnel %d", tun.ID)
	}
}

// TestEnsureBackendDeviceAttached_FencedOnStaleStateVersion verifies that if an endpoint update
// races ensureBackendDeviceAttached after initial validation but before acquiring s.mu,
// the attachment critical section detects the StateVersion mismatch under lock, refuses to
// attach the forwarder device, and returns tunnel.ErrStaleStateVersion.
func TestEnsureBackendDeviceAttached_FencedOnStaleStateVersion(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun := tunMust(t, vpnSvc, s1ID)

	// Ensure device is initially not attached
	vpnSvc.mu.Lock()
	delete(vpnSvc.backendDevices, tun.ID)
	vpnSvc.mu.Unlock()

	var hookCalled atomic.Bool
	vpnSvc.SetEnsureDevicePreLockHook(func() {
		hookCalled.Store(true)
		if err := vpnSvc.pool.SetTunnelEndpoint(ctx, tun.ID, "198.51.100.99:51820"); err != nil {
			t.Errorf("SetTunnelEndpoint in hook failed: %v", err)
		}
	})

	err := vpnSvc.ensureBackendDeviceAttached(ctx, tun)
	if !errors.Is(err, tunnel.ErrStaleStateVersion) {
		t.Fatalf("expected ErrStaleStateVersion, got %v", err)
	}
	if !hookCalled.Load() {
		t.Fatal("expected ensureDevicePreLockHook to be called")
	}

	// Assert that forwarder device was NOT attached for the old tunnel
	if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Fatal("backend device must not be attached after concurrent endpoint update")
	}
}

// TestUpdateBackendServerHost_CanceledContextRollback verifies that if context is canceled
// after SetTunnelEndpoint mutated the pool, UpdateBackendServerHost compensates by reverting
// the endpoint in both SQLite DB and in-memory pool back to the original endpoint.
func TestUpdateBackendServerHost_CanceledContextRollback(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunBefore := tunMust(t, vpnSvc, s1ID)
	origEndpoint := tunBefore.Endpoint

	reqCtx, cancelReq := context.WithCancel(ctx)
	vpnSvc.SetUpdateBackendServerHostPreLockHook(func() {
		cancelReq()
	})

	err := vpnSvc.UpdateBackendServerHost(reqCtx, s1ID, "198.51.100.88")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	// Assert endpoint in memory pool was reverted to origEndpoint
	tunAfter, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfter.Endpoint != origEndpoint {
		t.Errorf("expected pool endpoint %q, got %q", origEndpoint, tunAfter.Endpoint)
	}

	// Assert endpoint in DB was reverted to origEndpoint
	dbTun, err := db.GetBackendTunnelByServerID(ctx, s1ID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbTun.Endpoint != origEndpoint {
		t.Errorf("expected DB endpoint %q, got %q", origEndpoint, dbTun.Endpoint)
	}
}

// TestUpdateBackendServerHost_RollbackFailure_ReturnsErrVPNRollbackFailed verifies that
// if endpoint rollback fails during compensation, UpdateBackendServerHost returns an error
// joining the original error and ErrVPNRollbackFailed.
func TestUpdateBackendServerHost_RollbackFailure_ReturnsErrVPNRollbackFailed(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunBefore := tunMust(t, vpnSvc, s1ID)
	origEndpoint := tunBefore.Endpoint

	// 1. Hook forwarder sync to fail
	vpnSvc.SetSyncBackendForwarderHookForTest(func() error {
		return errors.New("forwarder sync failure")
	})

	// 2. Hook SetTunnelEndpoint so rollback to origEndpoint fails
	vpnSvc.SetTunnelEndpointHookForTest(func(ctx context.Context, tunnelID int64, endpoint string) error {
		if endpoint == origEndpoint {
			return errors.New("simulated disk error during rollback")
		}
		return nil
	})

	newHost := "198.51.100.89"
	err := vpnSvc.UpdateBackendServerHost(ctx, s1ID, newHost)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, ErrVPNRollbackFailed) {
		t.Errorf("expected error to wrap ErrVPNRollbackFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "forwarder sync failure") {
		t.Errorf("expected error to include original error 'forwarder sync failure', got %v", err)
	}
	if !strings.Contains(err.Error(), "simulated disk error during rollback") {
		t.Errorf("expected error to include rollback error, got %v", err)
	}
}

func TestUpdateBackendServerHost_SameEndpointReconcilesBackendForwarder(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	ctx := context.Background()

	sID, pub, _ := createTestServerAndKey(t, db, "Same Endpoint Srv", "198.51.100.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "198.51.100.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	dev1 := svc.GetBackendDeviceForTest(tun.ID)
	if dev1 == nil {
		t.Fatal("expected dev1 to be attached, got nil")
	}
	if dev1.IsClosed() {
		t.Fatal("expected dev1 to be open initially")
	}

	// 1. When already synchronized, calling with the same host is an idempotent no-op
	// that does NOT recreate the device.
	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.1"); err != nil {
		t.Fatalf("UpdateBackendServerHost (synchronized) failed: %v", err)
	}

	devAfter := svc.GetBackendDeviceForTest(tun.ID)
	if devAfter != dev1 {
		t.Errorf("expected device to remain unchanged, but devAfter != dev1")
	}
	if dev1.IsClosed() {
		t.Error("expected dev1 to remain open when already synchronized")
	}

	// 2. When attachedEndpoint is stale (e.g. set to a different endpoint),
	// calling with the same host reconciles the backend forwarder.
	svc.SetBackendDeviceEndpointForTest(tun.ID, "198.51.100.99:51820")

	if err := svc.UpdateBackendServerHost(ctx, sID, "198.51.100.1"); err != nil {
		t.Fatalf("UpdateBackendServerHost (reconciliation) failed: %v", err)
	}

	dev2 := svc.GetBackendDeviceForTest(tun.ID)
	if dev2 == nil {
		t.Fatal("expected dev2 to be attached, got nil")
	}
	if dev2 == dev1 {
		t.Error("expected new device instance to replace dev1")
	}
	if !dev1.IsClosed() {
		t.Error("expected old dev1 to be closed after stale-endpoint reconciliation")
	}
	if dev2.IsClosed() {
		t.Error("expected new dev2 to remain open")
	}
	if ep := svc.GetBackendDeviceEndpointForTest(tun.ID); ep != "198.51.100.1:51820" {
		t.Errorf("expected backendDeviceEndpoint to be %q, got %q", "198.51.100.1:51820", ep)
	}
}

type testMockPacketDev struct {
	mu       sync.Mutex
	pkts     [][]byte
	notifyCh chan struct{}
}

func (m *testMockPacketDev) Read(p []byte) (int, error) {
	return 0, nil
}

func (m *testMockPacketDev) Write(p []byte) (int, error) {
	m.mu.Lock()
	buf := make([]byte, len(p))
	copy(buf, p)
	m.pkts = append(m.pkts, buf)
	m.mu.Unlock()
	select {
	case m.notifyCh <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (m *testMockPacketDev) Close() error {
	return nil
}

func (m *testMockPacketDev) getPackets() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.pkts))
	for i, b := range m.pkts {
		cp := make([]byte, len(b))
		copy(cp, b)
		out[i] = cp
	}
	return out
}

func TestAttachBackendForwarder_ReattachStopsOldPumpRegression(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	// Start forwarder pumps
	svc.forwarder.Start(ctx)
	svc.forwarder.StartPumps(ctx)
	defer func() { _ = svc.forwarder.Stop() }()

	backendID := int64(999)
	peerKey := "peer-pump-regression"
	svc.forwarder.RegisterSession("sess-p", "conn-p", peerKey, "10.100.0.99", backendID)

	dev1 := &testMockPacketDev{notifyCh: make(chan struct{}, 300)}
	dev2 := &testMockPacketDev{notifyCh: make(chan struct{}, 300)}

	// First attach
	svc.forwarder.AttachBackendDevice(backendID, dev1)

	// Route initial packet to dev1
	if err := svc.forwarder.RouteClientToBackend(peerKey, []byte("pkt-1")); err != nil {
		t.Fatalf("RouteClientToBackend pkt-1 failed: %v", err)
	}

	select {
	case <-dev1.notifyCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for initial packet on dev1")
	}

	if len(dev1.getPackets()) != 1 {
		t.Fatalf("expected 1 packet on dev1 before re-attach, got %d", len(dev1.getPackets()))
	}

	// Re-attach: Detach old device, Attach new device (mirrors attachBackendForwarder lifecycle)
	svc.forwarder.DetachBackendDevice(backendID)
	svc.forwarder.AttachBackendDevice(backendID, dev2)

	// Route 200 packets
	totalPackets := 200
	for i := 0; i < totalPackets; i++ {
		if err := svc.forwarder.RouteClientToBackend(peerKey, []byte(fmt.Sprintf("pkt-%d", i))); err != nil {
			t.Fatalf("RouteClientToBackend failed at %d: %v", i, err)
		}
	}

	// Wait for packets to arrive on dev2
	deadline := time.Now().Add(2 * time.Second)
	for len(dev2.getPackets()) < totalPackets && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	dev1After := len(dev1.getPackets()) - 1 // minus initial packet
	dev2Count := len(dev2.getPackets())

	// Assert old device receives ZERO packets after re-attach
	if dev1After != 0 {
		t.Errorf("expected old device dev1 to receive 0 packets after re-attach, but got %d (pump leaked)", dev1After)
	}
	// Assert new device receives 100% of packets
	if dev2Count != totalPackets {
		t.Errorf("expected new device dev2 to receive %d packets (100%%), but got %d", totalPackets, dev2Count)
	}
}

func TestDisableBackend_PersistenceFailurePreservesStateAndDevice(t *testing.T) {
	t.Run("ContextCanceled", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()

		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		s1ID, pub1, _ := createTestServerAndKey(t, db, "Backend Srv 1", "127.0.0.1")
		s2ID, pub2, _ := createTestServerAndKey(t, db, "Backend Srv 2", "127.0.0.1")

		tun1, err := svc.pool.AddTunnel(ctx, s1ID, "127.0.0.1:51821", pub1)
		if err != nil {
			t.Fatalf("AddTunnel 1 failed: %v", err)
		}
		tun2, err := svc.pool.AddTunnel(ctx, s2ID, "127.0.0.1:51822", pub2)
		if err != nil {
			t.Fatalf("AddTunnel 2 failed: %v", err)
		}

		svc.mu.Lock()
		err = svc.attachBackendForwarder(tun1, nil)
		svc.mu.Unlock()
		if err != nil {
			t.Fatalf("attachBackendForwarder failed: %v", err)
		}

		devBefore := svc.GetBackendDeviceForTest(tun1.ID)
		if devBefore == nil {
			t.Fatal("expected backend device attached before test, got nil")
		}
		if devBefore.IsClosed() {
			t.Fatal("expected backend device to be open before test")
		}
		t.Cleanup(func() { _ = devBefore.Close() })

		uID, err := db.CreateUser(ctx, &models.User{Username: "charlie", Enabled: true})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		peerKey := "charlie-peer-key"
		_, err = db.CreateConnection(ctx, &models.UserConnection{
			UserID:   uID,
			ServerID: 0,
			Protocol: "awg",
			ClientID: peerKey,
			Name:     "charlie-device",
		})
		if err != nil {
			t.Fatalf("CreateConnection failed: %v", err)
		}

		sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, "10.100.0.10", tun1.ID, "charlie-device")
		if err != nil {
			t.Fatalf("CreateSession failed: %v", err)
		}
		svc.pool.IncrementConnections(tun1.ID)
		svc.stickyMgr.AssignPeerAffinity(peerKey, tun1.ID)
		svc.forwarder.RegisterSession(sess.ID, "charlie-conn", peerKey, "10.100.0.10", tun1.ID)

		tun1Check, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil || tun1Check.ActiveConnections != 1 {
			t.Fatalf("expected tun1 ActiveConnections == 1, got %d (err=%v)", tun1Check.ActiveConnections, err)
		}
		tun2Check, err := svc.pool.GetTunnelByID(tun2.ID)
		if err != nil || tun2Check.ActiveConnections != 0 {
			t.Fatalf("expected tun2 ActiveConnections == 0, got %d (err=%v)", tun2Check.ActiveConnections, err)
		}
		affPre, ok := svc.stickyMgr.GetPeerAffinity(peerKey)
		if !ok || affPre != tun1.ID {
			t.Fatalf("expected peer affinity to tun1 (%d), got ok=%v aff=%d", tun1.ID, ok, affPre)
		}

		canceledCtx, cancel := context.WithCancel(ctx)
		cancel()

		err = svc.DisableBackend(canceledCtx, s1ID)
		if err == nil {
			t.Fatal("expected DisableBackend to return error on DB persistence failure, got nil")
		}
		if !strings.Contains(err.Error(), "failed to persist administrative backend disable") {
			t.Errorf("unexpected error message: %v", err)
		}

		tunAfter, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tunAfter.Status != TunnelStatusActive {
			t.Errorf("expected pool status to remain %q, got %q", TunnelStatusActive, tunAfter.Status)
		}

		devAfter := svc.GetBackendDeviceForTest(tun1.ID)
		if devAfter == nil {
			t.Fatal("expected backend device to remain attached in service map, got nil")
		}
		if devAfter.IsClosed() {
			t.Error("expected backend device to remain open, but IsClosed() is true")
		}

		affPost, ok := svc.stickyMgr.GetPeerAffinity(peerKey)
		if !ok || affPost != tun1.ID {
			t.Errorf("expected peer affinity preserved for tun1 (%d), got ok=%v aff=%d", tun1.ID, ok, affPost)
		}
		tun1Final, err := svc.pool.GetTunnelByID(tun1.ID)
		if err != nil || tun1Final.ActiveConnections != 1 {
			t.Errorf("expected tun1 ActiveConnections to remain 1, got %d (err=%v)", tun1Final.ActiveConnections, err)
		}
		tun2Final, err := svc.pool.GetTunnelByID(tun2.ID)
		if err != nil || tun2Final.ActiveConnections != 0 {
			t.Errorf("expected tun2 ActiveConnections to remain 0, got %d (err=%v)", tun2Final.ActiveConnections, err)
		}
		liveSess, ok := svc.sessionMgr.GetSession(peerKey)
		if !ok || liveSess.BackendTunnelID != tun1.ID {
			t.Errorf("expected session backend to remain tun1 (%d), got ok=%v id=%d", tun1.ID, ok, liveSess.BackendTunnelID)
		}
	})

	t.Run("ClosedDB", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()

		svc, err := NewVPNService(db, nil)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}

		s1ID, pub1, _ := createTestServerAndKey(t, db, "Backend Srv ClosedDB", "127.0.0.1")
		tun1, err := svc.pool.AddTunnel(ctx, s1ID, "127.0.0.1:51823", pub1)
		if err != nil {
			t.Fatalf("AddTunnel failed: %v", err)
		}

		svc.mu.Lock()
		err = svc.attachBackendForwarder(tun1, nil)
		svc.mu.Unlock()
		if err != nil {
			t.Fatalf("attachBackendForwarder failed: %v", err)
		}

		devBefore := svc.GetBackendDeviceForTest(tun1.ID)
		if devBefore == nil {
			t.Fatal("expected backend device attached before test, got nil")
		}
		if devBefore.IsClosed() {
			t.Fatal("expected backend device to be open before test")
		}
		t.Cleanup(func() { _ = devBefore.Close() })

		// Close DB to inject DB write error
		_ = db.Close()

		err = svc.DisableBackend(ctx, s1ID)
		if err == nil {
			t.Fatal("expected DisableBackend to return error when DB is closed, got nil")
		}
		if !strings.Contains(err.Error(), "failed to persist administrative backend disable") {
			t.Errorf("unexpected error message: %v", err)
		}

		tunAfter, err := svc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if tunAfter.Status != TunnelStatusActive {
			t.Errorf("expected pool status to remain %q, got %q", TunnelStatusActive, tunAfter.Status)
		}

		devAfter := svc.GetBackendDeviceForTest(tun1.ID)
		if devAfter == nil {
			t.Fatal("expected backend device to remain attached in service map, got nil")
		}
		if devAfter.IsClosed() {
			t.Error("expected backend device to remain open, but IsClosed() is true")
		}
	})
}
