package vpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
)

// TestOrchestrator_AdminDisableConcurrentWithProbePreservedOnRestart verifies that:
// 1. When an active backend is being probed by the Orchestrator,
// 2. An administrator calls DisableBackend before probe completion,
// 3. The probe completion does NOT overwrite the administrative disable,
// 4. In-memory pool status and database records remain disabled with reason "admin",
// 5. Restarting the VPN service does NOT resurrect the tunnel or attach its forwarder device.
func TestOrchestrator_AdminDisableConcurrentWithProbePreservedOnRestart(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)

	sID, pub, _ := createTestServerAndKey(t, db, "Concurrent Srv", "127.0.0.1")

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	tun, err := vpnSvc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	vpnSvc.mu.Lock()
	err = vpnSvc.attachBackendForwarder(tun, nil)
	vpnSvc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	devBefore := vpnSvc.GetBackendDeviceForTest(tun.ID)
	if devBefore == nil || devBefore.IsClosed() {
		t.Fatalf("expected attached open backend device before test")
	}
	t.Cleanup(func() { _ = devBefore.Close() })

	probeStarted := make(chan struct{})
	probeBlock := make(chan struct{})
	var probeOnce sync.Once

	customProbe := func(probeCtx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probeOnce.Do(func() {
			close(probeStarted)
			<-probeBlock
		})
		return 25 * time.Millisecond, nil
	}

	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFunc(customProbe),
	)
	orch.SetTunnelStatusUpdater(vpnSvc)

	// Step 1: Orchestrator starts health check in background goroutine
	orchDone := make(chan error, 1)
	go func() {
		orchDone <- orch.CheckBackendTunnelHealth(ctx)
	}()

	// Step 2: Wait until probe has started and is blocked at the barrier
	select {
	case <-probeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe to start")
	}

	// Step 3: Administrator calls DisableBackend concurrently while probe is in-flight
	if err := vpnSvc.DisableBackend(ctx, sID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	// Step 4: Release the probe so Orchestrator completes probe and attempts status update
	close(probeBlock)

	select {
	case err := <-orchDone:
		if err != nil {
			t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CheckBackendTunnelHealth to complete")
	}

	// Step 5: Assert DB tunnel record remains status="disabled" and disable_reason="admin"
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTun == nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbTun.Status != "disabled" {
		t.Errorf("expected DB status 'disabled', got %q", dbTun.Status)
	}
	if dbTun.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected DB disable_reason %q, got %q", models.DisableReasonAdmin, dbTun.DisableReason)
	}

	// Step 6: Assert pool status remains "disabled" and disable_reason="admin"
	poolTun, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTun == nil {
		t.Fatalf("pool GetTunnel failed: %v", err)
	}
	if poolTun.Status != TunnelStatusDisabled {
		t.Errorf("expected pool status %q, got %q", TunnelStatusDisabled, poolTun.Status)
	}
	if poolTun.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected pool disable_reason %q, got %q", models.DisableReasonAdmin, poolTun.DisableReason)
	}

	// Step 7: Recreate VPN service from the same DB (simulating restart)
	vpnSvcRestarted, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService (restarted) failed: %v", err)
	}
	if err := vpnSvcRestarted.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB on restarted service failed: %v", err)
	}
	vpnSvcRestarted.restoreBackendDevices(ctx)

	// Step 8: Assert backend remains disabled and its data plane device is NOT attached
	restartedTun, err := vpnSvcRestarted.pool.GetTunnel(sID)
	if err != nil || restartedTun == nil {
		t.Fatalf("restarted pool GetTunnel failed: %v", err)
	}
	if restartedTun.Status != TunnelStatusDisabled {
		t.Errorf("expected restarted pool status %q, got %q", TunnelStatusDisabled, restartedTun.Status)
	}
	if restartedTun.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected restarted pool disable_reason %q, got %q", models.DisableReasonAdmin, restartedTun.DisableReason)
	}

	restartedDev := vpnSvcRestarted.GetBackendDeviceForTest(restartedTun.ID)
	if restartedDev != nil {
		t.Errorf("expected backend device to NOT be attached after restart for admin-disabled tunnel, got %v", restartedDev)
	}
}

// TestOrchestrator_AdminDisableConcurrentWithProbe_CASFallback verifies that even when
// Orchestrator has no statusUpdater configured (falling back to direct DB CAS updates),
// an admin disable during an in-flight probe is not overwritten due to state version mismatch.
func TestOrchestrator_AdminDisableConcurrentWithProbe_CASFallback(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)

	sID, pub, _ := createTestServerAndKey(t, db, "CAS Fallback Srv", "127.0.0.1")

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	tun, err := vpnSvc.pool.AddTunnel(ctx, sID, "127.0.0.1:51821", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeStarted := make(chan struct{})
	probeBlock := make(chan struct{})
	var probeOnce sync.Once

	customProbe := func(probeCtx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probeOnce.Do(func() {
			close(probeStarted)
			<-probeBlock
		})
		return 20 * time.Millisecond, nil
	}

	// Orchestrator initialized WITHOUT statusUpdater (nil updater -> CAS fallback)
	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFunc(customProbe),
	)

	orchDone := make(chan error, 1)
	go func() {
		orchDone <- orch.CheckBackendTunnelHealth(ctx)
	}()

	select {
	case <-probeStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe to start")
	}

	// Admin disables backend
	if err := vpnSvc.DisableBackend(ctx, sID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	close(probeBlock)

	select {
	case err := <-orchDone:
		if err != nil {
			t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CheckBackendTunnelHealth")
	}

	// Verify DB record remained disabled with reason admin
	dbTun, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil || dbTun == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if dbTun.Status != "disabled" {
		t.Errorf("expected DB status 'disabled', got %q", dbTun.Status)
	}
	if dbTun.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected DB disable_reason %q, got %q", models.DisableReasonAdmin, dbTun.DisableReason)
	}
}

// TestOrchestrator_ConcurrentAdminDisableDuringProbe_NeverReceivesMigratedSessions verifies that:
// 1. Probe for Backend A begins.
// 2. Administrator concurrently calls DisableBackend on Backend A.
// 3. Backend A probe finishes successfully, but is not added to healthyTunnels.
// 4. Backend B probe fails and B is marked degraded.
// 5. Orchestrator attempts migration for B's active sessions.
// 6. Sessions from B are NOT assigned to A.
func TestOrchestrator_ConcurrentAdminDisableDuringProbe_NeverReceivesMigratedSessions(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)

	sAID, pubA, _ := createTestServerAndKey(t, db, "Backend A", "127.0.0.1")
	sBID, pubB, _ := createTestServerAndKey(t, db, "Backend B", "127.0.0.1")

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	tunA, err := vpnSvc.pool.AddTunnel(ctx, sAID, "127.0.0.1:51830", pubA)
	if err != nil {
		t.Fatalf("AddTunnel A failed: %v", err)
	}
	tunB, err := vpnSvc.pool.AddTunnel(ctx, sBID, "127.0.0.1:51831", pubB)
	if err != nil {
		t.Fatalf("AddTunnel B failed: %v", err)
	}

	vpnSvc.mu.Lock()
	_ = vpnSvc.attachBackendForwarder(tunA, nil)
	_ = vpnSvc.attachBackendForwarder(tunB, nil)
	vpnSvc.mu.Unlock()

	t.Cleanup(func() {
		if devA := vpnSvc.GetBackendDeviceForTest(tunA.ID); devA != nil {
			_ = devA.Close()
		}
		if devB := vpnSvc.GetBackendDeviceForTest(tunB.ID); devB != nil {
			_ = devB.Close()
		}
	})

	uID, err := db.CreateUser(ctx, &models.User{Username: "test_mig_user", Role: models.RoleUser})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	sessB := &models.VPNSession{
		ID:              "sess-b-mig-test",
		UserID:          uID,
		BackendTunnelID: tunB.ID,
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, sessB); err != nil {
		t.Fatalf("CreateVPNSession failed: %v", err)
	}

	probeAStarted := make(chan struct{})
	probeABlock := make(chan struct{})
	var probeAOnce sync.Once

	customProbe := func(probeCtx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if endpoint == "127.0.0.1:51830" {
			probeAOnce.Do(func() {
				close(probeAStarted)
				<-probeABlock
			})
			return 25 * time.Millisecond, nil
		}
		return 0, errors.New("backend B probe failed")
	}

	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFunc(customProbe),
		orchestrator.WithProbeFailureThreshold(1),
	)
	orch.SetTunnelStatusUpdater(vpnSvc)

	orchDone := make(chan error, 1)
	go func() {
		orchDone <- orch.CheckBackendTunnelHealth(ctx)
	}()

	select {
	case <-probeAStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe A to start")
	}

	if err := vpnSvc.DisableBackend(ctx, sAID); err != nil {
		t.Fatalf("DisableBackend A failed: %v", err)
	}

	close(probeABlock)

	select {
	case err := <-orchDone:
		if err != nil {
			t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CheckBackendTunnelHealth")
	}

	dbTunA, err := db.GetBackendTunnel(ctx, tunA.ID)
	if err != nil || dbTunA == nil {
		t.Fatalf("GetBackendTunnel A failed: %v", err)
	}
	if dbTunA.Status != "disabled" || dbTunA.DisableReason != models.DisableReasonAdmin {
		t.Errorf("expected A to remain disabled/admin, got status=%q reason=%q", dbTunA.Status, dbTunA.DisableReason)
	}

	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil || len(sessions) == 0 {
		t.Fatalf("GetActiveVPNSessions failed: %v", err)
	}
	for _, s := range sessions {
		if s.BackendTunnelID == tunA.ID {
			t.Fatalf("active session %s was erroneously migrated onto admin-disabled backend A", s.ID)
		}
	}
}
