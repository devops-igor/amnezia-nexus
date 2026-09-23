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

// TestOrchestrator_TunnelStatusUpdater_PoolAndDBSync verifies that when
// orch.SetTunnelStatusUpdater(vpnSvc) is active, orchestrator health updates
// update vpnSvc.Pool and DB state_version in sync with no offset between pool and DB.
func TestOrchestrator_TunnelStatusUpdater_PoolAndDBSync(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)

	sID, pub, _ := createTestServerAndKey(t, db, "Sync Srv", "127.0.0.1")

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	tun, err := vpnSvc.pool.AddTunnel(ctx, sID, "127.0.0.1:51822", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	initialVersion := tun.StateVersion
	dbTunInitial, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTunInitial == nil {
		t.Fatalf("failed to get initial DB tunnel: %v", err)
	}
	if initialVersion != dbTunInitial.StateVersion {
		t.Fatalf("initial version mismatch: pool=%d, db=%d", initialVersion, dbTunInitial.StateVersion)
	}

	var probeMu sync.Mutex
	probeDuration := 35 * time.Millisecond
	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			probeMu.Lock()
			d := probeDuration
			probeMu.Unlock()
			return d, nil
		}),
	)
	orch.SetTunnelStatusUpdater(vpnSvc)

	// Run first probe cycle
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	poolTun1, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTun1 == nil {
		t.Fatalf("pool GetTunnel failed: %v", err)
	}
	dbTun1, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTun1 == nil {
		t.Fatalf("db GetBackendTunnelByServerID failed: %v", err)
	}

	if poolTun1.Status != "active" || dbTun1.Status != "active" {
		t.Errorf("status mismatch: pool=%q, db=%q", poolTun1.Status, dbTun1.Status)
	}
	if poolTun1.LatencyMS != 35 || dbTun1.LatencyMS != 35 {
		t.Errorf("latency mismatch: pool=%d, db=%d", poolTun1.LatencyMS, dbTun1.LatencyMS)
	}
	if poolTun1.StateVersion != initialVersion+1 {
		t.Errorf("expected pool state_version %d, got %d", initialVersion+1, poolTun1.StateVersion)
	}
	if dbTun1.StateVersion != initialVersion+1 {
		t.Errorf("expected db state_version %d, got %d", initialVersion+1, dbTun1.StateVersion)
	}
	if poolTun1.StateVersion != dbTun1.StateVersion {
		t.Fatalf("pool and DB state_version desynchronized: pool=%d, db=%d", poolTun1.StateVersion, dbTun1.StateVersion)
	}

	// Run second probe cycle with degraded latency (>2000ms default threshold)
	probeMu.Lock()
	probeDuration = 2500 * time.Millisecond
	probeMu.Unlock()

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth (second cycle) failed: %v", err)
	}

	poolTun2, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTun2 == nil {
		t.Fatalf("pool GetTunnel failed: %v", err)
	}
	dbTun2, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTun2 == nil {
		t.Fatalf("db GetBackendTunnelByServerID failed: %v", err)
	}

	if poolTun2.Status != "degraded" || dbTun2.Status != "degraded" {
		t.Errorf("status mismatch on degraded: pool=%q, db=%q", poolTun2.Status, dbTun2.Status)
	}
	if poolTun2.LatencyMS != 2500 || dbTun2.LatencyMS != 2500 {
		t.Errorf("latency mismatch on degraded: pool=%d, db=%d", poolTun2.LatencyMS, dbTun2.LatencyMS)
	}
	if poolTun2.StateVersion != initialVersion+2 {
		t.Errorf("expected pool state_version %d, got %d", initialVersion+2, poolTun2.StateVersion)
	}
	if dbTun2.StateVersion != initialVersion+2 {
		t.Errorf("expected db state_version %d, got %d", initialVersion+2, dbTun2.StateVersion)
	}
	if poolTun2.StateVersion != dbTun2.StateVersion {
		t.Fatalf("pool and DB state_version desynchronized after cycle 2: pool=%d, db=%d", poolTun2.StateVersion, dbTun2.StateVersion)
	}
}

// TestOrchestrator_StartupLifecycleSynchronization verifies that:
//  1. When startup lifecycle ordering wires orch.SetTunnelStatusUpdater(vpnSvc) before Orchestrator ticks,
//     Pool and DB state_version remain strictly identical.
//  2. Operational errors returned by the updater do not trigger direct DB CAS fallback,
//     preventing out-of-band DB mutation and state desynchronization.
func TestOrchestrator_StartupLifecycleSynchronization(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)

	sID, pub, _ := createTestServerAndKey(t, db, "Lifecycle Srv", "127.0.0.1")

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	tun, err := vpnSvc.pool.AddTunnel(ctx, sID, "127.0.0.1:51823", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	initialVersion := tun.StateVersion
	dbTunInitial, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTunInitial == nil {
		t.Fatalf("failed to get initial DB tunnel: %v", err)
	}
	if initialVersion != dbTunInitial.StateVersion {
		t.Fatalf("initial version mismatch: pool=%d, db=%d", initialVersion, dbTunInitial.StateVersion)
	}

	// 1. Verify startup lifecycle ordering: Orchestrator is configured with updater before probing begins
	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 45 * time.Millisecond, nil
		}),
	)
	orch.SetTunnelStatusUpdater(vpnSvc)

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	poolTun1, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTun1 == nil {
		t.Fatalf("pool GetTunnel failed: %v", err)
	}
	dbTun1, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTun1 == nil {
		t.Fatalf("db GetBackendTunnelByServerID failed: %v", err)
	}

	if poolTun1.StateVersion != initialVersion+1 || dbTun1.StateVersion != initialVersion+1 {
		t.Fatalf("expected version %d, got pool=%d, db=%d", initialVersion+1, poolTun1.StateVersion, dbTun1.StateVersion)
	}
	if poolTun1.StateVersion != dbTun1.StateVersion {
		t.Fatalf("pool and DB state_version desynchronized: pool=%d, db=%d", poolTun1.StateVersion, dbTun1.StateVersion)
	}

	// 2. Verify operational error prevents out-of-band DB mutation
	operationalErr := errors.New("simulated operational network error")
	faultyUpdater := &faultyStatusUpdater{
		target: vpnSvc,
		err:    operationalErr,
	}
	orch.SetTunnelStatusUpdater(faultyUpdater)

	// Attempt health check with operational error from updater
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	// DB record must NOT be mutated via CAS fallback on operational error
	dbTunAfterOpErr, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTunAfterOpErr == nil {
		t.Fatalf("db GetBackendTunnelByServerID after operational error failed: %v", err)
	}
	if dbTunAfterOpErr.StateVersion != initialVersion+1 {
		t.Errorf("DB state_version changed despite operational error: expected %d, got %d", initialVersion+1, dbTunAfterOpErr.StateVersion)
	}

	// Pool also remains at initialVersion+1
	poolTunAfterOpErr, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTunAfterOpErr == nil {
		t.Fatalf("pool GetTunnel after operational error failed: %v", err)
	}
	if poolTunAfterOpErr.StateVersion != dbTunAfterOpErr.StateVersion {
		t.Fatalf("version mismatch after operational error: pool=%d, db=%d", poolTunAfterOpErr.StateVersion, dbTunAfterOpErr.StateVersion)
	}
}

type faultyStatusUpdater struct {
	target orchestrator.TunnelStatusUpdater
	err    error
}

func (f *faultyStatusUpdater) SetTunnelStatus(ctx context.Context, serverID int64, status string, latencyMS int64) error {
	if f.err != nil {
		return f.err
	}
	return f.target.SetTunnelStatus(ctx, serverID, status, latencyMS)
}
