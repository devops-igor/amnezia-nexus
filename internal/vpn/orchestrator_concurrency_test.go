package vpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
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

func (f *faultyStatusUpdater) SetTunnelStatusWithVersion(ctx context.Context, serverID, expectedTunnelID, expectedVersion int64, status string, latencyMS int64) error {
	if f.err != nil {
		return f.err
	}
	return f.target.SetTunnelStatusWithVersion(ctx, serverID, expectedTunnelID, expectedVersion, status, latencyMS)
}

// TestOrchestrator_TunUnavailableManagementMode_PoolAndDBSync verifies that:
//  1. When VPN_ENABLED=true but the host has no TUN device (endpoint.ErrTunUnavailable),
//     vpnSvc.Start still executes Pool.SyncFromDB successfully before failing on TUN initialization.
//  2. Wiring orch.SetTunnelStatusUpdater(vpnSvc) in management mode keeps in-memory pool
//     and database records strictly synchronized when Orchestrator runs health updates.
func TestOrchestrator_TunUnavailableManagementMode_PoolAndDBSync(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)

	sID, serverPub, _ := createTestServerAndKey(t, db, "Management Mode Srv", "127.0.0.1")
	_, clientPriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateCurve25519KeyPair failed: %v", err)
	}
	_, probePriv, err := tunnel.GenerateCurve25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateCurve25519KeyPair failed: %v", err)
	}

	now := time.Now().UTC()
	dbTunnel := &models.BackendTunnel{
		ServerID:          sID,
		InterfaceName:     "awg-be-1",
		PublicKey:         serverPub,
		PrivateKey:        clientPriv,
		ProbePrivateKey:   probePriv,
		Endpoint:          "127.0.0.1:51820",
		Status:            "active",
		DisableReason:     models.DisableReasonNone,
		StateVersion:      1,
		LastHealthCheck:   &now,
		LatencyMS:         10,
		ActiveConnections: 0,
		CreatedAt:         now,
	}
	_, err = db.CreateBackendTunnel(ctx, dbTunnel)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	vpnSvc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.RequireTunDevice()
	vpnSvc.SetTunOpener(func() (endpoint.PacketDevice, error) {
		return nil, endpoint.ErrTunUnavailable
	})

	stErr := vpnSvc.Start(ctx)
	if !errors.Is(stErr, endpoint.ErrTunUnavailable) {
		t.Fatalf("expected ErrTunUnavailable from Start, got: %v", stErr)
	}

	// Verify pool contains tunnel synced from DB at version 1
	poolTunInitial, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTunInitial == nil {
		t.Fatalf("pool GetTunnel failed after SyncFromDB: %v", err)
	}
	if poolTunInitial.StateVersion != 1 {
		t.Fatalf("expected initial pool version 1, got %d", poolTunInitial.StateVersion)
	}
	if poolTunInitial.Status != "active" {
		t.Fatalf("expected initial pool status active, got %s", poolTunInitial.Status)
	}

	orch := orchestrator.New(db, nil,
		orchestrator.WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			// Return latency > 2000ms threshold to trigger transition to degraded
			return 2500 * time.Millisecond, nil
		}),
	)
	orch.SetTunnelStatusUpdater(vpnSvc)

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	poolTun, err := vpnSvc.pool.GetTunnel(sID)
	if err != nil || poolTun == nil {
		t.Fatalf("pool GetTunnel after health check failed: %v", err)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil || dbTun == nil {
		t.Fatalf("db GetBackendTunnelByServerID after health check failed: %v", err)
	}

	if poolTun.Status != "degraded" {
		t.Errorf("expected pool status degraded, got %s", poolTun.Status)
	}
	if dbTun.Status != "degraded" {
		t.Errorf("expected db status degraded, got %s", dbTun.Status)
	}
	if poolTun.StateVersion != 2 {
		t.Errorf("expected pool version 2, got %d", poolTun.StateVersion)
	}
	if dbTun.StateVersion != 2 {
		t.Errorf("expected db version 2, got %d", dbTun.StateVersion)
	}
	if poolTun.StateVersion != dbTun.StateVersion {
		t.Fatalf("pool and DB state_version desynchronized: pool=%d, db=%d", poolTun.StateVersion, dbTun.StateVersion)
	}
}

// TestOrchestrator_InFlightProbe_FencedOnEndpointUpdate_NoStatusMutationOrFailover verifies:
//  1. A probe starts targeting an old server endpoint while a VPN session is active on that backend tunnel.
//  2. The server host/endpoint is updated concurrently (via UpdateBackendServerHost), advancing StateVersion to 2.
//  3. The old probe is released and returns failure (or high latency).
//  4. The stale probe result is rejected by the version-aware status updater (SetTunnelStatusWithVersion)
//     and cannot mark the new endpoint degraded or trigger false session failover.
func TestOrchestrator_InFlightProbe_FencedOnEndpointUpdate_NoStatusMutationOrFailover(t *testing.T) {
	for _, tc := range []struct {
		name     string
		probeRTT time.Duration
		probeErr error
		desc     string
	}{
		{
			name:     "probe_failure",
			probeRTT: 0,
			probeErr: errors.New("connection timed out on old IP"),
			desc:     "failed probe targeting old IP cannot mark tunnel degraded or failover sessions",
		},
		{
			name:     "probe_high_latency",
			probeRTT: 3000 * time.Millisecond,
			probeErr: nil,
			desc:     "high-latency probe targeting old IP cannot mark tunnel degraded or failover sessions",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)

			s1ID, pub1, _ := createTestServerAndKey(t, db, "Target Srv 1", "198.51.100.1")
			s2ID, pub2, _ := createTestServerAndKey(t, db, "Peer Srv 2", "198.51.100.2")

			vpnSvc, err := NewVPNService(db, nil)
			if err != nil {
				t.Fatalf("NewVPNService failed: %v", err)
			}
			vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
				return 10 * time.Millisecond, nil
			})

			tun1, err := vpnSvc.pool.AddTunnel(ctx, s1ID, "198.51.100.1:51820", pub1)
			if err != nil {
				t.Fatalf("AddTunnel 1 failed: %v", err)
			}
			tun2, err := vpnSvc.pool.AddTunnel(ctx, s2ID, "198.51.100.2:51820", pub2)
			if err != nil {
				t.Fatalf("AddTunnel 2 failed: %v", err)
			}

			userID, err := db.CreateUser(ctx, &models.User{Username: "fencing-user-" + tc.name})
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Create active VPN session on tunnel 1
			sess := &models.VPNSession{
				ID:              "sess-fencing-test-" + tc.name,
				UserID:          userID,
				BackendTunnelID: tun1.ID,
				PeerPublicKey:   "peer-key-fencing",
				AssignedIP:      "10.8.0.2",
				Status:          "connected",
			}
			if err := db.CreateVPNSession(ctx, sess); err != nil {
				t.Fatalf("CreateVPNSession failed: %v", err)
			}

			probe1Started := make(chan struct{})
			probe1Block := make(chan struct{})
			var probe1Once sync.Once

			orch := orchestrator.New(db, nil,
				orchestrator.WithProbeFailureThreshold(1),
				orchestrator.WithProbeFunc(func(probeCtx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
					if endpoint == "198.51.100.1:51820" {
						probe1Once.Do(func() {
							close(probe1Started)
							<-probe1Block
						})
						return tc.probeRTT, tc.probeErr
					}
					// Peer server 2 is healthy
					return 15 * time.Millisecond, nil
				}),
			)
			orch.SetTunnelStatusUpdater(vpnSvc)

			orchDone := make(chan error, 1)
			go func() {
				orchDone <- orch.CheckBackendTunnelHealth(ctx)
			}()

			// Step 1: Wait for probe to start on old endpoint
			select {
			case <-probe1Started:
			case <-time.After(5 * time.Second):
				close(probe1Block)
				t.Fatal("timed out waiting for probe 1 to start on old endpoint")
			}

			// Step 2: Change endpoint via UpdateBackendServerHost, advancing StateVersion to 2
			newHost := "198.51.100.99"
			if err := vpnSvc.UpdateBackendServerHost(ctx, s1ID, newHost); err != nil {
				close(probe1Block)
				t.Fatalf("UpdateBackendServerHost failed: %v", err)
			}

			// Verify tunnel 1 version was bumped to 2
			t1AfterUpdate, err := vpnSvc.pool.GetTunnelByID(tun1.ID)
			if err != nil || t1AfterUpdate.StateVersion != 2 {
				close(probe1Block)
				t.Fatalf("expected tunnel 1 StateVersion = 2 after host update, got %+v", t1AfterUpdate)
			}

			// Step 3: Release old probe
			close(probe1Block)
			if err := <-orchDone; err != nil {
				t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
			}

			// Step 4: Verify tunnel 1 in pool and DB was NOT marked degraded
			poolTun1, err := vpnSvc.pool.GetTunnel(s1ID)
			if err != nil {
				t.Fatalf("GetTunnel pool failed: %v", err)
			}
			if poolTun1.Status != "active" {
				t.Errorf("expected pool status 'active', got %q", poolTun1.Status)
			}
			if poolTun1.StateVersion != 2 {
				t.Errorf("expected pool StateVersion to remain 2, got %d", poolTun1.StateVersion)
			}

			dbTun1, err := db.GetBackendTunnel(ctx, tun1.ID)
			if err != nil {
				t.Fatalf("GetBackendTunnel DB failed: %v", err)
			}
			if dbTun1.Status != "active" {
				t.Errorf("expected DB status 'active', got %q", dbTun1.Status)
			}
			if dbTun1.StateVersion != 2 {
				t.Errorf("expected DB StateVersion to remain 2, got %d", dbTun1.StateVersion)
			}
			if fc := orch.GetProbeFailCount(tun1.ID); fc != 0 {
				t.Errorf("expected probe fail count = 0 after stale probe fenced, got %d", fc)
			}

			// Step 5: Verify session was NOT migrated to peer tunnel 2
			sessions, err := db.GetActiveVPNSessions(ctx)
			if err != nil {
				t.Fatalf("GetActiveVPNSessions failed: %v", err)
			}
			var foundSess *models.VPNSession
			for i := range sessions {
				if sessions[i].ID == sess.ID {
					foundSess = &sessions[i]
					break
				}
			}
			if foundSess == nil {
				t.Fatalf("session %s not found in DB", sess.ID)
			}
			if foundSess.BackendTunnelID != tun1.ID {
				t.Errorf("session was improperly migrated to tunnel %d (want %d on tunnel 1)", foundSess.BackendTunnelID, tun1.ID)
			}
			_ = tun2
		})
	}
}
