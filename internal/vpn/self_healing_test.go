package vpn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// TestSelfHealing_EndToEndRecovery verifies the full lifecycle:
// 3 probe failures auto-disable backend -> ProbeAll skips it ->
// server recovers -> SelfHealSweep applies flap damping ->
// recovery re-attaches forwarder device, resets fail count, and sets status to active.
func TestSelfHealing_EndToEndRecovery(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	var probeFails atomic.Bool
	probeFails.Store(true)

	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeFails.Load() {
			return 0, errors.New("simulated probe timeout")
		}
		return 25 * time.Millisecond, nil
	})

	tun := tunMust(t, vpnSvc, s1ID)

	// Step 1: 3 probe failures auto-disable the backend
	for i := 0; i < 3; i++ {
		if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
			t.Fatalf("expected probe failure %d", i+1)
		}
	}

	got, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if got.Status != "disabled" {
		t.Fatalf("expected backend status disabled after 3 failures, got %q", got.Status)
	}
	if !vpnSvc.prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected backend %d to be marked auto-disabled", s1ID)
	}

	// Step 2: Regular ProbeAll skips auto-disabled backend (regression invariant)
	probeResults := vpnSvc.prober.ProbeAll(ctx)
	if _, probed := probeResults[s1ID]; probed {
		t.Fatalf("expected ProbeAll to skip disabled backend %d, got %v", s1ID, probeResults[s1ID])
	}
	tun = tunMust(t, vpnSvc, s1ID)
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); !errors.Is(err, tunnel.ErrTunnelDisabled) {
		t.Fatalf("expected ErrTunnelDisabled on direct ProbeTunnel, got %v", err)
	}

	// Step 3: Backend server recovers. First SelfHealSweep satisfies flap damping cycle 1
	probeFails.Store(false)

	reconnected := vpnSvc.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected on first sweep due to flap damping, got %d", reconnected)
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "disabled" {
		t.Fatalf("expected status disabled during flap damping, got %q", got.Status)
	}
	autoDisabled, successes := vpnSvc.prober.GetSelfHealingState(s1ID)
	if !autoDisabled || successes != 1 {
		t.Fatalf("expected autoDisabled=true and successes=1, got autoDisabled=%v, successes=%d", autoDisabled, successes)
	}

	// Step 4: Second sweep satisfies flap damping threshold (2 consecutive successes) -> recovery
	reconnected = vpnSvc.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected on second sweep, got %d", reconnected)
	}

	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "active" {
		t.Fatalf("expected status active after self-healing, got %q", got.Status)
	}
	if vpnSvc.prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected autoDisabled to be cleared after recovery")
	}

	// Verify forwarder data plane device is re-attached
	dev := vpnSvc.GetBackendDeviceForTest(got.ID)
	if dev == nil {
		t.Fatalf("expected backend forwarder device attached for tunnel %d after recovery", got.ID)
	}
}

// TestSelfHealing_SubsequentFailureGracePeriodRestored verifies that after
// self-healing recovery, the consecutive failure counter is cleared and the
// backend gets the full FailureThreshold (3) grace period.
func TestSelfHealing_SubsequentFailureGracePeriodRestored(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	var probeFails atomic.Bool
	probeFails.Store(true)

	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeFails.Load() {
			return 0, errors.New("simulated probe timeout")
		}
		return 20 * time.Millisecond, nil
	})

	tun := tunMust(t, vpnSvc, s1ID)

	// Trigger 3 failures -> auto-disable
	for i := 0; i < 3; i++ {
		_, _ = vpnSvc.prober.ProbeTunnel(ctx, tun)
	}

	// Server recovers -> 2 sweeps restore it
	probeFails.Store(false)
	vpnSvc.SelfHealSweep(ctx)
	reconnected := vpnSvc.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected, got %d", reconnected)
	}

	got, _ := vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "active" {
		t.Fatalf("expected status active, got %q", got.Status)
	}

	// Subsequent failures after recovery: must require full 3 failures
	probeFails.Store(true)

	// Failure 1 -> degraded
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe error on failure 1")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "degraded" {
		t.Fatalf("expected degraded on failure 1 after recovery, got %q", got.Status)
	}

	// Failure 2 -> degraded
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe error on failure 2")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "degraded" {
		t.Fatalf("expected degraded on failure 2 after recovery, got %q", got.Status)
	}

	// Failure 3 -> disabled
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe error on failure 3")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "disabled" {
		t.Fatalf("expected disabled on failure 3 after recovery, got %q", got.Status)
	}
}

// TestSelfHealing_AdminDisabledBackendNeverRecovered verifies that an
// administratively disabled backend via DisableBackend is NEVER recovered
// by SelfHealSweep.
func TestSelfHealing_AdminDisabledBackendNeverRecovered(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		// Probes succeed
		return 15 * time.Millisecond, nil
	})

	// Administratively disable backend via DisableBackend. Administrative
	// intent changes independently from runtime health (issue #90).
	beforeDisable, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel before disable failed: %v", err)
	}
	healthBeforeDisable := beforeDisable.Status
	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	got, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if got.Enabled {
		t.Fatal("expected backend to be administratively disabled")
	}
	if got.Status != healthBeforeDisable {
		t.Fatalf("administrative disable changed runtime health: got %q want %q", got.Status, healthBeforeDisable)
	}
	if vpnSvc.prober.IsAutoDisabled(s1ID) {
		t.Fatalf("administratively disabled backend must not be marked auto-disabled")
	}

	// Run multiple SelfHealSweep iterations: none must resurrect the admin-disabled backend
	for i := 0; i < 5; i++ {
		reconnected := vpnSvc.SelfHealSweep(ctx)
		if reconnected != 0 {
			t.Fatalf("sweep %d: expected 0 reconnected for admin-disabled backend, got %d", i+1, reconnected)
		}
	}

	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Enabled {
		t.Fatal("administratively disabled backend was re-enabled")
	}
	if got.Status != healthBeforeDisable {
		t.Fatalf("administratively disabled backend runtime health changed to %q", got.Status)
	}

	// Backend device must remain detached
	dev := vpnSvc.GetBackendDeviceForTest(got.ID)
	if dev != nil {
		t.Fatalf("expected backend device to remain nil for admin-disabled tunnel")
	}
}

// TestSelfHealing_AutoDisabledSurvivesRestartAndRecovers verifies that
// runtime health and administrative intent are restored independently: a
// health-disabled backend remains administratively enabled and self-healable.
func TestSelfHealing_AutoDisabledSurvivesRestartAndRecovers(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc1, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc1.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	var probeFails atomic.Bool
	probeFails.Store(true)
	vpnSvc1.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		if probeFails.Load() {
			return 0, errors.New("simulated probe timeout")
		}
		return 20 * time.Millisecond, nil
	})

	tun := tunMust(t, vpnSvc1, s1ID)
	for i := 0; i < 3; i++ {
		_, _ = vpnSvc1.prober.ProbeTunnel(ctx, tun)
	}

	got, err := vpnSvc1.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.Status != models.TunnelStatusDisabled || got.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected enabled health-disabled backend before restart, got %+v", got)
	}

	cfg := vpnSvc1.cfg
	_ = vpnSvc1.Stop()

	vpnSvc2, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("recreating NewVPNService failed: %v", err)
	}
	defer vpnSvc2.Stop()
	if err := vpnSvc2.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB on recreated service failed: %v", err)
	}

	restarted, err := vpnSvc2.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Enabled || restarted.Status != models.TunnelStatusDisabled || restarted.DisableReason != models.DisableReasonHealth {
		t.Fatalf("restart did not preserve independent state dimensions: %+v", restarted)
	}
	if !vpnSvc2.prober.IsAutoDisabled(s1ID) {
		t.Fatal("recreated service must recognize persisted health-disabled backend")
	}

	probeFails.Store(false)
	vpnSvc2.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if got := vpnSvc2.SelfHealSweep(ctx); got != 0 {
		t.Fatalf("first flap-damping sweep reconnected %d tunnels, want 0", got)
	}
	if got := vpnSvc2.SelfHealSweep(ctx); got != 1 {
		t.Fatalf("second self-heal sweep reconnected %d tunnels, want 1", got)
	}

	recovered, err := vpnSvc2.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Enabled || recovered.Status != models.TunnelStatusActive || recovered.DisableReason != models.DisableReasonNone {
		t.Fatalf("self-healing did not restore backend: %+v", recovered)
	}
}

// TestSelfHealing_AdminDisabledSurvivesRestartAndRemainsDisabled verifies that
// an administratively disabled backend (models.DisableReasonAdmin) survives process
// restart and is NEVER automatically resurrected by SelfHealSweep.
func TestSelfHealing_AdminDisabledSurvivesRestartAndRemainsDisabled(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc1, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc1.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	beforeDisable, err := vpnSvc1.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	healthBeforeDisable := beforeDisable.Status
	if err := vpnSvc1.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	got, err := vpnSvc1.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if got.Enabled || got.DisableReason != models.DisableReasonAdmin || got.Status != healthBeforeDisable {
		t.Fatalf("expected admin-disabled backend with preserved health, got %+v", got)
	}

	// Simulate restart
	cfg := vpnSvc1.cfg
	_ = vpnSvc1.Stop()

	vpnSvc2, err := NewVPNService(db, cfg)
	if err != nil {
		t.Fatalf("recreating NewVPNService failed: %v", err)
	}
	defer vpnSvc2.Stop()
	if err := vpnSvc2.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	// Recreated service must NOT consider it auto-disabled
	if vpnSvc2.prober.IsAutoDisabled(s1ID) {
		t.Fatal("recreated service must NOT consider admin-disabled backend as auto-disabled")
	}

	// Even if probes succeed, sweeps must NEVER resurrect it
	vpnSvc2.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	})

	for i := 0; i < 5; i++ {
		reconnected := vpnSvc2.SelfHealSweep(ctx)
		if reconnected != 0 {
			t.Fatalf("sweep %d: expected 0 reconnected, got %d", i+1, reconnected)
		}
	}

	got2, _ := vpnSvc2.pool.GetTunnel(s1ID)
	if got2.Enabled || got2.DisableReason != models.DisableReasonAdmin || got2.Status != healthBeforeDisable {
		t.Fatalf("admin-disabled tunnel changed after restart/sweeps: %+v", got2)
	}
}

// TestSelfHealing_ConcurrentDisableBackendDuringSelfHeal verifies that if an administrator
// calls DisableBackend concurrently while a self-healing recovery sweep is in-flight,
// the administrative disable wins, the backend is not resurrected, and no forwarder
// device is attached.
func TestSelfHealing_ConcurrentDisableBackendDuringSelfHeal(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	var probeFails atomic.Bool
	probeFails.Store(true)

	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeFails.Load() {
			return 0, errors.New("simulated probe timeout")
		}
		return 20 * time.Millisecond, nil
	})

	tun := tunMust(t, vpnSvc, s1ID)

	// Step 1: Auto-disable backend via 3 failures
	for i := 0; i < 3; i++ {
		_, _ = vpnSvc.prober.ProbeTunnel(ctx, tun)
	}

	got, _ := vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != models.TunnelStatusDisabled || got.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected health auto-disabled, got status=%q, reason=%q", got.Status, got.DisableReason)
	}

	// Step 2: Probes start succeeding
	probeFails.Store(false)

	// Sweep once to pass flap damping 1
	vpnSvc.SelfHealSweep(ctx)

	// Setup synchronization barrier on the prober's recovery hook
	hookEntered := make(chan struct{})
	hookRelease := make(chan struct{})

	// Intercept the recovery hook with barrier
	vpnSvc.prober.SetOnSelfHealHook(func(hookCtx context.Context, tunnel *models.BackendTunnel) error {
		close(hookEntered)
		<-hookRelease
		// Attempt EnableBackend as production does
		return vpnSvc.EnableBackend(hookCtx, tunnel.ServerID)
	})

	sweepDone := make(chan int)
	go func() {
		sweepDone <- vpnSvc.SelfHealSweep(ctx)
	}()

	// Wait until self-healing enters the hook
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for self-heal hook entry")
	}

	// While self-heal is paused inside hook, an administrator calls DisableBackend!
	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	// Release hook
	close(hookRelease)

	var reconnected int
	select {
	case reconnected = <-sweepDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sweep completion")
	}

	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected when admin disable raced self-heal, got %d", reconnected)
	}

	// Invariant verification: backend MUST be disabled with reason admin
	gotAfter, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if gotAfter.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status disabled, got %q", gotAfter.Status)
	}
	if gotAfter.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected disable_reason admin, got %q", gotAfter.DisableReason)
	}

	// Forwarder device must remain detached
	dev := vpnSvc.GetBackendDeviceForTest(gotAfter.ID)
	if dev != nil {
		t.Fatal("backend device must not be attached after concurrent admin disable")
	}
}

// TestSelfHealing_HighLatencyProductionRecoveryMarkedDegraded verifies that a backend
// recovering from auto-disable with latency exceeding LatencyThresholdMS (500ms)
// is committed as degraded (not active) with its measured latency in both pool and database,
// while its forwarder data-plane device is properly attached.
func TestSelfHealing_HighLatencyProductionRecoveryMarkedDegraded(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	var probeFails atomic.Bool
	probeFails.Store(true)

	// Recovered latency is 700ms, which exceeds HealthConfig.LatencyThresholdMS (500ms)
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeFails.Load() {
			return 0, errors.New("simulated probe failure")
		}
		return 700 * time.Millisecond, nil
	})

	tun := tunMust(t, vpnSvc, s1ID)

	// Step 1: 3 probe failures auto-disable the backend
	for i := 0; i < 3; i++ {
		if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
			t.Fatalf("expected probe failure %d", i+1)
		}
	}

	got, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if got.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status disabled, got %q", got.Status)
	}
	if !vpnSvc.prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected backend %d to be marked auto-disabled", s1ID)
	}

	// Step 2: Backend recovers with high latency (700ms > 500ms)
	probeFails.Store(false)

	// Sweep 1: flap damping 1st success (threshold = 2)
	reconnected := vpnSvc.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected on first sweep due to flap damping, got %d", reconnected)
	}

	tunAfterFirst, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfterFirst.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status to remain disabled after 1 success, got %q", tunAfterFirst.Status)
	}

	// Sweep 2: flap damping 2nd success triggers recovery
	reconnected = vpnSvc.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected on second sweep, got %d", reconnected)
	}

	// Step 3: Verify pool tunnel status is "degraded" (NOT "active") and latency is 700ms
	poolTun, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if poolTun.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected pool status degraded, got %q", poolTun.Status)
	}
	if poolTun.LatencyMS != 700 {
		t.Fatalf("expected pool latency 700ms, got %d", poolTun.LatencyMS)
	}

	// Step 4: Verify DB tunnel status is "degraded" (NOT "active") and latency is 700ms
	dbTun, err := db.GetBackendTunnelByServerID(ctx, s1ID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbTun.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected DB status degraded, got %q", dbTun.Status)
	}
	if dbTun.LatencyMS != 700 {
		t.Fatalf("expected DB latency 700ms, got %d", dbTun.LatencyMS)
	}

	// Step 5: Verify forwarder device is attached
	dev := vpnSvc.GetBackendDeviceForTest(poolTun.ID)
	if dev == nil {
		t.Fatal("expected backend forwarder device to be attached after high-latency recovery")
	}
}

// TestInFlightProbe_ConcurrentWithDisableBackend verifies that when ProbeTunnel is in-flight
// and races DisableBackend, the backend is not left in an auto-disabled state and its
// forwarder device is not re-attached.
func TestInFlightProbe_ConcurrentWithDisableBackend(t *testing.T) {
	t.Run("FailureRace", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()

		vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
		if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB failed: %v", err)
		}
		if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
			t.Fatalf("EnableBackend failed: %v", err)
		}

		tun := tunMust(t, vpnSvc, s1ID)
		if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev == nil {
			t.Fatal("expected backend device to be initially attached")
		}

		probeStarted := make(chan struct{})
		releaseProbe := make(chan struct{})

		vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			select {
			case <-probeStarted:
			default:
				close(probeStarted)
			}
			<-releaseProbe
			return 0, errors.New("simulated in-flight probe timeout")
		})

		probeErrCh := make(chan error, 1)
		go func() {
			_, err := vpnSvc.prober.ProbeTunnel(ctx, tun)
			probeErrCh <- err
		}()

		select {
		case <-probeStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for probe to start")
		}

		// Administrator disables backend while probe is in flight
		if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
			t.Fatalf("DisableBackend failed: %v", err)
		}

		// Release probe to return error
		close(releaseProbe)

		select {
		case err := <-probeErrCh:
			if err == nil {
				t.Fatal("expected probe to return error")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for probe completion")
		}

		// Verify pool status is disabled with reason admin
		poolTun, err := vpnSvc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if poolTun.Status != models.TunnelStatusDisabled {
			t.Fatalf("expected status disabled, got %q", poolTun.Status)
		}
		if poolTun.DisableReason != models.DisableReasonAdmin {
			t.Fatalf("expected disable_reason admin, got %q", poolTun.DisableReason)
		}

		// Verify DB status is disabled with reason admin
		dbTun, err := db.GetBackendTunnelByServerID(ctx, s1ID)
		if err != nil {
			t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
		}
		if dbTun.Status != models.TunnelStatusDisabled {
			t.Fatalf("expected DB status disabled, got %q", dbTun.Status)
		}
		if dbTun.DisableReason != models.DisableReasonAdmin {
			t.Fatalf("expected DB disable_reason admin, got %q", dbTun.DisableReason)
		}

		// Verify prober does not consider it auto-disabled
		if vpnSvc.prober.IsAutoDisabled(s1ID) {
			t.Fatal("expected IsAutoDisabled to be false after admin disable")
		}

		// Verify forwarder device remains detached
		if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
			t.Fatal("backend device must remain detached after DisableBackend")
		}

		// Verify self-healing sweep does not resurrect it
		if reconnected := vpnSvc.SelfHealSweep(ctx); reconnected != 0 {
			t.Fatalf("expected 0 reconnected, got %d", reconnected)
		}
	})

	t.Run("SuccessRace", func(t *testing.T) {
		db := setupTestDB(t)
		ctx := context.Background()

		vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
		if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
			t.Fatalf("SyncFromDB failed: %v", err)
		}
		if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
			t.Fatalf("EnableBackend failed: %v", err)
		}

		tun := tunMust(t, vpnSvc, s1ID)
		if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev == nil {
			t.Fatal("expected backend device to be initially attached")
		}

		probeStarted := make(chan struct{})
		releaseProbe := make(chan struct{})

		vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			select {
			case <-probeStarted:
			default:
				close(probeStarted)
			}
			<-releaseProbe
			return 25 * time.Millisecond, nil
		})

		probeErrCh := make(chan error, 1)
		go func() {
			_, err := vpnSvc.prober.ProbeTunnel(ctx, tun)
			probeErrCh <- err
		}()

		select {
		case <-probeStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for probe to start")
		}

		// Administrator disables backend while probe is in flight
		if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
			t.Fatalf("DisableBackend failed: %v", err)
		}

		// Release probe to return success
		close(releaseProbe)

		select {
		case err := <-probeErrCh:
			if !errors.Is(err, tunnel.ErrTunnelDisabled) {
				t.Fatalf("expected ErrTunnelDisabled, got %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for probe completion")
		}

		// Verify pool status is disabled with reason admin
		poolTun, err := vpnSvc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("GetTunnel failed: %v", err)
		}
		if poolTun.Status != models.TunnelStatusDisabled {
			t.Fatalf("expected status disabled, got %q", poolTun.Status)
		}
		if poolTun.DisableReason != models.DisableReasonAdmin {
			t.Fatalf("expected disable_reason admin, got %q", poolTun.DisableReason)
		}

		// Verify DB status is disabled with reason admin
		dbTun, err := db.GetBackendTunnelByServerID(ctx, s1ID)
		if err != nil {
			t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
		}
		if dbTun.Status != models.TunnelStatusDisabled {
			t.Fatalf("expected DB status disabled, got %q", dbTun.Status)
		}
		if dbTun.DisableReason != models.DisableReasonAdmin {
			t.Fatalf("expected DB disable_reason admin, got %q", dbTun.DisableReason)
		}

		// Verify forwarder device was not re-attached
		if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
			t.Fatal("backend device must not be re-attached after in-flight probe success")
		}

		// Verify prober does not consider it auto-disabled
		if vpnSvc.prober.IsAutoDisabled(s1ID) {
			t.Fatal("expected IsAutoDisabled to be false after admin disable")
		}

		// Verify self-healing sweep does not resurrect it
		if reconnected := vpnSvc.SelfHealSweep(ctx); reconnected != 0 {
			t.Fatalf("expected 0 reconnected, got %d", reconnected)
		}
	})
}

// TestEnsureBackendDeviceAttached_TOCTOURaceWithDisableBackend verifies that if DisableBackend
// races ensureBackendDeviceAttached after initial validation but before acquiring s.mu,
// the attachment critical section re-validates the tunnel state under lock, refuses to
// attach the forwarder device, and returns ErrTunnelDisabled.
func TestEnsureBackendDeviceAttached_TOCTOURaceWithDisableBackend(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun := tunMust(t, vpnSvc, s1ID)

	// Ensure device is initially not attached so ensureBackendDeviceAttached attempts attachment
	if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Fatal("expected backend device to be initially nil")
	}

	// Set the pre-lock hook to simulate an administrator calling DisableBackend right before s.mu.Lock()
	var hookCalled atomic.Bool
	vpnSvc.SetEnsureDevicePreLockHook(func() {
		hookCalled.Store(true)
		if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
			t.Errorf("DisableBackend in hook failed: %v", err)
		}
	})

	err := vpnSvc.ensureBackendDeviceAttached(ctx, tun)
	if !errors.Is(err, ErrTunnelDisabled) {
		t.Fatalf("expected ErrTunnelDisabled, got %v", err)
	}
	if !hookCalled.Load() {
		t.Fatal("expected ensureDevicePreLockHook to be called")
	}

	// Assert that forwarder device remains detached
	if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
		t.Fatal("backend device must not be attached after concurrent admin disable")
	}

	// Assert pool status remains disabled with reason admin
	poolTun, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if poolTun.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected pool status disabled, got %q", poolTun.Status)
	}
	if poolTun.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected pool disable_reason admin, got %q", poolTun.DisableReason)
	}

	// Assert DB status remains disabled with reason admin
	dbTun, err := db.GetBackendTunnelByServerID(ctx, s1ID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if dbTun.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected DB status disabled, got %q", dbTun.Status)
	}
	if dbTun.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected DB disable_reason admin, got %q", dbTun.DisableReason)
	}

	// Assert prober does not consider it auto-disabled
	if vpnSvc.prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected IsAutoDisabled to be false after admin disable")
	}

	// Assert SelfHealSweep does not resurrect it
	if reconnected := vpnSvc.SelfHealSweep(ctx); reconnected != 0 {
		t.Fatalf("expected 0 reconnected, got %d", reconnected)
	}
}
