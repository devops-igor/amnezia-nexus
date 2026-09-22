package vpn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

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

	// Administratively disable backend via DisableBackend
	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	got, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if got.Status != "disabled" {
		t.Fatalf("expected status disabled, got %q", got.Status)
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
	if got.Status != "disabled" {
		t.Fatalf("administratively disabled backend status changed to %q", got.Status)
	}

	// Backend device must remain detached
	dev := vpnSvc.GetBackendDeviceForTest(got.ID)
	if dev != nil {
		t.Fatalf("expected backend device to remain nil for admin-disabled tunnel")
	}
}
