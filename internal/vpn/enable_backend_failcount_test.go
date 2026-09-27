package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestEnableBackendResetsHealthFailCount verifies that an actual administrative
// disable/enable cycle clears accumulated health failures without fabricating a
// healthy status. Two failures first move the backend to degraded; after the
// admin cycle it must receive the full three-failure grace period again.
func TestEnableBackendResetsHealthFailCount(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	vpnSvc.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		return nil
	})

	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("simulated handshake timeout")
	})

	tun := tunMust(t, vpnSvc, s1ID)

	// Accumulate two failures (< threshold 3), leaving runtime health degraded.
	for i := 0; i < 2; i++ {
		if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
			t.Fatalf("failure %d: expected probe error", i+1)
		}
	}
	got, _ := vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected degraded after two failures, got %q", got.Status)
	}

	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	disabled, _ := vpnSvc.pool.GetTunnel(s1ID)
	if disabled.Enabled {
		t.Fatal("expected backend administratively disabled")
	}
	if disabled.Status != models.TunnelStatusDegraded {
		t.Fatalf("admin disable changed runtime health: got %q", disabled.Status)
	}

	if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if !got.Enabled {
		t.Fatal("expected backend administratively enabled")
	}
	if got.Status != models.TunnelStatusDegraded {
		t.Fatalf("admin enable changed runtime health: got %q, want degraded", got.Status)
	}

	// Failure 1 after re-enable must not instantly disable the backend.
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe error after re-enable")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status == models.TunnelStatusDisabled {
		t.Fatal("first probe after EnableBackend re-disabled the backend: fail count was not reset")
	}

	// Failure 2 still remains below threshold.
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected second probe error after re-enable")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status == models.TunnelStatusDisabled {
		t.Fatal("backend re-disabled before reaching FailureThreshold after EnableBackend")
	}

	// Failure 3 reaches threshold.
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected third probe error after re-enable")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != models.TunnelStatusDisabled || got.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected health-disabled after three failures, got status=%q reason=%q", got.Status, got.DisableReason)
	}
}

func TestEnableBackend_ReenablesAdminDisabledHealthState(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("simulated handshake timeout")
	})

	tun := tunMust(t, vpnSvc, s1ID)
	for i := 0; i < 3; i++ {
		_, _ = vpnSvc.prober.ProbeTunnel(ctx, tun)
	}

	healthDisabled, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel after health disable failed: %v", err)
	}
	if !healthDisabled.Enabled || healthDisabled.Status != models.TunnelStatusDisabled || healthDisabled.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected enabled health-disabled backend, got enabled=%v status=%q reason=%q",
			healthDisabled.Enabled, healthDisabled.Status, healthDisabled.DisableReason)
	}

	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	adminDisabled, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel after admin disable failed: %v", err)
	}
	if adminDisabled.Enabled || adminDisabled.Status != models.TunnelStatusDisabled || adminDisabled.DisableReason != models.DisableReasonHealth {
		t.Fatalf("admin disable must preserve health provenance, got enabled=%v status=%q reason=%q",
			adminDisabled.Enabled, adminDisabled.Status, adminDisabled.DisableReason)
	}

	// Manual re-enable changes only administrative eligibility. Runtime health
	// remains disabled/health until the dedicated self-healing path succeeds.
	if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
		t.Fatalf("EnableBackend must allow an already admin-disabled health state: %v", err)
	}
	reenabled, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel after re-enable failed: %v", err)
	}
	if !reenabled.Enabled || reenabled.Status != models.TunnelStatusDisabled || reenabled.DisableReason != models.DisableReasonHealth {
		t.Fatalf("manual enable fabricated health or lost provenance: enabled=%v status=%q reason=%q",
			reenabled.Enabled, reenabled.Status, reenabled.DisableReason)
	}

	vpnSvc.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	if got := vpnSvc.SelfHealSweep(ctx); got != 0 {
		t.Fatalf("first self-heal sweep must respect flap damping, got %d recoveries", got)
	}
	if got := vpnSvc.SelfHealSweep(ctx); got != 1 {
		t.Fatalf("second self-heal sweep should recover backend, got %d recoveries", got)
	}
	recovered, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel after self-heal failed: %v", err)
	}
	if !recovered.Enabled || recovered.Status != models.TunnelStatusActive || recovered.DisableReason != models.DisableReasonNone {
		t.Fatalf("unexpected recovered state: enabled=%v status=%q reason=%q",
			recovered.Enabled, recovered.Status, recovered.DisableReason)
	}
}
