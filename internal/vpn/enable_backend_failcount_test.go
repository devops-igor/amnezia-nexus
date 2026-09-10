package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// TestEnableBackendResetsHealthFailCount is the end-to-end regression for
// issue #50: a backend auto-disabled by 3 consecutive probe failures, then
// manually re-enabled via EnableBackend, must get the FULL failure-threshold
// grace period again. Before the fix, the prober's in-memory failCounts stayed
// >= threshold after the auto-disable, so the first jittery probe after
// re-enable instantly re-disabled the backend.
func TestEnableBackendResetsHealthFailCount(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	// Hermetic onActiveHook: the production hook would attempt a real AWG
	// device attach; the contract under test is the fail-count lifecycle.
	vpnSvc.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		return nil
	})

	probeShouldFail := true
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeShouldFail {
			return 0, errors.New("simulated handshake timeout")
		}
		return 20 * time.Millisecond, nil
	})

	// Disable the backend via the real health path: 3 consecutive failures.
	tun := tunMust(t, vpnSvc, s1ID)
	for i := 0; i < 3; i++ {
		if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
			t.Fatalf("failure %d: expected probe error", i+1)
		}
	}
	got, _ := vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "disabled" {
		t.Fatalf("expected backend disabled after 3 failing probes, got %q", got.Status)
	}

	// Admin recovers: probe path now healthy, manual re-enable.
	probeShouldFail = false
	if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "active" {
		t.Fatalf("expected backend active after EnableBackend, got %q", got.Status)
	}

	// First probe after re-enable must NOT re-disable (grace restored).
	probeShouldFail = true
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe error after re-enable")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status == "disabled" {
		t.Fatal("first probe after EnableBackend re-disabled the backend: fail count was not reset (issue #50)")
	}
	if got.Status != "degraded" {
		t.Fatalf("expected degraded after 1 post-re-enable failure, got %q", got.Status)
	}

	// One more failure (2 total < threshold 3) must still not disable.
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected second probe error after re-enable")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status == "disabled" {
		t.Fatal("backend re-disabled before reaching FailureThreshold after EnableBackend")
	}

	// A third consecutive failure must disable again (threshold honored).
	if _, err := vpnSvc.prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected third probe error after re-enable")
	}
	got, _ = vpnSvc.pool.GetTunnel(s1ID)
	if got.Status != "disabled" {
		t.Fatalf("expected disabled after 3 consecutive post-re-enable failures, got %q", got.Status)
	}
}
