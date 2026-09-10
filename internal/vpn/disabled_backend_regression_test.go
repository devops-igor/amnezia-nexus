package vpn

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// TestDisabledBackendNotResurrectedByProberCycle verifies the service-level
// contract for issues #28/#43: after DisableBackend, a health prober cycle
// must not flip the tunnel back to active, the onActiveHook (device
// re-attach) must not fire, load-balancer selection must never return the
// disabled backend, and the backend device map must stay empty.
func TestDisabledBackendNotResurrectedByProberCycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, s2ID, _, _ := setupTestVPNService(t, db)

	// Populate the in-memory pool from the DB rows created by the helper
	// (normally done by Start; done here to keep background loops out).
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	// Administratively disable backend 1 via the real disable path.
	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	// Replace the onActiveHook with a recording no-op so the test stays
	// hermetic: the production hook would attempt a real AWG device attach.
	// The contract under test is *whether the hook fires for the disabled
	// tunnel*, so record the tunnel ID on each call. The healthy backend
	// (s2) will legitimately transition to active and fire the hook.
	tun1, err := vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel(s1) failed: %v", err)
	}
	disabledTunnelID := tun1.ID

	hookCallsForDisabled := 0
	vpnSvc.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		if t != nil && t.ID == disabledTunnelID {
			hookCallsForDisabled++
		}
		return nil
	})

	// Run one prober cycle over all tunnels.
	results := vpnSvc.prober.ProbeAll(ctx)
	if _, probed := results[s1ID]; probed {
		t.Errorf("expected ProbeAll to skip disabled backend %d, got probe result %v", s1ID, results[s1ID])
	}

	tun1, err = vpnSvc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel(s1) failed: %v", err)
	}
	if tun1.Status != "disabled" {
		t.Errorf("disabled backend status changed by prober cycle: got %q, want %q", tun1.Status, "disabled")
	}
	if hookCallsForDisabled != 0 {
		t.Errorf("expected onActiveHook not to fire for disabled backend, got %d calls", hookCallsForDisabled)
	}

	// Pool selection must never return the disabled backend.
	active := vpnSvc.pool.GetActiveTunnels()
	for _, at := range active {
		if at.ServerID == s1ID {
			t.Errorf("disabled backend %d appears in active tunnel list", s1ID)
		}
	}

	best, err := vpnSvc.SelectTunnel(ctx, active)
	if err != nil {
		t.Fatalf("SelectTunnel failed: %v", err)
	}
	if best == nil {
		t.Fatalf("SelectTunnel returned nil, expected backend %d", s2ID)
	}
	if best.ServerID == s1ID {
		t.Errorf("load balancer selected disabled backend %d", s1ID)
	}
	if best.ServerID != s2ID {
		t.Errorf("expected selection of backend %d, got %d", s2ID, best.ServerID)
	}

	// The backend device map must stay empty: nothing re-attached the
	// disabled backend's data-plane device.
	vpnSvc.mu.RLock()
	devCount := len(vpnSvc.backendDevices)
	vpnSvc.mu.RUnlock()
	if devCount != 0 {
		t.Errorf("expected backendDevices to stay empty, got %d entries", devCount)
	}
}

// TestDisabledBackendStaysDisabledAcrossRepeatedProbeCycles is a tighter
// regression for the original live incident: repeated probe cycles (the
// prober loop runs every 10s) must never resurrect the disabled backend.
func TestDisabledBackendStaysDisabledAcrossRepeatedProbeCycles(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, _, _ := setupTestVPNService(t, db)

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	if err := vpnSvc.DisableBackend(ctx, s1ID); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}

	vpnSvc.prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		return nil
	})

	for i := 0; i < 3; i++ {
		_ = vpnSvc.prober.ProbeAll(ctx)
		tun, err := vpnSvc.pool.GetTunnel(s1ID)
		if err != nil {
			t.Fatalf("cycle %d: GetTunnel failed: %v", i, err)
		}
		if tun.Status != "disabled" {
			t.Fatalf("cycle %d: disabled backend resurrected to %q", i, tun.Status)
		}
	}

	// A direct ProbeTunnel call on the disabled tunnel must also refuse.
	lat, err := vpnSvc.ProbeTunnel(ctx, tunMust(t, vpnSvc, s1ID))
	if err == nil {
		t.Errorf("expected direct ProbeTunnel on disabled tunnel to be refused, got lat=%d err=nil", lat)
	}
	tun, _ := vpnSvc.pool.GetTunnel(s1ID)
	if tun.Status != "disabled" {
		t.Errorf("direct ProbeTunnel changed disabled status: got %q", tun.Status)
	}
}

// tunMust is a small helper to fetch a tunnel pointer for direct probing.
func tunMust(t *testing.T, svc *Service, serverID int64) *models.BackendTunnel {
	t.Helper()
	tun, err := svc.pool.GetTunnel(serverID)
	if err != nil {
		t.Fatalf("GetTunnel(%d) failed: %v", serverID, err)
	}
	return tun
}
