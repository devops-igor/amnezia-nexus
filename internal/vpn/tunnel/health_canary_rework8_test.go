package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthCanary_Rework8_PromotionToActiveRejectedWhenInnerCanaryFails tests Deliverable 1 & 3 (Test 1):
// Before promoting ANY backend to active (from connecting, degraded, or handshake_blocked),
// the inner canary probe must succeed. If outer handshake succeeds but inner canary fails:
// promotion to active is rejected, status transitions to/preserves handshake_blocked,
// and new client admission via GetActiveTunnels() is denied.
func TestHealthCanary_Rework8_PromotionToActiveRejectedWhenInnerCanaryFails(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name          string
		initialStatus string
	}{
		{name: "from connecting", initialStatus: models.TunnelStatusConnecting},
		{name: "from degraded", initialStatus: models.TunnelStatusDegraded},
		{name: "from handshake_blocked", initialStatus: models.TunnelStatusHandshakeBlocked},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupTestDB(t)
			pool := NewPool(db)

			sID, err := db.CreateServer(ctx, &models.Server{Name: "Server-" + tc.name, Host: "10.0.0.10"})
			if err != nil {
				t.Fatalf("failed to create server: %v", err)
			}
			tun, err := pool.AddTunnel(ctx, sID, "10.0.0.10:51820", "pubkey-rework8")
			if err != nil {
				t.Fatalf("failed to add tunnel: %v", err)
			}
			if err := pool.SetTunnelStatus(ctx, sID, tc.initialStatus, 50); err != nil {
				t.Fatalf("failed to set initial status %s: %v", tc.initialStatus, err)
			}

			cfg := DefaultHealthConfig()
			cfg.FailureThreshold = 3

			// Outer handshake probe always SUCCEEDS with fast RTT (20ms)
			outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
				return 20 * time.Millisecond, nil
			}

			hp := NewHealthProber(pool, db, cfg, outerProbe)

			// Inner data-plane canary probe FAILS (simulating payload drop / blackhole)
			canaryCalled := 0
			hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
				canaryCalled++
				return errors.New("data-plane payload blackhole")
			})

			lat, pErr := hp.ProbeTunnel(ctx, tun)
			if pErr != nil {
				t.Fatalf("expected ProbeTunnel to succeed outer probe without error, got: %v", pErr)
			}
			if lat != 20 {
				t.Fatalf("expected latency 20ms, got: %d", lat)
			}
			if canaryCalled == 0 {
				t.Fatal("expected inner canary probe to be executed before active promotion")
			}

			// 1. In-memory pool status MUST NOT be active; must be handshake_blocked
			cur, err := pool.GetTunnel(sID)
			if err != nil {
				t.Fatalf("failed to get tunnel from pool: %v", err)
			}
			if cur.Status == models.TunnelStatusActive {
				t.Fatalf("promotion to active MUST be rejected when canary fails; got status %q", cur.Status)
			}
			if cur.Status != models.TunnelStatusHandshakeBlocked {
				t.Fatalf("expected status %q, got %q", models.TunnelStatusHandshakeBlocked, cur.Status)
			}

			// 2. Database persisted status MUST NOT be active; must be handshake_blocked
			persisted, err := db.GetBackendTunnel(ctx, tun.ID)
			if err != nil {
				t.Fatalf("failed to get tunnel from db: %v", err)
			}
			if persisted.Status == models.TunnelStatusActive {
				t.Fatalf("persisted db status MUST NOT be active; got %q", persisted.Status)
			}
			if persisted.Status != models.TunnelStatusHandshakeBlocked {
				t.Fatalf("expected persisted db status %q, got %q", models.TunnelStatusHandshakeBlocked, persisted.Status)
			}

			// 3. New client admission via GetActiveTunnels() MUST be denied
			activeTunnels := pool.GetActiveTunnels()
			if len(activeTunnels) != 0 {
				t.Fatalf("expected 0 active tunnels available for new client admission; got %d", len(activeTunnels))
			}

			// 4. Now simulate inner canary RECOVERY: both outer and inner succeed!
			hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
				return nil
			})
			_, pErr = hp.ProbeTunnel(ctx, tun)
			if pErr != nil {
				t.Fatalf("expected ProbeTunnel success on recovery: %v", pErr)
			}
			curRecovered, _ := pool.GetTunnel(sID)
			if curRecovered.Status != models.TunnelStatusActive {
				t.Fatalf("expected promotion to active when both probes succeed, got %q", curRecovered.Status)
			}
			if len(pool.GetActiveTunnels()) != 1 {
				t.Fatalf("expected 1 active tunnel after recovery, got %d", len(pool.GetActiveTunnels()))
			}
		})
	}
}

// TestHealthCanary_Rework8_InitialOuterFailure_TransitionsToHandshakeBlocked_PreservesConnectedClient
// tests Deliverable 2 & 3 (Test 2):
// When an outer handshake probe fails below the threshold (failures < FailureThreshold):
//   - If established sessions exist or data-plane is viable: backend status transitions to
//     handshake_blocked immediately, excluding it from GetActiveTunnels() so new incoming clients
//     are denied admission.
//   - The established client session remains connected (active connections preserved, not degraded).
func TestHealthCanary_Rework8_InitialOuterFailure_TransitionsToHandshakeBlocked_PreservesConnectedClient(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Server-Test2", Host: "10.0.0.20"})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.20:51820", "pubkey-rework8-t2")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}
	if err := pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 30); err != nil {
		t.Fatalf("failed to set active status: %v", err)
	}

	// Simulate established connected client session on tunnel
	pool.IncrementConnections(sID)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	// Outer handshake probe fails (e.g. initial DPI handshake packet drop)
	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("initial DPI outer handshake packet drop")
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)

	// Inner data-plane canary probe is VIABLE (payload transit continues working)
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		return nil
	})

	// Initial probe failure 1 (failures=1 < FailureThreshold=3)
	_, pErr := hp.ProbeTunnel(ctx, tun)
	if pErr == nil {
		t.Fatal("expected probe error on outer probe failure")
	}

	// 1. Status MUST NOT remain active (to prevent new incoming client admissions)
	cur, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("failed to get tunnel from pool: %v", err)
	}
	if cur.Status == models.TunnelStatusActive {
		t.Fatalf("status MUST NOT remain active during outer probe failure; got %q", cur.Status)
	}

	// 2. Status MUST NOT be degraded (established sessions must not be migrated/disrupted)
	if cur.Status == models.TunnelStatusDegraded {
		t.Fatalf("status MUST NOT degrade during initial outer failure with viable data plane; got %q", cur.Status)
	}

	// 3. Status MUST be handshake_blocked
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %q, got %q", models.TunnelStatusHandshakeBlocked, cur.Status)
	}

	// 4. Excluded from GetActiveTunnels() -> new client admissions denied!
	activeTunnels := pool.GetActiveTunnels()
	if len(activeTunnels) != 0 {
		t.Fatalf("expected 0 active tunnels available for new client admission; got %d", len(activeTunnels))
	}

	// 5. Established client session remains connected
	if cur.ActiveConnections != 1 {
		t.Fatalf("expected established client connection count to be preserved at 1; got %d", cur.ActiveConnections)
	}

	// 6. DB persisted status matches handshake_blocked
	persisted, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatalf("failed to get tunnel from db: %v", err)
	}
	if persisted.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected persisted DB status %q, got %q", models.TunnelStatusHandshakeBlocked, persisted.Status)
	}
}
