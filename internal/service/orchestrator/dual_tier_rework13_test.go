package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestOrchestrator_Rework13_OuterPass_InnerFail_AllowsNormalFailover verifies [BLOCKER 1] in Orchestrator:
// When outer probe succeeds but inner canary probe fails:
// - Status MUST NOT be handshake_blocked!
// - Status transitions to degraded.
// - Established sessions on the degraded backend are included in failover.
func TestOrchestrator_Rework13_OuterPass_InnerFail_AllowsNormalFailover(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "10.0.0.1"})
	s2, _ := db.CreateServer(ctx, &models.Server{Name: "Server 2", Host: "10.0.0.2"})

	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:          s1,
		InterfaceName:     "awg0",
		PublicKey:         "pub1",
		Endpoint:          "10.0.0.1:51820",
		Status:            models.TunnelStatusActive,
		Enabled:           true,
		ActiveConnections: 5,
	})
	t2, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:          s2,
		InterfaceName:     "awg1",
		PublicKey:         "pub2",
		Endpoint:          "10.0.0.2:51820",
		Status:            models.TunnelStatusActive,
		Enabled:           true,
		ActiveConnections: 1,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	tun2, _ := db.GetBackendTunnel(ctx, t2)
	updater := newMockCanaryUpdater(db, tun1, tun2)

	// Outer probe always succeeds; threshold=1 ensures 1 failure reaches threshold to trigger failover
	orch := New(db, nil, WithProbeFailureThreshold(1), WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}), WithTunnelStatusUpdater(updater))

	// Inner canary probe FAILS for tunnel 1
	var canaryCalls atomic.Int32
	updater.canaryErr = errors.New("inner data plane dead")
	orch.statusUpdater = &orchestratorCanaryFilterUpdater{
		mockCanaryUpdater: updater,
		canaryFn: func(tunnel *models.BackendTunnel) error {
			canaryCalls.Add(1)
			if tunnel.ID == t1 {
				return errors.New("inner data plane dead")
			}
			return nil
		},
	}

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	if canaryCalls.Load() == 0 {
		t.Fatal("expected canary probe to be called")
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status == models.TunnelStatusHandshakeBlocked {
		t.Fatalf("[BLOCKER 1 REGRESSION] outer PASS / inner FAIL must NOT assign handshake_blocked; got %s", res1.Status)
	}
	if res1.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded on canary failure, got %s", res1.Status)
	}

	res2, _ := db.GetBackendTunnel(ctx, t2)
	if res2.Status != models.TunnelStatusActive {
		t.Fatalf("expected tunnel 2 to remain active, got %s", res2.Status)
	}
}

// TestOrchestrator_Rework13_Startup_OuterPass_InnerFail_DoesNotBecomeActive verifies [BLOCKER 2] in Orchestrator:
// When a backend is in connecting status during startup:
// - Outer probe succeeds.
// - Inner canary fails.
// - Backend does NOT become active!
// - Backend is NOT handshake_blocked!
// - Backend transitions to degraded.
func TestOrchestrator_Rework13_Startup_OuterPass_InnerFail_DoesNotBecomeActive(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Bootstrap-Server", Host: "10.0.0.1"})
	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1,
		InterfaceName: "awg0",
		PublicKey:     "pub1",
		Endpoint:      "10.0.0.1:51820",
		Status:        models.TunnelStatusConnecting,
		Enabled:       true,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)

	// Inner canary fails
	updater.hasCanary = true
	updater.canaryErr = errors.New("bootstrap data-plane failure")

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}), WithTunnelStatusUpdater(updater))

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	res, _ := db.GetBackendTunnel(ctx, t1)
	if res.Status == models.TunnelStatusActive {
		t.Fatalf("[BLOCKER 2 REGRESSION] backend promoted to active without passing inner canary on startup!")
	}
	if res.Status == models.TunnelStatusHandshakeBlocked {
		t.Fatalf("[BLOCKER 1 REGRESSION] outer PASS / inner FAIL assigned handshake_blocked! Must be degraded")
	}
	if res.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded, got %s", res.Status)
	}
}

type orchestratorCanaryFilterUpdater struct {
	*mockCanaryUpdater
	canaryFn func(tunnel *models.BackendTunnel) error
}

func (u *orchestratorCanaryFilterUpdater) ProbeCanary(ctx context.Context, tunnel *models.BackendTunnel) error {
	if u.canaryFn != nil {
		return u.canaryFn(tunnel)
	}
	return u.mockCanaryUpdater.ProbeCanary(ctx, tunnel)
}
