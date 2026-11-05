package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthCanary_Rework13_OuterPass_InnerFail_AllowsNormalFailover verifies [BLOCKER 1]:
// When outer handshake succeeds but inner data-plane canary fails:
// - Status MUST NOT be handshake_blocked! (Assigning handshake_blocked would trap sessions on a dead payload path).
// - Status transitions to degraded, permitting normal session failover.
// - Bounded retries: after FailureThreshold consecutive canary failures, transitions to disabled.
// - New client admission is blocked throughout.
func TestHealthCanary_Rework13_OuterPass_InnerFail_AllowsNormalFailover(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Failover-Server", Host: "10.0.0.50"})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.50:51820", "pubkey-failover-1")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}
	if err := pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 25); err != nil {
		t.Fatalf("failed to set active status: %v", err)
	}

	// Established client session on tunnel
	pool.IncrementConnections(sID)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	// Outer handshake probe always SUCCEEDS (outer PASS)
	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)

	// Inner canary probe FAILS (inner FAIL: broken data plane)
	var canaryCalls atomic.Int32
	canaryErr := errors.New("data-plane payload blackhole")
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		canaryCalls.Add(1)
		return canaryErr
	})

	// Cycle 1: Outer PASS, Inner FAIL
	lat, err := hp.ProbeTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("expected ProbeTunnel outer probe to succeed without error, got: %v", err)
	}
	if lat != 20 {
		t.Fatalf("expected latency 20ms, got: %d", lat)
	}
	if canaryCalls.Load() == 0 {
		t.Fatal("expected inner canary probe to be executed")
	}

	// Verify status is degraded, NOT handshake_blocked
	cur, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("failed to get tunnel: %v", err)
	}
	if cur.Status == models.TunnelStatusHandshakeBlocked {
		t.Fatalf("[BLOCKER 1 REGRESSION] outer PASS / inner FAIL assigned handshake_blocked! Must be degraded")
	}
	if cur.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded, got %q", cur.Status)
	}

	// Verify new client admissions denied
	if active := pool.GetActiveTunnels(); len(active) != 0 {
		t.Fatalf("expected 0 active tunnels, got %d", len(active))
	}

	// Verify canary failure count tracked
	if fc := hp.GetCanaryFailCount(sID); fc != 1 {
		t.Fatalf("expected canary fail count 1, got %d", fc)
	}

	// Cycle 2: Second canary failure
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded on second failure, got %q", cur.Status)
	}
	if fc := hp.GetCanaryFailCount(sID); fc != 2 {
		t.Fatalf("expected canary fail count 2, got %d", fc)
	}

	// Cycle 3: Third canary failure (reaches FailureThreshold 3) -> transitions to disabled
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur, _ = pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status disabled after threshold canary failures, got %q", cur.Status)
	}
	if cur.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable reason %q, got %q", models.DisableReasonHealth, cur.DisableReason)
	}
}

// TestHealthCanary_Rework13_Startup_OuterPass_InnerFail_NoPreexistingDevice_DoesNotBecomeActive
// verifies [BLOCKER 2]:
// On startup with outer PASS / inner FAIL and no preexisting device:
// - Data-plane device is initialized/attached during bootstrap.
// - Inner canary is verified before general new-client admission.
// - Backend does NOT become active when canary fails.
// - Backend is NOT handshake_blocked.
// - When inner canary recovers, backend successfully promotes to active.
func TestHealthCanary_Rework13_Startup_OuterPass_InnerFail_NoPreexistingDevice_DoesNotBecomeActive(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Bootstrap-Server", Host: "10.0.0.60"})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.60:51820", "pubkey-bootstrap-1")
	if err != nil {
		t.Fatalf("failed to add tunnel: %v", err)
	}

	// Initial startup status: connecting (no preexisting device attached)
	if err := pool.SetTunnelStatus(ctx, sID, models.TunnelStatusConnecting, 0); err != nil {
		t.Fatalf("failed to set connecting status: %v", err)
	}

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	// Outer handshake succeeds (outer PASS)
	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)

	// Verify no preexisting device
	if dev := hp.GetDevice(tun.ID); dev != nil {
		t.Fatalf("expected no preexisting device, got: %v", dev)
	}

	// Hook to attach device during bootstrap
	var hookCalls atomic.Int32
	mockDev := &mockPacketDevice{}
	hp.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		hookCalls.Add(1)
		hp.RegisterDevice(t.ID, mockDev)
		return nil
	})

	// Inner canary fails
	var canaryCalls atomic.Int32
	var canaryShouldFail atomic.Bool
	canaryShouldFail.Store(true)
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		canaryCalls.Add(1)
		if canaryShouldFail.Load() {
			return errors.New("bootstrap data-plane payload failed")
		}
		return nil
	})

	// 1. Startup probe: outer PASS, inner FAIL, no preexisting device
	_, pErr := hp.ProbeTunnel(ctx, tun)
	if pErr != nil {
		t.Fatalf("expected ProbeTunnel outer probe to succeed, got: %v", pErr)
	}

	// Verify bootstrap hook attached device
	if hookCalls.Load() == 0 {
		t.Fatal("expected bootstrap active hook to attach data-plane device")
	}
	if dev := hp.GetDevice(tun.ID); dev == nil {
		t.Fatal("expected device to be attached after bootstrap hook")
	}
	if canaryCalls.Load() == 0 {
		t.Fatal("expected canary probe to be verified during bootstrap")
	}

	// Verify backend does NOT become active!
	cur, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("failed to get tunnel: %v", err)
	}
	if cur.Status == models.TunnelStatusActive {
		t.Fatalf("[BLOCKER 2 REGRESSION] backend promoted to active without passing inner canary on startup!")
	}
	if cur.Status == models.TunnelStatusHandshakeBlocked {
		t.Fatalf("[BLOCKER 1 REGRESSION] outer PASS / inner FAIL promoted to handshake_blocked! Must be degraded")
	}
	if cur.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded on canary failure, got %q", cur.Status)
	}

	// Verify excluded from general client admission
	if active := pool.GetActiveTunnels(); len(active) != 0 {
		t.Fatalf("expected 0 active tunnels for client admission, got %d", len(active))
	}

	// 2. Now simulate inner canary recovery: both outer and inner succeed!
	canaryShouldFail.Store(false)
	_, err = hp.ProbeTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("expected recovery ProbeTunnel success, got: %v", err)
	}

	curRecovered, _ := pool.GetTunnel(sID)
	if curRecovered.Status != models.TunnelStatusActive {
		t.Fatalf("expected status active after inner canary recovers, got %q", curRecovered.Status)
	}
	if active := pool.GetActiveTunnels(); len(active) != 1 {
		t.Fatalf("expected 1 active tunnel after recovery, got %d", len(active))
	}
}

// TestHealthProber_TransitionToDegraded_Coverage exercises transitionToDegraded edge paths.
func TestHealthProber_TransitionToDegraded_Coverage(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Degraded-Cov", Host: "10.0.0.70"})
	tun, _ := pool.AddTunnel(ctx, sID, "10.0.0.70:51820", "pubkey-cov-1")

	cfg := DefaultHealthConfig()
	hp := NewHealthProber(pool, db, cfg, func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})

	// 1. Initial transition from active to degraded
	_ = pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 20)
	snap, _ := pool.GetTunnel(sID)
	if err := hp.transitionToDegraded(ctx, snap); err != nil {
		t.Fatalf("transitionToDegraded failed: %v", err)
	}
	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected degraded, got %s", cur.Status)
	}

	// 2. Already degraded: early return nil
	if err := hp.transitionToDegraded(ctx, cur); err != nil {
		t.Fatalf("expected nil when already degraded, got %v", err)
	}

	// 3. Without pool (hp.pool == nil fallback)
	hpNoPool := NewHealthProber(nil, nil, cfg)
	snapNoPool := &models.BackendTunnel{ServerID: sID, ID: tun.ID, Status: "active"}
	if err := hpNoPool.transitionToDegraded(ctx, snapNoPool); err != nil {
		t.Fatalf("expected nil for no pool, got %v", err)
	}
	if snapNoPool.Status != "degraded" {
		t.Fatalf("expected status degraded for no pool, got %s", snapNoPool.Status)
	}

	// 4. Concurrent CAS missed (!swapped branch)
	hp.mu.Lock()
	hp.failCounts[sID] = 2
	hp.mu.Unlock()
	snapStale := &models.BackendTunnel{ServerID: sID, ID: tun.ID, Status: "active", StateVersion: 9999}
	if err := hp.transitionToDegraded(ctx, snapStale); err != nil {
		t.Fatalf("expected nil on missed CAS, got %v", err)
	}
	if fc := hp.GetFailCount(sID); fc != 1 {
		t.Fatalf("expected fail count decremented to 1, got %d", fc)
	}
}
