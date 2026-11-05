package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthCanary_Rework19_TransientFailure_PreservesEstablishedSessions_UnderBoundedConfirmation verifies [BLOCKER 2]:
// On the first transient inner-canary failure through HealthProber, a backend with established sessions:
// - MUST NOT immediately transition to degraded.
// - MUST NOT make established sessions immediately eligible for migration.
// - Transitions to handshake_blocked (preserving established sessions under bounded confirmation).
// - Denies new client admissions via GetActiveTunnels().
func TestHealthCanary_Rework19_TransientFailure_PreservesEstablishedSessions_UnderBoundedConfirmation(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Bounded-Server", Host: "10.0.0.80"})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	tun, err := pool.AddTunnel(ctx, sID, "10.0.0.80:51820", "pubkey-rework19-1")
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

	// Outer handshake probe always succeeds
	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)

	// Inner canary probe fails
	var canaryCalls atomic.Int32
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		canaryCalls.Add(1)
		return errors.New("transient inner canary timeout")
	})

	// Pass 1: First transient inner-canary failure (1 < 3)
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

	// Verify status is handshake_blocked, NOT degraded!
	cur, err := pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("failed to get tunnel: %v", err)
	}
	if cur.Status == models.TunnelStatusDegraded {
		t.Fatalf("[BLOCKER 2 REGRESSION] transient canary failure immediately marked degraded!")
	}
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s under bounded confirmation, got %q", models.TunnelStatusHandshakeBlocked, cur.Status)
	}

	// Verify new client admissions are denied
	if active := pool.GetActiveTunnels(); len(active) != 0 {
		t.Fatalf("expected 0 active tunnels for new client admission, got %d", len(active))
	}

	// Verify canary failure count tracked
	if fc := hp.GetCanaryFailCount(sID); fc != 1 {
		t.Fatalf("expected canary fail count 1, got %d", fc)
	}

	// Pass 2: Second transient failure (2 < 3) maintains handshake_blocked
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur2, _ := pool.GetTunnel(sID)
	if cur2.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s on second failure below threshold, got %q", models.TunnelStatusHandshakeBlocked, cur2.Status)
	}
	if fc := hp.GetCanaryFailCount(sID); fc != 2 {
		t.Fatalf("expected canary fail count 2, got %d", fc)
	}
}

// TestHealthCanary_Rework19_SustainedFailures_ReachingThreshold_PermitsFailover verifies [DELIVERABLE 3]:
// Repeated confirmed canary failures reaching FailureThreshold transitions the tunnel
// to disabled (or degraded), permitting failover / session migration.
func TestHealthCanary_Rework19_SustainedFailures_ReachingThreshold_PermitsFailover(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Failover-Server", Host: "10.0.0.81"})
	tun, _ := pool.AddTunnel(ctx, sID, "10.0.0.81:51820", "pubkey-rework19-2")
	_ = pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 20)
	pool.IncrementConnections(sID) // established session

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		return errors.New("sustained data-plane payload loss")
	})

	// Cycles 1 and 2: below threshold -> handshake_blocked
	_, _ = hp.ProbeTunnel(ctx, tun)
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s before reaching threshold, got %q", models.TunnelStatusHandshakeBlocked, cur.Status)
	}

	// Cycle 3: reaches FailureThreshold (3 >= 3) -> transitions to disabled to permit failover
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur3, _ := pool.GetTunnel(sID)
	if cur3.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s after reaching failure threshold, got %q", models.TunnelStatusDisabled, cur3.Status)
	}
	if cur3.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable reason %s, got %q", models.DisableReasonHealth, cur3.DisableReason)
	}
}

// TestHealthCanary_Rework19_CanaryRecovery_ClearsFailHistory_RestoresActive verifies [DELIVERABLE 4]:
// When an established tunnel in handshake_blocked status subsequently passes an inner canary probe,
// failure history is cleared and active status (and new client admissions) is restored.
func TestHealthCanary_Rework19_CanaryRecovery_ClearsFailHistory_RestoresActive(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "Recovery-Server", Host: "10.0.0.82"})
	tun, _ := pool.AddTunnel(ctx, sID, "10.0.0.82:51820", "pubkey-rework19-3")
	_ = pool.SetTunnelStatus(ctx, sID, models.TunnelStatusActive, 20)
	pool.IncrementConnections(sID)

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)

	var shouldFail atomic.Bool
	shouldFail.Store(true)
	hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		if shouldFail.Load() {
			return errors.New("temporary canary error")
		}
		return nil
	})

	// Pass 1: Transient failure -> handshake_blocked
	_, _ = hp.ProbeTunnel(ctx, tun)
	cur, _ := pool.GetTunnel(sID)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("Pass 1: expected status %s, got %q", models.TunnelStatusHandshakeBlocked, cur.Status)
	}
	if count := hp.GetCanaryFailCount(sID); count != 1 {
		t.Fatalf("Pass 1: expected canaryFailCount 1, got %d", count)
	}

	// Pass 2: Canary probe recovers
	shouldFail.Store(false)
	_, err := hp.ProbeTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("Pass 2: expected ProbeTunnel success, got: %v", err)
	}

	cur2, _ := pool.GetTunnel(sID)
	if cur2.Status != models.TunnelStatusActive {
		t.Fatalf("Pass 2: expected status restored to %s, got %q", models.TunnelStatusActive, cur2.Status)
	}
	if count := hp.GetCanaryFailCount(sID); count != 0 {
		t.Fatalf("Pass 2: expected canaryFailCount cleared to 0, got %d", count)
	}

	// Verify normal client admission restored
	if active := pool.GetActiveTunnels(); len(active) != 1 {
		t.Fatalf("Pass 2: expected 1 active tunnel available for admission, got %d", len(active))
	}
}

// TestHealthCanary_Rework19_OuterPass_HandshakeBlocked_WithSessions_NoCanary_PreservesBlocked verifies [BLOCKER 1 & DELIVERABLE 1]:
// When outer handshake probe succeeds on a handshake_blocked backend with established sessions,
// but no canary prober is available:
// - Backend MUST NOT become active.
// - Status MUST preserve handshake_blocked.
// - New client admissions remain denied.
func TestHealthCanary_Rework19_OuterPass_HandshakeBlocked_WithSessions_NoCanary_PreservesBlocked(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "NoCanary-Server", Host: "10.0.0.83"})
	tun, _ := pool.AddTunnel(ctx, sID, "10.0.0.83:51820", "pubkey-rework19-4")
	_ = pool.SetTunnelStatus(ctx, sID, models.TunnelStatusHandshakeBlocked, 20)
	pool.IncrementConnections(sID) // established session

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}

	hp := NewHealthProber(pool, db, cfg, outerProbe)
	// Canary prober is NOT configured (nil)
	hp.SetCanaryProbeFunc(nil)

	lat, err := hp.ProbeTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("expected ProbeTunnel outer probe success, got: %v", err)
	}
	if lat != 15 {
		t.Fatalf("expected latency 15ms, got: %d", lat)
	}

	cur, _ := pool.GetTunnel(sID)
	if cur.Status == models.TunnelStatusActive {
		t.Fatalf("[BLOCKER 1 REGRESSION] handshake_blocked backend promoted to active without canary prober!")
	}
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status to preserve %s, got %q", models.TunnelStatusHandshakeBlocked, cur.Status)
	}

	if active := pool.GetActiveTunnels(); len(active) != 0 {
		t.Fatalf("expected 0 active tunnels for client admission, got %d", len(active))
	}
}
