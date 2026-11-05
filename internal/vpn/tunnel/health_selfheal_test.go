package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestHealthSelfHeal_RespectsInnerCanary tests that self-healing verification
// respects inner data-plane canary checks before promoting an auto-disabled
// tunnel to active status.
//
// If outer handshake probe succeeds but inner canary fails:
// - Recovery is denied, status MUST remain disabled (NOT active, NOT handshake_blocked).
// - New client admission via GetActiveTunnels() MUST be denied.
// - Database persisted status MUST match disabled.
// - When inner canary recovers, status recovers to active.
func TestHealthSelfHeal_RespectsInnerCanary(t *testing.T) {
	ctx := context.Background()

	t.Run("outer_good_inner_failed_denies_self_heal_recovery", func(t *testing.T) {
		db := setupTestDB(t)
		pool := NewPool(db)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "SelfHeal-Blocked-Server", Host: "10.0.0.10"})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		tun, err := pool.AddTunnel(ctx, sID, "10.0.0.10:51820", "pubkey-selfheal-1")
		if err != nil {
			t.Fatalf("failed to add tunnel: %v", err)
		}

		cfg := DefaultHealthConfig()
		cfg.FailureThreshold = 2
		cfg.SelfHealingThreshold = 2
		cfg.DisableSelfHealing = false

		var outerFails atomic.Bool
		outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			if outerFails.Load() {
				return 0, errors.New("outer handshake probe timeout")
			}
			return 20 * time.Millisecond, nil
		}

		hp := NewHealthProber(pool, db, cfg, outerProbe)

		var canaryFails atomic.Bool
		var canaryCalls atomic.Int32
		hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
			canaryCalls.Add(1)
			if canaryFails.Load() {
				return errors.New("data-plane payload blackholed")
			}
			return nil
		})

		var hookCalls atomic.Int32
		hp.SetOnSelfHealHook(func(ctx context.Context, tunnel *models.BackendTunnel) error {
			hookCalls.Add(1)
			return nil
		})

		// 1. Induce failure to auto-disable the tunnel
		outerFails.Store(true)
		canaryFails.Store(true)
		for i := 0; i < cfg.FailureThreshold; i++ {
			_, _ = hp.ProbeTunnel(ctx, tun)
		}

		preState, err := pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("failed to get tunnel: %v", err)
		}
		if preState.Status != models.TunnelStatusDisabled || preState.DisableReason != models.DisableReasonHealth {
			t.Fatalf("expected status disabled/health, got status=%q, reason=%q", preState.Status, preState.DisableReason)
		}
		if !hp.IsAutoDisabled(sID) {
			t.Fatalf("expected server %d to be tracked as auto-disabled", sID)
		}

		// 2. Outer handshake recovers, but inner canary data-plane is still broken
		outerFails.Store(false)
		canaryFails.Store(true)
		canaryCalls.Store(0)

		for i := 0; i < cfg.SelfHealingThreshold; i++ {
			hp.SelfHealSweep(ctx)
		}

		if canaryCalls.Load() == 0 {
			t.Fatal("expected inner canary probe to be evaluated during self-healing")
		}

		// Verify pool status remains disabled, NOT active or handshake_blocked
		curPool, err := pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("failed to get pool tunnel: %v", err)
		}
		if curPool.Status == models.TunnelStatusActive {
			t.Fatal("self-healing promoted tunnel to active despite failing inner canary!")
		}
		if curPool.Status != models.TunnelStatusDisabled {
			t.Fatalf("expected pool status %q, got %q", models.TunnelStatusDisabled, curPool.Status)
		}

		// Verify DB status remains disabled, NOT active or handshake_blocked
		storedDB, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("failed to get db tunnel: %v", err)
		}
		if storedDB.Status != models.TunnelStatusDisabled {
			t.Fatalf("expected db status %q, got %q", models.TunnelStatusDisabled, storedDB.Status)
		}

		// Verify GetActiveTunnels() excludes the tunnel (no new admissions)
		if active := pool.GetActiveTunnels(); len(active) != 0 {
			t.Fatalf("expected 0 active tunnels available for client admission, got %d", len(active))
		}

		// 3. Inner canary recovers -> normal probe promotes to active
		canaryFails.Store(false)
		for i := 0; i < cfg.SelfHealingThreshold; i++ {
			hp.SelfHealSweep(ctx)
		}

		curRecovered, err := pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("failed to get recovered tunnel: %v", err)
		}
		if curRecovered.Status != models.TunnelStatusActive {
			t.Fatalf("expected status active after inner recovery, got %q", curRecovered.Status)
		}
		storedRecovered, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("failed to get db recovered tunnel: %v", err)
		}
		if storedRecovered.Status != models.TunnelStatusActive {
			t.Fatalf("expected db status active after inner recovery, got %q", storedRecovered.Status)
		}
		if active := pool.GetActiveTunnels(); len(active) != 1 {
			t.Fatalf("expected 1 active tunnel after recovery, got %d", len(active))
		}
	})

	t.Run("both_good_promotes_to_active_directly", func(t *testing.T) {
		db := setupTestDB(t)
		pool := NewPool(db)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "SelfHeal-Healthy-Server", Host: "10.0.0.11"})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		tun, err := pool.AddTunnel(ctx, sID, "10.0.0.11:51820", "pubkey-selfheal-2")
		if err != nil {
			t.Fatalf("failed to add tunnel: %v", err)
		}

		cfg := DefaultHealthConfig()
		cfg.FailureThreshold = 2
		cfg.SelfHealingThreshold = 2
		cfg.DisableSelfHealing = false

		var outerFails atomic.Bool
		outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			if outerFails.Load() {
				return 0, errors.New("outer handshake probe timeout")
			}
			return 20 * time.Millisecond, nil
		}

		hp := NewHealthProber(pool, db, cfg, outerProbe)

		var canaryFails atomic.Bool
		hp.SetCanaryProbeFunc(func(ctx context.Context, tunnel *models.BackendTunnel) error {
			if canaryFails.Load() {
				return errors.New("data-plane payload blackholed")
			}
			return nil
		})

		// 1. Induce failure to auto-disable the tunnel
		outerFails.Store(true)
		canaryFails.Store(true)
		for i := 0; i < cfg.FailureThreshold; i++ {
			_, _ = hp.ProbeTunnel(ctx, tun)
		}

		preState, _ := pool.GetTunnel(sID)
		if preState.Status != models.TunnelStatusDisabled || preState.DisableReason != models.DisableReasonHealth {
			t.Fatalf("expected status disabled/health, got status=%q, reason=%q", preState.Status, preState.DisableReason)
		}

		// 2. Both outer and inner succeed during self-healing sweep
		outerFails.Store(false)
		canaryFails.Store(false)

		for i := 0; i < cfg.SelfHealingThreshold; i++ {
			hp.SelfHealSweep(ctx)
		}

		curPool, err := pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("failed to get pool tunnel: %v", err)
		}
		if curPool.Status != models.TunnelStatusActive {
			t.Fatalf("expected pool status active when both succeed, got %q", curPool.Status)
		}

		storedDB, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("failed to get db tunnel: %v", err)
		}
		if storedDB.Status != models.TunnelStatusActive {
			t.Fatalf("expected db status active when both succeed, got %q", storedDB.Status)
		}

		if active := pool.GetActiveTunnels(); len(active) != 1 {
			t.Fatalf("expected 1 active tunnel, got %d", len(active))
		}
	})

	t.Run("no_canary_prober_available_promotes_to_active", func(t *testing.T) {
		db := setupTestDB(t)
		pool := NewPool(db)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "SelfHeal-NoCanary-Server", Host: "10.0.0.12"})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		tun, err := pool.AddTunnel(ctx, sID, "10.0.0.12:51820", "pubkey-selfheal-3")
		if err != nil {
			t.Fatalf("failed to add tunnel: %v", err)
		}

		cfg := DefaultHealthConfig()
		cfg.FailureThreshold = 2
		cfg.SelfHealingThreshold = 2
		cfg.DisableSelfHealing = false

		var outerFails atomic.Bool
		outerProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			if outerFails.Load() {
				return 0, errors.New("outer handshake probe timeout")
			}
			return 20 * time.Millisecond, nil
		}

		// Note: NO canary prober configured! (hp.hasCanaryProber returns false)
		hp := NewHealthProber(pool, db, cfg, outerProbe)

		// 1. Induce failure to auto-disable the tunnel
		outerFails.Store(true)
		for i := 0; i < cfg.FailureThreshold; i++ {
			_, _ = hp.ProbeTunnel(ctx, tun)
		}

		preState, _ := pool.GetTunnel(sID)
		if preState.Status != models.TunnelStatusDisabled || preState.DisableReason != models.DisableReasonHealth {
			t.Fatalf("expected status disabled/health, got status=%q, reason=%q", preState.Status, preState.DisableReason)
		}

		// 2. Outer succeeds during self-healing sweep
		outerFails.Store(false)

		for i := 0; i < cfg.SelfHealingThreshold; i++ {
			hp.SelfHealSweep(ctx)
		}

		curPool, err := pool.GetTunnel(sID)
		if err != nil {
			t.Fatalf("failed to get pool tunnel: %v", err)
		}
		if curPool.Status != models.TunnelStatusActive {
			t.Fatalf("expected pool status active when no canary prober available, got %q", curPool.Status)
		}

		storedDB, err := db.GetBackendTunnel(ctx, tun.ID)
		if err != nil {
			t.Fatalf("failed to get db tunnel: %v", err)
		}
		if storedDB.Status != models.TunnelStatusActive {
			t.Fatalf("expected db status active when no canary prober available, got %q", storedDB.Status)
		}

		if active := pool.GetActiveTunnels(); len(active) != 1 {
			t.Fatalf("expected 1 active tunnel, got %d", len(active))
		}
	})

	t.Run("finalize_aborted_when_tunnel_missing_after_hook", func(t *testing.T) {
		db := setupTestDB(t)
		pool := NewPool(db)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "SelfHeal-Missing-Server", Host: "10.0.0.13"})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		tun, err := pool.AddTunnel(ctx, sID, "10.0.0.13:51820", "pubkey-selfheal-4")
		if err != nil {
			t.Fatalf("failed to add tunnel: %v", err)
		}

		cfg := DefaultHealthConfig()
		hp := NewHealthProber(pool, db, cfg, func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 20 * time.Millisecond, nil
		})

		// Remove tunnel from pool before finalizing recovery
		_ = pool.RemoveTunnel(ctx, sID)

		tunNow := *tun
		tunNow.Status = "disabled"
		tunNow.DisableReason = models.DisableReasonHealth

		ok := hp.finalizeSelfHealRecovery(ctx, tun, &tunNow, 20, 200)
		if ok {
			t.Fatal("expected finalizeSelfHealRecovery to return false when tunnel is missing from pool")
		}
	})

	t.Run("finalize_aborted_when_cas_missed", func(t *testing.T) {
		db := setupTestDB(t)
		pool := NewPool(db)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "SelfHeal-CAS-Server", Host: "10.0.0.14"})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}
		tun, err := pool.AddTunnel(ctx, sID, "10.0.0.14:51820", "pubkey-selfheal-5")
		if err != nil {
			t.Fatalf("failed to add tunnel: %v", err)
		}
		if err := pool.SetTunnelStatus(ctx, sID, "disabled", 0); err != nil {
			t.Fatalf("failed to disable tunnel: %v", err)
		}

		cfg := DefaultHealthConfig()
		hp := NewHealthProber(pool, db, cfg, func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 20 * time.Millisecond, nil
		})

		// tunNow has mismatched state version so CAS fails (!swapped)
		tunNow := *tun
		tunNow.Status = "disabled"
		tunNow.DisableReason = models.DisableReasonHealth
		tunNow.StateVersion = 9999

		ok := hp.finalizeSelfHealRecovery(ctx, tun, &tunNow, 20, 200)
		if ok {
			t.Fatal("expected finalizeSelfHealRecovery to return false when CAS misses")
		}
	})
}
