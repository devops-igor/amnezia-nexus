package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestReconnectManager(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "1.1.1.1"})
	_, _ = pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", "pub1")

	var mockLatency time.Duration = 0
	var mockErr error = errors.New("timeout")

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return mockLatency, mockErr
	}

	hCfg := HealthConfig{
		Timeout:            500 * time.Millisecond,
		LatencyThresholdMS: 200,
	}
	prober := NewHealthProber(pool, db, hCfg, mockProbe)

	rCfg := ReconnectConfig{
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		Multiplier:     2.0,
		MaxRetries:     3,
		CheckInterval:  20 * time.Millisecond,
	}

	reconnectMgr := NewReconnectManager(pool, prober, rCfg)

	simTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	reconnectMgr.SetNowFunc(func() time.Time { return simTime })

	// 1. Initial state: tunnel is active, so CheckAndReconnect does nothing
	reconnected := reconnectMgr.CheckAndReconnect(ctx)
	if reconnected != 0 {
		t.Errorf("expected 0 reconnected for active tunnel, got %d", reconnected)
	}

	// 2. Mark tunnel as degraded
	_ = pool.SetTunnelStatus(ctx, s1ID, "degraded", 0)

	// 3. First reconnect attempt (fails)
	reconnected = reconnectMgr.CheckAndReconnect(ctx)
	if reconnected != 0 {
		t.Errorf("expected 0 reconnected on failed probe, got %d", reconnected)
	}
	retries, nextAttempt, backoff := reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 1 || backoff != 100*time.Millisecond {
		t.Errorf("retry state mismatch: retries=%d, backoff=%v", retries, backoff)
	}
	if nextAttempt.IsZero() {
		t.Errorf("expected non-zero nextAttempt")
	}

	// 4. Immediate second pass before backoff elapsed -> should skip
	simTime = simTime.Add(40 * time.Millisecond) // only 40ms passed, need 100ms
	reconnected = reconnectMgr.CheckAndReconnect(ctx)
	if reconnected != 0 {
		t.Errorf("expected 0 reconnected when skipping, got %d", reconnected)
	}
	retries, _, _ = reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 1 {
		t.Errorf("expected retries to remain 1 before backoff expires, got %d", retries)
	}

	// 5. Advance time past backoff (100ms), second attempt fails
	simTime = simTime.Add(70 * time.Millisecond) // total 110ms > 100ms
	reconnectMgr.CheckAndReconnect(ctx)
	retries, _, backoff = reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 2 || backoff != 200*time.Millisecond { // 100 * 2.0 = 200 (capped at MaxBackoff 200ms)
		t.Errorf("retry state mismatch after 2nd attempt: retries=%d, backoff=%v", retries, backoff)
	}

	// 6. Third attempt fails -> reaches MaxRetries (3)
	simTime = simTime.Add(210 * time.Millisecond) // total elapsed > nextAttempt
	reconnectMgr.CheckAndReconnect(ctx)
	retries, _, _ = reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 3 {
		t.Errorf("expected retries 3, got %d", retries)
	}

	// 7. MaxRetries reached -> subsequent pass skips even after time advances
	simTime = simTime.Add(500 * time.Millisecond)
	reconnectMgr.CheckAndReconnect(ctx)
	retries, _, _ = reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 3 {
		t.Errorf("expected retries to remain 3 after MaxRetries cap, got %d", retries)
	}

	// 8. Reconnect with success
	mockErr = nil
	mockLatency = 20 * time.Millisecond
	// The tunnel is health-auto-disabled at this point; CheckAndReconnect must
	// never resurrect disabled tunnels (issues #28/#43), so re-enable manually
	// (as EnableBackend does) before the reconnect attempt can succeed.
	_ = pool.SetTunnelStatus(ctx, s1ID, "degraded", 0)
	// Reset retries by allowing unlimited retries safely
	rCfgUnlimited := rCfg
	rCfgUnlimited.MaxRetries = 0
	reconnectMgr.SetConfig(rCfgUnlimited)
	simTime = simTime.Add(300 * time.Millisecond)

	reconnected = reconnectMgr.CheckAndReconnect(ctx)
	if reconnected != 1 {
		t.Errorf("expected 1 reconnected tunnel, got %d", reconnected)
	}

	t1Status, _ := pool.GetTunnel(s1ID)
	if t1Status.Status != "active" {
		t.Errorf("expected tunnel status active after reconnect, got %s", t1Status.Status)
	}
	retries, _, _ = reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 0 {
		t.Errorf("expected retries reset to 0, got %d", retries)
	}

	// 9. Lifecycle Start and Stop
	reconnectMgr.SetNowFunc(nil) // restore real clock
	reconnectMgr.Start(ctx)
	if !reconnectMgr.IsRunning() {
		t.Errorf("expected running")
	}
	// Double start noop
	reconnectMgr.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	reconnectMgr.Stop()
	if reconnectMgr.IsRunning() {
		t.Errorf("expected not running after Stop")
	}
	// Double stop noop
	reconnectMgr.Stop()

	// Default config
	defCfg := DefaultReconnectConfig()
	if defCfg.InitialBackoff != 1*time.Second || defCfg.Multiplier != 2.0 {
		t.Errorf("DefaultReconnectConfig mismatch")
	}
	nilMgr := NewReconnectManager(nil, nil, defCfg)
	if nilMgr.CheckAndReconnect(ctx) != 0 {
		t.Errorf("expected 0 for nil pool reconnect")
	}
}

func TestReconnectManager_RespectsInnerCanaryRecoveryDecision(t *testing.T) {
	for _, healthy := range []bool{false, true} {
		name := "outer_good_inner_blackhole"
		if healthy {
			name = "both_good_control"
		}
		t.Run(name, func(t *testing.T) {
			db := setupTestDB(t)
			ctx := t.Context()

			pool := NewPool(db)

			s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "1.1.1.1"})
			if err != nil {
				t.Fatalf("CreateServer failed: %v", err)
			}
			tun, err := pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", "pub1")
			if err != nil {
				t.Fatalf("AddTunnel failed: %v", err)
			}

			if err := pool.SetTunnelStatus(ctx, s1ID, models.TunnelStatusHandshakeBlocked, 20); err != nil {
				t.Fatalf("SetTunnelStatus failed: %v", err)
			}

			mockOuterLatency := 20 * time.Millisecond
			mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
				return mockOuterLatency, nil
			}

			hCfg := HealthConfig{
				Timeout:            500 * time.Millisecond,
				LatencyThresholdMS: 200,
			}
			prober := NewHealthProber(pool, db, hCfg, mockProbe)

			canaryCalls := 0
			prober.SetCanaryProbeFunc(func(ctx context.Context, bt *models.BackendTunnel) error {
				canaryCalls++
				if healthy {
					return nil
				}
				return errors.New("inner canary failed: payload blackholed")
			})

			rCfg := DefaultReconnectConfig()
			reconnectMgr := NewReconnectManager(pool, prober, rCfg)

			reconnected := reconnectMgr.CheckAndReconnect(ctx)

			latestPool, err := pool.GetTunnel(s1ID)
			if err != nil {
				t.Fatalf("pool.GetTunnel failed: %v", err)
			}

			storedDB, err := db.GetBackendTunnel(ctx, tun.ID)
			if err != nil {
				t.Fatalf("db.GetBackendTunnel failed: %v", err)
			}

			activeTunnels := pool.GetActiveTunnels()

			if healthy {
				if canaryCalls != 1 {
					t.Errorf("expected 1 canary call, got %d", canaryCalls)
				}
				if reconnected != 1 {
					t.Errorf("expected 1 reconnected tunnel, got %d", reconnected)
				}
				if latestPool.Status != models.TunnelStatusActive {
					t.Errorf("expected pool status %s, got %s", models.TunnelStatusActive, latestPool.Status)
				}
				if storedDB.Status != models.TunnelStatusActive {
					t.Errorf("expected DB status %s, got %s", models.TunnelStatusActive, storedDB.Status)
				}
				if len(activeTunnels) != 1 {
					t.Errorf("expected 1 active tunnel available for client admission, got %d", len(activeTunnels))
				}
			} else {
				if canaryCalls != 1 {
					t.Errorf("expected 1 canary call, got %d", canaryCalls)
				}
				if reconnected != 0 {
					t.Errorf("expected 0 reconnected tunnels when inner canary fails, got %d", reconnected)
				}
				if latestPool.Status != models.TunnelStatusDegraded {
					t.Errorf("expected pool status to be %s, got %s", models.TunnelStatusDegraded, latestPool.Status)
				}
				if storedDB.Status != models.TunnelStatusDegraded {
					t.Errorf("expected DB status to be %s, got %s", models.TunnelStatusDegraded, storedDB.Status)
				}
				if len(activeTunnels) != 0 {
					t.Errorf("expected 0 active tunnels (new client admission rejected), got %d", len(activeTunnels))
				}
			}
		})
	}
}
