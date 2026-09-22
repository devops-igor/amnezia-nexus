package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestSelfHealing_AutoDisabledSweptAndFlapDamping(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.1"})
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.1:51820", "pubkey1")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	var probeShouldFail atomic.Bool
	probeShouldFail.Store(true)

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeShouldFail.Load() {
			return 0, errors.New("connection timeout")
		}
		return 30 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingInterval:  50 * time.Millisecond,
		SelfHealingThreshold: 2,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	var hookCalled atomic.Int32
	prober.SetOnSelfHealHook(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		hookCalled.Add(1)
		return nil
	})

	// Fail probes to trigger auto-disable (threshold = 2)
	for i := 0; i < 2; i++ {
		_, err = prober.ProbeTunnel(ctx, t1)
		if err == nil {
			t.Fatalf("expected probe %d to fail", i+1)
		}
	}

	status1, _ := pool.GetTunnel(s1ID)
	if status1.Status != "disabled" {
		t.Fatalf("expected status disabled, got %s", status1.Status)
	}
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d to be auto-disabled", s1ID)
	}

	// Server recovers: probes now succeed
	probeShouldFail.Store(false)

	// First sweep: 1st success (threshold is 2, so flap damping keeps tunnel disabled)
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected on first sweep due to flap damping, got %d", reconnected)
	}
	autoDisabled, successes := prober.GetSelfHealingState(s1ID)
	if !autoDisabled || successes != 1 {
		t.Fatalf("expected autoDisabled=true and successes=1, got autoDisabled=%v, successes=%d", autoDisabled, successes)
	}
	statusAfterFirst, _ := pool.GetTunnel(s1ID)
	if statusAfterFirst.Status != "disabled" {
		t.Fatalf("expected status to remain disabled after 1 success, got %s", statusAfterFirst.Status)
	}
	if hookCalled.Load() != 0 {
		t.Fatalf("expected onSelfHealHook not called yet, got %d", hookCalled.Load())
	}

	// Second sweep: 2nd consecutive success -> reaches threshold -> re-enables tunnel!
	reconnected = prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected on second sweep, got %d", reconnected)
	}
	if hookCalled.Load() != 1 {
		t.Fatalf("expected onSelfHealHook called once, got %d", hookCalled.Load())
	}
	autoDisabled, successes = prober.GetSelfHealingState(s1ID)
	if autoDisabled || successes != 0 {
		t.Fatalf("expected autoDisabled=false and successes=0 after recovery, got autoDisabled=%v, successes=%d", autoDisabled, successes)
	}
	statusAfterSecond, _ := pool.GetTunnel(s1ID)
	if statusAfterSecond.Status != "active" {
		t.Fatalf("expected status active after self-healing, got %s", statusAfterSecond.Status)
	}
	if statusAfterSecond.LatencyMS != 30 {
		t.Fatalf("expected latency 30ms, got %d", statusAfterSecond.LatencyMS)
	}
}

func TestSelfHealing_AdminDisabledSkipped(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.2"})
	_, err := pool.AddTunnel(ctx, s1ID, "192.0.2.2:51820", "pubkey2")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 1,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Administratively disable tunnel: set status disabled and clear autoDisabled
	_ = pool.SetTunnelStatus(ctx, s1ID, "disabled", 0)
	prober.MarkAdminDisabled(s1ID)

	if prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected IsAutoDisabled to be false for administratively disabled server")
	}

	// SelfHealSweep must skip administratively disabled tunnel
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected for admin-disabled tunnel, got %d", reconnected)
	}

	t1Status, _ := pool.GetTunnel(s1ID)
	if t1Status.Status != "disabled" {
		t.Fatalf("expected status to remain disabled, got %s", t1Status.Status)
	}
}

func TestSelfHealing_FlapDamping_ProbeFailureResetsCounter(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.3"})
	_, err := pool.AddTunnel(ctx, s1ID, "192.0.2.3:51820", "pubkey3")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	var probeFails atomic.Bool

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if probeFails.Load() {
			return 0, errors.New("simulated probe failure")
		}
		return 20 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 2,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)
	_ = pool.SetTunnelStatus(ctx, s1ID, "disabled", 0)
	prober.MarkAutoDisabled(s1ID)

	// Step 1: Probe succeeds once -> successes = 1
	probeFails.Store(false)
	prober.SelfHealSweep(ctx)
	_, successes := prober.GetSelfHealingState(s1ID)
	if successes != 1 {
		t.Fatalf("expected successes=1, got %d", successes)
	}

	// Step 2: Probe fails on next sweep -> resets successes to 0
	probeFails.Store(true)
	prober.SelfHealSweep(ctx)
	_, successes = prober.GetSelfHealingState(s1ID)
	if successes != 0 {
		t.Fatalf("expected successes=0 after failed probe, got %d", successes)
	}
	t1Status, _ := pool.GetTunnel(s1ID)
	if t1Status.Status != "disabled" {
		t.Fatalf("expected tunnel to remain disabled, got %s", t1Status.Status)
	}

	// Step 3: Probe succeeds once again -> successes = 1
	probeFails.Store(false)
	prober.SelfHealSweep(ctx)
	_, successes = prober.GetSelfHealingState(s1ID)
	if successes != 1 {
		t.Fatalf("expected successes=1, got %d", successes)
	}

	// Step 4: Probe succeeds second consecutive time -> recovers to active
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected after 2 consecutive successes, got %d", reconnected)
	}
	t1Status, _ = pool.GetTunnel(s1ID)
	if t1Status.Status != "active" {
		t.Fatalf("expected status active, got %s", t1Status.Status)
	}
}

func TestSelfHealing_GracePeriodRestoredAfterRecovery(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.4"})
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.4:51820", "pubkey4")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	var failProbes atomic.Bool
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if failProbes.Load() {
			return 0, errors.New("probe failure")
		}
		return 25 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     3,
		SelfHealingThreshold: 2,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Trigger 3 failures to auto-disable
	failProbes.Store(true)
	for i := 0; i < 3; i++ {
		_, _ = prober.ProbeTunnel(ctx, t1)
	}

	status1, _ := pool.GetTunnel(s1ID)
	if status1.Status != "disabled" {
		t.Fatalf("expected disabled after 3 failures, got %s", status1.Status)
	}

	// Server recovers -> 2 sweeps restore tunnel
	failProbes.Store(false)
	prober.SelfHealSweep(ctx)
	prober.SelfHealSweep(ctx)

	statusRecovered, _ := pool.GetTunnel(s1ID)
	if statusRecovered.Status != "active" {
		t.Fatalf("expected active after self-healing, got %s", statusRecovered.Status)
	}

	// First failure after recovery must set status to degraded, NOT disabled
	failProbes.Store(true)
	_, err = prober.ProbeTunnel(ctx, t1)
	if err == nil {
		t.Fatalf("expected probe error")
	}
	statusAfterFail1, _ := pool.GetTunnel(s1ID)
	if statusAfterFail1.Status != "degraded" {
		t.Fatalf("expected degraded after first failure post-recovery, got %s", statusAfterFail1.Status)
	}

	// Second failure -> still degraded
	_, _ = prober.ProbeTunnel(ctx, t1)
	statusAfterFail2, _ := pool.GetTunnel(s1ID)
	if statusAfterFail2.Status != "degraded" {
		t.Fatalf("expected degraded after second failure post-recovery, got %s", statusAfterFail2.Status)
	}

	// Third failure -> now disabled
	_, _ = prober.ProbeTunnel(ctx, t1)
	statusAfterFail3, _ := pool.GetTunnel(s1ID)
	if statusAfterFail3.Status != "disabled" {
		t.Fatalf("expected disabled after third failure post-recovery, got %s", statusAfterFail3.Status)
	}
}

func TestSelfHealing_HookFailurePreventsActivation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.5"})
	_, err := pool.AddTunnel(ctx, s1ID, "192.0.2.5:51820", "pubkey5")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 2,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)
	_ = pool.SetTunnelStatus(ctx, s1ID, "disabled", 0)
	prober.MarkAutoDisabled(s1ID)

	// Hook fails
	prober.SetOnSelfHealHook(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		return errors.New("hook execution failed")
	})

	// 1st success
	prober.SelfHealSweep(ctx)
	// 2nd success -> hook executes and fails -> resets consecutive successes to 0
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected on hook error, got %d", reconnected)
	}

	autoDisabled, successes := prober.GetSelfHealingState(s1ID)
	if !autoDisabled || successes != 0 {
		t.Fatalf("expected autoDisabled=true and successes=0 after hook failure, got autoDisabled=%v, successes=%d", autoDisabled, successes)
	}

	status, _ := pool.GetTunnel(s1ID)
	if status.Status != "disabled" {
		t.Fatalf("expected status to remain disabled after hook failure, got %s", status.Status)
	}
}

func TestSelfHealing_DisableSelfHealing(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.6"})
	_, err := pool.AddTunnel(ctx, s1ID, "192.0.2.6:51820", "pubkey6")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   true,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)
	_ = pool.SetTunnelStatus(ctx, s1ID, "disabled", 0)
	prober.MarkAutoDisabled(s1ID)

	// Sweep should return 0 when DisableSelfHealing is true
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected when DisableSelfHealing is true, got %d", reconnected)
	}
	_, successes := prober.GetSelfHealingState(s1ID)
	if successes != 0 {
		t.Fatalf("expected successes=0 when disabled, got %d", successes)
	}

	// Re-enable self healing via SetSelfHealingEnabled
	prober.SetSelfHealingEnabled(true)
	reconnected = prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected after enabling, got %d", reconnected)
	}
	status, _ := pool.GetTunnel(s1ID)
	if status.Status != "active" {
		t.Fatalf("expected status active, got %s", status.Status)
	}
}

func TestSelfHealing_DegradedOnHighLatencyRecovery(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.7"})
	_, err := pool.AddTunnel(ctx, s1ID, "192.0.2.7:51820", "pubkey7")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 350 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 1,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)
	_ = pool.SetTunnelStatus(ctx, s1ID, "disabled", 0)
	prober.MarkAutoDisabled(s1ID)

	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected, got %d", reconnected)
	}
	status, _ := pool.GetTunnel(s1ID)
	if status.Status != "degraded" {
		t.Fatalf("expected status degraded due to high latency, got %s", status.Status)
	}
	if status.LatencyMS != 350 {
		t.Fatalf("expected latency 350, got %d", status.LatencyMS)
	}
}
