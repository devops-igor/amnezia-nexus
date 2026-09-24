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

	// Administratively disable tunnel: set status disabled with reason admin and clear autoDisabled
	_ = pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0)
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
	_ = pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0)
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
	_ = pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0)
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
	_ = pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0)
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
	_ = pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0)
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

func TestSelfHealing_ConcurrentAdminDisableDuringHookNeverResurrects(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.8"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = pool.AddTunnel(ctx, s1ID, "192.0.2.8:51820", "pubkey8")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// Tunnel is auto-disabled due to health failures
	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 1, // Single probe triggers recovery hook
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)
	prober.MarkAutoDisabled(s1ID)

	hookEntered := make(chan struct{})
	hookRelease := make(chan struct{})

	prober.SetOnSelfHealHook(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		close(hookEntered)
		<-hookRelease
		return nil
	})

	sweepDone := make(chan int)
	go func() {
		sweepDone <- prober.SelfHealSweep(ctx)
	}()

	// Wait until the recovery hook is running
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hook entry")
	}

	// While hook is in flight, an administrator manually disables the backend
	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("admin disable failed: %v", err)
	}
	prober.MarkAdminDisabled(s1ID)

	// Release hook to resume SelfHealSweep
	close(hookRelease)

	var reconnected int
	select {
	case reconnected = <-sweepDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for sweep completion")
	}

	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected when admin disable raced hook, got %d", reconnected)
	}

	// Verify tunnel remains disabled with reason admin
	status, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if status.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status to remain disabled, got %s", status.Status)
	}
	if status.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected disable_reason admin, got %s", status.DisableReason)
	}

	// Verify prober does not consider it auto-disabled
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected IsAutoDisabled to be false after admin disable")
	}

	// Subsequent sweep must continue skipping it
	secondReconnected := prober.SelfHealSweep(ctx)
	if secondReconnected != 0 {
		t.Fatalf("expected 0 reconnected on subsequent sweep, got %d", secondReconnected)
	}
}

func TestSelfHealing_PersistenceFailureRemainsRetryable(t *testing.T) {
	db := setupTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.9"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = pool.AddTunnel(ctx, s1ID, "192.0.2.9:51820", "pubkey9")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
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
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)
	prober.MarkAutoDisabled(s1ID)

	// Cancel the context during hook execution so DB CAS in SelfHealSweep fails
	prober.SetOnSelfHealHook(func(hookCtx context.Context, tunnel *models.BackendTunnel) error {
		cancel()
		return nil
	})

	// Run sweep with context that gets canceled during hook
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected on DB CAS failure, got %d", reconnected)
	}

	// Verify tunnel remains in disabled state
	status, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if status.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected tunnel to remain disabled after persistence failure, got %s", status.Status)
	}
	if status.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable_reason to remain health, got %s", status.DisableReason)
	}

	// Verify prober still considers it auto-disabled (retryable)
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected IsAutoDisabled to remain true after persistence failure")
	}

	// Now run sweep with a fresh valid context and normal hook: recovery succeeds!
	freshCtx := context.Background()
	prober.SetOnSelfHealHook(func(hookCtx context.Context, tunnel *models.BackendTunnel) error {
		return nil
	})

	reconnected = prober.SelfHealSweep(freshCtx)
	if reconnected != 1 {
		t.Fatalf("expected 1 reconnected on retry with valid context, got %d", reconnected)
	}

	status, _ = pool.GetTunnel(s1ID)
	if status.Status != models.TunnelStatusActive {
		t.Fatalf("expected tunnel status active after retry, got %s", status.Status)
	}
	if status.DisableReason != models.DisableReasonNone {
		t.Fatalf("expected disable_reason cleared after retry, got %q", status.DisableReason)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected IsAutoDisabled to be false after successful retry")
	}
}

func TestInFlightProbeFailure_DoesNotOverwriteAdminDisable(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.10"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.10:51820", "pubkey10")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		select {
		case <-probeStarted:
		default:
			close(probeStarted)
		}
		<-releaseProbe
		return 0, errors.New("simulated probe failure")
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     1,
		SelfHealingThreshold: 1,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	probeDone := make(chan error, 1)
	go func() {
		_, probeErr := prober.ProbeTunnel(ctx, t1)
		probeDone <- probeErr
	}()

	select {
	case <-probeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe to start")
	}

	// While probe is in flight, an administrator disables the backend
	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("admin disable failed: %v", err)
	}
	prober.MarkAdminDisabled(s1ID)

	// Release probe so it returns failure
	close(releaseProbe)

	select {
	case err := <-probeDone:
		if err == nil {
			t.Fatal("expected probe to return error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe to complete")
	}

	// Verify tunnel remains disabled with reason admin
	status, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if status.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status to remain disabled, got %s", status.Status)
	}
	if status.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected disable_reason admin, got %s", status.DisableReason)
	}

	// Verify prober does not consider it auto-disabled
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected IsAutoDisabled to be false after admin disable")
	}

	// SelfHealSweep must skip it and return 0
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 0 {
		t.Fatalf("expected 0 reconnected for admin-disabled tunnel, got %d", reconnected)
	}
}

func TestInFlightProbeSuccess_DoesNotResurrectOrAttachDevice(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.11"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.11:51820", "pubkey11")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		select {
		case <-probeStarted:
		default:
			close(probeStarted)
		}
		<-releaseProbe
		return 20 * time.Millisecond, nil
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     2,
		SelfHealingThreshold: 1,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	var hookInvoked atomic.Bool
	prober.SetOnActiveHook(func(ctx context.Context, tunnel *models.BackendTunnel) error {
		hookInvoked.Store(true)
		return nil
	})

	probeDone := make(chan error, 1)
	go func() {
		_, probeErr := prober.ProbeTunnel(ctx, t1)
		probeDone <- probeErr
	}()

	select {
	case <-probeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe to start")
	}

	// While probe is in flight, an administrator disables the backend
	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("admin disable failed: %v", err)
	}
	prober.MarkAdminDisabled(s1ID)

	// Release probe so it returns success
	close(releaseProbe)

	select {
	case err := <-probeDone:
		if !errors.Is(err, ErrTunnelDisabled) {
			t.Fatalf("expected ErrTunnelDisabled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for probe to complete")
	}

	// Verify onActiveHook was never invoked
	if hookInvoked.Load() {
		t.Fatal("expected onActiveHook NOT to be invoked after admin disable")
	}

	// Verify tunnel remains disabled with reason admin
	status, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if status.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status to remain disabled, got %s", status.Status)
	}
	if status.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected disable_reason admin, got %s", status.DisableReason)
	}
}

func TestMarkAdminDisabled_ResetsFailCounts(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.12"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.12:51820", "pubkey12")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("failing probe")
	}

	cfg := HealthConfig{
		Interval:             50 * time.Millisecond,
		Timeout:              1 * time.Second,
		LatencyThresholdMS:   200,
		FailureThreshold:     5,
		SelfHealingThreshold: 2,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Run two failing probes to accumulate failCounts = 2
	_, _ = prober.ProbeTunnel(ctx, t1)
	_, _ = prober.ProbeTunnel(ctx, t1)

	prober.mu.RLock()
	fc := prober.failCounts[s1ID]
	prober.mu.RUnlock()
	if fc != 2 {
		t.Fatalf("expected failCounts to be 2, got %d", fc)
	}

	// MarkAdminDisabled must reset failCounts to 0
	prober.MarkAdminDisabled(s1ID)

	prober.mu.RLock()
	fcAfter := prober.failCounts[s1ID]
	prober.mu.RUnlock()
	if fcAfter != 0 {
		t.Fatalf("expected failCounts to be 0 after MarkAdminDisabled, got %d", fcAfter)
	}
}

func TestConcurrentProbeTunnel_SubThresholdDoesNotOverwriteDisabledState(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.14"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.14:51820", "pubkey14")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	initialTunnel, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	initialVersion := initialTunnel.StateVersion

	// 1. Simulate Probe A capturing snapshot at version V
	probeASnapshot := prober.getInitialSnapshot(t1)
	if probeASnapshot.StateVersion != initialVersion {
		t.Fatalf("expected snapshot version %d, got %d", initialVersion, probeASnapshot.StateVersion)
	}

	// 2. Before Probe A executes its status write, simulate Probe B running and reaching FailureThreshold (3),
	// successfully executing CAS to transition the tunnel to status="disabled", disable_reason="health",
	// and autoDisabled=true at state_version V+1
	prober.mu.Lock()
	prober.failCounts[s1ID] = 2 // will increment to 3 in handleProbeFailure
	prober.mu.Unlock()

	probeBSnapshot := prober.getInitialSnapshot(t1)
	_, err = prober.handleProbeFailure(ctx, probeBSnapshot, errors.New("probe B network timeout"))
	if err == nil {
		t.Fatal("expected probe B to return error")
	}

	tunAfterB, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfterB.Status != models.TunnelStatusDisabled || tunAfterB.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected Probe B to disable tunnel with health reason, got status=%s, reason=%s", tunAfterB.Status, tunAfterB.DisableReason)
	}
	if tunAfterB.StateVersion != initialVersion+1 {
		t.Fatalf("expected version %d after Probe B, got %d", initialVersion+1, tunAfterB.StateVersion)
	}
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected server to be auto-disabled after Probe B")
	}

	// 3. Probe A fails sub-threshold (e.g. fail count 2 < 3) and finishes its failure handling
	// using the stale snapshot captured at version V
	prober.mu.Lock()
	prober.failCounts[s1ID] = 1 // will increment to 2 (< FailureThreshold 3)
	prober.mu.Unlock()

	_, err = prober.handleProbeFailure(ctx, probeASnapshot, errors.New("probe A failure"))
	if err == nil {
		t.Fatal("expected probe A to return error")
	}

	// 4. Assert: Probe A's sub-threshold degraded CAS misses (swapped == false)
	// Pool tunnel remains status="disabled", disable_reason="health", and version V+1
	cur, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s, got %s (sub-threshold probe overwrote disabled status)", models.TunnelStatusDisabled, cur.Status)
	}
	if cur.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable reason %s, got %s", models.DisableReasonHealth, cur.DisableReason)
	}
	if cur.StateVersion != initialVersion+1 {
		t.Fatalf("expected state version %d, got %d", initialVersion+1, cur.StateVersion)
	}

	// Assert: hp.autoDisabled[serverID] remains true
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d to remain auto-disabled", s1ID)
	}

	// Assert: SelfHealSweep recognizes the auto-disabled tunnel and includes it in its recovery sweep
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected SelfHealSweep to reconnect 1 tunnel, got %d", reconnected)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d autoDisabled to be cleared after recovery", s1ID)
	}
	recoveredStatus, _ := pool.GetTunnel(s1ID)
	if recoveredStatus.Status != models.TunnelStatusActive {
		t.Fatalf("expected recovered status %s, got %s", models.TunnelStatusActive, recoveredStatus.Status)
	}
}

func TestConcurrentHookFailure_SubThresholdDoesNotOverwriteDisabledState(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.15"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.15:51820", "pubkey15")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	initialTunnel, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	initialVersion := initialTunnel.StateVersion

	// 1. Hook A captures snapshot at version V
	hookASnapshot := prober.getInitialSnapshot(t1)

	// 2. Simulate Probe B reaching FailureThreshold (3) and auto-disabling the tunnel at version V+1
	prober.mu.Lock()
	prober.failCounts[s1ID] = 2
	prober.mu.Unlock()

	probeBSnapshot := prober.getInitialSnapshot(t1)
	_, err = prober.handleProbeFailure(ctx, probeBSnapshot, errors.New("probe B network timeout"))
	if err == nil {
		t.Fatal("expected probe B to return error")
	}

	tunAfterB, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfterB.Status != models.TunnelStatusDisabled || tunAfterB.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected Probe B to disable tunnel, got status=%s, reason=%s", tunAfterB.Status, tunAfterB.DisableReason)
	}
	if tunAfterB.StateVersion != initialVersion+1 {
		t.Fatalf("expected version %d after Probe B, got %d", initialVersion+1, tunAfterB.StateVersion)
	}
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected server to be auto-disabled after Probe B")
	}

	// 3. Hook A fails sub-threshold (e.g. fail count 2 < 3) and executes handleHookFailure with stale snapshot
	prober.mu.Lock()
	prober.failCounts[s1ID] = 1
	prober.mu.Unlock()

	_, err = prober.handleHookFailure(ctx, hookASnapshot, errors.New("hook readiness failure"))
	if err == nil {
		t.Fatal("expected hook failure to return error")
	}

	// 4. Assert: Hook A's sub-threshold degraded CAS misses
	cur, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s, got %s (sub-threshold hook failure overwrote disabled status)", models.TunnelStatusDisabled, cur.Status)
	}
	if cur.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable reason %s, got %s", models.DisableReasonHealth, cur.DisableReason)
	}
	if cur.StateVersion != initialVersion+1 {
		t.Fatalf("expected state version %d, got %d", initialVersion+1, cur.StateVersion)
	}

	if !prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d to remain auto-disabled", s1ID)
	}

	// 5. Assert: SelfHealSweep recovers tunnel
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected SelfHealSweep to reconnect 1 tunnel, got %d", reconnected)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d autoDisabled to be cleared after recovery", s1ID)
	}
	recoveredStatus, _ := pool.GetTunnel(s1ID)
	if recoveredStatus.Status != models.TunnelStatusActive {
		t.Fatalf("expected recovered status %s, got %s", models.TunnelStatusActive, recoveredStatus.Status)
	}
}

func TestConcurrentProbeTunnel_ReverseOrder_SubThresholdWinsThenThresholdReconciles(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.16"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.16:51820", "pubkey16")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	initialTunnel, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	initialVersion := initialTunnel.StateVersion

	// Initial state: failCounts = 1
	prober.mu.Lock()
	prober.failCounts[s1ID] = 1
	prober.mu.Unlock()

	// 1. Both Probe A and Probe B take snapshots at version V
	probeASnapshot := prober.getInitialSnapshot(t1)
	probeBSnapshot := prober.getInitialSnapshot(t1)
	if probeASnapshot.StateVersion != initialVersion || probeBSnapshot.StateVersion != initialVersion {
		t.Fatalf("expected snapshots at version %d, got %d and %d", initialVersion, probeASnapshot.StateVersion, probeBSnapshot.StateVersion)
	}

	// 2. Probe A fails (sub-threshold, fail count: 1 -> 2 < FailureThreshold 3)
	// Probe A executes CAS active/V -> degraded/V+1, which succeeds.
	_, err = prober.handleProbeFailure(ctx, probeASnapshot, errors.New("probe A network timeout"))
	if err == nil {
		t.Fatal("expected probe A to return error")
	}

	tunAfterA, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfterA.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected Probe A to set status degraded, got %s", tunAfterA.Status)
	}
	if tunAfterA.StateVersion != initialVersion+1 {
		t.Fatalf("expected version %d after Probe A, got %d", initialVersion+1, tunAfterA.StateVersion)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("server should not be auto-disabled after sub-threshold probe A")
	}

	// 3. Probe B fails (reaching threshold, fail count: 2 -> 3 >= FailureThreshold 3)
	// Initial CAS with probeBSnapshot (version V) misses because pool is at version V+1.
	// Probe B reconciles against current tunnel (degraded/V+1) and CAS to disabled/health succeeds.
	_, err = prober.handleProbeFailure(ctx, probeBSnapshot, errors.New("probe B network timeout"))
	if err == nil {
		t.Fatal("expected probe B to return error")
	}

	// 4. Assertions:
	// status == "disabled", disable_reason == models.DisableReasonHealth, version == V+2
	cur, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s, got %s", models.TunnelStatusDisabled, cur.Status)
	}
	if cur.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable reason %s, got %s", models.DisableReasonHealth, cur.DisableReason)
	}
	if cur.StateVersion != initialVersion+2 {
		t.Fatalf("expected state version %d, got %d", initialVersion+2, cur.StateVersion)
	}

	// autoDisabled[serverID] == true
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d to be auto-disabled after reconciliation", s1ID)
	}

	// failCounts[serverID] >= 3
	prober.mu.Lock()
	fc := prober.failCounts[s1ID]
	prober.mu.Unlock()
	if fc < 3 {
		t.Fatalf("expected failCounts >= 3, got %d", fc)
	}

	// SelfHealSweep detects the tunnel and successfully restores it
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected SelfHealSweep to reconnect 1 tunnel, got %d", reconnected)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d autoDisabled to be cleared after recovery", s1ID)
	}
	recoveredStatus, _ := pool.GetTunnel(s1ID)
	if recoveredStatus.Status != models.TunnelStatusActive {
		t.Fatalf("expected recovered status %s, got %s", models.TunnelStatusActive, recoveredStatus.Status)
	}
}

func TestConcurrentHookFailure_ReverseOrder_SubThresholdWinsThenThresholdReconciles(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.17"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.17:51820", "pubkey17")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	initialTunnel, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	initialVersion := initialTunnel.StateVersion

	// Initial state: failCounts = 1
	prober.mu.Lock()
	prober.failCounts[s1ID] = 1
	prober.mu.Unlock()

	// 1. Both Hook A and Hook B capture snapshots at version V
	hookASnapshot := prober.getInitialSnapshot(t1)
	hookBSnapshot := prober.getInitialSnapshot(t1)
	if hookASnapshot.StateVersion != initialVersion || hookBSnapshot.StateVersion != initialVersion {
		t.Fatalf("expected snapshots at version %d, got %d and %d", initialVersion, hookASnapshot.StateVersion, hookBSnapshot.StateVersion)
	}

	// 2. Hook A fails (sub-threshold, fail count: 1 -> 2 < 3)
	// Hook A executes CAS active/V -> degraded/V+1, which succeeds.
	_, err = prober.handleHookFailure(ctx, hookASnapshot, errors.New("hook A readiness failure"))
	if err == nil {
		t.Fatal("expected hook A to return error")
	}

	tunAfterA, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfterA.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected Hook A to set status degraded, got %s", tunAfterA.Status)
	}
	if tunAfterA.StateVersion != initialVersion+1 {
		t.Fatalf("expected version %d after Hook A, got %d", initialVersion+1, tunAfterA.StateVersion)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("server should not be auto-disabled after sub-threshold hook A")
	}

	// 3. Hook B fails (reaching threshold, fail count: 2 -> 3 >= 3)
	// Initial CAS with hookBSnapshot (version V) misses because pool is at version V+1.
	// Hook B reconciles against current tunnel (degraded/V+1) and CAS to disabled/health succeeds.
	_, err = prober.handleHookFailure(ctx, hookBSnapshot, errors.New("hook B readiness failure"))
	if err == nil {
		t.Fatal("expected hook B to return error")
	}

	// 4. Assertions:
	// status == "disabled", disable_reason == models.DisableReasonHealth, version == V+2
	cur, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDisabled {
		t.Fatalf("expected status %s, got %s", models.TunnelStatusDisabled, cur.Status)
	}
	if cur.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected disable reason %s, got %s", models.DisableReasonHealth, cur.DisableReason)
	}
	if cur.StateVersion != initialVersion+2 {
		t.Fatalf("expected state version %d, got %d", initialVersion+2, cur.StateVersion)
	}

	// autoDisabled[serverID] == true
	if !prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d to be auto-disabled after reconciliation", s1ID)
	}

	// failCounts[serverID] >= 3
	prober.mu.Lock()
	fc := prober.failCounts[s1ID]
	prober.mu.Unlock()
	if fc < 3 {
		t.Fatalf("expected failCounts >= 3, got %d", fc)
	}

	// SelfHealSweep detects the tunnel and successfully restores it
	reconnected := prober.SelfHealSweep(ctx)
	if reconnected != 1 {
		t.Fatalf("expected SelfHealSweep to reconnect 1 tunnel, got %d", reconnected)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatalf("expected server %d autoDisabled to be cleared after recovery", s1ID)
	}
	recoveredStatus, _ := pool.GetTunnel(s1ID)
	if recoveredStatus.Status != models.TunnelStatusActive {
		t.Fatalf("expected recovered status %s, got %s", models.TunnelStatusActive, recoveredStatus.Status)
	}
}

func TestThresholdReconcile_ConcurrentAdminDisableAborts(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.18"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.18:51820", "pubkey18")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Snapshot at version V
	snapshot := prober.getInitialSnapshot(t1)

	// failCounts is 2 (will reach 3)
	prober.mu.Lock()
	prober.failCounts[s1ID] = 2
	prober.mu.Unlock()

	// Admin disable occurs concurrently before probe failure handler executes CAS
	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	// Probe failure handler runs
	_, err = prober.handleProbeFailure(ctx, snapshot, errors.New("network error"))
	if err == nil {
		t.Fatal("expected probe failure error")
	}

	// Assert: tunnel remains admin-disabled, autoDisabled is false, failCounts reset
	cur, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDisabled || cur.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected admin disabled tunnel, got status=%s, reason=%s", cur.Status, cur.DisableReason)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("server should not be marked autoDisabled when admin-disabled")
	}
	prober.mu.Lock()
	fc := prober.failCounts[s1ID]
	prober.mu.Unlock()
	if fc != 0 {
		t.Fatalf("expected failCounts to be reset to 0, got %d", fc)
	}
}

func TestThresholdReconcile_ConcurrentSuccessAborts(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.19"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = pool.AddTunnel(ctx, s1ID, "192.0.2.19:51820", "pubkey19")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Simulate concurrent probe changing version to V+1 (status degraded)
	if err := pool.SetTunnelStatus(ctx, s1ID, models.TunnelStatusDegraded, 250); err != nil {
		t.Fatalf("SetTunnelStatus failed: %v", err)
	}

	// Concurrent success probe resets failCounts to 0 right before reconcile checks it
	prober.mu.Lock()
	prober.failCounts[s1ID] = 0 // concurrent success reset it
	prober.mu.Unlock()

	current, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := prober.reconcileThresholdAutoDisable(ctx, s1ID, current.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reconciled {
		t.Fatal("expected reconcile to abort when failCounts < FailureThreshold")
	}

	// Tunnel remains degraded, not auto-disabled
	cur, _ := pool.GetTunnel(s1ID)
	if cur.Status != models.TunnelStatusDegraded {
		t.Fatalf("expected status degraded, got %s", cur.Status)
	}
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected autoDisabled to be false")
	}
}

func TestThresholdReconcile_AdminDisableDuringReconcile(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	s1ID, err := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "192.0.2.20"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	_, err = pool.AddTunnel(ctx, s1ID, "192.0.2.20:51820", "pubkey20")
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
		FailureThreshold:     3,
		SelfHealingThreshold: 1,
		DisableSelfHealing:   false,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Admin disable tunnel in pool
	if err := pool.SetTunnelStatusWithReason(ctx, s1ID, models.TunnelStatusDisabled, models.DisableReasonAdmin, 0); err != nil {
		t.Fatalf("SetTunnelStatusWithReason failed: %v", err)
	}

	// Set failCounts and autoDisabled in prober
	prober.mu.Lock()
	prober.failCounts[s1ID] = 3
	prober.autoDisabled[s1ID] = true
	prober.mu.Unlock()

	current, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatal(err)
	}
	reconciled, err := prober.reconcileThresholdAutoDisable(ctx, s1ID, current.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reconciled {
		t.Fatal("expected reconcile to return false when tunnel is admin-disabled")
	}

	// Assert: autoDisabled is cleared, failCounts reset
	if prober.IsAutoDisabled(s1ID) {
		t.Fatal("expected autoDisabled to be cleared")
	}
	prober.mu.Lock()
	fc := prober.failCounts[s1ID]
	prober.mu.Unlock()
	if fc != 0 {
		t.Fatalf("expected failCounts to be reset to 0, got %d", fc)
	}

	// Assert: tunnel in pool remains disabled with DisableReasonAdmin
	cur, err := pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if cur.Status != models.TunnelStatusDisabled || cur.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("expected status=disabled and reason=admin, got status=%s, reason=%s", cur.Status, cur.DisableReason)
	}
}
