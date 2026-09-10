package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

func TestHealthProber(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 1", Host: "1.1.1.1"})
	t1, err := pool.AddTunnel(ctx, s1ID, "1.1.1.1:51820", "pub1")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// Mock probe function
	var mockLatency time.Duration = 25 * time.Millisecond
	var mockErr error = nil

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return mockLatency, mockErr
	}

	cfg := HealthConfig{
		Interval:           50 * time.Millisecond,
		Timeout:            1 * time.Second,
		LatencyThresholdMS: 200,
		FailureThreshold:   2,
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// 1. Successful probe with normal latency
	lat, err := prober.ProbeTunnel(ctx, t1)
	if err != nil || lat != 25 {
		t.Fatalf("ProbeTunnel success mismatch: lat=%d, err=%v", lat, err)
	}
	t1Status, _ := pool.GetTunnel(s1ID)
	if t1Status.Status != "active" || t1Status.LatencyMS != 25 {
		t.Errorf("status mismatch: status=%s, lat=%d", t1Status.Status, t1Status.LatencyMS)
	}

	// 2. High latency probe (> 200ms threshold)
	mockLatency = 350 * time.Millisecond
	lat, err = prober.ProbeTunnel(ctx, t1)
	if err != nil || lat != 350 {
		t.Fatalf("ProbeTunnel high latency failed: lat=%d, err=%v", lat, err)
	}
	t1Status, _ = pool.GetTunnel(s1ID)
	if t1Status.Status != "degraded" || t1Status.LatencyMS != 350 {
		t.Errorf("expected degraded status on high latency, got %s", t1Status.Status)
	}

	// 3. Failing probe 1 (below threshold -> degraded)
	mockErr = errors.New("connection timeout")
	_, err = prober.ProbeTunnel(ctx, t1)
	if err == nil {
		t.Errorf("expected error from failing probe")
	}
	t1Status, _ = pool.GetTunnel(s1ID)
	if t1Status.Status != "degraded" {
		t.Errorf("expected degraded on first failure, got %s", t1Status.Status)
	}

	// 4. Failing probe 2 (reaching failure threshold 2 -> disabled)
	_, err = prober.ProbeTunnel(ctx, t1)
	if err == nil {
		t.Errorf("expected error from failing probe")
	}
	t1Status, _ = pool.GetTunnel(s1ID)
	if t1Status.Status != "disabled" {
		t.Errorf("expected disabled on second failure, got %s", t1Status.Status)
	}

	// 5. Recovery probe (success restores active)
	mockErr = nil
	mockLatency = 15 * time.Millisecond
	lat, err = prober.ProbeTunnel(ctx, t1)
	if err != nil || lat != 15 {
		t.Fatalf("ProbeTunnel recovery failed: lat=%d, err=%v", lat, err)
	}
	t1Status, _ = pool.GetTunnel(s1ID)
	if t1Status.Status != "active" || t1Status.LatencyMS != 15 {
		t.Errorf("expected active after recovery, got %s", t1Status.Status)
	}

	// 6. Nil tunnel
	if _, err := prober.ProbeTunnel(ctx, nil); err == nil {
		t.Errorf("expected error for nil tunnel")
	}

	// 7. ProbeAll
	s2ID, _ := db.CreateServer(ctx, &models.Server{Name: "Host 2", Host: "2.2.2.2"})
	_, _ = pool.AddTunnel(ctx, s2ID, "2.2.2.2:51820", "pub2")

	allResults := prober.ProbeAll(ctx)
	if len(allResults) != 2 {
		t.Errorf("expected 2 probe results from ProbeAll, got %d", len(allResults))
	}

	// 8. Background loop lifecycle
	prober.Start(ctx)
	if !prober.IsRunning() {
		t.Errorf("expected prober to be running")
	}
	// Double start noop
	prober.Start(ctx)

	time.Sleep(120 * time.Millisecond)

	prober.Stop()
	if prober.IsRunning() {
		t.Errorf("expected prober to not be running after Stop")
	}
	// Double stop noop
	prober.Stop()

	// Default config values
	defCfg := DefaultHealthConfig()
	defProber := NewHealthProber(nil, nil, defCfg)
	if defProber.cfg.Interval != 10*time.Second {
		t.Errorf("DefaultHealthConfig mismatch")
	}
	if defProber.ProbeAll(ctx) != nil {
		t.Errorf("expected nil ProbeAll for nil pool")
	}
}

func TestHealthProber_ResolveTunnelParamsAndNegativeMismatch(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	// 1. Server with backend-installed params
	s1ID, err := db.CreateServer(ctx, &models.Server{
		Name: "Server with AWG Params",
		Host: "192.0.2.1",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed": true,
				"awg_params": map[string]any{
					"h1": 111111,
					"h2": 222222,
					"s1": 40,
					"s2": 50,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer s1 failed: %v", err)
	}

	// 2. Server without AWG params, should fall back to VPNConfig
	s2ID, err := db.CreateServer(ctx, &models.Server{
		Name:      "Server without AWG Params",
		Host:      "192.0.2.2",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer s2 failed: %v", err)
	}

	// 3. Save VPNConfig
	vpnCfg := &models.VPNConfig{
		H1: models.DegenerateHeaderRange(333333),
		H2: models.DegenerateHeaderRange(444444),
		S1: 60,
		S2: 70,
	}
	if err := db.SaveVPNConfig(ctx, vpnCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	cfg := DefaultHealthConfig()
	cfg.H1 = 888888
	cfg.H2 = 999999
	cfg.S1 = 15
	cfg.S2 = 18

	var capturedH1, capturedH2 uint32
	var capturedS1, capturedS2 int
	var shouldFail bool

	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		capturedH1, capturedH2 = h1, h2
		capturedS1, capturedS2 = s1, s2
		if shouldFail {
			return 0, errors.New("handshake response verification failed: mismatched H1/S1")
		}
		return 30 * time.Millisecond, nil
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	// Verify resolveTunnelParams hierarchy for s1 (uses backend params)
	h1, h2, s1, s2, hpKeyResolved := prober.resolveTunnelParams(ctx, s1ID)
	if h1 != 111111 || h2 != 222222 || s1 != 40 || s2 != 50 {
		t.Errorf("s1 params mismatch: got (%d, %d, %d, %d), want (111111, 222222, 40, 50)", h1, h2, s1, s2)
	}
	if hpKeyResolved != "" {
		t.Errorf("s1 hpKey mismatch: got %q, want empty", hpKeyResolved)
	}

	// Verify resolveTunnelParams hierarchy for s2 (falls back to VPNConfig)
	h1, h2, s1, s2, hpKeyResolved = prober.resolveTunnelParams(ctx, s2ID)
	if h1 != 333333 || h2 != 444444 || s1 != 60 || s2 != 70 {
		t.Errorf("s2 params mismatch: got (%d, %d, %d, %d), want (333333, 444444, 60, 70)", h1, h2, s1, s2)
	}
	if hpKeyResolved != "" {
		t.Errorf("s2 hpKey mismatch: got %q, want empty", hpKeyResolved)
	}

	// Probe s1 tunnel: positive test
	t1, err := pool.AddTunnel(ctx, s1ID, "192.0.2.1:51820", "pub1")
	if err != nil {
		t.Fatalf("AddTunnel t1 failed: %v", err)
	}
	rtt, err := prober.ProbeTunnel(ctx, t1)
	if err != nil || rtt != 30 {
		t.Fatalf("ProbeTunnel t1 failed: rtt=%d, err=%v", rtt, err)
	}
	if capturedH1 != 111111 || capturedH2 != 222222 || capturedS1 != 40 || capturedS2 != 50 {
		t.Errorf("probeFn received wrong params: (%d, %d, %d, %d)", capturedH1, capturedH2, capturedS1, capturedS2)
	}

	// Negative test: mismatched parameters cause probe failure
	shouldFail = true
	_, err = prober.ProbeTunnel(ctx, t1)
	if err == nil {
		t.Error("expected ProbeTunnel to fail when params are mismatched")
	}
	st, _ := pool.GetTunnel(s1ID)
	if st.Status != "degraded" {
		t.Errorf("expected tunnel to be degraded after probe failure, got %s", st.Status)
	}
}

func TestHealthProber_InstalledServerEmptyAWGParams_FallsBackToVPNConfig(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	// Server has AWG protocol installed, port, public_key, but NO awg_params keys inside
	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Server with AWG installed but empty params",
		Host: "192.0.2.100",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "dummy-pubkey",
				"awg_params": map[string]any{},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Stored VPNConfig has randomized portal parameters
	vpnCfg := &models.VPNConfig{
		H1: models.DegenerateHeaderRange(777777),
		H2: models.DegenerateHeaderRange(888888),
		S1: 35,
		S2: 45,
	}
	if err := db.SaveVPNConfig(ctx, vpnCfg); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	cfg := DefaultHealthConfig()
	cfg.H1 = 12345
	cfg.H2 = 54321

	prober := NewHealthProber(pool, db, cfg, nil)

	// Explicitly verify paramsFromBackendServer returns found=false (Finding 2)
	bH1, bH2, bS1, bS2, bHPKey, found := paramsFromBackendServer(ctx, db, sID)
	if found {
		t.Errorf("expected paramsFromBackendServer to return found=false for empty params, got found=true (%d, %d, %d, %d)", bH1, bH2, bS1, bS2)
		if bHPKey != "" {
			t.Errorf("expected empty hpKey from paramsFromBackendServer for empty params, got %q", bHPKey)
		}
	}

	// Verify resolveTunnelParams resolves from VPNConfig (777777), NOT legacy constant 1020325451
	h1, h2, s1, s2, hpKeyResolved := prober.resolveTunnelParams(ctx, sID)
	if h1 != 777777 || h2 != 888888 || s1 != 35 || s2 != 45 {
		t.Errorf("resolveTunnelParams mismatch: got (%d, %d, %d, %d), want (777777, 888888, 35, 45)", h1, h2, s1, s2)
	}
	if h1 == health.DefaultH1 {
		t.Errorf("resolveTunnelParams incorrectly used legacy constant %d instead of VPNConfig", health.DefaultH1)
		if hpKeyResolved != "" {
			t.Errorf("resolveTunnelParams hpKey mismatch: got %q, want empty", hpKeyResolved)
		}
	}
}

func TestHealthProber_OnActiveHookFailure_EscalatesToDisabled(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:      "Hook Failure Test Server",
		Host:      "192.0.2.55",
		Protocols: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 3

	// Mock probe function always succeeds with 15ms latency
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}

	prober := NewHealthProber(pool, db, cfg, mockProbe)

	tunnel, err := pool.AddTunnel(ctx, sID, "192.0.2.55:51820", "pubkey-hook-test")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	hookFails := true
	prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		if hookFails {
			return errors.New("simulated hook failure: data-plane missing")
		}
		return nil
	})

	// Probe 1: hook fails -> failCounts = 1, status degraded
	rtt, err := prober.ProbeTunnel(ctx, tunnel)
	if err == nil {
		t.Fatal("expected ProbeTunnel to fail when onActiveHook fails")
	}
	if rtt != 0 {
		t.Errorf("expected rtt=0 on hook failure, got %d", rtt)
	}
	prober.mu.RLock()
	fc1 := prober.failCounts[sID]
	prober.mu.RUnlock()
	if fc1 != 1 {
		t.Fatalf("expected failCounts=1 after first failure, got %d", fc1)
	}
	st1, _ := pool.GetTunnel(sID)
	if st1.Status != "degraded" {
		t.Errorf("expected tunnel status 'degraded' after 1 hook failure, got %s", st1.Status)
	}

	// Probe 2: hook fails -> failCounts = 2, status degraded
	_, err = prober.ProbeTunnel(ctx, tunnel)
	if err == nil {
		t.Fatal("expected ProbeTunnel to fail on second hook failure")
	}
	prober.mu.RLock()
	fc2 := prober.failCounts[sID]
	prober.mu.RUnlock()
	if fc2 != 2 {
		t.Fatalf("expected failCounts=2 after second failure, got %d", fc2)
	}
	st2, _ := pool.GetTunnel(sID)
	if st2.Status != "degraded" {
		t.Errorf("expected tunnel status 'degraded' after 2 hook failures, got %s", st2.Status)
	}

	// Probe 3: hook fails -> reaches FailureThreshold (3) -> failCounts = 3, status disabled
	_, err = prober.ProbeTunnel(ctx, tunnel)
	if err == nil {
		t.Fatal("expected ProbeTunnel to fail on third hook failure")
	}
	prober.mu.RLock()
	fc3 := prober.failCounts[sID]
	prober.mu.RUnlock()
	if fc3 != 3 {
		t.Fatalf("expected failCounts=3 after third failure, got %d", fc3)
	}
	st3, _ := pool.GetTunnel(sID)
	if st3.Status != "disabled" {
		t.Errorf("expected tunnel status escalated to 'disabled' after %d hook failures, got %s", cfg.FailureThreshold, st3.Status)
	}

	// Recovery: hook succeeds -> failCounts resets to 0, status becomes active
	hookFails = false
	rtt, err = prober.ProbeTunnel(ctx, tunnel)
	if err != nil {
		t.Fatalf("expected ProbeTunnel to succeed on hook recovery, got: %v", err)
	}
	if rtt != 15 {
		t.Errorf("expected rtt=15 on success, got %d", rtt)
	}
	prober.mu.RLock()
	fcRec := prober.failCounts[sID]
	prober.mu.RUnlock()
	if fcRec != 0 {
		t.Errorf("expected failCounts reset to 0 after recovery, got %d", fcRec)
	}
	stRec, _ := pool.GetTunnel(sID)
	if stRec.Status != "active" {
		t.Errorf("expected tunnel status 'active' after recovery, got %s", stRec.Status)
	}
}
