package orchestrator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestOrchestrator_ProbeFailoverRetry_IsolatedFailureDoesNotDegrade verifies that
// a single isolated probe failure (e.g. transient UDP timeout or handshake drop)
// does not mark the backend tunnel as degraded and does not trigger session migration.
func TestOrchestrator_ProbeFailoverRetry_IsolatedFailureDoesNotDegrade(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	srv8ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	srv9ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 9", Host: "10.0.0.9", SSHPort: 22})

	t7ID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srv8ID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})
	t8ID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srv9ID,
		InterfaceName: "awg1",
		PublicKey:     "pub-srv9",
		Endpoint:      "127.0.0.1:55428",
		Status:        "active",
	})

	uID, _ := db.CreateUser(ctx, &models.User{Username: "client_user", Role: models.RoleUser})
	sessID := "session-client-1"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t7ID,
		PeerPublicKey:   "peer-pub-client-1",
		AssignedIP:      "10.100.100.10",
		Status:          "connected",
	})

	// Probe: Tunnel 7 suffers a single transient UDP read timeout; Tunnel 8 succeeds.
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if strings.Contains(endpoint, "55427") {
			return 0, errors.New("i/o timeout: read udp 127.0.0.1:55427: i/o timeout")
		}
		return 35 * time.Millisecond, nil
	}))

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	// 1. Fail count must be incremented to 1
	if got := orch.GetProbeFailCount(t7ID); got != 1 {
		t.Errorf("expected fail count 1 for tunnel 7, got %d", got)
	}

	// 2. Tunnel 7 must remain 'active' in database
	tun7, err := db.GetBackendTunnel(ctx, t7ID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if tun7.Status != "active" {
		t.Errorf("expected tunnel 7 status to remain active after 1 isolated failure, got %q", tun7.Status)
	}

	// 3. Session must NOT have migrated; must remain bound to Tunnel 7
	sess, err := db.GetVPNSessionByID(ctx, sessID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if sess.BackendTunnelID != t7ID {
		t.Errorf("expected session to remain on tunnel 7 (%d), but migrated to %d", t7ID, sess.BackendTunnelID)
	}
	if sess.Status != "connected" {
		t.Errorf("expected session status to remain connected, got %q", sess.Status)
	}

	_ = t8ID
}

// TestOrchestrator_ProbeFailoverRetry_ConsecutiveFailuresThresholdTriggersFailover verifies that
// reaching the consecutive failure threshold (default 3) marks the tunnel degraded and triggers session failover.
func TestOrchestrator_ProbeFailoverRetry_ConsecutiveFailuresThresholdTriggersFailover(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	srv8ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	srv9ID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 9", Host: "10.0.0.9", SSHPort: 22})

	t7ID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srv8ID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})
	t8ID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srv9ID,
		InterfaceName: "awg1",
		PublicKey:     "pub-srv9",
		Endpoint:      "127.0.0.1:55428",
		Status:        "active",
	})

	uID, _ := db.CreateUser(ctx, &models.User{Username: "client_user", Role: models.RoleUser})
	sessID := "session-client-2"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t7ID,
		PeerPublicKey:   "peer-pub-client-2",
		AssignedIP:      "10.100.100.11",
		Status:          "connected",
	})

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if strings.Contains(endpoint, "55427") {
			return 0, errors.New("handshake response verification failed")
		}
		return 30 * time.Millisecond, nil
	}))

	// Cycle 1: First failure (count=1 < 3) -> remains active, no failover
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("cycle 1 failed: %v", err)
	}
	if got := orch.GetProbeFailCount(t7ID); got != 1 {
		t.Errorf("cycle 1: expected fail count 1, got %d", got)
	}
	tun7, _ := db.GetBackendTunnel(ctx, t7ID)
	if tun7.Status != "active" {
		t.Errorf("cycle 1: expected tunnel 7 status active, got %q", tun7.Status)
	}

	// Cycle 2: Second failure (count=2 < 3) -> remains active, no failover
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("cycle 2 failed: %v", err)
	}
	if got := orch.GetProbeFailCount(t7ID); got != 2 {
		t.Errorf("cycle 2: expected fail count 2, got %d", got)
	}
	tun7, _ = db.GetBackendTunnel(ctx, t7ID)
	if tun7.Status != "active" {
		t.Errorf("cycle 2: expected tunnel 7 status active, got %q", tun7.Status)
	}
	sess, _ := db.GetVPNSessionByID(ctx, sessID)
	if sess.BackendTunnelID != t7ID {
		t.Errorf("cycle 2: session prematurely migrated to %d", sess.BackendTunnelID)
	}

	// Cycle 3: Third failure (count=3 == threshold) -> marks degraded, triggers failover
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("cycle 3 failed: %v", err)
	}
	if got := orch.GetProbeFailCount(t7ID); got != 3 {
		t.Errorf("cycle 3: expected fail count 3, got %d", got)
	}
	tun7, _ = db.GetBackendTunnel(ctx, t7ID)
	if tun7.Status != "degraded" {
		t.Errorf("cycle 3: expected tunnel 7 status degraded, got %q", tun7.Status)
	}

	// Session must now be migrated to healthy tunnel (t8ID)
	sess, _ = db.GetVPNSessionByID(ctx, sessID)
	if sess.BackendTunnelID != t8ID {
		t.Errorf("cycle 3: expected session migrated to tunnel 8 (%d), got %d", t8ID, sess.BackendTunnelID)
	}

	// Cycle 4: Fourth failure (count=4 >= threshold) -> remains degraded
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("cycle 4 failed: %v", err)
	}
	if got := orch.GetProbeFailCount(t7ID); got != 4 {
		t.Errorf("cycle 4: expected fail count 4, got %d", got)
	}
}

// TestOrchestrator_ProbeFailoverRetry_SuccessResetsCounter verifies that a successful
// probe immediately resets the consecutive failure counter to 0.
func TestOrchestrator_ProbeFailoverRetry_SuccessResetsCounter(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	srvID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srvID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})

	var shouldFail atomic.Bool
	shouldFail.Store(true)

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		if shouldFail.Load() {
			return 0, errors.New("temporary timeout")
		}
		return 20 * time.Millisecond, nil
	}))

	// Fail twice: fail count should be 2, tunnel active
	for i := 1; i <= 2; i++ {
		if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
			t.Fatalf("check failed on iter %d: %v", i, err)
		}
	}
	if got := orch.GetProbeFailCount(tID); got != 2 {
		t.Fatalf("expected fail count 2, got %d", got)
	}
	tun, _ := db.GetBackendTunnel(ctx, tID)
	if tun.Status != "active" {
		t.Fatalf("expected tunnel active, got %q", tun.Status)
	}

	// Next cycle succeeds: counter must be reset to 0
	shouldFail.Store(false)
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("check with success failed: %v", err)
	}
	if got := orch.GetProbeFailCount(tID); got != 0 {
		t.Errorf("expected fail count reset to 0 after success, got %d", got)
	}
	tun, _ = db.GetBackendTunnel(ctx, tID)
	if tun.Status != "active" || tun.LatencyMS != 20 {
		t.Errorf("expected status active with latency 20, got %s / %d", tun.Status, tun.LatencyMS)
	}

	// Subsequent failure starts from 1 again (not 3)
	shouldFail.Store(true)
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("check after reset failed: %v", err)
	}
	if got := orch.GetProbeFailCount(tID); got != 1 {
		t.Errorf("expected fail count 1 after fresh failure, got %d", got)
	}
	tun, _ = db.GetBackendTunnel(ctx, tID)
	if tun.Status != "active" {
		t.Errorf("expected status to remain active on 1 failure after reset, got %q", tun.Status)
	}
}

// TestOrchestrator_ProbeFailoverRetry_CustomThresholdOption verifies configuring custom
// failure thresholds via WithProbeFailureThreshold.
func TestOrchestrator_ProbeFailoverRetry_CustomThresholdOption(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Default threshold verification
	orchDef := New(db, nil)
	if orchDef.ProbeFailureThreshold() != DefaultProbeFailureThreshold {
		t.Errorf("expected default threshold %d, got %d", DefaultProbeFailureThreshold, orchDef.ProbeFailureThreshold())
	}

	// Custom threshold = 5
	srvID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srvID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})

	orch5 := New(db, nil,
		WithProbeFailureThreshold(5),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 0, errors.New("simulated error")
		}),
	)

	if orch5.ProbeFailureThreshold() != 5 {
		t.Fatalf("expected threshold 5, got %d", orch5.ProbeFailureThreshold())
	}

	// Failures 1 through 4 should remain active
	for i := 1; i <= 4; i++ {
		if err := orch5.CheckBackendTunnelHealth(ctx); err != nil {
			t.Fatalf("iter %d failed: %v", i, err)
		}
		if got := orch5.GetProbeFailCount(tID); got != i {
			t.Errorf("iter %d: expected fail count %d, got %d", i, i, got)
		}
		tun, _ := db.GetBackendTunnel(ctx, tID)
		if tun.Status != "active" {
			t.Errorf("iter %d: expected status active, got %q", i, tun.Status)
		}
	}

	// 5th failure reaches threshold -> degraded
	if err := orch5.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("5th check failed: %v", err)
	}
	if got := orch5.GetProbeFailCount(tID); got != 5 {
		t.Errorf("expected fail count 5, got %d", got)
	}
	tun, _ := db.GetBackendTunnel(ctx, tID)
	if tun.Status != "degraded" {
		t.Errorf("expected status degraded after 5 failures, got %q", tun.Status)
	}

	// Invalid threshold (<= 0) should preserve default
	orchInvalid := New(db, nil, WithProbeFailureThreshold(0))
	if orchInvalid.ProbeFailureThreshold() != DefaultProbeFailureThreshold {
		t.Errorf("expected threshold %d for 0 argument, got %d", DefaultProbeFailureThreshold, orchInvalid.ProbeFailureThreshold())
	}
}

// TestOrchestrator_ProbeFailoverRetry_ManualResetProbeFailCount verifies ResetProbeFailCount method.
func TestOrchestrator_ProbeFailoverRetry_ManualResetProbeFailCount(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	srvID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srvID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 0, errors.New("err")
	}))

	_ = orch.CheckBackendTunnelHealth(ctx)
	_ = orch.CheckBackendTunnelHealth(ctx)
	if got := orch.GetProbeFailCount(tID); got != 2 {
		t.Fatalf("expected count 2, got %d", got)
	}

	orch.ResetProbeFailCount(tID)
	if got := orch.GetProbeFailCount(tID); got != 0 {
		t.Errorf("expected count 0 after ResetProbeFailCount, got %d", got)
	}
}

// TestOrchestrator_ProbeFailoverRetry_HighLatencyStillDegrades verifies that latency exceeding
// threshold marks the tunnel degraded even when probe succeeds (err == nil).
func TestOrchestrator_ProbeFailoverRetry_HighLatencyStillDegrades(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 200})

	srvID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srvID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 350 * time.Millisecond, nil
	}))

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	// Probe succeeded, so consecutive failure count should be 0
	if got := orch.GetProbeFailCount(tID); got != 0 {
		t.Errorf("expected fail count 0 on probe success, got %d", got)
	}

	// But status should be degraded due to high latency
	tun, _ := db.GetBackendTunnel(ctx, tID)
	if tun.Status != "degraded" {
		t.Errorf("expected status degraded for 350ms > 200ms, got %q", tun.Status)
	}
	if tun.LatencyMS != 350 {
		t.Errorf("expected latency 350ms, got %d", tun.LatencyMS)
	}
}

// TestOrchestrator_ProbeFailoverRetry_ThreadSafety verifies concurrent safe operations
// on probe fail counts, threshold configurations, and health checks under race detector.
func TestOrchestrator_ProbeFailoverRetry_ThreadSafety(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	srvID, _ := db.CreateServer(ctx, &models.Server{Name: "Server 8", Host: "10.0.0.8", SSHPort: 22})
	tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      srvID,
		InterfaceName: "awg0",
		PublicKey:     "pub-srv8",
		Endpoint:      "127.0.0.1:55427",
		Status:        "active",
	})

	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 15 * time.Millisecond, nil
	}))

	var wg sync.WaitGroup
	workers := 10
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch (workerID + i) % 5 {
				case 0:
					_ = orch.CheckBackendTunnelHealth(ctx)
				case 1:
					_ = orch.GetProbeFailCount(tID)
				case 2:
					orch.ResetProbeFailCount(tID)
				case 3:
					_ = orch.recordProbeFailure(tID)
				case 4:
					WithProbeFailureThreshold(3 + (i % 3))(orch)
				}
			}
		}()
	}

	wg.Wait()
}
