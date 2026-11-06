package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestOrchestrator_Rework15_TransientCanaryFail_DoesNotMigrateSessions verifies [BLOCKER 2]:
// A single transient inner canary failure does NOT degrade active backends or migrate established sessions.
// Fresh admissions are blocked (marked handshake_blocked), but existing sessions remain connected.
// Only after sustained canary failures reaching the threshold is the backend degraded and sessions migrated.
func TestOrchestrator_Rework15_TransientCanaryFail_DoesNotMigrateSessions(t *testing.T) {
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
		ActiveConnections: 3,
		Protocol:          models.ProtocolAWG,
	})
	t2, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:          s2,
		InterfaceName:     "awg1",
		PublicKey:         "pub2",
		Endpoint:          "10.0.0.2:51820",
		Status:            models.TunnelStatusActive,
		Enabled:           true,
		ActiveConnections: 1,
		Protocol:          models.ProtocolAWG,
	})

	uID, _ := db.CreateUser(ctx, &models.User{Username: "bob", Role: models.RoleUser})
	sessID := "session-bob-1"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t1,
		PeerPublicKey:   "peer-bob-pub",
		AssignedIP:      "10.100.1.20",
		Status:          "connected",
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	tun2, _ := db.GetBackendTunnel(ctx, t2)
	updater := newMockCanaryUpdater(db, tun1, tun2)

	// Threshold = 3
	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 20 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	// Inner canary fails for tunnel 1
	updater.canaryErr = errors.New("transient inner canary timeout")
	orch.statusUpdater = &orchestratorCanaryFilterUpdater{
		mockCanaryUpdater: updater,
		canaryFn: func(tunnel *models.BackendTunnel) error {
			if tunnel.ID == t1 {
				return errors.New("transient inner canary timeout")
			}
			return nil
		},
	}

	// Pass 1: First transient failure (1 < 3)
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 1 CheckBackendTunnelHealth failed: %v", err)
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("Pass 1: expected status %s to block new admissions, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}

	sess1, _ := db.GetVPNSessionByID(ctx, sessID)
	if sess1.BackendTunnelID != t1 {
		t.Fatalf("[BLOCKER 2 REGRESSION] Pass 1: transient canary failure must NOT migrate sessions! Expected tunnel %d, got %d", t1, sess1.BackendTunnelID)
	}

	if count := orch.GetCanaryFailCount(t1); count != 1 {
		t.Fatalf("Pass 1: expected canaryFailCount 1, got %d", count)
	}

	// Pass 2: Second consecutive failure (2 < 3)
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 2 CheckBackendTunnelHealth failed: %v", err)
	}

	res2, _ := db.GetBackendTunnel(ctx, t1)
	if res2.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("Pass 2: expected status %s, got %s", models.TunnelStatusHandshakeBlocked, res2.Status)
	}

	sess2, _ := db.GetVPNSessionByID(ctx, sessID)
	if sess2.BackendTunnelID != t1 {
		t.Fatalf("[BLOCKER 2 REGRESSION] Pass 2: transient canary failure below threshold must NOT migrate sessions! Expected tunnel %d, got %d", t1, sess2.BackendTunnelID)
	}

	if count := orch.GetCanaryFailCount(t1); count != 2 {
		t.Fatalf("Pass 2: expected canaryFailCount 2, got %d", count)
	}

	// Pass 3: Third consecutive failure (3 >= 3 -> threshold reached!)
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 3 CheckBackendTunnelHealth failed: %v", err)
	}

	res3, _ := db.GetBackendTunnel(ctx, t1)
	if res3.Status != models.TunnelStatusDegraded {
		t.Fatalf("Pass 3: sustained failures reaching threshold MUST mark degraded, got %s", res3.Status)
	}

	sess3, _ := db.GetVPNSessionByID(ctx, sessID)
	if sess3.BackendTunnelID != t2 {
		t.Fatalf("Pass 3: sustained failures reaching threshold MUST migrate sessions to healthy tunnel %d, got %d", t2, sess3.BackendTunnelID)
	}
}

// TestOrchestrator_Rework15_CanarySuccess_ResetsFailureCounterAndRestoresActive verifies [BLOCKER 2]:
// When an active tunnel experiences a transient canary failure (below threshold), and on the next pass
// canary succeeds, the consecutive canary failure counter is reset to 0 and the tunnel recovers to active.
func TestOrchestrator_Rework15_CanarySuccess_ResetsFailureCounterAndRestoresActive(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	s1, _ := db.CreateServer(ctx, &models.Server{Name: "Server 1", Host: "10.0.0.1"})
	t1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:          s1,
		InterfaceName:     "awg0",
		PublicKey:         "pub1",
		Endpoint:          "10.0.0.1:51820",
		Status:            models.TunnelStatusActive,
		Enabled:           true,
		ActiveConnections: 2,
		Protocol:          models.ProtocolAWG,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)

	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 15 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	// Step 1: Canary probe fails on first pass
	updater.canaryErr = errors.New("intermittent network stall")
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 1 failed: %v", err)
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s after 1 canary failure, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}
	if count := orch.GetCanaryFailCount(t1); count != 1 {
		t.Fatalf("expected canaryFailCount 1, got %d", count)
	}

	// Step 2: Canary probe recovers on second pass
	updater.canaryErr = nil
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 2 failed: %v", err)
	}

	res2, _ := db.GetBackendTunnel(ctx, t1)
	if res2.Status != models.TunnelStatusActive {
		t.Fatalf("expected status restored to %s, got %s", models.TunnelStatusActive, res2.Status)
	}
	if count := orch.GetCanaryFailCount(t1); count != 0 {
		t.Fatalf("expected canaryFailCount reset to 0, got %d", count)
	}
}

// TestOrchestrator_Rework15_Concurrency_RaceFreeProbeFailVersions verifies [BLOCKER 1]:
// Concurrent access to probeFailVersions and canaryFailCounts via recordProbeFailVersion,
// recordCanaryFailure, ResetCanaryFailCount, GetCanaryFailCount, recordProbeFailure,
// and revertProbeFailure executes with zero data races detected under -race.
func TestOrchestrator_Rework15_Concurrency_RaceFreeProbeFailVersions(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	const numTunnels = 10
	var tunnelIDs []int64
	for i := 1; i <= numTunnels; i++ {
		sID, _ := db.CreateServer(ctx, &models.Server{Name: fmt.Sprintf("Server %d", i), Host: fmt.Sprintf("10.0.0.%d", i)})
		tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: fmt.Sprintf("awg%d", i),
			PublicKey:     fmt.Sprintf("pub%d", i),
			Endpoint:      fmt.Sprintf("10.0.0.%d:51820", i),
			Status:        models.TunnelStatusActive,
			Enabled:       true,
		})
		tunnelIDs = append(tunnelIDs, tID)
	}

	orch := New(db, nil, WithProbeFailureThreshold(3))

	const numWorkers = 8
	const numIterations = 100
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	var stopSignal atomic.Bool

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for it := 0; it < numIterations && !stopSignal.Load(); it++ {
				tID := tunnelIDs[(workerID+it)%numTunnels]
				version := int64(it + 1)

				switch it % 7 {
				case 0:
					orch.recordProbeFailVersion(tID, version)
				case 1:
					orch.recordProbeFailure(tID, version)
				case 2:
					orch.revertProbeFailure(tID, version)
				case 3:
					orch.ResetProbeFailCount(tID)
				case 4:
					orch.recordCanaryFailure(tID)
				case 5:
					_ = orch.GetCanaryFailCount(tID)
				case 6:
					orch.ResetCanaryFailCount(tID)
				}
			}
		}(w)
	}

	wg.Wait()
}

// TestOrchestrator_Rework15_Concurrency_ConcurrentProbes_RaceFree verifies [BLOCKER 1]:
// Running concurrent CheckBackendTunnelHealth passes with simultaneous outer/inner canary
// failures and updates runs cleanly with zero data races detected by -race.
func TestOrchestrator_Rework15_Concurrency_ConcurrentProbes_RaceFree(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 500})

	const numTunnels = 4
	var tunnels []*models.BackendTunnel
	for i := 1; i <= numTunnels; i++ {
		sID, _ := db.CreateServer(ctx, &models.Server{Name: fmt.Sprintf("Server %d", i), Host: fmt.Sprintf("10.0.0.%d", i)})
		tID, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:          sID,
			InterfaceName:     fmt.Sprintf("awg%d", i),
			PublicKey:         fmt.Sprintf("pub%d", i),
			Endpoint:          fmt.Sprintf("10.0.0.%d:51820", i),
			Status:            models.TunnelStatusActive,
			Enabled:           true,
			ActiveConnections: 1,
			Protocol:          models.ProtocolAWG,
		})
		tun, _ := db.GetBackendTunnel(ctx, tID)
		tunnels = append(tunnels, tun)
	}

	updater := newMockCanaryUpdater(db, tunnels...)
	updater.hasCanary = true
	var toggle atomic.Int32
	updater.canaryErr = errors.New("concurrent probe canary error")

	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			if toggle.Add(1)%2 == 0 {
				return 0, errors.New("probe err")
			}
			return 20 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	const numCallers = 4
	const numPasses = 10
	var wg sync.WaitGroup
	wg.Add(numCallers)

	for c := 0; c < numCallers; c++ {
		go func() {
			defer wg.Done()
			for p := 0; p < numPasses; p++ {
				_ = orch.CheckBackendTunnelHealth(ctx)
			}
		}()
	}

	wg.Wait()
}
