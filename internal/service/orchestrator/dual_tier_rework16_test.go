package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestOrchestrator_Rework16_OuterFail_InnerCanarySuccess_ResetsCanaryFailCount verifies [F13]:
// When an established backend tunnel has outer handshake failure but successful inner canary probe,
// consecutive canary failure counts are reset to 0 so isolated failures cannot accumulate into premature session migration.
func TestOrchestrator_Rework16_OuterFail_InnerCanarySuccess_ResetsCanaryFailCount(t *testing.T) {
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
		ActiveConnections: 2,
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

	uID, _ := db.CreateUser(ctx, &models.User{Username: "alice", Role: models.RoleUser})
	sessID := "session-alice-f13"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t1,
		PeerPublicKey:   "peer-alice-pub",
		AssignedIP:      "10.100.1.20",
		Status:          "connected",
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	tun2, _ := db.GetBackendTunnel(ctx, t2)
	updater := newMockCanaryUpdater(db, tun1, tun2)

	outerFail := false
	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			if outerFail && endpoint == "10.0.0.1:51820" {
				return 0, errors.New("intermittent outer handshake drop")
			}
			return 20 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	// Step 1: Pass 1 fails canary (1 < 3) -> handshake_blocked, counter = 1
	updater.canaryErr = errors.New("transient inner timeout")
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 1 failed: %v", err)
	}
	if count := orch.GetCanaryFailCount(t1); count != 1 {
		t.Fatalf("Pass 1: expected canaryFailCount 1, got %d", count)
	}

	// Step 2: Pass 2 has outer failure but inner canary succeeds -> must reset canaryFailCount to 0!
	outerFail = true
	updater.canaryErr = nil
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 2 failed: %v", err)
	}
	if count := orch.GetCanaryFailCount(t1); count != 0 {
		t.Fatalf("Pass 2: inner canary success must reset canaryFailCount to 0, got %d", count)
	}

	// Step 3: Pass 3 has another isolated canary failure -> counter must be 1, NOT 2 or 3!
	outerFail = false
	updater.canaryErr = errors.New("isolated inner timeout")
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 3 failed: %v", err)
	}
	if count := orch.GetCanaryFailCount(t1); count != 1 {
		t.Fatalf("Pass 3: isolated failure must yield canaryFailCount 1, got %d", count)
	}

	// Session must NOT have been migrated!
	sess, err := db.GetVPNSessionByID(ctx, sessID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if sess.BackendTunnelID != t1 {
		t.Fatalf("session must remain on tunnel %d, but was migrated to %d", t1, sess.BackendTunnelID)
	}
}

// TestOrchestrator_Rework16_ActiveRecovery_ClearsCanaryFailCount verifies [F13]:
// When an external health prober or ordinary recovery restores an active status between scheduler passes,
// the scheduler's stale failure history is cleared so subsequent isolated failures do not prematurely migrate sessions.
func TestOrchestrator_Rework16_ActiveRecovery_ClearsCanaryFailCount(t *testing.T) {
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
			return 20 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	// Step 1: First canary failure
	updater.canaryErr = errors.New("transient timeout")
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 1 failed: %v", err)
	}
	if count := orch.GetCanaryFailCount(t1); count != 1 {
		t.Fatalf("Pass 1: expected canaryFailCount 1, got %d", count)
	}

	// Step 2: Ordinary health prober restores tunnel to active in DB
	_ = db.UpdateBackendTunnelStatus(ctx, t1, models.TunnelStatusActive, 30)

	// GetCanaryFailCount on active tunnel must return 0
	if count := orch.GetCanaryFailCount(t1); count != 0 {
		t.Fatalf("observed active tunnel must clear canaryFailCount, got %d", count)
	}

	// Step 3: Next scheduler pass with isolated failure must record 1, not 2
	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("Pass 2 failed: %v", err)
	}
	if count := orch.GetCanaryFailCount(t1); count != 1 {
		t.Fatalf("Pass 2: expected canaryFailCount 1 after recovery, got %d", count)
	}
}
