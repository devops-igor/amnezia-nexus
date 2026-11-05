package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestOrchestrator_Rework19_OuterPass_HandshakeBlocked_WithSessions_NoCanary_DoesNotBecomeActive verifies [BLOCKER 1]:
// A handshake_blocked backend with established sessions enters CheckBackendTunnelHealth.
// Outer probe succeeds. If no canary prober is available:
// - Status MUST NOT become active (new client admission denied).
// - Status MUST preserve handshake_blocked.
// - Established sessions pinned to this backend are preserved (not migrated).
func TestOrchestrator_Rework19_OuterPass_HandshakeBlocked_WithSessions_NoCanary_DoesNotBecomeActive(t *testing.T) {
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
		Status:            models.TunnelStatusHandshakeBlocked,
		Enabled:           true,
		ActiveConnections: 4,
		Protocol:          models.ProtocolAWG,
	})

	uID, _ := db.CreateUser(ctx, &models.User{Username: "alice", Role: models.RoleUser})
	sessID := "session-alice-1"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t1,
		PeerPublicKey:   "peer-alice-pub",
		AssignedIP:      "10.100.1.30",
		Status:          "connected",
	})

	// Orchestrator without canary prober (uses mockStatusUpdater which does NOT implement CanaryProber)
	updater := &mockStatusUpdater{}
	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 20 * time.Millisecond, nil // Outer probe succeeds
		}),
		WithTunnelStatusUpdater(updater),
	)

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status == models.TunnelStatusActive {
		t.Fatalf("[BLOCKER 1 REGRESSION] handshake_blocked backend promoted to active without canary verification!")
	}
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status to remain %s, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}

	// Established session must NOT be migrated
	sess1, _ := db.GetVPNSessionByID(ctx, sessID)
	if sess1.BackendTunnelID != t1 {
		t.Fatalf("expected established session to remain on tunnel %d, but got %d", t1, sess1.BackendTunnelID)
	}
}

// TestOrchestrator_Rework19_OuterPass_HandshakeBlocked_WithSessions_HasCanaryFalse_DoesNotBecomeActive verifies [BLOCKER 1]:
// When a canary prober exists but reports hasCanary=false (e.g. data plane device unattached or protocol unsupported),
// a handshake_blocked backend with established sessions MUST NOT be promoted to active.
func TestOrchestrator_Rework19_OuterPass_HandshakeBlocked_WithSessions_HasCanaryFalse_DoesNotBecomeActive(t *testing.T) {
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
		Status:            models.TunnelStatusHandshakeBlocked,
		Enabled:           true,
		ActiveConnections: 2,
		Protocol:          models.ProtocolAWG,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)
	updater.hasCanary = false // canary verification unavailable

	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 25 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status == models.TunnelStatusActive {
		t.Fatalf("[BLOCKER 1 REGRESSION] promoted to active when hasCanary=false!")
	}
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("expected status %s, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}
}

// TestOrchestrator_Rework19_OuterPass_HandshakeBlocked_WithSessions_CanarySuccess_RestoresActive verifies [DELIVERABLE 1 & 4]:
// A handshake_blocked backend with established sessions restores active status and normal admission
// when inner canary probe successfully passes.
func TestOrchestrator_Rework19_OuterPass_HandshakeBlocked_WithSessions_CanarySuccess_RestoresActive(t *testing.T) {
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
		Status:            models.TunnelStatusHandshakeBlocked,
		Enabled:           true,
		ActiveConnections: 3,
		Protocol:          models.ProtocolAWG,
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	updater := newMockCanaryUpdater(db, tun1)
	updater.hasCanary = true
	updater.canaryErr = nil // inner canary probe SUCCEEDS

	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 15 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(updater),
	)

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status != models.TunnelStatusActive {
		t.Fatalf("expected status %s after successful inner canary, got %s", models.TunnelStatusActive, res1.Status)
	}
	if count := orch.GetCanaryFailCount(t1); count != 0 {
		t.Fatalf("expected canaryFailCount to be reset to 0, got %d", count)
	}
}

// TestOrchestrator_Rework19_HandshakeBlocked_SustainedCanaryFailures_ReachesThreshold_Degrades verifies [DELIVERABLE 3]:
// Repeated confirmed canary failures on a handshake_blocked backend reaching threshold
// transitions the backend to degraded and triggers failover / session migration.
func TestOrchestrator_Rework19_HandshakeBlocked_SustainedCanaryFailures_ReachesThreshold_Degrades(t *testing.T) {
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
		Status:            models.TunnelStatusHandshakeBlocked,
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

	uID, _ := db.CreateUser(ctx, &models.User{Username: "carol", Role: models.RoleUser})
	sessID := "session-carol-1"
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              sessID,
		UserID:          uID,
		BackendTunnelID: t1,
		PeerPublicKey:   "peer-carol-pub",
		AssignedIP:      "10.100.1.40",
		Status:          "connected",
	})

	tun1, _ := db.GetBackendTunnel(ctx, t1)
	tun2, _ := db.GetBackendTunnel(ctx, t2)
	updater := newMockCanaryUpdater(db, tun1, tun2)
	updater.hasCanary = true
	updater.canaryErr = errors.New("sustained canary error")

	filterUpdater := &orchestratorCanaryFilterUpdater{
		mockCanaryUpdater: updater,
		canaryFn: func(tunnel *models.BackendTunnel) error {
			if tunnel.ID == t1 {
				return errors.New("sustained canary error")
			}
			return nil
		},
	}

	orch := New(db, nil,
		WithProbeFailureThreshold(3),
		WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
			return 20 * time.Millisecond, nil
		}),
		WithTunnelStatusUpdater(filterUpdater),
	)

	// Pass 1: failures = 1 < 3 -> stays handshake_blocked, session preserved
	_ = orch.CheckBackendTunnelHealth(ctx)
	res1, _ := db.GetBackendTunnel(ctx, t1)
	if res1.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("Pass 1: expected status %s, got %s", models.TunnelStatusHandshakeBlocked, res1.Status)
	}
	s, _ := db.GetVPNSessionByID(ctx, sessID)
	if s.BackendTunnelID != t1 {
		t.Fatalf("Pass 1: session migrated prematurely!")
	}

	// Pass 2: failures = 2 < 3 -> stays handshake_blocked, session preserved
	_ = orch.CheckBackendTunnelHealth(ctx)
	res2, _ := db.GetBackendTunnel(ctx, t1)
	if res2.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("Pass 2: expected status %s, got %s", models.TunnelStatusHandshakeBlocked, res2.Status)
	}

	// Pass 3: failures = 3 >= 3 -> degrades and migrates session
	_ = orch.CheckBackendTunnelHealth(ctx)
	res3, _ := db.GetBackendTunnel(ctx, t1)
	if res3.Status != models.TunnelStatusDegraded {
		t.Fatalf("Pass 3: expected status %s, got %s", models.TunnelStatusDegraded, res3.Status)
	}
	sMigrated, _ := db.GetVPNSessionByID(ctx, sessID)
	if sMigrated.BackendTunnelID != t2 {
		t.Fatalf("Pass 3: expected session to migrate to healthy tunnel %d, got %d", t2, sMigrated.BackendTunnelID)
	}
}
