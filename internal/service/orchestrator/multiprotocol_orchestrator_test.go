package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestOrchestrator_ProbeAllBackendTunnels_SkipsNonAWG(t *testing.T) {
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()

	s1, err := db.CreateServer(ctx, &models.Server{Name: "SrvAWG", Host: "10.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer(AWG) failed: %v", err)
	}
	s2, err := db.CreateServer(ctx, &models.Server{Name: "SrvVLESS", Host: "10.0.0.2", SSHPort: 22})
	if err != nil {
		t.Fatalf("CreateServer(VLESS) failed: %v", err)
	}

	// 1. AWG tunnel
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s1,
		InterfaceName: "awg0",
		PublicKey:     "pub-awg",
		Endpoint:      "10.0.0.1:51820",
		Protocol:      models.ProtocolAWG,
		Status:        "active",
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel(AWG) failed: %v", err)
	}

	// 2. VLESS tunnel
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      s2,
		InterfaceName: "vless0",
		Endpoint:      "10.0.0.2:443",
		Protocol:      models.ProtocolVLESS,
		Status:        "active",
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel(VLESS) failed: %v", err)
	}

	probedEndpoints := make([]string, 0)
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probedEndpoints = append(probedEndpoints, endpoint)
		return 10 * time.Millisecond, nil
	}))

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	if len(probedEndpoints) != 1 || probedEndpoints[0] != "10.0.0.1:51820" {
		t.Fatalf("expected only AWG endpoint to be probed, got: %v", probedEndpoints)
	}
}

func TestOrchestrator_RebalanceVPNSessions_SameFamilyIsolation(t *testing.T) {
	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)
	ctx := context.Background()

	if err := db.SaveVPNConfig(ctx, &models.VPNConfig{
		HealthThresholdMS:    300,
		MinRebalanceSessions: 8,
	}); err != nil {
		t.Fatalf("SaveVPNConfig failed: %v", err)
	}

	userID, err := db.CreateUser(ctx, &models.User{Username: "multi_user", Role: models.RoleUser})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Create 2 AWG servers + tunnels
	s1, _ := db.CreateServer(ctx, &models.Server{Name: "AWG1", Host: "10.0.0.1", SSHPort: 22})
	s2, _ := db.CreateServer(ctx, &models.Server{Name: "AWG2", Host: "10.0.0.2", SSHPort: 22})
	awg1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: s1, InterfaceName: "awg0", PublicKey: "p1", Endpoint: "10.0.0.1:51820", Protocol: "awg", Status: "active", Enabled: true,
	})
	awg2, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: s2, InterfaceName: "awg1", PublicKey: "p2", Endpoint: "10.0.0.2:51820", Protocol: "awg", Status: "active", Enabled: true,
	})

	// Create 2 VLESS servers + tunnels
	s3, _ := db.CreateServer(ctx, &models.Server{Name: "VLESS1", Host: "10.0.0.3", SSHPort: 22})
	s4, _ := db.CreateServer(ctx, &models.Server{Name: "VLESS2", Host: "10.0.0.4", SSHPort: 22})
	vless1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: s3, InterfaceName: "vless0", Endpoint: "10.0.0.3:443", Protocol: "vless", Status: "active", Enabled: true,
	})
	vless2, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: s4, InterfaceName: "vless1", Endpoint: "10.0.0.4:443", Protocol: "vless", Status: "active", Enabled: true,
	})

	// Seed 2 sessions on AWG1, 2 sessions on AWG2 (balanced)
	for i := 1; i <= 2; i++ {
		_ = db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              fmt.Sprintf("sess-awg1-%d", i),
			UserID:          userID,
			PeerPublicKey:   fmt.Sprintf("peer-awg1-%d", i),
			AssignedIP:      fmt.Sprintf("10.100.1.%d", i),
			BackendTunnelID: awg1,
			Status:          "connected",
		})
		_ = db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              fmt.Sprintf("sess-awg2-%d", i),
			UserID:          userID,
			PeerPublicKey:   fmt.Sprintf("peer-awg2-%d", i),
			AssignedIP:      fmt.Sprintf("10.100.2.%d", i),
			BackendTunnelID: awg2,
			Status:          "connected",
		})
	}

	// Seed 9 sessions on VLESS1 and 1 on VLESS2 (overloaded VLESS1: excess = 9 - 7 = 2 sessions)
	for i := 1; i <= 9; i++ {
		_ = db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              fmt.Sprintf("sess-vless1-%d", i),
			UserID:          userID,
			PeerPublicKey:   fmt.Sprintf("peer-vless1-%d", i),
			AssignedIP:      fmt.Sprintf("10.100.3.%d", i),
			BackendTunnelID: vless1,
			Status:          "connected",
		})
	}
	_ = db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sess-vless2-1",
		UserID:          userID,
		PeerPublicKey:   "peer-vless2-1",
		AssignedIP:      "10.100.4.1",
		BackendTunnelID: vless2,
		Status:          "connected",
	})

	migrator := &mockSessionMigrator{}
	orch := New(db, nil, WithSessionMigrator(migrator))

	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	migrations := migrator.getMigrations()
	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(migrations))
	}

	// All migrations must target vless2 (same family!), never awg1 or awg2
	for _, m := range migrations {
		if m.targetTunnelID != vless2 {
			t.Fatalf("migration target tunnel = %d, want VLESS2 tunnel %d", m.targetTunnelID, vless2)
		}
	}
}
