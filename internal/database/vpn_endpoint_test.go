package database

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestUpdateBackendTunnelEndpoint(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "ep-test-server", Host: "192.0.2.10"})
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-10",
		PublicKey:     "pubkey-10",
		PrivateKey:    "privkey-10",
		Endpoint:      "192.0.2.10:51820",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	tun, err := db.GetBackendTunnel(ctx, tID)
	if err != nil || tun == nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if tun.StateVersion != 1 {
		t.Errorf("expected initial state_version 1, got %d", tun.StateVersion)
	}

	newEndpoint := "198.51.100.5:51820"
	if err := db.UpdateBackendTunnelEndpoint(ctx, tID, newEndpoint); err != nil {
		t.Fatalf("UpdateBackendTunnelEndpoint failed: %v", err)
	}

	updated, err := db.GetBackendTunnel(ctx, tID)
	if err != nil || updated == nil {
		t.Fatalf("GetBackendTunnel after update failed: %v", err)
	}
	if updated.Endpoint != newEndpoint {
		t.Errorf("expected endpoint %q, got %q", newEndpoint, updated.Endpoint)
	}
	if updated.StateVersion != 2 {
		t.Errorf("expected state_version 2, got %d", updated.StateVersion)
	}

	// Canceled context returns error
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := db.UpdateBackendTunnelEndpoint(canceledCtx, tID, "198.51.100.6:51820"); err == nil {
		t.Fatal("expected error on canceled context, got nil")
	}
}
