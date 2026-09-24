package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/endpoint"
)

func TestServerMainGracefulShutdown(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("DATA_DIR", tempDir)
	t.Setenv("DB_PATH", filepath.Join(tempDir, "server_test.db"))
	t.Setenv("PORT", "59133")
	t.Setenv("SECRET_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("run() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for server to shutdown")
	}
}

func TestStartVPNDataPlane_VPNEnabledFalse(t *testing.T) {
	tempDir := t.TempDir()
	db, err := database.New(filepath.Join(tempDir, "test.db"), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("database.New failed: %v", err)
	}
	defer db.Close()

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfg := &config.Config{
		VPNEnabled: false,
	}

	ctx := context.Background()
	vpnStarted, poolSynced, err := startVPNDataPlane(ctx, vpnSvc, cfg)
	if err != nil {
		t.Fatalf("startVPNDataPlane failed: %v", err)
	}
	if vpnStarted {
		t.Errorf("expected vpnStarted=false, got true")
	}
	if poolSynced {
		t.Errorf("expected poolSynced=false, got true")
	}
}

func TestStartVPNDataPlane_TunUnavailable_PoolSynced(t *testing.T) {
	tempDir := t.TempDir()
	db, err := database.New(filepath.Join(tempDir, "test.db"), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("database.New failed: %v", err)
	}
	defer db.Close()

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	vpnSvc.SetTunOpener(func() (endpoint.PacketDevice, error) {
		return nil, endpoint.ErrTunUnavailable
	})

	cfg := &config.Config{
		VPNEnabled: true,
	}

	ctx := context.Background()
	vpnStarted, poolSynced, err := startVPNDataPlane(ctx, vpnSvc, cfg)
	if err != nil {
		t.Fatalf("startVPNDataPlane failed: %v", err)
	}
	if vpnStarted {
		t.Errorf("expected vpnStarted=false, got true")
	}
	if !poolSynced {
		t.Errorf("expected poolSynced=true, got false")
	}
}
