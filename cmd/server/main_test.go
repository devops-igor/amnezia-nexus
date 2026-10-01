package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/config"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
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

func TestStartVPNDataPlane_VPNEnabledTrue_Success(t *testing.T) {
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

	ctx := context.Background()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen ephemeral udp: %v", err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	_ = socket.Close()

	vpnCfg, err := vpnSvc.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	vpnCfg.ListenPort = port
	if err := vpnSvc.UpdateConfig(ctx, vpnCfg); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	cfg := &config.Config{
		VPNEnabled: true,
	}

	vpnStarted, poolSynced, err := startVPNDataPlane(ctx, vpnSvc, cfg)
	if err != nil {
		t.Fatalf("startVPNDataPlane failed: %v", err)
	}
	defer func() { _ = vpnSvc.Stop() }()

	if !vpnStarted {
		t.Errorf("expected vpnStarted=true, got false")
	}
	if !poolSynced {
		t.Errorf("expected poolSynced=true, got false")
	}
	if !vpnSvc.IsRunning() {
		t.Errorf("expected vpnSvc.IsRunning()=true")
	}
}
