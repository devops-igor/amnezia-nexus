package vpn

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type testCanaryDevice struct {
	canaryCalls int
}

func (d *testCanaryDevice) Read([]byte) (int, error)     { return 0, io.EOF }
func (d *testCanaryDevice) Write(p []byte) (int, error)  { return len(p), nil }
func (d *testCanaryDevice) Close() error                 { return nil }
func (d *testCanaryDevice) IsClosed() bool               { return false }
func (d *testCanaryDevice) CreatedAt() time.Time         { return time.Now() }
func (d *testCanaryDevice) LastHandshakeTime() time.Time { return time.Now() }
func (d *testCanaryDevice) DroppedPackets() uint64       { return 0 }
func (d *testCanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	return nil
}

func TestVPNService_DeviceProvider_GetDevice(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	dev := &testCanaryDevice{}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}

	foundDev, ok := svc.GetDevice(tun.ID)
	if !ok || foundDev == nil {
		t.Fatalf("expected GetDevice(%d) to succeed, got ok=%v dev=%v", tun.ID, ok, foundDev)
	}

	foundByServer, ok := svc.GetDevice(s1)
	if !ok || foundByServer == nil {
		t.Fatalf("expected GetDevice(%d) by server ID to succeed, got ok=%v dev=%v", s1, ok, foundByServer)
	}

	missingDev, ok := svc.GetDevice(999999)
	if ok || missingDev != nil {
		t.Fatalf("expected missing device for unknown ID, got ok=%v dev=%v", ok, missingDev)
	}
}

func TestVPNService_ProbeCanary(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	dev := &testCanaryDevice{}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}
	svc.SetCanaryProbeFunc(nil)

	if err := svc.ProbeCanary(ctx, tun); err != nil {
		t.Fatalf("ProbeCanary failed: %v", err)
	}
	if dev.canaryCalls == 0 {
		t.Fatal("expected canary probe to reach attached device")
	}

	// Test custom override
	customCalled := false
	svc.SetCanaryProbeFunc(func(ctx context.Context, t *models.BackendTunnel) error {
		customCalled = true
		return errors.New("custom failure")
	})
	if err := svc.ProbeCanary(ctx, tun); err == nil || !strings.Contains(err.Error(), "custom failure") {
		t.Fatalf("expected custom failure, got %v", err)
	}
	if !customCalled {
		t.Fatal("expected custom canary probe function to be invoked")
	}
}

func TestVPNService_SubnetCIDR(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if got := svc.SubnetCIDR(); got != "10.100.0.0/16" {
		t.Fatalf("expected default 10.100.0.0/16, got %s", got)
	}
	svc.cfg.SubnetCIDR = "10.200.0.0/16"
	if got := svc.SubnetCIDR(); got != "10.200.0.0/16" {
		t.Fatalf("expected custom 10.200.0.0/16, got %s", got)
	}
}

func TestVPNService_PromoteQualifiedTunnel(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	svc.SetPendingEnrollment(s1, true)
	if !svc.prober.IsPendingEnrollment(s1) {
		t.Fatal("expected pending enrollment to be set on prober")
	}

	// Put tunnel in connecting status
	if err := svc.pool.SetTunnelStatus(ctx, s1, models.TunnelStatusConnecting, 0); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil || tun.Status != models.TunnelStatusConnecting {
		t.Fatalf("expected connecting status, got %v", tun)
	}

	// Promote with normal latency (< threshold 500ms)
	if err := svc.PromoteQualifiedTunnel(ctx, s1, 45); err != nil {
		t.Fatalf("PromoteQualifiedTunnel failed: %v", err)
	}
	tunAfter, err := svc.pool.GetTunnel(s1)
	if err != nil || tunAfter.Status != models.TunnelStatusActive || tunAfter.LatencyMS != 45 {
		t.Fatalf("expected active status with 45ms latency, got %+v", tunAfter)
	}

	// Reset to connecting and promote with high latency (> threshold)
	if err := svc.pool.SetTunnelStatus(ctx, s1, models.TunnelStatusConnecting, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, s1, 650); err != nil {
		t.Fatalf("PromoteQualifiedTunnel high latency failed: %v", err)
	}
	tunDegraded, err := svc.pool.GetTunnel(s1)
	if err != nil || tunDegraded.Status != models.TunnelStatusDegraded || tunDegraded.LatencyMS != 650 {
		t.Fatalf("expected degraded status with 650ms latency, got %+v", tunDegraded)
	}

	// Cannot promote disabled tunnel
	if err := svc.pool.SetTunnelStatus(ctx, s1, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableBackend(ctx, s1); err != nil {
		t.Fatal(err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, s1, 10); err == nil {
		t.Fatal("expected error promoting disabled tunnel")
	}
}
