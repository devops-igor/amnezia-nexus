package vpn

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

type testCanaryDevice struct {
	canaryCalls int
}

func (d *testCanaryDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (d *testCanaryDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *testCanaryDevice) Close() error { return nil }
func (d *testCanaryDevice) IsClosed() bool { return false }
func (d *testCanaryDevice) CreatedAt() time.Time { return time.Now() }
func (d *testCanaryDevice) LastHandshakeTime() time.Time { return time.Now() }
func (d *testCanaryDevice) DroppedPackets() uint64 { return 0 }
func (d *testCanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	return nil
}

func TestVPNService_DeviceProvider_ProductionCanaryWiring(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	dev := &testCanaryDevice{}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}

	// Verify prober discovers the device via Service.GetDevice
	proberDev := svc.prober.GetDevice(tun.ID)
	if proberDev == nil {
		t.Fatal("expected prober.GetDevice to return the attached backend device via Service provider")
	}

	// Outer handshake probe always fails (simulating DPI handshake blocking)
	svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("DPI handshake drop")
	})

	// Direct canary probe must succeed through the live device
	if err := svc.prober.ProbeCanary(ctx, tun); err != nil {
		t.Fatalf("expected ProbeCanary to succeed, got %v", err)
	}
	if dev.canaryCalls == 0 {
		t.Fatal("expected canary probe to reach attached device")
	}

	// Run outer probes up to FailureThreshold
	for i := 0; i < svc.prober.Config().FailureThreshold; i++ {
		_, _ = svc.prober.ProbeTunnel(ctx, tun)
	}

	got, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected pool status %s, got %s", models.TunnelStatusHandshakeBlocked, got.Status)
	}
	if persisted.Status != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected DB status %s, got %s", models.TunnelStatusHandshakeBlocked, persisted.Status)
	}
}

func TestVPNService_DeviceProvider_GetDeviceByServerID(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	dev := &testCanaryDevice{}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}

	// Look up by server ID should find the device via pool fallback
	foundDev, ok := svc.GetDevice(s1)
	if !ok || foundDev == nil {
		t.Fatalf("expected GetDevice(%d) by server ID to succeed, got ok=%v dev=%v", s1, ok, foundDev)
	}

	// Non-existent server/tunnel ID
	missingDev, ok := svc.GetDevice(999999)
	if ok || missingDev != nil {
		t.Fatalf("expected missing device for unknown ID, got ok=%v dev=%v", ok, missingDev)
	}
}
