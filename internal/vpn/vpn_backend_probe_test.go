package vpn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestProbeFunc_MatchByTunID(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "TunID Match Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-tun-id", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	recent := time.Now().Add(-10 * time.Second)
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return recent },
	}

	// Set device with matching tun.ID. Issue #43: the fake-success fast path
	// was REMOVED — ProbeTunnel now ALWAYS runs the real Noise IK probe with
	// the dedicated probe key, regardless of device handshake freshness.
	rtt, err := svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatalf("expected real-probe error against unlistening endpoint (fast path removed), got nil rtt=%d", rtt)
	}

	// Remove matching device by setting with wrong ID; prober falls through to
	// ProbeAWGEndpoint identically (still unlistening endpoint).
	svc.mu.Lock()
	if svc.backendDevices == nil {
		svc.backendDevices = make(map[int64]BackendDevice)
	}
	delete(svc.backendDevices, tun.ID)
	svc.backendDevices[99999] = dev
	svc.mu.Unlock()

	_, err = svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Error("expected ProbeTunnel to fail when device key does not match tun.ID, got nil")
	}
}

func TestProbeFunc_ZeroHandshake_Within90sGrace_SendsTrigger(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Grace Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-grace", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	inCh := make(chan []byte, 10)
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Time{} },
		createdAt:       time.Now().Add(-30 * time.Second),
		inPacketsCh:     inCh,
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Issue #43: fake-success fast path removed. ProbeTunnel now always runs
	// the real Noise IK probe with the dedicated probe key — no dummy trigger
	// packet, no synthetic 10ms RTT. Against an unlistening endpoint it fails.
	if _, err := svc.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint, got nil")
	}
}

func TestProbeFunc_ZeroHandshake_Past90sGrace_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Grace Timeout Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-grace-timeout", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	// Zero handshake, created 95s ago (>= 90s cutoff)
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Time{} },
		createdAt:       time.Now().Add(-95 * time.Second),
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	// Issue #43: real Noise IK probe always runs; against an unlistening
	// endpoint it fails with the probe transport error (device-based timeout
	// messages no longer apply).
	_, err = svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "failed to receive handshake response") {
		t.Errorf("expected handshake response transport error, got: %v", err)
	}
}

func TestProbeFunc_StaleHandshake_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Stale Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-stale", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	// Handshake 4 minutes ago (>= 3m cutoff). Issue #43: real Noise IK probe
	// always runs; the device-handshake-age fast paths are gone.
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Now().Add(-4 * time.Minute) },
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	_, err = svc.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "failed to receive handshake response") {
		t.Errorf("expected handshake response transport error, got: %v", err)
	}
}

func TestProbeFunc_RecentHandshake_ReturnsSuccess(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "Recent Srv", "127.0.0.1")

	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	realDev, err := tunnel.NewAWGClientDevice("test-recent", tun.Endpoint, priv, pub, 1340, nil)
	if err != nil {
		t.Fatalf("NewAWGClientDevice failed: %v", err)
	}
	defer realDev.Close()

	// Handshake 45s ago (< 3m cutoff). Issue #43: the fake-success fast path
	// was removed — freshness of the data device's handshake no longer
	// fabricates a probe result; the real Noise IK probe with the dedicated
	// probe key always runs. Against an unlistening endpoint it must fail.
	dev := &testBackendDevice{
		AWGClientDevice: realDev,
		lastHandshakeFn: func() time.Time { return time.Now().Add(-45 * time.Second) },
	}
	svc.SetBackendDeviceForTest(tun.ID, dev)

	if _, err := svc.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected real-probe error against unlistening endpoint (fresh device handshake must NOT short-circuit), got nil")
	}
}

func TestHealthProber_DegradedTunnel_FailsActivationWithoutDevice(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	sID, pub, priv := createTestServerAndKey(t, db, "NoDev Srv", "198.51.100.88")

	tun := &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: fmt.Sprintf("awg-be-%d", sID),
		PublicKey:     pub,
		PrivateKey:    priv,
		Endpoint:      "198.51.100.88:999999", // invalid port so attach fails
		Status:        TunnelStatusDegraded,
		CreatedAt:     time.Now().UTC(),
	}
	tunID, err := db.CreateBackendTunnel(ctx, tun)
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}
	tun.ID = tunID

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	// Stub probeFunc to return success
	svc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})

	// Add tunnel to pool
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	// Device is nil
	if dev := svc.GetBackendDeviceForTest(tunID); dev != nil {
		t.Fatalf("expected nil device, got %+v", dev)
	}

	// Probe the tunnel
	_, _ = svc.ProbeTunnel(ctx, tun)

	// Status must REMAIN degraded because data plane could not be attached
	tunAfter, err := svc.pool.GetTunnel(sID)
	if err != nil {
		t.Fatalf("GetTunnel failed: %v", err)
	}
	if tunAfter.Status != TunnelStatusDegraded {
		t.Errorf("expected tunnel without data plane device to stay degraded, but got %s", tunAfter.Status)
	}
}
