package tunnel

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestPool_AddTunnelWithConfig_ProxySkipsKeyGen(t *testing.T) {
	pool := NewPool(nil)
	pool.SetMultiProtocolEnabled(true)

	// Hook to detect keypair generation - should NOT be called for proxies
	keyGenCalled := false
	pool.generateKeypairFn = func() (string, string, error) {
		keyGenCalled = true
		return "fake-pub", "fake-priv", nil
	}

	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{
		UUID: "00000000-0000-0000-0000-000000000001",
	})

	ctx := context.Background()
	tun, err := pool.AddTunnelWithConfig(ctx, 100, "1.2.3.4:443", "", BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessRaw,
	})
	if err != nil {
		t.Fatalf("AddTunnelWithConfig failed: %v", err)
	}

	if keyGenCalled {
		t.Fatal("expected no Curve25519 key generation for VLESS proxy tunnel")
	}

	if tun.PublicKey != "" || tun.PrivateKey != "" || tun.ProbePrivateKey != "" {
		t.Fatalf("expected empty AWG keys for VLESS tunnel, got pub=%q priv=%q probe=%q",
			tun.PublicKey, tun.PrivateKey, tun.ProbePrivateKey)
	}

	if tun.Status != models.TunnelStatusConnecting {
		t.Fatalf("expected proxy tunnel to start in connecting status, got: %s", tun.Status)
	}

	if tun.Protocol != models.ProtocolVLESS {
		t.Fatalf("expected protocol %s, got: %s", models.ProtocolVLESS, tun.Protocol)
	}

	if tun.InterfaceName != "vless-be-100" {
		t.Fatalf("expected interface name vless-be-100, got: %s", tun.InterfaceName)
	}
}

func TestPool_AddTunnelWithConfig_FeatureFlagGuard(t *testing.T) {
	pool := NewPool(nil)
	// MultiProtocolEnabled is false by default

	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{
		UUID: "00000000-0000-0000-0000-000000000001",
	})

	ctx := context.Background()
	_, err := pool.AddTunnelWithConfig(ctx, 101, "1.2.3.4:443", "", BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessRaw,
	})
	if err == nil {
		t.Fatal("expected error adding proxy tunnel when multiProtocolEnabled is false")
	}

	// AWG tunnel succeeds even when multi-protocol is false
	awgTun, err := pool.AddTunnel(ctx, 102, "1.2.3.4:51820", "server-pub-key")
	if err != nil || awgTun == nil {
		t.Fatalf("expected AWG tunnel to succeed, got: %v", err)
	}
}

func TestPool_AddTunnelWithConfig_RejectInPlaceProtocolChange(t *testing.T) {
	pool := NewPool(nil)
	pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	// 1. Create AWG tunnel
	_, err := pool.AddTunnel(ctx, 200, "1.2.3.4:51820", "pubkey1")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// 2. Attempt to update server 200 to VLESS in-place
	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{
		UUID: "00000000-0000-0000-0000-000000000001",
	})
	_, err = pool.AddTunnelWithConfig(ctx, 200, "1.2.3.4:443", "", BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessRaw,
	})
	if err == nil {
		t.Fatal("expected in-place protocol family change from AWG to VLESS to be rejected")
	}
}

func TestPool_GetActiveTunnels_FeatureFlag(t *testing.T) {
	pool := NewPool(nil)
	pool.SetMultiProtocolEnabled(true)
	ctx := context.Background()

	// Add active AWG tunnel
	awgTun, err := pool.AddTunnel(ctx, 301, "1.2.3.4:51820", "pub")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	// Add active VLESS tunnel
	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{
		UUID: "uuid",
	})
	vlessTun, err := pool.AddTunnelWithConfig(ctx, 302, "1.2.3.4:443", "", BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessRaw,
	})
	if err != nil {
		t.Fatalf("AddTunnelWithConfig failed: %v", err)
	}
	// Manually transition VLESS to active
	_ = pool.SetTunnelStatus(ctx, 302, models.TunnelStatusActive, 25)

	// When multi-protocol is enabled, both appear in active tunnels
	active := pool.GetActiveTunnels()
	if len(active) != 2 {
		t.Fatalf("expected 2 active tunnels, got %d", len(active))
	}

	// When multi-protocol is toggled off, proxy is excluded from active tunnels
	pool.SetMultiProtocolEnabled(false)
	active = pool.GetActiveTunnels()
	if len(active) != 1 || active[0].ID != awgTun.ID {
		t.Fatalf("expected only AWG tunnel active, got %d tunnels: %+v", len(active), active)
	}

	_ = vlessTun
}
