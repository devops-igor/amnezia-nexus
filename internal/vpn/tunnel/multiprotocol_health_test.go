package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestJitterDuration(t *testing.T) {
	base := 10 * time.Second

	// Sample 0.0 -> factor 0.8 -> 8s
	d0 := jitterDuration(base, 0.0)
	if d0 != 8*time.Second {
		t.Fatalf("expected 8s, got %v", d0)
	}

	// Sample 0.5 -> factor 1.0 -> 10s
	dHalf := jitterDuration(base, 0.5)
	if dHalf != 10*time.Second {
		t.Fatalf("expected 10s, got %v", dHalf)
	}

	// Sample 0.999999 -> factor ~1.2 -> ~12s
	dMax := jitterDuration(base, 0.999999)
	if math.Abs(float64(dMax-12*time.Second)) > float64(time.Millisecond) {
		t.Fatalf("expected ~12s, got %v", dMax)
	}

	// Edge case: base <= 0
	if d := jitterDuration(0, 0.5); d != 0 {
		t.Fatalf("expected 0, got %v", d)
	}
	if d := jitterDuration(-5*time.Second, 0.5); d != -5*time.Second {
		t.Fatalf("expected -5s, got %v", d)
	}
}

func TestHealthProber_NextProbeInterval_Bounds(t *testing.T) {
	hp := NewHealthProber(nil, nil, HealthConfig{
		Interval: 10 * time.Second,
	})

	for i := 0; i < 50; i++ {
		interval := hp.nextProbeInterval()
		if interval < 8*time.Second || interval > 12*time.Second {
			t.Fatalf("jittered interval %v out of [8s, 12s] bounds", interval)
		}
	}
}

func TestHealthProber_Dispatch(t *testing.T) {
	hp := NewHealthProber(nil, nil, DefaultHealthConfig())

	vlessCalled := false
	var vlessTarget string
	var vlessParam models.VLESSRealityParams
	hp.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, p models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		vlessCalled = true
		vlessTarget = endpoint
		vlessParam = p
		return 42, nil
	})

	naiveCalled := false
	var naiveTarget string
	var naiveParam models.NaiveProxyParams
	hp.SetNaiveProbeFunc(func(ctx context.Context, endpoint string, p models.NaiveProxyParams, timeout time.Duration) (int64, error) {
		naiveCalled = true
		naiveTarget = endpoint
		naiveParam = p
		return 84, nil
	})

	awgCalled := false
	hp.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		awgCalled = true
		return 15 * time.Millisecond, nil
	})

	ctx := context.Background()

	// 1. Unknown protocol
	unknownTun := &models.BackendTunnel{
		ID:       1,
		ServerID: 10,
		Protocol: "unknown_proto",
		Endpoint: "1.2.3.4:443",
	}
	_, err := hp.probeEndpoint(ctx, unknownTun)
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}

	// 2. AWG dispatch (explicit)
	awgTun := &models.BackendTunnel{
		ID:        2,
		ServerID:  20,
		Protocol:  "awg",
		Endpoint:  "1.2.3.4:51820",
		PublicKey: "pub",
	}
	rtt, err := hp.probeEndpoint(ctx, awgTun)
	if err != nil || !awgCalled || rtt != 15 {
		t.Fatalf("expected AWG probe success, got rtt=%d err=%v awgCalled=%v", rtt, err, awgCalled)
	}

	// 3. AWG dispatch (empty/alias normalized)
	awgCalled = false
	legacyTun := &models.BackendTunnel{
		ID:        3,
		ServerID:  30,
		Protocol:  "awg2",
		Endpoint:  "1.2.3.4:51820",
		PublicKey: "pub",
	}
	rtt, err = hp.probeEndpoint(ctx, legacyTun)
	if err != nil || !awgCalled || rtt != 15 {
		t.Fatalf("expected legacy AWG probe success, got rtt=%d err=%v awgCalled=%v", rtt, err, awgCalled)
	}

	// 4. VLESS dispatch
	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{
		UUID:       "00000000-0000-0000-0000-000000000001",
		PublicKey:  "vless_pub",
		ServerName: "example.com",
	})
	vlessTun := &models.BackendTunnel{
		ID:             4,
		ServerID:       40,
		Protocol:       models.ProtocolVLESS,
		Endpoint:       "9.9.9.9:443",
		ProtocolParams: vlessRaw,
	}
	rtt, err = hp.probeEndpoint(ctx, vlessTun)
	if err != nil || !vlessCalled || rtt != 42 {
		t.Fatalf("expected VLESS probe success, got rtt=%d err=%v vlessCalled=%v", rtt, err, vlessCalled)
	}
	if vlessTarget != "9.9.9.9:443" || vlessParam.ServerName != "example.com" {
		t.Fatalf("mismatched VLESS target/param: target=%s param=%+v", vlessTarget, vlessParam)
	}

	// 5. Naive dispatch
	naiveRaw, _ := json.Marshal(models.NaiveProxyParams{
		Username: "user",
		Password: "password",
		Domain:   "camouflage.com",
		EnableH3: true,
	})
	naiveTun := &models.BackendTunnel{
		ID:             5,
		ServerID:       50,
		Protocol:       models.ProtocolNaive,
		Endpoint:       "8.8.8.8:443",
		ProtocolParams: naiveRaw,
	}
	rtt, err = hp.probeEndpoint(ctx, naiveTun)
	if err != nil || !naiveCalled || rtt != 84 {
		t.Fatalf("expected Naive probe success, got rtt=%d err=%v naiveCalled=%v", rtt, err, naiveCalled)
	}
	if naiveTarget != "8.8.8.8:443" || naiveParam.Domain != "camouflage.com" {
		t.Fatalf("mismatched Naive target/param: target=%s param=%+v", naiveTarget, naiveParam)
	}

	// 6. Malformed JSON returns error
	badJSONTun := &models.BackendTunnel{
		ID:             6,
		ServerID:       60,
		Protocol:       models.ProtocolVLESS,
		Endpoint:       "9.9.9.9:443",
		ProtocolParams: []byte("{invalid-json"),
	}
	_, err = hp.probeEndpoint(ctx, badJSONTun)
	if err == nil {
		t.Fatal("expected error on malformed JSON params")
	}

	// 7. Probe error propagation
	hp.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, p models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		return 0, errors.New("connection refused")
	})
	_, err = hp.probeEndpoint(ctx, vlessTun)
	if err == nil || err.Error() != "connection refused" {
		t.Fatalf("expected connection refused error, got: %v", err)
	}
}

func TestHealthProber_MultiProtocolEnabled_Toggle(t *testing.T) {
	pool := NewPool(nil)
	pool.SetMultiProtocolEnabled(true)
	hp := NewHealthProber(pool, nil, DefaultHealthConfig())

	vlessRaw, _ := json.Marshal(models.VLESSRealityParams{
		UUID: "test-uuid",
	})
	tun, err := pool.AddTunnelWithConfig(context.Background(), 1, "1.1.1.1:443", "", BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: vlessRaw,
	})
	if err != nil || tun == nil {
		t.Fatalf("failed to add vless tunnel to pool: %v", err)
	}

	vlessCalled := false
	hp.SetVLESSProbeFunc(func(ctx context.Context, endpoint string, p models.VLESSRealityParams, timeout time.Duration) (int64, error) {
		vlessCalled = true
		return 20, nil
	})

	// With multiProtocolEnabled = false (default), ProbeAll skips proxy tunnel
	res := hp.ProbeAll(context.Background())
	if vlessCalled {
		t.Fatal("expected VLESS probe to be skipped when multiProtocolEnabled is false")
	}
	if _, ok := res[1]; ok {
		t.Fatal("server 1 should not have probe results when multi-protocol is disabled")
	}

	// Enable multi-protocol
	hp.SetMultiProtocolEnabled(true)
	if !hp.MultiProtocolEnabled() {
		t.Fatal("expected MultiProtocolEnabled to return true")
	}

	res = hp.ProbeAll(context.Background())
	if !vlessCalled {
		t.Fatal("expected VLESS probe to run when multiProtocolEnabled is true")
	}
	if err, ok := res[1]; !ok || err != nil {
		t.Fatalf("expected server 1 to be probed successfully, got ok=%v err=%v", ok, err)
	}
}
