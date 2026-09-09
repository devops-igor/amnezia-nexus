package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// Regression test for issue-backend-awg-param-key-mismatch (secondary bug):
// CheckBackendTunnelHealth used to probe every tunnel with hardcoded default
// obfuscation params, so a custom-obfuscation backend could never complete a
// handshake probe and was marked degraded every orchestrator cycle. It must
// now resolve each tunnel's params from the server's stored awg_params.
func TestOrchestrator_CheckBackendTunnelHealth_UsesStoredSnakeCaseParams(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 300})

	// Custom-obfuscation backend: exact live DEV snake_case values from the task report.
	srvID, err := db.CreateServer(ctx, &models.Server{
		Name: "VPN #2 custom obfuscation",
		Host: "10.0.0.6",
		Protocols: map[string]any{
			"awg": map[string]any{
				"awg_params": map[string]any{
					"junk_packet_count":             6,
					"junk_packet_min_size":          10,
					"junk_packet_max_size":          50,
					"init_packet_junk_size":         12,
					"response_packet_junk_size":     12,
					"cookie_reply_packet_junk_size": 12,
					"transport_packet_junk_size":    12,
					"init_packet_magic_header":      1,
					"response_packet_magic_header":  2,
					"underload_packet_magic_header": 3,
					"transport_packet_magic_header": 4,
					"header_protection_key":         "BSX9FAKEHPKEY",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	tunID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:  srvID,
		PublicKey: "pub-custom",
		Endpoint:  "127.0.0.1:55430",
		Status:    "active",
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	var mu sync.Mutex
	var gotHPKey string
	var gotH1, gotH2 uint32
	var gotS1, gotS2 int

	probeCalled := make(chan struct{}, 1)
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		mu.Lock()
		gotHPKey, gotH1, gotH2, gotS1, gotS2 = hpKey, h1, h2, s1, s2
		mu.Unlock()
		select {
		case probeCalled <- struct{}{}:
		default:
		}
		return 25 * time.Millisecond, nil
	}))

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}

	select {
	case <-probeCalled:
	default:
		t.Fatal("probe function was never called")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotH1 != 1 || gotH2 != 2 {
		t.Errorf("expected probe h1/h2 = 1/2 from stored awg_params, got %d/%d", gotH1, gotH2)
	}
	if gotS1 != 12 || gotS2 != 12 {
		t.Errorf("expected probe s1/s2 = 12/12 from stored awg_params, got %d/%d", gotS1, gotS2)
	}
	if gotHPKey != "BSX9FAKEHPKEY" {
		t.Errorf("expected probe hpKey %q from stored awg_params, got %q", "BSX9FAKEHPKEY", gotHPKey)
	}

	tun, err := db.GetBackendTunnel(ctx, tunID)
	if err != nil {
		t.Fatalf("GetBackendTunnel failed: %v", err)
	}
	if tun.Status != "active" {
		t.Errorf("expected custom-obfuscation tunnel to stay active after successful probe, got %s", tun.Status)
	}
	if tun.LatencyMS != 25 {
		t.Errorf("expected latency 25, got %d", tun.LatencyMS)
	}
}

// A backend without explicit awg_params must still probe with defaults.
func TestOrchestrator_CheckBackendTunnelHealth_DefaultParamsWhenNoAwgParams(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	_ = db.SaveVPNConfig(ctx, &models.VPNConfig{HealthThresholdMS: 300})

	srvID, err := db.CreateServer(ctx, &models.Server{Name: "plain backend", Host: "10.0.0.7"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:  srvID,
		PublicKey: "pub-plain",
		Endpoint:  "127.0.0.1:55431",
		Status:    "active",
	}); err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	var mu sync.Mutex
	var gotH1, gotH2 uint32
	var gotS1, gotS2 int
	probeCalled := make(chan struct{}, 1)
	orch := New(db, nil, WithProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 uint32, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		mu.Lock()
		gotH1, gotH2, gotS1, gotS2 = h1, h2, s1, s2
		mu.Unlock()
		select {
		case probeCalled <- struct{}{}:
		default:
		}
		return 10 * time.Millisecond, nil
	}))

	if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
		t.Fatalf("CheckBackendTunnelHealth failed: %v", err)
	}
	select {
	case <-probeCalled:
	default:
		t.Fatal("probe function was never called")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotH1 != health.DefaultH1 || gotH2 != health.DefaultH2 {
		t.Errorf("expected default h1/h2 %d/%d, got %d/%d", health.DefaultH1, health.DefaultH2, gotH1, gotH2)
	}
	if gotS1 != health.DefaultS1 || gotS2 != health.DefaultS2 {
		t.Errorf("expected default s1/s2 %d/%d, got %d/%d", health.DefaultS1, health.DefaultS2, gotS1, gotS2)
	}
}
