package tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// TestProbeTunnel_DisabledTunnelNotResurrected verifies that ProbeTunnel never
// changes the status of an administratively disabled tunnel (issues #28/#43):
// a successful handshake probe must not write "active"/"degraded" over the
// admin-disabled state, and ProbeAll must skip disabled tunnels entirely.
func TestProbeTunnel_DisabledTunnelNotResurrected(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Disabled Host", Host: "192.0.2.10"})
	tun, err := pool.AddTunnel(ctx, s1ID, "192.0.2.10:51820", "pub-disabled")
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeCalls := 0
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probeCalls++
		return 15 * time.Millisecond, nil
	}

	cfg := DefaultHealthConfig()
	prober := NewHealthProber(pool, db, cfg, mockProbe)

	hookCalls := 0
	prober.SetOnActiveHook(func(ctx context.Context, t *models.BackendTunnel) error {
		hookCalls++
		return nil
	})

	// Administratively disable the tunnel (as DisableBackend does).
	if err := pool.SetTunnelStatus(ctx, s1ID, "disabled", 0); err != nil {
		t.Fatalf("SetTunnelStatus(disabled) failed: %v", err)
	}

	// A successful probe of a disabled tunnel must be rejected up front.
	lat, err := prober.ProbeTunnel(ctx, tun)
	if err == nil {
		t.Fatalf("expected ProbeTunnel to refuse probing a disabled tunnel, got lat=%d err=nil", lat)
	}
	if probeCalls != 0 {
		t.Errorf("expected probe function not to be called for disabled tunnel, got %d calls", probeCalls)
	}
	if hookCalls != 0 {
		t.Errorf("expected onActiveHook not to be called for disabled tunnel, got %d calls", hookCalls)
	}

	st, _ := pool.GetTunnel(s1ID)
	if st.Status != "disabled" {
		t.Errorf("disabled tunnel status was changed by probe: got %q, want %q", st.Status, "disabled")
	}

	// ProbeAll must skip the disabled tunnel entirely.
	results := prober.ProbeAll(ctx)
	if len(results) != 0 {
		t.Errorf("expected ProbeAll to skip disabled tunnel, got %d results", len(results))
	}
	if probeCalls != 0 {
		t.Errorf("expected probe function not to be called via ProbeAll for disabled tunnel, got %d calls", probeCalls)
	}
	st, _ = pool.GetTunnel(s1ID)
	if st.Status != "disabled" {
		t.Errorf("disabled tunnel status was changed by ProbeAll: got %q, want %q", st.Status, "disabled")
	}
}

// TestCheckAndReconnect_DoesNotResurrectDisabledTunnel verifies that the
// reconnect manager only considers "degraded"/"connecting" tunnels as
// candidates and never probes or reactivates an administratively disabled one.
func TestCheckAndReconnect_DoesNotResurrectDisabledTunnel(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	pool := NewPool(db)

	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "Disabled Reconnect Host", Host: "192.0.2.11"})
	if _, err := pool.AddTunnel(ctx, s1ID, "192.0.2.11:51820", "pub-reconnect"); err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	probeCalls := 0
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		probeCalls++
		return 15 * time.Millisecond, nil
	}

	hCfg := DefaultHealthConfig()
	prober := NewHealthProber(pool, db, hCfg, mockProbe)

	rCfg := ReconnectConfig{
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		Multiplier:     2.0,
		MaxRetries:     3,
		CheckInterval:  20 * time.Millisecond,
	}
	reconnectMgr := NewReconnectManager(pool, prober, rCfg)

	// Administratively disable the tunnel.
	if err := pool.SetTunnelStatus(ctx, s1ID, "disabled", 0); err != nil {
		t.Fatalf("SetTunnelStatus(disabled) failed: %v", err)
	}

	reconnected := reconnectMgr.CheckAndReconnect(ctx)
	if reconnected != 0 {
		t.Errorf("expected 0 reconnected for disabled tunnel, got %d", reconnected)
	}
	if probeCalls != 0 {
		t.Errorf("expected no probe attempts for disabled tunnel, got %d", probeCalls)
	}

	st, _ := pool.GetTunnel(s1ID)
	if st.Status != "disabled" {
		t.Errorf("reconnect manager resurrected disabled tunnel: got %q, want %q", st.Status, "disabled")
	}

	retries, _, _ := reconnectMgr.GetTunnelRetryState(s1ID)
	if retries != 0 {
		t.Errorf("expected no retry state to accumulate for disabled tunnel, got retries=%d", retries)
	}
}
