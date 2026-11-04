package vpn

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

type mockPBRDevice struct {
	mu     sync.Mutex
	closed bool
}

func (m *mockPBRDevice) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (m *mockPBRDevice) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockPBRDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

type mockRouteCache struct{}

func (c *mockRouteCache) Lookup(sessionID string, dst netip.Addr) policy.Decision {
	return policy.Unknown
}

func TestService_PBRDefaultDisabled(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	if svc.PBREnabled() {
		t.Fatal("expected PBR to be disabled by default")
	}
	if svc.DirectEgress() != nil {
		t.Fatal("expected DirectEgress to be nil when PBR is disabled")
	}
}

func TestService_PBRPrerequisitesValidation(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	validWAN := netip.MustParseAddr("198.51.200.1")
	dev := &mockPBRDevice{}
	rc := &mockRouteCache{}
	matcher := policy.NewMatcher()
	snap, _ := policy.CompileSnapshot(1, "gen-1", nil)
	matcher.Publish(snap)

	tests := []struct {
		name        string
		cfg         PBRConfig
		wantErr     error
		expectedMsg string
	}{
		{
			name: "unspecified 0.0.0.0 host WAN IP",
			cfg: PBRConfig{
				Enabled:       true,
				HostWANIP:     netip.MustParseAddr("0.0.0.0"),
				WANDevice:     dev,
				RouteCache:    rc,
				PolicyMatcher: matcher,
			},
			wantErr: ErrPBRMissingHostWAN,
		},
		{
			name: "loopback host WAN IP",
			cfg: PBRConfig{
				Enabled:       true,
				HostWANIP:     netip.MustParseAddr("127.0.0.1"),
				WANDevice:     dev,
				RouteCache:    rc,
				PolicyMatcher: matcher,
			},
			wantErr: ErrPBRMissingHostWAN,
		},
		{
			name: "missing WAN packet device",
			cfg: PBRConfig{
				Enabled:       true,
				HostWANIP:     validWAN,
				WANDevice:     nil,
				RouteCache:    rc,
				PolicyMatcher: matcher,
			},
			wantErr: ErrPBRMissingWANDevice,
		},
		{
			name: "missing route cache",
			cfg: PBRConfig{
				Enabled:       true,
				HostWANIP:     validWAN,
				WANDevice:     dev,
				RouteCache:    nil,
				PolicyMatcher: matcher,
			},
			wantErr: ErrPBRMissingRouteCache,
		},
		{
			name: "missing policy matcher",
			cfg: PBRConfig{
				Enabled:       true,
				HostWANIP:     validWAN,
				WANDevice:     dev,
				RouteCache:    rc,
				PolicyMatcher: nil,
			},
			wantErr: ErrPBRMissingPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := svc.ConfigurePBR(tt.cfg)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tt.name)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error wrapping %v, got: %v", tt.wantErr, err)
			}
			// Verify service remains disabled (fail closed)
			if svc.PBREnabled() {
				t.Fatalf("service must remain disabled when prerequisite validation fails")
			}
		})
	}
}

func TestService_PBREnableAndTeardown(t *testing.T) {
	svc, err := NewVPNService(nil, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	validWAN := netip.MustParseAddr("198.51.200.1")
	dev := &mockPBRDevice{}
	rc := &mockRouteCache{}
	matcher := policy.NewMatcher()
	snap, _ := policy.CompileSnapshot(1, "gen-1", nil)
	matcher.Publish(snap)

	cfg := PBRConfig{
		Enabled:       true,
		HostWANIP:     validWAN,
		GatewayDNSIP:  netip.MustParseAddr("10.100.0.1"),
		WANDevice:     dev,
		RouteCache:    rc,
		PolicyMatcher: matcher,
	}

	if err := svc.ConfigurePBR(cfg); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}

	if !svc.PBREnabled() {
		t.Fatal("expected PBR to be enabled")
	}
	if svc.DirectEgress() == nil {
		t.Fatal("expected DirectEgress to be non-nil")
	}

	// Teardown PBR
	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}

	if svc.PBREnabled() {
		t.Fatal("expected PBR to be disabled after teardown")
	}
	if svc.DirectEgress() != nil {
		t.Fatal("expected DirectEgress to be nil after teardown")
	}
}

func TestService_DeriveHostWANIPNoFallback(t *testing.T) {
	ip, _ := DeriveHostWANIP()
	forbiddenTestIP := netip.MustParseAddr("203.0.113.1")
	if ip == forbiddenTestIP {
		t.Fatalf("DeriveHostWANIP returned forbidden test address 203.0.113.1")
	}
}

func TestService_StartWithPBREnabled(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})

	validWAN := netip.MustParseAddr("198.51.200.1")
	dev := &mockPBRDevice{}
	rc := &mockRouteCache{}
	matcher := policy.NewMatcher()
	snap, _ := policy.CompileSnapshot(1, "gen-1", nil)
	matcher.Publish(snap)

	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     validWAN,
		GatewayDNSIP:  netip.MustParseAddr("10.100.0.1"),
		WANDevice:     dev,
		RouteCache:    rc,
		PolicyMatcher: matcher,
	})

	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("svc.Start with PBREnabled failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if !svc.PBREnabled() {
		t.Fatal("expected PBR to be enabled on running service")
	}
	if svc.DirectEgress() == nil {
		t.Fatal("expected DirectEgress to be non-nil on running service")
	}
}

func TestService_StartWithPBREnabled_FailsClosedWhenInitFails(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})

	// Invalid WAN IP causes prerequisite validation to fail
	svc.SetPBRConfig(PBRConfig{
		HostWANIP: netip.Addr{}, // Invalid
		WANDevice: &mockPBRDevice{},
	})

	err := svc.Start(context.Background())
	if err == nil {
		_ = svc.Stop()
		t.Fatal("expected svc.Start to fail when PBR initialization prerequisites fail")
	}

	if svc.IsRunning() {
		t.Fatal("service must not be running after PBR startup failure (fail closed)")
	}
	if svc.PBREnabled() {
		t.Fatal("PBR must not be enabled when initialization fails")
	}
}

func TestService_StartWithPBRDisabled_Default(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)

	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if svc.PBREnabled() {
		t.Fatal("expected PBR to be disabled by default")
	}
	if svc.DirectEgress() != nil {
		t.Fatal("expected DirectEgress to be nil when disabled")
	}
}

func TestMemoryRouteCache(t *testing.T) {
	rc := NewMemoryRouteCache()
	ip := netip.MustParseAddr("1.1.1.1")
	sessionID := "sess-test-1"

	if d := rc.Lookup(sessionID, ip); d != policy.Unknown {
		t.Fatalf("expected policy.Unknown for unrecorded IP, got %v", d)
	}

	rc.Set(sessionID, ip, policy.Direct)
	if d := rc.Lookup(sessionID, ip); d != policy.Direct {
		t.Fatalf("expected policy.Direct after Set, got %v", d)
	}

	ip2 := netip.MustParseAddr("8.8.8.8")
	rc.Set(sessionID, ip2, policy.Proxy)
	if d := rc.Lookup(sessionID, ip2); d != policy.Proxy {
		t.Fatalf("expected policy.Proxy after Set, got %v", d)
	}
}
