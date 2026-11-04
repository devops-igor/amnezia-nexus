package vpn

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"

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
