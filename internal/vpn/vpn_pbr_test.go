package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

type mockPBRDevice struct {
	mu        sync.Mutex
	closed    bool
	written   [][]byte
	hostWANIP netip.Addr
	setIPErr  error
}

func (m *mockPBRDevice) SetHostWANIP(ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setIPErr != nil {
		return m.setIPErr
	}
	m.hostWANIP = ip
	return nil
}

func (m *mockPBRDevice) Read(b []byte) (int, error) {
	return 0, io.EOF
}

func (m *mockPBRDevice) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(b))
	copy(cp, b)
	m.written = append(m.written, cp)
	return len(b), nil
}

func (m *mockPBRDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
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
	matcher := policy.NewMatcher()
	testSrc := policy.NewMemorySource("test-src", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	snap, _ := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{testSrc.ToSourceParsedRules()})
	matcher.Publish(snap)

	emptyMatcher := policy.NewMatcher()
	emptySnap, _ := policy.CompileSnapshot(1, "gen-empty", []policy.SourceParsedRules{policy.NewMemorySource("empty", policy.ParsedRules{}).ToSourceParsedRules()})
	emptyMatcher.Publish(emptySnap)

	tests := []struct {
		name    string
		cfg     PBRConfig
		wantErr error
	}{
		{name: "unspecified 0.0.0.0 host WAN IP", cfg: PBRConfig{Enabled: true, HostWANIP: netip.MustParseAddr("0.0.0.0"), WANDevice: dev, PolicyMatcher: matcher}, wantErr: ErrPBRMissingHostWAN},
		{name: "loopback host WAN IP", cfg: PBRConfig{Enabled: true, HostWANIP: netip.MustParseAddr("127.0.0.1"), WANDevice: dev, PolicyMatcher: matcher}, wantErr: ErrPBRMissingHostWAN},
		{name: "missing WAN packet device", cfg: PBRConfig{Enabled: true, HostWANIP: validWAN, WANDevice: nil, PolicyMatcher: matcher}, wantErr: ErrPBRMissingWANDevice},
		{name: "missing policy matcher", cfg: PBRConfig{Enabled: true, HostWANIP: validWAN, WANDevice: dev, PolicyMatcher: nil}, wantErr: ErrPBRMissingPolicy},
		{name: "empty policy matcher rules", cfg: PBRConfig{Enabled: true, HostWANIP: validWAN, WANDevice: dev, PolicyMatcher: emptyMatcher}, wantErr: ErrPBREmptyPolicy},
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
	matcher := policy.NewMatcher()
	testSrc := policy.NewMemorySource("test-src", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	snap, _ := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{testSrc.ToSourceParsedRules()})
	matcher.Publish(snap)

	cfg := PBRConfig{
		Enabled:       true,
		HostWANIP:     validWAN,
		WANDevice:     dev,
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
	matcher := policy.NewMatcher()
	testSrc := policy.NewMemorySource("test-src", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	snap, _ := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{testSrc.ToSourceParsedRules()})
	matcher.Publish(snap)

	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     validWAN,
		WANDevice:     dev,
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

func TestService_StartWithPBR_DefaultDependencies(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testSrc := policy.NewMemorySource("default-production-policy", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     netip.MustParseAddr("198.51.200.1"),
		WANDevice:     &mockPBRDevice{},
		PolicySources: []policy.SourceParsedRules{testSrc.ToSourceParsedRules()},
	})

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if !svc.PBREnabled() {
		t.Fatal("expected PBR to be enabled on service")
	}

	if cfg := svc.getPBRConfig(); cfg != nil && cfg.DNSResolver == nil {
		t.Error("startup did not build the configured upstream resolver")
	}
}

func buildTestPBRUDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func buildTestPBRTCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 0x50 // data offset: 5 32-bit words (20 bytes)
	pkt[33] = 0x02 // SYN
	copy(pkt[40:], payload)
	return pkt
}

func TestService_R10H1_ConfiguredHostWANIPReachesDeviceAndManager(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) { c.PBREnabled = true })
	testSrc := policy.NewMemorySource("default-production-policy", policy.ParsedRules{
		CIDRs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	})
	cfgIP := netip.MustParseAddr("198.51.100.77")
	dev := &mockPBRDevice{}
	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     cfgIP,
		WANDevice:     dev,
		PolicySources: []policy.SourceParsedRules{testSrc.ToSourceParsedRules()},
	})
	if err := svc.initPBR(context.Background()); err != nil {
		t.Fatalf("initPBR failed: %v", err)
	}
	defer func() { _ = svc.TeardownPBR() }()
	dev.mu.Lock()
	gotIP := dev.hostWANIP
	dev.mu.Unlock()
	if gotIP != cfgIP {
		t.Fatalf("expected device HostWANIP %v, got %v", cfgIP, gotIP)
	}
	dem := svc.DirectEgress()
	if dem == nil {
		t.Fatal("expected DirectEgress to be non-nil")
	}
	pkt := buildTestPBRUDPPacket(netip.MustParseAddr("1.1.1.1"), cfgIP, 1234, 5678, []byte("x"))
	if err := dem.HandleWANReply(pkt); err != nil && strings.Contains(err.Error(), "host WAN IP") {
		t.Fatalf("manager rejected valid reply for configured HostWANIP: %v", err)
	}
	failDev := &mockPBRDevice{setIPErr: errors.New("setter err")}
	svc.SetPBRConfig(PBRConfig{
		HostWANIP:     cfgIP,
		WANDevice:     failDev,
		PolicySources: []policy.SourceParsedRules{testSrc.ToSourceParsedRules()},
	})
	if err := svc.initPBR(context.Background()); err == nil {
		t.Fatal("expected setter error propagated, got nil")
	}
	failDev.mu.Lock()
	closed := failDev.closed
	failDev.mu.Unlock()
	if !closed {
		t.Fatal("expected failed WAN device closed")
	}
}
