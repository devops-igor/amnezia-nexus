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
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

type mockPBRDevice struct {
	mu      sync.Mutex
	closed  bool
	written [][]byte
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

func (m *mockPBRDevice) getWritten() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]byte, len(m.written))
	copy(out, m.written)
	return out
}

type mockPBRResolver struct {
	exchange func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

func (r *mockPBRResolver) Exchange(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	if r.exchange != nil {
		return r.exchange(ctx, req)
	}
	return nil, errors.New("not implemented")
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

func TestService_StartWithPBR_DefaultDependencies(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.PBREnabled = true
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc.SetPBRConfig(PBRConfig{
		HostWANIP: netip.MustParseAddr("198.51.200.1"),
		WANDevice: &mockPBRDevice{},
	})

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("svc.Start failed: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if !svc.PBREnabled() {
		t.Fatal("expected PBR to be enabled on service")
	}

	rc := svc.forwarder.RouteCache()
	if rc == nil {
		t.Fatal("expected forwarder route cache to be non-nil")
	}
	mem, ok := rc.(*MemoryRouteCache)
	if !ok {
		t.Fatalf("expected MemoryRouteCache, got %T", rc)
	}

	sessionID := "sess-dns-obs-1"
	directIP := netip.MustParseAddr("93.184.216.34")

	// 1. Initial lookup is Unknown
	if d := mem.Lookup(sessionID, directIP); d != policy.Unknown {
		t.Fatalf("expected Unknown before DNS observation, got %v", d)
	}

	// 2. Observe DNS query and response (unmatched public domain -> Direct)
	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   directIP.AsSlice(),
	})

	if err := svc.ObserveDNSResponse(sessionID, req, resp); err != nil {
		t.Fatalf("ObserveDNSResponse failed: %v", err)
	}

	// 3. Subsequent lookup reflects Direct decision
	if d := mem.Lookup(sessionID, directIP); d != policy.Direct {
		t.Fatalf("expected Direct after DNS observation, got %v", d)
	}
}

func TestMemoryRouteCache_ObserveDNSResponse_ProxyMatching(t *testing.T) {
	rc := NewMemoryRouteCache()
	matcher := policy.NewMatcher()

	// Parse proxy rule "blocked.com"
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("blocked.com\n"), policy.Source{
		ID:             "proxy-list",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	snap, err := policy.CompileSnapshot(1, "gen-proxy", []policy.SourceParsedRules{
		{
			SourceID: "proxy-list",
			Rules:    rules,
		},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot failed: %v", err)
	}
	matcher.Publish(snap)
	rc.AttachMatcher(matcher)

	sessionID := "sess-proxy-1"
	proxyIP := netip.MustParseAddr("198.51.200.55")

	req := new(mdns.Msg)
	req.SetQuestion("blocked.com.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: "blocked.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   proxyIP.AsSlice(),
	})

	if err := rc.ObserveDNSResponse(sessionID, req, resp); err != nil {
		t.Fatalf("ObserveDNSResponse failed: %v", err)
	}

	if d := rc.Lookup(sessionID, proxyIP); d != policy.Proxy {
		t.Fatalf("expected Proxy decision for blocked.com, got %v", d)
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

func TestPBR_DNSGatewayPopulatesRouteCache_DirectEgress(t *testing.T) {
	hostWAN := netip.MustParseAddr("203.0.113.1")
	gwDNS := netip.MustParseAddr("10.100.0.1")
	clientIP := netip.MustParseAddr("10.100.0.10")
	peerKey := "peer-dns-e2e"
	sessionID := "sess-dns-e2e"
	backendID := int64(101)

	wanDev := &mockPBRDevice{}
	backendDev := &mockPBRDevice{}
	rc := NewMemoryRouteCache()
	matcher := policy.NewMatcher()

	// Policy snapshot: blocked.com -> Proxy
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("blocked.com\n"), policy.Source{
		ID:             "proxy-rules",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("policy Parse: %v", err)
	}
	snap, err := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{
		{SourceID: "proxy-rules", Rules: rules},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snap)
	rc.AttachMatcher(matcher)

	// Mock DNS Resolver
	exampleIP := netip.MustParseAddr("93.184.216.34")
	blockedIP := netip.MustParseAddr("198.51.200.55")
	mockRes := &mockPBRResolver{
		exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			if len(req.Question) == 0 {
				return resp, nil
			}
			q := req.Question[0]
			switch q.Name {
			case "example.com.":
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
					A:   exampleIP.AsSlice(),
				})
			case "blocked.com.":
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
					A:   blockedIP.AsSlice(),
				})
			}
			return resp, nil
		},
	}

	dnsSrv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{
		Gateway: netip.AddrPortFrom(gwDNS, 53),
	}, mockRes, matcher)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{
		Gateway:       netip.AddrPortFrom(gwDNS, 53),
		RouteObserver: rc,
	}, dnsSrv)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	fwd.AttachBackendDevice(backendID, backendDev)

	var clientReplies [][]byte
	var repliesMu sync.Mutex
	returnPath := forwarder.NewReturnPath(func(pk, ip string, packet []byte) (int, error) {
		repliesMu.Lock()
		defer repliesMu.Unlock()
		cp := make([]byte, len(packet))
		copy(cp, packet)
		clientReplies = append(clientReplies, cp)
		return len(packet), nil
	})

	fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", peerKey, clientIP.String(), backendID, returnPath)

	cfg := PBRConfig{
		Enabled:       true,
		HostWANIP:     hostWAN,
		GatewayDNSIP:  gwDNS,
		WANDevice:     wanDev,
		RouteCache:    rc,
		PolicyMatcher: matcher,
		DNSGateway:    gw,
	}

	svc := &Service{
		forwarder: fwd,
	}
	if err := svc.ConfigurePBR(cfg); err != nil {
		t.Fatalf("ConfigurePBR: %v", err)
	}
	defer func() { _ = svc.TeardownPBR() }()

	// 1. Verify UNKNOWN destinations go to proxy backend, never DIRECT
	unqueriedIP := netip.MustParseAddr("8.8.4.4")
	unqueriedPkt := buildTestPBRTCPPacket(clientIP, unqueriedIP, 10001, 80, []byte("unqueried"))
	if err := fwd.RouteClientToBackend(peerKey, unqueriedPkt); err != nil {
		t.Fatalf("RouteClientToBackend for unqueried IP failed: %v", err)
	}
	if len(wanDev.getWritten()) != 0 {
		t.Fatalf("expected unqueried packet to not go to WAN, got %d writes", len(wanDev.getWritten()))
	}

	// 2. Client performs DNS lookup for example.com. through GatewayDNSIP:53
	reqMsg := new(mdns.Msg)
	reqMsg.SetQuestion("example.com.", mdns.TypeA)
	reqMsg.Id = 0xbeef
	reqBytes, err := reqMsg.Pack()
	if err != nil {
		t.Fatalf("Pack DNS request: %v", err)
	}
	dnsQueryPkt := buildTestPBRUDPPacket(clientIP, gwDNS, 54321, 53, reqBytes)

	if err := fwd.RouteClientToBackend(peerKey, dnsQueryPkt); err != nil {
		t.Fatalf("RouteClientToBackend for gateway DNS query failed: %v", err)
	}

	// Verify DNS reply was written back to client returnPath
	repliesMu.Lock()
	numReplies := len(clientReplies)
	var latestReply []byte
	if numReplies > 0 {
		latestReply = clientReplies[numReplies-1]
	}
	repliesMu.Unlock()
	if numReplies != 1 {
		t.Fatalf("expected 1 DNS reply delivered to client, got %d", numReplies)
	}
	if len(latestReply) < 28 {
		t.Fatalf("DNS reply packet too short: %d", len(latestReply))
	}
	respMsg := new(mdns.Msg)
	if err := respMsg.Unpack(latestReply[28:]); err != nil {
		t.Fatalf("Unpack DNS reply message failed: %v", err)
	}
	if len(respMsg.Answer) == 0 {
		t.Fatalf("expected at least 1 Answer in DNS reply, got 0")
	}

	// 3. Verify route cache was populated with DIRECT for 93.184.216.34 (WITHOUT manual injection!)
	if got := rc.Lookup(sessionID, exampleIP); got != policy.Direct {
		t.Fatalf("expected route cache to have Direct for example.com, got %v", got)
	}

	// 4. Subsequent packets to 93.184.216.34:80 must be dispatched DIRECT to WAN device!
	tcpPkt := buildTestPBRTCPPacket(clientIP, exampleIP, 12345, 80, []byte("get-example"))
	if err := fwd.RouteClientToBackend(peerKey, tcpPkt); err != nil {
		t.Fatalf("RouteClientToBackend for direct IP failed: %v", err)
	}
	wanWrites := wanDev.getWritten()
	if len(wanWrites) != 1 {
		t.Fatalf("expected 1 packet written directly to WAN device, got %d", len(wanWrites))
	}
	if fwd.DirectBytes() == 0 {
		t.Errorf("expected DirectBytes > 0, got %d", fwd.DirectBytes())
	}

	// 5. Client performs DNS lookup for blocked.com. through GatewayDNSIP:53
	reqBlocked := new(mdns.Msg)
	reqBlocked.SetQuestion("blocked.com.", mdns.TypeA)
	reqBlocked.Id = 0xcafe
	reqBlockedBytes, _ := reqBlocked.Pack()
	dnsBlockedPkt := buildTestPBRUDPPacket(clientIP, gwDNS, 54322, 53, reqBlockedBytes)

	if err := fwd.RouteClientToBackend(peerKey, dnsBlockedPkt); err != nil {
		t.Fatalf("RouteClientToBackend for blocked.com query failed: %v", err)
	}

	// Verify route cache was populated with PROXY for 198.51.200.55
	if got := rc.Lookup(sessionID, blockedIP); got != policy.Proxy {
		t.Fatalf("expected route cache to have Proxy for blocked.com, got %v", got)
	}

	// 6. Subsequent packets to 198.51.200.55:80 must NOT go to WAN device (proxy wins!)
	blockedTCP := buildTestPBRTCPPacket(clientIP, blockedIP, 12346, 80, []byte("get-blocked"))
	if err := fwd.RouteClientToBackend(peerKey, blockedTCP); err != nil {
		t.Fatalf("RouteClientToBackend for proxy IP failed: %v", err)
	}
	// WAN writes must STILL be 1 (blockedTCP did not write to WAN)
	if len(wanDev.getWritten()) != 1 {
		t.Fatalf("expected blocked destination to NOT write to WAN, got %d writes", len(wanDev.getWritten()))
	}
}
