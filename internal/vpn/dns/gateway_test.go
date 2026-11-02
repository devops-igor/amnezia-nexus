package gatewaydns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

type mockReplyWriter struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *mockReplyWriter) WritePacket(scope policy.Scope, packet []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := make([]byte, len(packet))
	copy(cp, packet)
	w.packets = append(w.packets, cp)
	return nil
}

func (w *mockReplyWriter) getPackets() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.packets))
	copy(out, w.packets)
	return out
}

func TestGateway_TrySubmit_UDP(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	gwAddrPort := netip.AddrPortFrom(gwIP, 53)
	clientIP := netip.MustParseAddr("10.8.0.2")

	res := &mockResolver{
		exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
				A:   net.ParseIP("93.184.216.34").To4(),
			})
			return resp, nil
		},
	}

	snap := compileTestSnapshot(t, "example.com", "")
	srv, _ := NewServer(ServerConfig{Gateway: gwAddrPort}, res, &staticPolicySource{snapshot: snap})
	gw, err := NewGateway(GatewayConfig{Gateway: gwAddrPort}, srv)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}

	rc, sess := setupTestSession(t, snap.Generation())
	_ = rc
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-gw", OwnershipEpoch: 1}, sess, writer)

	// Build a DNS query message inside an IPv4 UDP packet
	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	req.Id = 1122
	dnsBytes, _ := req.Pack()

	udpPkt := buildIPv4UDPPacket(clientIP, 54321, gwIP, 53, dnsBytes)

	// 1. TrySubmit valid packet to gateway:53
	handled, err := gw.TrySubmit(scope, udpPkt)
	if err != nil {
		t.Fatalf("TrySubmit failed: %v", err)
	}
	if !handled {
		t.Errorf("expected packet to be handled")
	}

	// Verify reply was written
	pkts := writer.getPackets()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 reply packet written, got %d", len(pkts))
	}
	replyPkt := pkts[0]
	if len(replyPkt) < 28 {
		t.Fatalf("reply packet too short: %d", len(replyPkt))
	}
	// Verify reply DNS message
	respMsg := new(mdns.Msg)
	if err := respMsg.Unpack(replyPkt[28:]); err != nil {
		t.Fatalf("failed to unpack reply DNS message: %v", err)
	}
	if respMsg.Id != 1122 {
		t.Errorf("expected original query ID 1122, got %d", respMsg.Id)
	}
	if len(respMsg.Answer) != 1 {
		t.Errorf("expected 1 answer in reply, got %d", len(respMsg.Answer))
	}

	// Check route cache was populated with PROXY for 93.184.216.34 (example.com is in snapshot)
	publicIP := netip.MustParseAddr("93.184.216.34")
	if got := sess.Lookup(publicIP, snap.Generation(), time.Now()); got != policy.Proxy {
		t.Errorf("expected Proxy in route cache, got %v", got)
	}

	// 2. TrySubmit to different IP -> not handled
	otherPkt := buildIPv4UDPPacket(clientIP, 54321, netip.MustParseAddr("1.1.1.1"), 53, dnsBytes)
	handled, _ = gw.TrySubmit(scope, otherPkt)
	if handled {
		t.Errorf("expected packet to non-gateway IP not to be handled")
	}

	// 3. TrySubmit to different port -> not handled
	otherPortPkt := buildIPv4UDPPacket(clientIP, 54321, gwIP, 80, dnsBytes)
	handled, _ = gw.TrySubmit(scope, otherPortPkt)
	if handled {
		t.Errorf("expected packet to non-53 port not to be handled")
	}
}

func TestGateway_FragmentedDrop(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	gwAddrPort := netip.AddrPortFrom(gwIP, 53)
	clientIP := netip.MustParseAddr("10.8.0.2")

	srv, _ := NewServer(ServerConfig{Gateway: gwAddrPort}, &mockResolver{}, &staticPolicySource{})
	gw, _ := NewGateway(GatewayConfig{Gateway: gwAddrPort}, srv)

	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-frag", OwnershipEpoch: 1}, nil, writer)

	req := new(mdns.Msg)
	req.SetQuestion("frag.com.", mdns.TypeA)
	dnsBytes, _ := req.Pack()

	fragPkt := buildIPv4UDPPacket(clientIP, 54321, gwIP, 53, dnsBytes)
	// Set more fragments flag (MF = 0x20 in flags byte)
	fragPkt[6] |= 0x20

	handled, err := gw.TrySubmit(scope, fragPkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Errorf("fragmented packet destined to gateway:53 must be handled (dropped)")
	}
	if len(writer.getPackets()) != 0 {
		t.Errorf("fragmented packet must not produce a reply")
	}
}

func TestGateway_BeginRetire(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	gwAddrPort := netip.AddrPortFrom(gwIP, 53)
	clientIP := netip.MustParseAddr("10.8.0.2")

	srv, _ := NewServer(ServerConfig{Gateway: gwAddrPort}, &mockResolver{}, &staticPolicySource{})
	gw, _ := NewGateway(GatewayConfig{Gateway: gwAddrPort}, srv)

	rc, sess := setupTestSession(t, "gen-test")
	_ = rc
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-retire", OwnershipEpoch: 1}, sess, writer)

	// Observe an IP first
	now := time.Now()
	ip := netip.MustParseAddr("93.184.216.34")
	_ = sess.Observe("gen-test", []policy.Observation{
		{IP: ip, Decision: policy.Direct, ExpiresAt: now.Add(30 * time.Second)},
	}, now)
	if got := sess.Lookup(ip, "gen-test", now); got != policy.Direct {
		t.Fatalf("expected Direct, got %v", got)
	}

	// Call BeginRetire
	ret := gw.BeginRetire(scope)
	if ret.Scope.SessionID != "sess-retire" {
		t.Errorf("expected Scope.SessionID sess-retire, got %s", ret.Scope.SessionID)
	}
	if !scope.IsRetired() {
		t.Errorf("expected scope to be retired")
	}

	// RouteCache should now immediately return UNKNOWN
	if got := sess.Lookup(ip, "gen-test", now); got != policy.Unknown {
		t.Errorf("expected Unknown in cache after BeginRetire, got %v", got)
	}

	// TrySubmit on retired scope should not be handled
	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	dnsBytes, _ := req.Pack()
	udpPkt := buildIPv4UDPPacket(clientIP, 54321, gwIP, 53, dnsBytes)

	handled, _ := gw.TrySubmit(scope, udpPkt)
	if handled {
		t.Errorf("retired scope should not handle queries")
	}
	if len(writer.getPackets()) != 0 {
		t.Errorf("retired scope should not write replies")
	}
}
