package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

type mockReplyWriter struct {
	mu       sync.Mutex
	packets  [][]byte
	onPacket func(packet []byte)
	writeErr error
}

func (w *mockReplyWriter) WritePacket(scope policy.Scope, packet []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return w.writeErr
	}
	cp := make([]byte, len(packet))
	copy(cp, packet)
	w.packets = append(w.packets, cp)
	if w.onPacket != nil {
		w.onPacket(cp)
	}
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

func TestGateway_TrySubmit_TCP(t *testing.T) {
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
	defer gw.Close()

	rc, sess := setupTestSession(t, snap.Generation())
	_ = rc
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-gw-tcp", OwnershipEpoch: 1}, sess, writer)
	defer scope.cancel()

	// Simulated client network stack
	clientVT, clientTnet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}
	defer clientVT.Close()

	// When Gateway produces reply packets, route them into client netstack
	writer.onPacket = func(packet []byte) {
		_, _ = clientVT.Write([][]byte{packet}, 0)
	}

	// Read packets from client netstack and submit to Gateway
	stopClientReader := make(chan struct{})
	go func() {
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			select {
			case <-stopClientReader:
				return
			default:
			}
			n, err := clientVT.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				_, _ = gw.TrySubmit(scope, pkt)
			}
		}
	}()
	defer close(stopClientReader)

	// Dial TCP to gateway on port 53
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := clientTnet.DialContextTCPAddrPort(dialCtx, gwAddrPort)
	if err != nil {
		t.Fatalf("client failed to dial TCP to gateway: %v", err)
	}
	defer conn.Close()

	// Build and send framed DNS query
	req := new(mdns.Msg)
	req.SetQuestion("example.com.", mdns.TypeA)
	req.Id = 3344
	dnsBytes, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dnsBytes)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("failed to write TCP length: %v", err)
	}
	if _, err := conn.Write(dnsBytes); err != nil {
		t.Fatalf("failed to write TCP query: %v", err)
	}

	// Read framed DNS reply
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("failed to read TCP reply length: %v", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("failed to read TCP reply payload: %v", err)
	}

	respMsg := new(mdns.Msg)
	if err := respMsg.Unpack(respBuf); err != nil {
		t.Fatalf("failed to unpack TCP reply DNS message: %v", err)
	}
	if respMsg.Id != 3344 {
		t.Errorf("expected query ID 3344, got %d", respMsg.Id)
	}
	if len(respMsg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(respMsg.Answer))
	}

	// Verify route cache was populated for example.com (proxy)
	publicIP := netip.MustParseAddr("93.184.216.34")
	deadline := time.Now().Add(2 * time.Second)
	var got policy.Decision
	for time.Now().Before(deadline) {
		got = sess.Lookup(publicIP, snap.Generation(), time.Now())
		if got == policy.Proxy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got != policy.Proxy {
		t.Errorf("expected Proxy in route cache for TCP query, got %v", got)
	}
}

func TestGateway_TrySubmit_TCP_WriteFailureMustNotCommit(t *testing.T) {
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

	snap := compileTestSnapshot(t, "", "") // Direct decision
	srv, _ := NewServer(ServerConfig{Gateway: gwAddrPort}, res, &staticPolicySource{snapshot: snap})
	gw, err := NewGateway(GatewayConfig{Gateway: gwAddrPort}, srv)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer gw.Close()

	_, sess := setupTestSession(t, snap.Generation())
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-gw-tcp-fail", OwnershipEpoch: 1}, sess, writer)
	defer gw.BeginRetire(scope)

	clientVT, clientTnet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}
	defer clientVT.Close()

	writer.onPacket = func(packet []byte) {
		_, _ = clientVT.Write([][]byte{packet}, 0)
	}

	stopClientReader := make(chan struct{})
	go func() {
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			select {
			case <-stopClientReader:
				return
			default:
			}
			n, err := clientVT.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				_, _ = gw.TrySubmit(scope, pkt)
			}
		}
	}()
	defer close(stopClientReader)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := clientTnet.DialContextTCPAddrPort(dialCtx, gwAddrPort)
	if err != nil {
		t.Fatalf("client failed to dial TCP to gateway: %v", err)
	}
	defer conn.Close()

	// Inject write failure before query response is sent back
	writer.mu.Lock()
	writer.writeErr = errors.New("injected transport failure")
	writer.mu.Unlock()

	req := new(mdns.Msg)
	req.SetQuestion("public.example.", mdns.TypeA)
	req.Id = 4455
	dnsBytes, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dnsBytes)))
	_, _ = conn.Write(lenBuf[:])
	_, _ = conn.Write(dnsBytes)

	// Wait for retirement to take effect
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if scope.IsRetired() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !scope.IsRetired() {
		t.Errorf("expected scope to be retired after reply writer failure")
	}

	publicIP := netip.MustParseAddr("93.184.216.34")
	if got := sess.Lookup(publicIP, snap.Generation(), time.Now()); got != policy.Unknown {
		t.Fatalf("expected Unknown in route cache after reply writer failure, got %v", got)
	}
}
