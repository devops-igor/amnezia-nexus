package gatewaydns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// interceptClient is a real client network stack. Its outbound packets are
// submitted to the gateway exactly as the forwarder submits an authenticated
// client's packets, and the gateway's replies are fed back into the stack, so
// the acceptance of a reply is decided by an unmodified client.
type interceptClient struct {
	dev   tun.Device
	stack *netstack.Net
	stop  chan struct{}
	done  chan struct{}
}

func newInterceptClient(t *testing.T, gw *Gateway, scope *ScopeHandle, clientIP netip.Addr) *interceptClient {
	t.Helper()
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}
	c := &interceptClient{dev: dev, stack: stack, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			select {
			case <-c.stop:
				return
			default:
			}
			n, err := dev.Read(buf, sizes, 0)
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
	return c
}

func (c *interceptClient) deliver(packet []byte) {
	_, _ = c.dev.Write([][]byte{packet}, 0)
}

func (c *interceptClient) close() {
	close(c.stop)
	_ = c.dev.Close()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
	}
}

func foreignDNSResolver(t *testing.T, ttl uint32, answers map[string]string) *mockResolver {
	t.Helper()
	return &mockResolver{
		exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			ip := answers[req.Question[0].Name]
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl},
				A:   net.ParseIP(ip).To4(),
			})
			return resp, nil
		},
	}
}

func newInterceptGateway(t *testing.T, snap *policy.Snapshot, resolver Resolver, gwIP netip.Addr) *Gateway {
	t.Helper()
	addr := netip.AddrPortFrom(gwIP, 53)
	srv, err := NewServer(ServerConfig{Gateway: addr}, resolver, &staticPolicySource{snapshot: snap})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}
	gw, err := NewGateway(GatewayConfig{Gateway: addr, InterceptAllDestinations: true}, srv)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })
	return gw
}

func waitForDecision(t *testing.T, sess *policy.SessionCache, generation string, ip netip.Addr, want policy.Decision) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got policy.Decision
	for time.Now().Before(deadline) {
		got = sess.Lookup(ip, generation, time.Now())
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected decision %v for %s, got %v", want, ip, got)
}

func writeUDPQuery(t *testing.T, conn net.Conn, name string, id uint16) *mdns.Msg {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write DNS query: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read DNS reply for %s: %v", name, err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack DNS reply for %s: %v", name, err)
	}
	return resp
}

func assertReplySource(t *testing.T, packets [][]byte, wantSrc netip.Addr) {
	t.Helper()
	if len(packets) == 0 {
		t.Fatal("gateway wrote no reply packets")
	}
	for _, pkt := range packets {
		if len(pkt) < 28 {
			t.Fatalf("reply packet too short: %d", len(pkt))
		}
		if (pkt[0] >> 4) != 4 {
			t.Fatalf("reply packet is not IPv4")
		}
		src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
		if src != wantSrc {
			t.Fatalf("reply source = %s, want queried address %s", src, wantSrc)
		}
		ihl := int(pkt[0]&0x0f) * 4
		if binary.BigEndian.Uint16(pkt[ihl:ihl+2]) != 53 {
			t.Fatalf("reply source port != 53")
		}
	}
}

// TestGateway_Interception_ForeignUDPRewritesSourceAndClassifies proves that a
// plain UDP DNS query to a foreign resolver is answered by the policy resolver
// with a reply that appears from the queried address, and that the answer
// records the same routing evidence a gateway-addressed query records: matched
// destinations are proxied, unmatched public destinations are direct-eligible,
// the evidence expires within the TTL bound, and it stays in its own session.
func TestGateway_Interception_ForeignUDPRewritesSourceAndClassifies(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	clientIP := netip.MustParseAddr("10.8.0.2")
	foreignResolver := netip.MustParseAddr("8.8.8.8")
	matchedIP := netip.MustParseAddr("198.51.200.55")
	directIP := netip.MustParseAddr("93.184.216.34")

	snap := compileTestSnapshot(t, "", "198.51.200.0/24")
	resolver := foreignDNSResolver(t, 7200, map[string]string{
		"matched.example.": matchedIP.String(),
		"direct.example.":  directIP.String(),
	})
	gw := newInterceptGateway(t, snap, resolver, gwIP)

	rc, sess := setupTestSession(t, snap.Generation())
	otherSession, err := rc.Open(policy.Scope{SessionID: "sess-other", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("failed to open second session: %v", err)
	}

	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-observe", OwnershipEpoch: 1}, sess, writer)
	defer gw.BeginRetire(scope)
	client := newInterceptClient(t, gw, scope, clientIP)
	defer client.close()
	writer.onPacket = client.deliver

	conn, err := client.stack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(foreignResolver, 53))
	if err != nil {
		t.Fatalf("client failed to dial foreign DNS resolver: %v", err)
	}
	defer conn.Close()

	for i, name := range []string{"matched.example.", "direct.example."} {
		resp := writeUDPQuery(t, conn, name, uint16(4000+i))
		if len(resp.Answer) != 1 {
			t.Fatalf("%s: expected one answer, got %d", name, len(resp.Answer))
		}
	}

	assertReplySource(t, writer.getPackets(), foreignResolver)

	waitForDecision(t, sess, snap.Generation(), matchedIP, policy.Proxy)
	waitForDecision(t, sess, snap.Generation(), directIP, policy.Direct)

	// The answer TTL is 7200s; the observation must be bounded by the server's
	// maximum TTL (3600s) and therefore be gone 90 minutes later.
	if got := sess.Lookup(directIP, snap.Generation(), time.Now().Add(90*time.Minute)); got != policy.Unknown {
		t.Fatalf("expected TTL-bounded evidence to expire, got %v", got)
	}
	if got := otherSession.Lookup(directIP, snap.Generation(), time.Now()); got != policy.Unknown {
		t.Fatalf("evidence leaked across sessions: %v", got)
	}
}

// TestGateway_Interception_ForeignTCPRewritesSourceAndClassifies is the TCP
// counterpart: the intercepted connection is accepted by an unmodified client
// stack on the queried address, and its answers record the same evidence.
func TestGateway_Interception_ForeignTCPRewritesSourceAndClassifies(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	clientIP := netip.MustParseAddr("10.8.0.2")
	foreignResolver := netip.MustParseAddr("9.9.9.9")
	matchedIP := netip.MustParseAddr("198.51.200.55")
	directIP := netip.MustParseAddr("93.184.216.34")

	snap := compileTestSnapshot(t, "", "198.51.200.0/24")
	resolver := foreignDNSResolver(t, 7200, map[string]string{
		"matched.example.": matchedIP.String(),
		"direct.example.":  directIP.String(),
	})
	gw := newInterceptGateway(t, snap, resolver, gwIP)

	rc, sess := setupTestSession(t, snap.Generation())
	otherSession, err := rc.Open(policy.Scope{SessionID: "sess-other", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("failed to open second session: %v", err)
	}
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-observe", OwnershipEpoch: 1}, sess, writer)
	defer gw.BeginRetire(scope)
	client := newInterceptClient(t, gw, scope, clientIP)
	defer client.close()
	writer.onPacket = client.deliver

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(foreignResolver, 53))
	if err != nil {
		t.Fatalf("client failed to dial foreign DNS resolver over TCP: %v", err)
	}
	defer conn.Close()

	for i, name := range []string{"matched.example.", "direct.example."} {
		req := new(mdns.Msg)
		req.SetQuestion(name, mdns.TypeA)
		req.Id = uint16(5000 + i)
		payload, err := req.Pack()
		if err != nil {
			t.Fatalf("failed to pack DNS query: %v", err)
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			t.Fatalf("failed to write TCP length: %v", err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("failed to write TCP query: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			t.Fatalf("failed to read TCP reply length: %v", err)
		}
		respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, respBuf); err != nil {
			t.Fatalf("failed to read TCP reply payload: %v", err)
		}
		resp := new(mdns.Msg)
		if err := resp.Unpack(respBuf); err != nil {
			t.Fatalf("failed to unpack TCP reply: %v", err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("%s: expected one answer over TCP, got %d", name, len(resp.Answer))
		}
	}

	assertReplySource(t, writer.getPackets(), foreignResolver)

	waitForDecision(t, sess, snap.Generation(), matchedIP, policy.Proxy)
	waitForDecision(t, sess, snap.Generation(), directIP, policy.Direct)
	if got := sess.Lookup(directIP, snap.Generation(), time.Now().Add(90*time.Minute)); got != policy.Unknown {
		t.Fatalf("expected TTL-bounded TCP evidence to expire, got %v", got)
	}
	if got := otherSession.Lookup(directIP, snap.Generation(), time.Now()); got != policy.Unknown {
		t.Fatalf("TCP evidence leaked across sessions: %v", got)
	}
}

// TestGateway_Interception_MalformedPacketsProduceNoEvidence proves that
// truncated, oversized and fragmented packets to a foreign destination are
// dropped without a panic, a reply, or routing evidence.
func TestGateway_Interception_MalformedPacketsProduceNoEvidence(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	clientIP := netip.MustParseAddr("10.8.0.2")
	foreignResolver := netip.MustParseAddr("8.8.8.8")

	snap := compileTestSnapshot(t, "", "198.51.200.0/24")
	gw := newInterceptGateway(t, snap, foreignDNSResolver(t, 300, map[string]string{}), gwIP)

	_, sess := setupTestSession(t, snap.Generation())
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-observe", OwnershipEpoch: 1}, sess, writer)
	defer gw.BeginRetire(scope)

	validQuery := new(mdns.Msg)
	validQuery.SetQuestion("truncated.example.", mdns.TypeA)
	validQuery.Id = 6000
	validPayload, err := validQuery.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}

	cases := []struct {
		name string
		pkt  []byte
	}{
		{
			name: "udp header truncated",
			pkt:  buildIPv4UDPPacket(clientIP, 40000, foreignResolver, 53, validPayload)[:24],
		},
		{
			name: "udp length field lies past the packet",
			pkt: func() []byte {
				pkt := buildIPv4UDPPacket(clientIP, 40001, foreignResolver, 53, validPayload)
				binary.BigEndian.PutUint16(pkt[24:26], uint16(len(pkt))) // #nosec G115
				return pkt
			}(),
		},
		{
			name: "udp payload is not DNS",
			pkt:  buildIPv4UDPPacket(clientIP, 40002, foreignResolver, 53, []byte{0xde, 0xad, 0xbe, 0xef}),
		},
		{
			name: "udp fragmented",
			pkt: func() []byte {
				pkt := buildIPv4UDPPacket(clientIP, 40003, foreignResolver, 53, validPayload)
				binary.BigEndian.PutUint16(pkt[6:8], 0x2000) // MF set
				return pkt
			}(),
		},
		{
			name: "tcp header truncated",
			pkt:  buildIPv4TCPPacket(clientIP, 40004, foreignResolver, 53, false)[:30],
		},
		{
			name: "tcp fragmented",
			pkt:  buildIPv4TCPPacket(clientIP, 40005, foreignResolver, 53, true),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gw.TrySubmit(scope, tc.pkt); err != nil {
				t.Fatalf("TrySubmit returned error for malformed packet: %v", err)
			}
		})
	}

	if got := len(writer.getPackets()); got != 0 {
		t.Fatalf("malformed packets produced %d replies", got)
	}
	for _, ip := range []netip.Addr{netip.MustParseAddr("198.51.200.55"), netip.MustParseAddr("93.184.216.34")} {
		if got := sess.Lookup(ip, snap.Generation(), time.Now()); got != policy.Unknown {
			t.Fatalf("malformed packets produced evidence for %s: %v", ip, got)
		}
	}
}

// TestGateway_InactiveGatewayDoesNotIntercept is the gateway-level half of the
// inactive negative control: the gateway that exists while policy routing is
// inactive is built without InterceptAllDestinations, so it must refuse a
// foreign destination on both transports while still answering its own address.
func TestGateway_InactiveGatewayDoesNotIntercept(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	clientIP := netip.MustParseAddr("10.8.0.2")
	foreignResolver := netip.MustParseAddr("8.8.8.8")

	snap := compileTestSnapshot(t, "", "198.51.200.0/24")
	addr := netip.AddrPortFrom(gwIP, 53)
	srv, err := NewServer(ServerConfig{Gateway: addr}, foreignDNSResolver(t, 300, map[string]string{}), &staticPolicySource{snapshot: snap})
	if err != nil {
		t.Fatalf("failed to create DNS server: %v", err)
	}
	gw, err := NewGateway(GatewayConfig{Gateway: addr}, srv)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	t.Cleanup(func() { _ = gw.Close() })

	_, sess := setupTestSession(t, snap.Generation())
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-observe", OwnershipEpoch: 1}, sess, writer)
	defer gw.BeginRetire(scope)

	req := new(mdns.Msg)
	req.SetQuestion("matched.example.", mdns.TypeA)
	req.Id = 7000
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}

	if handled, err := gw.TrySubmit(scope, buildIPv4UDPPacket(clientIP, 40000, foreignResolver, 53, payload)); handled || err != nil {
		t.Fatalf("inactive gateway handled a foreign UDP query: handled=%v err=%v", handled, err)
	}
	if handled, err := gw.TrySubmit(scope, buildIPv4TCPPacket(clientIP, 40001, foreignResolver, 53, false)); handled || err != nil {
		t.Fatalf("inactive gateway handled a foreign TCP query: handled=%v err=%v", handled, err)
	}
	if got := len(writer.getPackets()); got != 0 {
		t.Fatalf("inactive gateway answered %d foreign queries", got)
	}
	if got := gw.ActiveTransports(); got != 0 {
		t.Fatalf("inactive gateway opened %d foreign TCP transports", got)
	}

	// The gateway's own address keeps its previous behaviour.
	handled, err := gw.TrySubmit(scope, buildIPv4UDPPacket(clientIP, 40002, gwIP, 53, payload))
	if !handled || err != nil {
		t.Fatalf("inactive gateway stopped answering its own address: handled=%v err=%v", handled, err)
	}
	if got := len(writer.getPackets()); got != 1 {
		t.Fatalf("expected one reply to the gateway-addressed query, got %d", got)
	}
}

// TestDNSTCPNAT_GatewayFlowForgetsForeignTranslation proves a client flow that
// switches back to the gateway address drops the translation recorded for its
// earlier foreign resolver, so its reply can never be rewritten to an address
// the client is no longer talking to.
func TestDNSTCPNAT_GatewayFlowForgetsForeignTranslation(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	clientIP := netip.MustParseAddr("10.8.0.2")
	foreignResolver := netip.MustParseAddr("9.9.9.9")

	snap := compileTestSnapshot(t, "", "198.51.200.0/24")
	gw := newInterceptGateway(t, snap, foreignDNSResolver(t, 300, map[string]string{}), gwIP)

	_, sess := setupTestSession(t, snap.Generation())
	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-observe", OwnershipEpoch: 1}, sess, writer)
	defer gw.BeginRetire(scope)

	const clientPort = 40010
	if handled, err := gw.TrySubmit(scope, buildIPv4TCPPacket(clientIP, clientPort, foreignResolver, 53, false)); !handled || err != nil {
		t.Fatalf("foreign TCP query was not intercepted: handled=%v err=%v", handled, err)
	}
	gw.mu.Lock()
	tr := gw.transports[scope.Scope]
	gw.mu.Unlock()
	if tr == nil {
		t.Fatal("interception did not create a TCP transport")
	}
	key := netip.AddrPortFrom(clientIP, clientPort)
	if _, ok := tr.nat.lookup(key, time.Now()); !ok {
		t.Fatal("expected the foreign flow to record a translation")
	}

	if handled, err := gw.TrySubmit(scope, buildIPv4TCPPacket(clientIP, clientPort, gwIP, 53, false)); !handled || err != nil {
		t.Fatalf("gateway TCP query was not handled: handled=%v err=%v", handled, err)
	}
	if dest, ok := tr.nat.lookup(key, time.Now()); ok {
		t.Fatalf("gateway-directed flow kept a stale translation to %s", dest)
	}
}

// buildIPv4TCPPacket builds a minimal IPv4 TCP packet. When truncated is true
// the packet stops in the middle of the TCP header; when fragmented is true a
// more-fragments flag is set so the packet cannot be translated safely.
func buildIPv4TCPPacket(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, fragmented bool) []byte {
	ihl := 20
	tcpHdrLen := 20
	totalLen := ihl + tcpHdrLen
	if fragmented {
		totalLen = ihl + tcpHdrLen + 4
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // #nosec G115
	if fragmented {
		binary.BigEndian.PutUint16(pkt[6:8], 0x2000)
	} else {
		binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	}
	pkt[8] = 64
	pkt[9] = 6
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[10:12], calculateChecksum(pkt[:ihl]))
	if fragmented {
		copy(pkt[20:24], []byte{1, 2, 3, 4})
		return pkt
	}
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	pkt[32] = 0x50 // data offset: 5 words
	pkt[33] = 0x02 // SYN
	return pkt
}

// TestDNSTCPNAT_BoundsTranslations proves the per-session translation table is
// bounded and that stale entries are discarded.
func TestDNSTCPNAT_BoundsTranslations(t *testing.T) {
	now := time.Now()
	var nat dnsTCPNAT
	for i := 0; i < dnsTCPNATMaxEntries+50; i++ {
		key := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 8, 0, 2}), uint16(1024+i))
		nat.remember(key, netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 53), now)
	}
	nat.mu.Lock()
	size := len(nat.entries)
	nat.mu.Unlock()
	if size > dnsTCPNATMaxEntries {
		t.Fatalf("translation table grew past its bound: %d", size)
	}

	expiredKey := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 8, 0, 3}), 5555)
	nat.remember(expiredKey, netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 53), now)
	if _, ok := nat.lookup(expiredKey, now.Add(2*dnsTCPNATIdleTimeout)); ok {
		t.Fatal("expected an idle translation to expire")
	}
}
