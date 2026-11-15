package vpn

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
	mdns "github.com/miekg/dns"
)

// continuityClient is a real client network stack. Its outbound packets enter
// the production forwarder entry point and performed DNS replies arrive through
// the session's return path, so an unmodified client accepts every answer.
type continuityClient struct {
	dev   tun.Device
	stack *netstack.Net
	stop  chan struct{}
	done  chan struct{}
}

func newContinuityClient(t *testing.T, fwd *forwarder.Forwarder, peerKey string, clientIP netip.Addr) (*continuityClient, *forwarder.ReturnPath) {
	t.Helper()
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}
	path := forwarder.NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		return dev.Write([][]byte{packet}, 0)
	})
	c := &continuityClient{dev: dev, stack: stack, stop: make(chan struct{}), done: make(chan struct{})}
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
				_ = fwd.RouteClientToBackend(peerKey, pkt)
			}
		}
	}()
	return c, path
}

func (c *continuityClient) close() {
	close(c.stop)
	_ = c.dev.Close()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
	}
}

func continuityUDPQuery(t *testing.T, stack *netstack.Net, dst netip.AddrPort, name string, id uint16) *mdns.Msg {
	t.Helper()
	conn, err := stack.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		t.Fatalf("client failed to dial %s over UDP: %v", dst, err)
	}
	defer conn.Close()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write DNS query to %s: %v", dst, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no UDP reply from %s: %v", dst, err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("failed to unpack UDP reply from %s: %v", dst, err)
	}
	return resp
}

func continuityTCPQuery(t *testing.T, stack *netstack.Net, dst netip.AddrPort, name string, id uint16) *mdns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := stack.DialContextTCPAddrPort(ctx, dst)
	if err != nil {
		t.Fatalf("client failed to dial %s over TCP: %v", dst, err)
	}
	defer conn.Close()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack DNS query: %v", err)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("failed to write TCP length to %s: %v", dst, err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("failed to write TCP query to %s: %v", dst, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("no TCP reply length from %s: %v", dst, err)
	}
	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("no TCP reply payload from %s: %v", dst, err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		t.Fatalf("failed to unpack TCP reply from %s: %v", dst, err)
	}
	return resp
}

// TestPolicyDNSContinuity_ServesIssuedGatewayProfileAfterDisable is the F817-01
// regression: a configuration issued while policy routing was active keeps
// naming the gateway, and that address must keep answering over UDP and TCP
// after a real ConfigurePBR/TeardownPBR cycle. New inactive downloads keep the
// legacy defaults, external port 53 is not intercepted, and no direct-path
// evidence is created while disabled.
func TestPolicyDNSContinuity_ServesIssuedGatewayProfileAfterDisable(t *testing.T) {
	gateway := netip.MustParseAddr("10.100.0.1")
	clientIP := netip.MustParseAddr("10.100.0.2")
	const (
		backendID int64 = 9017
		peerKey         = "continuity-peer"
		sessionID       = "continuity-session"
	)
	afterDisableIP := netip.MustParseAddr("93.184.216.35")

	oldResolver := newDNSContinuityResolver
	newDNSContinuityResolver = func(gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
		return &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
				A:   net.IP(afterDisableIP.AsSlice()),
			})
			return resp, nil
		}}, nil
	}
	defer func() { newDNSContinuityResolver = oldResolver }()

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	fwd.AttachBackendDevice(backendID, &mockPBRDevice{})
	client, path := newContinuityClient(t, fwd, peerKey, clientIP)
	defer client.close()
	fwd.RegisterSessionWithReturnPath(sessionID, "continuity-connection", peerKey, clientIP.String(), backendID, path)

	svc := &Service{forwarder: fwd}
	defer svc.closeDNSContinuity()
	cfg := newSteeringPBRConfig(t, gateway)
	if err := svc.ConfigurePBR(cfg); err != nil {
		t.Fatalf("ConfigurePBR failed: %v", err)
	}

	issued, _ := svc.clientConfigDNSServers()
	if issued != gateway.String() {
		t.Fatalf("active configuration DNS = %q, want the gateway %q", issued, gateway.String())
	}
	issuedAddr := netip.AddrPortFrom(netip.MustParseAddr(issued), 53)

	// Positive control: the policy resolver answers the issued address while
	// policy routing is active.
	if reply := continuityUDPQuery(t, client.stack, issuedAddr, "active.example.", 100); reply.Rcode != mdns.RcodeSuccess {
		t.Fatalf("active gateway query failed with rcode %v", reply.Rcode)
	}

	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("TeardownPBR failed: %v", err)
	}
	if fwd.PBREnabled() {
		t.Fatal("policy routing still enabled after teardown")
	}
	if got1, got2 := svc.clientConfigDNSServers(); got1 != awg.AWGDefaults["dns1"] || got2 != awg.AWGDefaults["dns2"] {
		t.Fatalf("inactive generated configuration DNS = %q, %q; want the legacy defaults", got1, got2)
	}

	// The retained profile address keeps answering on both transports.
	udpReply := continuityUDPQuery(t, client.stack, issuedAddr, "after-disable.example.", 101)
	if len(udpReply.Answer) != 1 {
		t.Fatalf("issued gateway DNS over UDP after disable: got %d answers, want 1", len(udpReply.Answer))
	}
	tcpReply := continuityTCPQuery(t, client.stack, issuedAddr, "after-disable-tcp.example.", 102)
	if len(tcpReply.Answer) != 1 {
		t.Fatalf("issued gateway DNS over TCP after disable: got %d answers, want 1", len(tcpReply.Answer))
	}

	// The continuity responder must not grant DIRECT routing authority.
	if got := cfg.RouteCache.Lookup(sessionID, afterDisableIP); got != policy.Unknown {
		t.Fatalf("continuity answer produced routing evidence: decision = %v, want Unknown", got)
	}

	// External port 53 keeps its previous routing while policy routing is off.
	external := netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), 53)
	extConn, err := client.stack.DialUDPAddrPort(netip.AddrPort{}, external)
	if err != nil {
		t.Fatalf("client failed to dial external resolver: %v", err)
	}
	defer extConn.Close()
	extQuery := new(mdns.Msg)
	extQuery.SetQuestion("external.example.", mdns.TypeA)
	extPayload, err := extQuery.Pack()
	if err != nil {
		t.Fatalf("failed to pack external query: %v", err)
	}
	if _, err := extConn.Write(extPayload); err != nil {
		t.Fatalf("failed to write external query: %v", err)
	}
	_ = extConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := extConn.Read(make([]byte, 4096)); err == nil {
		t.Fatal("external port 53 was answered while policy routing was disabled")
	}
	backend, ok := fwd.GetBackendPacketChannel(backendID)
	if !ok {
		t.Fatal("fixture backend queue absent")
	}
	select {
	case pkt := <-backend:
		if got := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}); got != external.Addr() {
			t.Fatalf("backend packet destination = %s, want the external resolver %s", got, external.Addr())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("external DNS did not take the legacy path to the backend")
	}

	// A second enable/disable cycle keeps the responder installed.
	cfg2 := newSteeringPBRConfig(t, gateway)
	if err := svc.ConfigurePBR(cfg2); err != nil {
		t.Fatalf("second ConfigurePBR failed: %v", err)
	}
	if err := svc.TeardownPBR(); err != nil {
		t.Fatalf("second TeardownPBR failed: %v", err)
	}
	if reply := continuityUDPQuery(t, client.stack, issuedAddr, "after-restart.example.", 103); len(reply.Answer) != 1 {
		t.Fatalf("issued gateway DNS after a second disable cycle: got %d answers, want 1", len(reply.Answer))
	}
}

// TestDefaultPolicyUpstreamsMatchClientDNS pins the policy resolver's upstream
// pair so a blocked provider cannot silently return, and keeps it identical to
// the addresses generated client configurations push by deriving both from the
// one definition.
func TestDefaultPolicyUpstreamsMatchClientDNS(t *testing.T) {
	upstreams := policy.DefaultUpstreams()
	want := []struct {
		address string
		port    int
	}{
		{"94.140.14.14", policy.DefaultUpstreamPort},
		{"94.140.15.15", policy.DefaultUpstreamPort},
	}
	if len(upstreams) != len(want) {
		t.Fatalf("default policy upstreams = %v, want %d entries", upstreams, len(want))
	}
	for i := range want {
		if upstreams[i].Address != want[i].address || upstreams[i].Port != want[i].port {
			t.Fatalf("default policy upstream %d = %s, want %s:%d", i, upstreams[i], want[i].address, want[i].port)
		}
		if transport := upstreams[i].EffectiveTransport(); transport != policy.TransportPlain {
			t.Fatalf("default policy upstream %d transport = %q, want %q", i, transport, policy.TransportPlain)
		}
	}

	// The resolver fallback must be the same list, so a stored record that
	// carries no upstream configuration keeps resolving through it.
	effective := policy.DefaultSettings().EffectiveUpstreams()
	if len(effective) != len(upstreams) {
		t.Fatalf("effective default upstreams = %v, want %v", effective, upstreams)
	}
	for i := range upstreams {
		if effective[i] != upstreams[i] {
			t.Fatalf("effective default upstream %d = %s, want %s", i, effective[i], upstreams[i])
		}
	}

	// The rendered pair must come from that same definition: this is the drift
	// the single source exists to prevent.
	dns1, dns2 := defaultClientDNSServers()
	if dns1 != want[0].address || dns2 != want[1].address {
		t.Fatalf("client configuration DNS pair = (%q, %q), want (%q, %q)", dns1, dns2, want[0].address, want[1].address)
	}
	// A service with policy routing inactive pushes exactly that pair.
	if got1, got2 := (&Service{}).clientConfigDNSServers(); got1 != dns1 || got2 != dns2 {
		t.Fatalf("inactive client configuration DNS = (%q, %q), want (%q, %q)", got1, got2, dns1, dns2)
	}
}

// TestContinuityDNSRecoversAfterTransientTCPReturnFailure is the F817-03
// regression: one recoverable return-queue failure on a TCP DNS reply retires
// the gateway's cached authority. The session stays live, so the continuity
// responder must replace the retired authority instead of reusing it, and later
// UDP and TCP queries to the retained gateway address must be answered. The
// healthy control runs the identical assertions without the injected failure.
// No routing evidence may be produced across either sequence.
func TestContinuityDNSRecoversAfterTransientTCPReturnFailure(t *testing.T) {
	for _, inject := range []bool{false, true} {
		name := "healthy-control"
		if inject {
			name = "one-transient-queue-full"
		}
		t.Run(name, func(t *testing.T) {
			gateway := netip.MustParseAddr("10.100.0.1")
			clientIP := netip.MustParseAddr("10.100.0.2")
			answerIP := netip.MustParseAddr("93.184.216.36")
			const (
				backendID int64 = 9019
				peerKey         = "continuity-recovery-peer"
				sessionID       = "continuity-recovery-session"
			)

			oldResolver := newDNSContinuityResolver
			newDNSContinuityResolver = func(gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
				return &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
					resp := new(mdns.Msg)
					resp.SetReply(req)
					resp.Answer = append(resp.Answer, &mdns.A{
						Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
						A:   net.IP(answerIP.AsSlice()),
					})
					return resp, nil
				}}, nil
			}
			defer func() { newDNSContinuityResolver = oldResolver }()

			fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
			fwd.AttachBackendDevice(backendID, &mockPBRDevice{})
			client, clientPath := newContinuityClient(t, fwd, peerKey, clientIP)
			defer client.close()

			// The session's return path injects at most one production-equivalent
			// queue-full failure on a TCP DNS reply, then behaves normally. UDP
			// replies are counted so a dropped continuity answer is observable.
			var failNext atomic.Bool
			var injected, udpReplies atomic.Int64
			path := forwarder.NewReturnPath(func(pk, ip string, p []byte) (int, error) {
				if len(p) >= 40 && p[9] == 6 && binary.BigEndian.Uint16(p[20:22]) == 53 && failNext.CompareAndSwap(true, false) {
					injected.Add(1)
					return 0, virtualtun.ErrQueueFull
				}
				if len(p) >= 28 && p[9] == 17 {
					udpReplies.Add(1)
				}
				return clientPath.Write(pk, ip, p)
			})
			fwd.RegisterSessionWithReturnPath(sessionID, "continuity-recovery-connection", peerKey, clientIP.String(), backendID, path)

			svc := &Service{forwarder: fwd}
			defer svc.closeDNSContinuity()
			cfg := newSteeringPBRConfig(t, gateway)
			if err := svc.ConfigurePBR(cfg); err != nil {
				t.Fatalf("ConfigurePBR failed: %v", err)
			}
			issued, _ := svc.clientConfigDNSServers()
			if err := svc.TeardownPBR(); err != nil {
				t.Fatalf("TeardownPBR failed: %v", err)
			}
			issuedAddr := netip.AddrPortFrom(netip.MustParseAddr(issued), 53)
			handler, ok := fwd.DNSHandler().(*dnsContinuityHandler)
			if !ok {
				t.Fatal("continuity handler is not installed after disable")
			}

			// Positive control: one complete TCP DNS exchange through continuity.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := client.stack.DialContextTCPAddrPort(ctx, issuedAddr)
			cancel()
			if err != nil {
				t.Fatalf("continuity TCP dial: %v", err)
			}
			defer conn.Close()
			if reply := continuityTCPQueryOnConn(t, conn, "initial.example.", 810); len(reply.Answer) != 1 {
				t.Fatalf("initial continuity TCP query carried %d answers, want 1", len(reply.Answer))
			}

			handler.mu.Lock()
			cached := handler.sessions[sessionID]
			var oldHandle *gatewaydns.ScopeHandle
			if cached != nil {
				oldHandle = cached.runtime.handle
			}
			handler.mu.Unlock()
			if oldHandle == nil {
				t.Fatal("continuity responder cached no authority for the live session")
			}

			if inject {
				failNext.Store(true)
				req := new(mdns.Msg)
				req.SetQuestion("queue-failure.example.", mdns.TypeA)
				req.Id = 811
				body, err := req.Pack()
				if err != nil {
					t.Fatalf("pack query: %v", err)
				}
				var lenBuf [2]byte
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write(lenBuf[:])
				_, _ = conn.Write(body)

				waitForCondition(t, "one real TCP return-path failure", func() bool { return injected.Load() == 1 })
				waitForCondition(t, "the cached authority to be retired", func() bool { return oldHandle.IsRetired() })
				t.Logf("injected=%d, authenticated route live=%v, cached authority retired=%v",
					injected.Load(), fwd.HasLiveSession(sessionID), oldHandle.IsRetired())
			}
			if !fwd.HasLiveSession(sessionID) {
				t.Fatal("transient return failure retired the authenticated session")
			}

			// Congestion has cleared: ordinary UDP gateway DNS on the same session.
			before := udpReplies.Load()
			for i := 0; i < 3; i++ {
				req := new(mdns.Msg)
				req.SetQuestion("after-congestion.example.", mdns.TypeA)
				req.Id = uint16(900 + i)
				payload, err := req.Pack()
				if err != nil {
					t.Fatalf("pack UDP query: %v", err)
				}
				packet := buildTestPBRUDPPacket(clientIP, gateway, uint16(45100+i), 53, payload)
				if err := fwd.RouteClientToBackend(peerKey, packet); err != nil {
					t.Fatalf("route UDP query: %v", err)
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for udpReplies.Load()-before < 3 && time.Now().Before(deadline) {
				time.Sleep(2 * time.Millisecond)
			}
			if got := udpReplies.Load() - before; got != 3 {
				handler.mu.Lock()
				current := handler.sessions[sessionID]
				handler.mu.Unlock()
				same := current != nil && current.runtime.handle == oldHandle
				t.Fatalf("after congestion cleared, later UDP gateway DNS delivered %d/3 replies; same retired handle=%v, route still live=%v",
					got, same, fwd.HasLiveSession(sessionID))
			}

			// ... and fresh TCP DNS is usable again.
			if reply := continuityTCPQuery(t, client.stack, issuedAddr, "recovered-tcp.example.", 950); len(reply.Answer) != 1 {
				t.Fatalf("later TCP DNS carried %d answers, want 1", len(reply.Answer))
			}

			handler.mu.Lock()
			current := handler.sessions[sessionID]
			handler.mu.Unlock()
			if current == nil {
				t.Fatal("recovered live session lost its continuity authority")
			}
			if current.runtime.handle.IsRetired() {
				t.Fatal("recovered live session still holds a retired authority")
			}
			if inject && current.runtime.handle == oldHandle {
				t.Fatal("recovery reused the retired authority instead of building fresh authority")
			}
			// Replacement retires the old authority and its transport; allow the
			// bounded teardown to finish without making the reply assertions
			// depend on it.
			waitForConditionWithin(t, 15*time.Second, "replaced authority cleanup", func() bool {
				handler.mu.Lock()
				authorities := len(handler.sessions)
				handler.mu.Unlock()
				return authorities == 1 && handler.gw.ActiveTransports() <= 1 && handler.gw.ActiveSessionLimiters() <= 1
			})
			handler.mu.Lock()
			authorities := len(handler.sessions)
			handler.mu.Unlock()
			if authorities != 1 {
				t.Fatalf("live session owns %d continuity authorities, want 1", authorities)
			}
			if n := handler.gw.ActiveTransports(); n > 1 {
				t.Fatalf("live session owns %d gateway transports, want at most 1", n)
			}
			if n := handler.gw.ActiveSessionLimiters(); n > 1 {
				t.Fatalf("live session owns %d limiter scopes, want at most 1", n)
			}

			// Companion assertion: no routing evidence or route-cache entry was
			// created across the whole sequence.
			if got := cfg.RouteCache.Lookup(sessionID, answerIP); got != policy.Unknown {
				t.Fatalf("continuity answers produced routing evidence: decision = %v, want Unknown", got)
			}

			// A genuinely dead session must still retire, never be revived.
			fwd.BeginUnregisterSession(peerKey, sessionID).Wait()
			if fwd.HasLiveSession(sessionID) {
				t.Fatal("session still live after unregister")
			}
			repliesBefore := udpReplies.Load()
			if handled, _ := handler.HandleDNSPacket(sessionID, peerKey, clientIP.String(), path, buildTestPBRUDPPacket(clientIP, gateway, 45999, 53, mustPackQuery(t, "dead-session.example.", 960))); !handled {
				t.Fatal("dead-session query was not admitted for retirement")
			}
			time.Sleep(150 * time.Millisecond)
			if got := udpReplies.Load(); got != repliesBefore {
				t.Fatalf("retired session received %d replies", got-repliesBefore)
			}
			handler.mu.Lock()
			remaining := len(handler.sessions)
			handler.mu.Unlock()
			if remaining != 0 {
				t.Fatalf("retired session left %d continuity authorities behind", remaining)
			}
		})
	}
}

// continuityTCPQueryOnConn performs one length-prefixed DNS exchange on an
// existing TCP connection.
func continuityTCPQueryOnConn(t *testing.T, conn net.Conn, name string, id uint16) *mdns.Msg {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	body, err := req.Pack()
	if err != nil {
		t.Fatalf("pack TCP query: %v", err)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("write TCP length: %v", err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("write TCP query: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read TCP reply length: %v", err)
	}
	respBuf := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		t.Fatalf("read TCP reply payload: %v", err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(respBuf); err != nil {
		t.Fatalf("unpack TCP reply: %v", err)
	}
	return resp
}

// mustPackQuery packs a DNS A query or fails the test.
func mustPackQuery(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = id
	body, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return body
}

// waitForConditionWithin polls cond until it holds or the budget passes. It is
// used only for state a background owner advances (transport teardown); the
// decisive reply assertions above do not depend on it.
func waitForConditionWithin(t *testing.T, budget time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", budget, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
