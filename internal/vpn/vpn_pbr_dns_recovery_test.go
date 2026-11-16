package vpn

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
	mdns "github.com/miekg/dns"
)

// dnsRecoveryClient is a client-side network stack whose packets are handed to
// the intercepted DNS handler, so a TCP DNS exchange (handshake, framed query,
// framed answer) traverses the real gateway, the session's return path and the
// real reply writer instead of a mock.
type dnsRecoveryClient struct {
	vt        tun.Device
	tnet      *netstack.Net
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newDNSRecoveryClient(t *testing.T, handler *pbrDNSHandler, sessionID, peerKey, assignedIP string, path *forwarder.ReturnPath) *dnsRecoveryClient {
	t.Helper()
	vt, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(assignedIP)}, nil, 1500)
	if err != nil {
		t.Fatalf("create client netstack: %v", err)
	}
	c := &dnsRecoveryClient{vt: vt, tnet: tnet, stop: make(chan struct{}), done: make(chan struct{})}
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
			n, err := vt.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				handler.processJob(dnsJob{sessionID: sessionID, peerKey: peerKey, assignedIP: assignedIP, path: path, packet: pkt})
			}
		}
	}()
	return c
}

// Close stops the client and closes its device exactly once: the pinned
// netstack's Close closes channels unconditionally, so a second close would
// panic rather than be a no-op.
func (c *dnsRecoveryClient) Close() {
	c.closeOnce.Do(func() {
		close(c.stop)
		_ = c.vt.Close()
	})
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
	}
}

// dnsRecoveryQuery performs one framed DNS query over an established connection
// and returns the parsed answer.
func dnsRecoveryQuery(t *testing.T, conn io.ReadWriteCloser, id uint16, deadline time.Duration) *mdns.Msg {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion("unlisted.example.", mdns.TypeA)
	req.Id = id
	body, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
	_ = conn.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline(time.Now().Add(deadline))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("write length prefix: %v", err)
	}
	if _, err := conn.Write(body); err != nil {
		t.Fatalf("write query: %v", err)
	}
	_ = conn.(interface{ SetReadDeadline(time.Time) error }).SetReadDeadline(time.Now().Add(deadline))
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read answer length: %v", err)
	}
	respBody := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, respBody); err != nil {
		t.Fatalf("read answer: %v", err)
	}
	resp := new(mdns.Msg)
	if err := resp.Unpack(respBody); err != nil {
		t.Fatalf("unpack answer: %v", err)
	}
	return resp
}

// dnsRecoveryFixture is the shared subject of the recovery tests: the real
// handler/gateway/server over a controlled resolver, one authenticated session
// whose return path can be made to fail exactly once, and a real client stack.
type dnsRecoveryFixture struct {
	cache       *MemoryRouteCache
	fwd         *forwarder.Forwarder
	gw          *gatewaydns.Gateway
	handler     *pbrDNSHandler
	path        *forwarder.ReturnPath
	attempts    atomic.Int64
	accepted    atomic.Int64
	udpReplies  atomic.Int64
	tcpReplies  atomic.Int64
	injected    atomic.Int64
	failNext    atomic.Bool
	sessionID   string
	peerKey     string
	assignedIP  string
	gatewayAddr netip.AddrPort
}

func newDNSRecoveryFixture(t *testing.T) *dnsRecoveryFixture {
	t.Helper()
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	resolver := &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{&mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   netip.MustParseAddr("93.184.216.34").AsSlice(),
		}}
		return resp, nil
	}}
	gw, handler := dnsRuntimeTestHandler(t, cache, fwd, resolver)
	return &dnsRecoveryFixture{
		cache:       cache,
		fwd:         fwd,
		gw:          gw,
		handler:     handler,
		sessionID:   "sess-dns-recovery",
		peerKey:     "peer-dns-recovery",
		assignedIP:  "10.100.0.2",
		gatewayAddr: netip.MustParseAddrPort("10.100.0.1:53"),
	}
}

// start registers the session, the failing-capable return path and the client
// stack that closes the TCP loop back to the client.
func (f *dnsRecoveryFixture) start(t *testing.T) *dnsRecoveryClient {
	t.Helper()
	var client *dnsRecoveryClient
	f.path = forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		f.attempts.Add(1)
		proto := dnsRecoveryReplyProtocol(p)
		if proto != 0 && f.failNext.CompareAndSwap(true, false) {
			f.injected.Add(1)
			// The exact recoverable error the production engine returns when its
			// bounded inbound queue is momentarily full.
			return 0, virtualtun.ErrQueueFull
		}
		if proto == 0 {
			// Not a gateway DNS reply (for example a handshake packet): relay it
			// without counting it as a DNS answer.
			if client != nil {
				cp := make([]byte, len(p))
				copy(cp, p)
				_, _ = client.vt.Write([][]byte{cp}, 0)
			}
			return len(p), nil
		}
		if proto == 17 {
			f.udpReplies.Add(1)
		} else {
			f.tcpReplies.Add(1)
		}
		f.accepted.Add(1)
		if client != nil {
			cp := make([]byte, len(p))
			copy(cp, p)
			_, _ = client.vt.Write([][]byte{cp}, 0)
		}
		return len(p), nil
	})
	f.fwd.RegisterSessionWithReturnPath(f.sessionID, "conn-1", f.peerKey, f.assignedIP, 1, f.path)
	client = newDNSRecoveryClient(t, f.handler, f.sessionID, f.peerKey, f.assignedIP, f.path)
	return client
}

func (f *dnsRecoveryFixture) dial(t *testing.T, client *dnsRecoveryClient) (io.ReadWriteCloser, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := client.tnet.DialContextTCPAddrPort(ctx, f.gatewayAddr)
	cancel()
	if err != nil {
		t.Fatalf("client failed to dial TCP DNS: %v", err)
	}
	return conn, func() { _ = conn.Close() }
}

func (f *dnsRecoveryFixture) runtimeHandle() (handle *gatewaydns.ScopeHandle, present bool) {
	f.handler.mu.Lock()
	defer f.handler.mu.Unlock()
	rt := f.handler.sessions[f.sessionID]
	if rt == nil {
		return nil, false
	}
	return rt.handle, true
}

// dnsRecoveryReplyProtocol reports the transport protocol of an IPv4 packet
// that the gateway emitted from its DNS port, or 0 when the packet is not a
// gateway DNS reply.
func dnsRecoveryReplyProtocol(pkt []byte) byte {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+4 {
		return 0
	}
	if binary.BigEndian.Uint16(pkt[ihl:ihl+2]) != 53 {
		return 0
	}
	return pkt[9]
}

// dnsOwnedGoroutinePrefixes lists the code our DNS runtime runs its goroutines
// under: the gateway server's listeners, accept loops and connection handlers,
// the per-transport netstack readers and per-scope limiter watchers, and the
// queued workers of the intercepted and continuity handlers.
//
// The handler constructors are listed too, because a queued worker that has been
// created but not yet scheduled prints no frame of its own to attribute; its
// creation site is then the only ownership evidence, and taking it keeps the
// count independent of when the runtime first runs the goroutine.
var dnsOwnedGoroutinePrefixes = []string{
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dns.",
	"github.com/devops-igor/amnezia-nexus/internal/vpn.(*pbrDNSHandler).",
	"github.com/devops-igor/amnezia-nexus/internal/vpn.(*dnsContinuityHandler).",
	"github.com/devops-igor/amnezia-nexus/internal/vpn.newPBRDNSHandler",
	"github.com/devops-igor/amnezia-nexus/internal/vpn.newDNSContinuityHandler",
}

// dnsOwnsStack reports whether one goroutine dump block belongs to the DNS
// runtime.
//
// A frame line is matched with its symbol intact, including the receiver and
// the argument list: the handler prefixes above contain "(*pbrDNSHandler)." and
// "(*dnsContinuityHandler).", so truncating a symbol at its first parenthesis
// would remove exactly the receiver the match depends on. The runtime's
// "created by " marker is removed before matching, so a goroutine that is only
// attributable through its creator (its own frames belonging to a dependency)
// is counted as owned as well.
func dnsOwnsStack(stack string) bool {
	for _, line := range strings.Split(stack, "\n") {
		line = strings.TrimPrefix(strings.TrimSpace(line), "created by ")
		for _, prefix := range dnsOwnedGoroutinePrefixes {
			if strings.HasPrefix(line, prefix) {
				return true
			}
		}
	}
	return false
}

// dnsGoroutineStacks returns one dump block per goroutine.
func dnsGoroutineStacks() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Split(string(buf[:n]), "\n\n")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// dnsOwnedGoroutines counts the goroutines the DNS runtime owns, attributed by
// the code each goroutine runs or was created by.
//
// It deliberately does not use runtime.NumGoroutine: a live session legitimately
// raises the process total, because one gateway transport owns a whole netstack
// whose internal scheduler goroutines are not attributable to any frame of this
// repository. Counting only our own goroutines makes two steady states with one
// live transport comparable, so anything above the first one is a retirement
// that failed to release what it replaced.
func dnsOwnedGoroutines() int {
	return dnsOwnedGoroutinesMatching("")
}

// dnsOwnedGoroutinesMatching counts owned goroutines whose block contains want,
// or every owned goroutine when want is empty.
func dnsOwnedGoroutinesMatching(want string) int {
	owned := 0
	for _, stack := range dnsGoroutineStacks() {
		if !dnsOwnsStack(stack) {
			continue
		}
		if want != "" && !strings.Contains(stack, want) {
			continue
		}
		owned++
	}
	return owned
}

// dnsOwnedConnectionHandlers counts the DNS server's accepted-connection
// handlers. The recovery oracle compares steady states, so a baseline must not
// be sampled while one of the fixture's own TCP connections is still being
// served: that handler occupies a slot a leaked transport goroutine could
// otherwise hide in.
func dnsOwnedConnectionHandlers() int {
	return dnsOwnedGoroutinesMatching("(*Server).handleTCPConn")
}

// TestDNSOwnedGoroutineAttribution pins the symbol forms the oracle must and
// must not attribute. Every case is a goroutine dump block in the runtime's own
// format: frame lines carry the symbol with its receiver and arguments followed
// by the file:line, and a creation line carries the "created by " marker and an
// " in goroutine N" suffix.
func TestDNSOwnedGoroutineAttribution(t *testing.T) {
	const (
		// Frame of the gateway's accepted-connection handler (the form
		// runtime.Stack prints at dns/server.go:327).
		gatewayFrame = "goroutine 103 [chan receive]:\n" +
			"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet.(*TCPConn).Read(0xc0001e59c0, {0xc0000f0000, 0x2, 0x2}, 0x0, {0x0, 0x0})\n" +
			"\t/go/pkg/mod/gvisor.dev/gvisor@v0.0.0-20250610212827-59e91d9b9902/pkg/tcpip/adapters/gonet/gonet.go:399 +0x40d\n" +
			"github.com/devops-igor/amnezia-nexus/internal/vpn/dns.(*Server).handleTCPConn(0xc00023e800, 0xc00013e050, {0x22ce5f0, 0xc0001e59c0})\n" +
			"\t/internal/vpn/dns/server.go:335 +0x2b1\n" +
			"created by github.com/devops-igor/amnezia-nexus/internal/vpn/dns.(*Server).serveTCP in goroutine 195\n"
		// Frame of an intercepted-DNS handler method: the receiver symbol is the
		// only part that distinguishes it from any other package-level function.
		handlerFrame = "goroutine 210 [select]:\n" +
			"github.com/devops-igor/amnezia-nexus/internal/vpn.(*pbrDNSHandler).retireRuntime(0xc0000d4000, 0xc0001b2000)\n" +
			"\t/internal/vpn/vpn_pbr_dns_handler.go:234 +0x95\n" +
			"created by github.com/devops-igor/amnezia-nexus/internal/vpn.(*pbrDNSHandler).sessionRuntime in goroutine 195\n"
		// A goroutine that is attributable only through its creator: its own
		// frame belongs to the pinned netstack, and the creation line carries the
		// runtime's "created by " marker and " in goroutine N" suffix.
		creatorOnly = "goroutine 196 [chan receive]:\n" +
			"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack.(*netTun).Read(0xc0000fe050, {0xc0002f4018, 0x1, 0x1}, {0xc000018168, 0x1, 0x1}, 0x0)\n" +
			"\t/go/pkg/mod/github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828/tun/netstack/tun.go:124 +0x71\n" +
			"created by github.com/devops-igor/amnezia-nexus/internal/vpn/dns.(*Gateway).getOrCreateTransport in goroutine 195\n"
		// Near misses that must stay outside the owned set: the fixture's own
		// client goroutine (same package, different symbol) and the file:line
		// frames, whose paths contain the package directory.
		fixtureClient = "goroutine 34 [chan receive]:\n" +
			"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack.(*netTun).Read(0xc0001e51d0, {0xc000126000, 0x1, 0x1}, {0xc00012a008, 0x1, 0x1}, 0x0)\n" +
			"\t/go/pkg/mod/github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828/tun/netstack/tun.go:124 +0x71\n" +
			"github.com/devops-igor/amnezia-nexus/internal/vpn.newDNSRecoveryClient.func1()\n" +
			"\t/internal/vpn/vpn_pbr_dns_recovery_test.go:50 +0x25c\n" +
			"created by github.com/devops-igor/amnezia-nexus/internal/vpn.newDNSRecoveryClient in goroutine 8\n"
	)

	for _, tc := range []struct {
		name  string
		block string
		want  bool
	}{
		{"gateway server frame", gatewayFrame, true},
		{"intercepted handler method frame", handlerFrame, true},
		{"creator-only attribution", creatorOnly, true},
		{"fixture client is not owned", fixtureClient, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsOwnsStack(tc.block); got != tc.want {
				t.Fatalf("dnsOwnsStack() = %v want %v for\n%s", got, tc.want, tc.block)
			}
		})
	}
}

// blockedHandlerTask parks in a pbrDNSHandler method until it is released, so
// the attribution oracle can be driven with a handler-owned goroutine. Test
// only: no production path starts this task.
func (h *pbrDNSHandler) blockedHandlerTask(entered chan<- struct{}, release <-chan struct{}) {
	if h == nil {
		return
	}
	entered <- struct{}{}
	<-release
}

// TestDNSOwnedGoroutinesRejectHandlerOwnedLeak is the deterministic
// handler-owned leak regression: a goroutine parked inside an intercepted-DNS
// handler method must be counted by the same oracle the recovery test bounds, so
// a leaked retirement task cannot pass as an unchanged steady state.
func TestDNSOwnedGoroutinesRejectHandlerOwnedLeak(t *testing.T) {
	handler := newPBRDNSHandler(nil, nil, nil)
	defer func() { _ = handler.Close() }()

	baseline := dnsOwnedGoroutines()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.blockedHandlerTask(entered, release)
	}()
	<-entered
	withLeak := dnsOwnedGoroutines()
	close(release)
	<-done
	after := dnsOwnedGoroutines()

	if withLeak != baseline+1 {
		t.Fatalf("handler-owned goroutine counted %d owned goroutines, want %d", withLeak, baseline+1)
	}
	if after != baseline {
		t.Fatalf("released handler-owned goroutine left %d owned goroutines, want %d", after, baseline)
	}
}

// TestDNSRuntimeRecovery_TransientTCPReturnFailureKeepsLiveSession exercises the
// real handler/gateway/netstack TCP return path, injects exactly one recoverable
// virtualtun.ErrQueueFull, and then requires later UDP and TCP gateway DNS to be
// usable on the same still-live session, without reconnecting the session or
// tearing down its route. The healthy control runs the identical assertions with
// no injected failure.
func TestDNSRuntimeRecovery_TransientTCPReturnFailureKeepsLiveSession(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		name := "healthy-control"
		if failFirst {
			name = "one-transient-queue-full"
		}
		t.Run(name, func(t *testing.T) {
			f := newDNSRecoveryFixture(t)
			defer func() { _ = f.handler.Close() }()
			defer func() { _ = f.gw.Close() }()
			defer func() { f.fwd.BeginUnregisterSession(f.peerKey, f.sessionID).Wait() }()
			client := f.start(t)
			defer client.Close()

			// Positive control for the transport: one complete TCP DNS exchange.
			conn1, closeConn1 := f.dial(t, client)
			answer := dnsRecoveryQuery(t, conn1, 4242, 5*time.Second)
			if len(answer.Answer) != 1 {
				t.Fatalf("first TCP DNS answer carries %d records want 1", len(answer.Answer))
			}
			oldHandle, present := f.runtimeHandle()
			if !present {
				t.Fatal("live session owns no DNS runtime after its first query")
			}

			if failFirst {
				// Witness the teardown of the transport this failure must retire.
				// The live transport count cannot witness it: every intercepted
				// authority is stamped with the same scope key, so the recovered
				// session's next packet recreates a transport under that key and
				// the count is one again whether or not the old transport was
				// closed. The monotonic teardown count is the decisive witness.
				closedBefore := f.gw.ClosedTransports()
				// Arm one transient output failure, then ask again on the same
				// connection: the reply cannot be queued this one time.
				f.failNext.Store(true)
				req := new(mdns.Msg)
				req.SetQuestion("unlisted.example.", mdns.TypeA)
				req.Id = 4243
				body, err := req.Pack()
				if err != nil {
					t.Fatalf("pack query: %v", err)
				}
				var lenBuf [2]byte
				binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
				_ = conn1.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn1.Write(lenBuf[:])
				_, _ = conn1.Write(body)

				waitForCondition(t, "the injected queue-full to be produced by the real reply path", func() bool {
					return f.injected.Load() == 1
				})
				waitForCondition(t, "the failed reply to tear down its transport", func() bool {
					return f.gw.ClosedTransports() > closedBefore
				})
				closeConn1()
				if !f.fwd.HasLiveSession(f.sessionID) {
					t.Fatal("transient output failure retired the authenticated route")
				}
				if _, present := f.runtimeHandle(); !present {
					// Either state is legitimate before the next query; only the
					// post-recovery identity check below is decisive.
					t.Log("no cached runtime entry remains after the transient failure")
				}
			} else {
				// Control: the same second query is answered on the same connection.
				if resp := dnsRecoveryQuery(t, conn1, 4243, 5*time.Second); len(resp.Answer) != 1 {
					t.Fatalf("control second TCP answer carries %d records want 1", len(resp.Answer))
				}
				closeConn1()
			}

			// Congestion has cleared: ordinary UDP DNS on the same live session.
			udpPacket := dnsRuntimeTestPacket(t, 17)
			before := f.udpReplies.Load()
			for i := 0; i < 3; i++ {
				f.handler.processJob(dnsJob{sessionID: f.sessionID, peerKey: f.peerKey, assignedIP: f.assignedIP, path: f.path, packet: udpPacket})
			}
			if got := f.udpReplies.Load() - before; got != 3 {
				t.Fatalf("later UDP gateway DNS delivered %d/3 replies after the transient failure", got)
			}

			// ... and TCP DNS is usable again on a fresh connection, which needs
			// a working session transport (not a canceled one).
			conn2, closeConn2 := f.dial(t, client)
			defer closeConn2()
			if resp := dnsRecoveryQuery(t, conn2, 4244, 5*time.Second); len(resp.Answer) != 1 {
				t.Fatalf("later TCP DNS answer carries %d records want 1", len(resp.Answer))
			}

			newHandle, present := f.runtimeHandle()
			if !present {
				t.Fatal("recovered live session owns no DNS runtime")
			}
			if newHandle.IsRetired() {
				t.Fatal("recovered runtime is still the canceled handle")
			}
			if failFirst && newHandle == oldHandle {
				t.Fatal("recovery reused the canceled scope handle instead of building fresh authority")
			}
			if n := f.handler.ActiveSessionRuntimes(); n != 1 {
				t.Fatalf("live session owns %d DNS runtime(s) want 1", n)
			}
			if n := f.gw.ActiveTransports(); n != 1 {
				t.Fatalf("live session owns %d gateway transport(s) want 1", n)
			}
			if n := f.gw.ActiveSessionLimiters(); n > 1 {
				t.Fatalf("live session owns %d limiter scope(s) want at most 1", n)
			}
		})
	}
}

// TestDNSRuntimeRecovery_RepeatedTransientFailuresStayBounded repeats the
// failure/recovery cycle: each transient output failure may cost one transport,
// but the live session must keep answering and its runtime, limiter and
// transport state must stay at the active-session bound, and no goroutine the
// DNS runtime owns may survive a retirement.
func TestDNSRuntimeRecovery_RepeatedTransientFailuresStayBounded(t *testing.T) {
	f := newDNSRecoveryFixture(t)
	defer func() { _ = f.handler.Close() }()
	defer func() { _ = f.gw.Close() }()
	defer func() { f.fwd.BeginUnregisterSession(f.peerKey, f.sessionID).Wait() }()
	client := f.start(t)
	defer client.Close()

	udpPacket := dnsRuntimeTestPacket(t, 17)
	const cycles = 3
	// The baseline and the final measurement are the same shape: a session that
	// owns no gateway transport and no accepted connection. Two facts make that
	// the only comparable shape.
	//
	// First, a live transport legitimately costs goroutines: with one live
	// transport this oracle counts 8 queued workers plus 6 transport goroutines
	// (netstack reader, Serve, Serve's closer, the accept loop, the per-scope
	// limiter watcher and the scope watcher), so 14 against 8 with no transport,
	// and the process total is 49 against 27 at GOMAXPROCS=16. A settled state
	// after a recovery still owns a replacement transport, so retirement is
	// witnessed as the absence of the retired authority's goroutines, not as a
	// return to the pre-transport total.
	//
	// Second, an accepted connection costs one more handler goroutine. Sampling
	// the baseline through an open connection would leave exactly one spare slot
	// of the size a leaked transport reader needs, which is how a single leaked
	// device close could fit inside an unchanged baseline. The final measurement
	// therefore retires the session's authority first, so both measurements hold
	// no connection and no transport, and anything still owned is a retirement
	// that failed to release what it replaced.
	baseline := dnsOwnedGoroutines()
	for i := 0; i < cycles; i++ {
		conn, closeConn := f.dial(t, client)
		if resp := dnsRecoveryQuery(t, conn, uint16(5000+i), 5*time.Second); len(resp.Answer) != 1 {
			t.Fatalf("cycle %d: TCP DNS answer carries %d records want 1", i, len(resp.Answer))
		}
		// The next reply fails once, retiring this transport.
		f.failNext.Store(true)
		req := new(mdns.Msg)
		req.SetQuestion("unlisted.example.", mdns.TypeA)
		body, err := req.Pack()
		if err != nil {
			t.Fatalf("cycle %d: pack query: %v", i, err)
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(body)))
		_ = conn.(interface{ SetWriteDeadline(time.Time) error }).SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(lenBuf[:])
		_, _ = conn.Write(body)
		waitForCondition(t, "the injected queue-full to be produced", func() bool {
			return f.injected.Load() == int64(i+1)
		})
		closeConn()

		// Same live session answers UDP while the old transport is gone.
		base := f.udpReplies.Load()
		for j := 0; j < 2; j++ {
			f.handler.processJob(dnsJob{sessionID: f.sessionID, peerKey: f.peerKey, assignedIP: f.assignedIP, path: f.path, packet: udpPacket})
		}
		if got := f.udpReplies.Load() - base; got != 2 {
			t.Fatalf("cycle %d: UDP delivered %d/2 replies after the transient failure", i, got)
		}
		if !f.fwd.HasLiveSession(f.sessionID) {
			t.Fatalf("cycle %d: authenticated route was retired by a transient failure", i)
		}
		if n := f.handler.ActiveSessionRuntimes(); n != 1 {
			t.Fatalf("cycle %d: live session owns %d DNS runtime(s) want 1", i, n)
		}
	}
	if n := f.gw.ActiveTransports(); n > 1 {
		t.Fatalf("%d gateway transports accumulated across %d recoveries", n, cycles)
	}
	if n := f.gw.ActiveSessionLimiters(); n > 1 {
		t.Fatalf("%d limiter scopes accumulated across %d recoveries", n, cycles)
	}
	// Quiesce the fixture's client first, then retire the session's authority, so
	// the final measurement is the baseline's shape and no new packet enters the
	// gateway stack while the last transport is torn down. The deferred teardown
	// below repeats both steps harmlessly.
	client.Close()
	f.fwd.BeginUnregisterSession(f.peerKey, f.sessionID).Wait()
	waitForCondition(t, "the session's DNS runtime, transport and limiter to retire", func() bool {
		return f.handler.ActiveSessionRuntimes() == 0 && f.gw.ActiveTransports() == 0 &&
			f.gw.ActiveSessionLimiters() == 0 && dnsOwnedConnectionHandlers() == 0
	})
	waitForCondition(t, "recovery cycles to leave no extra DNS-owned goroutines", func() bool {
		return dnsOwnedGoroutines() <= baseline
	})
}

// TestDNSRuntimeRecovery_DoesNotReviveRetiredOrReplacedSession proves the
// recovery branch is fenced by the authenticated route: a session whose route
// really retired gets no new runtime and no reply, while a replacement session
// owns its own working runtime.
func TestDNSRuntimeRecovery_DoesNotReviveRetiredOrReplacedSession(t *testing.T) {
	f := newDNSRecoveryFixture(t)
	defer func() { _ = f.handler.Close() }()
	defer func() { _ = f.gw.Close() }()

	f.path = forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		if dnsRecoveryReplyProtocol(p) == 17 {
			f.udpReplies.Add(1)
		}
		return len(p), nil
	})
	f.fwd.RegisterSessionWithReturnPath(f.sessionID, "conn-1", f.peerKey, f.assignedIP, 1, f.path)
	udpPacket := dnsRuntimeTestPacket(t, 17)
	job := dnsJob{sessionID: f.sessionID, peerKey: f.peerKey, assignedIP: f.assignedIP, path: f.path, packet: udpPacket}

	f.handler.processJob(job)
	if got := f.udpReplies.Load(); got != 1 {
		t.Fatalf("live positive control delivered %d replies want 1", got)
	}
	f.fwd.BeginUnregisterSession(f.peerKey, f.sessionID).Wait()
	if n := f.handler.ActiveSessionRuntimes(); n != 0 {
		t.Fatalf("real retirement left %d DNS runtime(s)", n)
	}

	// The retired session must not be revived through the recovery branch.
	retiredBefore := f.handler.retired.Load()
	f.handler.processJob(job)
	if got := f.udpReplies.Load(); got != 1 {
		t.Fatalf("retired session's late work delivered a reply (total=%d)", got)
	}
	if n := f.handler.ActiveSessionRuntimes(); n != 0 {
		t.Fatalf("retired session was revived: %d DNS runtime(s)", n)
	}
	if f.handler.retired.Load() != retiredBefore+1 {
		t.Fatalf("late work after retirement was not counted as retired")
	}

	// A replacement session on the same peer owns its own runtime.
	const replacementID = "sess-dns-recovery-replacement"
	replacementPath := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		if dnsRecoveryReplyProtocol(p) == 17 {
			f.udpReplies.Add(1)
		}
		return len(p), nil
	})
	f.fwd.RegisterSessionWithReturnPath(replacementID, "conn-2", f.peerKey, f.assignedIP, 1, replacementPath)
	defer func() { f.fwd.BeginUnregisterSession(f.peerKey, replacementID).Wait() }()
	f.handler.processJob(dnsJob{sessionID: replacementID, peerKey: f.peerKey, assignedIP: f.assignedIP, path: replacementPath, packet: udpPacket})
	if got := f.udpReplies.Load(); got != 2 {
		t.Fatalf("replacement session delivered %d total replies want 2", got)
	}
	if n := f.handler.ActiveSessionRuntimes(); n != 1 {
		t.Fatalf("replacement session owns %d DNS runtime(s) want 1", n)
	}
}
