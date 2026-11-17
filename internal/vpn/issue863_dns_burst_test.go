package vpn

// Issue 863: a healthy client burst must be answered by the panel's own DNS
// path, and a genuine overload must stay bounded and separately attributable.
//
// Every decisive case below drives production code: the forwarder entry point
// (RouteClientToBackend -> routeClientPBR -> pbrDNSHandler queue -> Gateway ->
// Server -> real UpstreamResolver over a real loopback UDP upstream), the real
// route cache and the production gateway constructor. Only the WAN and backend
// devices are the package's own mocks.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

// issue863Upstream is a loopback UDP DNS upstream whose latency and stall are
// controlled by the test, so a "healthy upstream" is a real network exchange.
// When release is set, a query blocks on it while stall is nil or true.
type issue863Upstream struct {
	addr    netip.AddrPort
	queries atomic.Int64
	release <-chan struct{}
	stall   *atomic.Bool
	latency time.Duration
}

func issue863StartUpstream(t *testing.T, latency time.Duration, release <-chan struct{}) *issue863Upstream {
	t.Helper()
	return issue863StartUpstreamWithStall(t, latency, release, nil)
}

// issue863StartUpstreamWithStall starts an upstream that only blocks on release
// while stall is true, so a test can measure a healthy exchange first and hold
// later ones afterwards.
func issue863StartUpstreamWithStall(t *testing.T, latency time.Duration, release <-chan struct{}, stall *atomic.Bool) *issue863Upstream {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	up := &issue863Upstream{latency: latency, release: release, stall: stall}
	srv := &mdns.Server{PacketConn: conn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		up.queries.Add(1)
		if up.release != nil && (up.stall == nil || up.stall.Load()) {
			<-up.release
		}
		if up.latency > 0 {
			time.Sleep(up.latency)
		}
		resp := new(mdns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		hdr := mdns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: mdns.ClassINET, Ttl: 300}
		switch q.Qtype {
		case mdns.TypeA:
			resp.Answer = append(resp.Answer, &mdns.A{Hdr: hdr, A: issue863AnswerIP(q.Name).AsSlice()})
		case mdns.TypeAAAA:
			resp.Answer = append(resp.Answer, &mdns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::863")})
		case mdns.TypeHTTPS:
			resp.Answer = append(resp.Answer, &mdns.HTTPS{SVCB: mdns.SVCB{
				Hdr:      hdr,
				Priority: 1,
				Target:   ".",
				Value:    []mdns.SVCBKeyValue{&mdns.SVCBAlpn{Alpn: []string{"h2"}}},
			}})
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	up.addr = netip.MustParseAddrPort(conn.LocalAddr().String())
	return up
}

// issue863AnswerIP derives a stable public address per queried name, so the
// test can tell one name's routing evidence from another's.
func issue863AnswerIP(name string) netip.Addr {
	var h uint32 = 2166136261
	for _, b := range []byte(strings.ToLower(name)) {
		h = (h ^ uint32(b)) * 16777619
	}
	return netip.AddrFrom4([4]byte{198, 51, byte(h>>8) | 1, byte(h>>16) | 1})
}

// issue863Client captures what the client actually received on its return path.
type issue863Client struct {
	mu      sync.Mutex
	replies map[uint16]int // dns message id -> rcode
	addrs   map[uint16][]netip.Addr
}

func newIssue863Client() *issue863Client {
	return &issue863Client{replies: map[uint16]int{}, addrs: map[uint16][]netip.Addr{}}
}

func (c *issue863Client) write(_, _ string, packet []byte) (int, error) {
	if len(packet) >= 28+12 && packet[9] == 17 {
		var msg mdns.Msg
		if err := msg.Unpack(packet[28:]); err == nil {
			c.mu.Lock()
			c.replies[msg.Id] = msg.Rcode
			for _, rr := range msg.Answer {
				if a, ok := rr.(*mdns.A); ok {
					if ip, ok := netip.AddrFromSlice(a.A); ok {
						c.addrs[msg.Id] = append(c.addrs[msg.Id], ip.Unmap())
					}
				}
			}
			c.mu.Unlock()
		}
	}
	return len(packet), nil
}

func (c *issue863Client) replyCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.replies)
}

// summary waits for every listed id, then classifies the replies.
func (c *issue863Client) summary(ids []uint16, wait time.Duration) (noerror, servfail, noReply int) {
	deadline := time.Now().Add(wait)
	for {
		c.mu.Lock()
		done := true
		for _, id := range ids {
			if _, ok := c.replies[id]; !ok {
				done = false
				break
			}
		}
		c.mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		rcode, ok := c.replies[id]
		switch {
		case !ok:
			noReply++
		case rcode == mdns.RcodeSuccess:
			noerror++
		case rcode == mdns.RcodeServerFailure:
			servfail++
		}
	}
	return noerror, servfail, noReply
}

type issue863Env struct {
	t   *testing.T
	fwd *forwarder.Forwarder
	rc  *MemoryRouteCache
	gw  *gatewaydns.Gateway
	up  *issue863Upstream
	svc *Service
}

func issue863NewEnv(t *testing.T, up *issue863Upstream) *issue863Env {
	t.Helper()
	return issue863NewEnvWithServerConfig(t, up, nil)
}

// issue863NewEnvWithServerConfig builds the same production env, optionally with
// an explicit DNS server configuration so a test can exercise custom positive
// admission budgets through the real gateway and status path. A nil config uses
// the production constructor exactly as the service does.
func issue863NewEnvWithServerConfig(t *testing.T, up *issue863Upstream, serverCfg *gatewaydns.ServerConfig) *issue863Env {
	t.Helper()
	gwDNS := netip.MustParseAddr("10.100.0.1")
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("speedtest.net\n"),
		policy.Source{ID: "issue863", Format: policy.FormatDomains, BareDomainMode: policy.DomainModeInclusiveSuffix},
		policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("parse policy rules: %v", err)
	}
	snap, err := policy.CompileSnapshot(1, "gen-issue863", []policy.SourceParsedRules{{SourceID: "issue863", Rules: rules}})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}
	matcher := policy.NewMatcher()
	matcher.Publish(snap)
	rc := NewMemoryRouteCache()
	rc.AttachMatcher(matcher)
	resolver, err := gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{
		Upstreams:             []policy.Upstream{{Address: up.addr.Addr().String(), Port: int(up.addr.Port()), Transport: policy.TransportPlain}},
		AllowLoopbackUpstream: true,
		// A held upstream must stay held while a test measures admission, and these
		// fixtures bound every wait themselves; the production attempt deadline
		// would otherwise turn a deliberate stall into a timeout mid-measurement.
		AttemptTimeout: 30 * time.Second,
		QueryTimeout:   45 * time.Second,
	})
	if err != nil {
		t.Fatalf("build upstream resolver: %v", err)
	}
	gw := issue863BuildGateway(t, gwDNS, matcher, rc, resolver, serverCfg)
	if gw == nil {
		t.Fatal("initDNSGateway returned nil")
	}
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 256)
	fwd.AttachBackendDevice(1, &mockPBRDevice{})
	svc := &Service{forwarder: fwd}
	if err := svc.ConfigurePBR(PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr("203.0.113.7"),
		GatewayDNSIP:  gwDNS,
		WANDevice:     &mockPBRDevice{},
		RouteCache:    rc,
		PolicyMatcher: matcher,
		DNSGateway:    gw,
		DNSResolver:   resolver,
	}); err != nil {
		t.Fatalf("ConfigurePBR: %v", err)
	}
	t.Cleanup(func() { _ = svc.TeardownPBR() })
	return &issue863Env{t: t, fwd: fwd, rc: rc, gw: gw, up: up, svc: svc}
}

// issue863BuildGateway returns the production gateway. When the test supplies a
// server configuration it builds the same production transport over a server
// with explicit budgets — real server, real gateway transport, the same route
// observer and the same interception rule as the production constructor — so a
// test never swaps in a different implementation.
func issue863BuildGateway(t *testing.T, gwDNS netip.Addr, matcher *policy.Matcher, rc *MemoryRouteCache, resolver gatewaydns.Resolver, serverCfg *gatewaydns.ServerConfig) *gatewaydns.Gateway {
	t.Helper()
	if serverCfg == nil {
		return initDNSGateway(gwDNS, matcher, rc, resolver)
	}
	cfg := *serverCfg
	cfg.Gateway = netip.AddrPortFrom(gwDNS, 53)
	srv, err := gatewaydns.NewServer(cfg, resolver, matcher)
	if err != nil {
		t.Fatalf("build dns server with explicit budget: %v", err)
	}
	var obs gatewaydns.RouteObserver
	if rc != nil {
		obs = rc
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{
		Gateway:                  netip.AddrPortFrom(gwDNS, 53),
		RouteObserver:            obs,
		InterceptAllDestinations: true,
	}, srv)
	if err != nil {
		t.Fatalf("build dns gateway with explicit budget: %v", err)
	}
	return gw
}

func (e *issue863Env) addSession(idx int) (sid, peer string, ip netip.Addr, client *issue863Client, path *forwarder.ReturnPath) {
	client = newIssue863Client()
	sid = fmt.Sprintf("issue863-sess-%d", idx)
	peer = fmt.Sprintf("issue863-peer-%d", idx)
	ip = netip.MustParseAddr(fmt.Sprintf("10.100.0.%d", 10+idx))
	path = forwarder.NewReturnPath(client.write)
	e.fwd.RegisterSessionWithReturnPath(sid, fmt.Sprintf("issue863-conn-%d", idx), peer, ip.String(), 1, path)
	e.t.Cleanup(func() { e.fwd.BeginUnregisterSession(peer, sid).Wait() })
	return sid, peer, ip, client, path
}

func (e *issue863Env) sendQuery(peer string, ip netip.Addr, id uint16, name string, qtype uint16) {
	e.t.Helper()
	issue863SendUDPQuery(e.t, e.fwd, peer, ip, id, name, qtype)
}

// issue863SendUDPQuery injects one client UDP DNS query for the gateway address
// through the production forwarder entry point.
func issue863SendUDPQuery(t *testing.T, fwd *forwarder.Forwarder, peer string, ip netip.Addr, id uint16, name string, qtype uint16) {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(name, qtype)
	query.Id = id
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query %s: %v", name, err)
	}
	packet := buildTestPBRUDPPacket(ip, netip.MustParseAddr("10.100.0.1"), 40000+id, 53, body)
	if err := fwd.RouteClientToBackend(peer, packet); err != nil {
		t.Fatalf("RouteClientToBackend(%s): %v", name, err)
	}
}

func (e *issue863Env) handler() *pbrDNSHandler {
	h := e.rc.sessionRuntime()
	if h == nil {
		e.t.Fatal("policy DNS handler was not installed on the route cache")
	}
	return h
}

// TestIssue863_SessionBurstMixedTypes is the acceptance regression: one
// authenticated client resolves 24 queries at once (8 names x A, AAAA, HTTPS)
// against a healthy upstream and receives an answer for every one of them.
//
// On the defective source the panel's own per-session admission limit refuses
// the queries beyond the fourth with a SERVFAIL generated without any upstream
// attempt, so this test fails there and passes on the repaired sizing.
func TestIssue863_SessionBurstMixedTypes(t *testing.T) {
	up := issue863StartUpstream(t, 20*time.Millisecond, nil)
	env := issue863NewEnv(t, up)
	sid, peer, ip, client, _ := env.addSession(1)

	names := make([]string, 0, 8)
	ids := make([]uint16, 0, 24)
	id := uint16(1000)
	for n := 0; n < 8; n++ {
		name := fmt.Sprintf("issue863-host%d.example.test.", n)
		names = append(names, name)
		for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeHTTPS} {
			ids = append(ids, id)
			env.sendQuery(peer, ip, id, name, qtype)
			id++
		}
	}

	noerror, servfail, noReply := client.summary(ids, 10*time.Second)
	if noerror != len(ids) || servfail != 0 || noReply != 0 {
		t.Fatalf("24-query burst: noerror=%d servfail=%d no_reply=%d want 24/0/0; panel refusals=%+v accounting=%+v",
			noerror, servfail, noReply, env.gw.AdmissionRejections(), env.handler().QueryAccounting())
	}

	direct := 0
	for _, name := range names {
		if env.rc.Lookup(sid, issue863AnswerIP(name)) == policy.Direct {
			direct++
		}
	}
	if direct != len(names) {
		t.Fatalf("burst produced DIRECT evidence for %d of %d names", direct, len(names))
	}

	if got := env.gw.AdmissionRejections(); got != (gatewaydns.AdmissionRejections{}) {
		t.Fatalf("healthy burst was refused by the panel: %+v", got)
	}
	accounting := env.handler().QueryAccounting()
	if accounting.Enqueued != uint64(len(ids)) || accounting.DroppedQueueFull != 0 || accounting.RetiredBeforeAnswer != 0 {
		t.Fatalf("healthy burst accounting = %+v, want enqueued=%d and no loss", accounting, len(ids))
	}
}

// TestIssue863_SequentialControl is the healthy-pacing control: the same 24
// queries one at a time always succeed, on the defective source too. It shows
// the burst above measures the admission limit rather than a broken upstream.
func TestIssue863_SequentialControl(t *testing.T) {
	up := issue863StartUpstream(t, 0, nil)
	env := issue863NewEnv(t, up)
	_, peer, ip, client, _ := env.addSession(1)

	for i := 0; i < 24; i++ {
		id := uint16(2000 + i)
		env.sendQuery(peer, ip, id, fmt.Sprintf("issue863-seq%d.example.test.", i), mdns.TypeA)
		noerror, servfail, noReply := client.summary([]uint16{id}, 5*time.Second)
		if noerror != 1 || servfail != 0 || noReply != 0 {
			t.Fatalf("sequential query %d: noerror=%d servfail=%d no_reply=%d", i, noerror, servfail, noReply)
		}
	}
	if got := env.gw.AdmissionRejections(); got != (gatewaydns.AdmissionRejections{}) {
		t.Fatalf("sequential control was refused by the panel: %+v", got)
	}
}

// TestIssue863_AdmissionRefusalsAreAttributed drives the server's admission
// limits directly (small explicit budgets) and requires that genuine overload
// is refused by cause, answered explicitly, and never counted as an upstream
// attempt.
func TestIssue863_AdmissionRefusalsAreAttributed(t *testing.T) {
	block := make(chan struct{})
	var exchanges atomic.Int64
	resolver := &mockPBRResolver{exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		exchanges.Add(1)
		select {
		case <-block:
			resp := new(mdns.Msg)
			resp.SetReply(req)
			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	srv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{
		Gateway:               netip.MustParseAddrPort("10.100.0.1:53"),
		MaxInflight:           4,
		MaxInflightPerSession: 2,
	}, resolver, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	query := new(mdns.Msg)
	query.SetQuestion("issue863-overload.example.test.", mdns.TypeA)

	var wg sync.WaitGroup
	hold := func(sessionID string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := srv.ServeDNSMessage(context.Background(), policy.Scope{SessionID: sessionID, OwnershipEpoch: 1}, query, false); err != nil {
				t.Errorf("admitted query failed: %v", err)
			}
		}()
	}
	hold("issue863-busy-a")
	hold("issue863-busy-a")
	hold("issue863-busy-b")
	hold("issue863-busy-c")
	deadline := time.Now().Add(5 * time.Second)
	for exchanges.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := exchanges.Load(); got != 4 {
		t.Fatalf("admitted queries reaching the upstream = %d want 4", got)
	}

	// The session's own budget refuses before any upstream attempt.
	resp, err := srv.ServeDNSMessage(context.Background(), policy.Scope{SessionID: "issue863-busy-a", OwnershipEpoch: 1}, query, false)
	if err != nil || resp == nil || resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("per-session overload: resp=%v err=%v want explicit SERVFAIL", resp, err)
	}
	// With the server-wide budget full, another session is refused globally.
	resp, err = srv.ServeDNSMessage(context.Background(), policy.Scope{SessionID: "issue863-busy-d", OwnershipEpoch: 1}, query, false)
	if err != nil || resp == nil || resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("global overload: resp=%v err=%v want explicit SERVFAIL", resp, err)
	}

	got := srv.AdmissionRejections()
	if got.PerSession != 1 || got.Global != 1 {
		t.Fatalf("refusal attribution = %+v want per_session=1 global=1", got)
	}
	if n := exchanges.Load(); n != 4 {
		t.Fatalf("refused queries reached the upstream: exchanges=%d want 4", n)
	}
	close(block)
	wg.Wait()
}

// TestIssue863_QueueSaturationIsAttributed stalls the upstream, saturates the
// handler's bounded queue, and requires that (a) the excess is counted as a
// queue-full drop that is separate from admission refusals, (b) every enqueue is
// accounted for exactly once, and (c) a healthy client still makes progress once
// the upstream recovers.
func TestIssue863_QueueSaturationIsAttributed(t *testing.T) {
	release := make(chan struct{})
	up := issue863StartUpstream(t, 0, release)
	env := issue863NewEnv(t, up)
	handler := env.handler()

	// Prime the worker pool: two sessions x four queries block every worker in
	// the upstream exchange while the burst below is enqueued.
	var primed []*issue863Client
	var primedIDs [][]uint16
	enqueues := 0
	for idx := 1; idx <= 2; idx++ {
		_, peer, ip, client, _ := env.addSession(idx)
		ids := make([]uint16, 0, 4)
		for q := 0; q < 4; q++ {
			id := uint16(3000 + idx*10 + q)
			ids = append(ids, id)
			env.sendQuery(peer, ip, id, fmt.Sprintf("issue863-prime%d-%d.example.test.", idx, q), mdns.TypeA)
			enqueues++
		}
		primed = append(primed, client)
		primedIDs = append(primedIDs, ids)
	}
	deadline := time.Now().Add(5 * time.Second)
	for up.queries.Load() < 8 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := up.queries.Load(); got != 8 {
		t.Fatalf("primed upstream queries = %d want 8", got)
	}

	// Burst far past queue capacity (256 queued + 8 in workers).
	var burst []*issue863Client
	for idx := 3; idx <= 68; idx++ {
		_, peer, ip, client, _ := env.addSession(idx)
		for q := 0; q < 4; q++ {
			env.sendQuery(peer, ip, uint16(4000+idx*10+q), fmt.Sprintf("issue863-burst%d-%d.example.test.", idx, q), mdns.TypeA)
			enqueues++
		}
		burst = append(burst, client)
	}
	accounting := handler.QueryAccounting()
	if accounting.DroppedQueueFull == 0 {
		t.Fatalf("saturated queue reported no drops: %+v", accounting)
	}
	if total := accounting.Enqueued + accounting.DroppedQueueFull; total != uint64(enqueues) {
		t.Fatalf("enqueue accounting = %d enqueued + %d dropped, want %d total", accounting.Enqueued, accounting.DroppedQueueFull, enqueues)
	}
	if got := env.gw.AdmissionRejections(); got != (gatewaydns.AdmissionRejections{}) {
		t.Fatalf("queue saturation was misattributed to admission limits: %+v", got)
	}

	close(release)

	// Healthy progress control: the primed clients, whose queries were admitted
	// before saturation, are answered once the upstream recovers.
	for i := range primed {
		noerror, servfail, noReply := primed[i].summary(primedIDs[i], 15*time.Second)
		if noerror != len(primedIDs[i]) || servfail != 0 || noReply != 0 {
			t.Fatalf("primed client %d after recovery: noerror=%d servfail=%d no_reply=%d", i, noerror, servfail, noReply)
		}
	}

	// Every enqueued query is answered and nothing else is: a dropped query is
	// never represented as delivered.
	replyTotal := func() int {
		total := 0
		for _, client := range primed {
			total += client.replyCount()
		}
		for i := range burst {
			total += burst[i].replyCount()
		}
		return total
	}
	deadline = time.Now().Add(20 * time.Second)
	for replyTotal() < int(accounting.Enqueued) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if answered, want := replyTotal(), int(accounting.Enqueued); answered != want {
		t.Fatalf("replies after recovery = %d want %d (enqueued jobs)", answered, want)
	}
	delivered := 0
	for i := range burst {
		if burst[i].replyCount() > 0 {
			delivered++
		}
	}
	if delivered == 0 {
		t.Fatal("no burst client received any reply after the upstream recovered")
	}
}

// TestIssue863_StaleQueuedJobIsAttributed requires queued work for a session
// that retired while its query waited to be counted as retired and to write
// nothing, while a live client on the same path is still answered.
func TestIssue863_StaleQueuedJobIsAttributed(t *testing.T) {
	up := issue863StartUpstream(t, 0, nil)
	env := issue863NewEnv(t, up)
	handler := env.handler()

	sid, peer, ip, client, path := env.addSession(1)
	env.sendQuery(peer, ip, 5000, "issue863-stale.example.test.", mdns.TypeA)
	if noerror, servfail, noReply := client.summary([]uint16{5000}, 10*time.Second); noerror != 1 || servfail != 0 || noReply != 0 {
		t.Fatalf("live positive control: noerror=%d servfail=%d no_reply=%d", noerror, servfail, noReply)
	}

	env.fwd.BeginUnregisterSession(peer, sid).Wait()
	before := handler.QueryAccounting()
	query := new(mdns.Msg)
	query.SetQuestion("issue863-stale.example.test.", mdns.TypeA)
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack late query: %v", err)
	}
	if handled, err := handler.HandleDNSPacket(sid, peer, ip.String(), path, buildTestPBRUDPPacket(ip, netip.MustParseAddr("10.100.0.1"), 45000, 53, body)); !handled || err != nil {
		t.Fatalf("late queued query: handled=%v err=%v", handled, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for handler.QueryAccounting().RetiredBeforeAnswer != before.RetiredBeforeAnswer+1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	after := handler.QueryAccounting()
	if after.RetiredBeforeAnswer != before.RetiredBeforeAnswer+1 {
		t.Fatalf("stale job retired accounting = %+v want one more retired job than %+v", after, before)
	}
	if after.Enqueued != before.Enqueued+1 {
		t.Fatalf("stale job was not accounted as enqueued: %+v", after)
	}
	if got := client.replyCount(); got != 1 {
		t.Fatalf("stale job wrote a reply for a retired session (replies=%d)", got)
	}

	// Positive control on the same shapes: a live session is still answered.
	liveID, livePeer, liveIP, liveClient, _ := env.addSession(2)
	env.sendQuery(livePeer, liveIP, 5001, "issue863-live.example.test.", mdns.TypeA)
	if noerror, servfail, noReply := liveClient.summary([]uint16{5001}, 10*time.Second); noerror != 1 || servfail != 0 || noReply != 0 {
		t.Fatalf("live control after stale job: noerror=%d servfail=%d no_reply=%d", noerror, servfail, noReply)
	}
	if got := env.rc.Lookup(liveID, issue863AnswerIP("issue863-live.example.test.")); got != policy.Direct {
		t.Fatalf("live control recorded %v evidence want DIRECT", got)
	}
}

// TestIssue863_InterceptAdmissionFiltersPackets pins the ingress filter that
// decides whether an intercepted packet becomes queued DNS work, including the
// negative shapes that must never be enqueued or counted.
func TestIssue863_InterceptAdmissionFiltersPackets(t *testing.T) {
	up := issue863StartUpstream(t, 0, nil)
	env := issue863NewEnv(t, up)
	handler := env.handler()
	sid, peer, ip, client, path := env.addSession(1)

	query := new(mdns.Msg)
	query.SetQuestion("issue863-filter.example.test.", mdns.TypeA)
	id := query.Id
	body, err := query.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	gateway := netip.MustParseAddr("10.100.0.1")
	udp53 := buildTestPBRUDPPacket(ip, gateway, 46000, 53, body)
	udpOtherPort := buildTestPBRUDPPacket(ip, gateway, 46001, 853, body)
	otherProto := append([]byte(nil), udp53...)
	otherProto[9] = 1 // ICMP

	cases := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{"udp to port 53", udp53, true},
		{"udp to another port", udpOtherPort, false},
		{"non tcp/udp protocol", otherProto, false},
		{"truncated ip header", udp53[:19], false},
	}
	for _, tc := range cases {
		handled, err := handler.HandleDNSPacket(sid, peer, ip.String(), path, tc.packet)
		if handled != tc.want || err != nil {
			t.Fatalf("%s: handled=%v err=%v want handled=%v", tc.name, handled, err, tc.want)
		}
	}

	// The accepted packet is resolved; the rejected shapes never became work.
	noerror, servfail, noReply := client.summary([]uint16{id}, 10*time.Second)
	if noerror != 1 || servfail != 0 || noReply != 0 {
		t.Fatalf("accepted packet: noerror=%d servfail=%d no_reply=%d", noerror, servfail, noReply)
	}
	if accounting := handler.QueryAccounting(); accounting.Enqueued != 1 || accounting.DroppedQueueFull != 0 {
		t.Fatalf("filtered packets reached the queue accounting: %+v", accounting)
	}

	var nilHandler *pbrDNSHandler
	if handled, err := nilHandler.HandleDNSPacket(sid, peer, ip.String(), path, udp53); handled || err != nil {
		t.Fatalf("nil handler: handled=%v err=%v", handled, err)
	}
	noGateway := newPBRDNSHandler(nil, nil, nil)
	defer func() { _ = noGateway.Close() }()
	if handled, err := noGateway.HandleDNSPacket(sid, peer, ip.String(), path, udp53); handled || err != nil {
		t.Fatalf("handler without gateway: handled=%v err=%v", handled, err)
	}
}

// TestIssue863_SecondClientProgressDuringBurst requires that one client's burst
// does not keep another client waiting: while client A's 24-query burst is being
// resolved, client B's single query must still be answered promptly and
// correctly.
func TestIssue863_SecondClientProgressDuringBurst(t *testing.T) {
	up := issue863StartUpstream(t, 40*time.Millisecond, nil)
	env := issue863NewEnv(t, up)
	_, peerA, ipA, clientA, _ := env.addSession(1)
	_, peerB, ipB, clientB, _ := env.addSession(2)

	var burstIDs []uint16
	for n := 0; n < 24; n++ {
		id := uint16(6000 + n)
		burstIDs = append(burstIDs, id)
		env.sendQuery(peerA, ipA, id, fmt.Sprintf("issue863-burst-host%d.example.test.", n), mdns.TypeA)
	}

	started := time.Now()
	env.sendQuery(peerB, ipB, 6500, "issue863-second-client.example.test.", mdns.TypeA)
	noerror, servfail, noReply := clientB.summary([]uint16{6500}, 10*time.Second)
	elapsed := time.Since(started)
	if noerror != 1 || servfail != 0 || noReply != 0 {
		t.Fatalf("second client during burst: noerror=%d servfail=%d no_reply=%d", noerror, servfail, noReply)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("second client waited %v behind another client's burst", elapsed)
	}
	if got := env.rc.Lookup("issue863-sess-2", issue863AnswerIP("issue863-second-client.example.test.")); got != policy.Direct {
		t.Fatalf("second client recorded %v evidence want DIRECT", got)
	}
	if ok, sf, none := clientA.summary(burstIDs, 15*time.Second); ok != len(burstIDs) || sf != 0 || none != 0 {
		t.Fatalf("bursting client: noerror=%d servfail=%d no_reply=%d want %d/0/0", ok, sf, none, len(burstIDs))
	}
}

// TestIssue863_AdmissionBudgetCoversProducerConcurrency is the structural fence:
// a session's admission budget must cover the number of its queries the
// intercepted-DNS producers can hold at once, and must still stay below the
// server-wide budget. Changing either number alone fails here.
func TestIssue863_AdmissionBudgetCoversProducerConcurrency(t *testing.T) {
	if gatewaydns.DefaultMaxInflightPerSession < defaultDNSWorkerCount {
		t.Fatalf("per-session DNS budget %d is below the intercepted-DNS producer count %d: a burst would be refused by the panel itself",
			gatewaydns.DefaultMaxInflightPerSession, defaultDNSWorkerCount)
	}
	if gatewaydns.DefaultMaxInflightPerSession >= gatewaydns.DefaultMaxInflight {
		t.Fatalf("per-session DNS budget %d must stay below the server-wide budget %d",
			gatewaydns.DefaultMaxInflightPerSession, gatewaydns.DefaultMaxInflight)
	}
}

// issue863ClientNetstack gives a test a real client device for one registered
// session: UDP replies are captured, TCP frames are handed back to the client
// stack, and packets the client sends travel through the production forwarder.
// Cleanup unregisters the session, closes the device and joins the pump.
func issue863ClientNetstack(t *testing.T, fwd *forwarder.Forwarder, sid, connID, peer string, ip netip.Addr) (*netstack.Net, *issue863Client) {
	t.Helper()
	capture := newIssue863Client()
	dev, stack, err := netstack.CreateNetTUN([]netip.Addr{ip}, nil, 1500)
	if err != nil {
		t.Fatalf("create client netstack: %v", err)
	}
	path := forwarder.NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		capture.write("", "", packet)
		if len(packet) > 20 && packet[9] == 6 {
			if _, err := dev.Write([][]byte{append([]byte(nil), packet...)}, 0); err != nil {
				return 0, err
			}
		}
		return len(packet), nil
	})
	fwd.RegisterSessionWithReturnPath(sid, connID, peer, ip.String(), 1, path)
	t.Cleanup(func() { fwd.BeginUnregisterSession(peer, sid).Wait() })

	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		buffers := [][]byte{make([]byte, 1500)}
		sizes := make([]int, 1)
		for {
			n, err := dev.Read(buffers, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 {
				_ = fwd.RouteClientToBackend(peer, append([]byte(nil), buffers[0][:sizes[0]]...))
			}
		}
	}()
	t.Cleanup(func() {
		_ = dev.Close()
		select {
		case <-pumpDone:
		case <-time.After(2 * time.Second):
			t.Error("client pump did not stop")
		}
	})
	return stack, capture
}

// TestIssue863_MixedTCPAndUDPProducers is the regression for the reported mixed
// transport case: one live TCP query holds a session slot while eight UDP queries
// arrive from the same authenticated session. A TCP transport is a second
// producer of concurrent queries, so the derived session budget covers it plus
// the whole UDP worker pool and every one of those queries reaches the healthy
// upstream with no panel-origin SERVFAIL.
func TestIssue863_MixedTCPAndUDPProducers(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer func() { releaseOnce.Do(func() { close(release) }) }()
	up := issue863StartUpstream(t, 0, release)
	env := issue863NewEnv(t, up)

	const sid, peer, ip = "issue863-mixed", "issue863-mixed-peer", "10.100.0.91"
	stack, capture := issue863ClientNetstack(t, env.fwd, sid, "issue863-mixed-conn", peer, netip.MustParseAddr(ip))
	t.Cleanup(func() { _ = env.gw.Close() })

	dialCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tcpConn, err := stack.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort("10.100.0.1:53"))
	if err != nil {
		t.Fatalf("dial gateway TCP: %v", err)
	}
	defer func() { _ = tcpConn.Close() }()
	_ = tcpConn.SetDeadline(time.Now().Add(20 * time.Second))
	dnsConn := &mdns.Conn{Conn: tcpConn}

	tcpQuery := new(mdns.Msg)
	tcpQuery.SetQuestion("issue863-mixed-tcp.example.test.", mdns.TypeHTTPS)
	if err := dnsConn.WriteMsg(tcpQuery); err != nil {
		t.Fatalf("write TCP query: %v", err)
	}

	// The TCP query must be inside its upstream exchange (holding a session slot)
	// before the UDP burst arrives, so the case is the reported one and not a race.
	deadline := time.Now().Add(10 * time.Second)
	for up.queries.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := up.queries.Load(); got != 1 {
		t.Fatalf("TCP query did not reach the healthy upstream (queries=%d)", got)
	}

	udpIDs := make([]uint16, 0, defaultDNSWorkerCount)
	for i := 0; i < defaultDNSWorkerCount; i++ {
		id := uint16(7100 + i)
		udpIDs = append(udpIDs, id)
		env.sendQuery(peer, netip.MustParseAddr(ip), id, fmt.Sprintf("issue863-mixed-udp%d.example.test.", i), mdns.TypeA)
	}

	wantQueries := int64(1 + defaultDNSWorkerCount)
	for up.queries.Load() < wantQueries && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := up.queries.Load(); got != wantQueries {
		t.Fatalf("mixed burst reached the upstream with %d queries want %d; refusals=%+v",
			got, wantQueries, env.gw.AdmissionRejections())
	}
	if got := env.gw.AdmissionRejections(); got != (gatewaydns.AdmissionRejections{}) {
		t.Fatalf("supported mixed-transport burst was refused by the panel: %+v", got)
	}

	releaseOnce.Do(func() { close(release) })

	tcpResp, err := dnsConn.ReadMsg()
	if err != nil {
		t.Fatalf("read TCP response: %v", err)
	}
	if tcpResp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("TCP query rcode=%d want success", tcpResp.Rcode)
	}
	noerror, servfail, noReply := capture.summary(udpIDs, 15*time.Second)
	if noerror != len(udpIDs) || servfail != 0 || noReply != 0 {
		t.Fatalf("mixed burst: UDP noerror=%d servfail=%d no_reply=%d want %d/0/0",
			noerror, servfail, noReply, len(udpIDs))
	}

	// Sequential positive control on exactly the same TCP connection.
	tcpQuery.SetQuestion("issue863-mixed-control.example.test.", mdns.TypeAAAA)
	if err := dnsConn.WriteMsg(tcpQuery); err != nil {
		t.Fatalf("write TCP control: %v", err)
	}
	control, err := dnsConn.ReadMsg()
	if err != nil {
		t.Fatalf("read TCP control: %v", err)
	}
	if control.Rcode != mdns.RcodeSuccess {
		t.Fatalf("TCP control rcode=%d want success", control.Rcode)
	}

	// The production installation path (initDNSGateway plus the intercepted-DNS
	// handler) must have left a budget covering both producer bounds.
	if got, want := env.gw.SessionBudget(), defaultDNSWorkerCount+env.gw.TCPSessionBudget(); got != want {
		t.Fatalf("installed session budget %d does not cover the producer bounds %d", got, want)
	}
}

// TestIssue863_SessionBudgetCoversEveryDeclaredProducer measures the derived
// budget on the server itself: the declared UDP producer count plus the server's
// own TCP connection bound are admitted for one scope, the next query is refused
// with the per-session cause, the derivation is clamped to the global bound, and
// a caller-configured budget is never raised.
func TestIssue863_SessionBudgetCoversEveryDeclaredProducer(t *testing.T) {
	block := make(chan struct{})
	reached := make(chan struct{}, 32)
	resolver := &mockPBRResolver{exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		reached <- struct{}{}
		select {
		case <-block:
			resp := new(mdns.Msg)
			resp.SetReply(req)
			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	newServer := func(cfg gatewaydns.ServerConfig) *gatewaydns.Server {
		t.Helper()
		cfg.Gateway = netip.MustParseAddrPort("10.100.0.1:53")
		srv, err := gatewaydns.NewServer(cfg, resolver, nil)
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		return srv
	}

	const udpProducers, tcpSessions = 6, 3
	srv := newServer(gatewaydns.ServerConfig{MaxTCPSessions: tcpSessions})
	srv.DeclareUDPProducers(udpProducers)
	want := udpProducers + tcpSessions
	if got := srv.SessionBudget(); got != want {
		t.Fatalf("derived session budget = %d want %d (declared producers + TCP bound)", got, want)
	}
	if got := srv.TCPSessionBudget(); got != tcpSessions {
		t.Fatalf("TCP session bound = %d want %d", got, tcpSessions)
	}
	// A declaration below the unconfigured default never lowers the budget: the
	// default is the floor, so a small producer set keeps the historical bound.
	floor := newServer(gatewaydns.ServerConfig{MaxTCPSessions: 1})
	floor.DeclareUDPProducers(2)
	if got := floor.SessionBudget(); got != gatewaydns.DefaultMaxInflightPerSession {
		t.Fatalf("session budget = %d fell below the unconfigured default %d", got, gatewaydns.DefaultMaxInflightPerSession)
	}

	query := new(mdns.Msg)
	query.SetQuestion("issue863-budget.example.test.", mdns.TypeA)
	scope := policy.Scope{SessionID: "issue863-budget", OwnershipEpoch: 1}
	var wg sync.WaitGroup
	for i := 0; i < want; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := srv.ServeDNSMessage(context.Background(), scope, query, false); err != nil {
				t.Errorf("admitted query failed: %v", err)
			}
		}()
	}
	for i := 0; i < want; i++ {
		select {
		case <-reached:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d concurrent queries were admitted", i, want)
		}
	}
	resp, err := srv.ServeDNSMessage(context.Background(), scope, query, false)
	if err != nil || resp == nil || resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("over-budget query: resp=%v err=%v want explicit SERVFAIL", resp, err)
	}
	if got := srv.AdmissionRejections(); got.PerSession != 1 || got.Global != 0 {
		t.Fatalf("over-budget refusal attribution = %+v want per_session=1 global=0", got)
	}
	close(block)
	wg.Wait()

	// A caller-configured budget stays exactly as configured, so a deployment that
	// deliberately bounds a session keeps that bound.
	custom := newServer(gatewaydns.ServerConfig{MaxInflightPerSession: 2, MaxTCPSessions: tcpSessions})
	custom.DeclareUDPProducers(8)
	if got := custom.SessionBudget(); got != 2 {
		t.Fatalf("configured per-session budget was raised to %d", got)
	}

	// The derivation is clamped to the global budget, so a session is never
	// refused by its own budget before the server-wide budget refuses it.
	clamped := newServer(gatewaydns.ServerConfig{MaxInflight: 6, MaxTCPSessions: 4})
	clamped.DeclareUDPProducers(4)
	if got := clamped.SessionBudget(); got != 6 {
		t.Fatalf("derived session budget = %d not clamped to the global budget 6", got)
	}
}

// TestIssue863_PolicyStatusReportsPanelOutcomes requires the panel-side counters
// to reach the operator-facing policy status: a queue drop the panel caused must
// be visible there while the upstream health fields stay upstream-only.
func TestIssue863_PolicyStatusReportsPanelOutcomes(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer func() { releaseOnce.Do(func() { close(release) }) }()
	var stall atomic.Bool
	up := issue863StartUpstreamWithStall(t, 0, release, &stall)
	env := issue863NewEnv(t, up)
	_, peer, ip, client, _ := env.addSession(1)

	env.sendQuery(peer, ip, 8000, "issue863-status-warm.example.test.", mdns.TypeA)
	if noerror, servfail, noReply := client.summary([]uint16{8000}, 10*time.Second); noerror != 1 || servfail != 0 || noReply != 0 {
		t.Fatalf("warm control: noerror=%d servfail=%d no_reply=%d", noerror, servfail, noReply)
	}
	healthy := env.svc.PolicyStatusSnapshot()
	if healthy.LastUpstream == "" || healthy.LastUpstreamFailure != "" {
		t.Fatalf("healthy upstream status precondition not met: %+v", healthy)
	}
	if healthy.DNSQueriesEnqueued != 1 || healthy.DNSQueriesDroppedQueueFull != 0 {
		t.Fatalf("healthy status accounting = %+v", healthy)
	}

	// Hold every worker, then overflow the bounded queue.
	stall.Store(true)
	for i := 0; i < defaultDNSWorkerCount; i++ {
		env.sendQuery(peer, ip, uint16(8100+i), fmt.Sprintf("issue863-status-prime%d.example.test.", i), mdns.TypeA)
	}
	deadline := time.Now().Add(10 * time.Second)
	for up.queries.Load() < int64(1+defaultDNSWorkerCount) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := up.queries.Load(); got != int64(1+defaultDNSWorkerCount) {
		t.Fatalf("workers were not held at the upstream: queries=%d", got)
	}
	for i := 0; i < defaultDNSQueueCap+defaultDNSWorkerCount+16; i++ {
		env.sendQuery(peer, ip, uint16(9000+i), fmt.Sprintf("issue863-status-full%d.example.test.", i), mdns.TypeA)
	}

	saturated := env.svc.PolicyStatusSnapshot()
	if saturated.DNSQueriesDroppedQueueFull == 0 {
		t.Fatalf("queue saturation is invisible in the operator status: %+v (private accounting=%+v)",
			saturated, env.handler().QueryAccounting())
	}
	if saturated.DNSQueriesEnqueued != env.handler().QueryAccounting().Enqueued {
		t.Fatalf("operator status enqueued=%d disagrees with the live handler", saturated.DNSQueriesEnqueued)
	}
	if saturated.LastUpstream != healthy.LastUpstream || saturated.LastUpstreamFailure != "" {
		t.Fatalf("panel saturation altered upstream health fields: before=%+v after=%+v", healthy, saturated)
	}
	releaseOnce.Do(func() { close(release) })
}

// TestIssue863_PolicyStatusReportsRefusalCauses requires both panel-origin
// refusal causes to be visible through the same status path, with custom positive
// budgets still enforced, and the counts to restart with the data path instead of
// presenting stale numbers.
//
// The two causes are isolated in their own data paths on purpose: with both a
// per-session and a server-wide limit close to the number of queries, which limit
// refuses a given query depends on arrival order, and a test that asserted one
// fixed split there would be flaky rather than wrong.
func TestIssue863_PolicyStatusReportsRefusalCauses(t *testing.T) {
	t.Run("per-session", func(t *testing.T) {
		release := make(chan struct{})
		var releaseOnce sync.Once
		defer func() { releaseOnce.Do(func() { close(release) }) }()
		up := issue863StartUpstream(t, 0, release)
		env := issue863NewEnvWithServerConfig(t, up, &gatewaydns.ServerConfig{
			MaxInflight:           16,
			MaxInflightPerSession: 2,
		})

		// Session A exceeds its own configured budget while the server keeps global
		// room, so exactly one of its queries is refused by the per-session cause.
		_, peer, ip, client, _ := env.addSession(1)
		for i := 0; i < 3; i++ {
			env.sendQuery(peer, ip, uint16(9200+i), fmt.Sprintf("issue863-refuse-a%d.example.test.", i), mdns.TypeA)
		}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if got := env.svc.PolicyStatusSnapshot().DNSRefusalsPerSession; got == 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		status := env.svc.PolicyStatusSnapshot()
		if status.DNSRefusalsPerSession != 1 || status.DNSRefusalsGlobal != 0 {
			t.Fatalf("operator status refusal attribution = %+v want per_session=1 global=0", status)
		}
		// The admitted queries are still inside the held exchange; the refusal was
		// written before any upstream attempt.
		releaseOnce.Do(func() { close(release) })
		if noerror, servfail, noReply := client.summary([]uint16{9200, 9201, 9202}, 10*time.Second); noerror != 2 || servfail != 1 || noReply != 0 {
			t.Fatalf("session over its own budget: noerror=%d servfail=%d no_reply=%d want 2/1/0", noerror, servfail, noReply)
		}
	})

	t.Run("global", func(t *testing.T) {
		release := make(chan struct{})
		var releaseOnce sync.Once
		defer func() { releaseOnce.Do(func() { close(release) }) }()
		up := issue863StartUpstream(t, 0, release)
		env := issue863NewEnvWithServerConfig(t, up, &gatewaydns.ServerConfig{
			MaxInflight:           2,
			MaxInflightPerSession: 4,
		})

		// One session takes the whole server budget and a second session, with its
		// own budget free, meets the server-wide limit. Which of the three queries
		// loses depends on arrival order; the cause does not.
		_, peerA, ipA, _, _ := env.addSession(1)
		for i := 0; i < 2; i++ {
			env.sendQuery(peerA, ipA, uint16(9300+i), fmt.Sprintf("issue863-refuse-g%d.example.test.", i), mdns.TypeA)
		}
		_, peerB, ipB, _, _ := env.addSession(2)
		env.sendQuery(peerB, ipB, 9400, "issue863-refuse-second-client.example.test.", mdns.TypeA)

		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if got := env.svc.PolicyStatusSnapshot().DNSRefusalsGlobal; got == 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		status := env.svc.PolicyStatusSnapshot()
		if status.DNSRefusalsGlobal != 1 || status.DNSRefusalsPerSession != 0 {
			t.Fatalf("operator status refusal attribution = %+v want global=1 per_session=0", status)
		}
		releaseOnce.Do(func() { close(release) })
		if got := up.queries.Load(); got != 2 {
			t.Fatalf("admitted queries reaching the upstream = %d want 2 (the server's whole budget)", got)
		}

		// The counts belong to the live data path: replacing it reports the new
		// path's zeros rather than leaving the operator with stale numbers. A
		// disable installs the continuity responder, which accepts this fixture's
		// loopback upstream only through the package's existing resolver
		// substitution point; a real deployment's upstreams are never loopback.
		originalContinuityResolver := newDNSContinuityResolver
		newDNSContinuityResolver = func(cfg gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
			cfg.AllowLoopbackUpstream = true
			return gatewaydns.NewUpstreamResolver(cfg)
		}
		defer func() { newDNSContinuityResolver = originalContinuityResolver }()
		if err := env.svc.TeardownPBR(); err != nil {
			t.Fatalf("TeardownPBR: %v", err)
		}
		reset := env.svc.PolicyStatusSnapshot()
		if reset.DNSRefusalsPerSession != 0 || reset.DNSRefusalsGlobal != 0 || reset.DNSQueriesEnqueued != 0 {
			t.Fatalf("panel accounting did not restart with the data path: %+v", reset)
		}
	})
}

// TestIssue863_ContinuityMixedTCPAndUDPProducers drives the continuity responder
// that serves issued profiles while policy routing is off. Its producer set is the
// same shape as the intercepted path's: four plain-UDP workers plus up to
// MaxTCPSessions TCP connections, one query in flight per connection. A session
// that presents the whole UDP pool while many TCP queries are inside their
// upstream exchange must still be admitted, so the same producer-bound rule has to
// reach this gateway too; otherwise the panel refuses a supported burst with a
// SERVFAIL that never reached the upstream.
func TestIssue863_ContinuityMixedTCPAndUDPProducers(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer func() { releaseOnce.Do(func() { close(release) }) }()
	up := issue863StartUpstream(t, 0, release)

	gwDNS := netip.MustParseAddr("10.100.0.1")
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 256)
	fwd.AttachBackendDevice(1, &mockPBRDevice{})
	svc := &Service{forwarder: fwd}
	upstreams := []policy.Upstream{{
		Address:   up.addr.Addr().String(),
		Port:      int(up.addr.Port()),
		Transport: policy.TransportPlain,
	}}

	// The continuity responder dials the operator's upstream list; this fixture
	// reaches a loopback upstream through the package's existing resolver seam.
	originalResolver := newDNSContinuityResolver
	newDNSContinuityResolver = func(cfg gatewaydns.ResolverConfig) (gatewaydns.Resolver, error) {
		cfg.AllowLoopbackUpstream = true
		return gatewaydns.NewUpstreamResolver(cfg)
	}
	defer func() { newDNSContinuityResolver = originalResolver }()
	svc.mu.Lock()
	svc.installDNSContinuityLocked(gwDNS, upstreams)
	svc.mu.Unlock()
	handler, ok := fwd.DNSHandler().(*dnsContinuityHandler)
	if !ok || handler == nil {
		t.Fatalf("continuity responder was not installed: %T", fwd.DNSHandler())
	}
	t.Cleanup(func() { _ = handler.Close() })

	// One client device, so the TCP half is a real DNS-over-TCP exchange rather
	// than a call into the server.
	const sid, peer, ip = "issue863-continuity", "issue863-continuity-peer", "10.100.0.92"
	stack, capture := issue863ClientNetstack(t, fwd, sid, "issue863-continuity-conn", peer, netip.MustParseAddr(ip))

	// Fill the TCP connection bound with queries held inside the upstream
	// exchange: one in flight per connection, as a client issuing TCP retries or
	// large-answer lookups does.
	const tcpQueries = 30
	tcpConns := make([]*mdns.Conn, 0, tcpQueries)
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelDial()
	for i := 0; i < tcpQueries; i++ {
		conn, err := stack.DialContextTCPAddrPort(dialCtx, netip.MustParseAddrPort("10.100.0.1:53"))
		if err != nil {
			t.Fatalf("dial continuity TCP %d: %v", i, err)
		}
		_ = conn.SetDeadline(time.Now().Add(90 * time.Second))
		dnsConn := &mdns.Conn{Conn: conn}
		query := new(mdns.Msg)
		query.SetQuestion(fmt.Sprintf("issue863-continuity-tcp%d.example.test.", i), mdns.TypeA)
		if err := dnsConn.WriteMsg(query); err != nil {
			t.Fatalf("write continuity TCP query %d: %v", i, err)
		}
		tcpConns = append(tcpConns, dnsConn)
	}

	deadline := time.Now().Add(30 * time.Second)
	for up.queries.Load() < int64(tcpQueries) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := up.queries.Load(); got != int64(tcpQueries) {
		t.Fatalf("TCP queries inside the upstream exchange = %d want %d", got, tcpQueries)
	}

	// The responder's whole plain-UDP pool now has work for the same session.
	udpIDs := make([]uint16, 0, dnsContinuityWorkerCount)
	for i := 0; i < dnsContinuityWorkerCount; i++ {
		id := uint16(7500 + i)
		udpIDs = append(udpIDs, id)
		issue863SendUDPQuery(t, fwd, peer, netip.MustParseAddr(ip), id,
			fmt.Sprintf("issue863-continuity-udp%d.example.test.", i), mdns.TypeA)
	}

	// Every supported producer must be admitted: the TCP connections plus the
	// whole UDP worker pool reach the healthy upstream, with no panel refusal.
	wantQueries := int64(tcpQueries + dnsContinuityWorkerCount)
	settle := time.Now().Add(5 * time.Second)
	for up.queries.Load() < wantQueries && time.Now().Before(settle) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := up.queries.Load(); got != wantQueries {
		t.Fatalf("continuity mixed burst reached the upstream with %d queries want %d; refusals=%+v",
			got, wantQueries, handler.gw.AdmissionRejections())
	}
	if got := handler.gw.AdmissionRejections(); got != (gatewaydns.AdmissionRejections{}) {
		t.Fatalf("continuity responder refused a supported mixed burst: %+v", got)
	}

	releaseOnce.Do(func() { close(release) })

	// The TCP half is a legitimate positive control: every held exchange answers.
	for i, dnsConn := range tcpConns {
		resp, err := dnsConn.ReadMsg()
		if err != nil {
			t.Fatalf("read continuity TCP response %d: %v", i, err)
		}
		if resp.Rcode != mdns.RcodeSuccess {
			t.Fatalf("continuity TCP response %d rcode=%d want success", i, resp.Rcode)
		}
		_ = dnsConn.Close()
	}
	noerror, servfail, noReply := capture.summary(udpIDs, 15*time.Second)
	if noerror != len(udpIDs) || servfail != 0 || noReply != 0 {
		t.Fatalf("continuity UDP burst: noerror=%d servfail=%d no_reply=%d want %d/0/0",
			noerror, servfail, noReply, len(udpIDs))
	}
}
