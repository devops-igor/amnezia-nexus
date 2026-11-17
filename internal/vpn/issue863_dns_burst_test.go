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

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

// issue863Upstream is a loopback UDP DNS upstream whose latency and stall are
// controlled by the test, so a "healthy upstream" is a real network exchange.
type issue863Upstream struct {
	addr    netip.AddrPort
	queries atomic.Int64
	release <-chan struct{}
	latency time.Duration
}

func issue863StartUpstream(t *testing.T, latency time.Duration, release <-chan struct{}) *issue863Upstream {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	up := &issue863Upstream{latency: latency, release: release}
	srv := &mdns.Server{PacketConn: conn, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		up.queries.Add(1)
		if up.release != nil {
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
	})
	if err != nil {
		t.Fatalf("build upstream resolver: %v", err)
	}
	gw := initDNSGateway(gwDNS, matcher, rc, resolver)
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
	query := new(mdns.Msg)
	query.SetQuestion(name, qtype)
	query.Id = id
	body, err := query.Pack()
	if err != nil {
		e.t.Fatalf("pack query %s: %v", name, err)
	}
	packet := buildTestPBRUDPPacket(ip, netip.MustParseAddr("10.100.0.1"), 40000+id, 53, body)
	if err := e.fwd.RouteClientToBackend(peer, packet); err != nil {
		e.t.Fatalf("RouteClientToBackend(%s): %v", name, err)
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
