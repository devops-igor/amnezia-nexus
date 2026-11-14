package vpn

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

// sessionScopeTestCache builds the production MemoryRouteCache over a real policy
// matcher: the protected name resolves PROXY, every other public name DIRECT.
func sessionScopeTestCache(t *testing.T) *MemoryRouteCache {
	t.Helper()
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("protected.example\n"), policy.Source{
		ID:             "session-scope",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	src := policy.NewMemorySource("session-scope", rules)
	snap, err := policy.CompileSnapshot(1, "gen-session-scope", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		t.Fatalf("compile policy snapshot: %v", err)
	}
	matcher := policy.NewMatcher()
	matcher.Publish(snap)
	cache := NewMemoryRouteCache()
	cache.AttachMatcher(matcher)
	return cache
}

// sessionScopeTestAnswer is a trusted DNS answer for a name the policy does not
// protect, which yields DIRECT evidence.
func sessionScopeTestAnswer(t *testing.T) (*mdns.Msg, *mdns.Msg, netip.Addr) {
	t.Helper()
	ip := netip.MustParseAddr("93.184.216.34")
	req := new(mdns.Msg)
	req.SetQuestion("unlisted.example.", mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: "unlisted.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   ip.AsSlice(),
	}}
	return req, resp, ip
}

// sessionScopeTestGateway builds the production DNS gateway over a deterministic
// in-process resolver, so a queued job can be driven through the real
// submit -> resolve -> observe path without touching the network.
func sessionScopeTestGateway(t *testing.T, cache *MemoryRouteCache) *gatewaydns.Gateway {
	t.Helper()
	_, _, ip := sessionScopeTestAnswer(t)
	resolver := &mockPBRResolver{
		exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			if len(req.Question) > 0 {
				resp.Answer = []mdns.RR{&mdns.A{
					Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
					A:   ip.AsSlice(),
				}}
			}
			return resp, nil
		},
	}
	srv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{
		Gateway: netip.MustParseAddrPort("10.100.0.1:53"),
	}, resolver, cache.PolicyMatcher())
	if err != nil {
		t.Fatalf("build dns server: %v", err)
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{
		Gateway:       netip.MustParseAddrPort("10.100.0.1:53"),
		RouteObserver: cache,
	}, srv)
	if err != nil {
		t.Fatalf("build dns gateway: %v", err)
	}
	return gw
}

// TestSessionScopeRetirement_SequentialChurnBeyondCapacity drives admit -> observe
// -> retire more times than the default cache capacity, with at most one session
// admitted at a time, and requires the next session to still acquire DIRECT
// evidence. Retirement must release capacity for every session, not defer it to
// expiry or a policy refresh.
func TestSessionScopeRetirement_SequentialChurnBeyondCapacity(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	req, resp, ip := sessionScopeTestAnswer(t)

	const churn = 200 // default policy.RouteCache session capacity is 128.
	for i := 1; i <= churn; i++ {
		sid := fmt.Sprintf("sess-churn-%d", i)
		fwd.RegisterSession(sid, "conn-1", "peer-1", "10.100.0.2", 1)
		if !fwd.HasLiveSession(sid) {
			t.Fatalf("session %d: registered route is not reported live", i)
		}
		if err := cache.ObserveDNSResponse(sid, req, resp); err != nil {
			t.Fatalf("session %d: observation failed: %v", i, err)
		}
		if got := cache.Lookup(sid, ip); got != policy.Direct {
			t.Fatalf("session %d positive control: got %v want DIRECT", i, got)
		}
		fwd.BeginUnregisterSession("peer-1", sid).Wait()
		if n := cache.RouteCache().SessionCount(); n != 0 {
			t.Fatalf("session %d retired but %d scope(s) remain admitted; retirement must reclaim capacity", i, n)
		}
		if got := cache.Lookup(sid, ip); got != policy.Unknown {
			t.Fatalf("session %d retired: lookup returned %v want UNKNOWN", i, got)
		}
	}

	sid := "sess-churn-next"
	fwd.RegisterSession(sid, "conn-1", "peer-1", "10.100.0.2", 1)
	defer func() { fwd.BeginUnregisterSession("peer-1", sid).Wait() }()
	if err := cache.ObserveDNSResponse(sid, req, resp); err != nil {
		t.Fatalf("after %d sequentially retired sessions the next trusted observation failed: %v", churn, err)
	}
	if got := cache.Lookup(sid, ip); got != policy.Direct {
		t.Fatalf("after %d sequentially retired sessions the next session got %v want DIRECT", churn, got)
	}
}

// TestSessionScopeRetirement_LateDNSWorkCannotResurrectScope covers the delayed
// consumers of a released scope: an ordinary lookup, a queued DNS job that runs
// after retirement, a job overtaken by retirement during its own allocation, and
// the production queued-job entry point.
func TestSessionScopeRetirement_LateDNSWorkCannotResurrectScope(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	req, resp, ip := sessionScopeTestAnswer(t)

	const peer = "peer-late"
	retiredID := "sess-late-retired"
	fwd.RegisterSession(retiredID, "conn-1", peer, "10.100.0.2", 1)
	if err := cache.ObserveDNSResponse(retiredID, req, resp); err != nil {
		t.Fatalf("observation before retirement: %v", err)
	}
	fwd.BeginUnregisterSession(peer, retiredID).Wait()
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("retirement left %d scope(s) admitted", n)
	}

	// (a) An ordinary lookup for a retired session must not allocate again.
	if got := cache.Lookup(retiredID, ip); got != policy.Unknown {
		t.Fatalf("lookup for a retired session returned %v want UNKNOWN", got)
	}
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("lookup recreated %d scope(s) for a retired session", n)
	}

	// (b) A queued job that runs after retirement resolves no scope.
	if sc := cache.SessionScopeForLiveSession(retiredID, fwd.HasLiveSession); sc != nil {
		t.Fatalf("queued work resolved a scope for a retired session")
	}
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("queued work recreated %d scope(s) for a retired session", n)
	}

	// (c) A job that passes the liveness check and is then overtaken by the
	// retirement must not keep the scope it allocated.
	calls := 0
	overtaken := func(string) bool {
		calls++
		return calls == 1
	}
	if sc := cache.SessionScopeForLiveSession(retiredID, overtaken); sc != nil {
		t.Fatalf("allocation overtaken by retirement still returned a scope")
	}
	if calls < 2 {
		t.Fatalf("allocation was not re-checked against retirement: %d liveness check(s)", calls)
	}
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("retirement raced allocation and left %d scope(s) admitted", n)
	}

	// (d) The production queued-job path drops the late job and counts it, even
	// when the job carries a fully valid DNS query and usable return path.
	query := new(mdns.Msg)
	query.SetQuestion("unlisted.example.", mdns.TypeA)
	queryBytes, err := query.Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}
	var replies [][]byte
	path := forwarder.NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		replies = append(replies, append([]byte(nil), packet...))
		return len(packet), nil
	})
	gatewayIP := netip.MustParseAddr("10.100.0.1")
	queryPacket := buildTestPBRUDPPacket(netip.MustParseAddr("10.100.0.2"), gatewayIP, 40000, 53, queryBytes)

	handler := newPBRDNSHandler(sessionScopeTestGateway(t, cache), cache, fwd.HasLiveSession)
	defer func() { _ = handler.Close() }()
	handler.processJob(dnsJob{sessionID: retiredID, peerKey: peer, assignedIP: "10.100.0.2", path: path, packet: queryPacket})
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("late queued DNS job recreated %d scope(s)", n)
	}
	if got := handler.retired.Load(); got != 1 {
		t.Fatalf("late queued DNS job drop accounting: got %d want 1", got)
	}
	if len(replies) != 0 {
		t.Fatalf("late queued DNS job wrote %d reply packet(s) for a retired session", len(replies))
	}

	// Positive control: the same entry point resolves and returns a real answer
	// for a live session, and the answer becomes DIRECT evidence in its scope.
	liveID := "sess-late-live"
	fwd.RegisterSessionWithReturnPath(liveID, "conn-2", peer, "10.100.0.2", 1, path)
	defer func() { fwd.BeginUnregisterSession(peer, liveID).Wait() }()
	handler.processJob(dnsJob{sessionID: liveID, peerKey: peer, assignedIP: "10.100.0.2", path: path, packet: queryPacket})
	if n := cache.RouteCache().SessionCount(); n != 1 {
		t.Fatalf("live queued DNS job admitted %d scope(s) want 1", n)
	}
	if got := handler.retired.Load(); got != 1 {
		t.Fatalf("live queued DNS job was counted as retired: %d", got)
	}
	if len(replies) != 1 {
		t.Fatalf("live queued DNS job wrote %d reply packet(s) want 1", len(replies))
	}
	if got := cache.Lookup(liveID, ip); got != policy.Direct {
		t.Fatalf("live queued DNS job recorded %v evidence want DIRECT", got)
	}
}

// TestSessionScopeRetirement_ReplacementPreservesNewSessionScope requires a
// replacement session to keep its own scope and evidence across the old
// session's delayed teardown and a rekey of the same session.
func TestSessionScopeRetirement_ReplacementPreservesNewSessionScope(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	req, resp, ip := sessionScopeTestAnswer(t)

	const peer = "peer-replace"
	oldID, newID := "sess-replace-old", "sess-replace-new"

	fwd.RegisterSession(oldID, "conn-1", peer, "10.100.0.2", 1)
	if err := cache.ObserveDNSResponse(oldID, req, resp); err != nil {
		t.Fatalf("old session observation: %v", err)
	}
	if got := cache.Lookup(oldID, ip); got != policy.Direct {
		t.Fatalf("old session positive control: got %v want DIRECT", got)
	}

	retirement, err := fwd.TryRegisterSessionWithLimit(newID, "conn-2", peer, "10.100.0.2", 1, 0, 0)
	if err != nil {
		t.Fatalf("replacement registration failed: %v", err)
	}
	retirement.Wait()
	if got := cache.Lookup(oldID, ip); got != policy.Unknown {
		t.Fatalf("replaced session kept evidence: got %v want UNKNOWN", got)
	}
	if err := cache.ObserveDNSResponse(newID, req, resp); err != nil {
		t.Fatalf("replacement session observation: %v", err)
	}
	if got := cache.Lookup(newID, ip); got != policy.Direct {
		t.Fatalf("replacement session evidence: got %v want DIRECT", got)
	}

	// A delayed teardown of the old session must not touch its replacement.
	fwd.BeginUnregisterSession(peer, oldID).Wait()
	if !fwd.HasLiveSession(newID) {
		t.Fatalf("delayed old-session teardown removed the replacement route")
	}
	if got := cache.Lookup(newID, ip); got != policy.Direct {
		t.Fatalf("delayed old-session teardown removed the replacement evidence: got %v", got)
	}

	// A rekey re-registers the same session and must preserve its evidence.
	rekey, err := fwd.TryRegisterSessionWithLimit(newID, "conn-3", peer, "10.100.0.2", 1, 0, 0)
	if err != nil {
		t.Fatalf("rekey registration failed: %v", err)
	}
	rekey.Wait()
	if got := cache.Lookup(newID, ip); got != policy.Direct {
		t.Fatalf("rekey of the same session discarded its evidence: got %v", got)
	}
	if n := cache.RouteCache().SessionCount(); n != 1 {
		t.Fatalf("replacement lifecycle admitted %d scope(s) want 1", n)
	}

	fwd.BeginUnregisterSession(peer, newID).Wait()
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("retirement of the replacement left %d scope(s) admitted", n)
	}
}

// TestSessionScopeRetirement_BulkRetirementReleasesScopes covers the bulk
// retirement paths the ingress engine uses when it stops owning routes.
func TestSessionScopeRetirement_BulkRetirementReleasesScopes(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	req, resp, ip := sessionScopeTestAnswer(t)

	path := forwarder.NewReturnPath(func(_, _ string, _ []byte) (int, error) { return 0, nil })
	owned := []string{"sess-bulk-a", "sess-bulk-b", "sess-bulk-c"}
	for i, sid := range owned {
		fwd.RegisterSessionWithReturnPath(sid, fmt.Sprintf("conn-%d", i), fmt.Sprintf("peer-%d", i), "10.100.0.2", 1, path)
		if err := cache.ObserveDNSResponse(sid, req, resp); err != nil {
			t.Fatalf("session %s observation: %v", sid, err)
		}
		if got := cache.Lookup(sid, ip); got != policy.Direct {
			t.Fatalf("session %s positive control: got %v want DIRECT", sid, got)
		}
	}
	if n := cache.RouteCache().SessionCount(); n != len(owned) {
		t.Fatalf("bulk positive control admitted %d scope(s) want %d", n, len(owned))
	}

	wait := fwd.RetireRoutesByReturnPath(path)
	if err := wait(context.Background()); err != nil {
		t.Fatalf("bulk retirement wait: %v", err)
	}
	for _, sid := range owned {
		if fwd.HasLiveSession(sid) {
			t.Fatalf("session %s still reported live after bulk retirement", sid)
		}
		if got := cache.Lookup(sid, ip); got != policy.Unknown {
			t.Fatalf("session %s kept evidence after bulk retirement: got %v", sid, got)
		}
	}
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("bulk retirement left %d scope(s) admitted", n)
	}

	// RetireAllRoutes (forwarder shutdown) must release scopes as well.
	unmanaged := []string{"sess-all-a", "sess-all-b"}
	for i, sid := range unmanaged {
		fwd.RegisterSession(sid, fmt.Sprintf("conn-%d", i), fmt.Sprintf("peer-all-%d", i), "10.100.0.2", 1)
		if err := cache.ObserveDNSResponse(sid, req, resp); err != nil {
			t.Fatalf("session %s observation: %v", sid, err)
		}
	}
	if n := cache.RouteCache().SessionCount(); n != len(unmanaged) {
		t.Fatalf("shutdown positive control admitted %d scope(s) want %d", n, len(unmanaged))
	}
	if err := fwd.RetireAllRoutes()(context.Background()); err != nil {
		t.Fatalf("retire all routes wait: %v", err)
	}
	if n := cache.RouteCache().SessionCount(); n != 0 {
		t.Fatalf("RetireAllRoutes left %d scope(s) admitted", n)
	}
}
