package vpn

import (
	"context"
	"net/netip"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	mdns "github.com/miekg/dns"
)

// dnsRuntimeTestHandler builds the production intercepted-DNS path (real gateway,
// real server, real route cache) over the caller's resolver and installs it on
// the forwarder exactly as the PBR configuration does.
func dnsRuntimeTestHandler(t *testing.T, cache *MemoryRouteCache, fwd *forwarder.Forwarder, resolver *mockPBRResolver) (*gatewaydns.Gateway, *pbrDNSHandler) {
	t.Helper()
	gwAddr := netip.MustParseAddrPort("10.100.0.1:53")
	srv, err := gatewaydns.NewServer(gatewaydns.ServerConfig{Gateway: gwAddr}, resolver, cache.PolicyMatcher())
	if err != nil {
		t.Fatalf("build dns server: %v", err)
	}
	gw, err := gatewaydns.NewGateway(gatewaydns.GatewayConfig{Gateway: gwAddr, RouteObserver: cache}, srv)
	if err != nil {
		t.Fatalf("build dns gateway: %v", err)
	}
	handler := newPBRDNSHandler(gw, cache, fwd.HasLiveSession)
	fwd.SetDNSHandler(handler)
	return gw, handler
}

// dnsRuntimeTestPacket builds a client→gateway DNS query packet for the default
// test peer address.
func dnsRuntimeTestPacket(t *testing.T, proto byte) []byte {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion("unlisted.example.", mdns.TypeA)
	body, err := req.Pack()
	if err != nil {
		t.Fatalf("pack dns query: %v", err)
	}
	src := netip.MustParseAddr("10.100.0.2")
	dst := netip.MustParseAddr("10.100.0.1")
	if proto == 6 {
		return buildTestPBRTCPPacket(src, dst, 40000, 53, body)
	}
	return buildTestPBRUDPPacket(src, dst, 40000, 53, body)
}

// waitForCondition polls cond until it holds or the deadline passes. It is used
// only for state a background owner advances (queued workers, context watchers);
// every decisive assertion of this file is made after such a join.
func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestDNSRuntimeRetirement_RefusesInFlightReplyAfterReplacement retires an
// authenticated session while its queued DNS query is blocked in the resolver,
// re-admits the same peer on the engine-shared ReturnPath, and then releases the
// resolver. The retired session's reply must never reach that path, and the
// session's runtime authority must be gone.
//
// The blocked resolver deliberately ignores its context cancellation and still
// returns a complete answer once released: cooperative abort alone is not the
// property under test, the final writer fence is.
func TestDNSRuntimeRetirement_RefusesInFlightReplyAfterReplacement(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)

	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var calls atomic.Int64
	resolver := &mockPBRResolver{exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		if calls.Add(1) == 1 {
			return resp, nil
		}
		entered <- ctx
		<-release
		return resp, nil
	}}
	gw, handler := dnsRuntimeTestHandler(t, cache, fwd, resolver)
	defer func() { _ = handler.Close() }()
	defer func() { _ = gw.Close() }()

	var writes atomic.Int64
	// One ReturnPath is shared across routing sessions by the production engine,
	// so the writer, not the path, must carry the session fence.
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		writes.Add(1)
		return len(p), nil
	})
	const peer, oldID, newID = "peer-dns-runtime", "sess-dns-old", "sess-dns-new"
	fwd.RegisterSessionWithReturnPath(oldID, "conn-old", peer, "10.100.0.2", 1, path)
	defer func() { fwd.BeginUnregisterSession(peer, newID).Wait() }()

	packet := dnsRuntimeTestPacket(t, 17)
	// Positive control: the same live session is answered through the queue.
	if handled, err := handler.HandleDNSPacket(oldID, peer, "10.100.0.2", path, packet); !handled || err != nil {
		t.Fatalf("live query was not accepted by the queued DNS consumer: handled=%v err=%v", handled, err)
	}
	waitForCondition(t, "live DNS answer", func() bool { return writes.Load() == 1 })

	// The queued worker's per-job unit, run with a join so the decisive
	// assertion below is made after this job has finished rather than raced
	// against the worker pool.
	jobDone := make(chan struct{})
	go func() {
		defer close(jobDone)
		handler.processJob(dnsJob{sessionID: oldID, peerKey: peer, assignedIP: "10.100.0.2", path: path, packet: packet})
	}()
	var resolveCtx context.Context
	select {
	case resolveCtx = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("resolver did not start")
	}

	// Retire the session while its query is still in flight, then re-admit the
	// same peer under a replacement session.
	fwd.BeginUnregisterSession(peer, oldID).Wait()
	if err := resolveCtx.Err(); err == nil {
		t.Error("retirement did not cancel the in-flight resolver context")
	}
	if n := handler.ActiveSessionRuntimes(); n != 0 {
		t.Errorf("retired session still owns %d DNS runtime(s)", n)
	}
	fwd.RegisterSessionWithReturnPath(newID, "conn-new", peer, "10.100.0.2", 1, path)

	close(release)
	select {
	case <-jobDone:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight DNS job did not finish after the resolver was released")
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("retired session's DNS reply reached the engine ReturnPath after replacement: writes=%d want only the live-session answer", got)
	}
}

// TestDNSRuntimeRetirement_ReclaimsRuntimeStateAcrossChurn drives valid gateway
// DNS through sequential admitted→answered→retired sessions and requires the
// server limiter entries, cleanup waiters and session runtimes to return to the
// active-session bound instead of accumulating per retired session.
func TestDNSRuntimeRetirement_ReclaimsRuntimeStateAcrossChurn(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	resolver := &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp, nil
	}}
	gw, handler := dnsRuntimeTestHandler(t, cache, fwd, resolver)
	defer func() { _ = handler.Close() }()
	defer func() { _ = gw.Close() }()

	var writes atomic.Int64
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		writes.Add(1)
		return len(p), nil
	})
	packet := dnsRuntimeTestPacket(t, 17)

	before := runtime.NumGoroutine()
	const churn = 200
	for i := 0; i < churn; i++ {
		sid := "sess-dns-churn-" + strconv.Itoa(i)
		fwd.RegisterSessionWithReturnPath(sid, "conn", "peer-dns-churn", "10.100.0.2", 1, path)
		// One synchronous queued job: the positive control is that every live
		// session is still answered.
		before := writes.Load()
		handler.processJob(dnsJob{sessionID: sid, peerKey: "peer-dns-churn", assignedIP: "10.100.0.2", path: path, packet: packet})
		if writes.Load() != before+1 {
			t.Fatalf("session %d: live DNS query was not answered", i)
		}
		if n := handler.ActiveSessionRuntimes(); n != 1 {
			t.Fatalf("session %d: handler owns %d runtime(s) want 1", i, n)
		}
		fwd.BeginUnregisterSession("peer-dns-churn", sid).Wait()
		if n := gw.ActiveSessionLimiters(); n != 0 {
			t.Fatalf("session %d retired but %d DNS limiter scope(s) remain", i, n)
		}
		if n := handler.ActiveSessionRuntimes(); n != 0 {
			t.Fatalf("session %d retired but %d DNS runtime(s) remain", i, n)
		}
		if n := cache.RouteCache().SessionCount(); n != 0 {
			t.Fatalf("session %d retired but %d policy scope(s) remain", i, n)
		}
	}
	// The per-session limiter waiters are goroutines; a retired session leaves
	// none of them behind.
	waitForCondition(t, "churn cleanup goroutines to exit", func() bool {
		return runtime.NumGoroutine() <= before+5
	})
}

// TestDNSRuntimeRetirement_PreservesLiveAnswerRekeyAndReplacement covers the
// legitimate paths the runtime must not break: a live session is answered, a
// same-session rekey keeps the runtime and retargets its writer, and a
// replacement session owns its own runtime after the previous one retires.
func TestDNSRuntimeRetirement_PreservesLiveAnswerRekeyAndReplacement(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	resolver := &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp, nil
	}}
	gw, handler := dnsRuntimeTestHandler(t, cache, fwd, resolver)
	defer func() { _ = handler.Close() }()
	defer func() { _ = gw.Close() }()

	const peer, sessionID = "peer-dns-live", "sess-dns-live"
	var onFirst, onSecond atomic.Int64
	first := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		onFirst.Add(1)
		return len(p), nil
	})
	second := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		onSecond.Add(1)
		return len(p), nil
	})
	packet := dnsRuntimeTestPacket(t, 17)

	fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", peer, "10.100.0.2", 1, first)
	defer func() { fwd.BeginUnregisterSession(peer, sessionID).Wait() }()

	// Live answer through the real queue.
	if handled, err := handler.HandleDNSPacket(sessionID, peer, "10.100.0.2", first, packet); !handled || err != nil {
		t.Fatalf("live query was not accepted: handled=%v err=%v", handled, err)
	}
	waitForCondition(t, "live DNS answer", func() bool { return onFirst.Load() == 1 })
	if n := handler.ActiveSessionRuntimes(); n != 1 {
		t.Fatalf("live session owns %d DNS runtime(s) want 1", n)
	}

	// Same-session rekey: the route is replaced on the same authenticated
	// session, so its DNS runtime must survive and follow the new path.
	retirement, err := fwd.TryRegisterSessionWithReturnPath(sessionID, "conn-2", peer, "10.100.0.2", 1, 0, 0, second)
	if err != nil {
		t.Fatalf("same-session rekey failed: %v", err)
	}
	retirement.Wait()
	if n := handler.ActiveSessionRuntimes(); n != 1 {
		t.Fatalf("same-session rekey left %d DNS runtime(s) want 1", n)
	}
	handler.processJob(dnsJob{sessionID: sessionID, peerKey: peer, assignedIP: "10.100.0.2", path: second, packet: packet})
	if got := onSecond.Load(); got != 1 {
		t.Fatalf("query after rekey wrote to the new path %d time(s) want 1", got)
	}
	if got := onFirst.Load(); got != 1 {
		t.Fatalf("query after rekey also wrote to the stale path: total=%d", got)
	}

	// Replacement session: the previous session retires, the new one owns the
	// only runtime and answers on the shared path.
	const replacementID = "sess-dns-replacement"
	replacement := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) {
		return len(p), nil
	})
	replaceRetirement, err := fwd.TryRegisterSessionWithReturnPath(replacementID, "conn-3", peer, "10.100.0.2", 1, 0, 0, replacement)
	if err != nil {
		t.Fatalf("replacement registration failed: %v", err)
	}
	replaceRetirement.Wait()
	defer func() { fwd.BeginUnregisterSession(peer, replacementID).Wait() }()
	if n := handler.ActiveSessionRuntimes(); n != 0 {
		t.Fatalf("replaced session still owns %d DNS runtime(s)", n)
	}
	handler.processJob(dnsJob{sessionID: replacementID, peerKey: peer, assignedIP: "10.100.0.2", path: replacement, packet: packet})
	if n := handler.ActiveSessionRuntimes(); n != 1 {
		t.Fatalf("replacement session owns %d DNS runtime(s) want 1", n)
	}
	// The replaced session's runtime is retired: its late work is refused, and
	// its DNS state is not reused for the replacement.
	if got := onSecond.Load(); got != 1 {
		t.Fatalf("replaced session's DNS runtime was reused: writes=%d", got)
	}
}

// TestDNSRuntimeRetirement_BulkRetirementCancelsRuntime covers the bulk
// route-removal paths: every retired session's DNS runtime and limiter entry
// must be released, not only its policy scope.
func TestDNSRuntimeRetirement_BulkRetirementCancelsRuntime(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	resolver := &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp, nil
	}}
	gw, handler := dnsRuntimeTestHandler(t, cache, fwd, resolver)
	defer func() { _ = handler.Close() }()
	defer func() { _ = gw.Close() }()

	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	packet := dnsRuntimeTestPacket(t, 17)
	sessions := []string{"sess-dns-bulk-a", "sess-dns-bulk-b", "sess-dns-bulk-c"}
	for _, sid := range sessions {
		fwd.RegisterSessionWithReturnPath(sid, "conn", "peer-"+sid, "10.100.0.2", 1, path)
		handler.processJob(dnsJob{sessionID: sid, peerKey: "peer-" + sid, assignedIP: "10.100.0.2", path: path, packet: packet})
	}
	if n := handler.ActiveSessionRuntimes(); n != len(sessions) {
		t.Fatalf("bulk positive control owns %d DNS runtime(s) want %d", n, len(sessions))
	}
	if n := gw.ActiveSessionLimiters(); n != len(sessions) {
		t.Fatalf("bulk positive control holds %d limiter scope(s) want %d", n, len(sessions))
	}

	if err := fwd.RetireRoutesByReturnPath(path)(context.Background()); err != nil {
		t.Fatalf("bulk retirement: %v", err)
	}
	if n := handler.ActiveSessionRuntimes(); n != 0 {
		t.Fatalf("bulk retirement left %d DNS runtime(s)", n)
	}
	if n := gw.ActiveSessionLimiters(); n != 0 {
		t.Fatalf("bulk retirement left %d limiter scope(s)", n)
	}

	// Forwarder shutdown path.
	fwd.RegisterSession("sess-dns-all", "conn", "peer-dns-all", "10.100.0.2", 1)
	handler.processJob(dnsJob{sessionID: "sess-dns-all", peerKey: "peer-dns-all", assignedIP: "10.100.0.2", path: path, packet: packet})
	if n := handler.ActiveSessionRuntimes(); n != 1 {
		t.Fatalf("shutdown positive control owns %d DNS runtime(s) want 1", n)
	}
	if err := fwd.RetireAllRoutes()(context.Background()); err != nil {
		t.Fatalf("retire all routes: %v", err)
	}
	if n := handler.ActiveSessionRuntimes(); n != 0 {
		t.Fatalf("RetireAllRoutes left %d DNS runtime(s)", n)
	}
}

// TestDNSRuntimeRetirement_ReleasesGatewayTransport requires the per-session TCP
// DNS transport, which the gateway owns, to be released when the authenticated
// session retires.
func TestDNSRuntimeRetirement_ReleasesGatewayTransport(t *testing.T) {
	cache := sessionScopeTestCache(t)
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetRouteCache(cache)
	resolver := &mockPBRResolver{exchange: func(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		return resp, nil
	}}
	gw, handler := dnsRuntimeTestHandler(t, cache, fwd, resolver)
	defer func() { _ = handler.Close() }()
	defer func() { _ = gw.Close() }()

	const peer, sessionID = "peer-dns-tcp", "sess-dns-tcp"
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	fwd.RegisterSessionWithReturnPath(sessionID, "conn", peer, "10.100.0.2", 1, path)

	handler.processJob(dnsJob{sessionID: sessionID, peerKey: peer, assignedIP: "10.100.0.2", path: path, packet: dnsRuntimeTestPacket(t, 6)})
	if n := gw.ActiveTransports(); n != 1 {
		t.Fatalf("TCP DNS positive control opened %d gateway transport(s) want 1", n)
	}

	fwd.BeginUnregisterSession(peer, sessionID).Wait()
	// Transport teardown runs in the watcher that owns it, so it is joined by a
	// bounded wait rather than assumed synchronous.
	waitForCondition(t, "retired session's gateway transport to be released", func() bool {
		return gw.ActiveTransports() == 0
	})
	if n := gw.ActiveSessionLimiters(); n != 0 {
		t.Fatalf("retired TCP session left %d limiter scope(s)", n)
	}
	if n := handler.ActiveSessionRuntimes(); n != 0 {
		t.Fatalf("retired TCP session left %d DNS runtime(s)", n)
	}
}
