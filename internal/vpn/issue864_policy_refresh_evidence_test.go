package vpn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestIssue864UnchangedRefreshPreservesRoutingEvidence is the consumer oracle for
// the policy refresh contract.
//
// The forwarder decides a new flow from the client's DNS evidence: an address the
// session legitimately resolved as DIRECT is routed direct, and a missing entry
// takes the fail-closed PROXY path. That evidence is keyed on the policy
// generation, and the cache adapter below is the only writer of the generation the
// evidence is compared against. So a scheduled refresh that re-publishes identical
// rules silently discards it.
//
// The oracle drives the real adapter (MemoryRouteCache), the real policy.RouteCache
// behind it, a real policy.Syncer over a real FileStore and Matcher, and the
// fixture TLS listener. Only TLS trust and the approved-IP/dial pair are
// substituted, exactly as the existing policy fixtures do.
func TestIssue864UnchangedRefreshPreservesRoutingEvidence(t *testing.T) {
	var body atomic.Pointer[[]string]
	var etag atomic.Pointer[string]
	initial := domainList("policy", 20)
	body.Store(&initial)
	v1 := `"list-v1"`
	etag.Store(&v1)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == *etag.Load() {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", *etag.Load())
		for _, domain := range *body.Load() {
			fmt.Fprintln(w, domain)
		}
	}))
	defer server.Close()

	settings := policyListSettings(t)
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}

	cache := NewMemoryRouteCache()
	cache.AttachMatcher(matcher)
	ctx := context.Background()

	first, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !first.Published {
		t.Fatal("initial sync did not publish")
	}

	// The evidence a DNS observation records for a name the list does not cover:
	// the address was resolved directly, so new flows to it must stay direct.
	const session = "session-refresh-evidence"
	evidence := netip.MustParseAddr("93.184.216.34")
	if got := cache.Lookup(session, evidence); got != policy.Unknown {
		t.Fatalf("precondition: a fresh session answered %v for the evidence address, want UNKNOWN", got)
	}
	cache.Observe(session, evidence, policy.Direct)
	if got := cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("precondition: recorded evidence answered %v, want DIRECT", got)
	}

	// A refresh whose rules are unchanged (the upstream answers 304) must keep the
	// generation, and therefore the session's evidence.
	second, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("unchanged refresh: %v", err)
	}
	sourceID := cfg.Sources[0].ID
	if !second.SourceStats[sourceID].NotModified {
		t.Fatalf("fixture did not answer 304 for the unchanged refresh: %+v", second.SourceStats)
	}
	// Assert the harm before the mechanism, so a failing run shows what the client
	// loses rather than only that an identifier changed.
	if got := cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("unchanged refresh discarded the session's DIRECT evidence (lookup answered %v): new flows fall back to the fail-closed PROXY path (generation %q -> %q)",
			got, first.GenerationID, second.GenerationID)
	}
	if second.GenerationID != first.GenerationID {
		t.Fatalf("unchanged refresh published generation %q over %q", second.GenerationID, first.GenerationID)
	}

	// The control: a genuine rule change publishes a new generation, and the same
	// evidence is then correctly invalidated instead of being reused.
	grown := append(domainList("policy", 20), "added-after-refresh.example.com")
	body.Store(&grown)
	v2 := `"list-v2"`
	etag.Store(&v2)

	third, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("changed refresh: %v", err)
	}
	if third.GenerationID == second.GenerationID {
		t.Fatalf("a genuine rule change retained generation %q", second.GenerationID)
	}
	if got := cache.Lookup(session, evidence); got != policy.Unknown {
		t.Fatalf("changed rules kept the session's evidence (lookup answered %v), want UNKNOWN", got)
	}
}
