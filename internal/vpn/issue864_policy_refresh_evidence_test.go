package vpn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestIssue864UnchangedRefreshPreservesGeneration is the consumer oracle for the
// policy refresh contract.
//
// A published generation is what the forwarder stamps on the flows it records, so
// a scheduled refresh that republishes identical rules under a new generation
// changes what those flows report without changing what they route. The
// equivalence gate internal/policy/equivalence.go owns that decision; this test
// pins its two outcomes against a real policy.Syncer over a real FileStore and
// Matcher, and the fixture TLS listener. Only TLS trust and the approved-IP/dial
// pair are substituted, exactly as the existing policy fixtures do.
func TestIssue864UnchangedRefreshPreservesGeneration(t *testing.T) {
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
	ctx := context.Background()

	first, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if !first.Published {
		t.Fatal("initial sync did not publish")
	}

	// A refresh whose rules are unchanged (the upstream answers 304) must keep the
	// generation the flows are stamped with.
	second, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("unchanged refresh: %v", err)
	}
	sourceID := cfg.Sources[0].ID
	if !second.SourceStats[sourceID].NotModified {
		t.Fatalf("fixture did not answer 304 for the unchanged refresh: %+v", second.SourceStats)
	}
	if second.GenerationID != first.GenerationID {
		t.Fatalf("unchanged refresh published generation %q over %q", second.GenerationID, first.GenerationID)
	}
	if live := matcher.Current(); live == nil || live.Generation() != first.GenerationID {
		t.Fatalf("live snapshot generation = %v, want the retained %q", live, first.GenerationID)
	}

	// The control: a genuine rule change publishes a new generation, so the
	// retention cannot freeze the policy.
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
	live := matcher.Current()
	if live == nil {
		t.Fatal("no live snapshot after the changed refresh")
	}
	if live.Generation() != third.GenerationID {
		t.Errorf("live snapshot generation = %q, want the published %q", live.Generation(), third.GenerationID)
	}
	if !live.MatchDomain("added-after-refresh.example.com") {
		t.Error("live snapshot does not carry the added rule")
	}
}
