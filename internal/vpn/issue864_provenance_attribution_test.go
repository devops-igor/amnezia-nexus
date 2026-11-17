package vpn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// TestIssue864AttributionOnlyMoveAfterRestartInvalidatesEvidence is the consumer
// oracle for the durable attribution criterion.
//
// Two lists supply the same merged rules; one domain and one prefix move from
// the first list to the second. Routing cannot change, because every rule is
// still supplied by someone. What does change is which list an explanation names,
// and the generation the session's route evidence is keyed on — so a restart that
// followed by such a move must publish a new generation and the evidence recorded
// under the old one must be invalidated, exactly as for any other genuine change.
//
// The subjects are real: MemoryRouteCache, the policy.RouteCache behind it, a real
// policy.Syncer over a real FileStore and Matcher, and the production settings
// path that turns two custom URLs into two sources.
func TestIssue864AttributionOnlyMoveAfterRestartInvalidatesEvidence(t *testing.T) {
	var mu sync.Mutex
	bodies := map[string]string{
		"/a.lst": "shared.example.com\nalpha.example.com\n198.51.100.0/24\n",
		"/b.lst": "beta.example.com\n203.0.113.0/24\n",
	}
	etags := map[string]string{"/a.lst": `"a1"`, "/b.lst": `"b1"`}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body, known := bodies[r.URL.Path]
		etag := etags[r.URL.Path]
		mu.Unlock()
		if !known {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", etag)
		_, _ = fmt.Fprint(w, body)
	}))
	defer server.Close()

	settings := policy.DefaultSettings()
	settings.Enabled = true
	settings.Preset = policy.PresetCustom
	settings.CustomURLs = []string{
		"https://audit-shared.example/a.lst",
		"https://audit-shared.example/b.lst",
	}
	if err := settings.Validate(); err != nil {
		t.Fatalf("fixture settings are invalid: %v", err)
	}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if len(cfg.Sources) != 2 {
		t.Fatalf("fixture produced %d sources, want 2", len(cfg.Sources))
	}
	fetch, store := fixtureFetcherAndStore(t, server, cfg)
	ctx := context.Background()

	matcher := policy.NewMatcher()
	syncer, err := policy.NewSyncer(matcher, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer: %v", err)
	}
	cache := NewMemoryRouteCache()

	first, err := syncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("initial sync: published=%v err=%v", first.Published, err)
	}
	// Attach after the first publication, so the adapter starts on the published
	// generation instead of clearing evidence it never stored.
	cache.AttachMatcher(matcher)
	seedSnap := matcher.Current()
	seedMatch, ok := seedSnap.ExplainDomain("shared.example.com")
	if !ok || !reflect.DeepEqual(seedMatch.Contributors, []string{"custom-1"}) {
		t.Fatalf("seed attribution = %+v, want custom-1", seedMatch)
	}

	const session = "session-attribution-move"
	evidence := netip.MustParseAddr("93.184.216.34")
	cache.Observe(session, evidence, policy.Direct)
	if got := cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("precondition: recorded evidence answered %v, want DIRECT", got)
	}
	beforeStats := [2]int{seedSnap.DomainCount(), seedSnap.CIDRCount()}

	// The same merged rules, with the domain and the prefix supplied by the
	// second list instead of the first.
	mu.Lock()
	bodies["/a.lst"] = "alpha.example.com\n"
	etags["/a.lst"] = `"a2"`
	bodies["/b.lst"] = "beta.example.com\nshared.example.com\n198.51.100.0/24\n203.0.113.0/24\n"
	etags["/b.lst"] = `"b2"`
	mu.Unlock()

	// Restart: a fresh matcher and syncer over the durable store, as activation
	// rebuilds them. The baseline is primed from durable state, so the syncer has
	// no memory of the previous per-source rules.
	restarted := policy.NewMatcher()
	restartedSyncer, err := policy.NewSyncer(restarted, fetch, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer after restart: %v", err)
	}
	if baseline, err := restartedSyncer.PrimeBaseline(ctx); err != nil || baseline != policy.BaselinePrimed {
		t.Fatalf("PrimeBaseline: status=%v err=%v", baseline, err)
	}
	cache.AttachMatcher(restarted)

	// Priming the baseline replays the same generation, so the evidence must
	// still be there: only a real change may discard it.
	if got := cache.Lookup(session, evidence); got != policy.Direct {
		t.Fatalf("priming the durable baseline discarded the session's evidence (lookup answered %v)", got)
	}

	second, err := restartedSyncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("post-restart refresh: %v", err)
	}
	if !second.Published {
		t.Fatal("post-restart refresh did not establish the live policy")
	}

	// Routing is identical: the merged rules did not change, only their origin.
	snap := restarted.Current()
	if snap.DomainCount() != beforeStats[0] || snap.CIDRCount() != beforeStats[1] {
		t.Fatalf("merged rule counts changed from %v to %d/%d; this fixture must not change routing",
			beforeStats, snap.DomainCount(), snap.CIDRCount())
	}
	for _, name := range []string{"shared.example.com", "alpha.example.com", "beta.example.com"} {
		if !seedSnap.MatchDomain(name) || !snap.MatchDomain(name) {
			t.Fatalf("%q stopped matching across an attribution-only move", name)
		}
	}
	if seedSnap.MatchDomain("unlisted.example.com") || snap.MatchDomain("unlisted.example.com") {
		t.Fatal("a rule the lists never contained matches after the move")
	}
	if !snap.MatchIPv4(netip.MustParseAddr("198.51.100.1")) || !snap.MatchIPv4(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("a prefix the lists still contain no longer matches after the move")
	}

	// The contract: a moved attribution is a new generation, so the session's
	// evidence recorded under the old one is invalidated rather than reused.
	if second.GenerationID == first.GenerationID {
		t.Fatalf("an attribution-only move after a restart retained generation %q; the explanation would name the previous list and the route evidence would outlive the attribution it was recorded under",
			first.GenerationID)
	}
	if got := cache.Lookup(session, evidence); got != policy.Unknown {
		t.Fatalf("attribution-only move kept the session's evidence (lookup answered %v), want UNKNOWN", got)
	}

	// The current attribution is the one the live snapshot reports.
	movedMatch, ok := snap.ExplainDomain("shared.example.com")
	if !ok || !reflect.DeepEqual(movedMatch.Contributors, []string{"custom-2"}) {
		t.Fatalf("current attribution = %+v, want custom-2", movedMatch)
	}
	movedPrefix, ok := snap.ExplainIPv4(netip.MustParseAddr("198.51.100.1"))
	if !ok || !reflect.DeepEqual(movedPrefix.Sources, []string{"custom-2"}) {
		t.Fatalf("current prefix attribution = %+v, want custom-2", movedPrefix)
	}
}
