package policy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This file closes the proof gaps left by the merged #883 implementation. The
// acceptance criteria ask for manifest-wide evidence, not samples: every list in
// the reviewed manifest is served by a fixture, every non-excluded rule must be
// matched, and the guard's exclusion count is pinned. The tests never reach the
// live upstream; they exercise the production fetcher, parser, guard, union,
// provenance and snapshot compilation through AggregateSources.

// aggregatePoisonedComponents maps a manifest path to the guarded rows injected
// into that component's fixture. The total is the pinned exclusion count.
var aggregatePoisonedComponents = map[string][]string{
	"Russia/inside-raw.lst":  {"*.gov.ru"},
	"Ukraine/inside-raw.lst": {"82.mvd.ru", "ozon.ru"},
	"Categories/block.lst":   {"rzd.ru"},
}

// aggregateSharedComponents serve one extra rule from two different lists, so
// deduplication and provenance attribution are exercised over the real manifest.
var aggregateSharedComponents = map[string]bool{
	"Services/telegram.lst": true,
	"Services/youtube.lst":  true,
}

// aggregateFixturePath is the HTTP request path the fixture server sees for one
// manifest list, derived from the production URL rather than hand-copied.
func aggregateFixturePath(path string) string {
	return strings.TrimPrefix(aggregateBaseURL+path, "https://raw.githubusercontent.com")
}

func aggregateSourceByPath(t *testing.T, path string) Source {
	t.Helper()
	for _, src := range AggregateSources() {
		if src.ID == "aggregate:"+path {
			return src
		}
	}
	t.Fatalf("manifest path %q has no aggregate source", path)
	return Source{}
}

// TestAggregateManifestFixtureCoverage drives all 24 manifest lists through the
// production aggregate path. It fails if a list is dropped from the union, if a
// non-excluded rule is missing, if a guarded rule survives, or if the pinned
// exclusion/union counts move.
func TestAggregateManifestFixtureCoverage(t *testing.T) {
	manifest := AggregateManifest()
	if len(manifest) != 24 {
		t.Fatalf("manifest has %d lists, want the reviewed 24", len(manifest))
	}
	fixturePaths := make([]string, len(manifest))
	for i, path := range manifest {
		fixturePaths[i] = aggregateFixturePath(path)
	}
	fixture := newRefreshFixture(t, fixturePaths...)

	wantUnique := make([]string, 0, len(manifest))
	for i, path := range manifest {
		body := fmt.Sprintf("list%d.example\n", i)
		wantUnique = append(wantUnique, fmt.Sprintf("list%d.example", i))
		if aggregateSharedComponents[path] {
			body += "shared.example\n"
		}
		for _, poisoned := range aggregatePoisonedComponents[path] {
			body += poisoned + "\n"
		}
		fixture.serve(fixturePaths[i], body, fmt.Sprintf(`"v%d"`, i))
	}

	cfg := SyncConfig{
		Sources:         AggregateSources(),
		RefreshInterval: time.Hour,
		FetchLimits:     DefaultFetchLimits(),
		ParseLimits:     DefaultParseLimits(),
	}
	if len(cfg.Sources) != len(manifest) {
		t.Fatalf("AggregateSources has %d sources, want %d", len(cfg.Sources), len(manifest))
	}
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), NewFileStore(t.TempDir()), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("aggregate fixture sync: %v", err)
	}
	if !result.Published {
		t.Fatal("aggregate fixture sync did not publish")
	}
	snap := matcher.Current()
	if snap == nil {
		t.Fatal("aggregate fixture sync left no live snapshot")
	}

	// Every rule of every manifest list that the guard did not remove is present
	// and matches. An omitted list would leave its listN.example unmatched.
	for _, name := range wantUnique {
		if !snap.MatchDomain(name) {
			t.Errorf("rule %q from the manifest is missing from the published snapshot", name)
		}
		if !snap.MatchDomain("sub." + name) {
			t.Errorf("inclusive-suffix rule %q does not cover sub.%s", name, name)
		}
	}
	if !snap.MatchDomain("shared.example") {
		t.Fatal("the rule shared by two manifest lists is missing")
	}

	// Deduplication: the shared rule is one published rule attributed to both
	// lists, in manifest order.
	shared, ok := snap.ExplainDomain("shared.example")
	if !ok {
		t.Fatal("shared.example has no explanation")
	}
	wantContributors := make([]string, 0, 2)
	for _, src := range AggregateSources() {
		path := strings.TrimPrefix(src.ID, "aggregate:")
		if aggregateSharedComponents[path] {
			wantContributors = append(wantContributors, src.ID)
		}
	}
	if !reflect.DeepEqual(shared.Contributors, wantContributors) {
		t.Fatalf("shared.example contributors = %v, want %v", shared.Contributors, wantContributors)
	}

	// Every injected guarded name is absent, including the subdomain form of the
	// wildcard entry.
	for _, name := range []string{"gov.ru", "www.gov.ru", "82.mvd.ru", "ozon.ru", "rzd.ru"} {
		if snap.MatchDomain(name) {
			t.Errorf("guarded name %q reached the published snapshot", name)
		}
	}
	if got, want := snap.DomainCount(), len(wantUnique)+1; got != want {
		t.Fatalf("published domain count = %d, want %d unique non-excluded rules", got, want)
	}

	// The exclusion count is pinned per component and in total.
	if len(result.SourceStats) != len(manifest) {
		t.Fatalf("source stats = %d, want one entry per manifest list", len(result.SourceStats))
	}
	wantExcluded := 0
	for path, poisoned := range aggregatePoisonedComponents {
		id := "aggregate:" + path
		wantExcluded += len(poisoned)
		if got := result.SourceStats[id].Excluded; got != len(poisoned) {
			t.Errorf("%s excluded = %d, want the injected %d", id, got, len(poisoned))
		}
		wantAccepted := len(poisoned) + 1
		if aggregateSharedComponents[path] {
			wantAccepted++
		}
		if got := result.SourceStats[id].Accepted; got != wantAccepted {
			t.Errorf("%s accepted = %d, want %d", id, got, wantAccepted)
		}
	}
	gotExcluded := 0
	for _, stat := range result.SourceStats {
		gotExcluded += stat.Excluded
	}
	if gotExcluded != wantExcluded {
		t.Fatalf("total excluded = %d, want the fixture-pinned %d", gotExcluded, wantExcluded)
	}
}

// TestAggregateManifestBoundedSync pins the bounded behaviour of a 24-component
// aggregate: the cycle completes inside a bounded context and every component
// stays within the per-source parse limit. Memory is bounded structurally by the
// same per-source limits (the union merges at most the sum of those bounded rule
// sets and provenance is capped at maxSnapshotSources); it is not measured here.
func TestAggregateManifestBoundedSync(t *testing.T) {
	manifest := AggregateManifest()
	fixturePaths := make([]string, len(manifest))
	for i, path := range manifest {
		fixturePaths[i] = aggregateFixturePath(path)
	}
	fixture := newRefreshFixture(t, fixturePaths...)
	for i := range manifest {
		fixture.serve(fixturePaths[i], fmt.Sprintf("bounded%d.example\n", i), fmt.Sprintf(`"b%d"`, i))
	}

	cfg := SyncConfig{
		Sources:         AggregateSources(),
		RefreshInterval: time.Hour,
		FetchLimits:     DefaultFetchLimits(),
		ParseLimits:     DefaultParseLimits(),
	}
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), NewFileStore(t.TempDir()), cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("bounded 24-component sync: %v", err)
	}
	if !result.Published {
		t.Fatal("bounded 24-component sync did not publish")
	}
	for id, stat := range result.SourceStats {
		if stat.Accepted > cfg.ParseLimits.MaxRules {
			t.Errorf("%s accepted %d rules, above the per-source limit %d", id, stat.Accepted, cfg.ParseLimits.MaxRules)
		}
	}
	snap := matcher.Current()
	if snap == nil || snap.DomainCount() != len(manifest) {
		t.Fatalf("bounded sync published %d domains, want %d", snap.DomainCount(), len(manifest))
	}
}

// TestGuardMutationControlInjectedWildcardGovernmentName is the control the
// issue asks for: an injected `*.gov.ru` entry matches www.gov.ru when compiled
// without the guard, and stops matching after FilterNeverProxyDomains. If the
// guard were bypassed, the coverage test's absence assertions would fail for the
// same reason.
func TestGuardMutationControlInjectedWildcardGovernmentName(t *testing.T) {
	src := aggregateSourceByPath(t, "Russia/inside-raw.lst")
	parsed, report, err := Parse(context.Background(),
		strings.NewReader("*.gov.ru\nsafe.example\n"), src, DefaultParseLimits())
	if err != nil {
		t.Fatalf("parse mutation fixture: %v", err)
	}
	if report.Accepted != 2 || report.Rejected != 0 {
		t.Fatalf("mutation fixture report = %+v, want two accepted rules", report)
	}

	unfiltered, err := CompileSnapshot(1, "gen-mutation-unfiltered", []SourceParsedRules{{SourceID: src.ID, Rules: parsed}})
	if err != nil {
		t.Fatalf("compile unfiltered mutation fixture: %v", err)
	}
	if !unfiltered.MatchDomain("www.gov.ru") {
		t.Fatal("mutation control is not sensitive: *.gov.ru does not match www.gov.ru without the guard")
	}

	filtered, excluded := FilterNeverProxyDomains(parsed)
	if excluded != 1 {
		t.Fatalf("guard excluded %d rules from the mutation fixture, want 1", excluded)
	}
	guarded, err := CompileSnapshot(1, "gen-mutation-filtered", []SourceParsedRules{{SourceID: src.ID, Rules: filtered}})
	if err != nil {
		t.Fatalf("compile filtered mutation fixture: %v", err)
	}
	if guarded.MatchDomain("www.gov.ru") {
		t.Fatal("the guard did not remove the injected *.gov.ru rule")
	}
	if !guarded.MatchDomain("safe.example") {
		t.Fatal("the guard removed an unrelated rule")
	}
}
