package policy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// These oracles cover the durable half of the attribution question: what a
// refresh must do with a rule that moved between two lists while the merged
// rules stayed identical, once the syncer no longer holds the per-source rules
// of the live generation. That is the state after a restart (baseline primed
// from durable state) and after an operator save adopts the durable generation
// into a fresh syncer.
//
// The generation identifier is what an explanation and the forwarder's route
// cache key their answer on, so "which list supplied this rule" has to survive
// the restart too, not only the lifetime of one syncer.

func requireContributors(t *testing.T, snapshot interface {
	ExplainDomain(string) (DomainRuleMatch, bool)
}, name string, want []string) {
	t.Helper()
	match, ok := snapshot.ExplainDomain(name)
	if !ok {
		t.Fatalf("%q matches no rule; want the rule supplied by %v", name, want)
	}
	if !reflect.DeepEqual(match.Contributors, want) {
		t.Fatalf("%q contributors = %v, want %v", name, match.Contributors, want)
	}
}

// attributionMoveFixture seeds one generation where a domain and a prefix come
// from source-1, then serves the same merged rules with both supplied by
// source-2. Routing decisions are byte-for-byte identical in both shapes.
type attributionMoveFixture struct {
	paths [2]string
}

func newAttributionMoveFixture(t *testing.T) (*refreshFixture, *attributionMoveFixture) {
	t.Helper()
	fixture := newRefreshFixture(t, "/a.lst", "/b.lst")
	fixture.serve("/a.lst", "shared.example.com\nalpha.example.com\n198.51.100.0/24\n", `"a1"`)
	fixture.serve("/b.lst", "beta.example.com\n203.0.113.0/24\n", `"b1"`)
	return fixture, &attributionMoveFixture{paths: [2]string{"/a.lst", "/b.lst"}}
}

// moveToSecondSource serves the identical merged rules with shared.example.com
// and 198.51.100.0/24 attributed to source-2 instead of source-1.
func (m *attributionMoveFixture) moveToSecondSource(fixture *refreshFixture, validator string) {
	fixture.serve(m.paths[0], "alpha.example.com\n", `"a2-`+validator+`"`)
	fixture.serve(m.paths[1],
		"beta.example.com\nshared.example.com\n198.51.100.0/24\n203.0.113.0/24\n",
		`"b2-`+validator+`"`)
}

// moveBackToFirstSource is the second attribution move, back to source-1.
func (m *attributionMoveFixture) moveBackToFirstSource(fixture *refreshFixture, validator string) {
	fixture.serve(m.paths[0],
		"alpha.example.com\nshared.example.com\n198.51.100.0/24\n", `"a3-`+validator+`"`)
	fixture.serve(m.paths[1], "beta.example.com\n203.0.113.0/24\n", `"b3-`+validator+`"`)
}

// TestSyncer_AttributionOnlyMoveAfterRestartOrAdoptionPublishesNewGeneration is
// the decisive oracle for the criterion the merged implementation left partial:
// a rule that moves to a different list must advance the generation even when
// the syncer learned the previous attribution from durable state rather than
// from its own previous cycle.
func TestSyncer_AttributionOnlyMoveAfterRestartOrAdoptionPublishesNewGeneration(t *testing.T) {
	const (
		domain = "shared.example.com"
		prefix = "198.51.100.1"
	)

	for _, mode := range []string{"adopt-live", "restart"} {
		t.Run(mode, func(t *testing.T) {
			fixture, mover := newAttributionMoveFixture(t)
			cfg := refreshConfig("/a.lst", "/b.lst")
			store := NewFileStore(t.TempDir())
			ctx := context.Background()

			matcher := NewMatcher()
			seeder := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
			seeded, err := seeder.SyncOnce(ctx)
			if err != nil || !seeded.Published {
				t.Fatalf("seed sync: published=%v err=%v", seeded.Published, err)
			}
			requireContributors(t, matcher.Current(), domain, []string{"source-1"})
			seedPrefix, ok := matcher.Current().ExplainIPv4(netip.MustParseAddr(prefix))
			if !ok || !reflect.DeepEqual(seedPrefix.Sources, []string{"source-1"}) {
				t.Fatalf("seed prefix attribution = %+v, want source-1", seedPrefix)
			}
			before, err := store.Load(ctx)
			if err != nil || before == nil {
				t.Fatalf("load seeded durable generation: gen=%v err=%v", before, err)
			}

			// The same merged rules, supplied by the other list.
			mover.moveToSecondSource(fixture, "v2")

			if mode == "restart" {
				matcher = NewMatcher()
			}
			replacement := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
			var baseline BaselineStatus
			if mode == "restart" {
				baseline, err = replacement.PrimeBaseline(ctx)
			} else {
				baseline, err = replacement.AdoptBaseline(ctx)
			}
			if err != nil {
				t.Fatalf("baseline for %s: %v", mode, err)
			}
			if baseline != BaselinePrimed {
				t.Fatalf("baseline status = %v, want BaselinePrimed", baseline)
			}

			after, err := replacement.SyncOnce(ctx)
			if err != nil {
				t.Fatalf("attribution refresh: %v", err)
			}
			if !after.Published {
				t.Fatal("attribution refresh did not establish the live policy")
			}

			// Routing cannot be what changed: the merged rules are identical, so
			// the equivalence decision is the only thing this oracle exercises.
			durable, err := store.Load(ctx)
			if err != nil || durable == nil {
				t.Fatalf("load durable generation after the move: gen=%v err=%v", durable, err)
			}
			if !equalFlagMap(before.Domains, durable.Domains) {
				t.Fatalf("fixture changed the merged domain rules: %v -> %v", before.Domains, durable.Domains)
			}
			if !equalStringSet(before.CIDRs, durable.CIDRs) {
				t.Fatalf("fixture changed the merged prefixes: %v -> %v", before.CIDRs, durable.CIDRs)
			}
			if !equalFlagMap(durable.Domains, map[string]uint32{
				"shared.example.com": 1,
				"alpha.example.com":  1,
				"beta.example.com":   1,
			}) {
				t.Fatalf("unexpected merged domain rules: %v", durable.Domains)
			}

			// The criterion: identity must move because attribution moved.
			if after.GenerationID == seeded.GenerationID || after.Version == seeded.Version {
				t.Fatalf("an attribution-only move retained generation %s/v%d after %s; the explanation would name the previous list and the route evidence would keep a generation the rules no longer belong to",
					seeded.GenerationID, seeded.Version, mode)
			}
			if durable.GenerationID != after.GenerationID {
				t.Fatalf("durable generation = %q, want the published %q", durable.GenerationID, after.GenerationID)
			}
			if durable.AttributionHash == "" {
				t.Error("durable generation recorded no attribution digest, so the next restart cannot compare attribution")
			}
			if durable.AttributionHash == before.AttributionHash {
				t.Error("durable attribution digest did not move with the attribution")
			}

			// The current attribution is still correct, and matching is unchanged.
			requireContributors(t, matcher.Current(), domain, []string{"source-2"})
			movedPrefix, ok := matcher.Current().ExplainIPv4(netip.MustParseAddr(prefix))
			if !ok || !reflect.DeepEqual(movedPrefix.Sources, []string{"source-2"}) {
				t.Fatalf("prefix attribution after the move = %+v, want source-2", movedPrefix)
			}
			if !matcher.Current().MatchDomain(domain) {
				t.Fatal("the moved rule no longer matches after an attribution-only change")
			}
			if got := matcher.Current().DomainCount(); got != 3 {
				t.Errorf("snapshot domain count = %d, want the unchanged 3", got)
			}
		})
	}
}

// TestSyncer_SameAttributionAfterRestartOrAdoptionRetainsGeneration is the
// control for the oracle above: identical per-source content must still keep the
// generation on both the 304 and the identical-200 path, or the fix would
// discard client route evidence on a timer.
func TestSyncer_SameAttributionAfterRestartOrAdoptionRetainsGeneration(t *testing.T) {
	for _, mode := range []string{"adopt-live", "restart"} {
		t.Run(mode, func(t *testing.T) {
			fixture, _ := newAttributionMoveFixture(t)
			cfg := refreshConfig("/a.lst", "/b.lst")
			store := NewFileStore(t.TempDir())
			ctx := context.Background()

			matcher := NewMatcher()
			seeder := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
			seeded, err := seeder.SyncOnce(ctx)
			if err != nil || !seeded.Published {
				t.Fatalf("seed sync: published=%v err=%v", seeded.Published, err)
			}
			before, err := store.Load(ctx)
			if err != nil || before == nil {
				t.Fatalf("load seeded durable generation: gen=%v err=%v", before, err)
			}
			if before.AttributionHash == "" {
				t.Fatal("seeded generation recorded no attribution digest")
			}

			if mode == "restart" {
				matcher = NewMatcher()
			}
			replacement := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
			if mode == "restart" {
				if _, err := replacement.PrimeBaseline(ctx); err != nil {
					t.Fatalf("PrimeBaseline: %v", err)
				}
			} else if _, err := replacement.AdoptBaseline(ctx); err != nil {
				t.Fatalf("AdoptBaseline: %v", err)
			}

			// Cycle 1: unchanged content behind current validators, so the
			// upstream answers 304.
			notModified, err := replacement.SyncOnce(ctx)
			if err != nil {
				t.Fatalf("304 refresh after %s: %v", mode, err)
			}
			if !notModified.SourceStats["source-1"].NotModified {
				t.Errorf("fixture did not answer 304: %+v", notModified.SourceStats["source-1"])
			}
			if notModified.GenerationID != seeded.GenerationID || notModified.Version != seeded.Version {
				t.Fatalf("304 refresh after %s advanced the generation from %s/v%d to %s/v%d",
					mode, seeded.GenerationID, seeded.Version, notModified.GenerationID, notModified.Version)
			}

			// Cycle 2: identical bytes under new validators, so the whole parse
			// path runs again.
			fixture.serve("/a.lst", "shared.example.com\nalpha.example.com\n198.51.100.0/24\n", `"a1-again"`)
			fixture.serve("/b.lst", "beta.example.com\n203.0.113.0/24\n", `"b1-again"`)
			reparsed, err := replacement.SyncOnce(ctx)
			if err != nil {
				t.Fatalf("identical-200 refresh after %s: %v", mode, err)
			}
			if reparsed.GenerationID != seeded.GenerationID || reparsed.Version != seeded.Version {
				t.Fatalf("identical-200 refresh after %s advanced the generation from %s/v%d to %s/v%d",
					mode, seeded.GenerationID, seeded.Version, reparsed.GenerationID, reparsed.Version)
			}
			durable, err := store.Load(ctx)
			if err != nil || durable == nil {
				t.Fatalf("load durable generation: gen=%v err=%v", durable, err)
			}
			if durable.AttributionHash != before.AttributionHash {
				t.Errorf("identical content rewrote the attribution digest: %q -> %q",
					before.AttributionHash, durable.AttributionHash)
			}
			requireContributors(t, matcher.Current(), "shared.example.com", []string{"source-1"})
		})
	}
}

// TestSyncer_LegacyGenerationWithoutAttributionRetainsOnceThenDetectsMoves pins
// the backwards-compatibility half: a durable generation written before the
// digest existed must still load and must not invalidate the policy, and the
// first successful cycle then records the digest so later moves are detected.
func TestSyncer_LegacyGenerationWithoutAttributionRetainsOnceThenDetectsMoves(t *testing.T) {
	fixture, mover := newAttributionMoveFixture(t)
	cfg := refreshConfig("/a.lst", "/b.lst")
	dir := t.TempDir()
	store := NewFileStore(dir)
	ctx := context.Background()

	matcher := NewMatcher()
	seeder := newRefreshSyncer(t, matcher, fixture.fetcher(), store, cfg)
	seeded, err := seeder.SyncOnce(ctx)
	if err != nil || !seeded.Published {
		t.Fatalf("seed sync: published=%v err=%v", seeded.Published, err)
	}
	seededGen, err := store.Load(ctx)
	if err != nil || seededGen == nil {
		t.Fatalf("load seeded durable generation: gen=%v err=%v", seededGen, err)
	}

	// Rewrite the durable record in the older shape: same content, no digest.
	legacy := *seededGen
	legacy.AttributionHash = ""
	if err := store.Commit(ctx, &legacy); err != nil {
		t.Fatalf("write legacy-shaped generation: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, cacheFileName))
	if err != nil {
		t.Fatalf("read durable policy file: %v", err)
	}
	if strings.Contains(string(raw), "attribution_hash") {
		t.Fatal("fixture did not produce a generation without an attribution digest")
	}
	loaded, err := store.Load(ctx)
	if err != nil || loaded == nil {
		t.Fatalf("a generation without an attribution digest must still load: gen=%v err=%v", loaded, err)
	}
	if loaded.AttributionHash != "" {
		t.Fatalf("legacy generation reported digest %q", loaded.AttributionHash)
	}
	if loaded.GenerationID != seeded.GenerationID || !equalFlagMap(loaded.Domains, seededGen.Domains) {
		t.Fatal("legacy round-trip changed the generation identity or rules")
	}

	// First move: attribution is genuinely unknown for this generation, so the
	// cycle must not invalidate the policy. It records the observed digest.
	mover.moveToSecondSource(fixture, "legacy")
	restarted := NewMatcher()
	replacement := newRefreshSyncer(t, restarted, fixture.fetcher(), store, cfg)
	if _, err := replacement.PrimeBaseline(ctx); err != nil {
		t.Fatalf("PrimeBaseline: %v", err)
	}
	first, err := replacement.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("refresh over a legacy generation: %v", err)
	}
	if first.GenerationID != seeded.GenerationID || first.Version != seeded.Version {
		t.Fatalf("a legacy generation without a digest was invalidated: %s/v%d -> %s/v%d",
			seeded.GenerationID, seeded.Version, first.GenerationID, first.Version)
	}
	requireContributors(t, restarted.Current(), "shared.example.com", []string{"source-2"})
	recorded, err := store.Load(ctx)
	if err != nil || recorded == nil {
		t.Fatalf("load durable generation after the first move: gen=%v err=%v", recorded, err)
	}
	if recorded.AttributionHash == "" {
		t.Fatal("the first successful cycle did not record an attribution digest, so the legacy gap would never close")
	}
	if !equalFlagMap(recorded.Domains, seededGen.Domains) || !equalStringSet(recorded.CIDRs, seededGen.CIDRs) {
		t.Fatalf("fixture changed the merged rules: %v/%v -> %v/%v",
			seededGen.Domains, seededGen.CIDRs, recorded.Domains, recorded.CIDRs)
	}

	// Second move: the digest is recorded now, so this one must publish.
	mover.moveBackToFirstSource(fixture, "legacy")
	next := NewMatcher()
	successor := newRefreshSyncer(t, next, fixture.fetcher(), store, cfg)
	if _, err := successor.PrimeBaseline(ctx); err != nil {
		t.Fatalf("PrimeBaseline for the second move: %v", err)
	}
	second, err := successor.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("second attribution move: %v", err)
	}
	if second.GenerationID == recorded.GenerationID || second.Version == recorded.Version {
		t.Fatalf("an attribution-only move after the digest was recorded retained generation %s/v%d",
			recorded.GenerationID, recorded.Version)
	}
	requireContributors(t, next.Current(), "shared.example.com", []string{"source-1"})
	final, err := store.Load(ctx)
	if err != nil || final == nil {
		t.Fatalf("load final durable generation: gen=%v err=%v", final, err)
	}
	if !equalFlagMap(final.Domains, seededGen.Domains) || !equalStringSet(final.CIDRs, seededGen.CIDRs) {
		t.Fatalf("an attribution-only move changed the merged rules: %v/%v -> %v/%v",
			seededGen.Domains, seededGen.CIDRs, final.Domains, final.CIDRs)
	}
}

// TestSyncer_AttributionMoveCommitFailureKeepsIncumbent pins the failure half of
// the new invalidation: a moved attribution whose durable commit fails must not
// reach the live policy, and the incumbent generation must stay live and durable.
func TestSyncer_AttributionMoveCommitFailureKeepsIncumbent(t *testing.T) {
	fixture, mover := newAttributionMoveFixture(t)
	store := &failingCommitStore{inner: NewFileStore(t.TempDir())}
	matcher := NewMatcher()
	ctx := context.Background()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), store, refreshConfig("/a.lst", "/b.lst"))

	seeded, err := syncer.SyncOnce(ctx)
	if err != nil || !seeded.Published {
		t.Fatalf("seed sync: published=%v err=%v", seeded.Published, err)
	}

	store.fail.Store(true)
	mover.moveToSecondSource(fixture, "fail")
	moved, err := syncer.SyncOnce(ctx)
	if err == nil {
		t.Fatal("an attribution change whose durable commit failed reported success")
	}
	if moved.Published {
		t.Error("a refresh whose durable commit failed reported that it established the live policy")
	}
	if got := matcher.Current().Generation(); got != seeded.GenerationID {
		t.Errorf("live snapshot generation = %q, want the retained %q", got, seeded.GenerationID)
	}
	requireContributors(t, matcher.Current(), "shared.example.com", []string{"source-1"})
	durable, loadErr := store.Load(ctx)
	if loadErr != nil || durable == nil {
		t.Fatalf("load durable generation after the failed commit: gen=%v err=%v", durable, loadErr)
	}
	if durable.GenerationID != seeded.GenerationID {
		t.Errorf("durable generation = %q, want the retained %q", durable.GenerationID, seeded.GenerationID)
	}
	if status := syncer.Status(); status.LastError == "" {
		t.Error("status did not report the failed refresh")
	}
}
