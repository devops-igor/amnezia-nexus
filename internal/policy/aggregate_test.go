package policy

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAggregateManifestIsTheReviewedPrimaryRawSet(t *testing.T) {
	manifest := AggregateManifest()
	if len(manifest) != 24 {
		t.Fatalf("aggregate manifest has %d lists, want 24", len(manifest))
	}
	seen := map[string]bool{}
	for _, path := range manifest {
		if seen[path] {
			t.Fatalf("manifest repeats %q", path)
		}
		seen[path] = true
		if strings.Contains(path, "outside") {
			t.Fatalf("manifest includes excluded outside list %q", path)
		}
		for _, excluded := range []string{"clashx", "dnsmasq", "kvas", "mikrotik", "src/"} {
			if strings.Contains(path, excluded) {
				t.Fatalf("manifest includes converted/derived path %q", path)
			}
		}
	}
	for _, required := range []string{
		"Categories/geoblock.lst", "Russia/inside-raw.lst", "Ukraine/inside-raw.lst", "Services/telegram.lst",
	} {
		if !seen[required] {
			t.Fatalf("manifest is missing %q", required)
		}
	}
	sources := AggregateSources()
	if len(sources) != len(manifest) {
		t.Fatalf("AggregateSources = %d, want %d", len(sources), len(manifest))
	}
	if sources[0].ID != "aggregate:"+manifest[0] || !sources[0].IsPreset {
		t.Fatalf("first aggregate source = %+v", sources[0])
	}
	for _, src := range sources {
		if _, err := ValidateFetchURL(src.URL); err != nil {
			t.Fatalf("aggregate source %q URL invalid: %v", src.ID, err)
		}
	}
}

func TestNeverProxyGuardRemovesGovernmentAndInternalNames(t *testing.T) {
	government := []string{
		"gov.ru", "government.ru", "kremlin.ru", "mil.ru", "mvd.ru", "rkn.gov.ru",
		"mchs.gov.ru", "rospotrebnadzor.gov.ru", "roszdravnadzor.gov.ru", "genproc.gov.ru",
		"sudrf.ru", "pravo.gov.ru", "gosuslugi.ru", "gu-st.ru", "mos.ru", "mosreg.ru",
		"nalog.ru", "rosreestr.gov.ru", "fssp.gov.ru", "82.mchs.gov.ru", "82.mvd.ru",
		"82.rkn.gov.ru", "82.rospotrebnadzor.gov.ru", "82reg.roszdravnadzor.ru",
		"crimea.gov.ru", "dzhankoy.rk.gov.ru", "rk.gov.ru", "epp.genproc.gov.ru",
		"usd.krm.sudrf.ru", "vs.krm.sudrf.ru",
	}
	overlaps := []string{"gosuslugi.ru", "gov.ru", "ozon.ru", "rzd.ru", "showip.net", "yandex.net"}
	domains := map[string]domainFlags{}
	for _, name := range append(government, overlaps...) {
		domains[name] = domainInclusiveSuffix
	}
	domains["allowed.example"] = domainInclusiveSuffix
	filtered, excluded := FilterNeverProxyDomains(ParsedRules{Domains: domains})
	if excluded != len(domains)-1 {
		t.Fatalf("excluded = %d, want %d", excluded, len(domains)-1)
	}
	for _, name := range append(government, overlaps...) {
		if _, still := filtered.Domains[name]; still {
			t.Errorf("guarded name %q survived the filter", name)
		}
	}
	if _, ok := filtered.Domains["allowed.example"]; !ok {
		t.Fatal("safe domain was removed")
	}
}

func TestNeverProxyGuardRejectsBroadAncestorRules(t *testing.T) {
	for _, broad := range []string{"ru", "gov.ru", "rk.gov.ru"} {
		if _, guarded := NeverProxyReason(broad); !guarded {
			t.Errorf("broad rule %q was not guarded", broad)
		}
	}
	if _, guarded := NeverProxyReason("example.ru"); guarded {
		t.Error("unrelated example.ru was guarded")
	}
}

func TestParseLocalRulesRejectsGuardedEntryWithReason(t *testing.T) {
	_, _, err := ParseLocalRules([]string{"allowed.example", "ozon.ru"})
	if err == nil || !strings.Contains(err.Error(), "never-proxy guard") {
		t.Fatalf("error = %v, want a named never-proxy refusal", err)
	}
}

func TestParseLocalRulesAcceptsAndDeduplicatesForms(t *testing.T) {
	rules, report, err := ParseLocalRules([]string{
		"# comment", "", "example.com", "*.example.com", "example.com",
		"203.0.113.7", "198.51.100.0/24",
	})
	if err != nil {
		t.Fatalf("parse local rules: %v", err)
	}
	if len(rules.Domains) != 1 || len(rules.CIDRs) != 2 {
		t.Fatalf("rules = domains:%d cidrs:%d, want 1/2", len(rules.Domains), len(rules.CIDRs))
	}
	if report.Rejected != 0 {
		t.Fatalf("rejected = %d", report.Rejected)
	}
}

func TestSyncer_AppliesGuardAndReportsPerComponentExclusions(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "allowed.example\ngov.ru\n82.mvd.ru\nozon.ru\n198.51.100.0/24\n", `"v1"`)
	cfg := refreshConfig("/rules.lst")
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), NewFileStore(t.TempDir()), cfg)
	result, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !result.Published {
		t.Fatal("sync did not publish")
	}
	stat := result.SourceStats["source-1"]
	if stat.Excluded != 3 {
		t.Fatalf("excluded = %d, want 3", stat.Excluded)
	}
	snap := matcher.Current()
	for _, blocked := range []string{"gov.ru", "82.mvd.ru", "ozon.ru"} {
		if snap.MatchDomain(blocked) {
			t.Errorf("guarded domain %q matched the published snapshot", blocked)
		}
	}
	if !snap.MatchDomain("allowed.example") {
		t.Fatal("safe domain did not match")
	}
}

func TestSyncer_LocalRulesRetainThenBumpGeneration(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "external.example\n", `"v1"`)
	cfg := refreshConfig("/rules.lst")
	local, _, err := ParseLocalRules([]string{"local.example", "198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parse local: %v", err)
	}
	cfg.LocalRules = local
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), NewFileStore(t.TempDir()), cfg)
	first, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if !matcher.Current().MatchDomain("local.example") {
		t.Fatal("local domain missing from snapshot")
	}
	second, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if second.GenerationID != first.GenerationID {
		t.Fatalf("unchanged local rules bumped generation: %s -> %s", first.GenerationID, second.GenerationID)
	}

	changed, _, err := ParseLocalRules([]string{"local.example", "other.example", "198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parse changed local: %v", err)
	}
	cfg.LocalRules = changed
	thirdSyncer := newRefreshSyncer(t, matcher, fixture.fetcher(), NewFileStore(t.TempDir()), cfg)
	third, err := thirdSyncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if third.GenerationID == first.GenerationID {
		t.Fatal("changed local rules did not bump generation")
	}
	if !matcher.Current().MatchDomain("other.example") {
		t.Fatal("new local domain missing after sync")
	}
}

func TestParseLocalRulesIgnoresCommentsAndBlankLines(t *testing.T) {
	rules, _, err := ParseLocalRules([]string{"", "# comment", "  ", "// note", "; !"})
	if err != nil {
		t.Fatalf("comment-only local entries: %v", err)
	}
	if len(rules.Domains) != 0 || len(rules.CIDRs) != 0 {
		t.Fatalf("comment-only entries produced rules: %+v", rules)
	}
}

func TestNeverProxyGuardRemovesEveryRussiaOutsideName(t *testing.T) {
	outside := []string{
		"1018213540.rsc.cdn77.org", "avtodor-tr.ru", "b2c-ticket-sentry.onelya.ru",
		"bitrix.info", "bkvet.ru", "cdn1.ozonusercontent.com", "cms1.dzvr.ru",
		"consultant.ru", "counter.yadro.ru", "dzvr.ru", "emex.ru",
		"fairplay-proxy.ott.yandex.ru", "fssp.gov.ru", "gorzdrav.spb.ru",
		"gosuslugi.ru", "gov.ru", "graphql.kinopoisk.ru", "gu-st.ru",
		"lemanapro.ru", "leroymerlin.ru", "magnit.ru", "mobileapp.russianpost.ru",
		"mos.ru", "mosenergosbyt.ru", "mosreg.ru", "nalog.ru", "ozon.ru",
		"pesc.ru", "pochta.ru", "reso.ru", "rosreestr.gov.ru", "rzd-bonus.ru",
		"rzd.ru", "showip.net", "sys.refocus.ru", "vshark.ttk.ru",
		"widevine-proxy.ott.yandex.ru", "xn--90aijkdmaud0d.xn--p1ai", "yandex.net",
	}
	if len(outside) != 39 {
		t.Fatalf("fixture has %d names, want the measured 39", len(outside))
	}
	domains := make(map[string]domainFlags, len(outside))
	for _, name := range outside {
		domains[name] = domainInclusiveSuffix
	}
	filtered, excluded := FilterNeverProxyDomains(ParsedRules{Domains: domains})
	if excluded != len(outside) || len(filtered.Domains) != 0 {
		t.Fatalf("outside names survived: excluded=%d remaining=%v", excluded, filtered.Domains)
	}
}

func TestCompileSnapshotKeepsProvenanceForAggregateAndLocal(t *testing.T) {
	sources := make([]SourceParsedRules, 0, len(aggregateManifest)+1)
	for i := range aggregateManifest {
		sources = append(sources, SourceParsedRules{
			SourceID: AggregateSources()[i].ID,
			Rules:    ParsedRules{Domains: map[string]domainFlags{"shared.example": domainInclusiveSuffix}},
		})
	}
	sources = append(sources, SourceParsedRules{
		SourceID: "local",
		Rules:    ParsedRules{Domains: map[string]domainFlags{"shared.example": domainInclusiveSuffix}},
	})
	snap, err := CompileSnapshot(1, "gen-aggregate", sources)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	match, ok := snap.ExplainDomain("shared.example")
	if !ok {
		t.Fatal("shared.example missing")
	}
	if len(match.Contributors) != len(sources) {
		t.Fatalf("contributors = %d, want %d", len(match.Contributors), len(sources))
	}
}

// seedGeneration writes a durable generation whose ConfigHash matches cfg, so a
// baseline decision reaches the content checks instead of the source check.
func seedGeneration(t *testing.T, store Store, cfg SyncConfig, id string, domains map[string]uint32) {
	t.Helper()
	hash := (&Syncer{cfg: cfg}).computeConfigHash()
	gen := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  id,
		Version:       3,
		CreatedAt:     time.Now().UTC().Add(-time.Hour),
		ConfigHash:    hash,
		Domains:       domains,
	}
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("seed generation %q: %v", id, err)
	}
}

// TestPrimeBaselineRefusesStoredGuardViolations is the HIGH-01 regression: an
// upgrade must not activate a last-known-good snapshot written before the guard
// existed. The config matches, so only revalidating the stored rules can stop
// gov.ru from being published when the upstream fetch fails.
func TestPrimeBaselineRefusesStoredGuardViolations(t *testing.T) {
	store := NewFileStore(t.TempDir())
	cfg := refreshConfig("/rules.lst")
	seedGeneration(t, store, cfg, "gen-before-guard", map[string]uint32{
		"allowed.example": uint32(domainInclusiveSuffix),
		"gov.ru":          uint32(domainInclusiveSuffix),
		"82.mvd.ru":       uint32(domainInclusiveSuffix),
	})

	// The upstream is unavailable, so the only candidate rules are the stored ones.
	down := newRefreshFixture(t)
	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, down.fetcher(), store, cfg)

	status, err := syncer.PrimeBaseline(context.Background())
	if err != nil {
		t.Fatalf("PrimeBaseline: %v", err)
	}
	if status != BaselineForeign {
		t.Fatalf("baseline status = %v, want BaselineForeign for a stored guard violation", status)
	}
	if matcher.Current() != nil {
		t.Fatal("PrimeBaseline published a stored generation containing a never-proxy name")
	}
	// The save path adopts rather than publishes. It must refuse the same
	// generation, or the replacement syncer would treat it as the baseline.
	adopted, err := syncer.AdoptBaseline(context.Background())
	if err != nil {
		t.Fatalf("AdoptBaseline: %v", err)
	}
	if adopted != BaselineForeign {
		t.Fatalf("adopt status = %v, want BaselineForeign for a stored guard violation", adopted)
	}
	if syncer.cachedGen != nil {
		t.Fatal("AdoptBaseline cached a generation containing a never-proxy name")
	}
	if _, syncErr := syncer.SyncOnce(context.Background()); syncErr == nil {
		t.Fatal("fixture upstream was expected to fail")
	}
	if matcher.Current() != nil {
		t.Fatal("a failed fetch activated the stored guard-violating generation")
	}
}

// TestPrimeBaselineStillAcceptsCleanStoredGeneration is the positive control for
// the check above: an old but clean snapshot must remain a usable baseline, so
// the fix does not turn every upgrade into a full outage dependency.
func TestPrimeBaselineStillAcceptsCleanStoredGeneration(t *testing.T) {
	store := NewFileStore(t.TempDir())
	cfg := refreshConfig("/rules.lst")
	seedGeneration(t, store, cfg, "gen-clean", map[string]uint32{
		"allowed.example": uint32(domainInclusiveSuffix),
	})

	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, newRefreshFixture(t).fetcher(), store, cfg)
	status, err := syncer.PrimeBaseline(context.Background())
	if err != nil {
		t.Fatalf("PrimeBaseline: %v", err)
	}
	if status != BaselinePrimed {
		t.Fatalf("baseline status = %v, want BaselinePrimed for a clean stored generation", status)
	}
	if matcher.Current() == nil || !matcher.Current().MatchDomain("allowed.example") {
		t.Fatal("clean stored generation was not published")
	}
}

// TestSyncer_LocalRulesRestartRetainsGeneration is the MEDIUM-03 regression: the
// durable attribution digest and the candidate digest must both include the local
// source. Stripping it on one side made every restart with local rules publish a
// new generation and discard trusted client DNS evidence.
func TestSyncer_LocalRulesRestartRetainsGeneration(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "listed.example\n", `"v1"`)
	cfg := refreshConfig("/rules.lst")
	local, _, err := ParseLocalRules([]string{"local.example", "198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parse local: %v", err)
	}
	cfg.LocalRules = local
	store := NewFileStore(t.TempDir())
	ctx := context.Background()

	firstSyncer := newRefreshSyncer(t, NewMatcher(), fixture.fetcher(), store, cfg)
	first, err := firstSyncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("seed sync: published=%v err=%v", first.Published, err)
	}

	// Restart: a fresh syncer over the same store and an unchanged configuration.
	// The live matcher is the one the runtime keeps serving across the restart.
	liveMatcher := NewMatcher()
	restarted := newRefreshSyncer(t, liveMatcher, fixture.fetcher(), store, cfg)
	baseline, err := restarted.PrimeBaseline(ctx)
	if err != nil || baseline != BaselinePrimed {
		t.Fatalf("restart baseline = %v err=%v, want BaselinePrimed", baseline, err)
	}
	second, err := restarted.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("post-restart refresh: %v", err)
	}
	if second.GenerationID != first.GenerationID {
		t.Fatalf("unchanged local rules bumped the generation after restart: %s -> %s", first.GenerationID, second.GenerationID)
	}

	// An unrelated save builds a replacement syncer that adopts the durable
	// generation over the same live matcher; the same unchanged local rules must
	// still retain it.
	replacement := newRefreshSyncer(t, liveMatcher, fixture.fetcher(), store, cfg)
	adopted, err := replacement.AdoptBaseline(ctx)
	if err != nil || adopted != BaselinePrimed {
		t.Fatalf("replacement baseline = %v err=%v, want BaselinePrimed", adopted, err)
	}
	third, err := replacement.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("replacement refresh: %v", err)
	}
	if third.GenerationID != first.GenerationID {
		t.Fatalf("adopted unchanged local rules bumped the generation: %s -> %s", first.GenerationID, third.GenerationID)
	}

	// A genuine local change must still publish, against the same live matcher.
	changedLocal, _, err := ParseLocalRules([]string{"other.example", "198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parse changed local: %v", err)
	}
	changedCfg := cfg
	changedCfg.LocalRules = changedLocal
	changed := newRefreshSyncer(t, liveMatcher, fixture.fetcher(), store, changedCfg)
	if _, err := changed.PrimeBaseline(ctx); err != nil {
		t.Fatalf("changed baseline: %v", err)
	}
	fourth, err := changed.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("changed refresh: %v", err)
	}
	if fourth.GenerationID == first.GenerationID {
		t.Fatal("a changed local rule set retained the old generation")
	}
	if !liveMatcher.Current().MatchDomain("other.example") {
		t.Fatal("changed local rule is missing from the published snapshot")
	}
}

// TestSyncer_ConditionalRefreshPreservesComponentAccounting is the MEDIUM-04
// regression: a 304 says the bytes did not change, so the accepted and excluded
// counts of the reused filtered rules must survive the refresh.
func TestSyncer_ConditionalRefreshPreservesComponentAccounting(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "allowed.example\nsecond.example\ngov.ru\n", `"v1"`)
	cfg := refreshConfig("/rules.lst")
	syncer := newRefreshSyncer(t, NewMatcher(), fixture.fetcher(), NewFileStore(t.TempDir()), cfg)

	first, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	firstStat := first.SourceStats["source-1"]
	if firstStat.Accepted != 3 || firstStat.Excluded != 1 {
		t.Fatalf("first sync accounting = accepted:%d excluded:%d, want 3/1", firstStat.Accepted, firstStat.Excluded)
	}

	second, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	secondStat := second.SourceStats["source-1"]
	if !secondStat.NotModified {
		t.Fatalf("second sync did not receive a 304: %+v", secondStat)
	}
	if secondStat.Accepted != firstStat.Accepted || secondStat.Excluded != firstStat.Excluded {
		t.Fatalf("304 refresh accounting = accepted:%d excluded:%d, want the retained %d/%d",
			secondStat.Accepted, secondStat.Excluded, firstStat.Accepted, firstStat.Excluded)
	}
}

// TestFilterNeverProxyDomainsLeavesCIDRRulesUnchanged pins the narrowed HIGH-02
// contract: the guard is name-based, and a CIDR is matched by destination address
// before DNS evidence, so it passes through and remains the operator's choice.
func TestFilterNeverProxyDomainsLeavesCIDRRulesUnchanged(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.0/24")
	filtered, excluded := FilterNeverProxyDomains(ParsedRules{
		Domains: map[string]domainFlags{
			"gov.ru":          domainInclusiveSuffix,
			"allowed.example": domainInclusiveSuffix,
		},
		CIDRs: []netip.Prefix{prefix},
	})
	if excluded != 1 {
		t.Fatalf("excluded = %d, want the one guarded domain", excluded)
	}
	if len(filtered.CIDRs) != 1 || filtered.CIDRs[0] != prefix {
		t.Fatalf("CIDR rules = %v, want the input prefix unchanged", filtered.CIDRs)
	}
	if len(filtered.Domains) != 1 {
		t.Fatalf("domain rules = %v, want only the safe domain", filtered.Domains)
	}
}
