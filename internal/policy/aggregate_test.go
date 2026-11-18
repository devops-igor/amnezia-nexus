package policy

import (
	"context"
	"strings"
	"testing"
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
