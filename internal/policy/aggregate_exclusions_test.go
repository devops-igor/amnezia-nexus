package policy

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// These oracles cover #892: the VK family is direct by default, and an operator
// can add more never-proxy domains. The exclusions use the same guard semantics
// as the built-in patterns, including ancestor removal, so an exclusion cannot
// be proxied by a broader list rule.

func TestNeverProxyGuardRemovesVKFamily(t *testing.T) {
	family := []string{
		"vk.com", "vk.ru", "vkontakte.ru", "userapi.com", "vk-apps.com",
		"vkvideo.ru", "vkforms.ru", "vkplay.live", "vkopt.net", "vk.me", "vk-cdn.net",
	}
	for _, pattern := range family {
		for _, name := range []string{pattern, "sub." + pattern} {
			if _, guarded := NeverProxyReason(name); !guarded {
				t.Errorf("VK name %q is not guarded by the default pattern set", name)
			}
		}
	}
	// Names measured in the aggregate lists must be covered by the family
	// patterns, including the parent and a subdomain.
	for _, measured := range []string{"www.vk.com", "m.vk.ru", "live.vkvideo.ru", "vkontakte.ru"} {
		if _, guarded := NeverProxyReason(measured); !guarded {
			t.Errorf("measured VK name %q is not guarded", measured)
		}
	}
	if _, guarded := NeverProxyReason("example.ru"); guarded {
		t.Error("an unrelated domain was guarded by the VK family")
	}
}

func TestParseExcludedDomainsAcceptsAndDeduplicates(t *testing.T) {
	got, err := ParseExcludedDomains([]string{
		"# comment", "", "  ", "example.com", "*.sub.example", "*.sub.example",
		"  Example.COM. ", "internal.api.example.com",
	})
	if err != nil {
		t.Fatalf("parse excluded domains: %v", err)
	}
	want := []string{"example.com", "internal.api.example.com", "sub.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed exclusions = %v, want %v", got, want)
	}
}

func TestParseExcludedDomainsRejectsUnsupportedForms(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"scheme", "https://example.com"},
		{"port", "example.com:443"},
		{"path", "example.com/path"},
		{"userinfo", "user@example.com"},
		{"ipv4", "203.0.113.7"},
		{"ipv6", "2001:db8::1"},
		{"cidr", "198.51.100.0/24"},
		{"malformed label", "bad_label"},
		{"overlong", strings.Repeat("a", 254) + ".com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseExcludedDomains([]string{tt.line}); err == nil {
				t.Fatalf("excluded entry %q was accepted", tt.line)
			}
		})
	}

	many := make([]string, MaxExcludedDomains+1)
	for i := range many {
		many[i] = fmt.Sprintf("excluded%d.example", i)
	}
	if _, err := ParseExcludedDomains(many); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversized exclusion list error = %v, want a maximum-bound refusal", err)
	}
}

func TestSettingsExcludedDomainsValidationAndLocalOverlap(t *testing.T) {
	settings := DefaultSettings()
	settings.Preset = PresetAggregate
	settings.ExcludedDomains = []string{"internal.api.example.com", "*.corp.example"}
	settings.LocalEntries = []string{"local.example"}
	if err := settings.Validate(); err != nil {
		t.Fatalf("valid exclusions rejected: %v", err)
	}
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig: %v", err)
	}
	if want := []string{"corp.example", "internal.api.example.com"}; !reflect.DeepEqual(cfg.ExcludedDomains, want) {
		t.Fatalf("SyncConfig exclusions = %v, want %v", cfg.ExcludedDomains, want)
	}

	overlap := settings
	overlap.LocalEntries = []string{"api.example.com"}
	overlap.ExcludedDomains = []string{"example.com"}
	if err := overlap.Validate(); err == nil || !strings.Contains(err.Error(), "excluded_domains") {
		t.Fatalf("local/exclusion overlap error = %v, want a named excluded_domains refusal", err)
	}

	invalid := settings
	invalid.ExcludedDomains = []string{"203.0.113.7"}
	if err := invalid.Validate(); err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("address exclusion error = %v, want an address-specific refusal", err)
	}
}

// TestSyncer_OperatorExclusionRemovesRuleAndAncestor pins the documented
// consequence: excluding api.example.com also removes the broader example.com
// rule, while an unrelated rule survives. A name-based matcher cannot keep the
// parent while excluding the child.
func TestSyncer_OperatorExclusionRemovesRuleAndAncestor(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "example.com\napi.example.com\nother.example\n", `"v1"`)
	cfg := refreshConfig("/rules.lst")
	exclusions, err := ParseExcludedDomains([]string{"api.example.com"})
	if err != nil {
		t.Fatalf("parse exclusions: %v", err)
	}
	cfg.ExcludedDomains = exclusions

	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, fixture.fetcher(), NewFileStore(t.TempDir()), cfg)
	result, err := syncer.SyncOnce(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := result.SourceStats["source-1"].Excluded; got != 2 {
		t.Fatalf("excluded count = %d, want 2 (the exact rule and its parent)", got)
	}
	snap := matcher.Current()
	for _, name := range []string{"example.com", "api.example.com"} {
		if snap.MatchDomain(name) {
			t.Errorf("excluded name %q reached the published snapshot", name)
		}
	}
	if !snap.MatchDomain("other.example") {
		t.Error("the exclusion removed an unrelated rule")
	}
	if got := snap.DomainCount(); got != 1 {
		t.Fatalf("published domain count = %d, want 1", got)
	}
}

func TestSyncer_OperatorExclusionGenerationRetention(t *testing.T) {
	fixture := newRefreshFixture(t, "/rules.lst")
	fixture.serve("/rules.lst", "listed.example\nother.example\n", `"v1"`)
	cfg := refreshConfig("/rules.lst")
	noop, err := ParseExcludedDomains([]string{"noop.example"})
	if err != nil {
		t.Fatalf("parse no-op exclusion: %v", err)
	}
	store := NewFileStore(t.TempDir())
	ctx := context.Background()
	liveMatcher := NewMatcher()

	firstSyncer := newRefreshSyncer(t, liveMatcher, fixture.fetcher(), store, cfg)
	first, err := firstSyncer.SyncOnce(ctx)
	if err != nil || !first.Published {
		t.Fatalf("seed sync: published=%v err=%v", first.Published, err)
	}

	// Adding an exclusion that matches nothing must retain the generation: the
	// exclusion list is not part of the config hash, so only the effective
	// content decides.
	retainedCfg := cfg
	retainedCfg.ExcludedDomains = noop
	retainedSyncer := newRefreshSyncer(t, liveMatcher, fixture.fetcher(), store, retainedCfg)
	if _, err := retainedSyncer.AdoptBaseline(ctx); err != nil {
		t.Fatalf("adopt baseline: %v", err)
	}
	retained, err := retainedSyncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("retained sync: %v", err)
	}
	if retained.GenerationID != first.GenerationID {
		t.Fatalf("a no-op exclusion bumped the generation: %s -> %s", first.GenerationID, retained.GenerationID)
	}

	// An exclusion that removes a rule must publish a new generation.
	changedCfg := cfg
	changed, err := ParseExcludedDomains([]string{"listed.example"})
	if err != nil {
		t.Fatalf("parse changed exclusion: %v", err)
	}
	changedCfg.ExcludedDomains = changed
	changedSyncer := newRefreshSyncer(t, liveMatcher, fixture.fetcher(), store, changedCfg)
	if _, err := changedSyncer.AdoptBaseline(ctx); err != nil {
		t.Fatalf("adopt changed baseline: %v", err)
	}
	published, err := changedSyncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("changed sync: %v", err)
	}
	if published.GenerationID == first.GenerationID {
		t.Fatal("an exclusion that removed a rule retained the old generation")
	}
	if liveMatcher.Current().MatchDomain("listed.example") {
		t.Fatal("the newly excluded rule is still in the published snapshot")
	}
	if !liveMatcher.Current().MatchDomain("other.example") {
		t.Fatal("the changed exclusion removed an unrelated rule")
	}
}

func TestPrimeBaselineRefusesStoredOperatorExclusion(t *testing.T) {
	store := NewFileStore(t.TempDir())
	cfg := refreshConfig("/rules.lst")
	exclusions, err := ParseExcludedDomains([]string{"custom.example"})
	if err != nil {
		t.Fatalf("parse exclusions: %v", err)
	}
	cfg.ExcludedDomains = exclusions
	seedGeneration(t, store, cfg, "gen-before-exclusion", map[string]uint32{
		"allowed.example": uint32(domainInclusiveSuffix),
		"custom.example":  uint32(domainInclusiveSuffix),
	})

	matcher := NewMatcher()
	syncer := newRefreshSyncer(t, matcher, newRefreshFixture(t).fetcher(), store, cfg)
	status, err := syncer.PrimeBaseline(context.Background())
	if err != nil {
		t.Fatalf("PrimeBaseline: %v", err)
	}
	if status != BaselineForeign {
		t.Fatalf("baseline status = %v, want BaselineForeign for an operator exclusion violation", status)
	}
	if matcher.Current() != nil {
		t.Fatal("PrimeBaseline published a generation containing an excluded name")
	}
	adopted, err := syncer.AdoptBaseline(context.Background())
	if err != nil {
		t.Fatalf("AdoptBaseline: %v", err)
	}
	if adopted != BaselineForeign || syncer.cachedGen != nil {
		t.Fatalf("adopt status = %v cached=%v, want BaselineForeign and no cached generation", adopted, syncer.cachedGen != nil)
	}

	// A clean generation for the same configuration is still a usable baseline.
	seedGeneration(t, store, cfg, "gen-clean", map[string]uint32{
		"allowed.example": uint32(domainInclusiveSuffix),
	})
	cleanMatcher := NewMatcher()
	cleanSyncer := newRefreshSyncer(t, cleanMatcher, newRefreshFixture(t).fetcher(), store, cfg)
	cleanStatus, err := cleanSyncer.PrimeBaseline(context.Background())
	if err != nil {
		t.Fatalf("clean PrimeBaseline: %v", err)
	}
	if cleanStatus != BaselinePrimed {
		t.Fatalf("clean baseline status = %v, want BaselinePrimed", cleanStatus)
	}
	if cleanMatcher.Current() == nil || !cleanMatcher.Current().MatchDomain("allowed.example") {
		t.Fatal("clean generation was not published")
	}
}

func TestGenerationViolationsUsesOperatorExclusions(t *testing.T) {
	cfg := refreshConfig("/rules.lst")
	exclusions, err := ParseExcludedDomains([]string{"custom.example"})
	if err != nil {
		t.Fatalf("parse exclusions: %v", err)
	}
	cfg.ExcludedDomains = exclusions
	syncer := newRefreshSyncer(t, NewMatcher(), newRefreshFixture(t).fetcher(), NewFileStore(t.TempDir()), cfg)
	gen := &Generation{Domains: map[string]uint32{
		"allowed.example": uint32(domainInclusiveSuffix),
		"custom.example":  uint32(domainInclusiveSuffix),
		"gov.ru":          uint32(domainInclusiveSuffix),
	}}

	if got, want := syncer.GenerationViolations(gen), []string{"custom.example", "gov.ru"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("syncer violations = %v, want %v (built-in plus operator exclusions)", got, want)
	}
	if got, want := GenerationNeverProxyViolations(gen), []string{"gov.ru"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("built-in violations = %v, want %v", got, want)
	}
}
