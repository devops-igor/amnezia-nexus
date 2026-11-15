package policy

import (
	"net/netip"
	"testing"
)

// These tests pin the explanation accessors of the compiled snapshot:
// provenance (which list supplied a rule), shape (how a domain rule applies),
// most-specific-prefix selection, and — most importantly — that explaining never
// disagrees with the matchers the packet and DNS paths use.

func TestSnapshotExplainDomainProvenance(t *testing.T) {
	snap, err := CompileSnapshot(1, "gen-1", []SourceParsedRules{
		{SourceID: "geoblock", Rules: ParsedRules{Domains: map[string]domainFlags{
			"shared.example": domainExact,
			"only-a.example": domainInclusiveSuffix,
		}}},
		{SourceID: "custom-1", Rules: ParsedRules{Domains: map[string]domainFlags{
			"shared.example": domainInclusiveSuffix,
			"only-b.example": domainExact,
		}}},
	})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}

	t.Run("both sources are named for a rule they both supply", func(t *testing.T) {
		match, ok := snap.ExplainDomain("shared.example")
		if !ok {
			t.Fatal("shared.example should match")
		}
		if match.Shape != DomainRuleApexAndSubdomains {
			t.Errorf("shape = %q, want %q for exact+inclusive flags", match.Shape, DomainRuleApexAndSubdomains)
		}
		assertSources(t, match.Sources, "geoblock", "custom-1")
	})

	t.Run("a single source is named for a rule only it supplies", func(t *testing.T) {
		match, ok := snap.ExplainDomain("only-b.example")
		if !ok {
			t.Fatal("only-b.example should match")
		}
		if match.Base != "only-b.example" || match.Shape != DomainRuleApex {
			t.Fatalf("match = %+v, want only-b.example/apex", match)
		}
		assertSources(t, match.Sources, "custom-1")
	})

	t.Run("an exact rule does not match a subdomain", func(t *testing.T) {
		if _, ok := snap.ExplainDomain("sub.only-b.example"); ok {
			t.Fatal("an exact rule must not match a subdomain")
		}
	})

	t.Run("a subdomain of an inclusive-suffix rule names the rule base", func(t *testing.T) {
		match, ok := snap.ExplainDomain("deep.only-a.example")
		if !ok {
			t.Fatal("deep.only-a.example should match")
		}
		if match.Base != "only-a.example" || match.Shape != DomainRuleApexAndSubdomains {
			t.Fatalf("match = %+v, want only-a.example/apex_and_subdomains", match)
		}
	})
}

func TestSnapshotExplainWithoutAttribution(t *testing.T) {
	sources := make([]SourceParsedRules, 0, 5)
	for i := 0; i < 5; i++ {
		sources = append(sources, SourceParsedRules{
			SourceID: string(rune('a' + i)),
			Rules:    ParsedRules{Domains: map[string]domainFlags{"demo.example": domainInclusiveSuffix}},
		})
	}
	snap, err := CompileSnapshot(2, "gen-2", sources)
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}
	match, ok := snap.ExplainDomain("demo.example")
	if !ok {
		t.Fatal("demo.example should match")
	}
	// More sources than the provenance encoding holds: the rule and its shape
	// are still reported, the source list is honestly empty rather than wrong.
	if len(match.Sources) != 0 {
		t.Fatalf("sources = %v, want none beyond the provenance budget", match.Sources)
	}
	if !snap.MatchDomain("demo.example") {
		t.Error("a snapshot with more than four sources must still match")
	}
}

func TestSnapshotExplainCIDRProvenance(t *testing.T) {
	snap, err := CompileSnapshot(3, "gen-3", []SourceParsedRules{
		{SourceID: "antifilter_ipv4", Rules: ParsedRules{CIDRs: []netip.Prefix{
			netip.MustParsePrefix("198.51.200.0/24"),
		}}},
		{SourceID: "custom-1", Rules: ParsedRules{CIDRs: []netip.Prefix{
			netip.MustParsePrefix("198.51.200.128/25"),
			netip.MustParsePrefix("198.51.200.0/24"),
		}}},
	})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}

	match, ok := snap.ExplainIPv4(netip.MustParseAddr("198.51.200.200"))
	if !ok {
		t.Fatal("198.51.200.200 should match")
	}
	if got := match.Prefix.String(); got != "198.51.200.128/25" {
		t.Fatalf("prefix = %s, want the narrowest containing prefix", got)
	}
	assertSources(t, match.Sources, "custom-1")

	wide, ok := snap.ExplainIPv4(netip.MustParseAddr("198.51.200.9"))
	if !ok || wide.Prefix.String() != "198.51.200.0/24" {
		t.Fatalf("match = %+v, want 198.51.200.0/24", wide)
	}
	assertSources(t, wide.Sources, "antifilter_ipv4", "custom-1")

	if _, ok := snap.ExplainIPv4(netip.MustParseAddr("198.51.201.1")); ok {
		t.Error("an address outside every prefix must not match")
	}
	if _, ok := snap.ExplainIPv4(netip.MustParseAddr("2001:db8::1")); ok {
		t.Error("IPv6 must not match the IPv4 rules")
	}
}

// TestSnapshotExplainAgreesWithMatchers is the divergence guard: the
// explanation is a second reader of the same rule structures, so every name and
// address must agree with the matcher production uses.
func TestSnapshotExplainAgreesWithMatchers(t *testing.T) {
	snap, err := CompileSnapshot(4, "gen-4", []SourceParsedRules{
		{SourceID: "preset", Rules: ParsedRules{
			Domains: map[string]domainFlags{
				"exact.example":       domainExact,
				"suffix.example":      domainInclusiveSuffix,
				"wild.example":        domainDescendants,
				"multi.example":       domainExact | domainInclusiveSuffix,
				"no-match.example":    domainExact,
				"overlap.example":     domainInclusiveSuffix,
				"sub.overlap.example": domainExact,
			},
			CIDRs: []netip.Prefix{
				netip.MustParsePrefix("198.51.200.0/24"),
				netip.MustParsePrefix("203.0.114.0/23"),
			},
		}},
	})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}

	names := []string{
		"exact.example", "sub.exact.example", "suffix.example", "a.b.suffix.example",
		"wild.example", "sub.wild.example", "multi.example", "x.multi.example",
		"no-match.example", "sub.no-match.example", "overlap.example",
		"sub.overlap.example", "other.example", "example", "",
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		canon, err := NormalizeDomain(name)
		if err != nil {
			t.Fatalf("normalize %q: %v", name, err)
		}
		_, explained := snap.ExplainCanonicalDomain(canon)
		if matched := snap.MatchCanonicalDomain(canon); matched != explained {
			t.Errorf("%q: matcher=%v explained=%v", name, matched, explained)
		}
	}

	addresses := []string{
		"198.51.200.1", "198.51.200.255", "198.51.201.1",
		"203.0.114.1", "203.0.115.255", "203.0.116.1", "8.8.8.8",
	}
	for _, raw := range addresses {
		addr := netip.MustParseAddr(raw)
		_, explained := snap.ExplainIPv4(addr)
		if matched := snap.MatchIPv4(addr); matched != explained {
			t.Errorf("%s: matcher=%v explained=%v", raw, matched, explained)
		}
	}
}

// TestGenerationSnapshotExplainsPrefixesWithoutSources pins the last-known-good
// path: a durable generation keeps merged rules and no per-rule attribution, so
// the prefix is named and the source list is empty instead of invented.
func TestGenerationSnapshotExplainsPrefixesWithoutSources(t *testing.T) {
	gen := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  "gen-lkg",
		Version:       9,
		Domains:       map[string]uint8{"blocked.example": uint8(domainInclusiveSuffix)},
		CIDRs:         []string{"198.51.200.0/24"},
		DomainCount:   1,
		CIDRCount:     1,
	}
	gen.ContentHash = ComputeContentHash(gen.Domains, gen.CIDRs)

	snap, err := GenerationToSnapshot(gen)
	if err != nil {
		t.Fatalf("generation to snapshot: %v", err)
	}
	match, ok := snap.ExplainDomain("blocked.example")
	if !ok || match.Base != "blocked.example" {
		t.Fatalf("domain match = %+v, ok=%v", match, ok)
	}
	if len(match.Sources) != 0 {
		t.Errorf("sources = %v, want none for a merged generation", match.Sources)
	}
	prefix, ok := snap.ExplainIPv4(netip.MustParseAddr("198.51.200.5"))
	if !ok || prefix.Prefix.String() != "198.51.200.0/24" {
		t.Fatalf("prefix match = %+v, ok=%v", prefix, ok)
	}
	if len(prefix.Sources) != 0 {
		t.Errorf("prefix sources = %v, want none for a merged generation", prefix.Sources)
	}
	if !snap.MatchIPv4(netip.MustParseAddr("198.51.200.5")) {
		t.Error("a generation snapshot must still match its prefixes")
	}
}

func assertSources(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("sources = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sources = %v, want %v", got, want)
		}
	}
}
