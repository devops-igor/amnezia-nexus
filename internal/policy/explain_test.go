package policy

import (
	"net/netip"
	"testing"
	"time"
)

// Decision-table coverage for issue #825's explanation, driven through the real
// Snapshot, the real RouteCache and a real SessionCache seeded by Observe. No
// DNS interception is involved anywhere: evidence is written directly, exactly
// as the cache API allows, so a failure here is a failure of the explanation and
// not of the observation path.
//
// Fixture addresses use 198.51.200.0/24, the non-denied block the route-cache
// tests already seed with (ValidateFetchIP rejects the RFC 5737 blocks), and
// 192.0.2.10 for the prohibited case.

// explainFixture is one compiled policy plus one seeded session cache.
type explainFixture struct {
	snap  *Snapshot
	cache *RouteCache
	scope *SessionCache
	gen   string
	now   time.Time
}

func newExplainFixture(t *testing.T) *explainFixture {
	t.Helper()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

	preset := SourceParsedRules{SourceID: "geoblock", Rules: ParsedRules{
		Domains: map[string]domainFlags{
			"blocked.example": domainInclusiveSuffix,
			"apex.example":    domainExact,
			"wild.example":    domainDescendants,
		},
	}}
	custom := SourceParsedRules{SourceID: "custom-1", Rules: ParsedRules{
		Domains: map[string]domainFlags{"custom.example": domainInclusiveSuffix},
		CIDRs: []netip.Prefix{
			netip.MustParsePrefix("198.51.200.0/24"),
			netip.MustParsePrefix("198.51.200.128/25"),
		},
	}}

	snap, err := CompileSnapshot(7, "gen-7", []SourceParsedRules{preset, custom})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}

	cache, err := NewRouteCache(CacheConfig{})
	if err != nil {
		t.Fatalf("new route cache: %v", err)
	}
	cache.SetPolicyGeneration("gen-7")
	scope, err := cache.Open(Scope{SessionID: "session-1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}
	return &explainFixture{snap: snap, cache: cache, scope: scope, gen: "gen-7", now: now}
}

// observe seeds one decision for the fixture session.
func (f *explainFixture) observe(t *testing.T, raw, decision string, ttl time.Duration) {
	t.Helper()
	addr := netip.MustParseAddr(raw)
	if err := f.scope.Observe(f.gen, []Observation{{
		IP:        addr,
		Decision:  decisionOf(decision),
		ExpiresAt: f.now.Add(ttl),
	}}, f.now); err != nil {
		t.Fatalf("seed evidence for %s: %v", raw, err)
	}
}

func decisionOf(name string) Decision {
	if name == "DIRECT" {
		return Direct
	}
	return Proxy
}

// explain runs the explanation for the fixture's session.
func (f *explainFixture) explain(in ExplainDestinationInput) DestinationExplanation {
	in.Enabled = true
	in.Snapshot = f.snap
	in.EvidenceFor = func(addr netip.Addr) *Evidence {
		ev := f.scope.Inspect(addr, f.gen, f.now)
		return &ev
	}
	return ExplainDestination(in)
}

func noProhibited(netip.Addr) bool { return false }

func TestExplainDestinationDecisionTable(t *testing.T) {
	const (
		directAddr = "198.51.201.7"
		cidrAddr   = "198.51.200.9"
		narrowAddr = "198.51.200.200"
		plainAddr  = "198.51.201.20"
		proxyAddr  = "198.51.201.30"
	)

	t.Run("policy disabled is the legacy proxy route", func(t *testing.T) {
		f := newExplainFixture(t)
		got := ExplainDestination(ExplainDestinationInput{Enabled: false, Snapshot: f.snap})
		if got.Decision != ActionProxy || got.Reason != CausePolicyDisabled {
			t.Fatalf("disabled = %s/%s, want PROXY/%s", got.Decision, got.Reason, CausePolicyDisabled)
		}
		if got.Summary != SummaryNone {
			t.Errorf("summary = %s, want %s", got.Summary, SummaryNone)
		}
	})

	t.Run("prohibited destination drops before any rule is considered", func(t *testing.T) {
		f := newExplainFixture(t)
		prohibited := netip.MustParseAddr("192.0.2.10")
		got := f.explain(ExplainDestinationInput{
			Names:       []string{"a.blocked.example"},
			Addresses:   []netip.Addr{prohibited},
			Resolved:    true,
			Prohibited:  func(a netip.Addr) bool { return a == prohibited },
			EvidenceFor: nil,
		})
		if got.Decision != ActionDrop || got.Reason != CauseProhibitedDestination {
			t.Fatalf("prohibited = %s/%s, want DROP/%s", got.Decision, got.Reason, CauseProhibitedDestination)
		}
		if len(got.Addresses) != 1 || got.Addresses[0].Decision != ActionDrop {
			t.Fatalf("address verdicts = %+v, want one DROP", got.Addresses)
		}
	})

	t.Run("exact apex rule", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"apex.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(directAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		assertRule(t, got, ActionProxy, CauseDomainRule, "apex.example", DomainRuleApex, []string{"geoblock"})
	})

	t.Run("inclusive suffix rule on a subdomain", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"deep.a.blocked.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(directAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		assertRule(t, got, ActionProxy, CauseDomainRule, "blocked.example", DomainRuleApexAndSubdomains, []string{"geoblock"})
	})

	t.Run("descendants rule matches below the apex only", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"sub.wild.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(directAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		assertRule(t, got, ActionProxy, CauseDomainRule, "wild.example", DomainRuleSubdomains, []string{"geoblock"})

		if f.snap.MatchDomain("wild.example") {
			t.Error("a descendants-only rule must not match the apex")
		}
	})

	t.Run("CNAME target rule", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"edge.cdn.example", "a.blocked.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(directAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		assertRule(t, got, ActionProxy, CauseCNAMERule, "blocked.example", DomainRuleApexAndSubdomains, []string{"geoblock"})
		if got.RuleName != "a.blocked.example" {
			t.Errorf("rule name = %q, want the CNAME target", got.RuleName)
		}
	})

	t.Run("CIDR rule", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"plain.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(cidrAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseCIDRRule {
			t.Fatalf("cidr = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseCIDRRule)
		}
		if got.Prefix == nil || got.Prefix.Prefix.String() != "198.51.200.0/24" {
			t.Fatalf("prefix = %+v, want 198.51.200.0/24", got.Prefix)
		}
		if len(got.Prefix.Sources) != 1 || got.Prefix.Sources[0] != "custom-1" {
			t.Fatalf("prefix sources = %v, want [custom-1]", got.Prefix.Sources)
		}
	})

	t.Run("most specific CIDR prefix wins", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Addresses:  []netip.Addr{netip.MustParseAddr(narrowAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Prefix == nil || got.Prefix.Prefix.String() != "198.51.200.128/25" {
			t.Fatalf("prefix = %+v, want the narrowest containing prefix 198.51.200.128/25", got.Prefix)
		}
	})

	t.Run("fresh direct evidence", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, plainAddr, "DIRECT", 120*time.Second)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"plain.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(plainAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionDirect || got.Reason != CauseFreshEvidenceDirect {
			t.Fatalf("evidence = %s/%s, want DIRECT/%s", got.Decision, got.Reason, CauseFreshEvidenceDirect)
		}
		if got.Evidence == nil || got.Evidence.State != EvidenceFresh || got.Evidence.Decision != Direct {
			t.Fatalf("evidence = %+v, want fresh Direct", got.Evidence)
		}
		if remaining := got.Evidence.Remaining(f.now); remaining != 120*time.Second {
			t.Fatalf("remaining TTL = %v, want 120s", remaining)
		}
	})

	t.Run("fresh proxy evidence is a shared-IP conflict", func(t *testing.T) {
		f := newExplainFixture(t)
		// Another name that resolves to the same address is proxy-required, so the
		// cache holds PROXY for it and PROXY wins over any direct evidence.
		f.observe(t, proxyAddr, "PROXY", 60*time.Second)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"unlisted.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(proxyAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseSharedIPConflict {
			t.Fatalf("shared ip = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseSharedIPConflict)
		}
		if got.Evidence == nil || got.Evidence.Decision != Proxy {
			t.Fatalf("evidence = %+v, want the proxy observation", got.Evidence)
		}
	})

	t.Run("expired evidence", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, plainAddr, "DIRECT", 30*time.Second)
		// Move the explanation window past the stored deadline without touching
		// the cache: Inspect is evaluated at the later time.
		later := *f
		later.now = f.now.Add(2 * time.Minute)
		got := later.explain(ExplainDestinationInput{
			Names:      []string{"plain.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(plainAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseExpiredEvidence {
			t.Fatalf("expired = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseExpiredEvidence)
		}
		if got.Evidence == nil || got.Evidence.State != EvidenceExpired {
			t.Fatalf("evidence = %+v, want expired", got.Evidence)
		}
	})

	t.Run("evicted evidence after a capacity quarantine", func(t *testing.T) {
		now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
		snap, err := CompileSnapshot(3, "gen-3", []SourceParsedRules{{
			SourceID: "custom-1",
			Rules:    ParsedRules{Domains: map[string]domainFlags{"other.example": domainInclusiveSuffix}},
		}})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		cache, err := NewRouteCache(CacheConfig{MaxEntriesPerSession: 1})
		if err != nil {
			t.Fatalf("new cache: %v", err)
		}
		cache.SetPolicyGeneration("gen-3")
		scope, err := cache.Open(Scope{SessionID: "session-1", OwnershipEpoch: 1})
		if err != nil {
			t.Fatalf("open scope: %v", err)
		}
		batch := func(addrs ...string) []Observation {
			out := make([]Observation, 0, len(addrs))
			for _, raw := range addrs {
				out = append(out, Observation{
					IP:        netip.MustParseAddr(raw),
					Decision:  Proxy,
					ExpiresAt: now.Add(time.Minute),
				})
			}
			return out
		}
		if err := scope.Observe("gen-3", batch("198.51.201.40"), now); err != nil {
			t.Fatalf("first observation: %v", err)
		}
		// Two proxy entries cannot fit in a one-entry session, and there is no
		// direct entry to evict, so the session is quarantined and its entries drop.
		if err := scope.Observe("gen-3", batch("198.51.201.41", "198.51.201.42"), now); err == nil {
			t.Fatal("expected the second observation to quarantine the session")
		}

		got := ExplainDestination(ExplainDestinationInput{
			Enabled:   true,
			Snapshot:  snap,
			Addresses: []netip.Addr{netip.MustParseAddr("198.51.201.40")},
			Resolved:  true,
			EvidenceFor: func(addr netip.Addr) *Evidence {
				ev := scope.Inspect(addr, "gen-3", now)
				return &ev
			},
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseEvictedEvidence {
			t.Fatalf("quarantined = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseEvictedEvidence)
		}
		if got.Evidence == nil || got.Evidence.State != EvidenceQuarantined {
			t.Fatalf("evidence = %+v, want quarantined", got.Evidence)
		}
	})

	t.Run("stale generation evidence", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, plainAddr, "DIRECT", time.Minute)
		got := ExplainDestination(ExplainDestinationInput{
			Enabled:   true,
			Snapshot:  f.snap,
			Addresses: []netip.Addr{netip.MustParseAddr(plainAddr)},
			Resolved:  true,
			EvidenceFor: func(addr netip.Addr) *Evidence {
				// The policy was refreshed after the observation: the evidence
				// belongs to the previous generation.
				ev := f.scope.Inspect(addr, "gen-8", f.now)
				return &ev
			},
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseStaleEvidence {
			t.Fatalf("stale = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseStaleEvidence)
		}
	})

	t.Run("retired session evidence is treated as no evidence", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, plainAddr, "DIRECT", time.Minute)
		other, err := f.cache.Open(Scope{SessionID: "session-2", OwnershipEpoch: 1})
		if err != nil {
			t.Fatalf("open second scope: %v", err)
		}
		other.Invalidate()
		got := ExplainDestination(ExplainDestinationInput{
			Enabled:   true,
			Snapshot:  f.snap,
			Addresses: []netip.Addr{netip.MustParseAddr(plainAddr)},
			Resolved:  true,
			EvidenceFor: func(addr netip.Addr) *Evidence {
				ev := other.Inspect(addr, f.gen, f.now)
				return &ev
			},
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseNoEvidence {
			t.Fatalf("retired = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseNoEvidence)
		}
	})

	t.Run("no evidence at all is the safe proxy default", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"plain.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(plainAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseNoEvidence {
			t.Fatalf("no evidence = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseNoEvidence)
		}
	})

	t.Run("no session selected is also the safe default", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, plainAddr, "DIRECT", time.Minute)
		got := ExplainDestination(ExplainDestinationInput{
			Enabled:    true,
			Snapshot:   f.snap,
			Names:      []string{"plain.example"},
			Addresses:  []netip.Addr{netip.MustParseAddr(plainAddr)},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseNoEvidence {
			t.Fatalf("no session = %s/%s, want PROXY/%s", got.Decision, got.Reason, CauseNoEvidence)
		}
		if got.Evidence != nil {
			t.Fatalf("evidence = %+v, want none without a session", got.Evidence)
		}
	})

	t.Run("unresolved name with a rule keeps the rule verdict", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"blocked.example"},
			Resolved:   false,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Reason != CauseDomainRule || got.Summary != SummaryRuleOnly {
			t.Fatalf("unresolved with rule = %s/%s/%s", got.Decision, got.Reason, got.Summary)
		}
	})

	t.Run("unresolved name without a rule is unknown, not invented", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"nothing.example"},
			Resolved:   false,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionUnknown || got.Reason != CauseNameUnresolved {
			t.Fatalf("unresolved = %s/%s, want UNKNOWN/%s", got.Decision, got.Reason, CauseNameUnresolved)
		}
	})

	t.Run("no usable address is unknown", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names:      []string{"nothing.example"},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionUnknown || got.Reason != CauseNoUsableAddress {
			t.Fatalf("no address = %s/%s, want UNKNOWN/%s", got.Decision, got.Reason, CauseNoUsableAddress)
		}
	})

	t.Run("several agreeing addresses are unanimous", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, "198.51.201.50", "DIRECT", time.Minute)
		f.observe(t, "198.51.201.51", "DIRECT", time.Minute)
		got := f.explain(ExplainDestinationInput{
			Names: []string{"multi.example"},
			Addresses: []netip.Addr{
				netip.MustParseAddr("198.51.201.50"),
				netip.MustParseAddr("198.51.201.51"),
			},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionDirect || got.Summary != SummaryUnanimous {
			t.Fatalf("unanimous = %s/%s, want DIRECT/%s", got.Decision, got.Summary, SummaryUnanimous)
		}
		if len(got.Addresses) != 2 {
			t.Fatalf("address verdicts = %d, want 2", len(got.Addresses))
		}
	})

	t.Run("several disagreeing addresses take the most restrictive", func(t *testing.T) {
		f := newExplainFixture(t)
		f.observe(t, "198.51.201.60", "DIRECT", time.Minute)
		got := f.explain(ExplainDestinationInput{
			Names: []string{"multi.example"},
			Addresses: []netip.Addr{
				netip.MustParseAddr("198.51.201.60"), // fresh DIRECT evidence
				netip.MustParseAddr(cidrAddr),        // CIDR rule → PROXY
			},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Summary != SummaryMostRestrictive {
			t.Fatalf("disagreeing = %s/%s, want PROXY/%s", got.Decision, got.Summary, SummaryMostRestrictive)
		}
		if got.Addresses[0].Decision != ActionDirect || got.Addresses[1].Decision != ActionProxy {
			t.Fatalf("per-address verdicts = %+v", got.Addresses)
		}
		if got.Reason != CauseCIDRRule {
			t.Fatalf("headline reason = %s, want the reason of the deciding address (%s)", got.Reason, CauseCIDRRule)
		}
	})

	t.Run("a name rule applies to every address of the name", func(t *testing.T) {
		f := newExplainFixture(t)
		got := f.explain(ExplainDestinationInput{
			Names: []string{"blocked.example"},
			Addresses: []netip.Addr{
				netip.MustParseAddr("198.51.201.70"),
				netip.MustParseAddr("198.51.201.71"),
			},
			Resolved:   true,
			Prohibited: noProhibited,
		})
		if got.Decision != ActionProxy || got.Summary != SummaryUnanimous {
			t.Fatalf("rule across addresses = %s/%s", got.Decision, got.Summary)
		}
	})
}

// assertRule checks the headline and the named rule that produced it.
func assertRule(t *testing.T, got DestinationExplanation, decision Action, cause Cause, base string, shape DomainRuleShape, sources []string) {
	t.Helper()
	if got.Decision != decision || got.Reason != cause {
		t.Fatalf("decision = %s/%s, want %s/%s", got.Decision, got.Reason, decision, cause)
	}
	if got.Rule == nil {
		t.Fatal("explanation carries no rule")
	}
	if got.Rule.Base != base {
		t.Errorf("rule base = %q, want %q", got.Rule.Base, base)
	}
	if got.Rule.Shape != shape {
		t.Errorf("rule shape = %q, want %q", got.Rule.Shape, shape)
	}
	if len(got.Rule.Sources) != len(sources) {
		t.Fatalf("rule sources = %v, want %v", got.Rule.Sources, sources)
	}
	for i := range sources {
		if got.Rule.Sources[i] != sources[i] {
			t.Fatalf("rule sources = %v, want %v", got.Rule.Sources, sources)
		}
	}
}

// TestExplainDestinationIsReadOnly is the no-side-effect proof: the route cache,
// its entry and session counts and the evidence for the explained destination
// are identical before and after a full explanation, and no evidence appears for
// an address that only a CIDR rule matched.
//
// The policy package owns no traffic counters. The forwarder counters that the
// data path increments are asserted unchanged by the vpn-level test
// (TestExplainPolicyLeavesCountersAndCacheUntouched), because policy cannot
// import the forwarder.
func TestExplainDestinationIsReadOnly(t *testing.T) {
	f := newExplainFixture(t)
	f.observe(t, "198.51.201.80", "DIRECT", time.Minute)

	unexplained := netip.MustParseAddr("198.51.201.90")
	beforeEntries := f.cache.EntryCount()
	beforeSessions := f.cache.SessionCount()
	beforeExplained := f.scope.Inspect(netip.MustParseAddr("198.51.201.80"), f.gen, f.now)
	beforeUnexplained := f.scope.Inspect(unexplained, f.gen, f.now)

	if got := f.explain(ExplainDestinationInput{
		Names:      []string{"plain.example"},
		Addresses:  []netip.Addr{netip.MustParseAddr("198.51.201.80"), unexplained},
		Resolved:   true,
		Prohibited: noProhibited,
	}); len(got.Addresses) != 2 || got.Addresses[0].Decision != ActionDirect {
		t.Fatalf("decision = %s (%+v), want the seeded DIRECT evidence for the first address", got.Decision, got.Addresses)
	}

	if after := f.cache.EntryCount(); after != beforeEntries {
		t.Errorf("route-cache entry count changed by the explanation: %d → %d", beforeEntries, after)
	}
	if after := f.cache.SessionCount(); after != beforeSessions {
		t.Errorf("route-cache session count changed by the explanation: %d → %d", beforeSessions, after)
	}
	if after := f.scope.Inspect(netip.MustParseAddr("198.51.201.80"), f.gen, f.now); after != beforeExplained {
		t.Errorf("existing evidence changed: %+v → %+v", beforeExplained, after)
	}
	if after := f.scope.Inspect(unexplained, f.gen, f.now); after != beforeUnexplained {
		t.Errorf("the explanation recorded evidence: %+v → %+v", beforeUnexplained, after)
	}
	if state := f.scope.Inspect(unexplained, f.gen, f.now); state.State != EvidenceAbsent {
		t.Errorf("an explained address gained evidence: %+v", state)
	}
	if sc := f.cache.Get(Scope{SessionID: "never-opened", OwnershipEpoch: 1}); sc != nil {
		t.Error("the explanation created a session scope")
	}
}
