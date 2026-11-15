package vpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests drive the explanation through the real snapshot, a real route
// cache and a fake resolver, so the resolution path, the summary of several
// addresses and the read-only property are exercised without a data path, a WAN
// device or a packet.

// fakeExplainResolver is a resolver.Exchange double that records how often it was
// asked to look something up.
type fakeExplainResolver struct {
	mu    sync.Mutex
	calls int
	resp  *mdns.Msg
	err   error
}

func (f *fakeExplainResolver) Exchange(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeExplainResolver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// explainAnswer builds a response for name, following the given CNAME targets
// and ending in the given A records.
func explainAnswer(t *testing.T, name string, cnames, addrs []string) *mdns.Msg {
	t.Helper()
	resp := new(mdns.Msg)
	resp.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	resp.Response = true
	current := mdns.Fqdn(name)
	for _, target := range cnames {
		resp.Answer = append(resp.Answer, &mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: current, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300},
			Target: mdns.Fqdn(target),
		})
		current = mdns.Fqdn(target)
	}
	for _, raw := range addrs {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("invalid fixture address %q", raw)
		}
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: current, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 120},
			A:   ip.To4(),
		})
	}
	return resp
}

// explainTestSnapshot compiles a one-source policy with a domain rule and a CIDR
// rule, and opens a session scope on a real route cache under the same
// generation.
func explainTestSnapshot(t *testing.T) (*policy.Snapshot, *policy.RouteCache, *policy.SessionCache, string, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	// The rule maps are unexported, so rules are built the production way: by
	// parsing a list.
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("blocked.example\n198.51.200.0/24\n"),
		policy.Source{
			ID:             "geoblock",
			Format:         policy.FormatMixed,
			BareDomainMode: policy.DomainModeInclusiveSuffix,
		}, policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("parse fixture rules: %v", err)
	}
	snap, err := policy.CompileSnapshot(11, "gen-11", []policy.SourceParsedRules{{
		SourceID: "geoblock",
		Rules:    rules,
	}})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}
	cache, err := policy.NewRouteCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("new route cache: %v", err)
	}
	cache.SetPolicyGeneration("gen-11")
	scope, err := cache.Open(policy.Scope{SessionID: "session-1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}
	return snap, cache, scope, "gen-11", now
}

func TestExplainPolicyResolvesThroughTheConfiguredResolver(t *testing.T) {
	snap, cache, scope, _, now := explainTestSnapshot(t)
	resolver := &fakeExplainResolver{resp: explainAnswer(t, "www.example",
		[]string{"edge.cdn.example"}, []string{"198.51.201.10", "198.51.201.11"})}

	out, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled:      true,
		Snapshot:     snap,
		SessionScope: scope,
		Resolver:     resolver,
		Upstreams:    []policy.Upstream{{Address: "1.1.1.1", Port: 53}},
		Now:          now,
	}, PolicyExplainRequest{Value: "www.example", Name: "www.example"})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}

	if got := out.Resolution.Method; got != policyExplainMethodConfiguredResolver {
		t.Fatalf("resolution method = %q, want %q", got, policyExplainMethodConfiguredResolver)
	}
	if len(out.Resolution.Nameservers) != 1 || out.Resolution.Nameservers[0] != "1.1.1.1:53" {
		t.Fatalf("nameservers = %v, want the configured upstream", out.Resolution.Nameservers)
	}
	wantNames := []string{"www.example", "edge.cdn.example"}
	if len(out.Resolution.Names) != len(wantNames) {
		t.Fatalf("traversed names = %v, want %v", out.Resolution.Names, wantNames)
	}
	for i := range wantNames {
		if out.Resolution.Names[i] != wantNames[i] {
			t.Fatalf("traversed names = %v, want %v", out.Resolution.Names, wantNames)
		}
	}
	if len(out.Addresses) != 2 {
		t.Fatalf("address verdicts = %d, want both A records", len(out.Addresses))
	}
	// No rule matches and the session holds no evidence, so the safe default wins
	// for both addresses and the answer says so.
	if out.Decision != string(policy.ActionProxy) || out.Reason != string(policy.CauseNoEvidence) {
		t.Fatalf("decision = %s/%s, want PROXY/%s", out.Decision, out.Reason, policy.CauseNoEvidence)
	}
	if out.Summary != string(policy.SummaryUnanimous) {
		t.Fatalf("summary = %s, want %s", out.Summary, policy.SummaryUnanimous)
	}
	if !out.ReadOnly {
		t.Error("the answer must state that it is read-only")
	}
	if got := cache.EntryCount(); got != 0 {
		t.Errorf("the lookup recorded %d evidence entries", got)
	}
}

// TestExplainPolicySummarisesSeveralAddresses proves the documented summary: the
// addresses disagree (one CIDR rule, one fresh DIRECT evidence), the headline is
// the most restrictive verdict, and every per-address cause is reported.
func TestExplainPolicySummarisesSeveralAddresses(t *testing.T) {
	snap, _, scope, gen, now := explainTestSnapshot(t)
	if err := scope.Observe(gen, []policy.Observation{{
		IP:        netip.MustParseAddr("198.51.201.20"),
		Decision:  policy.Direct,
		ExpiresAt: now.Add(2 * time.Minute),
	}}, now); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	resolver := &fakeExplainResolver{resp: explainAnswer(t, "split.example", nil,
		[]string{"198.51.200.9", "198.51.201.20"})}

	out, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled:      true,
		Snapshot:     snap,
		SessionScope: scope,
		Resolver:     resolver,
		Now:          now,
	}, PolicyExplainRequest{Value: "split.example", Name: "split.example"})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}

	if out.Decision != string(policy.ActionProxy) || out.Reason != string(policy.CauseCIDRRule) {
		t.Fatalf("headline = %s/%s, want PROXY/%s", out.Decision, out.Reason, policy.CauseCIDRRule)
	}
	if out.Summary != string(policy.SummaryMostRestrictive) {
		t.Fatalf("summary = %s, want %s", out.Summary, policy.SummaryMostRestrictive)
	}
	if len(out.Addresses) != 2 {
		t.Fatalf("addresses = %d, want 2", len(out.Addresses))
	}
	if out.Addresses[0].Reason != string(policy.CauseCIDRRule) || out.Addresses[0].Prefix == nil {
		t.Fatalf("first verdict = %+v, want the CIDR rule", out.Addresses[0])
	}
	if out.Addresses[1].Decision != string(policy.ActionDirect) || out.Addresses[1].Reason != string(policy.CauseFreshEvidenceDirect) {
		t.Fatalf("second verdict = %+v, want DIRECT from fresh evidence", out.Addresses[1])
	}
	if out.Addresses[1].Evidence == nil || out.Addresses[1].Evidence.State != string(policy.EvidenceFresh) {
		t.Fatalf("second verdict evidence = %+v, want fresh", out.Addresses[1].Evidence)
	}
	if out.Addresses[1].Evidence.Source != policyExplainEvidenceSource {
		t.Errorf("fresh evidence source = %q, want %q",
			out.Addresses[1].Evidence.Source, policyExplainEvidenceSource)
	}
	// The first address matched a CIDR rule, so it has no evidence at all; nothing
	// may claim an observation source for it.
	if out.Addresses[0].Evidence != nil {
		t.Errorf("first verdict carries evidence %+v, want none", out.Addresses[0].Evidence)
	}
}

func TestExplainPolicyUnresolvableName(t *testing.T) {
	snap, _, scope, _, now := explainTestSnapshot(t)

	t.Run("resolver failure", func(t *testing.T) {
		resolver := &fakeExplainResolver{err: errors.New("upstream DNS exchange failed")}
		out, err := explainPolicy(context.Background(), policyExplainDeps{
			Enabled: true, Snapshot: snap, SessionScope: scope, Resolver: resolver, Now: now,
		}, PolicyExplainRequest{Value: "missing.example", Name: "missing.example"})
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		if out.Resolution.Error == "" {
			t.Fatal("a failed lookup must be reported, not hidden")
		}
		if len(out.Addresses) != 0 {
			t.Fatalf("addresses = %v, want none", out.Addresses)
		}
		if out.Decision != string(policy.ActionUnknown) || out.Reason != string(policy.CauseNameUnresolved) {
			t.Fatalf("decision = %s/%s, want UNKNOWN/%s", out.Decision, out.Reason, policy.CauseNameUnresolved)
		}
	})

	t.Run("answer without an address", func(t *testing.T) {
		resolver := &fakeExplainResolver{resp: explainAnswer(t, "empty.example", nil, nil)}
		out, err := explainPolicy(context.Background(), policyExplainDeps{
			Enabled: true, Snapshot: snap, SessionScope: scope, Resolver: resolver, Now: now,
		}, PolicyExplainRequest{Value: "empty.example", Name: "empty.example"})
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		if out.Resolution.Error == "" {
			t.Fatal("an answer with no usable address must be reported")
		}
		if out.Decision != string(policy.ActionUnknown) {
			t.Fatalf("decision = %s, want UNKNOWN", out.Decision)
		}
	})

	t.Run("no resolver installed", func(t *testing.T) {
		out, err := explainPolicy(context.Background(), policyExplainDeps{
			Enabled: true, Snapshot: snap, SessionScope: scope, Now: now,
		}, PolicyExplainRequest{Value: "missing.example", Name: "missing.example"})
		if err != nil {
			t.Fatalf("explain: %v", err)
		}
		if out.Resolution.Method != policyExplainMethodUnavailable || out.Resolution.Error == "" {
			t.Fatalf("resolution = %+v, want an unavailable method and a reason", out.Resolution)
		}
	})
}

// TestExplainPolicyCallerAddressesSkipResolution proves the "evaluate exactly
// these addresses" contract: no query is sent, and the answer says so.
func TestExplainPolicyCallerAddressesSkipResolution(t *testing.T) {
	snap, _, scope, _, now := explainTestSnapshot(t)
	resolver := &fakeExplainResolver{err: errors.New("must not be called")}

	out, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: scope, Resolver: resolver, Now: now,
	}, PolicyExplainRequest{
		Value:     "198.51.200.9",
		Addresses: []netip.Addr{netip.MustParseAddr("198.51.200.9")},
	})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if got := resolver.callCount(); got != 0 {
		t.Fatalf("resolver was called %d times, want 0", got)
	}
	if out.Resolution.Method != policyExplainMethodCallerSupplied {
		t.Fatalf("resolution method = %q, want %q", out.Resolution.Method, policyExplainMethodCallerSupplied)
	}
	if out.Decision != string(policy.ActionProxy) || out.Reason != string(policy.CauseCIDRRule) {
		t.Fatalf("decision = %s/%s, want PROXY/%s", out.Decision, out.Reason, policy.CauseCIDRRule)
	}
	if out.Input.Kind != "address" {
		t.Fatalf("input kind = %q, want address", out.Input.Kind)
	}
	if len(out.Limitations) == 0 {
		t.Fatal("an address-only answer must state its limitations")
	}
	if out.Prefix == nil || out.Prefix.SourceKind != "preset" {
		t.Fatalf("prefix = %+v, want the preset source kind named", out.Prefix)
	}
}

// TestPolicyExplainSourceKind pins the preset/custom classification an operator
// reads alongside a matched rule.
func TestPolicyExplainSourceKind(t *testing.T) {
	cases := []struct {
		sources []string
		want    string
	}{
		{nil, ""},
		{[]string{"geoblock"}, "preset"},
		{[]string{"antifilter_ipv4"}, "preset"},
		{[]string{"custom-1"}, "custom"},
		{[]string{"custom-1", "custom-2"}, "custom"},
		{[]string{"geoblock", "custom-1"}, "mixed"},
	}
	for _, tc := range cases {
		if got := policyExplainSourceKind(tc.sources); got != tc.want {
			t.Errorf("policyExplainSourceKind(%v) = %q, want %q", tc.sources, got, tc.want)
		}
	}
}

// TestPolicyExplainSessionLimitations distinguishes "no session was asked about"
// from "the selected session holds no cached evidence": the two mean different
// things to an operator debugging a missing direct path.
func TestPolicyExplainSessionLimitations(t *testing.T) {
	snap, _, scope, _, now := explainTestSnapshot(t)
	hasLimitation := func(limits []string, want string) bool {
		for _, limit := range limits {
			if limit == want {
				return true
			}
		}
		return false
	}

	withoutSession, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: scope, Now: now,
	}, PolicyExplainRequest{Value: "198.51.200.9", Addresses: []netip.Addr{netip.MustParseAddr("198.51.200.9")}})
	if err != nil {
		t.Fatalf("explain without a session: %v", err)
	}
	if !hasLimitation(withoutSession.Limitations, PolicyLimitNoSession) {
		t.Errorf("limitations = %v, want %q", withoutSession.Limitations, PolicyLimitNoSession)
	}

	withUnknownSession, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: nil, Now: now,
	}, PolicyExplainRequest{
		Value: "198.51.200.9", Addresses: []netip.Addr{netip.MustParseAddr("198.51.200.9")},
		SessionID: "session-without-scope",
	})
	if err != nil {
		t.Fatalf("explain with an unscoped session: %v", err)
	}
	if !hasLimitation(withUnknownSession.Limitations, PolicyLimitNoSessionData) {
		t.Errorf("limitations = %v, want %q", withUnknownSession.Limitations, PolicyLimitNoSessionData)
	}
}

func TestExplainPolicyDisabledSkipsEverything(t *testing.T) {
	snap, cache, _, _, now := explainTestSnapshot(t)
	resolver := &fakeExplainResolver{err: errors.New("must not be called")}

	out, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: false, Snapshot: snap, Resolver: resolver, Now: now,
	}, PolicyExplainRequest{Value: "www.example", Name: "www.example"})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if out.Decision != string(policy.ActionProxy) || out.Reason != string(policy.CausePolicyDisabled) {
		t.Fatalf("decision = %s/%s, want PROXY/%s", out.Decision, out.Reason, policy.CausePolicyDisabled)
	}
	if out.Resolution.Method != policyExplainMethodNotAttempted {
		t.Fatalf("resolution = %q, want %q", out.Resolution.Method, policyExplainMethodNotAttempted)
	}
	if got := resolver.callCount(); got != 0 {
		t.Fatalf("resolver was called %d times with policy routing disabled", got)
	}
	if got := cache.SessionCount(); got != 1 {
		t.Fatalf("session count = %d, want the single fixture scope", got)
	}
	if got := cache.EntryCount(); got != 0 {
		t.Fatalf("entry count = %d, want no evidence", got)
	}
}

// TestExplainPolicyLeavesRouteCacheUntouched is the vpn-level no-side-effect
// proof: entry count, session count and the evidence of the explained address
// are identical before and after, and the explained address that only matched a
// CIDR rule gained no evidence.
func TestExplainPolicyLeavesRouteCacheUntouched(t *testing.T) {
	snap, cache, scope, gen, now := explainTestSnapshot(t)
	if err := scope.Observe(gen, []policy.Observation{{
		IP:        netip.MustParseAddr("198.51.201.40"),
		Decision:  policy.Direct,
		ExpiresAt: now.Add(time.Minute),
	}}, now); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	entriesBefore := cache.EntryCount()
	sessionsBefore := cache.SessionCount()
	evidenceBefore := scope.Inspect(netip.MustParseAddr("198.51.201.40"), gen, now)
	unobservedBefore := scope.Inspect(netip.MustParseAddr("198.51.200.9"), gen, now)

	resolver := &fakeExplainResolver{resp: explainAnswer(t, "both.example", nil,
		[]string{"198.51.201.40", "198.51.200.9"})}
	if _, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: scope, Resolver: resolver, Now: now,
	}, PolicyExplainRequest{Value: "both.example", Name: "both.example", SessionID: "session-1"}); err != nil {
		t.Fatalf("explain: %v", err)
	}

	if got := cache.EntryCount(); got != entriesBefore {
		t.Errorf("entry count = %d, want %d", got, entriesBefore)
	}
	if got := cache.SessionCount(); got != sessionsBefore {
		t.Errorf("session count = %d, want %d", got, sessionsBefore)
	}
	if got := scope.Inspect(netip.MustParseAddr("198.51.201.40"), gen, now); got != evidenceBefore {
		t.Errorf("existing evidence changed: %+v → %+v", evidenceBefore, got)
	}
	if got := scope.Inspect(netip.MustParseAddr("198.51.200.9"), gen, now); got != unobservedBefore || got.State != policy.EvidenceAbsent {
		t.Errorf("the explanation recorded evidence for the CIDR address: %+v", got)
	}
}
