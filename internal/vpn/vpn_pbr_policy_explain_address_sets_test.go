package vpn

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Regression for the owner review HIGH-01 on PR #844 (issue #825).
//
// The shared DNS classifier once served two questions with one address set:
// "may this address become trusted evidence" and "which destinations does an
// operator need evaluated". A name resolving to 10.0.0.5, which production
// routing drops, was filtered out as ineligible evidence and explained as
// UNKNOWN. These tests drive the real production decision function
// (Forwarder.RouteClientToBackend over the production MemoryRouteCache and the
// production observation path) and the real explainer from one DNS answer and
// require them to agree per destination and in the headline.

const addressSetsSession = "address-sets-session"

// addressSetsFixture is one policy, one production route cache and one real
// forwarder whose policy routing is enabled. The explainer reads the very same
// cache scope the forwarder consults, so the two cannot diverge by fixture.
type addressSetsFixture struct {
	snap     *policy.Snapshot
	cache    *MemoryRouteCache
	fwd      *forwarder.Forwarder
	wan      *mockPBRDevice
	nextPort uint16
}

func newAddressSetsFixture(t *testing.T) *addressSetsFixture {
	t.Helper()
	rules, _, err := policy.Parse(context.Background(),
		strings.NewReader("blocked.example\n198.51.200.0/24\n"),
		policy.Source{ID: "custom-1", Format: policy.FormatMixed, BareDomainMode: policy.DomainModeInclusiveSuffix},
		policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("parse fixture rules: %v", err)
	}
	snap, err := policy.CompileSnapshot(1, "gen-address-sets", []policy.SourceParsedRules{{SourceID: "custom-1", Rules: rules}})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}
	matcher := policy.NewMatcher()
	matcher.Publish(snap)
	cache := NewMemoryRouteCache()
	cache.AttachMatcher(matcher)
	if _, err := cache.Open(policy.Scope{SessionID: addressSetsSession, OwnershipEpoch: 1}); err != nil {
		t.Fatalf("open session scope: %v", err)
	}

	gwDNS := netip.MustParseAddr("10.100.0.1")
	wan := &mockPBRDevice{}
	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 64)
	dem := forwarder.NewDirectEgressManager(forwarder.DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"), GatewayDNSIP: gwDNS, WANDevice: wan,
	}, fwd)
	t.Cleanup(func() { _ = dem.Close() })
	fwd.SetDirectEgress(dem)
	fwd.SetPBREnabled(true)
	fwd.SetGatewayDNSIP(gwDNS)
	fwd.SetPolicyMatcher(matcher)
	fwd.SetRouteCache(cache)
	fwd.AttachBackendDevice(1, &mockPBRDevice{})
	fwd.RegisterSessionWithReturnPath(addressSetsSession, "conn-1", "peer-1", "10.100.0.10", 1,
		forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil }))
	return &addressSetsFixture{snap: snap, cache: cache, fwd: fwd, wan: wan, nextPort: 30000}
}

// observe feeds the answer through the production observation path.
func (f *addressSetsFixture) observe(t *testing.T, name string, resp *mdns.Msg) {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	if err := f.cache.ObserveDNSResponseEvidence(addressSetsSession, query, resp); err != nil {
		t.Fatalf("production observation: %v", err)
	}
}

// productionAction sends one fresh flow to dst through the production dispatcher
// and reports what it actually did, from the error and the real counters.
func (f *addressSetsFixture) productionAction(t *testing.T, dst netip.Addr) policy.Action {
	t.Helper()
	direct, proxied := f.fwd.DirectBytes(), f.fwd.ProxiedBytes()
	f.nextPort++
	pkt := buildTestPBRTCPPacket(netip.MustParseAddr("10.100.0.10"), dst, f.nextPort, 443, []byte("probe"))
	err := f.fwd.RouteClientToBackend("peer-1", pkt)
	switch {
	case errors.Is(err, forwarder.ErrProhibitedDestination):
		return policy.ActionDrop
	case err != nil:
		t.Fatalf("dispatch to %s failed for an unexpected reason: %v", dst, err)
	case f.fwd.DirectBytes() > direct && f.fwd.ProxiedBytes() == proxied:
		return policy.ActionDirect
	case f.fwd.ProxiedBytes() > proxied && f.fwd.DirectBytes() == direct:
		return policy.ActionProxy
	}
	t.Fatalf("dispatch to %s had no single observable outcome", dst)
	return ""
}

func (f *addressSetsFixture) explain(t *testing.T, name string, resp *mdns.Msg) PolicyExplanation {
	t.Helper()
	out, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: true, Snapshot: f.snap, SessionScope: f.cache.SessionScope(addressSetsSession),
		Resolver: &fakeExplainResolver{resp: resp}, Clock: time.Now,
	}, PolicyExplainRequest{Name: name, Value: name, SessionID: addressSetsSession})
	if err != nil {
		t.Fatalf("explain %s: %v", name, err)
	}
	return out
}

// restriction orders actions the way the explainer's headline does.
func restriction(a policy.Action) int {
	switch a {
	case policy.ActionDrop:
		return 3
	case policy.ActionProxy:
		return 2
	default:
		return 0
	}
}

// TestExplainAgreesWithProductionOnResolvedDestinations is the parity oracle:
// per destination the explainer must give the action the production dispatcher
// takes, and the headline must be the most restrictive of those actions.
func TestExplainAgreesWithProductionOnResolvedDestinations(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		addrs     []string
		wantEach  []policy.Action
		wantCause []policy.Cause
		wantHead  policy.Action
		wantSum   policy.Summary
	}{
		{
			name: "prohibited address alone", host: "internal.example", addrs: []string{"10.0.0.5"},
			wantEach: []policy.Action{policy.ActionDrop}, wantCause: []policy.Cause{policy.CauseProhibitedDestination},
			wantHead: policy.ActionDrop, wantSum: policy.SummarySingle,
		},
		{
			name: "mixed public and prohibited answer", host: "mixed.example", addrs: []string{"198.51.201.30", "10.0.0.5"},
			wantEach:  []policy.Action{policy.ActionDirect, policy.ActionDrop},
			wantCause: []policy.Cause{policy.CauseFreshEvidenceDirect, policy.CauseProhibitedDestination},
			wantHead:  policy.ActionDrop, wantSum: policy.SummaryMostRestrictive,
		},
		{
			name: "prohibited address listed first", host: "mixed-first.example", addrs: []string{"10.0.0.5", "198.51.201.31"},
			wantEach:  []policy.Action{policy.ActionDrop, policy.ActionDirect},
			wantCause: []policy.Cause{policy.CauseProhibitedDestination, policy.CauseFreshEvidenceDirect},
			wantHead:  policy.ActionDrop, wantSum: policy.SummaryMostRestrictive,
		},
		{
			name: "fresh DIRECT evidence", host: "plain.example", addrs: []string{"198.51.201.40"},
			wantEach: []policy.Action{policy.ActionDirect}, wantCause: []policy.Cause{policy.CauseFreshEvidenceDirect},
			wantHead: policy.ActionDirect, wantSum: policy.SummarySingle,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddressSetsFixture(t)
			resp := explainAnswer(t, tc.host, nil, tc.addrs)
			f.observe(t, tc.host, resp)
			out := f.explain(t, tc.host, resp)

			if len(out.Addresses) != len(tc.addrs) {
				t.Fatalf("explained %d destinations, want every resolved one (%v): %+v", len(out.Addresses), tc.addrs, out.Addresses)
			}
			head := policy.ActionDirect
			for i, raw := range tc.addrs {
				produced := f.productionAction(t, netip.MustParseAddr(raw))
				got := out.Addresses[i]
				if got.Address != raw || got.Decision != string(produced) {
					t.Errorf("%s: explainer %s %s, production %s", raw, got.Address, got.Decision, produced)
				}
				if produced != tc.wantEach[i] || got.Reason != string(tc.wantCause[i]) {
					t.Errorf("%s: production %s / explainer reason %s, want %s / %s",
						raw, produced, got.Reason, tc.wantEach[i], tc.wantCause[i])
				}
				if restriction(produced) > restriction(head) {
					head = produced
				}
			}
			if out.Decision != string(head) || head != tc.wantHead {
				t.Errorf("headline = %s, most restrictive production outcome = %s, want %s", out.Decision, head, tc.wantHead)
			}
			if out.Summary != string(tc.wantSum) {
				t.Errorf("summary = %s, want %s", out.Summary, tc.wantSum)
			}
			if out.Resolution.Error != "" {
				t.Errorf("a resolved answer must not carry a resolution error: %q", out.Resolution.Error)
			}
		})
	}
}

// TestExplainAddresslessAnswerKeepsProspectiveMatch covers the second half of the
// finding: an answer with no terminal A record used to discard the submitted
// name, so a domain that matches a rule was never matched.
func TestExplainAddresslessAnswerKeepsProspectiveMatch(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		cnames     []string
		wantReason policy.Cause
		wantName   string
	}{
		{name: "queried name matches", host: "www.blocked.example", wantReason: policy.CauseDomainRule, wantName: "www.blocked.example"},
		{name: "CNAME target matches", host: "front.other.example", cnames: []string{"edge.blocked.example"},
			wantReason: policy.CauseCNAMERule, wantName: "edge.blocked.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddressSetsFixture(t)
			resp := explainAnswer(t, tc.host, tc.cnames, nil)
			f.observe(t, tc.host, resp)
			out := f.explain(t, tc.host, resp)

			if out.Prospective == nil || !out.Prospective.Matched {
				t.Fatalf("the rule match was lost for an address-less answer: %+v", out.Prospective)
			}
			if out.Prospective.Reason != string(tc.wantReason) || out.Prospective.MatchedName != tc.wantName {
				t.Errorf("prospective = %s on %q, want %s on %q",
					out.Prospective.Reason, out.Prospective.MatchedName, tc.wantReason, tc.wantName)
			}
			if out.Prospective.Rule == nil || out.Prospective.Rule.Base != "blocked.example" {
				t.Errorf("matched rule = %+v, want base blocked.example", out.Prospective.Rule)
			}
			// The cause label is deliberately not pinned: this finding requires only
			// that there is no current action to report while the rule match stays.
			if out.Decision != string(policy.ActionUnknown) {
				t.Errorf("current action = %s/%s, want UNKNOWN", out.Decision, out.Reason)
			}
			if len(out.Addresses) != 0 || out.Resolution.Error == "" {
				t.Errorf("an address-less answer must be reported as such: addresses=%v error=%q", out.Addresses, out.Resolution.Error)
			}
			if got := f.cache.SessionScope(addressSetsSession).Inspect(netip.MustParseAddr("198.51.201.99"),
				f.snap.Generation(), time.Now()); got.State != policy.EvidenceAbsent {
				t.Errorf("an address-less answer recorded evidence: %+v", got)
			}
		})
	}
}

// TestExplainProhibitedDestinationIsNeverRecordedAsEvidence pins the production
// boundary the fix must not move: the explainer evaluates 10.0.0.5, but the
// session cache still holds nothing for it and the public address alone is recorded.
func TestExplainProhibitedDestinationIsNeverRecordedAsEvidence(t *testing.T) {
	f := newAddressSetsFixture(t)
	resp := explainAnswer(t, "mixed.example", nil, []string{"10.0.0.5", "198.51.201.30"})
	f.observe(t, "mixed.example", resp)
	scope := f.cache.SessionScope(addressSetsSession)
	now := time.Now()

	if got := scope.Inspect(netip.MustParseAddr("10.0.0.5"), f.snap.Generation(), now); got.State != policy.EvidenceAbsent {
		t.Errorf("prohibited destination became evidence: %+v", got)
	}
	if got := scope.Inspect(netip.MustParseAddr("198.51.201.30"), f.snap.Generation(), now); got.State != policy.EvidenceFresh || got.Decision != policy.Direct {
		t.Errorf("public destination evidence = %+v, want fresh DIRECT", got)
	}
	before := f.cache.RouteCache().EntryCount()
	_ = f.explain(t, "mixed.example", resp)
	if after := f.cache.RouteCache().EntryCount(); after != before {
		t.Errorf("explaining changed the cache entry count: %d -> %d", before, after)
	}
	if got := scope.Inspect(netip.MustParseAddr("10.0.0.5"), f.snap.Generation(), now); got.State != policy.EvidenceAbsent {
		t.Errorf("explaining a prohibited destination created evidence: %+v", got)
	}
}
