package forwarder

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Parity oracle for the policy dry run (issue #825, repair of review finding
// F825-01).
//
// The review's counterexample was an answer that disagreed with the packet path:
// a listed name sharing an address the session already routes DIRECT explained
// as PROXY/domain_rule, while the real dispatcher sent the packet direct. The
// explanation now reports the rule separately as a prospective classification.
//
// This file asserts the property that actually matters: for a fresh application
// flow, the explained CURRENT ACTION equals what Forwarder.RouteClientToBackend
// does with the authentic session cache. It drives the real dispatcher with
// in-memory WAN/backend devices and the real policy.RouteCache — only the
// forwarder's session-id→evidence adapter is local, and it calls the real
// SessionCache.
//
// Case list (one behavior per review requirement): the counterexample itself,
// a CIDR-proxy destination, a genuinely cached PROXY decision, and a fresh
// DIRECT destination with no matching rule. The prohibited destination is
// included because it is the third possible action.

// explainParityCache adapts the authentic session cache to the forwarder's
// RouteCache interface. It answers exactly as the packet path would: the real
// SessionCache.Lookup at the current time.
type explainParityCache struct {
	scope *policy.SessionCache
	gen   string
}

func (c explainParityCache) Lookup(_ string, ip netip.Addr) policy.Decision {
	return c.scope.Lookup(ip, c.gen, time.Now())
}

// explainParityFixture is one compiled policy, one seeded session cache, and one
// real forwarder whose PBR path is enabled.
type explainParityFixture struct {
	snap  *policy.Snapshot
	cache *policy.RouteCache
	scope *policy.SessionCache
	fwd   *Forwarder
	wan   *mockPacketDev
	gen   string
}

func newExplainParityFixture(t *testing.T) *explainParityFixture {
	t.Helper()
	rules, _, err := policy.Parse(context.Background(),
		strings.NewReader("blocked.example\n198.51.200.0/24\n"),
		policy.Source{ID: "custom-1", Format: policy.FormatMixed, BareDomainMode: policy.DomainModeInclusiveSuffix},
		policy.DefaultParseLimits())
	if err != nil {
		t.Fatalf("parse fixture rules: %v", err)
	}
	snap, err := policy.CompileSnapshot(1, "gen-parity-825", []policy.SourceParsedRules{{
		SourceID: "custom-1",
		Rules:    rules,
	}})
	if err != nil {
		t.Fatalf("compile snapshot: %v", err)
	}
	cache, err := policy.NewRouteCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("new route cache: %v", err)
	}
	cache.SetPolicyGeneration(snap.Generation())
	scope, err := cache.Open(policy.Scope{SessionID: "parity-session", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("open scope: %v", err)
	}

	fwd, _, wan, _ := setupForwarderWithPBR(t)
	matcher := policy.NewMatcher()
	matcher.Publish(snap)
	fwd.SetPolicyMatcher(matcher)
	fwd.SetRouteCache(explainParityCache{scope: scope, gen: snap.Generation()})

	return &explainParityFixture{snap: snap, cache: cache, scope: scope, fwd: fwd, wan: wan, gen: snap.Generation()}
}

// observe seeds one decision for the parity session.
func (f *explainParityFixture) observe(t *testing.T, addr netip.Addr, decision policy.Decision, ttl time.Duration) {
	t.Helper()
	now := time.Now()
	if err := f.scope.Observe(f.gen, []policy.Observation{{
		IP: addr, Decision: decision, ExpiresAt: now.Add(ttl),
	}}, now); err != nil {
		t.Fatalf("seed evidence for %s: %v", addr, err)
	}
}

// explain runs the real explanation for a name plus one destination address.
func (f *explainParityFixture) explain(names []string, addr netip.Addr) policy.DestinationExplanation {
	return policy.ExplainDestination(policy.ExplainDestinationInput{
		Enabled:  true,
		Snapshot: f.snap,
		Names:    names,
		Addresses: []netip.Addr{
			addr,
		},
		Resolved: true,
		EvidenceFor: func(a netip.Addr) *policy.Evidence {
			evidence := f.scope.Inspect(a, f.gen, time.Now())
			return &evidence
		},
		Prohibited: IsProhibitedIPv4Destination,
	})
}

// dispatch sends one brand-new UDP flow to addr through the real forwarder.
func (f *explainParityFixture) dispatch(t *testing.T, addr netip.Addr, srcPort uint16) error {
	t.Helper()
	cap := newTestCaptureReturnPath()
	f.fwd.RegisterSessionWithReturnPath("parity-session", "parity-connection", "parity-peer",
		"10.100.0.30", 205, cap.path)
	pkt := buildTestIPv4UDPPacket(netip.MustParseAddr("10.100.0.30"), addr, srcPort, 443, []byte("fixture"))
	return f.fwd.RouteClientToBackend("parity-peer", pkt)
}

// assertNoSideEffects proves the explanation moved nothing observable: no
// dispatcher counter, no WAN packet, no cache entry, no session and no change to
// the stored evidence.
func (f *explainParityFixture) assertNoSideEffects(t *testing.T, addr netip.Addr, entriesBefore, sessionsBefore int, evidenceBefore policy.Evidence) {
	t.Helper()
	if got, got2, got3 := f.fwd.DirectBytes(), f.fwd.ProxiedBytes(), f.fwd.DirectDrops(); got != 0 || got2 != 0 || got3 != 0 {
		t.Fatalf("explanation moved dispatcher counters: direct=%d proxy=%d drops=%d", got, got2, got3)
	}
	if packets := len(f.wan.getPackets()); packets != 0 {
		t.Fatalf("explanation emitted %d WAN packets", packets)
	}
	if after := f.scope.Inspect(addr, f.gen, time.Now()); after != evidenceBefore {
		t.Fatalf("explanation changed stored evidence: %+v → %+v", evidenceBefore, after)
	}
	if got := f.cache.EntryCount(); got != entriesBefore {
		t.Fatalf("explanation changed the route-cache entry count: %d → %d", entriesBefore, got)
	}
	if got := f.cache.SessionCount(); got != sessionsBefore {
		t.Fatalf("explanation changed the route-cache session count: %d → %d", sessionsBefore, got)
	}
}

// assertParity checks the explained action against what the dispatcher did.
// passing is the dispatch error; the counters are the actual terminal effect.
func (f *explainParityFixture) assertParity(t *testing.T, explained policy.DestinationExplanation, dispatchErr error) {
	t.Helper()
	directBytes, proxyBytes, drops := f.fwd.DirectBytes(), f.fwd.ProxiedBytes(), f.fwd.DirectDrops()
	wanPackets := len(f.wan.getPackets())
	t.Logf("explain=%s/%s actual: direct bytes=%d proxy bytes=%d WAN packets=%d direct drops=%d err=%v",
		explained.Decision, explained.Reason, directBytes, proxyBytes, wanPackets, drops, dispatchErr)

	switch explained.Decision {
	case policy.ActionDirect:
		if dispatchErr != nil || directBytes == 0 || proxyBytes != 0 || wanPackets != 1 {
			t.Fatalf("explained DIRECT but the dispatcher did not egress directly: err=%v direct=%d proxy=%d wan=%d",
				dispatchErr, directBytes, proxyBytes, wanPackets)
		}
	case policy.ActionProxy:
		if dispatchErr != nil || proxyBytes == 0 || directBytes != 0 {
			t.Fatalf("explained PROXY but the dispatcher did not queue to the backend: err=%v direct=%d proxy=%d",
				dispatchErr, directBytes, proxyBytes)
		}
	case policy.ActionDrop:
		if dispatchErr != ErrProhibitedDestination || drops == 0 || directBytes != 0 || proxyBytes != 0 {
			t.Fatalf("explained DROP but the dispatcher did not drop: err=%v drops=%d direct=%d proxy=%d",
				dispatchErr, drops, directBytes, proxyBytes)
		}
	default:
		t.Fatalf("explanation gave no definitive action: %s/%s", explained.Decision, explained.Reason)
	}
}

// TestExplainActionMatchesForwarderDispatch is the review's counterexample plus
// its three controls, asserted against the real packet path.
func TestExplainActionMatchesForwarderDispatch(t *testing.T) {
	listedName := []string{"blocked.example"}
	unlistedName := []string{"unlisted.example"}

	cases := []struct {
		name        string
		names       []string
		destination string
		seed        func(t *testing.T, f *explainParityFixture, addr netip.Addr)
		wantAction  policy.Action
		wantReason  policy.Cause
	}{
		{
			name:        "listed name over fresh DIRECT evidence is still DIRECT",
			names:       listedName,
			destination: "198.51.201.50",
			seed: func(t *testing.T, f *explainParityFixture, addr netip.Addr) {
				f.observe(t, addr, policy.Direct, time.Minute)
			},
			wantAction: policy.ActionDirect,
			wantReason: policy.CauseFreshEvidenceDirect,
		},
		{
			name:        "CIDR destination is PROXY",
			names:       unlistedName,
			destination: "198.51.200.9",
			wantAction:  policy.ActionProxy,
			wantReason:  policy.CauseCIDRRule,
		},
		{
			name:        "cached PROXY decision is PROXY",
			names:       unlistedName,
			destination: "198.51.201.60",
			seed: func(t *testing.T, f *explainParityFixture, addr netip.Addr) {
				f.observe(t, addr, policy.Proxy, time.Minute)
			},
			wantAction: policy.ActionProxy,
			wantReason: policy.CauseCachedProxyEvidence,
		},
		{
			name:        "fresh DIRECT destination with no matching rule",
			names:       unlistedName,
			destination: "198.51.201.70",
			seed: func(t *testing.T, f *explainParityFixture, addr netip.Addr) {
				f.observe(t, addr, policy.Direct, time.Minute)
			},
			wantAction: policy.ActionDirect,
			wantReason: policy.CauseFreshEvidenceDirect,
		},
		{
			name:        "prohibited destination is DROP",
			names:       unlistedName,
			destination: "192.0.2.10",
			wantAction:  policy.ActionDrop,
			wantReason:  policy.CauseProhibitedDestination,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newExplainParityFixture(t)
			addr := netip.MustParseAddr(tc.destination)
			if tc.seed != nil {
				tc.seed(t, f, addr)
			}

			entriesBefore := f.cache.EntryCount()
			sessionsBefore := f.cache.SessionCount()
			evidenceBefore := f.scope.Inspect(addr, f.gen, time.Now())
			explained := f.explain(tc.names, addr)
			f.assertNoSideEffects(t, addr, entriesBefore, sessionsBefore, evidenceBefore)

			if explained.Decision != tc.wantAction || explained.Reason != tc.wantReason {
				t.Fatalf("explain = %s/%s, want %s/%s", explained.Decision, explained.Reason, tc.wantAction, tc.wantReason)
			}

			dispatchErr := f.dispatch(t, addr, uint16(20000+i))
			f.assertParity(t, explained, dispatchErr)
		})
	}
}

// TestExplainProspectiveRuleNeverDecidesADirectDestination states the separation
// explicitly on the case that produced the finding: the same answer carries a
// matched prospective rule AND a DIRECT current action, and the dispatcher agrees
// with the action, not with the classification.
func TestExplainProspectiveRuleNeverDecidesADirectDestination(t *testing.T) {
	f := newExplainParityFixture(t)
	addr := netip.MustParseAddr("198.51.201.80")
	f.observe(t, addr, policy.Direct, time.Minute)

	explained := f.explain([]string{"blocked.example"}, addr)
	if explained.Prospective == nil || explained.Prospective.Rule == nil {
		t.Fatal("the listed name must still be reported as a prospective match")
	}
	if explained.Prospective.Rule.Base != "blocked.example" {
		t.Fatalf("prospective base = %q, want blocked.example", explained.Prospective.Rule.Base)
	}
	if explained.Decision != policy.ActionDirect {
		t.Fatalf("action = %s/%s, want DIRECT", explained.Decision, explained.Reason)
	}

	f.assertParity(t, explained, f.dispatch(t, addr, 21000))
}
