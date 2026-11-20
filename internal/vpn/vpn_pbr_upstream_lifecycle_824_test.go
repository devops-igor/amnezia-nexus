package vpn

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Regressions for the upstream-list lifecycle: the list the operator accepts
// must reach the resolver that dials it, and must survive a live change instead
// of reverting to the values an earlier activation captured.

// sameUpstreams reports whether two upstream lists dial the same endpoints.
func sameUpstreams(a, b []policy.Upstream) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAcceptedLiveChangeReachesTheLiveResolver is F824-01: an accepted live
// change to list B must reach the resolver that is actually answering, instead
// of the list the activation started with.
func TestAcceptedLiveChangeReachesTheLiveResolver(t *testing.T) {
	gate := newPolicyGate()
	server := newGatedPolicyServer(gate, map[string][]string{"/policy.lst": domainList("upstream", 20)})
	defer server.Close()
	previousFetcher := policyFetcherForTest
	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = previousFetcher })
	withNameOwnedWANDevice(t, newNameRegistry())

	svc := serviceForActivation(t)
	t.Cleanup(svc.StopPolicyRouting)

	listA := []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	listB := []policy.Upstream{{Address: "149.112.112.112", Port: 53}}
	settingsA := policySettingsForURL(t, "https://lists.example/policy.lst")
	settingsA.UpstreamDNS = listA
	store := policy.NewFileStore(t.TempDir())
	if err := svc.StartPolicyRouting(context.Background(), settingsA, store, string(settingsA.Preset)); err != nil {
		t.Fatalf("activate with list A: %v", err)
	}
	if got := svc.EffectiveDNSUpstreams(); !sameUpstreams(got, listA) {
		t.Fatalf("activation did not record list A: got %v want %v", got, listA)
	}

	settingsB := settingsA.Normalize()
	settingsB.UpstreamDNS = listB
	if err := svc.StartPolicyRouting(context.Background(), settingsB, store, string(settingsB.Preset)); err != nil {
		t.Fatalf("accept live change to list B: %v", err)
	}
	if got := svc.EffectiveDNSUpstreams(); !sameUpstreams(got, listB) {
		t.Fatalf("accepted live change kept the activation list: got %v want %v", got, listB)
	}
	// The one resolver consumer in this build must dial what was accepted.
	pbrCfg := svc.getPBRConfig()
	if pbrCfg == nil || pbrCfg.DNSResolver == nil {
		t.Fatal("still-active policy routing has no resolver to check")
	}
	if got := pbrCfg.DNSResolver.Upstreams(); !sameUpstreams(got, listB) {
		t.Fatalf("live resolver dials %v, want the accepted list %v", got, listB)
	}
}

// TestApplyEffectiveUpstreamsRecordsAcceptedListWhenDisabled keeps the disabled
// path inert and honest: the accepted list is recorded for the next activation,
// and no resolver is installed for it.
func TestApplyEffectiveUpstreamsRecordsAcceptedListWhenDisabled(t *testing.T) {
	svc := serviceForActivation(t)

	custom := []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := svc.ApplyEffectiveUpstreams(custom); err != nil {
		t.Fatalf("ApplyEffectiveUpstreams: %v", err)
	}
	if got := svc.EffectiveDNSUpstreams(); !sameUpstreams(got, custom) {
		t.Fatalf("accepted list not recorded on the service: got %v want %v", got, custom)
	}
	if svc.PBREnabled() {
		t.Fatal("the test fixture unexpectedly enabled policy routing")
	}
	if cfg := svc.getPBRConfig(); cfg != nil && cfg.DNSResolver != nil {
		t.Fatalf("a disabled service installed a resolver for %v", cfg.DNSResolver.Upstreams())
	}
}
