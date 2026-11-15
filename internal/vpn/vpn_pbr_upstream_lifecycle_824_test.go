package vpn

import (
	"context"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Regressions for the two continuity lifecycle defects found in review round 1
// of issue 824. They exercise the real activation, syncer, resolver, teardown and
// continuity components; only the WAN device constructor and the list download
// are substitutes.

// TestUpstreamListSurvivesAcceptedLiveChangeThroughDisable is F824-01: an
// accepted live change to list B must reach the responder that keeps issued
// gateway-DNS profiles answering after policy routing is disabled, instead of the
// list the activation started with.
func TestUpstreamListSurvivesAcceptedLiveChangeThroughDisable(t *testing.T) {
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
	t.Cleanup(svc.closeDNSContinuity)
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

	svc.StopPolicyRouting()
	if svc.dnsContinuity == nil {
		t.Fatal("no continuity responder after disable")
	}
	if got := svc.dnsContinuity.upstreams; !sameUpstreams(got, listB) {
		t.Fatalf("continuity responder rebuilt from the activation list after an accepted live change: got %v want %v", got, listB)
	}
}

// TestStartupContinuityInstallKeepsAcceptedUpstreams is the second half of
// F824-01: the install that runs at startup must not replace an already accepted
// list with the built-in defaults.
func TestStartupContinuityInstallKeepsAcceptedUpstreams(t *testing.T) {
	svc := serviceForActivation(t)
	t.Cleanup(svc.closeDNSContinuity)

	chosen := []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	svc.installDNSContinuityLocked(netip.MustParseAddr("10.100.0.1"), chosen)
	if svc.dnsContinuity == nil || !sameUpstreams(svc.dnsContinuity.upstreams, chosen) {
		t.Fatalf("fixture did not install the chosen list: %+v", svc.dnsContinuity)
	}

	svc.installDNSContinuity()
	if got := svc.dnsContinuity.upstreams; !sameUpstreams(got, chosen) {
		t.Fatalf("startup install replaced the accepted upstream list with the defaults: got %v want %v", got, chosen)
	}
}

// TestApplyEffectiveUpstreamsReachesDisabledContinuity is the mechanism the
// disabled-startup and accepted-disable paths use: with policy routing off, an
// accepted list is published to the responder that is actually answering.
func TestApplyEffectiveUpstreamsReachesDisabledContinuity(t *testing.T) {
	svc := serviceForActivation(t)
	t.Cleanup(svc.closeDNSContinuity)

	svc.installDNSContinuity()
	if got := svc.dnsContinuity.upstreams; !sameUpstreams(got, policy.DefaultUpstreams()) {
		t.Fatalf("fixture expected the default pair before any list is applied: got %v", got)
	}

	custom := []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := svc.ApplyEffectiveUpstreams(custom); err != nil {
		t.Fatalf("ApplyEffectiveUpstreams: %v", err)
	}
	if got := svc.dnsContinuity.upstreams; !sameUpstreams(got, custom) {
		t.Fatalf("a disabled data path kept the default pair after an accepted list: got %v want %v", got, custom)
	}
	if got := svc.EffectiveDNSUpstreams(); !sameUpstreams(got, custom) {
		t.Fatalf("accepted list not recorded on the service: got %v want %v", got, custom)
	}
}

// TestEnabledStartupKeepsPolicyDNSHandler is HIGH-01: after a persisted-policy
// activation, the service-start continuity install must not take the DNS path
// away from the active policy handler, or routing evidence stops while the status
// still reports policy routing enabled.
func TestEnabledStartupKeepsPolicyDNSHandler(t *testing.T) {
	gate := newPolicyGate()
	server := newGatedPolicyServer(gate, map[string][]string{"/policy.lst": domainList("startup", 20)})
	defer server.Close()
	previousFetcher := policyFetcherForTest
	policyFetcherForTest = func(limits policy.FetchLimits) *policy.Fetcher {
		return fixtureFetcherFor(t, server, policy.SyncConfig{FetchLimits: limits})
	}
	t.Cleanup(func() { policyFetcherForTest = previousFetcher })
	withNameOwnedWANDevice(t, newNameRegistry())

	svc := serviceForActivation(t)
	t.Cleanup(svc.closeDNSContinuity)
	t.Cleanup(svc.StopPolicyRouting)

	settings := policySettingsForURL(t, "https://lists.example/policy.lst")
	settings.UpstreamDNS = []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	store := policy.NewFileStore(t.TempDir())
	if err := svc.StartPolicyRouting(context.Background(), settings, store, string(settings.Preset)); err != nil {
		t.Fatalf("activate from persisted settings: %v", err)
	}
	if !svc.PBREnabled() {
		t.Fatal("fixture did not enable policy routing")
	}
	before, ok := svc.forwarder.DNSHandler().(*pbrDNSHandler)
	if !ok {
		t.Fatalf("activation installed %T, want the policy DNS handler", svc.forwarder.DNSHandler())
	}

	// This is the call Service.Start makes for configurations issued while policy
	// routing was active.
	svc.installDNSContinuity()

	after, ok := svc.forwarder.DNSHandler().(*pbrDNSHandler)
	if !ok {
		t.Fatalf("startup install replaced the policy DNS handler with %T: routing evidence would stop", svc.forwarder.DNSHandler())
	}
	if after != before {
		t.Fatal("startup install rebuilt the policy DNS handler instead of leaving the active one in place")
	}
	pbrCfg := svc.getPBRConfig()
	if pbrCfg == nil || after.gw != pbrCfg.DNSGateway {
		t.Fatalf("installed handler is bound to %p, want the policy gateway %p", after.gw, pbrCfg.DNSGateway)
	}
	if after.rc == nil {
		t.Fatal("installed handler has no route cache, so it cannot produce routing evidence")
	}
}

// TestDisabledStartupInstallsContinuityHandlerWithSavedList is the disabled half
// of HIGH-01: with policy routing off, the startup install must still install the
// continuity responder, and it must dial the saved list.
func TestDisabledStartupInstallsContinuityHandlerWithSavedList(t *testing.T) {
	svc := serviceForActivation(t)
	t.Cleanup(svc.closeDNSContinuity)

	custom := []policy.Upstream{{Address: "9.9.9.9", Port: 53}}
	if err := svc.ApplyEffectiveUpstreams(custom); err != nil {
		t.Fatalf("apply the saved list: %v", err)
	}
	svc.installDNSContinuity()

	if _, ok := svc.forwarder.DNSHandler().(*dnsContinuityHandler); !ok {
		t.Fatalf("disabled startup installed %T, want the continuity responder", svc.forwarder.DNSHandler())
	}
	if svc.dnsContinuity == nil || !sameUpstreams(svc.dnsContinuity.upstreams, custom) {
		t.Fatalf("continuity responder dials %v, want the saved list %v", svc.dnsContinuity, custom)
	}
}
