package forwarder

import (
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// This is the acceptance oracle for the surviving operator control: the settings
// page offers exactly one address input, an IPv4 PROXY exception list, and the
// owner's principle is that a visible control must actually work.
//
// So the assertions below drive the real packet path — RouteClientToBackend →
// routeClientPBR → decideEgress — with a snapshot compiled from a record's own
// exception list, and check which way each destination leaves:
//
//   - a LISTED prefix is forced to PROXY, ahead of the classifier, for a
//     destination the classifier would otherwise route DIRECT;
//   - an UNLISTED destination inside the Russian allocation is decided by the
//     classifier and goes DIRECT;
//   - an UNLISTED destination outside the allocation goes PROXY by the
//     classifier's fail-safe branch (row 5);
//   - a LISTED prefix that names a prohibited destination is still dropped, so
//     the control can never be used to bypass the contract's first row.
//
// The exception snapshot is built exactly as production builds it, from
// policy.Settings, so the fixture cannot drift from what a saved record yields.

// exceptionSnapshot compiles the snapshot a saved record produces, so the list
// under test is the production derivation rather than a hand-written fixture.
func exceptionSnapshot(t *testing.T, exceptions ...string) *policy.Matcher {
	t.Helper()
	settings := policy.DefaultSettings()
	settings.ProxyExceptions = exceptions
	cfg, err := settings.SyncConfig()
	if err != nil {
		t.Fatalf("SyncConfig for the fixture record: %v", err)
	}
	if len(cfg.LocalRules.CIDRs) == 0 {
		t.Fatal("the fixture record produced no prefixes; the scenario would be vacuous")
	}
	matcher := policy.NewMatcher()
	snap, err := policy.CompileSnapshot(1, "gen-exceptions", []policy.SourceParsedRules{
		{SourceID: "local", Rules: cfg.LocalRules},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher.Publish(snap)
	return matcher
}

// TestProxyExceptionListOverridesTheClassifier is the positive half: a listed
// prefix is forced to PROXY even though the classifier would send it DIRECT.
//
// 213.180.204.186 is music.yandex.ru — inside the Russian allocation with no CDN
// exclusion, so the classifier's own answer is DIRECT. Listing it in the exception
// list must move it to PROXY, which is the whole purpose of the control.
func TestProxyExceptionListOverridesTheClassifier(t *testing.T) {
	fwd, dem, wanDev := setupForwarderWithPBR(t)
	classifier := installedClassifier(t)
	fwd.SetDestinationClassifier(classifier)

	target := netip.MustParseAddr("213.180.204.186")

	// Control first: with no exception list the classifier routes this DIRECT, so a
	// later PROXY decision can only come from the list.
	if got := classifier.Classify(target); !got.AllocationRoutesDirect() {
		t.Fatalf("fixture is invalid: the classifier does not route %s direct: %+v", target, got)
	}

	fwd.SetPolicyMatcher(exceptionSnapshot(t, "213.180.192.0/19"))

	const (
		peerKey   = "peer-exception-listed"
		sessionID = "s-exception-listed"
		clientIP  = "10.100.0.97"
		backendID = int64(311)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-exception-listed", peerKey, clientIP, backendID, capPath.path)

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 42001, 443, 0x02, nil)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("a listed exception prefix was routed DIRECT (%d direct packets); the control does not work", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 1 {
		t.Fatalf("packets queued to the proxy backend = %d, want 1", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceProxy || flow.DecisionReason != EgressReasonProxyCIDRRule {
		t.Fatalf("flow = %v/%q, want PROXY/%q from the operator exception list",
			flow.Choice, flow.DecisionReason, EgressReasonProxyCIDRRule)
	}
}

// TestUnlistedDestinationIsDecidedByTheClassifier is the negative half: with the
// same installed exception list, a destination the list does not name is decided by
// the classifier, and its DIRECT verdict stands.
func TestUnlistedDestinationIsDecidedByTheClassifier(t *testing.T) {
	fwd, dem, wanDev := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	// A list that exists but does not cover the destination under test.
	fwd.SetPolicyMatcher(exceptionSnapshot(t, "203.0.113.0/24"))

	const (
		peerKey   = "peer-exception-unlisted"
		sessionID = "s-exception-unlisted"
		clientIP  = "10.100.0.98"
		backendID = int64(312)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-exception-unlisted", peerKey, clientIP, backendID, capPath.path)

	target := netip.MustParseAddr("213.180.204.186")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 42002, 443, 0x02, nil)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 1 {
		t.Fatalf("an unlisted allocation destination wrote %d direct packets, want 1: the classifier did not decide it", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 0 {
		t.Fatalf("an unlisted allocation destination queued %d proxy packets, want 0", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceDirect || flow.DecisionReason != EgressReasonAllocationDirect {
		t.Fatalf("flow = %v/%q, want DIRECT/%q from the classifier",
			flow.Choice, flow.DecisionReason, EgressReasonAllocationDirect)
	}
}

// TestUnlistedUncoveredDestinationProxies keeps the fail-safe branch honest: a
// destination the list does not name and the classifier does not cover still goes
// PROXY, so the exception list changes only what it names.
func TestUnlistedUncoveredDestinationProxies(t *testing.T) {
	fwd, dem, wanDev := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))
	fwd.SetPolicyMatcher(exceptionSnapshot(t, "203.0.113.0/24"))

	const (
		peerKey   = "peer-exception-uncovered"
		sessionID = "s-exception-uncovered"
		clientIP  = "10.100.0.99"
		backendID = int64(313)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-exception-uncovered", peerKey, clientIP, backendID, capPath.path)

	// 45.33.32.156 is outside the Russian allocation and covered by no CDN entry.
	target := netip.MustParseAddr("45.33.32.156")
	if got := installedClassifier(t).Classify(target); got.InAllocation {
		t.Fatalf("fixture is invalid: %s is inside the allocation: %+v", target, got)
	}
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 42003, 443, 0x02, nil)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("an uncovered destination wrote %d direct packets, want 0", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceProxy || flow.DecisionReason != EgressReasonNoTrustedEvidence {
		t.Fatalf("flow = %v/%q, want PROXY/%q",
			flow.Choice, flow.DecisionReason, EgressReasonNoTrustedEvidence)
	}
}

// TestProhibitedDestinationStillDropsDespiteAListedException is the constraint that
// must survive this change: the prohibition is address-side and independent of the
// policy snapshot, so an exception naming a prohibited range cannot route it.
//
// This proves precedence rather than absence: the exception list really does claim
// the address.
func TestProhibitedDestinationStillDropsDespiteAListedException(t *testing.T) {
	matcher := exceptionSnapshot(t, "10.0.0.0/8", "169.254.0.0/16")
	if !matcher.Current().MatchIPv4(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("fixture is invalid: the exception list does not claim 10.1.2.3")
	}

	fwd, _, wanDev := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))
	fwd.SetPolicyMatcher(matcher)

	const (
		peerKey   = "peer-exception-prohibited"
		sessionID = "s-exception-prohibited"
		clientIP  = "10.100.0.96"
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-exception-prohibited", peerKey, clientIP, 314, capPath.path)

	for _, raw := range []string{"10.1.2.3", "169.254.169.254"} {
		target := netip.MustParseAddr(raw)
		pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 42004, 443, 0x02, nil)
		if err := fwd.RouteClientToBackend(peerKey, pkt); err == nil {
			t.Fatalf("%s was not refused although it is a prohibited destination", raw)
		}
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("prohibited destinations wrote %d direct packets, want 0", got)
	}
	if got := fwd.DirectDrops(); got == 0 {
		t.Fatal("prohibited destinations were refused without being accounted as drops")
	}
}

// TestClassifierDecisionIsUnchangedByThisSlice pins the shapes that must not change,
// captured from the real classifier rather than restated: allocation membership, CDN
// exclusion keeping an allocation member proxied, and non-membership reported as
// unclassified.
func TestClassifierDecisionIsUnchangedByThisSlice(t *testing.T) {
	classifier := installedClassifier(t)

	// Inside the allocation, no CDN exclusion: DIRECT.
	if got := classifier.Classify(netip.MustParseAddr("213.180.204.186")); !got.AllocationRoutesDirect() {
		t.Errorf("an allocation member with no CDN exclusion classified as %+v, want direct", got)
	}

	// Inside the allocation but on a multi-region CDN network: PROXY.
	cdnAddr := netip.MustParseAddr(cdnExclusionSampleAddr(t))
	got := classifier.Classify(cdnAddr)
	if !got.InAllocation || got.CDNProvider == "" || got.AllocationRoutesDirect() {
		t.Errorf("a CDN-excluded allocation member classified as %+v, want allocation+CDN and not direct", got)
	}

	// Outside the allocation and covered by no exclusion: unclassified, which the
	// contract's row 5 proxies.
	if got := classifier.Classify(netip.MustParseAddr("45.33.32.156")); got.InAllocation || got.CDNProvider != "" {
		t.Errorf("an out-of-allocation destination classified as %+v, want the zero classification", got)
	}
}

// cdnExclusionSampleAddr returns one address inside a committed CDN network that
// also falls inside the allocation. The CDN exclusion table is read first, so a
// fixture failure means the shipped set changed rather than that this literal was
// invented: 193.176.179.0/24 is allocated and covered by AS16509 (Amazon), which
// the exclusion table lists.
func cdnExclusionSampleAddr(t *testing.T) string {
	t.Helper()
	entries, err := geodb.CDNExclusions()
	if err != nil {
		t.Fatalf("read the CDN exclusion set: %v", err)
	}
	const amazonASN = 16509
	found := false
	for _, entry := range entries {
		if entry.ASN == amazonASN {
			found = true
		}
	}
	if !found {
		t.Fatalf("the CDN exclusion set no longer covers AS%d, so the CDN fixture is stale: %+v", amazonASN, entries)
	}
	return "193.176.179.1"
}
