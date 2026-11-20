package forwarder

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/geodb"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Packet-path tests for issue #918: routing by destination address.
//
// They drive the real pump entry point (RouteClientToBackend → routeClientPBR),
// not the decision function alone, because the properties that matter are about
// what the packet path does with the decision: where the packet leaves, what the
// flow records, and what the DROP ledger says when it cannot leave at all.

// installedClassifier is the classifier the VPN service installs in production:
// the committed inventory joined to the embedded ASN table.
func installedClassifier(t *testing.T) DestinationClassifier {
	t.Helper()
	inventory, err := policy.ShippedInventory()
	if err != nil {
		t.Fatalf("committed inventory is unusable: %v", err)
	}
	geo, err := geodb.DefaultGeoDB()
	if err != nil {
		t.Fatalf("embedded ASN table is unusable: %v", err)
	}
	classifier, err := policy.NewAddressClassifier(inventory, geo)
	if err != nil {
		t.Fatalf("build classifier: %v", err)
	}
	return classifier
}

// overrideClassifier is the production classifier with an operator DIRECT input
// layered on top, exactly as an operator override would arrive.
func overrideClassifier(t *testing.T, body string) *policy.AddressClassifier {
	t.Helper()
	inventory, err := policy.ShippedInventory()
	if err != nil {
		t.Fatalf("committed inventory is unusable: %v", err)
	}
	override, err := policy.ParseInventoryOverride([]byte(body))
	if err != nil {
		t.Fatalf("parse operator override: %v", err)
	}
	geo, err := geodb.DefaultGeoDB()
	if err != nil {
		t.Fatalf("embedded ASN table is unusable: %v", err)
	}
	classifier, err := policy.NewAddressClassifier(inventory.WithOverride(override), geo)
	if err != nil {
		t.Fatalf("build classifier: %v", err)
	}
	return classifier
}

// routeGeneration reads the generation the registered route currently owns, which
// the per-session reads below need exactly.
func routeGeneration(t *testing.T, fwd *Forwarder, peerKey string) uint64 {
	t.Helper()
	fwd.mu.RLock()
	defer fwd.mu.RUnlock()
	route, ok := fwd.routesByPeer[peerKey]
	if !ok {
		t.Fatalf("no route registered for %q", peerKey)
	}
	return route.generation
}

// recordedFlow returns the flow record the packet path installed for dstIP.
func recordedFlow(t *testing.T, dem *DirectEgressManager, sessionID string, dstIP netip.Addr) SessionFlow {
	t.Helper()
	list := dem.SnapshotSessionFlows(sessionID, 0, time.Now(), 8)
	for _, flow := range list.Flows {
		if flow.DstIP == dstIP {
			return flow
		}
	}
	t.Fatalf("no flow record for %s in session %q (%d records)", dstIP, sessionID, len(list.Flows))
	return SessionFlow{}
}

// TestAllocationClassifiedFlowRoutesDirectWithNoDNSEvidence is the headline
// acceptance case: a client that resolves through DoH or DoT leaves no DNS
// evidence at all, and the destination address alone must route it direct.
func TestAllocationClassifiedFlowRoutesDirectWithNoDNSEvidence(t *testing.T) {
	fwd, dem, wanDev, _ := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	const (
		peerKey   = "peer-alloc-direct"
		sessionID = "s-alloc-direct"
		clientIP  = "10.100.0.90"
		backendID = int64(301)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-alloc-direct", peerKey, clientIP, backendID, capPath.path)

	// 213.180.204.186 is music.yandex.ru: inside 213.180.192.0/19, and the
	// embedded table reports a Serbian country and AS208398 for it.
	target := netip.MustParseAddr("213.180.204.186")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41001, 443, 0x02, nil)

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 1 {
		t.Fatalf("packets written to the direct WAN device = %d, want 1", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 0 {
		t.Fatalf("packets queued to the proxy backend = %d, want 0", got)
	}
	if fwd.DirectBytes() != int64(len(pkt)) {
		t.Errorf("directBytes = %d, want %d", fwd.DirectBytes(), len(pkt))
	}
	if fwd.ProxiedBytes() != 0 {
		t.Errorf("proxiedBytes = %d, want 0", fwd.ProxiedBytes())
	}

	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceDirect {
		t.Fatalf("flow choice = %v, want DIRECT", flow.Choice)
	}
	if flow.DecisionReason != EgressReasonAllocationDirect {
		t.Errorf("decision reason = %q, want %q", flow.DecisionReason, EgressReasonAllocationDirect)
	}
	if flow.BackendTunnelID != 0 {
		t.Errorf("a DIRECT flow recorded backend %d, want none", flow.BackendTunnelID)
	}
}

// TestGenuineSerbianDestinationStaysProxied is the other half of the ambiguity:
// an address that the embedded table also reports as `RS` but which is outside
// the Russian allocation must not be routed direct.
func TestGenuineSerbianDestinationStaysProxied(t *testing.T) {
	fwd, dem, wanDev, _ := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	const (
		peerKey   = "peer-serbian"
		sessionID = "s-serbian"
		clientIP  = "10.100.0.91"
		backendID = int64(302)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-serbian", peerKey, clientIP, backendID, capPath.path)

	target := netip.MustParseAddr("147.91.1.1") // AS13092, Serbia
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41002, 443, 0x02, nil)

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("packets written direct = %d, want 0", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 1 {
		t.Fatalf("packets queued to the proxy backend = %d, want 1", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceProxy || flow.DecisionReason != EgressReasonNoTrustedEvidence {
		t.Errorf("flow = %v/%q, want PROXY/%q", flow.Choice, flow.DecisionReason, EgressReasonNoTrustedEvidence)
	}
}

// TestCDNRangeInsideAllocationStaysProxied is the CDN exclusion control on real
// data: 193.176.179.0/24 is inside the committed Russian allocation and is
// covered by AS16509 (Amazon), so it must stay proxied.
func TestCDNRangeInsideAllocationStaysProxied(t *testing.T) {
	fwd, dem, wanDev, _ := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	const (
		peerKey   = "peer-cdn"
		sessionID = "s-cdn"
		clientIP  = "10.100.0.92"
		backendID = int64(303)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-cdn", peerKey, clientIP, backendID, capPath.path)

	target := netip.MustParseAddr("193.176.179.1")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41003, 443, 0x02, nil)

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("a multi-region CDN address was written direct (%d packets)", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 1 {
		t.Fatalf("packets queued to the proxy backend = %d, want 1", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceProxy || flow.DecisionReason != EgressReasonAllocationCDNExcluded {
		t.Errorf("flow = %v/%q, want PROXY/%q", flow.Choice, flow.DecisionReason, EgressReasonAllocationCDNExcluded)
	}
}

// TestExplicitProxyRuleWinsOverAllocationMatch is the operator override going
// the other way: a published address rule keeps an allocation member on the
// proxy.
func TestExplicitProxyRuleWinsOverAllocationMatch(t *testing.T) {
	fwd, dem, wanDev, _ := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	snapshot, err := policy.CompileSnapshot(1, "gen-override", []policy.SourceParsedRules{{
		SourceID: "operator-cidr",
		Rules:    policy.ParsedRules{CIDRs: []netip.Prefix{netip.MustParsePrefix("213.180.192.0/19")}},
	}})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	matcher := policy.NewMatcher()
	matcher.Publish(snapshot)
	fwd.SetPolicyMatcher(matcher)

	const (
		peerKey   = "peer-override"
		sessionID = "s-override"
		clientIP  = "10.100.0.93"
		backendID = int64(304)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-override", peerKey, clientIP, backendID, capPath.path)

	target := netip.MustParseAddr("213.180.204.186")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41004, 443, 0x02, nil)

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("an operator PROXY rule was overridden by the classifier (%d direct packets)", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.DecisionReason != EgressReasonProxyCIDRRule {
		t.Errorf("decision reason = %q, want %q", flow.DecisionReason, EgressReasonProxyCIDRRule)
	}
}

// TestOperatorDirectInputCannotBypassProhibitedGuard is the constraint from the
// issue: the prohibited check needs an address-side form, and an operator DIRECT
// input must never route a prohibited or internal destination.
func TestOperatorDirectInputCannotBypassProhibitedGuard(t *testing.T) {
	classifier := overrideClassifier(t, "10.0.0.0/8\n169.254.0.0/16\n")
	// The operator's input really does claim these addresses, so the guard below
	// is proving precedence rather than the absence of a match.
	for _, raw := range []string{"10.1.2.3", "169.254.169.254"} {
		got := classifier.Classify(netip.MustParseAddr(raw))
		if !got.InAllocation || got.Source != policy.InventorySourceOverride {
			t.Fatalf("operator override did not claim %s: %+v", raw, got)
		}
	}

	fwd, _, wanDev, _ := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(classifier)

	const (
		peerKey   = "peer-bypass"
		sessionID = "s-bypass"
		clientIP  = "10.100.0.94"
		backendID = int64(305)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-bypass", peerKey, clientIP, backendID, capPath.path)
	generation := routeGeneration(t, fwd, peerKey)

	target := netip.MustParseAddr("10.1.2.3")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41005, 443, 0x02, nil)

	err := fwd.RouteClientToBackend(peerKey, pkt)
	if !errors.Is(err, ErrProhibitedDestination) {
		t.Fatalf("RouteClientToBackend = %v, want ErrProhibitedDestination", err)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("a prohibited destination reached the WAN device (%d packets)", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 0 {
		t.Fatalf("a prohibited destination was queued for the proxy (%d packets)", got)
	}

	drops := fwd.ClientDropSnapshot(sessionID, generation, 8)
	found := false
	for _, entry := range drops.Entries {
		if entry.Key.Reason == DropReasonProhibitedDestination {
			found = true
		}
		if entry.Key.HasTuple && entry.Key.DstIP == [4]byte{10, 1, 2, 3} && entry.Key.Reason != DropReasonProhibitedDestination {
			t.Errorf("prohibited destination recorded with reason %q", entry.Key.Reason)
		}
	}
	if !found {
		t.Fatalf("no %q record for the refused destination: %+v", DropReasonProhibitedDestination, drops.Entries)
	}
}

// TestWithoutClassifierAllocationDestinationsStayProxied is the fail-closed
// control: with no classifier configured, decisions are exactly today's, so an
// allocation member still takes the proxy path and says why.
func TestWithoutClassifierAllocationDestinationsStayProxied(t *testing.T) {
	fwd, dem, wanDev, _ := setupForwarderWithPBR(t)
	if got := fwd.DestinationClassifier(); got != nil {
		t.Fatalf("a classifier is installed without being configured: %T", got)
	}

	const (
		peerKey   = "peer-noclassifier"
		sessionID = "s-noclassifier"
		clientIP  = "10.100.0.95"
		backendID = int64(306)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-noclassifier", peerKey, clientIP, backendID, capPath.path)

	targets := []netip.Addr{
		netip.MustParseAddr("213.180.204.186"), // inside the allocation
		netip.MustParseAddr("8.8.4.4"),         // uncovered
	}
	for i, target := range targets {
		pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, uint16(41010+i), 443, 0x02, nil)
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("RouteClientToBackend(%s): %v", target, err)
		}
		flow := recordedFlow(t, dem, sessionID, target)
		if flow.Choice != EgressChoiceProxy || flow.DecisionReason != EgressReasonNoTrustedEvidence {
			t.Errorf("%s: flow = %v/%q, want PROXY/%q", target, flow.Choice, flow.DecisionReason, EgressReasonNoTrustedEvidence)
		}
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("packets written direct without a classifier: %d", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 2 {
		t.Fatalf("packets queued to the proxy backend = %d, want 2", got)
	}
}

// TestRetainedProxyEvidenceCannotProxyAllocationDestination is one half of the
// stale-evidence control: the session still holds a retained PROXY decision for
// an address inside the Russian allocation, and the address must route DIRECT
// anyway. The retained evidence is present in the same route cache the packet
// path is configured with, so the only way this passes is that the decision no
// longer reads it.
func TestRetainedProxyEvidenceCannotProxyAllocationDestination(t *testing.T) {
	fwd, dem, wanDev, rc := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	const (
		peerKey   = "peer-stale-proxy"
		sessionID = "s-stale-proxy"
		clientIP  = "10.100.0.97"
		backendID = int64(308)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-stale-proxy", peerKey, clientIP, backendID, capPath.path)

	target := netip.MustParseAddr("213.180.204.186") // inside 213.180.192.0/19
	rc.Set(sessionID, target, policy.Proxy)
	if got := rc.Lookup(sessionID, target); got != policy.Proxy {
		t.Fatalf("fixture evidence = %v, want the retained PROXY decision under test", got)
	}

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41030, 443, 0x02, nil)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 1 {
		t.Fatalf("packets written to the direct WAN device = %d, want 1: retained PROXY evidence proxied an allocation address", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 0 {
		t.Fatalf("packets queued to the proxy backend = %d, want 0: retained PROXY evidence proxied an allocation address", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceDirect {
		t.Fatalf("flow choice = %v, want DIRECT", flow.Choice)
	}
	if flow.DecisionReason != EgressReasonAllocationDirect {
		t.Errorf("decision reason = %q, want %q: the address decided, not the evidence", flow.DecisionReason, EgressReasonAllocationDirect)
	}
	if flow.DecisionReason == EgressReasonProxyCachedEvidence || flow.DecisionReason == EgressReasonEvidenceDirect {
		t.Errorf("decision reason = %q, want an address-based reason", flow.DecisionReason)
	}
}

// TestRetainedDirectEvidenceCannotRouteUncoveredDestinationDirect is the other
// half: the session holds a retained DIRECT decision for an address the
// classifier does not cover, and the address must still proxy.
func TestRetainedDirectEvidenceCannotRouteUncoveredDestinationDirect(t *testing.T) {
	fwd, dem, wanDev, rc := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))

	const (
		peerKey   = "peer-stale-direct"
		sessionID = "s-stale-direct"
		clientIP  = "10.100.0.98"
		backendID = int64(309)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-stale-direct", peerKey, clientIP, backendID, capPath.path)

	target := netip.MustParseAddr("147.91.1.1") // Serbia, outside the allocation
	rc.Set(sessionID, target, policy.Direct)
	if got := rc.Lookup(sessionID, target); got != policy.Direct {
		t.Fatalf("fixture evidence = %v, want the retained DIRECT decision under test", got)
	}

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41031, 443, 0x02, nil)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}

	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("packets written direct = %d, want 0: retained DIRECT evidence routed an uncovered address direct", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 1 {
		t.Fatalf("packets queued to the proxy backend = %d, want 1", got)
	}
	flow := recordedFlow(t, dem, sessionID, target)
	if flow.Choice != EgressChoiceProxy {
		t.Fatalf("flow choice = %v, want PROXY", flow.Choice)
	}
	if flow.DecisionReason != EgressReasonNoTrustedEvidence {
		t.Errorf("decision reason = %q, want %q: the address decided, not the evidence", flow.DecisionReason, EgressReasonNoTrustedEvidence)
	}
}

// TestAllocationClassifiedFlowWithoutEgressDrops is the contract's last row: a
// DIRECT decision whose required egress is unavailable is a DROP with the
// producer's reason, never a silent switch to the proxy.
func TestAllocationClassifiedFlowWithoutEgressDrops(t *testing.T) {
	fwd, _, wanDev, _ := setupForwarderWithPBR(t)
	fwd.SetDestinationClassifier(installedClassifier(t))
	// No direct-egress manager: the proxied path is healthy, the direct one is not.
	fwd.SetDirectEgress(nil)

	const (
		peerKey   = "peer-noegress"
		sessionID = "s-noegress"
		clientIP  = "10.100.0.96"
		backendID = int64(307)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "c-noegress", peerKey, clientIP, backendID, capPath.path)
	generation := routeGeneration(t, fwd, peerKey)

	target := netip.MustParseAddr("213.180.204.186")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), target, 41020, 443, 0x02, nil)

	err := fwd.RouteClientToBackend(peerKey, pkt)
	if !errors.Is(err, ErrDirectEgressUnavailable) {
		t.Fatalf("RouteClientToBackend = %v, want ErrDirectEgressUnavailable", err)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("packets written to an unavailable WAN device: %d", got)
	}
	if got := len(fwd.backendQueues[backendID]); got != 0 {
		t.Fatalf("a DIRECT decision was silently switched to the proxy (%d queued packets)", got)
	}

	drops := fwd.ClientDropSnapshot(sessionID, generation, 8)
	found := false
	for _, entry := range drops.Entries {
		if entry.Key.Reason == DropReasonEgressUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %q record for the refused DIRECT dispatch: %+v", DropReasonEgressUnavailable, drops.Entries)
	}
}
