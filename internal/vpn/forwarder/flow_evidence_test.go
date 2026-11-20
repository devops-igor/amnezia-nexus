package forwarder

import (
	"errors"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Producer→snapshot coverage for the per-flow evidence of issue #861, slice 3a.
//
// Every value asserted here is produced by the path that owns it: the decision is
// taken inside routeClientPBR, the dispatch outcome inside RouteDirect or the
// proxy enqueue, and the DIRECT return inside HandleWANReply. The snapshot only
// copies. A producer that stops attributing (or attributes the wrong incarnation)
// therefore fails these tests — which is what makes them consumer proof rather
// than a DTO check.

// flowEvidenceFixture builds a policy-active forwarder whose WAN device and
// backend queue are test devices, plus a route cache the test can steer.
type flowEvidenceFixture struct {
	fwd        *Forwarder
	dem        *DirectEgressManager
	wan        *mockPacketDev
	backendDev *mockPacketDev
	rc         *testRouteCache
	matcher    *policy.Matcher
	peerKey    string
	session    string
	client     string
	backendID  int64
	returnPath *testCaptureReturnPath
}

func newFlowEvidenceFixture(t *testing.T, queueSize int) *flowEvidenceFixture {
	t.Helper()
	fix := &flowEvidenceFixture{
		fwd:        NewForwarder(nil, "10.100.0.0/16", queueSize),
		wan:        newMockPacketDev(),
		backendDev: newMockPacketDev(),
		rc:         newTestRouteCache(),
		matcher:    policy.NewMatcher(),
		peerKey:    "peer-flow-evidence",
		session:    "sess-flow-evidence",
		client:     "10.100.0.5",
		backendID:  77,
	}
	fix.fwd.SetPBREnabled(true)
	fix.fwd.AttachBackendDevice(fix.backendID, fix.backendDev)
	fix.dem = NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: fix.wan,
	}, fix.fwd)
	fix.fwd.SetDirectEgress(fix.dem)
	// The manager owns a WAN reader; retire it with the test that created it.
	t.Cleanup(func() { _ = fix.dem.Close() })
	fix.fwd.SetRouteCache(fix.rc)
	fix.publishSnapshot(t, nil)
	fix.returnPath = newTestCaptureReturnPath()
	fix.fwd.RegisterSessionWithReturnPath(fix.session, "conn-1", fix.peerKey, fix.client, fix.backendID, fix.returnPath.path)
	return fix
}

// publishSnapshot publishes a policy snapshot with the supplied CIDR rules and
// attaches it to the forwarder.
func (f *flowEvidenceFixture) publishSnapshot(t *testing.T, cidrs []netip.Prefix) {
	t.Helper()
	f.publishSnapshotGeneration(t, "gen-flow", cidrs)
}

// publishSnapshotGeneration publishes under an explicit generation, which is what
// makes "the recorded generation did not move" observable.
func (f *flowEvidenceFixture) publishSnapshotGeneration(t *testing.T, generation string, cidrs []netip.Prefix) {
	t.Helper()
	rules := policy.ParsedRules{CIDRs: cidrs}
	snapshot, err := policy.CompileSnapshot(1, generation, []policy.SourceParsedRules{
		{SourceID: "flow-rules", Rules: rules},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	f.matcher.Publish(snapshot)
	f.fwd.SetPolicyMatcher(f.matcher)
}

func (f *flowEvidenceFixture) send(t *testing.T, dst string, dstPort uint16) {
	t.Helper()
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(f.client), netip.MustParseAddr(dst), 41000, dstPort, 0x02, nil)
	if err := f.fwd.RouteClientToBackend(f.peerKey, pkt); err != nil {
		t.Fatalf("RouteClientToBackend(%s:%d): %v", dst, dstPort, err)
	}
}

// direct installs an address classifier that puts the supplied destinations inside
// the Russian allocation, which is how the final contract decides a flow DIRECT.
// A test states the address input the production classifier would supply; retained
// DNS evidence no longer decides a route.
func (f *flowEvidenceFixture) direct(t *testing.T, dsts ...string) {
	t.Helper()
	addrs := make([]netip.Addr, 0, len(dsts))
	for _, dst := range dsts {
		addr, err := netip.ParseAddr(dst)
		if err != nil {
			t.Fatalf("fixture destination %q: %v", dst, err)
		}
		addrs = append(addrs, addr)
	}
	f.fwd.SetDestinationClassifier(newTestDirectClassifier(addrs...))
}

func (f *flowEvidenceFixture) snapshot(t *testing.T) SessionFlowList {
	t.Helper()
	return f.snapshotFor(t, f.session)
}

// snapshotFor reads one session's flows, which is what a diagnosis for that exact
// session does.
func (f *flowEvidenceFixture) snapshotFor(t *testing.T, sessionID string) SessionFlowList {
	t.Helper()
	return f.dem.SnapshotSessionFlows(sessionID, 0, time.Now(), 0)
}

func (f *flowEvidenceFixture) onlyFlow(t *testing.T) SessionFlow {
	t.Helper()
	list := f.snapshot(t)
	if list.Total != 1 {
		t.Fatalf("flows = %d, want exactly one", list.Total)
	}
	return list.Flows[0]
}

// TestFlowEvidenceRecordsTheDirectDecision is the primary positive control: a
// DIRECT flow states the branch that chose it, when, against which policy
// generation, and what the dispatch did.
func TestFlowEvidenceRecordsTheDirectDecision(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := "93.184.216.34"
	fix.direct(t, dst)

	before := time.Now()
	fix.send(t, dst, 443)
	flow := fix.onlyFlow(t)

	if flow.Choice != EgressChoiceDirect {
		t.Fatalf("choice = %v, want DIRECT", flow.Choice)
	}
	if flow.DecisionReason != EgressReasonAllocationDirect {
		t.Errorf("reason = %q, want %q: the decision branch must be recorded, not inferred", flow.DecisionReason, EgressReasonAllocationDirect)
	}
	if flow.DecidedAt.IsZero() || flow.DecidedAt.Before(before.Add(-time.Second)) {
		t.Errorf("decided_at = %v, want the instant of the decision", flow.DecidedAt)
	}
	if flow.PolicyGeneration != "gen-flow" {
		t.Errorf("policy generation = %q, want the published generation", flow.PolicyGeneration)
	}
	if flow.ForwardPackets != 1 || flow.ForwardBytes == 0 || flow.ForwardFailed != 0 {
		t.Errorf("forward = %d packets/%d bytes/%d failed, want one successful WAN write",
			flow.ForwardPackets, flow.ForwardBytes, flow.ForwardFailed)
	}
	if flow.ReturnObserved || flow.ReturnPackets != 0 {
		t.Errorf("return = %v/%d before any reply, want no return evidence yet", flow.ReturnObserved, flow.ReturnPackets)
	}
	if flow.PROXYReturnMeasured {
		t.Error("PROXY return must be reported as not measured at this checkpoint")
	}
	if got := len(fix.wan.getPackets()); got != 1 {
		t.Errorf("WAN writes = %d, want the packet actually dispatched", got)
	}
}

// TestFlowEvidenceRecordsProxyDecisionsAndDispatch covers the three PROXY
// branches and the enqueue outcome, which lives in a different producer from the
// decision.
func TestFlowEvidenceRecordsProxyDecisionsAndDispatch(t *testing.T) {
	t.Run("CIDRRule", func(t *testing.T) {
		fix := newFlowEvidenceFixture(t, 8)
		fix.publishSnapshot(t, []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")})
		dst := "93.184.216.34"
		fix.send(t, dst, 443)
		flow := fix.onlyFlow(t)

		if flow.Choice != EgressChoiceProxy {
			t.Fatalf("choice = %v, want PROXY", flow.Choice)
		}
		if flow.DecisionReason != EgressReasonProxyCIDRRule {
			t.Errorf("reason = %q, want %q", flow.DecisionReason, EgressReasonProxyCIDRRule)
		}
		if flow.BackendTunnelID != fix.backendID {
			t.Errorf("backend = %d, want the selected tunnel %d", flow.BackendTunnelID, fix.backendID)
		}
		if flow.ForwardPackets != 1 || flow.ForwardFailed != 0 {
			t.Errorf("forward = %d/%d, want one accepted enqueue", flow.ForwardPackets, flow.ForwardFailed)
		}
		if flow.ForwardBytes != 0 {
			t.Errorf("proxy forward bytes = %d, want 0: bytes are booked by the queue, not by the decision", flow.ForwardBytes)
		}
	})

	t.Run("RetainedEvidenceDoesNotDecide", func(t *testing.T) {
		fix := newFlowEvidenceFixture(t, 8)
		dst := "93.184.216.35"
		// A retained PROXY decision is present for the destination; the address is
		// classified as an allocation member, so the address decides and the flow
		// records the branch that actually ran.
		fix.rc.Set(fix.session, netip.MustParseAddr(dst), policy.Proxy)
		fix.direct(t, dst)
		fix.send(t, dst, 443)
		flow := fix.onlyFlow(t)
		if flow.Choice != EgressChoiceDirect {
			t.Fatalf("choice = %v, want DIRECT: the address decided, not the evidence", flow.Choice)
		}
		if flow.DecisionReason != EgressReasonAllocationDirect {
			t.Errorf("reason = %q, want %q", flow.DecisionReason, EgressReasonAllocationDirect)
		}
	})

	t.Run("NoTrustedEvidence", func(t *testing.T) {
		fix := newFlowEvidenceFixture(t, 8)
		dst := "1.1.1.1"
		fix.send(t, dst, 443)
		flow := fix.onlyFlow(t)
		if flow.DecisionReason != EgressReasonNoTrustedEvidence {
			t.Errorf("reason = %q, want the fail-closed default", flow.DecisionReason)
		}
		if flow.Choice != EgressChoiceProxy {
			t.Errorf("choice = %v, want PROXY for an unevidenced destination", flow.Choice)
		}
	})
}

// TestFlowEvidenceRecordsRefusedDispatch covers a proxy dispatch the queue
// refused and a DIRECT dispatch the WAN device refused: both must state the
// failure on the flow instead of looking like a delivery.
func TestFlowEvidenceRecordsRefusedDispatch(t *testing.T) {
	t.Run("ProxyQueueFull", func(t *testing.T) {
		fix := newFlowEvidenceFixture(t, 8)
		dst := "8.8.4.4"
		// An unbuffered backend queue refuses every enqueue, which is the real
		// queue-full branch of the proxy dispatch.
		fix.fwd.mu.Lock()
		fix.fwd.backendQueues[fix.backendID] = make(chan BackendPacket)
		fix.fwd.mu.Unlock()
		if err := fix.fwd.RouteClientToBackend(fix.peerKey,
			buildTestIPv4TCPPacket(netip.MustParseAddr(fix.client), netip.MustParseAddr(dst), 41001, 443, 0x02, nil)); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("packet error = %v, want ErrQueueFull", err)
		}

		flow := fix.onlyFlow(t)
		if flow.ForwardFailed != 1 {
			t.Fatalf("forward failed = %d, want the refused enqueue", flow.ForwardFailed)
		}
		if flow.ForwardFailure != FlowFailureQueueFull {
			t.Errorf("forward failure = %q, want %q", flow.ForwardFailure, FlowFailureQueueFull)
		}
		if flow.ForwardPackets != 0 {
			t.Errorf("forward packets = %d, want none: the enqueue was refused", flow.ForwardPackets)
		}
	})

	t.Run("ProxyBackendDetached", func(t *testing.T) {
		fix := newFlowEvidenceFixture(t, 8)
		dst := "8.8.4.8"
		fix.fwd.DetachBackendDevice(fix.backendID)
		_ = fix.fwd.RouteClientToBackend(fix.peerKey,
			buildTestIPv4TCPPacket(netip.MustParseAddr(fix.client), netip.MustParseAddr(dst), 41002, 443, 0x02, nil))

		flow := fix.onlyFlow(t)
		if flow.ForwardFailed != 1 || flow.ForwardFailure != FlowFailureBackendDetached {
			t.Errorf("forward = %d failed/%q, want the detached refusal", flow.ForwardFailed, flow.ForwardFailure)
		}
	})

	t.Run("DirectWriteFailed", func(t *testing.T) {
		fix := newFlowEvidenceFixture(t, 8)
		dst := "93.184.216.36"
		fix.direct(t, dst)
		fix.dem.AttachWANDevice(newFailingFlowDev())
		if err := fix.fwd.RouteClientToBackend(fix.peerKey,
			buildTestIPv4TCPPacket(netip.MustParseAddr(fix.client), netip.MustParseAddr(dst), 41000, 443, 0x02, nil)); err == nil {
			t.Fatal("a failed WAN write was reported as a successful dispatch")
		}

		flow := fix.onlyFlow(t)
		if flow.ForwardFailed != 1 || flow.ForwardFailure != FlowFailureWrite {
			t.Errorf("forward = %d failed/%q, want one WAN write failure", flow.ForwardFailed, flow.ForwardFailure)
		}
		if flow.ForwardPackets != 0 {
			t.Errorf("forward packets = %d, want none: the write failed", flow.ForwardPackets)
		}
	})
}

// TestFlowEvidenceRecordsDirectReturn proves the return direction is attributed
// to the flow that owns the NAT entry, and that a reply the path refuses is not
// attributed to any flow.
func TestFlowEvidenceRecordsDirectReturn(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := "93.184.216.37"
	fix.direct(t, dst)
	fix.send(t, dst, 443)

	flow := fix.onlyFlow(t)
	if flow.ReturnObserved {
		t.Fatal("return observed before any reply")
	}

	// Craft the WAN reply for the NAT port the flow was given, then deliver it.
	fix.dem.mu.RLock()
	var natPort uint16
	var flowKey FlowKey
	for _, entry := range fix.dem.inboundNAT {
		natPort = entry.natPort
		flowKey = entry.flowKey
	}
	fix.dem.mu.RUnlock()
	if natPort == 0 {
		t.Fatal("no NAT entry for the DIRECT flow")
	}
	reply := buildTestIPv4TCPPacket(netip.MustParseAddr(dst), netip.MustParseAddr("203.0.113.1"), 443, natPort, 0x12, []byte("reply"))
	if err := fix.dem.HandleWANReply(reply); err != nil {
		t.Fatalf("HandleWANReply: %v", err)
	}

	flow = fix.onlyFlow(t)
	if !flow.ReturnObserved || flow.ReturnPackets != 1 {
		t.Fatalf("return = %v/%d, want one observed reply", flow.ReturnObserved, flow.ReturnPackets)
	}
	if flow.ReturnBytes == 0 || flow.ReturnFirst.IsZero() || flow.ReturnLast.IsZero() {
		t.Errorf("return = %d bytes, first %v, last %v, want the delivered reply measured", flow.ReturnBytes, flow.ReturnFirst, flow.ReturnLast)
	}
	if flow.ReturnLast.Before(flow.ReturnFirst) {
		t.Error("return last is before return first")
	}

	// A reply for a flow that has retired is refused and is attributed to no
	// flow: the retired incarnation keeps no evidence at all.
	fix.dem.mu.Lock()
	fix.dem.retireFlowLocked(flowKey, fix.dem.flows[flowKey], 6, time.Now())
	fix.dem.mu.Unlock()
	if err := fix.dem.HandleWANReply(reply); err == nil {
		t.Fatal("a reply for a retired flow was accepted")
	}
	if got := fix.snapshot(t); got.Total != 0 {
		t.Errorf("flows after retirement = %d, want none: a retired flow keeps no evidence", got.Total)
	}
}

// TestFlowEvidenceKeepsTheOriginalDecisionAcrossPolicyChanges proves a sticky
// flow keeps the choice, reason, generation and decision instant it was created
// with, even after the published policy would decide differently.
func TestFlowEvidenceKeepsTheOriginalDecisionAcrossPolicyChanges(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := "93.184.216.38"
	fix.direct(t, dst)
	fix.send(t, dst, 443)
	original := fix.onlyFlow(t)

	// Publish a NEW generation that puts the same destination range on the proxy: a
	// new flow would now be PROXY, and a record that re-read the policy at read
	// time would report the new generation instead of the deciding one.
	fix.publishSnapshotGeneration(t, "gen-flow-2", []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")})
	fix.send(t, dst, 443)

	sticky := fix.onlyFlow(t)
	if sticky.Choice != EgressChoiceDirect {
		t.Errorf("choice = %v, want the original DIRECT: a sticky flow is not re-decided", sticky.Choice)
	}
	if sticky.DecisionReason != EgressReasonAllocationDirect {
		t.Errorf("reason = %q, want the original branch, not the current policy", sticky.DecisionReason)
	}
	if !sticky.DecidedAt.Equal(original.DecidedAt) {
		t.Errorf("decided_at moved from %v to %v: the decision instant belongs to the decision", original.DecidedAt, sticky.DecidedAt)
	}
	if sticky.PolicyGeneration != original.PolicyGeneration {
		t.Errorf("policy generation moved from %q to %q: the flow must keep the generation that decided it",
			original.PolicyGeneration, sticky.PolicyGeneration)
	}
	if sticky.PolicyGeneration != "gen-flow" {
		t.Errorf("policy generation = %q, want the deciding generation gen-flow (the current one is gen-flow-2)", sticky.PolicyGeneration)
	}
	if sticky.ForwardPackets != 2 {
		t.Errorf("forward packets = %d, want both packets dispatched on the same flow", sticky.ForwardPackets)
	}
}

// TestFlowEvidenceTupleReuseIsANewIncarnation proves a tuple that is retired and
// then re-decided carries fresh evidence instead of the previous incarnation's.
func TestFlowEvidenceTupleReuseIsANewIncarnation(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := "93.184.216.39"
	fix.direct(t, dst)
	fix.send(t, dst, 443)
	first := fix.onlyFlow(t)

	// Retire the flow the way the packet path does, then send the same tuple again.
	fix.dem.PurgePeer(fix.peerKey)
	if got := fix.snapshot(t); got.Total != 0 {
		t.Fatalf("flows after purge = %d, want none", got.Total)
	}
	fix.send(t, dst, 443)
	second := fix.onlyFlow(t)

	if !second.DecidedAt.After(first.DecidedAt) {
		t.Errorf("decided_at = %v, want later than the previous incarnation %v", second.DecidedAt, first.DecidedAt)
	}
	if second.ForwardPackets != 1 || second.ForwardFailed != 0 {
		t.Errorf("forward = %d/%d, want a fresh block counting only the new packet", second.ForwardPackets, second.ForwardFailed)
	}
	if second.ReturnPackets != 0 {
		t.Error("the new incarnation inherited return evidence")
	}
}

// TestFlowEvidenceRefusesAttributionForASupersededRoute pins the branch that
// must not record a DIRECT decision: when the route the evidence came from is no
// longer the registered one, the packet still goes to the proxy but no DIRECT flow
// record is installed for the dead incarnation.
func TestFlowEvidenceRefusesAttributionForASupersededRoute(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := netip.MustParseAddr("93.184.216.60")

	// Capture the current route, then re-register the peer so that route's
	// generation is no longer the registered one.
	fix.fwd.mu.RLock()
	stale := fix.fwd.routesByPeer[fix.peerKey]
	fix.fwd.mu.RUnlock()
	if stale == nil {
		t.Fatal("fixture has no route")
	}
	fix.fwd.RegisterSessionWithReturnPath(fix.session, "conn-1", fix.peerKey, fix.client, fix.backendID, fix.returnPath.path)

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(fix.client), dst, 41000, 443, 0x02, nil)
	err := fix.fwd.routeDirectDecision(fix.dem, stale, fix.peerKey, pkt, int64(len(pkt)),
		proxyBackend{tunnelID: fix.backendID, queue: fix.fwd.backendQueues[fix.backendID]}, nil, fix.session, "conn-1",
		FlowDecision{Reason: EgressReasonEvidenceDirect, PolicyGeneration: "gen-flow", DecidedAt: time.Now()})
	if err != nil {
		t.Fatalf("fallback dispatch: %v", err)
	}
	if got := fix.snapshot(t); got.Total != 0 {
		t.Fatalf("flows = %d, want none: a superseded incarnation must not get a DIRECT record", got.Total)
	}

	// No direct egress at all is a distinct refusal, and it must not record a flow
	// either. It is reached with the CURRENT route, since the generation check runs
	// first.
	fix.fwd.mu.RLock()
	current := fix.fwd.routesByPeer[fix.peerKey]
	fix.fwd.mu.RUnlock()
	before := fix.fwd.DirectDrops()
	if err := fix.fwd.routeDirectDecision(nil, current, fix.peerKey, pkt, int64(len(pkt)),
		proxyBackend{}, nil, fix.session, "conn-1", FlowDecision{}); !errors.Is(err, ErrDirectEgressUnavailable) {
		t.Fatalf("missing direct egress error = %v, want ErrDirectEgressUnavailable", err)
	}
	if fix.fwd.DirectDrops() <= before {
		t.Error("a refused DIRECT dispatch was not counted")
	}
}

// TestFlowEvidenceDispatchCreditsOnlyTheDispatchingIncarnation is the deterministic
// replacement control for proxy dispatch accounting: a queued outcome carries the
// session and generation that dispatched it, so a late outcome from a retired
// incarnation must not credit the successor that reused the same tuple.
func TestFlowEvidenceDispatchCreditsOnlyTheDispatchingIncarnation(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := "1.1.1.1"
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(fix.client), netip.MustParseAddr(dst), 41000, 443, 0x02, nil)
	firstSession := fix.session
	firstGeneration := fix.generationOf(t)

	if err := fix.fwd.RouteClientToBackend(fix.peerKey, pkt); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	first := fix.onlyFlow(t)
	if first.ForwardPackets != 1 {
		t.Fatalf("first flow forward packets = %d, want 1", first.ForwardPackets)
	}

	// The session ends and the same peer is re-admitted: same peer key and tuple,
	// new session and route generation.
	fix.dem.PurgePeer(fix.peerKey)
	fix.dem.RecordProxyDispatch(fix.peerKey, firstSession, firstGeneration, pkt, false, FlowFailureQueueFull)
	if got := fix.snapshot(t); got.Total != 0 {
		t.Fatalf("flows after purge = %d, want none", got.Total)
	}

	fix.fwd.RegisterSessionWithReturnPath("sess-successor", "conn-2", fix.peerKey, fix.client, fix.backendID, fix.returnPath.path)
	if err := fix.fwd.RouteClientToBackend(fix.peerKey, pkt); err != nil {
		t.Fatalf("successor dispatch: %v", err)
	}
	successor := fix.snapshotFor(t, "sess-successor")
	if successor.Total != 1 {
		t.Fatalf("successor flows = %d, want 1", successor.Total)
	}
	if successor.Flows[0].ForwardPackets != 1 || successor.Flows[0].ForwardFailed != 0 {
		t.Fatalf("successor evidence before the late outcome = %d/%d, want 1/0",
			successor.Flows[0].ForwardPackets, successor.Flows[0].ForwardFailed)
	}

	// The late outcome of the retired incarnation: refused by the incarnation
	// check, so the successor's record is untouched.
	fix.dem.RecordProxyDispatch(fix.peerKey, firstSession, firstGeneration, pkt, false, FlowFailureQueueFull)
	if got := fix.snapshotFor(t, "sess-successor").Flows[0]; got.ForwardFailed != 0 || got.ForwardFailure != "" {
		t.Errorf("a retired incarnation's outcome credited the successor: failed=%d token=%q", got.ForwardFailed, got.ForwardFailure)
	}

	// The successor's own outcome is credited.
	fix.dem.RecordProxyDispatch(fix.peerKey, "sess-successor", fix.generationOf(t), pkt, false, FlowFailureQueueFull)
	if got := fix.snapshotFor(t, "sess-successor").Flows[0]; got.ForwardFailed != 1 || got.ForwardFailure != FlowFailureQueueFull {
		t.Errorf("the successor's own refusal was not credited: failed=%d token=%q", got.ForwardFailed, got.ForwardFailure)
	}
}

// generationOf reports the route generation currently registered for the fixture's
// peer.
func (f *flowEvidenceFixture) generationOf(t *testing.T) uint64 {
	t.Helper()
	f.fwd.mu.RLock()
	defer f.fwd.mu.RUnlock()
	if route := f.fwd.routesByPeer[f.peerKey]; route != nil {
		return route.generation
	}
	return 0
}

// TestFlowEvidenceSnapshotIsPure proves the read neither refreshes a flow nor
// moves its evidence.
func TestFlowEvidenceSnapshotIsPure(t *testing.T) {
	fix := newFlowEvidenceFixture(t, 8)
	dst := "93.184.216.40"
	fix.direct(t, dst)
	fix.send(t, dst, 443)

	first := fix.onlyFlow(t)
	second := fix.onlyFlow(t)

	if !first.LastSeen.Equal(second.LastSeen) {
		t.Errorf("a read refreshed lastSeen: %v -> %v", first.LastSeen, second.LastSeen)
	}
	if !first.DecidedAt.Equal(second.DecidedAt) ||
		first.ForwardPackets != second.ForwardPackets ||
		first.ForwardFailed != second.ForwardFailed ||
		first.ReturnPackets != second.ReturnPackets {
		t.Errorf("a read changed the evidence: %+v -> %+v", first, second)
	}
	if got := fix.snapshot(t).Total; got != 1 {
		t.Errorf("flows = %d after two reads, want 1", got)
	}
}

// TestFlowEvidenceBoundsAreTheFlowTable pins the metadata bound: there is no
// second store, so the existing table capacity is the cap and the worst-case size
// is a stated constant.
func TestFlowEvidenceBoundsAreTheFlowTable(t *testing.T) {
	perFlow := FlowEvidenceBytesPerFlow()
	if perFlow < int(unsafe.Sizeof(flowStats{})) {
		t.Fatalf("per-flow footprint = %d, want at least the measured struct size %d", perFlow, unsafe.Sizeof(flowStats{}))
	}
	if FlowEvidenceMaxFlowTableBytes() != perFlow*65536 {
		t.Fatalf("metadata bound = %d, want per-flow %d x table 65536", FlowEvidenceMaxFlowTableBytes(), perFlow)
	}
	t.Logf("measured evidence footprint: %d bytes per flow, %d bytes at the 65536-flow cap",
		perFlow, FlowEvidenceMaxFlowTableBytes())
	// A table-full refusal leaves no record rather than an unbounded one.
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	fix := newFlowEvidenceFixture(t, 8)
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: newMockPacketDev(),
		MaxFlows:  2,
	}, fwd)
	fwd.SetDirectEgress(dem)
	t.Cleanup(func() { _ = dem.Close() })
	fwd.RegisterSessionWithReturnPath(fix.session, "conn-1", fix.peerKey, fix.client, fix.backendID, nil)
	for i := 0; i < 2; i++ {
		if err := dem.RecordFlow(fix.peerKey, fix.session, 1, buildTestIPv4TCPPacket(
			netip.MustParseAddr(fix.client), netip.MustParseAddr("93.184.216.50"), uint16(42000+i), 443, 0x02, nil), EgressChoiceProxy); err != nil {
			t.Fatalf("RecordFlow %d: %v", i, err)
		}
	}
	err := dem.RecordFlow(fix.peerKey, fix.session, 1, buildTestIPv4TCPPacket(
		netip.MustParseAddr(fix.client), netip.MustParseAddr("93.184.216.51"), 42002, 443, 0x02, nil), EgressChoiceProxy)
	if !errors.Is(err, ErrFlowTableFull) {
		t.Fatalf("third flow error = %v, want ErrFlowTableFull", err)
	}
	if got := dem.SnapshotSessionFlows(fix.session, 0, time.Now(), 0); got.Total > 2 {
		t.Errorf("flows = %d, want at most the table cap 2", got.Total)
	}
}

// failingFlowDev fails every write, so a dispatch failure can be observed. Its read
// half parks like a TUN read, so the manager that replaces it does not spin.
type failingFlowDev struct{ *wanReadGate }

func newFailingFlowDev() *failingFlowDev {
	return &failingFlowDev{wanReadGate: newWANReadGate()}
}

func (d *failingFlowDev) Write(_ []byte) (int, error) { return 0, errors.New("wan write failed") }
