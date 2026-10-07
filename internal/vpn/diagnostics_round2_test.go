package vpn

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

// requireDeterministicInboundQueue asserts that the fixture's portal device
// has its inbound reads suspended, BEFORE the caller creates any inbound queue
// state. Every test that injects into the inbound queue and then asserts its
// occupancy, its peak, or that a later Close drains it must call this first.
//
// Why the gate must be armed at construction time: the upstream engine starts
// its TUN reader goroutine inside device.NewDevice (amneziawg-go
// v3.1.20260828 device/device.go:374) and device.Down() only closes the bind
// and stops the peers (downLocked, device/device.go:236-248), so no upstream
// API can stop it. That reader then sits parked inside VirtualTUN.Read,
// already past the gate at the top of Read. Arming the gate after the fact
// does not reach it, and it dequeues the next injected packet immediately.
// newSingleOwnerFixture therefore builds the device with
// NewDeviceWithSuspendedReadsForTest, so the reader's first Read call blocks
// on the gate; this helper exists so each test states that dependency at its
// own call site and fails loudly if the fixture ever regresses.
//
// Without it such a test passes when the assertions run first and fails when
// the reader runs first, which is exactly what a loaded, coverage-instrumented
// CI runner produces.
//
// This is a test-only determinism measure. Production is untouched: the queue,
// NewDevice, Up and the reader goroutine all behave exactly as before, and the
// direction mapping these tests assert is the production mapping.
func requireDeterministicInboundQueue(t *testing.T, engine *IngressEngine) {
	t.Helper()
	if engine.portal == nil {
		t.Fatal("fixture has no portal device")
	}
	if !engine.portal.ReadsSuspendedForTest() {
		t.Fatal("inbound reads are not suspended: the upstream TUN reader will " +
			"drain the queue this test is about to assert on")
	}
}

// Blocker 1: the VirtualTUN direction mapping must match the device's actual
// queue semantics. VirtualTUN.Write feeds the OUTBOUND queue and carries
// upstream -> Nexus traffic; VirtualTUN.InjectInbound feeds the INBOUND queue
// and carries Nexus -> Upstream traffic.
//
// The fixture builds an intentionally asymmetric state: several outbound
// packets and one inbound packet, so the two directions cannot be confused and
// still produce matching totals.
//
// The fixture builds the device with inbound reads already suspended, so the
// upstream TUN reader (started inside device.NewDevice) blocks on its first
// Read and never drains the inbound queue. Every inbound assertion below is
// therefore deterministic rather than a race against that goroutine: on a
// loaded or coverage-instrumented runner the reader would otherwise win and
// the packet would already be gone, so occupancy and peak would read 0.
// This does NOT change production queue behavior: NewDevice, Up and the
// reader are untouched, and the direction mapping asserted here is the
// production one.
func TestVirtualTUNDirectionMapping(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)
	// Must precede any InjectInbound: the assertions below read inbound
	// occupancy and inbound peak.
	requireDeterministicInboundQueue(t, engine)

	outbound := [][]byte{[]byte("up"), []byte("stream"), []byte("payload")}
	if _, err := engine.portal.WriteOutboundForTest(outbound, 0); err != nil {
		t.Fatalf("portal.Write: %v", err)
	}
	if err := engine.portal.InjectInbound([]byte("down")); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}

	var status Status
	svc.populateOperationalDiagnostics(&status)

	up := status.VirtualTUN.UpstreamToNexus
	down := status.VirtualTUN.NexusToUpstream

	if up.Occupancy != 3 {
		t.Errorf("UpstreamToNexus.Occupancy: expected 3 (outbound queue), got %d", up.Occupancy)
	}
	if down.Occupancy != 1 {
		t.Errorf("NexusToUpstream.Occupancy: expected 1 (inbound queue), got %d", down.Occupancy)
	}
	if up.Capacity != virtualtun.DefaultOutboundCapacity {
		t.Errorf("UpstreamToNexus.Capacity: expected outbound capacity %d, got %d",
			virtualtun.DefaultOutboundCapacity, up.Capacity)
	}
	if down.Capacity != 2 {
		t.Errorf("NexusToUpstream.Capacity: expected the fixture inbound capacity 2, got %d", down.Capacity)
	}
	if up.Peak != 3 {
		t.Errorf("UpstreamToNexus.Peak: expected 3, got %d", up.Peak)
	}
	if down.Peak != 1 {
		t.Errorf("NexusToUpstream.Peak: expected 1, got %d", down.Peak)
	}
}

// Blocker 2: an Upstream -> Nexus (outbound) VirtualTUN drop must be counted
// exactly once, in the client-side bucket, and must move both the cumulative
// totals and the sampled rates together.
func TestOutboundVirtualTUNDropsCountedOnceInClientBucket(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)
	// Must precede the queue-filling writes: the shared device is live and a
	// draining reader would change the exact overflow drop count.
	requireDeterministicInboundQueue(t, engine)

	// Prime the windowed rate tracker BEFORE any drop exists. The tracker must
	// only report NEW loss inside a window; without this first collection the
	// drops below would sit in the lifetime totals at prime time and correctly
	// contribute no rate (issue #424 round 8, finding 2). Previously this test
	// passed only because the tracker compared lifetime totals against a zero
	// baseline, which reported a burst of historical drops as an active rate.
	var first Status
	svc.populateOperationalDiagnostics(&first)
	if first.DropCategories.TotalDrops != 0 {
		t.Fatalf("precondition: expected no drops before the burst, got %d",
			first.DropCategories.TotalDrops)
	}

	// Fill the outbound queue to capacity, then push past it. The device
	// counts a queue-full drop per rejected packet.
	capacity := virtualtun.DefaultOutboundCapacity
	for i := 0; i < capacity+5; i++ {
		if _, err := engine.portal.WriteOutboundForTest([][]byte{[]byte("p")}, 0); err != nil {
			t.Fatalf("portal.Write %d: %v", i, err)
		}
	}

	snap := engine.portal.Stats()
	if snap.OutboundDrops != 5 {
		t.Fatalf("precondition: expected 5 outbound drops, got %d", snap.OutboundDrops)
	}

	// The tracker throttles sub-200ms resampling, so space the two samples.
	var second Status
	time.Sleep(250 * time.Millisecond)
	svc.populateOperationalDiagnostics(&second)
	if second.DropCategories.ClientVirtualTUNDrops != 5 {
		t.Errorf("ClientVirtualTUNDrops: expected 5, got %d", second.DropCategories.ClientVirtualTUNDrops)
	}
	if second.DropCategories.ClientTotalDrops != 5 {
		t.Errorf("ClientTotalDrops: expected 5, got %d", second.DropCategories.ClientTotalDrops)
	}
	if second.DropCategories.ReturnTotalDrops != 0 {
		t.Errorf("ReturnTotalDrops: expected 0, got %d (outbound drops are not return-side)",
			second.DropCategories.ReturnTotalDrops)
	}
	if second.DropCategories.TotalDrops != 5 {
		t.Errorf("TotalDrops: expected 5, got %d", second.DropCategories.TotalDrops)
	}
	if second.DropCategories.ClientDropRatePps <= 0 {
		t.Errorf("ClientDropRatePps: expected a non-zero rate for drops NEW in this window, got %f",
			second.DropCategories.ClientDropRatePps)
	}
	if second.DropCategories.TotalDropRatePps <= 0 {
		t.Errorf("TotalDropRatePps: expected a non-zero rate for drops NEW in this window, got %f",
			second.DropCategories.TotalDropRatePps)
	}

	// No category may double-count the same packet.
	d := second.DropCategories
	categories := uint64(d.ClientMalformed + d.ClientUnmappedSource + d.ClientMismatch +
		d.ClientRejected + d.ClientBackendQueueFull + d.ClientRateLimited +
		d.ClientNoHealthyBackend + d.ClientVirtualTUNDrops +
		d.ReturnMalformed + d.ReturnUnmapped + d.ReturnMismatch +
		d.ReturnInjectionErrors + d.ReturnVirtualTUNDrops)
	if categories != d.TotalDrops {
		t.Errorf("categories sum to %d but TotalDrops is %d: a drop is counted twice or not at all",
			categories, d.TotalDrops)
	}
}

// Blocker 3: the mix explicitly requested by the review. One real non-TUN
// injection failure (an oversized packet, which loses the packet without ever
// touching an inbound drop bucket) alongside inbound VirtualTUN drops that have
// no injection error at all (shutdown drain). Every loss must be counted
// exactly once, and the non-TUN injection error must survive.
func TestInjectionAndInboundTUNDropsAreDisjoint(t *testing.T) {
	svc, _, engine, resolver, _ := newSingleOwnerFixture(t)
	// The shutdown drain below only produces an inbound drop while the packet
	// is still queued, so the upstream reader must be suspended first.
	requireDeterministicInboundQueue(t, engine)
	// The fixture configures a 1280-byte MTU (see newSingleOwnerFixture).
	const mtu = 1280

	// Register ownership so writeReturnPacket reaches the injection site rather
	// than short-circuiting on the unmapped-destination branch.
	resolver.Update(ingress.PeerOwnership{
		PeerPublicKey: "ps-peer", IP: netip.MustParseAddr("10.100.0.1"), ConnectionID: "c", UserID: "u",
	})

	// One real non-TUN injection failure: an oversized packet is rejected by
	// the device as an external drop, with no inbound bucket entry and no
	// queue-full ownership, so it must survive as a non-TUN injection error.
	oversized := buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.1"), mtu+64)
	if _, err := engine.writeReturnPacket("ps-peer", "10.100.0.1", oversized); err == nil {
		t.Fatalf("expected the oversized injection to be rejected")
	}
	if got := engine.ReturnStats().InjectionTunDrops; got != 0 {
		t.Fatalf("precondition: an oversized packet must not be owned by the inbound bucket, got %d", got)
	}

	// Inbound drops with no injection error at all: queue a packet, then Close
	// drains it as a shutdown drop.
	if err := engine.portal.InjectInbound(
		buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.1"), 40)); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	if err := engine.portal.Close(); err != nil {
		t.Fatalf("portal.Close: %v", err)
	}

	stats := engine.ReturnStats()
	if stats.InjectionErrors != 1 {
		t.Fatalf("precondition: expected 1 injection error, got %d", stats.InjectionErrors)
	}
	if stats.TUN.InboundDrops < 1 {
		t.Fatalf("precondition: expected the shutdown drain to count as an inbound drop")
	}

	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories

	// The old rule subtracted the whole inbound aggregate from the error
	// count, which would have clamped 1 - inboundDrops to 0 and hidden the
	// real non-TUN failure.
	if d.ReturnInjectionErrors != 1 {
		t.Errorf("ReturnInjectionErrors: expected the non-TUN failure to survive as 1, got %d",
			d.ReturnInjectionErrors)
	}
	if d.ReturnVirtualTUNDrops != stats.TUN.InboundDrops {
		t.Errorf("ReturnVirtualTUNDrops: expected %d, got %d",
			stats.TUN.InboundDrops, d.ReturnVirtualTUNDrops)
	}
	if d.ReturnInjectionTUNDrops != 0 {
		t.Errorf("ReturnInjectionTUNDrops: expected 0 owned drops, got %d", d.ReturnInjectionTUNDrops)
	}

	// Each individual loss is counted exactly once.
	wantReturn := uint64(1) + d.ReturnVirtualTUNDrops
	if d.ReturnTotalDrops != wantReturn {
		t.Errorf("ReturnTotalDrops: expected %d, got %d", wantReturn, d.ReturnTotalDrops)
	}
	categories := uint64(d.ReturnMalformed + d.ReturnUnmapped + d.ReturnMismatch +
		d.ReturnInjectionErrors + d.ReturnVirtualTUNDrops)
	if categories != d.ReturnTotalDrops {
		t.Errorf("return categories sum to %d but ReturnTotalDrops is %d", categories, d.ReturnTotalDrops)
	}
	if d.TotalDrops != d.ClientTotalDrops+d.ReturnTotalDrops {
		t.Errorf("TotalDrops (%d) != client (%d) + return (%d)",
			d.TotalDrops, d.ClientTotalDrops, d.ReturnTotalDrops)
	}
}

// Blocker 3 (negative control): a queue-full injection is owned by the inbound
// bucket and must not also appear as a non-TUN injection error.
func TestQueueFullInjectionOwnedByInboundBucket(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)
	// The priming packets below must still be queued when the real injection
	// runs, otherwise the inbound queue never fills and the test silently
	// skips instead of covering the ownership annotation.
	requireDeterministicInboundQueue(t, engine)

	// Fill the inbound queue, then inject through the real site so the
	// ownership counter is exercised.
	for i := 0; i < 2; i++ {
		pkt := buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.1"), 40)
		if err := engine.portal.InjectInbound(pkt); err != nil {
			t.Fatalf("priming InjectInbound %d: %v", i, err)
		}
	}
	engine.resolver.Update(ingress.PeerOwnership{
		PeerPublicKey: "ps-peer", IP: netip.MustParseAddr("10.100.0.1"), ConnectionID: "c", UserID: "u",
	})
	if _, err := engine.writeReturnPacket("ps-peer", "10.100.0.1",
		buildTestIPv4Packet(net.ParseIP("1.1.1.1"), net.ParseIP("10.100.0.1"), 40)); err == nil {
		t.Skip("inbound queue did not fill; the fixture capacity changed")
	}

	stats := engine.ReturnStats()
	if stats.InjectionErrors != 1 || stats.InjectionTunDrops != 1 {
		t.Fatalf("precondition: expected 1/1 injection errors and owned TUN drops, got %d/%d",
			stats.InjectionErrors, stats.InjectionTunDrops)
	}

	var status Status
	svc.populateOperationalDiagnostics(&status)
	d := status.DropCategories
	if d.ReturnInjectionErrors != 0 {
		t.Errorf("ReturnInjectionErrors: expected 0 (owned by the inbound bucket), got %d",
			d.ReturnInjectionErrors)
	}
	if d.ReturnVirtualTUNDrops != stats.InjectionTunDrops {
		t.Errorf("ReturnVirtualTUNDrops: expected %d, got %d",
			stats.InjectionTunDrops, d.ReturnVirtualTUNDrops)
	}
}

// Blocker 5: a historical ownership-mismatch counter must stay visible while
// current routing health recovers to consistent.
func TestOwnershipMismatchRecoversToConsistent(t *testing.T) {
	svc, _, engine, _, _ := newSingleOwnerFixture(t)

	// Prime the window first: the tracker's first sample is a baseline, so a
	// counter that was already non-zero at construction is not reported as a
	// fresh incident.
	svc.populateOperationalDiagnostics(&Status{})

	// Mismatches now arrive.
	engine.returnCounters.mismatch.Add(7)
	time.Sleep(250 * time.Millisecond)

	var during Status
	svc.populateOperationalDiagnostics(&during)
	if during.RoutingConsistency.IsConsistent {
		t.Fatalf("expected routing inconsistent while mismatches are arriving")
	}
	if during.RoutingConsistency.OwnershipMismatchDrops != 7 {
		t.Errorf("cumulative OwnershipMismatchDrops: expected 7, got %d",
			during.RoutingConsistency.OwnershipMismatchDrops)
	}
	if during.RoutingConsistency.OwnershipMismatchDropsRecent != 7 {
		t.Errorf("OwnershipMismatchDropsRecent: expected 7, got %d",
			during.RoutingConsistency.OwnershipMismatchDropsRecent)
	}

	// Stop injecting. After a window with no increase the health must recover
	// even though the cumulative counter stays at 7.
	time.Sleep(250 * time.Millisecond)
	var after Status
	svc.populateOperationalDiagnostics(&after)
	if !after.RoutingConsistency.IsConsistent {
		t.Errorf("expected routing consistent after recovery, details: %v",
			after.RoutingConsistency.InconsistencyDetails)
	}
	if after.RoutingConsistency.OwnershipMismatchDrops != 7 {
		t.Errorf("cumulative counter must stay at 7 as history, got %d",
			after.RoutingConsistency.OwnershipMismatchDrops)
	}
	if after.RoutingConsistency.OwnershipMismatchDropsRecent != 0 {
		t.Errorf("recent delta must fall to 0 after recovery, got %d",
			after.RoutingConsistency.OwnershipMismatchDropsRecent)
	}
	if len(after.RoutingConsistency.HistoricalDetails) != 1 {
		t.Errorf("expected the recovered incident in HistoricalDetails, got %v",
			after.RoutingConsistency.HistoricalDetails)
	}
}

// Blocker 5: peer sync failures must not pin DEGRADED after recovery.
func TestPeerSyncFailuresRecoverToHealthy(t *testing.T) {
	ps := PeerSyncStatus{DesiredPeers: 10, ActualPeers: 10}

	// Active failures degrade.
	active := ps
	active.SyncFailures = 5
	active.SyncFailuresRecent = 2
	active.FailuresWindowSec = 1
	conds := evaluatePeerSyncAndBackendConditions(&active, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	if !hasCondition(conds, "peer_sync", "DEGRADED") {
		t.Fatalf("expected an active peer_sync DEGRADED condition, got %+v", conds)
	}

	// Recovered: cumulative stays non-zero, no recent delta, no condition.
	recovered := ps
	recovered.SyncFailures = 5
	conds = evaluatePeerSyncAndBackendConditions(&recovered, BackendsDiagnostics{}, HandshakeFreshnessDiagnostics{})
	if hasCondition(conds, "peer_sync", "DEGRADED") {
		t.Errorf("lifetime SyncFailures must not degrade current health, got %+v", conds)
	}
}

// Blocker 5: the end-to-end delta window the service actually applies.
func TestPeerSyncDeltaWindowRecovers(t *testing.T) {
	svc := &Service{}
	ps := &PeerSyncStatus{DesiredPeers: 1, ActualPeers: 1}

	svc.diagDeltas.sampleSyncFailures(0, time.Now(), 0)
	time.Sleep(250 * time.Millisecond)

	svc.diagDeltas.sampleSyncFailures(0, time.Now(), 3)
	svc.diagDeltas.sampleEnqueueFailures(0, time.Now(), 2)
	if ps.SyncFailures != 0 {
		t.Fatalf("precondition failed")
	}

	// After the increase, a fresh window with no further increase recovers.
	time.Sleep(250 * time.Millisecond)
	syncRate := svc.diagDeltas.sampleSyncFailures(0, time.Now(), 3)
	enqueueRate := svc.diagDeltas.sampleEnqueueFailures(0, time.Now(), 2)
	if syncRate.delta != 0 || enqueueRate.delta != 0 {
		t.Errorf("expected zero deltas after recovery, got sync=%d enqueue=%d",
			syncRate.delta, enqueueRate.delta)
	}
}

// Blocker 7: the headline message must describe the condition at the winning
// severity, not simply the first condition in the list.
func TestSummarizeHealthConditionsMatchesWinningSeverity(t *testing.T) {
	tests := []struct {
		name       string
		conditions []HealthCondition
		wantStatus string
		wantSubstr string
	}{
		{
			name: "critical_after_warning",
			conditions: []HealthCondition{
				{Category: "queue_pressure", Severity: "WARNING", Message: "queue warning message"},
				{Category: "backend", Severity: "CRITICAL", Message: "backend critical message"},
			},
			wantStatus: HealthCritical,
			wantSubstr: "backend critical message",
		},
		{
			name: "degraded_after_critical_free_warning",
			conditions: []HealthCondition{
				{Category: "queue_pressure", Severity: "WARNING", Message: "queue warning message"},
				{Category: "drops", Severity: "DEGRADED", Message: "drop degradation message"},
			},
			wantStatus: HealthDegraded,
			wantSubstr: "drop degradation message",
		},
		{
			name: "warning_only",
			conditions: []HealthCondition{
				{Category: "sessions", Severity: "WARNING", Message: "session warning message"},
			},
			wantStatus: HealthHealthy,
			wantSubstr: "session warning message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, summary := summarizeHealthConditions(tt.conditions)
			if status != tt.wantStatus {
				t.Errorf("status: expected %s, got %s", tt.wantStatus, status)
			}
			if !contains(summary, tt.wantSubstr) {
				t.Errorf("summary %q does not describe the winning condition %q",
					summary, tt.wantSubstr)
			}
		})
	}
}

func TestEvaluateForwarderHealth_HeadlineMatchesCritical(t *testing.T) {
	backends := BackendsDiagnostics{TotalCount: 2, HealthyCount: 0}
	queue := QueuePressureDiagnostics{Capacity: 1000, Occupancy: 810, UtilizationPct: 81.0}
	vtun := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5},
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5},
	}
	drops := DropCategoryBreakdown{}
	latency := ForwardLatencyDiagnostics{P95MS: 1}
	routing := RoutingConsistencyDiagnostics{IsConsistent: true}

	a := EvaluateForwarderHealth(true, true, queue, latency, drops, vtun, nil, routing,
		HandshakeFreshnessDiagnostics{}, backends)
	if a.Status != HealthCritical {
		t.Fatalf("expected CRITICAL, got %s (%s)", a.Status, a.Summary)
	}
	if !contains(a.Summary, "No healthy backends") {
		t.Errorf("headline cites the wrong condition: %q", a.Summary)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func hasCondition(conds []HealthCondition, category, severity string) bool {
	for _, c := range conds {
		if c.Category == category && c.Severity == severity {
			return true
		}
	}
	return false
}

var _ = forwarder.RouteInfo{}
