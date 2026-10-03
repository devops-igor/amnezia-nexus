package forwarder

// Regression coverage for issue #424 round 6, finding 3: ProblemRoutes treated
// a route's LIFETIME failure counters as CURRENT pressure.
//
// queueFullDrops, writeMetrics.Errors and writeMetrics.Stalls are monotonic for
// the lifetime of a route, and production resets NONE of them anywhere (there
// is no Store(0) for any of the three outside test code). The pre-change
// HasPressure read all three with "> 0", so ONE historical drop kept that
// route in the CURRENT problem-routes list until the sessionRoute was
// destroyed. That is the same lifetime-versus-current confusion round 2 fixed
// at the aggregate level, uncorrected at the route level.
//
// The pre-existing recovery coverage was vacuous: it did
// r2.queueFullDrops.Store(0), a reset production never performs, so it
// exercised a code path that does not exist. The tests below recover WITHOUT
// mutating any lifetime counter to zero.

import (
	"errors"
	"testing"
	"time"
)

// routePressureWindowAdvance moves past routePressureSampleInterval. The
// constant is read from production rather than re-spelled here so a test
// cannot drift from the implementation.
func routePressureWindowAdvance() time.Duration { return routePressureSampleInterval * 3 }

// TestProblemRoutesRecoverWithoutResettingALifetimeCounter is the finding-3
// regression.
//
// Sequence, with no counter ever set back to zero:
//
//	T0  prime the per-route recency window
//	T1  drive REAL drops through the production enqueue path (queue filled to
//	    capacity, next packet refused). The route becomes a problem route.
//	T2  stop the traffic and let time pass. The queue drains, occupancy falls,
//	    and no new drop occurs.
//	T3  the route must NO LONGER be a problem route, while its lifetime
//	    queue_full_drops is still nonzero and still visible on the payload.
//
// Under the pre-change condition, T3 fails: "> 0" on the lifetime counter holds
// the route in the list forever.
func TestProblemRoutesRecoverWithoutResettingALifetimeCounter(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.RegisterSession("s1", "c1", "peer-drops", "10.100.0.3", 1)

	// T0: prime every window. Without this the first accepted sample would be
	// the drop itself and the delta would be reported as zero. The wait is
	// required because the FIRST accepted sample of the window is the priming
	// one, and a sample that lands inside the sampling floor after it is not
	// accepted at all.
	f.InspectRoutes()
	time.Sleep(routePressureWindowAdvance())

	// T1: real drops through the production enqueue path.
	queue, ok := f.GetClientPacketChannel("peer-drops")
	if !ok {
		t.Fatal("client queue missing")
	}
	for i := 0; i < cap(queue); i++ {
		if err := f.RouteBackendToClient(1, returnPacketFor("10.100.0.3"), "10.100.0.3"); err != nil {
			t.Fatalf("priming enqueue %d: %v", i, err)
		}
	}
	if err := f.RouteBackendToClient(1, returnPacketFor("10.100.0.3"), "10.100.0.3"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected the full queue to drop, got %v", err)
	}

	during := f.InspectRoutes()
	if len(during) != 1 {
		t.Fatalf("expected one route, got %d", len(during))
	}
	if during[0].Stats.QueueFullDrops != 1 {
		t.Fatalf("precondition: the lifetime drop must be recorded, got %d", during[0].Stats.QueueFullDrops)
	}
	if during[0].Stats.QueueFullDropsRecent == 0 {
		t.Fatal("a drop inside the window must be reported as RECENT pressure")
	}
	if !during[0].HasPressure {
		t.Fatal("a route that just dropped a packet must have HasPressure=true")
	}
	if problems := f.ProblemRoutes(10); len(problems) != 1 {
		t.Fatalf("a route that just dropped a packet must be a problem route, got %d", len(problems))
	}

	// T2: the traffic stops. Draining the queue is what production does when
	// the consumer catches up; no counter is touched.
	for len(queue) > 0 {
		<-queue
	}
	time.Sleep(routePressureWindowAdvance())

	// T3: the incident is over. Only time and a quiet queue moved.
	after := f.InspectRoutes()
	if len(after) != 1 {
		t.Fatalf("expected one route, got %d", len(after))
	}
	// The lifetime history is PRESERVED. This is the point of the fix: an
	// admin still needs "this route dropped 1 packet since it was created".
	if after[0].Stats.QueueFullDrops != 1 {
		t.Fatalf("the lifetime drop count must remain visible as history, got %d",
			after[0].Stats.QueueFullDrops)
	}
	if after[0].Stats.QueueFullDropsRecent != 0 {
		t.Fatalf("a quiet window must report no recent drops, got %d",
			after[0].Stats.QueueFullDropsRecent)
	}
	if after[0].HasPressure {
		t.Errorf("a route with no new drops and an empty queue must NOT have pressure")
	}
	if problems := f.ProblemRoutes(10); len(problems) != 0 {
		t.Fatalf("a recovered route must leave the problem-routes list, got %d: %+v",
			len(problems), problems)
	}
}

// TestProblemRoutesAreNotPrimedIntoPressureByLifetimeHistory is the second
// half of the defect: a route whose counters were already nonzero when the
// process started reporting must not be treated as a fresh incident.
//
// A route created after several drops already happened has history but no
// incident. The first sample of its window is a baseline and reports zero, so
// such a route must not appear in ProblemRoutes at all.
func TestProblemRoutesAreNotPrimedIntoPressureByLifetimeHistory(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.RegisterSession("s1", "c1", "peer-old", "10.100.0.3", 1)

	// Lifetime history that predates any observation, written directly the way
	// a long-lived production counter arrives: already nonzero at the first
	// snapshot this process ever takes.
	f.mu.RLock()
	f.routesByPeer["peer-old"].queueFullDrops.Store(7)
	f.mu.RUnlock()

	// First observation ever: baseline only.
	first := f.InspectRoutes()
	if len(first) != 1 {
		t.Fatalf("expected one route, got %d", len(first))
	}
	if first[0].Stats.QueueFullDropsRecent != 0 {
		t.Fatalf("the first sample must be a baseline, got %d recent drops",
			first[0].Stats.QueueFullDropsRecent)
	}
	if first[0].HasPressure {
		t.Error("lifetime history alone must not be reported as current pressure")
	}
	if problems := f.ProblemRoutes(10); len(problems) != 0 {
		t.Fatalf("a route with only lifetime history must not be a problem route, got %d: %+v",
			len(problems), problems)
	}

	// A later window with no new drops is still quiet.
	time.Sleep(routePressureWindowAdvance())
	second := f.InspectRoutes()
	if second[0].Stats.QueueFullDrops != 7 {
		t.Fatalf("lifetime history must stay visible, got %d", second[0].Stats.QueueFullDrops)
	}
	if second[0].Stats.QueueFullDropsRecent != 0 || second[0].HasPressure {
		t.Fatalf("a quiet route must stay quiet: recent=%d pressure=%v",
			second[0].Stats.QueueFullDropsRecent, second[0].HasPressure)
	}
}

// TestProblemRoutesKeepPressureWithinOneSamplingWindow pins the reason the
// window has a 200ms floor: one diagnostics collection reads each route's
// stats more than once, so the first read must not CONSUME the delta and leave
// the second read reporting zero. Both reads of one collection must agree, or
// the problem-routes pass silently hides the incident the collection exists to
// surface.
func TestProblemRoutesKeepPressureWithinOneSamplingWindow(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.RegisterSession("s1", "c1", "peer-burst", "10.100.0.3", 1)
	f.InspectRoutes() // prime
	time.Sleep(routePressureWindowAdvance())

	queue, _ := f.GetClientPacketChannel("peer-burst")
	for i := 0; i < cap(queue); i++ {
		if err := f.RouteBackendToClient(1, returnPacketFor("10.100.0.3"), "10.100.0.3"); err != nil {
			t.Fatalf("priming enqueue %d: %v", i, err)
		}
	}
	if err := f.RouteBackendToClient(1, returnPacketFor("10.100.0.3"), "10.100.0.3"); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("expected the full queue to drop, got %v", err)
	}
	for len(queue) > 0 {
		<-queue
	}

	// Three back-to-back reads, exactly as one status collection performs them
	// (routing invariants, then problem routes, then the route-queue map).
	time.Sleep(routePressureWindowAdvance())
	var reads []RouteInfo
	for i := 0; i < 3; i++ {
		reads = append(reads, f.InspectRoutes()...)
	}
	for i, r := range reads {
		if r.Stats.QueueFullDropsRecent == 0 {
			t.Errorf("read %d inside one collection lost the delta", i)
		}
		if !r.HasPressure {
			t.Errorf("read %d inside one collection lost the pressure flag", i)
		}
	}
}

// TestRoutePressureWindowLifecycle unit-tests the window itself, including the
// counter-DECREASED case a route generation replacement produces.
func TestRoutePressureWindowLifecycle(t *testing.T) {
	base := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	var w routePressureWindow

	// First sample primes and reports zero.
	if got := w.sample(base, 5, 3, 2); got != (pressureSnapshot{}) {
		t.Fatalf("the first sample must prime and report zero, got %+v", got)
	}
	// Inside the floor the previous delta is returned unchanged.
	if got := w.sample(base.Add(routePressureSampleInterval/10), 9, 9, 9); got != (pressureSnapshot{}) {
		t.Fatalf("a sample inside the floor must return the previous delta, got %+v", got)
	}
	// Past the floor, the increase is reported.
	got := w.sample(base.Add(routePressureSampleInterval*2), 9, 3, 2)
	if got.QueueFullDropsRecent != 4 || got.WriteErrorsRecent != 0 || got.WriteStallsRecent != 0 {
		t.Fatalf("expected a 4 drop delta and no other, got %+v", got)
	}
	// A counter that decreased contributes no new loss this window.
	got = w.sample(base.Add(routePressureSampleInterval*3), 1, 3, 0)
	if got.QueueFullDropsRecent != 0 || got.WriteStallsRecent != 0 {
		t.Fatalf("a decreased counter must contribute zero, got %+v", got)
	}
	// And the window keeps tracking afterwards.
	got = w.sample(base.Add(routePressureSampleInterval*4), 3, 3, 0)
	if got.QueueFullDropsRecent != 2 {
		t.Fatalf("expected 2 recent drops, got %d", got.QueueFullDropsRecent)
	}
}

// TestProblemRoutesStillReportsRecentWriteErrorsAndStalls proves the pressure
// decision did not simply narrow to drops. Write errors and stalls are the
// other two lifetime counters the defect covered, and both must still drive
// pressure through the same recency window.
func TestProblemRoutesStillReportsRecentWriteErrorsAndStalls(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 10, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits: %v", err)
	}
	f.RegisterSession("s1", "c1", "peer-writes", "10.100.0.3", 1)
	f.InspectRoutes() // prime
	time.Sleep(routePressureWindowAdvance())

	f.writeMetricsMu.Lock()
	route := f.routesByPeer["peer-writes"]
	route.writeMetrics.Errors++
	route.writeMetrics.Stalls++
	f.writeMetricsMu.Unlock()

	time.Sleep(routePressureWindowAdvance())
	stats, ok := f.RouteQueueStats("peer-writes")
	if !ok {
		t.Fatal("route missing")
	}
	if stats.WriteErrorsRecent != 1 || stats.WriteStallsRecent != 1 {
		t.Fatalf("expected 1 recent error and 1 recent stall, got %+v", stats)
	}
	problems := f.ProblemRoutes(10)
	if len(problems) != 1 || !problems[0].HasPressure {
		t.Fatalf("recent write errors and stalls must drive pressure, got %+v", problems)
	}

	// Lifetime values stay on the payload as history.
	if stats.WriteErrors != 1 || stats.WriteStalls != 1 {
		t.Fatalf("lifetime write telemetry must remain visible, got %+v", stats)
	}

	// Quiet window: they stop driving pressure, history intact.
	time.Sleep(routePressureWindowAdvance())
	after := f.ProblemRoutes(10)
	if len(after) != 0 {
		t.Fatalf("a quiet window must clear pressure, got %+v", after)
	}
	final, _ := f.RouteQueueStats("peer-writes")
	if final.WriteErrors != 1 || final.WriteStalls != 1 {
		t.Fatalf("lifetime write telemetry must survive, got %+v", final)
	}
}
