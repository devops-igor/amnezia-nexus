package forwarder

import (
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
)

// Round-5 finding 4, measurement side.
//
// The queue observer used to compare utilization against the literals 0.5 and
// 0.8 written into queue_dwell.go, while the health evaluator in internal/vpn
// reported whatever HealthThresholds said. Those were two sources of truth for
// one boundary: raising the configured level to 85 would have changed the
// operator-facing message and left the measurement at 80.
//
// These regressions make the measurement read the canonical source, so the
// health message and the number it describes cannot disagree.

// dwellBoundaries drives a queueDwellTracker over a fixed capacity and returns
// the occupancy at which each of its two booleans first becomes true.
func dwellBoundaries(t *testing.T, capacity int) (warningAt, degradedAt int) {
	t.Helper()
	for occ := 0; occ <= capacity; occ++ {
		var d queueDwellTracker
		// Two observations: the first establishes the baseline instant, the
		// second classifies the transition into occ.
		d.observe(time.Unix(0, 0), 0, capacity)
		d.observe(time.Unix(1, 0), occ, capacity)
		if d.above50 && warningAt == 0 {
			warningAt = occ
		}
		if d.above80 && degradedAt == 0 {
			degradedAt = occ
		}
	}
	return warningAt, degradedAt
}

// TestDwellMeasurementUsesCanonicalThresholds is the numeric-identity
// regression on the measurement side: the dwell boundaries must still be at
// exactly 50% and 80%, which is what the literals were.
func TestDwellMeasurementUsesCanonicalThresholds(t *testing.T) {
	const capacity = 1000
	warningAt, degradedAt := dwellBoundaries(t, capacity)

	if want := int(thresholds.QueueDwellWarningUtilization() * capacity); warningAt != want {
		t.Errorf("sustained-warning boundary at %d/%d, want %d (the canonical %v)",
			warningAt, capacity, want, thresholds.QueueDwellWarningUtilization())
	}
	if want := int(thresholds.QueueDwellDegradedUtilization() * capacity); degradedAt != want {
		t.Errorf("sustained-degraded boundary at %d/%d, want %d (the canonical %v)",
			degradedAt, capacity, want, thresholds.QueueDwellDegradedUtilization())
	}
	if warningAt != 500 || degradedAt != 800 {
		t.Errorf("dwell boundaries moved from the literals 0.5/0.8: warning=%d degraded=%d, want 500/800", warningAt, degradedAt)
	}
}

// TestPerturbingCanonicalLevelMovesTheDwellMeasurement is the measurement half
// of the reviewer's "perturb it and watch both move" test: moving the canonical
// level must move where the observer classifies the queue.
//
// Against the pre-fix tree this fails, because the observer compared against a
// literal that no configuration could reach.
func TestPerturbingCanonicalLevelMovesTheDwellMeasurement(t *testing.T) {
	const capacity = 1000

	original := thresholds.QueueDwellDegradedUtilization()
	t.Cleanup(func() { thresholds.SetQueueDwellDegradedUtilization(original) })

	// Lower the canonical degraded level to 0.6: a 65%-full queue must now be
	// classified as "above the degraded level".
	thresholds.SetQueueDwellDegradedUtilization(0.6)
	_, degradedAt := dwellBoundaries(t, capacity)
	if want := int(0.6 * capacity); degradedAt != want {
		t.Errorf("after lowering the canonical level to 0.6 the dwell boundary is %d/%d, want %d: "+
			"the observer is not reading the canonical source", degradedAt, capacity, want)
	}

	// Raise it to 0.9: the same 65%-full queue must no longer qualify.
	thresholds.SetQueueDwellDegradedUtilization(0.9)
	_, degradedAt = dwellBoundaries(t, capacity)
	if want := int(0.9 * capacity); degradedAt != want {
		t.Errorf("after raising the canonical level to 0.9 the dwell boundary is %d/%d, want %d: "+
			"the observer is not reading the canonical source", degradedAt, capacity, want)
	}
}

// TestRateTrackerPressureUsesCanonicalThresholds covers the SECOND place the
// same two levels were hardcoded: the sampled/interpolated rate tracker credits
// seconds above 0.50 and 0.80 while estimating pressure between readings.
func TestRateTrackerPressureUsesCanonicalThresholds(t *testing.T) {
	rt := NewRateTracker()
	rt.Sample(time.Unix(0, 0), 0, 0, 0, 0, 0, 0, 0, 1000)

	// Sample one second later with the queue at 70% — above the canonical 0.5
	// but below the canonical 0.8.
	rt.Sample(time.Unix(1, 0), 0, 0, 0, 0, 0, 0, 700, 1000)
	// And again one second after that, still at 70%.
	//
	// The tracker interpolates utilization LINEARLY between accepted
	// readings, so a single jump from 0% to 70% credits only the fraction of
	// the interval spent above the level (0.286 s of the 1 s interval), which
	// the published whole-second field rounds to 0. Holding the queue AT 70%
	// for a second makes the reading unambiguous: the steady interval is
	// wholly above the canonical warning level, so the requirement below is
	// pinned without depending on sub-second truncation.
	rt.Sample(time.Unix(2, 0), 0, 0, 0, 0, 0, 0, 700, 1000)
	stats := rt.PressureSnapshot(700, 1000, 700, 0)

	if stats.SecondsAbove50Pct <= 0 {
		t.Errorf("a queue at 70%% credited 0 seconds above the canonical warning level %v: %+v",
			thresholds.QueueDwellWarningUtilization(), stats)
	}
	if stats.SecondsAbove80Pct != 0 {
		t.Errorf("a queue at 70%% credited %d seconds above the canonical degraded level %v: %+v",
			stats.SecondsAbove80Pct, thresholds.QueueDwellDegradedUtilization(), stats)
	}

	// Now lower the canonical degraded level to 0.6 and repeat: the same 70%
	// reading must credit seconds above it.
	original := thresholds.QueueDwellDegradedUtilization()
	t.Cleanup(func() { thresholds.SetQueueDwellDegradedUtilization(original) })
	thresholds.SetQueueDwellDegradedUtilization(0.6)

	rt2 := NewRateTracker()
	rt2.Sample(time.Unix(0, 0), 0, 0, 0, 0, 0, 0, 0, 1000)
	rt2.Sample(time.Unix(1, 0), 0, 0, 0, 0, 0, 0, 700, 1000)
	rt2.Sample(time.Unix(2, 0), 0, 0, 0, 0, 0, 0, 700, 1000)
	stats2 := rt2.PressureSnapshot(700, 1000, 700, 0)
	if stats2.SecondsAbove80Pct <= 0 {
		t.Errorf("after lowering the canonical degraded level to 0.6 a 70%% reading credited 0 seconds above it: %+v", stats2)
	}
}

// TestRoutePressureUsesCanonicalThreshold covers the third measurement site:
// the per-route HasPressure classification, which had its own literal 0.8.
func TestRoutePressureUsesCanonicalThreshold(t *testing.T) {
	const capacity = 100
	routeAt := func(occupancy int) forwarderRoutePressure {
		f := newRoutePressureFixture(t)
		return f.pressureFor(occupancy, capacity)
	}

	// 79% is below the canonical 0.8.
	if routeAt(79).HasPressure {
		t.Errorf("79%% occupancy classified as pressure at the canonical ratio %v", thresholds.RoutePressureUtilization())
	}
	// 80% is exactly at it, and the comparison is >=.
	if !routeAt(80).HasPressure {
		t.Errorf("80%% occupancy NOT classified as pressure at the canonical ratio %v: the boundary is >=",
			thresholds.RoutePressureUtilization())
	}

	original := thresholds.RoutePressureUtilization()
	t.Cleanup(func() { thresholds.SetRoutePressureUtilization(original) })

	// Lower the canonical ratio to 0.75: 79% must now qualify.
	thresholds.SetRoutePressureUtilization(0.75)
	if !routeAt(79).HasPressure {
		t.Errorf("79%% occupancy not classified as pressure after lowering the canonical ratio to 0.75: " +
			"the route classifier is not reading the canonical source")
	}
	// Raise it to 0.85: 80% must no longer qualify.
	thresholds.SetRoutePressureUtilization(0.85)
	if routeAt(80).HasPressure {
		t.Errorf("80%% occupancy still classified as pressure after raising the canonical ratio to 0.85: " +
			"the route classifier is not reading the canonical source")
	}
}

// forwarderRoutePressure is the pressure classification InspectRoutes
// publishes for one registered route. It is the observation the regression
// below makes, so the test reads the SAME production classifier rather than
// re-implementing the comparison it is checking.
type forwarderRoutePressure struct {
	HasPressure bool
	Utilization float64
}

// routePressureFixture drives a REAL Forwarder with one registered route, so
// the classification comes from the production code path (InspectRoutes ->
// routeUtilization -> the canonical ratio) and not from a stand-in.
type routePressureFixture struct {
	t          *testing.T
	assignedIP string
}

// newRoutePressureFixture registers a single session route on a fresh
// forwarder. The route's queue capacity is chosen per pressureFor call, since
// InspectRoutes reports cap(clientQueue) as the capacity.
func newRoutePressureFixture(t *testing.T) *routePressureFixture {
	t.Helper()
	return &routePressureFixture{t: t, assignedIP: "10.100.0.11"}
}

// pressureFor fills a route's client queue to occupancy out of capacity and
// returns the pressure classification production publishes for it.
//
// It uses a fresh forwarder per call so one fill cannot leak into the next,
// and it never drains the queue, so the occupancy InspectRoutes reads is the
// one this call created.
func (fx *routePressureFixture) pressureFor(occupancy, capacity int) forwarderRoutePressure {
	fx.t.Helper()
	if occupancy < 0 || capacity <= 0 || occupancy > capacity {
		fx.t.Fatalf("pressureFor(%d, %d) is not a realizable occupancy/capacity pair", occupancy, capacity)
	}

	f := NewForwarder(nil, "10.100.0.0/16", capacity)
	peerKey := "pressure-peer"
	f.RegisterSession("pressure-session", "pressure-connection", peerKey, fx.assignedIP, 1)

	// No backend device is attached: the queue is filled by the production
	// enqueue path and nothing consumes it, so occupancy is exact.
	for i := 0; i < occupancy; i++ {
		if err := f.RouteBackendToClient(1, []byte("pkt"), fx.assignedIP); err != nil {
			fx.t.Fatalf("enqueue %d/%d failed: %v", i+1, occupancy, err)
		}
	}

	routes := f.InspectRoutes()
	if len(routes) != 1 {
		fx.t.Fatalf("InspectRoutes returned %d routes, want 1", len(routes))
	}
	stats := routes[0].Stats
	if stats.Capacity != capacity {
		fx.t.Fatalf("route capacity=%d, want %d: the fixture is not measuring the pair it asked for",
			stats.Capacity, capacity)
	}
	if stats.Occupancy != occupancy {
		fx.t.Fatalf("route occupancy=%d, want %d: the queue was not filled to the requested depth",
			stats.Occupancy, occupancy)
	}
	return forwarderRoutePressure{HasPressure: routes[0].HasPressure, Utilization: routeUtilization(stats)}
}
