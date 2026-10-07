package vpn

import (
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
)

// Round-5 finding 4: the health thresholds that MEASURE queue pressure are
// canonical values in the leaf package internal/vpn/forwarder/thresholds,
// which both internal/vpn (the health evaluation) and internal/vpn/forwarder
// (the measurement) import. It has no dependency on either, which breaks the cycle.

// TestCanonicalQueueThresholdsAreNumericallyIdentical is the numeric-identity
// regression. Every canonical value must still be exactly the expected level.
func TestCanonicalQueueThresholdsAreNumericallyIdentical(t *testing.T) {
	if got := thresholds.QueueDwellWarningUtilization(); got != 0.5 {
		t.Errorf("canonical dwell warning level=%v, want 0.5 (was the literal 0.5 in queue_dwell.go)", got)
	}
	if got := thresholds.QueueDwellDegradedUtilization(); got != 0.8 {
		t.Errorf("canonical dwell degraded level=%v, want 0.8 (was the literal 0.8 in queue_dwell.go)", got)
	}
	if got := thresholds.RoutePressureUtilization(); got != 0.8 {
		t.Errorf("canonical route pressure level=%v, want 0.8 (was the literal 0.8 in routes.go)", got)
	}

	// The health set must still carry the same numbers it always did.
	th := DefaultHealthThresholds
	if th.QueueWarningSustainedAbovePct != 50.0 {
		t.Errorf("QueueWarningSustainedAbovePct=%v, want 50.0", th.QueueWarningSustainedAbovePct)
	}
	if th.QueueDegradedAbovePct != 80.0 {
		t.Errorf("QueueDegradedAbovePct=%v, want 80.0", th.QueueDegradedAbovePct)
	}
	if th.ProblemRoutePressureRatio != 0.8 {
		t.Errorf("ProblemRoutePressureRatio=%v, want 0.8", th.ProblemRoutePressureRatio)
	}
}

// TestHealthThresholdsDeriveFromCanonicalSource pins the DERIVATION, not just
// the numbers: each measurement-linked field must equal the canonical value
// rather than a transcribed copy of it.
func TestHealthThresholdsDeriveFromCanonicalSource(t *testing.T) {
	th := DefaultHealthThresholds
	if want := thresholds.QueueDwellWarningPct(); th.QueueWarningSustainedAbovePct != want {
		t.Errorf("QueueWarningSustainedAbovePct=%v, want the canonical %v", th.QueueWarningSustainedAbovePct, want)
	}
	if want := thresholds.QueueDwellDegradedPct(); th.QueueDegradedAbovePct != want {
		t.Errorf("QueueDegradedAbovePct=%v, want the canonical %v", th.QueueDegradedAbovePct, want)
	}
	if want := thresholds.RoutePressureUtilization(); th.ProblemRoutePressureRatio != want {
		t.Errorf("ProblemRoutePressureRatio=%v, want the canonical %v", th.ProblemRoutePressureRatio, want)
	}
}

// TestQueueConditionsReportCanonicalDwellThreshold verifies that the evaluator's
// sustained dwell messages report the canonical threshold (80%).
func TestQueueConditionsReportCanonicalDwellThreshold(t *testing.T) {
	th := defaultHealthThresholds()
	if th.QueueDegradedAbovePct != 80.0 {
		t.Fatalf("derived QueueDegradedAbovePct=%v, want 80.0", th.QueueDegradedAbovePct)
	}

	// The message an operator reads must state the canonical level 80%.
	q := quietQueue()
	q.UtilizationPct = 10 // below the warning level, so only the dwell branch can fire
	q.ConsecutiveAbove80Sec = th.QueueDegradedSustainedSeconds
	conds := evaluateQueueConditions(q)
	var degraded string
	for _, c := range conds {
		if c.Severity == "DEGRADED" {
			degraded = c.Message
		}
	}
	if degraded == "" {
		t.Fatalf("no DEGRADED condition at the sustained dwell boundary: %+v", conds)
	}
	if !strings.Contains(degraded, "80%") {
		t.Errorf("message %q does not report canonical threshold 80%%", degraded)
	}
}

// TestProblemRouteNoteTracksCanonicalPressureRatio covers the third
// measurement-linked field, whose threshold decides whether a problem route
// gets the "Queue pressure" note.
func TestProblemRouteNoteTracksCanonicalPressureRatio(t *testing.T) {
	const capacity = 100
	routeBelow := forwarder.RouteInfo{
		PeerKey:     "pressure-peer-below",
		HasPressure: true,
		Stats:       forwarder.RouteQueueStats{Capacity: capacity, Occupancy: 79},
	}
	// At the canonical 0.8 a 79%-full queue is BELOW the ratio: no note
	items := collectProblemRoutes([]forwarder.RouteInfo{routeBelow})
	if len(items) != 1 {
		t.Fatalf("collectProblemRoutes returned %d items, want 1", len(items))
	}
	if note := items[0].PressureNote; note != "" {
		t.Fatalf("79%% occupancy produced pressure note %q at ratio 0.8: want empty note", note)
	}

	// At 80% occupancy, exactly at the canonical ratio: note is present (comparison is >=)
	routeAtBoundary := forwarder.RouteInfo{
		PeerKey:     "pressure-peer-at",
		HasPressure: true,
		Stats:       forwarder.RouteQueueStats{Capacity: capacity, Occupancy: 80},
	}
	items = collectProblemRoutes([]forwarder.RouteInfo{routeAtBoundary})
	if len(items) != 1 || items[0].PressureNote == "" {
		t.Errorf("80%% occupancy produced no pressure note at canonical ratio 0.8: the boundary is >=, not >")
	}
}
