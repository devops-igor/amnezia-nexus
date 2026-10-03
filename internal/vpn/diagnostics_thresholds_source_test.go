package vpn

import (
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
)

// Round-5 finding 4: the health thresholds that MEASURE queue pressure were
// declared in HealthThresholds but hardcoded a second time in the forwarder.
//
// internal/vpn/forwarder/queue_dwell.go compared util against literal 0.5 and
// 0.8 to produce ConsecutiveAbove50Sec / ConsecutiveAbove80Sec, and
// internal/vpn/forwarder/routes.go compared against a literal 0.8 for route
// pressure. Changing DefaultHealthThresholds.QueueDegradedAbovePct to 85 would
// have changed only the human-readable message while the measurement kept
// running against 80: the configuration would have silently lied.
//
// The canonical values live in the leaf package
// internal/vpn/forwarder/thresholds, which both internal/vpn (the health
// evaluation) and internal/vpn/forwarder (the measurement) import. It has no
// dependency on either, which is what breaks the cycle: internal/vpn already
// imports internal/vpn/forwarder, so the shared values cannot live in
// internal/vpn itself.

// TestCanonicalQueueThresholdsAreNumericallyIdentical is the numeric-identity
// regression. This change is a DE-DUPLICATION, not a retuning: every canonical
// value must still be exactly the literal it replaced.
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

// TestPerturbingCanonicalValueMovesTheReportedMessage is the reviewer's
// "perturb it and watch both move" test, on the health-evaluation side.
//
// The health set is DERIVED from the canonical source by
// defaultHealthThresholds. Perturbing the canonical value must therefore
// change the threshold the evaluator reports, which is exactly what a
// hardcoded copy in the measurement path could never do.
func TestPerturbingCanonicalValueMovesTheReportedMessage(t *testing.T) {
	original := thresholds.QueueDwellDegradedUtilization()
	t.Cleanup(func() { thresholds.SetQueueDwellDegradedUtilization(original) })
	thresholds.SetQueueDwellDegradedUtilization(0.85)

	th := defaultHealthThresholds()
	if th.QueueDegradedAbovePct != 85.0 {
		t.Fatalf("derived QueueDegradedAbovePct=%v, want the perturbed 85.0", th.QueueDegradedAbovePct)
	}
	if th.QueueWarningSustainedAbovePct != thresholds.QueueDwellWarningPct() {
		t.Errorf("perturbing the degraded level moved the unrelated warning level to %v", th.QueueWarningSustainedAbovePct)
	}

	// The message an operator reads must state the perturbed level, not 80.
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
	if !strings.Contains(degraded, "85%") {
		t.Errorf("message %q does not report the perturbed canonical threshold 85%%", degraded)
	}
	if strings.Contains(degraded, "80%") {
		t.Errorf("message %q still reports the hardcoded 80%%: the message is not derived from the canonical value", degraded)
	}
}

// TestProblemRouteNoteTracksCanonicalPressureRatio covers the third
// measurement-linked field, whose threshold decides whether a problem route
// gets the "Queue pressure" note.
func TestProblemRouteNoteTracksCanonicalPressureRatio(t *testing.T) {
	original := thresholds.RoutePressureUtilization()
	t.Cleanup(func() { thresholds.SetRoutePressureUtilization(original) })

	const capacity = 100
	// The route is at 79%: just BELOW the production ratio, and just above a
	// lowered 0.75. That single occupancy is what makes the perturbation
	// observable in both directions.
	route := forwarder.RouteInfo{
		PeerKey:     "pressure-peer",
		HasPressure: true,
		Stats:       forwarder.RouteQueueStats{Capacity: capacity, Occupancy: 79},
	}
	// noteAt perturbs the CANONICAL ratio and reads the note production
	// publishes. It must move the canonical source rather than build a local
	// HealthThresholds copy: collectProblemRoutes does not take a threshold
	// argument, and a discarded copy would leave the note reading a value no
	// configuration can reach.
	noteAt := func(ratio float64) string {
		thresholds.SetRoutePressureUtilization(ratio)
		t.Cleanup(func() { thresholds.SetRoutePressureUtilization(original) })
		items := collectProblemRoutes([]forwarder.RouteInfo{route})
		if len(items) != 1 {
			t.Fatalf("collectProblemRoutes returned %d items, want 1", len(items))
		}
		return items[0].PressureNote
	}

	// At the production 0.8 a 79%-full queue is BELOW the ratio, so the note
	// is correctly absent: the boundary is >-, and 0.79 < 0.8.
	if note := noteAt(original); note != "" {
		t.Fatalf("79%% occupancy produced pressure note %q at the canonical ratio %v: the boundary moved",
			note, original)
	}

	// A route at exactly the ratio is inside it: the comparison is >=, not >.
	atBoundary := route
	atBoundary.Stats.Occupancy = 80
	thresholds.SetRoutePressureUtilization(0.8)
	items := collectProblemRoutes([]forwarder.RouteInfo{atBoundary})
	if len(items) != 1 || items[0].PressureNote == "" {
		t.Errorf("80%% occupancy produced no pressure note at the canonical ratio 0.8: the boundary is >=, not >")
	}

	// Lower the canonical ratio to 0.75: the same 79% route now qualifies, and
	// the DERIVED health threshold reports the perturbed value.
	if note := noteAt(0.75); note == "" {
		t.Errorf("79%% occupancy produced no pressure note at the perturbed ratio 0.75: " +
			"the note is not reading the canonical source")
	}
	if th := defaultHealthThresholds(); th.ProblemRoutePressureRatio != 0.75 {
		t.Fatalf("derived ProblemRoutePressureRatio=%v, want the perturbed 0.75", th.ProblemRoutePressureRatio)
	}

	// Raise it to 0.85: the same route no longer qualifies.
	if note := noteAt(0.85); note != "" {
		t.Errorf("79%% occupancy produced pressure note %q at the raised ratio 0.85", note)
	}
}
