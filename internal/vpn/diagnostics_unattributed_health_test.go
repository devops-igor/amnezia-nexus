package vpn

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// The R5-refinement acceptance tests: backend-device loss that is ACTIVE but
// ATTRIBUTIONLESS (a device with no backendDeviceStatsProvider, published
// under the direction-neutral backend_device_unattributed key) must surface as
// its own DEGRADED health condition instead of being folded into the generic
// routine-loss aggregate, which the review called not actionable.
//
// Firing exclusions are pinned by reason, not by accident: a device WITH
// detailed attribution publishes a measured zero for the directionless key
// (the condition stays off), and quiet devices publish a zero rate (likewise
// off). An unmeasured window fabricates no incident, matching the
// RatesAvailable gate every other reason-keyed condition uses.

// unattributedDrops is the one-situation fixture: active unattributed loss on
// an attribution-less device, measured in the current window. The total rate
// equals the unattributed rate so nothing else is active in the window.
func unattributedDrops(rate float64) DropCategoryBreakdown {
	return DropCategoryBreakdown{
		TotalDropRatePps: rate,
		RatesAvailable:   true,
		ReasonRates:      map[string]float64{reasonBackendDeviceUnattributed: rate},
	}
}

// TestBackendDeviceUnattributedHealthConditionFiresDegraded is the positive
// case: the condition exists, is DEGRADED (not CRITICAL — attribution missing
// is an observability gap, not a dataplane failure mode of its own), carries
// the canonical translation key, and its message is the review's actionable
// wording rather than the routine aggregate's.
func TestBackendDeviceUnattributedHealthConditionFiresDegraded(t *testing.T) {
	th := DefaultHealthThresholds
	const rate = 2.5
	if rate <= th.BackendDeviceUnattributedActiveDropRatePPS {
		t.Fatalf("test does not exercise the threshold: %v <= %v",
			rate, th.BackendDeviceUnattributedActiveDropRatePPS)
	}

	conds := evaluateVirtualTUNAndDropConditions(
		quietVirtualTUN(), unattributedDrops(rate), RoutingConsistencyDiagnostics{IsConsistent: true}, 0)
	if got := conditionsIn(conds, "drops"); len(got) != 1 {
		t.Fatalf("unattributed active loss must produce exactly one drops condition, got %+v", conds)
	} else {
		cond := got[0]
		if cond.Severity != "DEGRADED" {
			t.Errorf("severity=%q, want DEGRADED: attribution unavailable is not a CRITICAL failure mode", cond.Severity)
		}
		if cond.MessageKey != vpnDiagConditionBackendDeviceUnattributed {
			t.Errorf("message_key=%q, want %q so every locale can translate it", cond.MessageKey, vpnDiagConditionBackendDeviceUnattributed)
		}
		if !strings.Contains(cond.Message, "attribution is unavailable") {
			t.Errorf("message must be the review's actionable wording, got %q", cond.Message)
		}
	}

	// Boundary: the comparison is STRICT >. A zero measured rate must not fire
	// and an arbitrarily small positive one must, which pins the operator; the
	// threshold's value of 0 is pinned by
	// TestDefaultHealthThresholdsPreservePreviousLiterals.
	for _, tc := range []struct {
		name string
		rate float64
		want bool
	}{
		{"a zero measured rate does not fire", 0, false},
		{"an arbitrarily small positive rate does fire", math.SmallestNonzeroFloat64, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := conditionsIn(evaluateVirtualTUNAndDropConditions(
				quietVirtualTUN(), unattributedDrops(tc.rate), RoutingConsistencyDiagnostics{IsConsistent: true}, 0), "drops")
			if tc.want && (len(got) != 1 || got[0].Severity != "DEGRADED") {
				t.Fatalf("rate=%v: want exactly one DEGRADED condition, got %+v", tc.rate, got)
			}
			if !tc.want && len(got) != 0 {
				t.Fatalf("rate=%v: want no drops condition, got %+v", tc.rate, got)
			}
		})
	}
}

// TestBackendDeviceUnattributedHealthConditionAbsentWithDetailedProvider pins
// the first firing exclusion: when the device HAS a detailed per-direction
// stats provider, its loss is published under device-specific reason keys and
// the directionless key carries a measured zero — the condition must stay off
// even though the window is measured and other loss is present.
//
// This is the service-level path: realDropCategories drives the production
// loader (snapshotBackendDeviceDrops reads the axes a realVtunBackendDevice
// reports), so the test breaks if attribution ever starts landing under the
// directionless key.
func TestBackendDeviceUnattributedHealthConditionAbsentWithDetailedProvider(t *testing.T) {
	svc, dev := deviceStatsForService(t)
	if err := dev.vtun.InjectInbound([]byte("in-1")); err != nil {
		t.Fatalf("first inbound packet must be accepted: %v", err)
	}
	if err := dev.vtun.InjectInbound([]byte("in-2")); err == nil {
		t.Fatal("saturated inbound queue must refuse the packet")
	}

	at := time.Now()
	drops := svc.collectDropCategories()
	if got := drops.ClientBackendDeviceQueueFull; got != 1 {
		t.Fatalf("fixture lost attribution: client_backend_device_queue_full=%d, want 1", got)
	}
	if got := drops.BackendDeviceUnattributed; got != 0 {
		t.Fatalf("a detailed provider must never publish the directionless key: %d", got)
	}
	svc.sampleDropRates(0, at, &drops, 0)

	conds := evaluateVirtualTUNAndDropConditions(
		quietVirtualTUN(), drops, RoutingConsistencyDiagnostics{IsConsistent: true}, 0)
	for _, cond := range conds {
		if cond.Category == "drops" && cond.MessageKey == vpnDiagConditionBackendDeviceUnattributed {
			t.Fatalf("condition fired although attribution IS available: %+v", conds)
		}
	}
}

// TestBackendDeviceUnattributedHealthConditionAbsentAtZeroDrops pins the
// second firing exclusion: a measured window with NO device loss anywhere
// produces no condition at all.
func TestBackendDeviceUnattributedHealthConditionAbsentAtZeroDrops(t *testing.T) {
	drops := DropCategoryBreakdown{
		TotalDropRatePps: 0,
		RatesAvailable:   true,
		ReasonRates:      map[string]float64{reasonBackendDeviceUnattributed: 0},
	}
	if got := conditionsIn(evaluateVirtualTUNAndDropConditions(
		quietVirtualTUN(), drops, RoutingConsistencyDiagnostics{IsConsistent: true}, 0), "drops"); len(got) != 0 {
		t.Fatalf("zero drops must not produce a condition: %+v", got)
	}
}

// TestBackendDeviceUnattributedHealthConditionAbsentWhenRatesUnmeasured pins
// the RatesAvailable gate: an unmeasured window is unknown, not an incident,
// even if a stale reason rate is present in the breakdown.
func TestBackendDeviceUnattributedHealthConditionAbsentWhenRatesUnmeasured(t *testing.T) {
	drops := DropCategoryBreakdown{
		TotalDropRatePps: 0,
		RatesAvailable:   false,
		ReasonRates:      map[string]float64{reasonBackendDeviceUnattributed: 99.0},
	}
	if got := conditionsIn(evaluateVirtualTUNAndDropConditions(
		quietVirtualTUN(), drops, RoutingConsistencyDiagnostics{IsConsistent: true}, 0), "drops"); len(got) != 0 {
		t.Fatalf("unmeasured reason rates must not produce a condition: %+v", got)
	}
}

// TestBackendDeviceUnattributedHealthConditionEndToEnd walks the full
// production path: attribution-less device -> loader publishes the
// direction-neutral backend_device_unattributed key -> sampled rates ->
// health evaluation -> serialized status payload. The MessageKey must survive
// serialization so the web renderer can translate it.
//
// The forwarder startup copies TestDiagnosticsDisjointMixedLossProductionPaths
// (diagnostics_expanded_test.go): a live forwarder attached to the
// setupTestVPNService service, so populateOperationalDiagnostics reads the
// production sampler inputs instead of an empty shell. The running-dataplane
// flags ride the status the way every sibling Service test delivers them
// (TestReturnQueueLossHasOneCurrentHealthExplanation): GetStatus derives them
// from a running ingress engine, whose lifecycle is out of scope here — the
// firing exclusions cover the evaluator directly.
func TestBackendDeviceUnattributedHealthConditionEndToEnd(t *testing.T) {
	svc, _, _, _, _ := setupTestVPNService(t, setupTestDB(t))
	svc.forwarder = forwarder.NewForwarder(nil, "")
	opaque := &noStatsDevice{}
	opaque.dropped.Add(9)
	svc.backendDevices = map[int64]BackendDevice{1: opaque}

	at := time.Now()
	status := Status{ForwarderAvailable: true, EngineRunning: true}
	// GetStatus orchestrates flags first, diagnostics second (vpn.go: engine
	// running => EngineRunning/ForwarderAvailable, then
	// populateOperationalDiagnosticsFromInputs evaluates health on them). The
	// fixture models the same running-dataplane scenario: an attribution-less
	// device attached to an active forwarder. The engine lifecycle itself is
	// out of scope here — the firing exclusions cover the evaluator directly.
	// The status instance is REUSED for both polls so the running-dataplane
	// flags survive into the second populate; a fresh Status{} would fall back
	// through EvaluateForwarderHealth's engine gate and the condition under
	// test would never be reached.
	svc.populateOperationalDiagnostics(&status)
	// A single instantaneous observation cannot produce a rate window: prime
	// the per-reason baselines, then resample one floor later so the window
	// is measured (the same production sampler every diagnostics read uses).
	if rate := svc.sampleDropRates(0, at, &status.DropCategories, 0); rate != 0 || status.DropCategories.RatesAvailable {
		t.Fatalf("priming sample must publish no window: rate=%v available=%v", rate, status.DropCategories.RatesAvailable)
	}
	// The device loses MORE packets, and the next real production poll happens
	// well after the sample floor: the growth between the two real polls is
	// the measured positive rate, and populateOperationalDiagnostics evaluates
	// health on exactly that window. (A synthetic second timestamp of
	// at+floor cannot work here: the tracker's anchor is populate's internal
	// clock reading, which is strictly later than at, so at+floor still sits
	// inside the 200ms floor and no window — and no positive rate — can ever
	// open for a counter that does not grow.)
	opaque.dropped.Add(5)
	time.Sleep(3 * diagEpochSampleFloor)
	svc.populateOperationalDiagnostics(&status)
	if !status.DropCategories.RatesAvailable {
		t.Fatal("fixture must produce a measured rate window")
	}
	if got := status.DropCategories.ReasonRates[reasonBackendDeviceUnattributed]; got <= 0 {
		t.Fatalf("fixture must produce a positive unattributed rate, got %v", got)
	}

	var found *HealthCondition
	for i := range status.HealthAssessment.Conditions {
		cond := status.HealthAssessment.Conditions[i]
		if cond.Category == "drops" && cond.MessageKey == vpnDiagConditionBackendDeviceUnattributed {
			found = &status.HealthAssessment.Conditions[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("end-to-end status must carry the unattributed condition: %+v", status.HealthAssessment.Conditions)
	}
	if found.Severity != "DEGRADED" {
		t.Errorf("end-to-end severity=%q, want DEGRADED", found.Severity)
	}
	encoded, err := json.Marshal(status.HealthAssessment)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"message_key":"`+vpnDiagConditionBackendDeviceUnattributed+`"`) {
		t.Errorf("message_key must survive serialization for the web renderer: %s", encoded)
	}
}
