package vpn

import (
	"strings"
	"testing"
)

// Issue #424 round 8, finding 4: headline latency health must have a freshness
// semantic. Before the fix, P95MS (a never-expiring 1024-sample percentile)
// drove DEGRADED directly, so an idle server stayed DEGRADED on stale samples.
// This asserts the HEALTH DECISION recovers while the DESCRIPTIVE percentile is
// still reported to operators.
func TestEvaluateLatencyConditions_StaleDescriptiveP95DoesNotPinHealth(t *testing.T) {
	base := func() (QueuePressureDiagnostics, DropCategoryBreakdown, VirtualTUNDiagnostics) {
		queue := QueuePressureDiagnostics{Capacity: 1000, Occupancy: 5, UtilizationPct: 0.5}
		drops := DropCategoryBreakdown{}
		vtun := VirtualTUNDiagnostics{
			UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 1},
			NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 1},
		}
		return queue, drops, vtun
	}
	routing := RoutingConsistencyDiagnostics{IsConsistent: true}

	// Stale burst: descriptive p95 is high, but the health window is EMPTY
	// because nothing was written recently. This is an idle server.
	queue, drops, vtun := base()
	stale := ForwardLatencyDiagnostics{
		P50MS:      180.0,
		P95MS:      220.0,
		P99MS:      240.0,
		MaxMS:      240,
		Stalls:     20,
		WriteTotal: 5000,

		P95HealthMS:        0,
		P95HealthSamples:   0,
		P95HealthWindowSec: 60,
	}

	assessment := EvaluateForwarderHealth(true, true, queue, stale, drops, vtun, nil, routing,
		HandshakeFreshnessDiagnostics{TotalPeers: 3}, BackendsDiagnostics{HealthyCount: 1, TotalCount: 1})

	if assessment.Status == HealthDegraded || assessment.Status == HealthCritical {
		t.Fatalf("an idle server must not be held DEGRADED on stale latency samples, got %s (%s)",
			assessment.Status, assessment.Summary)
	}
	for _, c := range assessment.Conditions {
		if c.Category == "latency" && strings.Contains(c.Message, "p95") {
			t.Errorf("stale samples must not produce a latency p95 condition, got %q", c.Message)
		}
	}
	// Descriptive percentile is untouched and still available to operators.
	if stale.P95MS < 100 {
		t.Fatalf("descriptive p95 must still report history, got %v", stale.P95MS)
	}

	// Fresh slow writes in the health window still degrade. The fix must not
	// blind health to a CURRENT incident.
	fresh := stale
	fresh.P95HealthMS = 220.0
	fresh.P95HealthSamples = 40

	assessment = EvaluateForwarderHealth(true, true, queue, fresh, drops, vtun, nil, routing,
		HandshakeFreshnessDiagnostics{TotalPeers: 3}, BackendsDiagnostics{HealthyCount: 1, TotalCount: 1})
	if assessment.Status != HealthDegraded {
		t.Fatalf("fresh slow writes must still report DEGRADED, got %s (%s)", assessment.Status, assessment.Summary)
	}
	found := false
	for _, c := range assessment.Conditions {
		if c.Category == "latency" && c.Severity == "DEGRADED" && strings.Contains(c.Message, "p95") {
			found = true
			if !strings.Contains(c.Message, "over the last") {
				t.Errorf("latency message must state the window it covers, got %q", c.Message)
			}
		}
	}
	if !found {
		t.Error("fresh slow writes must produce a DEGRADED latency condition")
	}
}

// The live, non-historical signals must still gate health: an in-flight write
// blocked right now is CRITICAL regardless of how quiet the percentile window
// is, so the freshness change cannot be used to hide an active stall.
func TestEvaluateLatencyConditions_LiveStallStillGatesHealthOnIdleServer(t *testing.T) {
	queue := QueuePressureDiagnostics{Capacity: 1000, Occupancy: 5, UtilizationPct: 0.5}
	vtun := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 1},
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 1},
	}
	latency := ForwardLatencyDiagnostics{
		P95MS:              200.0,
		P95HealthMS:        0,
		P95HealthSamples:   0,
		P95HealthWindowSec: 60,
		OldestInFlightMS:   1500,
	}

	assessment := EvaluateForwarderHealth(true, true, queue, latency, DropCategoryBreakdown{}, vtun, nil,
		RoutingConsistencyDiagnostics{IsConsistent: true},
		HandshakeFreshnessDiagnostics{TotalPeers: 3}, BackendsDiagnostics{HealthyCount: 1, TotalCount: 1})

	if assessment.Status != HealthCritical {
		t.Fatalf("a write blocked for 1500ms must stay CRITICAL, got %s (%s)", assessment.Status, assessment.Summary)
	}
}

// The sustained-pressure condition reports measured queue dwell.
func TestEvaluateQueueConditions_SaturationMessageReportsMeasuredDwell(t *testing.T) {
	queue := QueuePressureDiagnostics{
		Capacity:              1000,
		Occupancy:             810,
		UtilizationPct:        81.0,
		ConsecutiveAbove80Sec: 45,
	}
	conds := evaluateQueueConditions(queue)
	if len(conds) == 0 {
		t.Fatal("45 measured seconds above 80%% must produce a condition")
	}
	if strings.Contains(conds[0].Message, "estimated") || !strings.Contains(conds[0].Message, "for 45s") {
		t.Errorf("measured dwell must be reported accurately, got %q", conds[0].Message)
	}
	if conds[0].Severity != "DEGRADED" {
		t.Errorf("expected DEGRADED, got %s", conds[0].Severity)
	}
}
