package vpn

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEvaluateForwarderHealth_States(t *testing.T) {
	// Baseline healthy inputs
	baseQueue := QueuePressureDiagnostics{
		Occupancy:             10,
		Capacity:              1000,
		UtilizationPct:        1.0,
		HighWaterPct:          5.0,
		ConsecutiveAbove50Sec: 0,
		ConsecutiveAbove80Sec: 0,
		QueueFullDrops:        0,
	}
	baseLatency := ForwardLatencyDiagnostics{
		P50MS:            1.5,
		P95MS:            5.0,
		P99MS:            8.0,
		OldestInFlightMS: 10,
		Stalls:           0,
		WriteErrors:      0,
	}
	baseDrops := DropCategoryBreakdown{
		TotalDrops:       0,
		TotalDropRatePps: 0.0,
	}
	baseVTUN := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5, Peak: 20, Drops: 0},
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 5, Peak: 20, Drops: 0},
	}
	basePeerSync := &PeerSyncStatus{
		DesiredPeers: 10,
		ActualPeers:  10,
		SyncFailures: 0,
	}
	baseRouting := RoutingConsistencyDiagnostics{
		ActiveSessionsCount: 5,
		ActiveRoutesCount:   5,
		ReturnOwnersCount:   5,
		IsConsistent:        true,
	}
	baseHandshake := HandshakeFreshnessDiagnostics{
		TotalPeers: 10,
	}
	baseBackends := BackendsDiagnostics{
		HealthyCount: 2,
		TotalCount:   2,
		LatencyP95MS: 15.0,
	}

	// 1. Healthy
	h := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if h.Status != HealthHealthy {
		t.Errorf("expected HEALTHY, got %s (summary: %s)", h.Status, h.Summary)
	}
	if h.Conditions == nil {
		t.Errorf("expected non-nil h.Conditions for healthy forwarder")
	}
	hJSON, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal(h): %v", err)
	}
	if !strings.Contains(string(hJSON), `"conditions":[]`) {
		t.Errorf("expected JSON to contain '\"conditions\":[]', got %s", string(hJSON))
	}

	// 2. Unavailable
	u := EvaluateForwarderHealth(false, false, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if u.Status != HealthUnavailable {
		t.Errorf("expected UNAVAILABLE, got %s", u.Status)
	}

	// 3. Degraded on active queue drops
	qDrops := baseQueue
	qDrops.QueueDropRatePps = 1.0
	deg := EvaluateForwarderHealth(true, true, qDrops, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if deg.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for active queue drops, got %s", deg.Status)
	}

	// 4. Critical on queue saturation >= 95%
	qSat := baseQueue
	qSat.UtilizationPct = 96.0
	crit := EvaluateForwarderHealth(true, true, qSat, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if crit.Status != HealthCritical {
		t.Errorf("expected CRITICAL for queue saturation, got %s", crit.Status)
	}

	// 5. Critical on write stall >= 1000ms
	latStall := baseLatency
	latStall.OldestInFlightMS = 1200
	critStall := EvaluateForwarderHealth(true, true, baseQueue, latStall, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if critStall.Status != HealthCritical {
		t.Errorf("expected CRITICAL for write stall, got %s", critStall.Status)
	}

	// 6. Critical on 0 healthy backends
	beDown := baseBackends
	beDown.HealthyCount = 0
	critBE := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, beDown)
	if critBE.Status != HealthCritical {
		t.Errorf("expected CRITICAL for 0 healthy backends, got %s", critBE.Status)
	}

	// 7. Critical on duplicate IP routing inconsistency
	routeDup := baseRouting
	routeDup.IsConsistent = false
	routeDup.DuplicateIPs = []string{"10.100.0.5"}
	routeDup.InconsistencyDetails = []string{"1 duplicate IP detected"}
	critRoute := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, baseVTUN, basePeerSync, routeDup, baseHandshake, baseBackends)
	if critRoute.Status != HealthCritical {
		t.Errorf("expected CRITICAL for duplicate IP, got %s", critRoute.Status)
	}

	// 8. Degraded on VirtualTUN queue saturation
	vtunSat := baseVTUN
	vtunSat.NexusToUpstream.Capacity = 1000
	vtunSat.NexusToUpstream.Occupancy = 950 // 95% utilization
	degVTUN := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, baseDrops, vtunSat, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degVTUN.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for VirtualTUN saturation, got %s", degVTUN.Status)
	}

	// 9. Degraded on write errors
	latErr := baseLatency
	latErr.WriteErrorRatePps = 2.0
	degLat := EvaluateForwarderHealth(true, true, baseQueue, latErr, baseDrops, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degLat.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for write errors, got %s", degLat.Status)
	}

	// 10. Degraded on active dataplane drops
	dropsActive := baseDrops
	dropsActive.TotalDropRatePps = 12.0
	degDrops := EvaluateForwarderHealth(true, true, baseQueue, baseLatency, dropsActive, baseVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if degDrops.Status != HealthDegraded {
		t.Errorf("expected DEGRADED for elevated drop rate, got %s", degDrops.Status)
	}
}

func TestEvaluateForwarderHealth_Recovery(t *testing.T) {
	// Lifetime cumulative counters are non-zero (previous incident)
	histQueue := QueuePressureDiagnostics{
		Occupancy:             5,
		Capacity:              1000,
		UtilizationPct:        0.5,
		HighWaterPct:          85.0,
		ConsecutiveAbove50Sec: 0,
		ConsecutiveAbove80Sec: 0,
		QueueFullDrops:        100, // Historical drops
		QueueDropRatePps:      0.0, // Active rate is 0
	}
	histLatency := ForwardLatencyDiagnostics{
		P50MS:             1.5,
		P95MS:             5.0,
		P99MS:             8.0,
		OldestInFlightMS:  0,
		Stalls:            10, // Historical stalls
		WriteErrors:       50, // Historical errors
		WriteTotal:        5000,
		WriteErrorRatePps: 0.0, // Active rate is 0
	}
	histDrops := DropCategoryBreakdown{
		ClientBackendQueueFull: 100,
		ClientTotalDrops:       100,
		ReturnVirtualTUNDrops:  20,
		ReturnTotalDrops:       20,
		TotalDrops:             120, // Historical total
		ClientDropRatePps:      0.0,
		ReturnDropRatePps:      0.0,
		TotalDropRatePps:       0.0, // Active rate is 0
	}
	histVTUN := VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 10, Peak: 800, Drops: 20}, // Historical drops
		NexusToUpstream: VirtualTUNDirectionalHealth{Capacity: 1000, Occupancy: 10, Peak: 800, Drops: 15}, // Historical drops
	}
	basePeerSync := &PeerSyncStatus{
		DesiredPeers: 10,
		ActualPeers:  10,
		SyncFailures: 0,
	}
	baseRouting := RoutingConsistencyDiagnostics{
		ActiveSessionsCount: 5,
		ActiveRoutesCount:   5,
		ReturnOwnersCount:   5,
		IsConsistent:        true,
	}
	baseHandshake := HandshakeFreshnessDiagnostics{
		TotalPeers: 10,
	}
	baseBackends := BackendsDiagnostics{
		HealthyCount: 2,
		TotalCount:   2,
		LatencyP95MS: 15.0,
	}

	// Dynamic recovery: when active rates and stalls are 0, status MUST evaluate to HEALTHY
	assessment := EvaluateForwarderHealth(true, true, histQueue, histLatency, histDrops, histVTUN, basePeerSync, baseRouting, baseHandshake, baseBackends)
	if assessment.Status != HealthHealthy {
		t.Fatalf("expected HEALTHY status upon recovery, got %s (conditions: %+v)", assessment.Status, assessment.Conditions)
	}
}

func TestEvaluateForwarderHealth_EscalationFromActionableProblems(t *testing.T) {
	baseQueue := QueuePressureDiagnostics{}
	baseLatency := ForwardLatencyDiagnostics{}
	baseDrops := DropCategoryBreakdown{}
	baseVTUN := VirtualTUNDiagnostics{}
	basePeerSync := &PeerSyncStatus{
		DesiredPeers: 5,
		ActualPeers:  5,
	}
	baseRouting := RoutingConsistencyDiagnostics{
		IsConsistent: true,
	}
	baseHandshake := HandshakeFreshnessDiagnostics{}
	baseBackends := BackendsDiagnostics{
		HealthyCount: 2,
		TotalCount:   2,
	}

	t.Run("DegradedRouteEscalatesHealthyStatusToDegraded", func(t *testing.T) {
		degradedProblem := ActionableProblem{
			Severity:     "DEGRADED",
			Category:     "dataplane",
			Message:      "Return queue full drops (5 recent) for 10.8.0.2",
			MessageKey:   "vpn_problem_route_queue_drops",
			AssignedIP:   "10.8.0.2",
			ObservedRate: "2.5 drops/s",
		}

		health := EvaluateForwarderHealth(
			true,
			true,
			baseQueue,
			baseLatency,
			baseDrops,
			baseVTUN,
			basePeerSync,
			baseRouting,
			baseHandshake,
			baseBackends,
			degradedProblem,
		)

		if health.Status != HealthDegraded {
			t.Errorf("status: got %q, want %q", health.Status, HealthDegraded)
		}
		if !strings.Contains(health.Summary, "Active VPN session routing or dataplane issues detected") {
			t.Errorf("summary: got %q, want to contain 'Active VPN session routing or dataplane issues detected'", health.Summary)
		}
		if len(health.ActionableProblems) != 1 {
			t.Errorf("actionable problems length: got %d, want 1", len(health.ActionableProblems))
		}
	})

	t.Run("UnroutableSessionEscalatesStatusToCritical", func(t *testing.T) {
		unroutableProblem := ActionableProblem{
			Severity:   "CRITICAL",
			Category:   "routing",
			Message:    "Session sess-1 has no active route",
			MessageKey: "vpn_problem_session_without_route",
			SessionID:  "sess-1",
			AssignedIP: "10.8.0.10",
		}

		health := EvaluateForwarderHealth(
			true,
			true,
			baseQueue,
			baseLatency,
			baseDrops,
			baseVTUN,
			basePeerSync,
			baseRouting,
			baseHandshake,
			baseBackends,
			unroutableProblem,
		)

		if health.Status != HealthCritical {
			t.Errorf("status: got %q, want %q", health.Status, HealthCritical)
		}
		if !strings.Contains(health.Summary, "Active VPN session routing or dataplane issues detected") {
			t.Errorf("summary: got %q, want to contain 'Active VPN session routing or dataplane issues detected'", health.Summary)
		}
	})
}
