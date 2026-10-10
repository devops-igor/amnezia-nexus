package vpn

import (
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Issue #457 Rework Round 5: Under divergent directional windows, return mismatch losses
// must be subtracted from total drop rate using the return tracker's own window duration,
// preventing residual loss from triggering false DEGRADED routine-drop conditions.
func TestReturnOwnershipMismatch_DivergentWindowsDoNotTriggerRoutineDropCondition(t *testing.T) {
	// Return window is 0.25s with 3 drops (12 PPS, streak 1 -> WARNING).
	// Client window is 1.50s with 0 drops.
	diag := RoutingConsistencyDiagnostics{
		IsConsistent:                                      false,
		OwnershipMismatchDropsRecent:                      3,
		ClientOwnershipMismatchDropsRecent:                0,
		OwnershipMismatchWindowSec:                        1.50, // shared math.Max window (would dilute to 3 / 1.5 = 2.0 PPS)
		ReturnOwnershipMismatchWindowSec:                  0.25, // return-specific window (3 / 0.25 = 12.0 PPS)
		ClientOwnershipMismatchWindowSec:                  1.50, // client-specific window
		ReturnOwnershipMismatchConsecutiveHighRateWindows: 1,    // single burst -> WARNING only
	}
	diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

	// Verify directional rate is 12.0 PPS and diluted aggregate is 2.0 PPS
	if got := diag.DirectionalOwnershipMismatchRatePPS(); got != 12.0 {
		t.Fatalf("expected DirectionalOwnershipMismatchRatePPS() 12.0 PPS, got %v", got)
	}
	if got := diag.OwnershipMismatchRatePPS(); got != 2.0 {
		t.Fatalf("expected diluted OwnershipMismatchRatePPS() 2.0 PPS, got %v", got)
	}

	// DropCategoryBreakdown.TotalDropRatePps = 12.0 (all 3 drops from return mismatch)
	drops := DropCategoryBreakdown{
		RatesAvailable:   true,
		TotalDropRatePps: 12.0,
		TotalDrops:       3,
		ReasonRates: map[string]float64{
			reasonReturnOwnershipMismatch: 12.0,
		},
	}

	// Assert that evaluateVirtualTUNAndDropConditions() calculates routineRate == 0 (no routine drop condition emitted).
	dropConds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, diag, 0)
	for _, c := range dropConds {
		if c.Category == "drops" {
			t.Fatalf("unexpected routine drop condition emitted: severity=%s message=%q", c.Severity, c.Message)
		}
	}

	// Routing conditions must produce exactly 1 WARNING condition
	routingConds := evaluateRoutingConditions(diag)
	routingCond := assertSingleCondition(t, routingConds, "routing")
	if routingCond.Severity != "WARNING" {
		t.Fatalf("routing condition severity=%s, want WARNING", routingCond.Severity)
	}

	// Assert that EvaluateForwarderHealth() produces overall headline HEALTHY (with 1 WARNING condition for routing, zero DEGRADED conditions).
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		drops, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

	if health.Status != HealthHealthy {
		t.Fatalf("headline status=%s, want HEALTHY", health.Status)
	}

	var degradedCount int
	var warningCount int
	for _, c := range health.Conditions {
		if c.Severity == "DEGRADED" {
			degradedCount++
		}
		if c.Severity == "WARNING" {
			warningCount++
		}
	}
	if degradedCount != 0 {
		t.Fatalf("expected 0 DEGRADED conditions, got %d: %+v", degradedCount, health.Conditions)
	}
	if warningCount != 1 {
		t.Fatalf("expected 1 WARNING condition, got %d: %+v", warningCount, health.Conditions)
	}
}

// Issue #457 Rework Round 6 (R5-H1): Subtracting same-loss-window reason rates
// prevents routine drop DEGRADED condition during an isolated return-only burst
// under concurrent collection / paused collection schedules where routing sampling
// advances to a different observation window or rate.
func TestReturnOwnershipMismatch_SameLossWindowPreventsFalseRoutineDrop(t *testing.T) {
	t.Run("direct_diagnostics_evaluation", func(t *testing.T) {
		// Aggregate loss window measured 24.0 PPS (all 6 drops are return mismatch drops).
		// Because loss and routing collection are separate stages, a concurrent collection
		// or interleaved schedule advanced the routing tracker over a longer window (e.g. 500ms),
		// measuring DirectionalOwnershipMismatchRatePPS() = 12.0 PPS (streak 1 -> WARNING).
		// Under cross-window subtraction (24 - 12), a 12 PPS routine drop residue would falsely
		// trigger DEGRADED routine loss. Under same-loss-window subtraction (24 - 24),
		// routine loss is 0 PPS, preserving overall HEALTHY.
		drops := DropCategoryBreakdown{
			RatesAvailable:   true,
			TotalDropRatePps: 24.0,
			TotalDrops:       6,
			ReturnMismatch:   6,
			ReasonRates: map[string]float64{
				reasonReturnOwnershipMismatch: 24.0,
			},
		}

		diag := RoutingConsistencyDiagnostics{
			IsConsistent:                                      false,
			OwnershipMismatchDropsRecent:                      6,
			ClientOwnershipMismatchDropsRecent:                0,
			OwnershipMismatchWindowSec:                        0.50,
			ReturnOwnershipMismatchWindowSec:                  0.50,
			ReturnOwnershipMismatchConsecutiveHighRateWindows: 1, // single burst -> WARNING only
		}
		diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

		if got := diag.DirectionalOwnershipMismatchRatePPS(); got != 12.0 {
			t.Fatalf("expected DirectionalOwnershipMismatchRatePPS() 12.0 PPS, got %v", got)
		}

		dropConds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, diag, 0)
		for _, c := range dropConds {
			if c.Category == "drops" {
				t.Fatalf("unexpected routine drop condition emitted: severity=%s message=%q", c.Severity, c.Message)
			}
		}

		routingConds := evaluateRoutingConditions(diag)
		routingCond := assertSingleCondition(t, routingConds, "routing")
		if routingCond.Severity != "WARNING" {
			t.Fatalf("routing condition severity=%s, want WARNING", routingCond.Severity)
		}

		health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
			drops, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
			BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

		if health.Status != HealthHealthy {
			t.Fatalf("headline status=%s, want HEALTHY: %+v", health.Status, health.Conditions)
		}
		if hasCondition(health.Conditions, "drops", "DEGRADED") {
			t.Fatalf("expected no drops DEGRADED condition, got %+v", health.Conditions)
		}
	})

	t.Run("service_assembly_interleaved_schedule", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			svc := &Service{}
			base := time.Now()

			// Prime trackers at t0.
			var primeDrops DropCategoryBreakdown
			svc.sampleDropRates(0, base, &primeDrops, 0)
			svc.diagDeltas.sampleClientOwnershipMismatch(0, base, 0)
			svc.diagDeltas.sampleOwnershipMismatch(0, base, 0)

			// Advance 250ms: 6 return mismatch drops occur in this interval (24.0 PPS).
			// Loss sampler captures this at t0 + 250ms.
			at250 := base.Add(250 * time.Millisecond)
			drops := DropCategoryBreakdown{
				ReturnMismatch:   6,
				ReturnTotalDrops: 6,
				TotalDrops:       6,
			}
			svc.sampleDropRates(0, at250, &drops, 0)
			if !drops.RatesAvailable || drops.TotalDropRatePps != 24.0 {
				t.Fatalf("expected TotalDropRatePps=24.0, got %v (ratesAvailable=%v)", drops.TotalDropRatePps, drops.RatesAvailable)
			}
			if drops.ReasonRates[reasonReturnOwnershipMismatch] != 24.0 {
				t.Fatalf("expected reasonReturnOwnershipMismatch=24.0, got %v", drops.ReasonRates[reasonReturnOwnershipMismatch])
			}

			// Simulating interleaved concurrent execution: routing sampling runs at t0 + 500ms
			// (500ms window, 6 drops -> 12.0 PPS, streak 1 -> WARNING).
			at500 := base.Add(500 * time.Millisecond)
			time.Sleep(500 * time.Millisecond)
			snap := svc.diagDeltas.sampleOwnershipMismatch(0, at500, 6)
			diag := RoutingConsistencyDiagnostics{
				IsConsistent:                                      false,
				OwnershipMismatchDropsRecent:                      snap.delta,
				ReturnOwnershipMismatchWindowSec:                  snap.windowSeconds,
				OwnershipMismatchWindowSec:                        snap.windowSeconds,
				ReturnOwnershipMismatchConsecutiveHighRateWindows: snap.consecutiveHighRateWindows,
			}
			diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

			if diag.ReturnOwnershipMismatchRatePPS() != 12.0 {
				t.Fatalf("expected ReturnOwnershipMismatchRatePPS()=12.0, got %v", diag.ReturnOwnershipMismatchRatePPS())
			}

			// Under same-loss-window subtraction, drops.TotalDropRatePps (24) minus
			// drops.ReasonRates[reasonReturnOwnershipMismatch] (24) leaves 0 routine loss.
			dropConds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, diag, 0)
			for _, c := range dropConds {
				if c.Category == "drops" {
					t.Fatalf("unexpected routine drop condition emitted: severity=%s message=%q", c.Severity, c.Message)
				}
			}

			health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
				drops, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
				BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

			if health.Status != HealthHealthy {
				t.Fatalf("headline status=%s, want HEALTHY: %+v", health.Status, health.Conditions)
			}
		})
	})
}

// Issue #457 Rework Round 6 (R5-H1): Genuine routine loss (e.g. 12 PPS malformed packets)
// is preserved and produces DEGRADED when concurrent return mismatch loss is present,
// even if routing observation rates skew higher due to interleaved sampling.
func TestReturnOwnershipMismatch_PreservesGenuineRoutineLossDuringConcurrentMismatch(t *testing.T) {
	t.Run("direct_diagnostics_evaluation", func(t *testing.T) {
		// Aggregate loss window has 16.0 PPS total drops:
		// 4.0 PPS from return mismatch, and 12.0 PPS from return malformed packets (routine loss).
		// Interleaved routing observation advanced with more drops and reports
		// DirectionalOwnershipMismatchRatePPS() = 20.0 PPS.
		// Under old subtraction (16.0 - 20.0 <= 0), the real 12.0 PPS routine loss was masked!
		// Under same-loss-window subtraction: 16.0 - 4.0 = 12.0 PPS routine drops,
		// triggering DEGRADED routine drop condition.
		drops := DropCategoryBreakdown{
			RatesAvailable:   true,
			TotalDropRatePps: 16.0,
			TotalDrops:       4,
			ReturnMismatch:   1,
			ReturnMalformed:  3,
			ReasonRates: map[string]float64{
				reasonReturnOwnershipMismatch: 4.0,
				"return_malformed":            12.0,
			},
		}

		diag := RoutingConsistencyDiagnostics{
			IsConsistent:                                      false,
			OwnershipMismatchDropsRecent:                      10,
			ClientOwnershipMismatchDropsRecent:                0,
			OwnershipMismatchWindowSec:                        0.50,
			ReturnOwnershipMismatchWindowSec:                  0.50,
			ReturnOwnershipMismatchConsecutiveHighRateWindows: 1,
		}
		diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

		if got := diag.DirectionalOwnershipMismatchRatePPS(); got != 20.0 {
			t.Fatalf("expected DirectionalOwnershipMismatchRatePPS() 20.0 PPS, got %v", got)
		}

		dropConds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, diag, 0)
		var hasRoutineDegraded bool
		for _, c := range dropConds {
			if c.Category == "drops" && c.Severity == "DEGRADED" && strings.Contains(c.Message, "routine drop rate") {
				hasRoutineDegraded = true
				if !strings.Contains(c.Message, "12.0") {
					t.Fatalf("expected routine drop rate message to report 12.0 drops/sec, got: %q", c.Message)
				}
			}
		}
		if !hasRoutineDegraded {
			t.Fatalf("expected DEGRADED routine drop condition, got %+v", dropConds)
		}

		health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
			drops, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
			BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

		if health.Status != HealthDegraded {
			t.Fatalf("headline status=%s, want DEGRADED: %+v", health.Status, health.Conditions)
		}
	})

	t.Run("service_assembly_interleaved_schedule", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			svc := &Service{}
			base := time.Now()

			// Prime trackers at t0.
			var primeDrops DropCategoryBreakdown
			svc.sampleDropRates(0, base, &primeDrops, 0)
			svc.diagDeltas.sampleClientOwnershipMismatch(0, base, 0)
			svc.diagDeltas.sampleOwnershipMismatch(0, base, 0)

			// Advance 250ms: 1 return mismatch drop (4.0 PPS) and 3 malformed return drops (12.0 PPS).
			// Total drop rate = 16.0 PPS.
			at250 := base.Add(250 * time.Millisecond)
			drops := DropCategoryBreakdown{
				ReturnMismatch:   1,
				ReturnMalformed:  3,
				ReturnTotalDrops: 4,
				TotalDrops:       4,
			}
			svc.sampleDropRates(0, at250, &drops, 0)
			if !drops.RatesAvailable || drops.TotalDropRatePps != 16.0 {
				t.Fatalf("expected TotalDropRatePps=16.0, got %v", drops.TotalDropRatePps)
			}
			if drops.ReasonRates[reasonReturnOwnershipMismatch] != 4.0 {
				t.Fatalf("expected return_mismatch=4.0, got %v", drops.ReasonRates[reasonReturnOwnershipMismatch])
			}
			if drops.ReasonRates["return_malformed"] != 12.0 {
				t.Fatalf("expected return_malformed=12.0, got %v", drops.ReasonRates["return_malformed"])
			}

			// Simulating interleaved execution: routing saw 9 more mismatch drops over 500ms
			// (total 10 drops in 500ms -> 20.0 PPS).
			at500 := base.Add(500 * time.Millisecond)
			time.Sleep(500 * time.Millisecond)
			snap := svc.diagDeltas.sampleOwnershipMismatch(0, at500, 10)
			diag := RoutingConsistencyDiagnostics{
				IsConsistent:                                      false,
				OwnershipMismatchDropsRecent:                      snap.delta,
				ReturnOwnershipMismatchWindowSec:                  snap.windowSeconds,
				OwnershipMismatchWindowSec:                        snap.windowSeconds,
				ReturnOwnershipMismatchConsecutiveHighRateWindows: snap.consecutiveHighRateWindows,
			}
			diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

			if diag.DirectionalOwnershipMismatchRatePPS() != 20.0 {
				t.Fatalf("expected DirectionalOwnershipMismatchRatePPS()=20.0, got %v", diag.DirectionalOwnershipMismatchRatePPS())
			}

			// Assert that the real 12.0 PPS routine loss is NOT masked by the 20.0 PPS routing rate.
			dropConds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), drops, diag, 0)
			var hasRoutineDegraded bool
			for _, c := range dropConds {
				if c.Category == "drops" && c.Severity == "DEGRADED" && strings.Contains(c.Message, "routine drop rate") {
					hasRoutineDegraded = true
					if !strings.Contains(c.Message, "12.0") {
						t.Fatalf("expected 12.0 drops/sec in routine drop message, got: %q", c.Message)
					}
				}
			}
			if !hasRoutineDegraded {
				t.Fatalf("expected DEGRADED routine drop condition preserving real routine loss, got: %+v", dropConds)
			}

			health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
				drops, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
				BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

			if health.Status != HealthDegraded {
				t.Fatalf("headline status=%s, want DEGRADED: %+v", health.Status, health.Conditions)
			}
		})
	})
}

// Issue #457 Rework Round 7 (R6-H1): A delayed counter snapshot delivered to
// sampleDropRates after a newer collection has advanced the baseline cannot advance
// reason rates to a quiet 0 PPS window while retaining an older aggregate rate,
// guaranteeing that drops.TotalDropRatePps and drops.ReasonRates represent the exact
// same accepted loss window and preventing false routine DEGRADED conditions.
func TestReturnOwnershipMismatch_StaleLossSnapshotDoesNotSplitAggregateAndReasonPublication(t *testing.T) {
	t.Run("direct_diagnostics_evaluation", func(t *testing.T) {
		svc := &Service{}
		base := time.Now()

		// Prime trackers at t0.
		var primeDrops DropCategoryBreakdown
		svc.sampleDropRates(0, base, &primeDrops, 0)

		// At t0 + 250ms, Collector A captures an observation with 3 return mismatch drops.
		// Older snapshot: 3 return mismatch drops, 3 total drops. (Paused before loss sampling).
		older := DropCategoryBreakdown{
			ReturnMismatch:   3,
			ReturnTotalDrops: 3,
			TotalDrops:       3,
		}

		// At t0 + 500ms, Collector B samples a newer observation with 3 mismatch + 3 malformed = 6 total drops.
		at500 := base.Add(500 * time.Millisecond)
		newer := DropCategoryBreakdown{
			ReturnMismatch:   3,
			ReturnMalformed:  3,
			ReturnTotalDrops: 6,
			TotalDrops:       6,
		}
		svc.sampleDropRates(0, at500, &newer, 0)
		if !newer.RatesAvailable || newer.TotalDropRatePps != 12.0 {
			t.Fatalf("newer window: expected TotalDropRatePps=12.0, got %v (ratesAvailable=%v)", newer.TotalDropRatePps, newer.RatesAvailable)
		}
		if newer.ReasonRates[reasonReturnOwnershipMismatch] != 6.0 {
			t.Fatalf("newer window: expected reasonReturnOwnershipMismatch=6.0, got %v", newer.ReasonRates[reasonReturnOwnershipMismatch])
		}
		if newer.ReasonRates["return_malformed"] != 6.0 {
			t.Fatalf("newer window: expected return_malformed=6.0, got %v", newer.ReasonRates["return_malformed"])
		}

		// At t0 + 750ms, Collector A delivers its older snapshot late.
		// Its total drops (3) < accepted baseline (6), so s.diagRates rejects it (accepted=false)
		// and retains TotalDropRatePps = 12.0.
		// Under coherent publication gating (R6-H1), s.diagDeltas.reasons does NOT advance
		// its windows or report a quiet 0 PPS ownership window; it retains the previously accepted
		// reason rates snapshot (ownership=6.0, malformed=6.0).
		at750 := base.Add(750 * time.Millisecond)
		svc.sampleDropRates(0, at750, &older, 0)

		if !older.RatesAvailable {
			t.Fatal("older window: expected RatesAvailable=true from retained publication")
		}
		if older.TotalDropRatePps != 12.0 {
			t.Fatalf("older window: expected retained TotalDropRatePps=12.0, got %v", older.TotalDropRatePps)
		}
		if older.ReasonRates[reasonReturnOwnershipMismatch] != 6.0 {
			t.Fatalf("older window: expected retained reasonReturnOwnershipMismatch=6.0, got %v (must NOT advance to 0 PPS)",
				older.ReasonRates[reasonReturnOwnershipMismatch])
		}
		if older.ReasonRates["return_malformed"] != 6.0 {
			t.Fatalf("older window: expected retained return_malformed=6.0, got %v", older.ReasonRates["return_malformed"])
		}

		// Evaluating conditions on older: routine loss = 12.0 - 6.0 = 6.0 PPS (< 10 PPS degraded threshold).
		diag := RoutingConsistencyDiagnostics{
			IsConsistent:                                      false,
			OwnershipMismatchDropsRecent:                      3,
			ReturnOwnershipMismatchWindowSec:                  0.50,
			OwnershipMismatchWindowSec:                        0.50,
			ReturnOwnershipMismatchConsecutiveHighRateWindows: 1, // single burst -> WARNING only
		}
		diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

		dropConds := evaluateVirtualTUNAndDropConditions(quietVirtualTUN(), older, diag, 0)
		for _, c := range dropConds {
			if c.Category == "drops" && c.Severity == "DEGRADED" {
				t.Fatalf("unexpected routine drop DEGRADED condition emitted on stale observation: %q", c.Message)
			}
		}

		health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
			older, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
			BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

		if health.Status != HealthHealthy {
			t.Fatalf("headline status=%s, want HEALTHY (single burst + 6 PPS routine loss is warning): %+v", health.Status, health.Conditions)
		}
		if hasCondition(health.Conditions, "drops", "DEGRADED") {
			t.Fatalf("stale observation must not emit drops DEGRADED condition, got: %+v", health.Conditions)
		}
	})

	t.Run("synctest_stale_collector_schedule", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := forwarder.NewForwarder(nil, "192.0.2.0/24")
			t.Cleanup(func() {
				_ = f.Stop()
			})
			e := &IngressEngine{}
			f.SetReturnRejectClassifier(e.classifyForwarderReject)
			f.RegisterSessionWithReturnPath("stale-session", "stale-connection", "stale-peer", "192.0.2.1", 1,
				forwarder.NewReturnPath(e.writeReturnPacket))
			inputs := diagnosticsInputs{
				forwarder:     f,
				ingressEngine: e,
				sessions:      []Session{{ID: "stale-session", PeerPublicKey: "stale-peer", AssignedIP: "192.0.2.1"}},
			}
			mismatch := func(n int) {
				for range n {
					if err := f.RouteBackendToClient(2, nil, "192.0.2.1"); !errors.Is(err, forwarder.ErrReturnRouteMismatch) {
						t.Fatalf("wrong-backend packet was not refused: %v", err)
					}
				}
			}
			malformed := func(n int) {
				for range n {
					if _, err := e.writeReturnPacket("stale-peer", "192.0.2.1", nil); err == nil {
						t.Fatal("malformed return packet was not refused")
					}
				}
			}

			svc := &Service{}
			routes := inputs.forwarder.InspectRoutes()
			var baseline, newer Status

			// t=0: Prime collectors
			svc.populateOperationalDiagnosticsFromInputs(&baseline, routes, inputs)

			// t=250ms: 3 return mismatch drops occur. Collector A captures counters but pauses before loss sampling.
			time.Sleep(250 * time.Millisecond)
			mismatch(3)
			older := inputs.collectDropCategories()

			// t=500ms: 3 malformed drops occur. Collector B completes full sampling pass.
			time.Sleep(250 * time.Millisecond)
			malformed(3)
			svc.populateOperationalDiagnosticsFromInputs(&newer, routes, inputs)
			if newer.DropCategories.TotalDropRatePps != 12.0 ||
				newer.DropCategories.ReasonRates[reasonReturnOwnershipMismatch] != 6.0 ||
				newer.DropCategories.ReasonRates["return_malformed"] != 6.0 {
				t.Fatalf("newer collection incorrect: %+v", newer.DropCategories)
			}

			// t=750ms: Collector A delivers its previously captured observation late.
			time.Sleep(250 * time.Millisecond)
			svc.sampleDropRates(inputs.generation, time.Now(), &older, 0)

			delayed := Status{
				DropCategories:     older,
				RoutingConsistency: checkRoutingInvariantsWithInputs(svc, inputs, routes, inputs.ingressEngine.ReturnStats(), 0),
			}
			health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
				delayed.DropCategories, quietVirtualTUN(), nil, delayed.RoutingConsistency, HandshakeFreshnessDiagnostics{},
				BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

			if delayed.DropCategories.TotalDropRatePps != 12.0 {
				t.Fatalf("delayed total drop rate=%v, want 12.0", delayed.DropCategories.TotalDropRatePps)
			}
			if delayed.DropCategories.ReasonRates[reasonReturnOwnershipMismatch] != 6.0 {
				t.Fatalf("delayed reasonReturnOwnershipMismatch=%v, want 6.0 (must NOT advance to 0 PPS)",
					delayed.DropCategories.ReasonRates[reasonReturnOwnershipMismatch])
			}
			if delayed.DropCategories.ReasonRates["return_malformed"] != 6.0 {
				t.Fatalf("delayed return_malformed=%v, want 6.0", delayed.DropCategories.ReasonRates["return_malformed"])
			}
			if health.Status != HealthHealthy {
				t.Fatalf("delayed headline status=%s, want HEALTHY (routine loss is 6 PPS, warning): %+v", health.Status, health.Conditions)
			}
			if hasCondition(health.Conditions, "drops", "DEGRADED") {
				t.Fatalf("delayed collection must not emit drops DEGRADED condition, got: %+v", health.Conditions)
			}
		})
	})
}

// Issue #457 Rework Round 6 (R5-L1): Test partially populated fallback helper composition
// asserting that each directional helper is strictly directional and does not double-count
// client or return drops when directional windows are partially populated.
func TestRoutingConsistency_PartiallyPopulatedDirectionalFallback(t *testing.T) {
	tests := []struct {
		name                string
		diag                RoutingConsistencyDiagnostics
		wantReturnRate      float64
		wantClientRate      float64
		wantDirectionalRate float64
	}{
		{
			name: "return_window_unset_client_window_set",
			diag: RoutingConsistencyDiagnostics{
				OwnershipMismatchDropsRecent:       3,
				ClientOwnershipMismatchDropsRecent: 1,
				OwnershipMismatchWindowSec:         1.0,
				ClientOwnershipMismatchWindowSec:   0.25,
			},
			wantReturnRate:      3.0, // 3 / 1.0 (only return drops in numerator)
			wantClientRate:      4.0, // 1 / 0.25 (only client drops in numerator)
			wantDirectionalRate: 7.0, // 3.0 + 4.0; must NOT double-count client drops to 8.0
		},
		{
			name: "client_window_unset_return_window_set",
			diag: RoutingConsistencyDiagnostics{
				OwnershipMismatchDropsRecent:       3,
				ClientOwnershipMismatchDropsRecent: 1,
				OwnershipMismatchWindowSec:         1.0,
				ReturnOwnershipMismatchWindowSec:   0.25,
			},
			wantReturnRate:      12.0, // 3 / 0.25
			wantClientRate:      1.0,  // 1 / 1.0
			wantDirectionalRate: 13.0, // 12.0 + 1.0; must NOT double-count return drops
		},
		{
			name: "both_directional_windows_set",
			diag: RoutingConsistencyDiagnostics{
				OwnershipMismatchDropsRecent:       6,
				ClientOwnershipMismatchDropsRecent: 2,
				ReturnOwnershipMismatchWindowSec:   0.5,
				ClientOwnershipMismatchWindowSec:   0.25,
			},
			wantReturnRate:      12.0, // 6 / 0.5
			wantClientRate:      8.0,  // 2 / 0.25
			wantDirectionalRate: 20.0, // 12.0 + 8.0
		},
		{
			name: "neither_directional_window_set",
			diag: RoutingConsistencyDiagnostics{
				OwnershipMismatchDropsRecent:       6,
				ClientOwnershipMismatchDropsRecent: 2,
				OwnershipMismatchWindowSec:         2.0,
			},
			wantReturnRate:      3.0, // 6 / 2.0
			wantClientRate:      1.0, // 2 / 2.0
			wantDirectionalRate: 4.0, // (6 + 2) / 2.0 = 4.0
		},
		{
			name: "all_windows_unset",
			diag: RoutingConsistencyDiagnostics{
				OwnershipMismatchDropsRecent:       6,
				ClientOwnershipMismatchDropsRecent: 2,
			},
			wantReturnRate:      0.0,
			wantClientRate:      0.0,
			wantDirectionalRate: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotReturn := tt.diag.ReturnOwnershipMismatchRatePPS()
			if gotReturn != tt.wantReturnRate {
				t.Errorf("ReturnOwnershipMismatchRatePPS() = %v, want %v", gotReturn, tt.wantReturnRate)
			}
			gotClient := tt.diag.ClientOwnershipMismatchRatePPS()
			if gotClient != tt.wantClientRate {
				t.Errorf("ClientOwnershipMismatchRatePPS() = %v, want %v", gotClient, tt.wantClientRate)
			}
			gotDirectional := tt.diag.DirectionalOwnershipMismatchRatePPS()
			if gotDirectional != tt.wantDirectionalRate {
				t.Errorf("DirectionalOwnershipMismatchRatePPS() = %v, want %v", gotDirectional, tt.wantDirectionalRate)
			}
		})
	}
}
