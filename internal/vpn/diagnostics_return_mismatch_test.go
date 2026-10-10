package vpn

import (
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// Issue #457: escalating RETURN-direction ownership mismatches reach DEGRADED
// when sustained at high rate (>= ReturnOwnershipMismatchDegradedRatePPS) across
// consecutive observation windows. A single initial burst remains WARNING.
func TestB3EscalatingReturnOwnershipMismatchReachesDegraded(t *testing.T) {
	th := DefaultHealthThresholds
	svc := &Service{}
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)

	const escalating = 500
	// Window 1: high rate burst (rate >= 10 PPS). Initial window must remain WARNING.
	diag1 := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: escalating}, 0)
	if diag1.OwnershipMismatchDropsRecent != escalating {
		t.Fatalf("return recent mismatch=%d, want %d", diag1.OwnershipMismatchDropsRecent, escalating)
	}
	if diag1.OwnershipMismatchRatePPS() < th.ReturnOwnershipMismatchDegradedRatePPS {
		t.Fatalf("test does not exercise the degraded rate threshold: rate=%v threshold=%v",
			diag1.OwnershipMismatchRatePPS(), th.ReturnOwnershipMismatchDegradedRatePPS)
	}
	cond1 := assertSingleCondition(t, evaluateRoutingConditions(diag1), "routing")
	if cond1.Severity != "WARNING" {
		t.Fatalf("single burst return ownership mismatch severity=%q, want WARNING: %q",
			cond1.Severity, cond1.Message)
	}

	time.Sleep(250 * time.Millisecond)

	// Window 2: sustained high rate across consecutive windows. Escalates to DEGRADED.
	diag2 := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: escalating * 2}, 0)
	if diag2.OwnershipMismatchDropsRecent != escalating {
		t.Fatalf("return recent mismatch window 2=%d, want %d", diag2.OwnershipMismatchDropsRecent, escalating)
	}
	if diag2.OwnershipMismatchRatePPS() < th.ReturnOwnershipMismatchDegradedRatePPS {
		t.Fatalf("window 2 rate=%v must meet degraded rate threshold %v",
			diag2.OwnershipMismatchRatePPS(), th.ReturnOwnershipMismatchDegradedRatePPS)
	}
	cond2 := assertSingleCondition(t, evaluateRoutingConditions(diag2), "routing")
	if cond2.Severity != "DEGRADED" {
		t.Fatalf("sustained return ownership mismatch severity=%q, want DEGRADED: %q",
			cond2.Severity, cond2.Message)
	}
}

// Issue #457: sparse return-direction ownership mismatches classify as WARNING,
// and do not degrade overall forwarder health (evaluates to HEALTHY with warning condition).
func TestReturnOwnershipMismatch_SparseClassifiesAsWarning(t *testing.T) {
	th := DefaultHealthThresholds

	const sparseDrops = 19
	const windowSec = 30.0

	diag := RoutingConsistencyDiagnostics{
		IsConsistent:                 false,
		OwnershipMismatchDropsRecent: sparseDrops,
		OwnershipMismatchWindowSec:   windowSec,
	}
	diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

	rate := diag.OwnershipMismatchRatePPS()
	if rate >= th.ReturnOwnershipMismatchDegradedRatePPS {
		t.Fatalf("test rate=%v must be below degraded rate threshold %v", rate, th.ReturnOwnershipMismatchDegradedRatePPS)
	}
	if diag.OwnershipMismatchDropsRecent < th.ReturnOwnershipMismatchWarningDrops {
		t.Fatalf("test drops=%d must meet or exceed warning drops threshold %d",
			diag.OwnershipMismatchDropsRecent, th.ReturnOwnershipMismatchWarningDrops)
	}

	conds := evaluateRoutingConditions(diag)
	cond := assertSingleCondition(t, conds, "routing")
	if cond.Severity != "WARNING" {
		t.Fatalf("sparse return ownership mismatch severity=%q, want WARNING: %q", cond.Severity, cond.Message)
	}

	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		DropCategoryBreakdown{}, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

	if health.Status == HealthCritical || health.Status == HealthDegraded {
		t.Fatalf("headline=%s: sparse return ownership mismatch must not evaluate to CRITICAL or DEGRADED (%s)",
			health.Status, health.Summary)
	}
	if health.Status != HealthHealthy {
		t.Fatalf("headline=%s, want HEALTHY (operational with warning)", health.Status)
	}
	if !hasCondition(health.Conditions, "routing", "WARNING") {
		t.Fatalf("expected routing WARNING condition in health assessment, got: %+v", health.Conditions)
	}
}

// Issue #457: A single high-rate return-direction burst (e.g. 12 PPS in window 1)
// evaluates to WARNING, preventing false DEGRADED alerts during routine migration tails.
func TestReturnOwnershipMismatch_SingleHighRateBurstEvaluatesToWarning(t *testing.T) {
	th := DefaultHealthThresholds

	// 250ms window with 3 drops = 12.0 PPS (the exact counterexample from review).
	const drops = 3
	const windowSec = 0.25

	diag := RoutingConsistencyDiagnostics{
		IsConsistent:                                      false,
		OwnershipMismatchDropsRecent:                      drops,
		OwnershipMismatchWindowSec:                        windowSec,
		ReturnOwnershipMismatchConsecutiveHighRateWindows: 1, // first window above rate threshold
	}
	diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

	rate := diag.OwnershipMismatchRatePPS()
	if rate < th.ReturnOwnershipMismatchDegradedRatePPS {
		t.Fatalf("test rate=%.2f must meet or exceed degraded rate threshold %.2f",
			rate, th.ReturnOwnershipMismatchDegradedRatePPS)
	}

	conds := evaluateRoutingConditions(diag)
	cond := assertSingleCondition(t, conds, "routing")
	if cond.Severity != "WARNING" {
		t.Fatalf("single high-rate burst severity=%q, want WARNING: %q", cond.Severity, cond.Message)
	}

	// Overall headline health must evaluate to HEALTHY (operational with warning).
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		DropCategoryBreakdown{}, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

	if health.Status != HealthHealthy {
		t.Fatalf("headline=%s, want HEALTHY (operational with warning condition)", health.Status)
	}
	if !hasCondition(health.Conditions, "routing", "WARNING") {
		t.Fatalf("expected routing WARNING condition in health assessment, got: %+v", health.Conditions)
	}
}

// Issue #457: Successive sustained high-rate bursts across consecutive observation windows
// escalate return-direction ownership mismatch to DEGRADED.
func TestReturnOwnershipMismatch_SustainedHighRateEvaluatesToDegraded(t *testing.T) {
	th := DefaultHealthThresholds

	diag := RoutingConsistencyDiagnostics{
		IsConsistent:                                      false,
		OwnershipMismatchDropsRecent:                      500,
		OwnershipMismatchWindowSec:                        1.0,
		ReturnOwnershipMismatchConsecutiveHighRateWindows: th.ReturnOwnershipMismatchDegradedConsecutiveWindows,
	}
	diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

	rate := diag.OwnershipMismatchRatePPS()
	if rate < th.ReturnOwnershipMismatchDegradedRatePPS {
		t.Fatalf("rate=%.2f must meet degraded rate threshold %.2f", rate, th.ReturnOwnershipMismatchDegradedRatePPS)
	}

	conds := evaluateRoutingConditions(diag)
	cond := assertSingleCondition(t, conds, "routing")
	if cond.Severity != "DEGRADED" {
		t.Fatalf("sustained return mismatch severity=%q, want DEGRADED: %q", cond.Severity, cond.Message)
	}

	// Overall headline health must evaluate to DEGRADED.
	health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
		DropCategoryBreakdown{}, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
		BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

	if health.Status != HealthDegraded {
		t.Fatalf("headline=%s, want DEGRADED", health.Status)
	}
}

// Issue #457: Recovery window (drop rate falls below threshold or drops reach zero)
// clears DEGRADED, recovers health, and resets the persistence counter.
func TestReturnOwnershipMismatch_RecoveryClearsDegradedAndResetsPersistence(t *testing.T) {
	svc := &Service{}
	// Window 1: prime tracker
	checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{}, 0)
	time.Sleep(250 * time.Millisecond)

	const burst = 500
	// Window 2: initial high-rate burst -> WARNING (consecutive = 1)
	diag1 := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: burst}, 0)
	cond1 := assertSingleCondition(t, evaluateRoutingConditions(diag1), "routing")
	if cond1.Severity != "WARNING" {
		t.Fatalf("window 2 (burst) severity=%q, want WARNING", cond1.Severity)
	}

	time.Sleep(250 * time.Millisecond)

	// Window 3: sustained high-rate -> DEGRADED (consecutive = 2)
	diag2 := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: burst * 2}, 0)
	cond2 := assertSingleCondition(t, evaluateRoutingConditions(diag2), "routing")
	if cond2.Severity != "DEGRADED" {
		t.Fatalf("window 3 (sustained) severity=%q, want DEGRADED", cond2.Severity)
	}

	time.Sleep(250 * time.Millisecond)

	// Window 4: recovery / quiet (zero new drops) -> clean recovery
	diag3 := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: burst * 2}, 0)
	if !diag3.IsConsistent {
		t.Fatalf("window 4 (quiet) must be consistent: %+v", diag3.InconsistencyDetails)
	}
	if got := evaluateRoutingConditions(diag3); len(got) != 0 {
		t.Fatalf("window 4 (quiet) must produce no condition, got: %+v", got)
	}
	if diag3.ReturnOwnershipMismatchConsecutiveHighRateWindows != 0 {
		t.Fatalf("consecutive counter must reset to 0 on quiet recovery, got %d",
			diag3.ReturnOwnershipMismatchConsecutiveHighRateWindows)
	}

	time.Sleep(250 * time.Millisecond)

	// Window 5: new isolated burst -> must be WARNING again because persistence was reset
	diag4 := checkRoutingInvariants(svc, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: burst * 3}, 0)
	cond4 := assertSingleCondition(t, evaluateRoutingConditions(diag4), "routing")
	if cond4.Severity != "WARNING" {
		t.Fatalf("window 5 (new burst after recovery) severity=%q, want WARNING (persistence did not reset)",
			cond4.Severity)
	}
}

// Issue #457: Mixed client and return drops evaluate strictly to CRITICAL regardless of persistence.
func TestReturnOwnershipMismatch_MixedClientAndReturnDropsEvaluateToCritical(t *testing.T) {
	for _, consecutive := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("consecutive=%d", consecutive), func(t *testing.T) {
			diag := RoutingConsistencyDiagnostics{
				IsConsistent:                                      false,
				ClientOwnershipMismatchDropsRecent:                1,   // client-direction mismatch
				OwnershipMismatchDropsRecent:                      500, // return-direction mismatch (high volume)
				OwnershipMismatchWindowSec:                        1.0,
				ReturnOwnershipMismatchConsecutiveHighRateWindows: consecutive,
			}
			diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

			conds := evaluateRoutingConditions(diag)
			cond := assertSingleCondition(t, conds, "routing")
			if cond.Severity != "CRITICAL" {
				t.Fatalf("mixed mismatch severity=%q, want CRITICAL: %q", cond.Severity, cond.Message)
			}

			health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
				DropCategoryBreakdown{}, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
				BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})

			if health.Status != HealthCritical {
				t.Fatalf("mixed mismatch headline=%s, want CRITICAL", health.Status)
			}
		})
	}
}

// Issue #457: Lifecycle reset / re-priming on generation advance resets the consecutive tracker to zero.
func TestReturnOwnershipMismatch_LifecycleResetClearsConsecutiveCounter(t *testing.T) {
	var dts diagDeltaTrackers
	now := time.Now()

	// Prime generation 0
	dts.sampleOwnershipMismatch(0, now, 0)
	now = now.Add(250 * time.Millisecond)

	// Window 1: burst
	dts.sampleOwnershipMismatch(0, now, 100)
	now = now.Add(250 * time.Millisecond)

	// Window 2: sustained -> consecutive = 2
	dts.sampleOwnershipMismatch(0, now, 200)
	if dts.consecutiveHighRateWindows() != 2 {
		t.Fatalf("expected consecutive=2, got %d", dts.consecutiveHighRateWindows())
	}

	// Advance generation via reset(1)
	dts.reset(1)

	// Sample in generation 1: prime
	dts.sampleOwnershipMismatch(1, now, 0)
	if dts.consecutiveHighRateWindows() != 0 {
		t.Fatalf("expected consecutive=0 after reset, got %d", dts.consecutiveHighRateWindows())
	}

	now = now.Add(250 * time.Millisecond)
	// Window 1 of generation 1: fresh burst -> consecutive must be 1 (not 3)
	dts.sampleOwnershipMismatch(1, now, 100)
	if dts.consecutiveHighRateWindows() != 1 {
		t.Fatalf("expected consecutive=1 on fresh burst after reset, got %d", dts.consecutiveHighRateWindows())
	}
}

// Issue #457: Calling reset(staleGen) must be a strict no-op: it does NOT clear
// the consecutive high-rate streak, mutate the delta snapshot, or downgrade severity.
func TestReturnOwnershipMismatch_StaleResetMustPreservePersistence(t *testing.T) {
	var dts diagDeltaTrackers
	now := time.Now()

	// Advance to generation 1 and prime it.
	dts.reset(1)
	dts.sampleOwnershipMismatch(1, now, 0)
	now = now.Add(250 * time.Millisecond)

	// Window 1: high-rate burst (3 drops over 0.25s = 12 PPS) -> streak = 1.
	snap1 := dts.sampleOwnershipMismatch(1, now, 3)
	if snap1.consecutiveHighRateWindows != 1 {
		t.Fatalf("window 1: want streak=1, got %d", snap1.consecutiveHighRateWindows)
	}

	now = now.Add(250 * time.Millisecond)
	// Window 2: sustained high-rate (3 more drops over 0.25s = 12 PPS) -> streak = 2.
	snap2 := dts.sampleOwnershipMismatch(1, now, 6)
	if snap2.consecutiveHighRateWindows != 2 {
		t.Fatalf("window 2: want streak=2, got %d", snap2.consecutiveHighRateWindows)
	}

	// Verify routing condition severity is DEGRADED before stale reset.
	diagBefore := RoutingConsistencyDiagnostics{
		IsConsistent:                                      false,
		OwnershipMismatchDropsRecent:                      snap2.delta,
		OwnershipMismatchWindowSec:                        snap2.windowSeconds,
		ReturnOwnershipMismatchConsecutiveHighRateWindows: snap2.consecutiveHighRateWindows,
	}
	diagBefore.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diagBefore)}
	condsBefore := evaluateRoutingConditions(diagBefore)
	condBefore := assertSingleCondition(t, condsBefore, "routing")
	if condBefore.Severity != "DEGRADED" {
		t.Fatalf("expected DEGRADED before stale reset, got %q", condBefore.Severity)
	}

	// Stale reset to generation 0 (must be a no-op against current generation 1).
	dts.reset(0)

	// Re-read snapshot in current window: delta, window, and streak must be untouched.
	snapAfter := dts.sampleOwnershipMismatch(1, now, 6)
	if snapAfter.delta != snap2.delta || snapAfter.windowSeconds != snap2.windowSeconds {
		t.Fatalf("stale reset changed delta/window: before=%+v, after=%+v", snap2, snapAfter)
	}
	if snapAfter.consecutiveHighRateWindows != 2 {
		t.Fatalf("stale reset cleared streak: want 2, got %d", snapAfter.consecutiveHighRateWindows)
	}
	if dts.consecutiveHighRateWindows() != 2 {
		t.Fatalf("stale reset cleared consecutiveHighRateWindows(): want 2, got %d", dts.consecutiveHighRateWindows())
	}

	// Evaluate routing conditions after stale reset: must still evaluate to DEGRADED.
	diagAfter := RoutingConsistencyDiagnostics{
		IsConsistent:                                      false,
		OwnershipMismatchDropsRecent:                      snapAfter.delta,
		OwnershipMismatchWindowSec:                        snapAfter.windowSeconds,
		ReturnOwnershipMismatchConsecutiveHighRateWindows: snapAfter.consecutiveHighRateWindows,
	}
	diagAfter.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diagAfter)}
	condsAfter := evaluateRoutingConditions(diagAfter)
	condAfter := assertSingleCondition(t, condsAfter, "routing")
	if condAfter.Severity != "DEGRADED" {
		t.Fatalf("stale reset caused false downgrade: want DEGRADED, got %q", condAfter.Severity)
	}
}

// Issue #457: Old-generation sample completion after forward reset must NOT restore
// or increment the consecutive counter. Tested both deterministically with synctest
// and under concurrent race execution.
func TestReturnOwnershipMismatch_ConcurrentResetMustNotRestoreOldStreak(t *testing.T) {
	t.Run("deterministic_interleaving", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dts diagDeltaTrackers
			base := time.Now()

			// Generation 0: prime and sample high-rate burst.
			dts.sampleOwnershipMismatch(0, base, 0)
			dts.sampleOwnershipMismatch(0, base.Add(250*time.Millisecond), 100)
			if dts.consecutiveHighRateWindows() != 1 {
				t.Fatalf("expected streak=1 in gen 0, got %d", dts.consecutiveHighRateWindows())
			}

			// Forward lifecycle reset to generation 1.
			dts.reset(1)
			if dts.consecutiveHighRateWindows() != 0 {
				t.Fatalf("expected streak=0 immediately after reset(1), got %d", dts.consecutiveHighRateWindows())
			}

			// In-flight generation 0 sample completes now (captured gen 0 before reset).
			// Must be rejected as stale: streak must remain 0!
			staleSnap := dts.sampleOwnershipMismatch(0, base.Add(500*time.Millisecond), 200)
			if dts.consecutiveHighRateWindows() != 0 {
				t.Fatalf("stale gen 0 sample restored streak after reset(1): got %d, want 0", dts.consecutiveHighRateWindows())
			}
			if staleSnap.consecutiveHighRateWindows != 0 {
				t.Fatalf("stale snapshot published streak=%d, want 0", staleSnap.consecutiveHighRateWindows)
			}

			// Generation 1 primes: streak must stay 0.
			dts.sampleOwnershipMismatch(1, base.Add(750*time.Millisecond), 0)
			if dts.consecutiveHighRateWindows() != 0 {
				t.Fatalf("streak after gen 1 prime=%d, want 0", dts.consecutiveHighRateWindows())
			}

			// Another delayed generation 0 sample completes after priming: must still be rejected!
			dts.sampleOwnershipMismatch(0, base.Add(1000*time.Millisecond), 300)
			if dts.consecutiveHighRateWindows() != 0 {
				t.Fatalf("delayed gen 0 sample after gen 1 prime corrupted streak: got %d, want 0", dts.consecutiveHighRateWindows())
			}

			// Genuine generation 1 burst: streak must cleanly advance to 1 (not 2 or 3).
			gen1Burst := dts.sampleOwnershipMismatch(1, base.Add(1250*time.Millisecond), 100)
			if gen1Burst.consecutiveHighRateWindows != 1 {
				t.Fatalf("gen 1 first burst streak=%d, want 1", gen1Burst.consecutiveHighRateWindows)
			}
			if dts.consecutiveHighRateWindows() != 1 {
				t.Fatalf("gen 1 consecutiveHighRateWindows()=%d, want 1", dts.consecutiveHighRateWindows())
			}
		})
	})

	t.Run("deterministic_contention_sample_first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dts diagDeltaTrackers
			base := time.Now()

			// Prime generation 0.
			dts.sampleOwnershipMismatch(0, base, 0)

			// Contention order A: Sample acquires first, completing high-rate sample
			// before reset acquires and clears the tracker.
			sampleReady := make(chan struct{})
			sampleDone := make(chan struct{})
			resetDone := make(chan struct{})

			go func() {
				close(sampleReady)
				snap := dts.sampleOwnershipMismatch(0, base.Add(250*time.Millisecond), 100)
				if snap.consecutiveHighRateWindows != 1 {
					t.Errorf("sample-first: want streak=1, got %d", snap.consecutiveHighRateWindows)
				}
				close(sampleDone)
			}()

			go func() {
				<-sampleReady
				<-sampleDone
				dts.reset(1)
				close(resetDone)
			}()

			<-resetDone
			if streak := dts.consecutiveHighRateWindows(); streak != 0 {
				t.Fatalf("sample-first contention: streak after reset(1)=%d, want 0", streak)
			}

			// Delayed stale sample from gen 0 must not restore streak.
			staleSnap := dts.sampleOwnershipMismatch(0, base.Add(500*time.Millisecond), 200)
			if staleSnap.consecutiveHighRateWindows != 0 {
				t.Fatalf("sample-first contention: stale snapshot published streak=%d, want 0", staleSnap.consecutiveHighRateWindows)
			}
			if streak := dts.consecutiveHighRateWindows(); streak != 0 {
				t.Fatalf("sample-first contention: stale sample restored streak to %d, want 0", streak)
			}
		})
	})

	t.Run("deterministic_contention_reset_first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var dts diagDeltaTrackers
			base := time.Now()

			// Prime gen 0 and establish high-rate streak = 1.
			dts.sampleOwnershipMismatch(0, base, 0)
			dts.sampleOwnershipMismatch(0, base.Add(250*time.Millisecond), 100)
			if dts.consecutiveHighRateWindows() != 1 {
				t.Fatalf("expected streak=1 before reset, got %d", dts.consecutiveHighRateWindows())
			}

			// Contention order B: Reset acquires first, advancing generation to 1.
			// The in-flight gen 0 sample executes immediately after and must be rejected.
			inFlightReady := make(chan struct{})
			resetDone := make(chan struct{})
			var inFlightSnap returnOwnershipSnapshot
			inFlightFinished := make(chan struct{})

			go func() {
				close(inFlightReady)
				<-resetDone
				inFlightSnap = dts.sampleOwnershipMismatch(0, base.Add(500*time.Millisecond), 200)
				close(inFlightFinished)
			}()

			go func() {
				<-inFlightReady
				dts.reset(1)
				close(resetDone)
			}()

			<-inFlightFinished
			if inFlightSnap.consecutiveHighRateWindows != 0 {
				t.Fatalf("reset-first contention: stale snapshot published streak=%d, want 0", inFlightSnap.consecutiveHighRateWindows)
			}
			if streak := dts.consecutiveHighRateWindows(); streak != 0 {
				t.Fatalf("reset-first contention: stale gen 0 sample restored streak to %d, want 0", streak)
			}
		})
	})

	t.Run("concurrent_race_interleaving", func(t *testing.T) {
		for iter := 0; iter < 50; iter++ {
			var dts diagDeltaTrackers
			base := time.Now()

			// Prime gen 0
			dts.sampleOwnershipMismatch(0, base, 0)
			dts.sampleOwnershipMismatch(0, base.Add(250*time.Millisecond), 100)

			var wg sync.WaitGroup
			wg.Add(2)

			// Goroutine 1: attempts to sample in gen 0 (competing with reset)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					dts.sampleOwnershipMismatch(0, base.Add(time.Duration(300+j*10)*time.Millisecond), uint64(100+j*10))
				}
			}()

			// Goroutine 2: executes reset(1)
			go func() {
				defer wg.Done()
				dts.reset(1)
			}()

			wg.Wait()

			// After both complete, an old gen 0 sample must not leave streak > 0 in gen 1
			// Test with another gen 0 sample
			dts.sampleOwnershipMismatch(0, base.Add(2*time.Second), 500)
			if streak := dts.consecutiveHighRateWindows(); streak != 0 {
				t.Fatalf("iter %d: old generation sample left streak=%d after reset(1), want 0", iter, streak)
			}
		}
	})
}

// Issue #457: A longer quiet client window must NOT dilute the return-direction drop rate.
// When the return window is 0.25s with 3 drops (12.0 PPS) and the client window is 1.50s with
// 0 drops, ReturnOwnershipMismatchRatePPS() must report 12.0 PPS (not diluted to 2.0 PPS by math.Max),
// and sustained return loss across consecutive windows must escalate to DEGRADED.
func TestReturnOwnershipMismatch_DivergentClientWindowDoesNotDiluteReturnRate(t *testing.T) {
	th := DefaultHealthThresholds

	t.Run("direct_diagnostics_evaluation", func(t *testing.T) {
		// Return window is 0.25s with 3 drops (12.0 PPS, streak 2).
		// Client window is 1.50s with 0 drops (shared math.Max window would be 1.50s -> 2.0 PPS).
		diag := RoutingConsistencyDiagnostics{
			IsConsistent:                                      false,
			OwnershipMismatchDropsRecent:                      3,
			OwnershipMismatchWindowSec:                        1.50, // shared math.Max window
			ReturnOwnershipMismatchWindowSec:                  0.25, // return-specific window
			ReturnOwnershipMismatchConsecutiveHighRateWindows: 2,
		}
		diag.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diag)}

		// Aggregate rate is diluted by the client window (3 / 1.50 = 2.0 PPS).
		aggregateRate := diag.OwnershipMismatchRatePPS()
		if aggregateRate != 2.0 {
			t.Fatalf("expected diluted aggregate rate 2.0 PPS, got %v", aggregateRate)
		}

		// Return-specific rate must NOT be diluted (3 / 0.25 = 12.0 PPS).
		returnRate := diag.ReturnOwnershipMismatchRatePPS()
		if returnRate != 12.0 {
			t.Fatalf("expected ReturnOwnershipMismatchRatePPS() 12.0 PPS, got %v", returnRate)
		}
		if returnRate < th.ReturnOwnershipMismatchDegradedRatePPS {
			t.Fatalf("returnRate %v must meet or exceed degraded threshold %v",
				returnRate, th.ReturnOwnershipMismatchDegradedRatePPS)
		}

		// Severity must escalate to DEGRADED (not falsely downgraded to WARNING).
		conds := evaluateRoutingConditions(diag)
		cond := assertSingleCondition(t, conds, "routing")
		if cond.Severity != "DEGRADED" {
			t.Fatalf("expected DEGRADED severity, got %q: %q", cond.Severity, cond.Message)
		}

		// Headline health must be DEGRADED.
		health := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
			DropCategoryBreakdown{}, quietVirtualTUN(), nil, diag, HandshakeFreshnessDiagnostics{},
			BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})
		if health.Status != HealthDegraded {
			t.Fatalf("headline status=%s, want DEGRADED", health.Status)
		}

		// An isolated single burst (streak = 1) under divergent windows remains WARNING / headline HEALTHY.
		diagSingle := diag
		diagSingle.ReturnOwnershipMismatchConsecutiveHighRateWindows = 1
		condsSingle := evaluateRoutingConditions(diagSingle)
		condSingle := assertSingleCondition(t, condsSingle, "routing")
		if condSingle.Severity != "WARNING" {
			t.Fatalf("single burst under divergent windows severity=%q, want WARNING", condSingle.Severity)
		}
		healthSingle := EvaluateForwarderHealth(true, true, QueuePressureDiagnostics{}, ForwardLatencyDiagnostics{},
			DropCategoryBreakdown{}, quietVirtualTUN(), nil, diagSingle, HandshakeFreshnessDiagnostics{},
			BackendsDiagnostics{HealthyCount: 1, TotalCount: 1, EligibilityKnown: true, EnabledCount: 1})
		if healthSingle.Status != HealthHealthy {
			t.Fatalf("single burst headline status=%s, want HEALTHY", healthSingle.Status)
		}

		// Client mismatch drops under divergent windows strictly evaluate to CRITICAL.
		diagClient := diag
		diagClient.ClientOwnershipMismatchDropsRecent = 1
		diagClient.InconsistencyDetails = []string{describeOwnershipMismatchRecent(&diagClient)}
		condsClient := evaluateRoutingConditions(diagClient)
		condClient := assertSingleCondition(t, condsClient, "routing")
		if condClient.Severity != "CRITICAL" {
			t.Fatalf("mixed client mismatch under divergent windows severity=%q, want CRITICAL", condClient.Severity)
		}
	})

	t.Run("service_assembly_under_divergent_windows", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			svc := &Service{}

			// Client tracker is primed at t0.
			svc.diagDeltas.sampleClientOwnershipMismatch(0, time.Now(), 0)

			// Advance 1250ms, then prime return tracker at t0 + 1250ms.
			time.Sleep(1250 * time.Millisecond)
			svc.diagDeltas.sampleOwnershipMismatch(0, time.Now(), 0)

			// Advance 250ms to t0 + 1500ms: sample window 1 of return tracker.
			// Return window = 250ms, 3 drops = 12 PPS, streak = 1.
			time.Sleep(250 * time.Millisecond)
			snap1 := svc.diagDeltas.sampleOwnershipMismatch(0, time.Now(), 3)
			if snap1.consecutiveHighRateWindows != 1 {
				t.Fatalf("return window 1 streak=%d, want 1", snap1.consecutiveHighRateWindows)
			}

			// Advance 250ms to t0 + 1750ms.
			// At t0 + 1750ms:
			//   Client elapsed window since prime (t0) = 1.75s (0 drops).
			//   Return elapsed window since window 1 (t0 + 1500ms) = 0.25s (3 more drops -> cumulative 6).
			// Calling checkRoutingInvariantsWithInputs simulates the status assembly pass.
			time.Sleep(250 * time.Millisecond)
			inputs := svc.captureDiagnosticsInputs()
			diag := checkRoutingInvariantsWithInputs(svc, inputs, nil, ReturnStatsSnapshot{OwnershipMismatchDrops: 6}, 0)

			if diag.OwnershipMismatchDropsRecent != 3 {
				t.Fatalf("recent return drops=%d, want 3", diag.OwnershipMismatchDropsRecent)
			}
			if diag.ClientOwnershipMismatchDropsRecent != 0 {
				t.Fatalf("recent client drops=%d, want 0", diag.ClientOwnershipMismatchDropsRecent)
			}
			if diag.ReturnOwnershipMismatchConsecutiveHighRateWindows != 2 {
				t.Fatalf("consecutive high rate windows=%d, want 2", diag.ReturnOwnershipMismatchConsecutiveHighRateWindows)
			}
			if diag.ReturnOwnershipMismatchWindowSec != 0.25 {
				t.Fatalf("return-specific window=%.3fs, want 0.25s", diag.ReturnOwnershipMismatchWindowSec)
			}
			if diag.OwnershipMismatchWindowSec < 1.50 {
				t.Fatalf("shared window=%.3fs must be at least 1.50s", diag.OwnershipMismatchWindowSec)
			}

			// Verify return-specific rate is 12.0 PPS and aggregate rate is diluted below 10.0 PPS.
			if diag.ReturnOwnershipMismatchRatePPS() != 12.0 {
				t.Fatalf("ReturnOwnershipMismatchRatePPS()=%.2f, want 12.0", diag.ReturnOwnershipMismatchRatePPS())
			}
			if diag.OwnershipMismatchRatePPS() >= 10.0 {
				t.Fatalf("aggregate rate=%.2f should be diluted below 10.0 PPS", diag.OwnershipMismatchRatePPS())
			}

			// Condition severity must escalate to DEGRADED.
			conds := evaluateRoutingConditions(diag)
			cond := assertSingleCondition(t, conds, "routing")
			if cond.Severity != "DEGRADED" {
				t.Fatalf("severity under divergent service windows=%q, want DEGRADED: %q", cond.Severity, cond.Message)
			}
		})
	})
}
