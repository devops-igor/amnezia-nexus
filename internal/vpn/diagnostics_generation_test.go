package vpn

import (
	"testing"
	"testing/synctest"
	"time"
)

// This file pins issue #429 review blocker 1: the diagnostics cumulative
// trackers are generation-aware. Every Start after Stop is an explicit new
// generation; within a generation the accepted baselines are monotonic, so an
// out-of-order observation can never rewind them, and a lifecycle reset
// re-primes instead of inferring a restart from counters that moved backwards.

// TestDiagGeneration_OutOfOrderNeverRewindsBaselines drives one tracker per
// cumulative diagnostics population through the same out-of-order scenario:
// rising counters, one LOWER observation (the restart epoch replaying), then
// the return to the higher value. In every case the lower observation must
// report no fresh loss and must leave the accepted baseline untouched.
func TestDiagGeneration_OutOfOrderNeverRewindsBaselines(t *testing.T) {
	t.Run("aggregate_rates", func(t *testing.T) {
		tk := newDiagRatesTracker()
		base := time.Now()

		// Window 1: 100 -> 110 over 1s.
		tk.Sample(base, 100, 100, 200, 10)
		tk.Sample(base.Add(1*time.Second), 110, 110, 220, 12)

		// Out-of-order: the pre-restart observation (100) replays AFTER the
		// higher one was accepted. It must report zero rates...
		c, r, tot, w := tk.Sample(base.Add(2*time.Second), 100, 100, 200, 10)
		if c != 0 || r != 0 || tot != 0 || w != 0 {
			t.Fatalf("lower observation must report zero rates, got client=%v return=%v total=%v writeErr=%v", c, r, tot, w)
		}
		// ...and must not rewind the baseline: the counters return to 110 and
		// the delta must still be zero (no replayed "fresh" loss).
		c, r, tot, w = tk.Sample(base.Add(3*time.Second), 110, 110, 220, 12)
		if c != 0 || r != 0 || tot != 0 || w != 0 {
			t.Fatalf("activity up to the accepted baseline must not replay as fresh loss, got client=%v return=%v total=%v writeErr=%v", c, r, tot, w)
		}
	})

	t.Run("per_reason_drops", func(t *testing.T) {
		var tr dropReasonRatesTracker
		base := time.Now()

		// Window 1: 100 -> 110 for client_queue_full over 1s.
		tr.sample(base, map[string]uint64{"client_queue_full": 100})
		rates, avail := tr.sample(base.Add(1*time.Second), map[string]uint64{"client_queue_full": 110})
		if !avail || rates["client_queue_full"] != 10 {
			t.Fatalf("window 1: want rate 10 avail true, got %v avail=%v", rates, avail)
		}

		// Out-of-order: the pre-restart total 100 replays after 110 was
		// accepted. It must report a zero rate and keep 110 accepted.
		rates, avail = tr.sample(base.Add(2*time.Second), map[string]uint64{"client_queue_full": 100})
		if avail && rates["client_queue_full"] != 0 {
			t.Fatalf("lower observation must report a zero rate, got %v avail=%v", rates, avail)
		}
		// Back to 110: still zero — the baseline was never rewound.
		rates, avail = tr.sample(base.Add(3*time.Second), map[string]uint64{"client_queue_full": 110})
		if avail && rates["client_queue_full"] != 0 {
			t.Fatalf("activity up to the accepted baseline must not replay, got %v avail=%v", rates, avail)
		}
	})

	t.Run("ownership_mismatch_delta", func(t *testing.T) {
		var dts diagDeltaTrackers
		base := time.Now()

		// Window 1: 100 -> 110 over 1s.
		dts.sampleOwnershipMismatch(base, 100)
		first := dts.sampleOwnershipMismatch(base.Add(1*time.Second), 110)
		if first.delta != 10 {
			t.Fatalf("window 1: want delta 10, got %d", first.delta)
		}

		// Out-of-order: pre-restart observation 100 replays, then 110 again.
		replay := dts.sampleOwnershipMismatch(base.Add(2*time.Second), 100)
		if replay.delta != 0 {
			t.Fatalf("lower observation must report zero delta, got %d", replay.delta)
		}
		again := dts.sampleOwnershipMismatch(base.Add(3*time.Second), 110)
		if again.delta != 0 {
			t.Fatalf("activity up to the accepted baseline must not replay as fresh delta, got %d", again.delta)
		}
	})
}

// TestDiagGeneration_LifecycleResetsReprime is the deterministic Stop->Start
// lifecycle regression: foreground AND history rates recorded after the reset
// must be computed only from post-start generations — never from pre-start
// totals, in EITHER direction (inflated by old totals, or swallowed by a
// rewound baseline). The synctest bubble gives a deterministic clock, so the
// windows have exactly the elapsed times the test sleeps.
func TestDiagGeneration_LifecycleResetsReprime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := &Service{rollingHistory: NewRollingHistory()}
		if svc.diagGeneration != 0 {
			t.Fatalf("fresh service must start at generation 0, got %d", svc.diagGeneration)
		}
		svc.diagRates = newDiagRatesTracker()

		// --- Pre-start era (generation 0): real activity, baselines live. ---
		base := time.Now()
		svc.diagRates.Sample(base, 100, 100, 200, 10)
		svc.diagRates.Sample(base.Add(1*time.Second), 110, 110, 220, 12)
		svc.diagDeltas.sampleOwnershipMismatch(base, 100)
		svc.diagDeltas.sampleOwnershipMismatch(base.Add(1*time.Second), 110)
		svc.sampleHistoryDropRates(base, &DropCategoryBreakdown{})
		svc.sampleHistoryDropRates(base.Add(1*time.Second), &DropCategoryBreakdown{ClientTotalDrops: 100, TotalDrops: 100})

		// --- Stop->Start: the production lifecycle reset. ---
		// (Service.Start itself needs the full engine stack;
		// resetDiagnosticsGeneration is exactly the diagnostics part of it.)
		svc.resetDiagnosticsGeneration()
		if svc.diagGeneration != 1 {
			t.Fatalf("reset must advance the generation to 1, got %d", svc.diagGeneration)
		}

		// --- Post-start era (generation 1): counters restarted from zero. ---
		// Foreground trackers re-prime lazily from the post-start counters;
		// history baselines were re-primed eagerly by the reset itself.
		post := time.Now()
		svc.diagRates.Sample(post, 0, 0, 0, 0) // prime gen 1 from zero
		rc, rr, rt, rw := svc.diagRates.Sample(post.Add(1*time.Second), 0, 5, 5, 0)
		if rc != 0 || rr != 5 || rt != 5 || rw != 0 {
			t.Fatalf("post-start foreground rates must come only from post-start counters, got client=%v return=%v total=%v writeErr=%v", rc, rr, rt, rw)
		}

		svc.diagDeltas.sampleOwnershipMismatch(post, 0) // prime gen 1
		d := svc.diagDeltas.sampleOwnershipMismatch(post.Add(1*time.Second), 3)
		if d.delta != 3 {
			t.Fatalf("post-start delta must come only from post-start activity, got %d", d.delta)
		}

		svc.sampleHistoryDropRates(post, &DropCategoryBreakdown{})
		drops := DropCategoryBreakdown{ReturnTotalDrops: 4, TotalDrops: 4}
		svc.sampleHistoryDropRates(post.Add(1*time.Second), &drops)
		if !drops.RatesAvailable {
			t.Fatal("post-start history window must be available")
		}
		if drops.ReturnDropRatePps != 4 || drops.TotalDropRatePps != 4 || drops.ClientDropRatePps != 0 {
			t.Fatalf("post-start history rates must come only from post-start counters, got client=%v return=%v total=%v",
				drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.TotalDropRatePps)
		}
	})
}

// TestDiagGeneration_HistoryPrimingIsGenerationKeyed pins the helper pair the
// primeHistoryFromDrops gate is built on: priming is recorded per generation,
// a generation bump invalidates it by itself, and re-priming records the new
// generation — including a fresh service priming at generation 0.
func TestDiagGeneration_HistoryPrimingIsGenerationKeyed(t *testing.T) {
	svc := &Service{}

	svc.diagRatesMu.Lock()
	if svc.historyPrimedForCurrentGenerationLocked() {
		svc.diagRatesMu.Unlock()
		t.Fatal("fresh service must not report primed history")
	}
	svc.markHistoryPrimedForCurrentGenerationLocked(time.Now(), &DropCategoryBreakdown{})
	if !svc.historyPrimedForCurrentGenerationLocked() {
		svc.diagRatesMu.Unlock()
		t.Fatal("history must be primed for generation 0 after marking")
	}
	svc.diagRatesMu.Unlock()

	// A lifecycle reset moves the generation: the recorded priming no longer
	// matches, so history must re-prime.
	svc.resetDiagnosticsGeneration()

	svc.diagRatesMu.Lock()
	if svc.historyPrimedForCurrentGenerationLocked() {
		svc.diagRatesMu.Unlock()
		t.Fatal("history must be un-primed after the generation bump")
	}
	svc.markHistoryPrimedForCurrentGenerationLocked(time.Now(), &DropCategoryBreakdown{})
	if !svc.historyPrimedForCurrentGenerationLocked() {
		svc.diagRatesMu.Unlock()
		t.Fatal("history must re-prime into the new generation")
	}
	svc.diagRatesMu.Unlock()
}

// TestDiagGeneration_HistoryRatesComputedOnlyFromPostStartGeneration drives the
// production history sampling entry point across a lifecycle reset with a
// deterministic clock: history rates recorded after the reset must be computed
// only from post-reset generations, never from pre-start totals.
func TestDiagGeneration_HistoryRatesComputedOnlyFromPostStartGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := &Service{rollingHistory: NewRollingHistory()}

		base := time.Now()
		// Pre-start history sampling: prime at gen 0, then a live window.
		svc.sampleHistoryDropRates(base, &DropCategoryBreakdown{})
		svc.sampleHistoryDropRates(base.Add(1*time.Second), &DropCategoryBreakdown{ClientTotalDrops: 100, TotalDrops: 100})

		// Lifecycle reset (the diagnostics part of Stop->Start).
		svc.resetDiagnosticsGeneration()

		// Post-start sampling with counters restarted from zero: the first
		// sample re-primes, the second records the window.
		post := time.Now()
		svc.sampleHistoryDropRates(post, &DropCategoryBreakdown{})
		drops := DropCategoryBreakdown{ReturnTotalDrops: 4, TotalDrops: 4}
		svc.sampleHistoryDropRates(post.Add(1*time.Second), &drops)
		if !drops.RatesAvailable {
			t.Fatal("post-start history window must be available")
		}
		if drops.ReturnDropRatePps != 4 || drops.TotalDropRatePps != 4 || drops.ClientDropRatePps != 0 {
			t.Fatalf("post-start history rates must come only from post-start counters, got client=%v return=%v total=%v",
				drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.TotalDropRatePps)
		}
	})
}
