package vpn

import (
	"math"
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
		tk.Sample(0, base, 100, 100, 200, 10)
		tk.Sample(0, base.Add(1*time.Second), 110, 110, 220, 12)

		// Out-of-order: the pre-restart observation (100) replays AFTER the
		// higher one was accepted. It is rejected wholesale (round 3, blocker
		// 2: a fully stale observation mutates nothing), so the tracker keeps
		// publishing the LAST ACCEPTED window — 10 pps — and the replay
		// contributes no fresh loss.
		c, r, tot, w := tk.Sample(0, base.Add(2*time.Second), 100, 100, 200, 10)
		if c != 10 || r != 10 || tot != 20 || w != 2 {
			t.Fatalf("lower observation must keep the last accepted rates, got client=%v return=%v total=%v writeErr=%v", c, r, tot, w)
		}
		// ...and must not rewind the baseline: the counters return to 110 and
		// the delta must still be zero (no replayed "fresh" loss).
		c, r, tot, w = tk.Sample(0, base.Add(3*time.Second), 110, 110, 220, 12)
		if c != 0 || r != 0 || tot != 0 || w != 0 {
			t.Fatalf("activity up to the accepted baseline must not replay as fresh loss, got client=%v return=%v total=%v writeErr=%v", c, r, tot, w)
		}
	})

	t.Run("per_reason_drops", func(t *testing.T) {
		var tr dropReasonRatesTracker
		base := time.Now()

		// Window 1: 100 -> 110 for client_queue_full over 1s.
		tr.sample(0, base, map[string]uint64{"client_queue_full": 100})
		rates, avail := tr.sample(0, base.Add(1*time.Second), map[string]uint64{"client_queue_full": 110})
		if !avail || rates["client_queue_full"] != 10 {
			t.Fatalf("window 1: want rate 10 avail true, got %v avail=%v", rates, avail)
		}

		// Out-of-order: the pre-restart total 100 replays after 110 was
		// accepted. The stale observation is rejected wholesale (round 3,
		// blocker 2: nothing mutates), so the tracker keeps publishing the
		// last accepted window's rate and keeps 110 accepted.
		rates, avail = tr.sample(0, base.Add(2*time.Second), map[string]uint64{"client_queue_full": 100})
		if !avail || rates["client_queue_full"] != 10 {
			t.Fatalf("lower observation must keep the last accepted rate, got %v avail=%v", rates, avail)
		}
		// Back to 110: still zero — the baseline was never rewound.
		rates, avail = tr.sample(0, base.Add(3*time.Second), map[string]uint64{"client_queue_full": 110})
		if avail && rates["client_queue_full"] != 0 {
			t.Fatalf("activity up to the accepted baseline must not replay, got %v avail=%v", rates, avail)
		}
	})

	t.Run("ownership_mismatch_delta", func(t *testing.T) {
		var dts diagDeltaTrackers
		base := time.Now()

		// Window 1: 100 -> 110 over 1s.
		dts.sampleOwnershipMismatch(0, base, 100)
		first := dts.sampleOwnershipMismatch(0, base.Add(1*time.Second), 110)
		if first.delta != 10 {
			t.Fatalf("window 1: want delta 10, got %d", first.delta)
		}

		// Out-of-order: pre-restart observation 100 replays, then 110 again.
		// The stale observation is rejected wholesale (round 3, blocker 2:
		// nothing mutates), so the PREVIOUS accepted snapshot is returned.
		replay := dts.sampleOwnershipMismatch(0, base.Add(2*time.Second), 100)
		if replay.delta != 10 {
			t.Fatalf("lower observation must keep the last accepted delta, got %d", replay.delta)
		}
		again := dts.sampleOwnershipMismatch(0, base.Add(3*time.Second), 110)
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
		if svc.diagGeneration.Load() != 0 {
			t.Fatalf("fresh service must start at generation 0, got %d", svc.diagGeneration.Load())
		}
		svc.diagRates = newDiagRatesTracker()

		// --- Pre-start era (generation 0): real activity, baselines live. ---
		base := time.Now()
		svc.diagRates.Sample(0, base, 100, 100, 200, 10)
		svc.diagRates.Sample(0, base.Add(1*time.Second), 110, 110, 220, 12)
		svc.diagDeltas.sampleOwnershipMismatch(0, base, 100)
		svc.diagDeltas.sampleOwnershipMismatch(0, base.Add(1*time.Second), 110)
		svc.sampleHistoryDropRates(0, base, &DropCategoryBreakdown{})
		svc.sampleHistoryDropRates(0, base.Add(1*time.Second), &DropCategoryBreakdown{ClientTotalDrops: 100, TotalDrops: 100})

		// --- Stop->Start: the production lifecycle reset. ---
		// (Service.Start itself needs the full engine stack;
		// resetDiagnosticsGeneration is exactly the diagnostics part of it.)
		svc.resetDiagnosticsGeneration()
		if svc.currentDiagGeneration() != 1 {
			t.Fatalf("reset must advance the generation to 1, got %d", svc.currentDiagGeneration())
		}

		// --- Post-start era (generation 1): counters restarted from zero. ---
		// Foreground trackers re-prime lazily from the post-start counters;
		// history baselines were re-primed eagerly by the reset itself.
		post := time.Now()
		svc.diagRates.Sample(1, post, 0, 0, 0, 0) // prime gen 1 from zero
		rc, rr, rt, rw := svc.diagRates.Sample(1, post.Add(1*time.Second), 0, 5, 5, 0)
		if rc != 0 || rr != 5 || rt != 5 || rw != 0 {
			t.Fatalf("post-start foreground rates must come only from post-start counters, got client=%v return=%v total=%v writeErr=%v", rc, rr, rt, rw)
		}

		svc.diagDeltas.sampleOwnershipMismatch(1, post, 0) // prime gen 1
		d := svc.diagDeltas.sampleOwnershipMismatch(1, post.Add(1*time.Second), 3)
		if d.delta != 3 {
			t.Fatalf("post-start delta must come only from post-start activity, got %d", d.delta)
		}

		svc.sampleHistoryDropRates(1, post, &DropCategoryBreakdown{})
		drops := DropCategoryBreakdown{ReturnTotalDrops: 4, TotalDrops: 4}
		svc.sampleHistoryDropRates(1, post.Add(1*time.Second), &drops)
		if !drops.RatesAvailable {
			t.Fatal("post-start history window must be available")
		}
		if drops.ReturnDropRatePps != 4 || drops.TotalDropRatePps != 4 || drops.ClientDropRatePps != 0 {
			t.Fatalf("post-start history rates must come only from post-start counters, got client=%v return=%v total=%v",
				drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.ClientDropRatePps)
		}
	})
}

// TestGenerationWindow_FullyStaleObservationNeverAdvancesWindow pins review
// round 3, blocker 2 with the review's exact numbers: accepted 110@t1, fully
// stale 100@t10, valid 120@t10.2. The stale observation must return
// accepted=false and change nothing, so the valid window keeps its true
// denominator (9.2s) instead of the corrupted 0.2s the pre-fix semantics
// produced (10 pps over 0.2s = 50/s instead of the true rate).
func TestGenerationWindow_FullyStaleObservationNeverAdvancesWindow(t *testing.T) {
	t.Run("primitive_single_counter", func(t *testing.T) {
		var w generationWindow[uint64]
		base := time.Now()
		w.sample(0, base, []uint64{100}) // prime
		if !w.sample(0, base.Add(1*time.Second), []uint64{110}) {
			t.Fatal("window 1 must be accepted")
		}
		if w.sample(0, base.Add(10*time.Second), []uint64{100}) {
			t.Fatal("fully stale observation must return accepted=false")
		}
		accepted := w.sample(0, base.Add(10200*time.Millisecond), []uint64{120})
		if !accepted {
			t.Fatal("valid observation must be accepted")
		}
		deltas, windowSec, primed := w.last()
		if !primed {
			t.Fatal("window must be primed")
		}
		if deltas[0] != 10 {
			t.Fatalf("delta=%d, want 10 (120-110): the stale read must not re-baseline", deltas[0])
		}
		// The denominator: 10.2s - 1s = 9.2s. Pre-fix the stale read advanced
		// the anchor and the denominator became 0.2s.
		if math.Abs(windowSec-9.2) > 1e-9 {
			t.Fatalf("window=%v, want 9.2: a stale observation must not consume the denominator", windowSec)
		}
	})

	t.Run("primitive_partial_stale_advances", func(t *testing.T) {
		// Whole-vector monotonicity (issue #429 review round 7): any counter
		// below baseline must cause wholesale rejection of the observation,
		// leaving baselines, timestamp, and published deltas untouched.
		var w generationWindow[float64]
		base := time.Now()
		w.sample(0, base, []uint64{100, 200})
		if !w.sample(0, base.Add(1*time.Second), []uint64{110, 210}) {
			t.Fatal("window 1 must be accepted")
		}
		// counter[1] replays stale (200 < 210) while counter[0] genuinely advanced (130 >= 110).
		// Whole-vector monotonicity requires wholesale rejection.
		if w.sample(0, base.Add(2*time.Second), []uint64{130, 200}) {
			t.Fatal("partially stale observation must be rejected wholesale")
		}
		deltas, windowSec, primed := w.last()
		if !primed {
			t.Fatal("window must be primed")
		}
		if deltas[0] != 10 || deltas[1] != 10 {
			t.Fatalf("deltas=%v, want [10 10]: rejected sample must not mutate published deltas", deltas)
		}
		if math.Abs(windowSec-1.0) > 1e-9 {
			t.Fatalf("window=%v, want 1.0: rejected sample must not mutate window length", windowSec)
		}
		if !w.at.Equal(base.Add(1 * time.Second)) {
			t.Fatalf("anchor moved: got %v, want %v", w.at, base.Add(1*time.Second))
		}
		if w.baseline[0] != 110 || w.baseline[1] != 210 {
			t.Fatalf("baseline mutated: got %v, want [110 210]", w.baseline)
		}

		// Subsequent genuine sample retains original denominator: 3s - 1s = 2s.
		if !w.sample(0, base.Add(3*time.Second), []uint64{130, 220}) {
			t.Fatal("subsequent genuine observation must be accepted")
		}
		deltas, windowSec, _ = w.last()
		if deltas[0] != 20 || deltas[1] != 10 {
			t.Fatalf("deltas=%v, want [20 10] (130-110, 220-210)", deltas)
		}
		if math.Abs(windowSec-2.0) > 1e-9 {
			t.Fatalf("window=%v, want 2.0: denominator must be preserved across rejected sample", windowSec)
		}
	})

	t.Run("aggregate_rates_tracker", func(t *testing.T) {
		tk := newDiagRatesTracker()
		base := time.Now()
		tk.Sample(0, base, 100, 100, 200, 10)
		c, r, tot, w := tk.Sample(0, base.Add(1*time.Second), 110, 110, 220, 12)
		if c != 10 || r != 10 || tot != 20 || w != 2 {
			t.Fatalf("window 1: want 10/10/20/2 pps, got %v %v %v %v", c, r, tot, w)
		}
		// Fully stale across every counter: rejected, so the tracker keeps
		// publishing the previous window's rates unchanged.
		c, r, tot, w = tk.Sample(0, base.Add(10*time.Second), 100, 100, 200, 10)
		if c != 10 || r != 10 || tot != 20 || w != 2 {
			t.Fatalf("fully stale observation must keep the previous rates, got %v %v %v %v", c, r, tot, w)
		}
		// The valid observation 0.2s later keeps its true denominator: the
		// same 10-count growth over 9.2s, not 50/s over the corrupted 0.2s.
		c, r, tot, w = tk.Sample(0, base.Add(10200*time.Millisecond), 120, 120, 240, 14)
		if math.Abs(c-10/9.2) > 1e-9 || math.Abs(r-10/9.2) > 1e-9 ||
			math.Abs(tot-20/9.2) > 1e-9 || math.Abs(w-2/9.2) > 1e-9 {
			t.Fatalf("rates must use the preserved denominator (9.2s), got client=%v return=%v total=%v writeErr=%v", c, r, tot, w)
		}
	})

	t.Run("per_reason_windows", func(t *testing.T) {
		// diagCounterWindows must mirror the primitive: a fully stale set
		// advances neither the per-key windows nor the shared window. Per the
		// documented contract the stale counter's published delta is ZEROED
		// for that window (baseline untouched), so the tracker publishes a
		// zero rate while availability is retained.
		var tr dropReasonRatesTracker
		base := time.Now()
		tr.sample(0, base, map[string]uint64{"client_malformed": 100})
		rates, avail := tr.sample(0, base.Add(1*time.Second), map[string]uint64{"client_malformed": 110})
		if !avail || rates["client_malformed"] != 10 {
			t.Fatalf("window 1: want rate 10, got %v avail=%v", rates, avail)
		}
		rates, avail = tr.sample(0, base.Add(10*time.Second), map[string]uint64{"client_malformed": 100})
		if !avail {
			t.Fatal("availability must survive a stale observation")
		}
		if rates["client_malformed"] != 10 {
			t.Fatalf("stale observation must keep the last accepted rate, got %v", rates["client_malformed"])
		}
		rates, avail = tr.sample(0, base.Add(10200*time.Millisecond), map[string]uint64{"client_malformed": 120})
		if !avail {
			t.Fatal("valid window must keep availability")
		}
		if math.Abs(rates["client_malformed"]-10/9.2) > 1e-9 {
			t.Fatalf("rate=%v, want ~%v: the shared window must keep its true denominator (9.2s), not the corrupted 0.2s",
				rates["client_malformed"], 10/9.2)
		}
	})

	t.Run("delta_tracker", func(t *testing.T) {
		var dts diagDeltaTrackers
		base := time.Now()
		dts.sampleOwnershipMismatch(0, base, 100)
		first := dts.sampleOwnershipMismatch(0, base.Add(1*time.Second), 110)
		if first.delta != 10 {
			t.Fatalf("window 1: want delta 10, got %d", first.delta)
		}
		stale := dts.sampleOwnershipMismatch(0, base.Add(10*time.Second), 100)
		if stale.delta != 10 || stale.windowSeconds != 1 {
			t.Fatalf("stale observation must return the PREVIOUS snapshot unchanged, got %+v", stale)
		}
		valid := dts.sampleOwnershipMismatch(0, base.Add(10200*time.Millisecond), 120)
		if valid.delta != 10 {
			t.Fatalf("valid delta=%d, want 10", valid.delta)
		}
		if math.Abs(valid.windowSeconds-9.2) > 1e-9 {
			t.Fatalf("valid windowSeconds=%v, want 9.2: the stale read must not consume the denominator", valid.windowSeconds)
		}
	})
}

// TestGenerationWindow_CrossGenerationSnapshotLeavesNoTrace pins the
// generation gate end to end (review round 3 regression 2): a diagnostics
// snapshot request that overlaps a lifecycle reset must not move ANY
// new-generation sampler — baseline, anchor or window — when it completes
// after the reset. The in-flight request captured the old generation tag
// before the reset; completing it later must be a no-op against every
// new-generation sampler.
func TestGenerationWindow_CrossGenerationSnapshotLeavesNoTrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tk diagDeltaTracker
		base := time.Now()

		// Generation 0: live baselines.
		tk.Sample(0, base, 100)
		first := tk.Sample(0, base.Add(1*time.Second), 110)
		if first.delta != 10 {
			t.Fatalf("window 1: want delta 10, got %+v", first)
		}
		// The in-flight snapshot request captured its generation and its
		// (pre-reset) observation time before the lifecycle reset happened.
		capturedGen := diagGeneration(0) // the generation travels with the observation (round 4)
		capturedAt := base.Add(10 * time.Second)

		// Stop->Start: the production lifecycle reset, then the new
		// generation is primed from post-start counters.
		tk.reset(1)
		post := time.Now()
		tk.Sample(1, post, 0)                            // prime gen 1
		snap := tk.Sample(1, post.Add(1*time.Second), 3) // first gen-1 window
		if snap.delta != 3 {
			t.Fatalf("gen 1 must prime from post-start counters, got %+v", snap)
		}

		// The old request completes now, tagged with its captured generation.
		if tk.window.sample(capturedGen, capturedAt, []uint64{110}) {
			t.Fatal("a completed pre-reset request must be rejected by the generation gate")
		}
		// ZERO trace: the new-generation window is exactly as the last
		// accepted gen-1 sample left it.
		deltas, windowSec, primed := tk.window.last()
		if !primed || deltas[0] != 3 || math.Abs(windowSec-1) > 1e-9 {
			t.Fatalf("stale completion moved the new-generation sampler: deltas=%v window=%v primed=%v", deltas, windowSec, primed)
		}

		// The next live sample still sees the gen-1 baseline (3), not one
		// rewound to the pre-reset 110.
		next := tk.Sample(1, post.Add(2*time.Second), 7)
		if next.delta != 4 {
			t.Fatalf("post-stale delta=%d, want 4 (7-3): the stale request must not have re-baselined the new generation", next.delta)
		}
		if math.Abs(next.windowSeconds-1) > 1e-9 {
			t.Fatalf("windowSeconds=%v, want 1: the stale request must not have moved the anchor", next.windowSeconds)
		}
	})
}

// TestDiagGeneration_HistoryPrimingIsGenerationKeyed pins the generation
// keying of the priming gate: priming is recorded per generation via the
// production entry point, a generation bump invalidates it by itself, and
// re-priming records the new generation — including a fresh service priming
// at generation 0. (The mark primitive was removed in review round 5: it
// substituted the tracker-current generation for the observation's, letting
// a stale snapshot mark the new generation.)
func TestDiagGeneration_HistoryPrimingIsGenerationKeyed(t *testing.T) {
	svc := &Service{}
	now := time.Now()

	svc.primeHistoryFromDrops(now, nil, 0, DropCategoryBreakdown{})
	svc.diagRatesMu.Lock()
	if !svc.historyPrimedForCurrentGenerationLocked() {
		svc.diagRatesMu.Unlock()
		t.Fatal("fresh service must report primed history for generation 0 after priming")
	}
	if svc.historyPrimedGen != 0 {
		svc.diagRatesMu.Unlock()
		t.Fatalf("historyPrimedGen=%d, want 0", svc.historyPrimedGen)
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
	svc.diagRatesMu.Unlock()

	svc.primeHistoryFromDrops(now, nil, svc.currentDiagGeneration(), DropCategoryBreakdown{})
	svc.diagRatesMu.Lock()
	defer svc.diagRatesMu.Unlock()
	if !svc.historyPrimedForCurrentGenerationLocked() {
		t.Fatal("history must re-prime into the new generation")
	}
	if want := svc.currentDiagGeneration(); svc.historyPrimedGen != want {
		t.Fatalf("historyPrimedGen=%d, want %d", svc.historyPrimedGen, want)
	}
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
		svc.sampleHistoryDropRates(0, base, &DropCategoryBreakdown{})
		svc.sampleHistoryDropRates(0, base.Add(1*time.Second), &DropCategoryBreakdown{ClientTotalDrops: 100, TotalDrops: 100})

		// Lifecycle reset (the diagnostics part of Stop->Start).
		svc.resetDiagnosticsGeneration()

		// Post-start sampling with counters restarted from zero: the first
		// sample re-primes, the second records the window.
		post := time.Now()
		svc.sampleHistoryDropRates(1, post, &DropCategoryBreakdown{})
		drops := DropCategoryBreakdown{ReturnTotalDrops: 4, TotalDrops: 4}
		svc.sampleHistoryDropRates(1, post.Add(1*time.Second), &drops)
		if !drops.RatesAvailable {
			t.Fatal("post-start history window must be available")
		}
		if drops.ReturnDropRatePps != 4 || drops.TotalDropRatePps != 4 || drops.ClientDropRatePps != 0 {
			t.Fatalf("post-start history rates must come only from post-start counters, got client=%v return=%v total=%v",
				drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.TotalDropRatePps)
		}
	})
}

// TestGenerationWindow_WholeVectorMonotonicity pins issue #424 round 7
// remediation: whole-vector monotonicity across generationWindow.
func TestGenerationWindow_WholeVectorMonotonicity(t *testing.T) {
	t.Run("lower_plus_equal", func(t *testing.T) {
		// 1. Lower + Equal:
		// Baseline: [110, 200, 10]
		// Stale observation: [100, 200, 10]
		// Verification: Rejected (accepted == false), timestamp and baselines unchanged.
		var w generationWindow[uint64]
		base := time.Now()
		w.sample(0, base, []uint64{100, 190, 5}) // prime
		if !w.sample(0, base.Add(1*time.Second), []uint64{110, 200, 10}) {
			t.Fatal("window 1 must be accepted")
		}
		anchor1 := base.Add(1 * time.Second)

		// Stale observation: counter 0 lower (100 < 110), counters 1 and 2 equal (200, 10)
		accepted := w.sample(0, base.Add(2*time.Second), []uint64{100, 200, 10})
		if accepted {
			t.Fatal("lower+equal observation must be rejected")
		}
		if !w.at.Equal(anchor1) {
			t.Fatalf("at=%v, want %v: timestamp must not mutate", w.at, anchor1)
		}
		wantBaselines := []uint64{110, 200, 10}
		for i, want := range wantBaselines {
			if w.baseline[i] != want {
				t.Fatalf("baseline[%d]=%d, want %d", i, w.baseline[i], want)
			}
		}
		deltas, windowSec, primed := w.last()
		if !primed || deltas[0] != 10 || deltas[1] != 10 || deltas[2] != 5 || math.Abs(windowSec-1.0) > 1e-9 {
			t.Fatalf("last window mutated by rejected sample: deltas=%v window=%v", deltas, windowSec)
		}
	})

	t.Run("lower_plus_greater", func(t *testing.T) {
		// 2. Lower + Greater:
		// Baseline: [110, 200]
		// Stale observation: [100, 220]
		// Verification: Rejected wholesale (accepted == false), baseline and timestamp unchanged.
		var w generationWindow[uint64]
		base := time.Now()
		w.sample(0, base, []uint64{100, 190}) // prime
		if !w.sample(0, base.Add(1*time.Second), []uint64{110, 200}) {
			t.Fatal("window 1 must be accepted")
		}
		anchor1 := base.Add(1 * time.Second)

		// Stale observation: counter 0 lower (100 < 110), counter 1 greater (220 >= 200)
		accepted := w.sample(0, base.Add(2*time.Second), []uint64{100, 220})
		if accepted {
			t.Fatal("lower+greater observation must be rejected wholesale")
		}
		if !w.at.Equal(anchor1) {
			t.Fatalf("at=%v, want %v: timestamp must not mutate", w.at, anchor1)
		}
		if w.baseline[0] != 110 || w.baseline[1] != 200 {
			t.Fatalf("baseline=%v, want [110 200]", w.baseline)
		}
		deltas, windowSec, primed := w.last()
		if !primed || deltas[0] != 10 || deltas[1] != 10 || math.Abs(windowSec-1.0) > 1e-9 {
			t.Fatalf("last window mutated by rejected sample: deltas=%v window=%v", deltas, windowSec)
		}
	})

	t.Run("all_equal", func(t *testing.T) {
		// 3. All Equal:
		// Baseline: [110, 200]
		// Observation: [110, 200] after sample floor
		// Verification: Accepted (accepted == true), deltas [0, 0], rates compute to 0.
		var w generationWindow[float64]
		base := time.Now()
		w.sample(0, base, []uint64{100, 190}) // prime
		if !w.sample(0, base.Add(1*time.Second), []uint64{110, 200}) {
			t.Fatal("window 1 must be accepted")
		}

		// Observation with all counters equal after sample floor (1s elapsed >= 200ms)
		accepted := w.sample(0, base.Add(2*time.Second), []uint64{110, 200})
		if !accepted {
			t.Fatal("all-equal observation after floor must be accepted")
		}
		deltas, windowSec, primed := w.last()
		if !primed {
			t.Fatal("window must be primed")
		}
		if deltas[0] != 0 || deltas[1] != 0 {
			t.Fatalf("deltas=%v, want [0 0]", deltas)
		}
		if math.Abs(windowSec-1.0) > 1e-9 {
			t.Fatalf("windowSec=%v, want 1.0", windowSec)
		}
		if !w.at.Equal(base.Add(2 * time.Second)) {
			t.Fatalf("at=%v, want %v", w.at, base.Add(2*time.Second))
		}
		rate0 := deltas[0] / windowSec
		rate1 := deltas[1] / windowSec
		if rate0 != 0 || rate1 != 0 {
			t.Fatalf("rates must compute to 0, got %v %v", rate0, rate1)
		}
	})

	t.Run("greater_plus_equal", func(t *testing.T) {
		// 4. Greater + Equal:
		// Baseline: [110, 200]
		// Observation: [120, 200] after sample floor
		// Verification: Accepted, deltas [10, 0], baselines [120, 200].
		var w generationWindow[uint64]
		base := time.Now()
		w.sample(0, base, []uint64{100, 190}) // prime
		if !w.sample(0, base.Add(1*time.Second), []uint64{110, 200}) {
			t.Fatal("window 1 must be accepted")
		}

		accepted := w.sample(0, base.Add(2*time.Second), []uint64{120, 200})
		if !accepted {
			t.Fatal("greater+equal observation must be accepted")
		}
		deltas, windowSec, primed := w.last()
		if !primed {
			t.Fatal("window must be primed")
		}
		if deltas[0] != 10 || deltas[1] != 0 {
			t.Fatalf("deltas=%v, want [10 0]", deltas)
		}
		if math.Abs(windowSec-1.0) > 1e-9 {
			t.Fatalf("windowSec=%v, want 1.0", windowSec)
		}
		if w.baseline[0] != 120 || w.baseline[1] != 200 {
			t.Fatalf("baseline=%v, want [120 200]", w.baseline)
		}
		if !w.at.Equal(base.Add(2 * time.Second)) {
			t.Fatalf("at=%v, want %v", w.at, base.Add(2*time.Second))
		}
	})
}

// TestDiagRatesTracker_WholeVectorMonotonicity_NoRateInflation pins issue #424
// round 7 regression 6: production-level diagRatesTracker must reject an older
// same-generation lower+equal snapshot, leaving headline drop/write-error rates,
// baselines, and timestamp unaffected, so the next genuine sample preserves its
// full denominator without rate inflation.
func TestDiagRatesTracker_WholeVectorMonotonicity_NoRateInflation(t *testing.T) {
	tk := newDiagRatesTracker()
	base := time.Now()

	// 1. Prime generation 0
	tk.Sample(0, base, 100, 100, 200, 10)

	// 2. Establish baseline at t1 = base + 1s
	t1 := base.Add(1 * time.Second)
	// clientDrops: 100 -> 110 (+10)
	// returnDrops: 100 -> 110 (+10)
	// totalDrops: 200 -> 220 (+20)
	// writeErrors: 10 -> 12 (+2)
	c1, r1, tot1, w1 := tk.Sample(0, t1, 110, 110, 220, 12)
	if c1 != 10 || r1 != 10 || tot1 != 20 || w1 != 2 {
		t.Fatalf("window 1: want 10/10/20/2 pps, got %v %v %v %v", c1, r1, tot1, w1)
	}

	// 3. Stale same-generation lower+equal observation at tStale = base + 10s
	// e.g. clientDrops lower (105 < 110), others equal (returnDrops=110, totalDrops=220, writeErrors=12)
	tStale := base.Add(10 * time.Second)
	cStale, rStale, totStale, wStale := tk.Sample(0, tStale, 105, 110, 220, 12)
	if cStale != 10 || rStale != 10 || totStale != 20 || wStale != 2 {
		t.Fatalf("stale sample must keep previous rates, got %v %v %v %v", cStale, rStale, totStale, wStale)
	}
	if !tk.lastSampleTime.Equal(t1) {
		t.Fatalf("lastSampleTime mutated: got %v, want %v", tk.lastSampleTime, t1)
	}
	if !tk.window.at.Equal(t1) {
		t.Fatalf("window.at mutated: got %v, want %v", tk.window.at, t1)
	}
	wantBaselines := []uint64{110, 110, 220, 12}
	for i, want := range wantBaselines {
		if tk.window.baseline[i] != want {
			t.Fatalf("baseline[%d] mutated: got %d, want %d", i, tk.window.baseline[i], want)
		}
	}

	// 4. Next genuine sample at t2 = base + 11s (10s elapsed since t1)
	// clientDrops: 110 -> 120 (+10)
	// returnDrops: 110 -> 120 (+10)
	// totalDrops: 220 -> 240 (+20)
	// writeErrors: 12 -> 14 (+2)
	t2 := base.Add(11 * time.Second)
	c2, r2, tot2, w2 := tk.Sample(0, t2, 120, 120, 240, 14)

	// Denominator must be preserved: 11s - 1s = 10s!
	// If the stale read at tStale had corrupted the denominator, elapsed would be 1s,
	// and rates would be inflated 10x (10/10/20/2 pps instead of 1/1/2/0.2 pps).
	const wantElapsed = 10.0
	const wantClient = 10.0 / wantElapsed
	const wantReturn = 10.0 / wantElapsed
	const wantTotal = 20.0 / wantElapsed
	const wantWrite = 2.0 / wantElapsed

	if math.Abs(c2-wantClient) > 1e-9 {
		t.Fatalf("clientDropRate inflated: got %v, want %v", c2, wantClient)
	}
	if math.Abs(r2-wantReturn) > 1e-9 {
		t.Fatalf("returnDropRate inflated: got %v, want %v", r2, wantReturn)
	}
	if math.Abs(tot2-wantTotal) > 1e-9 {
		t.Fatalf("totalDropRate inflated: got %v, want %v", tot2, wantTotal)
	}
	if math.Abs(w2-wantWrite) > 1e-9 {
		t.Fatalf("writeErrorRate inflated: got %v, want %v", w2, wantWrite)
	}
}

// TestWindowedTrackersAudit_PrimingBehavior verifies that trackers prime on their
// first sample and report zero deltas/rates rather than treating pre-existing cumulative
// totals as live rate spikes (issue #424 round 8, finding 2).
func TestWindowedTrackersAudit_PrimingBehavior(t *testing.T) {
	t.Run("diagDeltaTracker", func(t *testing.T) {
		var d diagDeltaTracker
		now := time.Now()
		// First sample must prime baseline and report zero delta
		if snap := d.Sample(0, now, 5_000); snap.delta != 0 {
			t.Fatalf("first sample must prime and report zero delta, got %d", snap.delta)
		}
		// Unchanged counter after sample interval reports zero delta
		if snap := d.Sample(0, now.Add(5*time.Second), 5_000); snap.delta != 0 {
			t.Fatalf("unchanged counter must report zero delta, got %d", snap.delta)
		}
		// Counter increase reports proper delta
		if snap := d.Sample(0, now.Add(10*time.Second), 5_010); snap.delta != 10 {
			t.Fatalf("incremented counter must report delta 10, got %d", snap.delta)
		}
	})

	t.Run("diagRatesTracker", func(t *testing.T) {
		tk := newDiagRatesTracker()
		now := time.Now()
		// First sample must prime and report zero rates
		c, r, tot, w := tk.Sample(0, now, 100, 100, 200, 10)
		if c != 0 || r != 0 || tot != 0 || w != 0 {
			t.Fatalf("first sample must prime and report zero rates, got %v %v %v %v", c, r, tot, w)
		}
		// Second sample over 1s reports valid rate
		c, r, tot, w = tk.Sample(0, now.Add(1*time.Second), 110, 110, 220, 12)
		if c != 10 || r != 10 || tot != 20 || w != 2 {
			t.Fatalf("second sample must report 10/10/20/2 pps, got %v %v %v %v", c, r, tot, w)
		}
	})

	t.Run("RollingHistory", func(t *testing.T) {
		rh := NewRollingHistory()
		rh.mu.RLock()
		preSeeded := rh.last1hTime
		rh.mu.RUnlock()
		if !preSeeded.IsZero() {
			t.Fatalf("NewRollingHistory must not pre-seed last1hTime, got %v", preSeeded)
		}
	})
}

// TestGenerationWindow_OlderGenerationResetIsNoop verifies that older-generation
// resets are ignored and do not clear the active generation's baseline (issue #424).
func TestGenerationWindow_OlderGenerationResetIsNoop(t *testing.T) {
	t.Run("generationWindow", func(t *testing.T) {
		var w generationWindow[uint64]
		now := time.Now()

		// Prime gen 2
		w.sample(2, now, []uint64{100})
		// Valid delta in gen 2
		accepted := w.sample(2, now.Add(1*time.Second), []uint64{110})
		if !accepted {
			t.Fatalf("expected accepted window in gen 2")
		}

		// Stale reset for gen 1 arriving late
		w.reset(1)

		// State must remain intact: deltas and baselines untouched
		deltas, windowSec, primed := w.last()
		if !primed || len(deltas) != 1 || deltas[0] != 10 || windowSec <= 0 {
			t.Fatalf("generationWindow state wiped by older reset: primed=%v deltas=%v windowSec=%v", primed, deltas, windowSec)
		}
	})

	t.Run("diagCounterWindows", func(t *testing.T) {
		dw := newDiagCounterWindows()
		now := time.Now()

		// Prime gen 2
		dw.sample(2, now, map[string]uint64{"client_malformed": 100})
		dw.sample(2, now.Add(1*time.Second), map[string]uint64{"client_malformed": 110})

		rate, ok := dw.rate("client_malformed")
		if !ok || rate != 10 {
			t.Fatalf("expected rate 10 in gen 2, got rate=%v ok=%v", rate, ok)
		}

		// Stale reset for gen 1
		dw.reset(1)

		// Rate must still be available
		rateAfter, okAfter := dw.rate("client_malformed")
		if !okAfter || rateAfter != 10 {
			t.Fatalf("diagCounterWindows rate wiped by older reset: rate=%v ok=%v", rateAfter, okAfter)
		}
	})
}


