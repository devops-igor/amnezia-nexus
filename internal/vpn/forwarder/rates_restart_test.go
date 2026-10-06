package forwarder

// Review round 6 regression (issue #429): the aggregate RateTracker used to
// tag every observation with the TRACKER's current generation instead of the
// generation its caller captured before reading the counters. A gen-N
// observation captured before Forwarder.Start() and completed after the N+1
// baseline was established was therefore labeled N+1; counters that stayed
// equal across the restart made the sampler's partial-accept rule advance the
// window with no new information, and an advancing stale counter was measured
// against the tiny post-restart window. Both scenarios corrupt the accepted
// state. The production capture order (generation FIRST, then counters) makes
// such an observation carry the old generation, and the tracker must reject
// it wholesale: none of the baseline, the accepted sampling timestamp, the
// published rates, the EWMAs, the queue-drop rate or the history window may
// change, and the next genuine N+1 delta must keep its original denominator.
//
// The interleaving is made deterministic with testing/synctest: the forwarder
// constructor and Start() spawn no goroutines, and time only advances where
// the test sleeps.

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// TestForwarder_AggregateRatesRejectStaleGenerationObservation drives the
// foreground tracker through the production entry points (Rates,
// QueuePressure): capture gen-N totals, Start() -> N+1, prime and open an N+1
// window in which exactly one counter advances, then complete the stalled
// gen-N observation.
func TestForwarder_AggregateRatesRejectStaleGenerationObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fwd, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 256, 16)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits failed: %v", err)
		}

		// --- Generation N (the constructor incarnation): prime and open a
		// window through the production entry point. ---
		base := time.Now()
		fwd.Rates() // prime generation N from zero counters
		fwd.totalRxPackets.Store(100)
		fwd.totalTxPackets.Store(200)
		fwd.dropsTotal.Store(10)
		time.Sleep(1 * time.Second) // bubble clock: instant

		// The stalled request captures its observation in production order:
		// generation FIRST, then the counter snapshot.
		staleGen := fwd.currentGeneration()
		staleRxBytes, staleTxBytes, _ := fwd.GetStats()
		staleRxPackets := fwd.totalRxPackets.Load()
		staleTxPackets := fwd.totalTxPackets.Load()
		staleQueueDrops, _, staleTotalDrops := fwd.DropStats()
		if staleGen != 0 || staleRxPackets != 100 || staleTxPackets != 200 || staleTotalDrops != 10 {
			t.Fatalf("capture setup: gen=%d rx=%d tx=%d drops=%d, want gen 0 and 100/200/10", staleGen, staleRxPackets, staleTxPackets, staleTotalDrops)
		}

		if got := fwd.Rates(); !got.Available || got.RxPps != 100 || got.TxPps != 200 || got.DropRatePps != 10 {
			t.Fatalf("generation N window: want 100/200pps drops 10pps, got %+v", got)
		}

		// --- Start(): the production lifecycle reset -> generation N+1. ---
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fwd.Start(ctx)
		if got := fwd.currentGeneration(); got != 1 {
			t.Fatalf("Start must advance the generation to 1, got %d", got)
		}

		// --- Generation N+1: counters restarted from zero. Prime N+1, then
		// advance ONE N+1 counter while the others stay equal to their
		// baselines (the equal-fields partial-accept trap). ---
		fwd.totalRxPackets.Store(0)
		fwd.totalTxPackets.Store(0)
		fwd.dropsTotal.Store(0)
		fwd.Rates() // prime N+1 from the restarted counters
		fwd.totalRxPackets.Store(30)
		fwd.dropsQueueFull.Store(4)
		time.Sleep(1 * time.Second)
		if p := fwd.QueuePressure(); p.QueueFullDropRate != 4 {
			t.Fatalf("generation N+1 window: want queue-drop rate 4pps, got %+v", p)
		}

		// Accepted N+1 state, captured before the stale observation lands.
		before := fwd.rateTracker.Snapshot(30, 0)
		beforePressure := fwd.rateTracker.PressureSnapshot(0, 0, 0, 0)
		_, anchorBefore, primed, anchorGen := fwd.rateTracker.sampler.Baseline(2)
		if !primed || anchorGen != 1 || !anchorBefore.Equal(base.Add(2*time.Second)) {
			t.Fatalf("accepted N+1 anchor: primed=%v gen=%d at=%v, want gen 1 at %v", primed, anchorGen, anchorBefore, base.Add(2*time.Second))
		}

		// --- The stalled gen-N observation completes 2s after the accepted
		// N+1 window: past the sample-interval floor, so mislabeling it with
		// the tracker's current generation would accept it. The completion
		// goes through the tracker directly because no production entry
		// point can hold a capture across a Start() — that in-flight span
		// is exactly what this regression simulates; every window the
		// production entry points establish above uses Rates/QueuePressure. ---
		time.Sleep(2 * time.Second)
		fwd.rateTracker.Sample(staleGen, time.Now(), staleRxBytes, staleTxBytes, staleRxPackets, staleTxPackets, staleTotalDrops, staleQueueDrops)

		// NONE of the tracker state may change: the observation must be
		// rejected wholesale, not partially accepted as N+1.
		after := fwd.rateTracker.Snapshot(30, 0)
		if after != before {
			t.Fatalf("stale gen-%d observation changed published rates: before=%+v after=%+v", staleGen, before, after)
		}
		afterPressure := fwd.rateTracker.PressureSnapshot(0, 0, 0, 0)
		if afterPressure.QueueFullDropRate != beforePressure.QueueFullDropRate {
			t.Fatalf("stale gen-%d observation changed the queue-drop rate: %v -> %v", staleGen, beforePressure.QueueFullDropRate, afterPressure.QueueFullDropRate)
		}
		if v, at, primed, gen := fwd.rateTracker.sampler.Baseline(2); !primed || gen != 1 || v != 30 || !at.Equal(anchorBefore) {
			t.Fatalf("accepted baseline/timestamp must be untouched: value=%d at=%v primed=%v gen=%d, want 30 @ %v gen 1", v, at, primed, gen, anchorBefore)
		}

		// --- The next genuine N+1 delta keeps its original denominator: the
		// stale observation must not have advanced the sampling anchor. ---
		fwd.totalRxPackets.Store(90) // +60 packets since the accepted window
		next := fwd.Rates()
		if !next.Available || next.RxPps != 30 { // 60 packets / 2s true window
			t.Fatalf("next genuine N+1 window must keep its original denominator: want RxPps=30, got %+v", next)
		}
	})
}

// TestForwarder_HistoryRatesRejectStaleGenerationObservation is the same
// round-6 scenario against the independent history tracker, driven through
// HistoryRates/PrimeHistoryRates with explicit observation timestamps.
func TestForwarder_HistoryRatesRejectStaleGenerationObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fwd, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 256, 16)
		if err != nil {
			t.Fatalf("NewForwarderWithLimits failed: %v", err)
		}

		// --- Generation N: prime and open a history window. ---
		base := time.Now()
		fwd.HistoryRates(base) // prime generation N from zero counters
		fwd.totalRxPackets.Store(100)
		fwd.totalTxPackets.Store(200)
		fwd.dropsTotal.Store(10)

		// Stalled-request capture: generation FIRST, then counters.
		staleGen := fwd.currentGeneration()
		staleRxBytes, staleTxBytes, _ := fwd.GetStats()
		staleRxPackets := fwd.totalRxPackets.Load()
		staleTxPackets := fwd.totalTxPackets.Load()
		staleQueueDrops, _, staleTotalDrops := fwd.DropStats()
		if staleGen != 0 || staleRxPackets != 100 || staleTxPackets != 200 || staleTotalDrops != 10 {
			t.Fatalf("capture setup: gen=%d rx=%d tx=%d drops=%d, want gen 0 and 100/200/10", staleGen, staleRxPackets, staleTxPackets, staleTotalDrops)
		}

		if pre := fwd.HistoryRates(base.Add(1 * time.Second)); !pre.Available || pre.RxPps != 100 || pre.TxPps != 200 || pre.DropRatePps != 10 {
			t.Fatalf("generation N history window: want 100/200pps drops 10pps, got %+v", pre)
		}

		// --- Start(): the production lifecycle reset -> generation N+1. ---
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fwd.Start(ctx)
		if got := fwd.currentGeneration(); got != 1 {
			t.Fatalf("Start must advance the generation to 1, got %d", got)
		}

		// --- Generation N+1: counters restarted; prime N+1, then advance ONE
		// counter while the others stay equal. ---
		fwd.totalRxPackets.Store(0)
		fwd.totalTxPackets.Store(0)
		fwd.dropsTotal.Store(0)
		fwd.PrimeHistoryRates(base.Add(1 * time.Second))
		fwd.totalRxPackets.Store(30)
		fwd.dropsQueueFull.Store(4)
		if r := fwd.HistoryRates(base.Add(2 * time.Second)); !r.Available || r.RxPps != 30 || r.TxPps != 0 || r.DropRatePps != 0 {
			t.Fatalf("generation N+1 history window: want rx=30pps only, got %+v", r)
		}

		before := fwd.historyRateTracker.Snapshot(30, 0)
		beforePressure := fwd.historyRateTracker.PressureSnapshot(0, 0, 0, 0)
		_, anchorBefore, primed, anchorGen := fwd.historyRateTracker.sampler.Baseline(2)
		if !primed || anchorGen != 1 || !anchorBefore.Equal(base.Add(2*time.Second)) {
			t.Fatalf("accepted N+1 anchor: primed=%v gen=%d at=%v, want gen 1 at %v", primed, anchorGen, anchorBefore, base.Add(2*time.Second))
		}

		// --- The stalled gen-N observation completes 2s after the accepted
		// N+1 window (past the floor); via the tracker directly — no
		// production entry point can span a Start() mid-capture. ---
		fwd.historyRateTracker.Sample(staleGen, base.Add(4*time.Second), staleRxBytes, staleTxBytes, staleRxPackets, staleTxPackets, staleTotalDrops, staleQueueDrops)

		after := fwd.historyRateTracker.Snapshot(30, 0)
		if after != before {
			t.Fatalf("stale gen-%d observation changed published history rates: before=%+v after=%+v", staleGen, before, after)
		}
		afterPressure := fwd.historyRateTracker.PressureSnapshot(0, 0, 0, 0)
		if afterPressure.QueueFullDropRate != beforePressure.QueueFullDropRate {
			t.Fatalf("stale gen-%d observation changed the queue-drop rate: %v -> %v", staleGen, beforePressure.QueueFullDropRate, afterPressure.QueueFullDropRate)
		}
		if v, at, primed, gen := fwd.historyRateTracker.sampler.Baseline(2); !primed || gen != 1 || v != 30 || !at.Equal(anchorBefore) {
			t.Fatalf("accepted baseline/timestamp must be untouched: value=%d at=%v primed=%v gen=%d, want 30 @ %v gen 1", v, at, primed, gen, anchorBefore)
		}

		// --- The next genuine N+1 delta keeps its original denominator. ---
		fwd.totalRxPackets.Store(90) // +60 packets since the accepted window
		next := fwd.HistoryRates(base.Add(4 * time.Second))
		if !next.Available || next.RxPps != 30 { // 60 packets / 2s true window
			t.Fatalf("next genuine N+1 history window must keep its original denominator: want RxPps=30, got %+v", next)
		}
	})
}
