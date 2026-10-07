package forwarder

import (
	"math"
	"testing"
	"time"
)

func TestRateTracker_RatesAndEWMA(t *testing.T) {
	rt := NewRateTracker()
	t0 := time.Now()

	// Initial sample at t0
	rt.Sample(0, t0, 0, 0, 0, 0, 0, 0)

	// Sample after 1 second: 1000 bytes RX, 2000 bytes TX, 10 pkts RX, 20 pkts TX, 1 drop
	t1 := t0.Add(1 * time.Second)
	rt.Sample(0, t1, 1000, 2000, 10, 20, 1, 1)

	rates := rt.Snapshot(10, 20)
	if rates.RxBps != 8000.0 { // 1000 * 8 / 1s
		t.Errorf("expected RxBps=8000, got %f", rates.RxBps)
	}
	if rates.TxBps != 16000.0 { // 2000 * 8 / 1s
		t.Errorf("expected TxBps=16000, got %f", rates.TxBps)
	}
	if rates.RxPps != 10.0 {
		t.Errorf("expected RxPps=10, got %f", rates.RxPps)
	}
	if rates.TxPps != 20.0 {
		t.Errorf("expected TxPps=20, got %f", rates.TxPps)
	}
	if rates.DropRatePps != 1.0 {
		t.Errorf("expected DropRatePps=1, got %f", rates.DropRatePps)
	}
	if rates.RxBpsAvg5m <= 0 || rates.TxBpsAvg5m <= 0 {
		t.Errorf("expected non-zero EWMA: 5m_rx=%f, 5m_tx=%f", rates.RxBpsAvg5m, rates.TxBpsAvg5m)
	}

	// Check pressure snapshot
	pressure := rt.PressureSnapshot(600, 1000, 700, 1)
	if pressure.UtilizationPct != 60.0 {
		t.Errorf("expected UtilizationPct=60%%, got %f", pressure.UtilizationPct)
	}
	if pressure.HighWaterPct != 70.0 {
		t.Errorf("expected HighWaterPct=70%%, got %f", pressure.HighWaterPct)
	}
	if pressure.QueueFullDropRate != 1 {
		t.Errorf("queue refusal rate=%v, want 1", pressure.QueueFullDropRate)
	}

}

func TestForwarder_RatesAndPressureAPI(t *testing.T) {
	f, err := NewForwarderWithLimits(nil, "10.100.0.0/16", 2048, 100)
	if err != nil {
		t.Fatalf("NewForwarderWithLimits failed: %v", err)
	}

	rxPackets, txPackets := f.PacketStats()
	if rxPackets != 0 || txPackets != 0 {
		t.Errorf("expected zero packet stats initially, got rx=%d tx=%d", rxPackets, txPackets)
	}

	rates := f.Rates()
	if rates.TotalRxPackets != 0 || rates.TotalTxPackets != 0 {
		t.Errorf("expected zero totals in rates snapshot, got rx=%d tx=%d", rates.TotalRxPackets, rates.TotalTxPackets)
	}

	pressure := f.QueuePressure()
	if pressure.Capacity != 0 || pressure.Occupancy != 0 {
		t.Errorf("expected zero queue pressure with no routes, got occ=%d cap=%d", pressure.Occupancy, pressure.Capacity)
	}
}

// TestRateTracker_WholeVectorMonotonicity_NoRateInflation pins issue #424
// round 7 regression 5: production-level RateTracker must reject an older
// same-generation lower+equal snapshot, leaving baseline, sampling timestamp,
// published rates (Snapshot), QueuePressure, and EWMA completely unchanged,
// so the next genuine sample preserves the full elapsed denominator without rate inflation.
func TestRateTracker_WholeVectorMonotonicity_NoRateInflation(t *testing.T) {
	rt := NewRateTracker()
	base := time.Now()

	// 1. Prime generation 0 at t0
	rt.Sample(0, base, 1000, 2000, 100, 200, 10, 5)

	// 2. Accept baseline at t1 = base + 1s
	t1 := base.Add(1 * time.Second)
	// rxBytes: 1000 -> 2000 (+1000B -> 8000 bps)
	// txBytes: 2000 -> 4000 (+2000B -> 16000 bps)
	// rxPackets: 100 -> 200 (+100 -> 100 pps)
	// txPackets: 200 -> 400 (+200 -> 200 pps)
	// totalDrops: 10 -> 20 (+10 -> 10 pps)
	// queueDrops: 5 -> 7 (+2 -> 2 pps)
	rt.Sample(0, t1, 2000, 4000, 200, 400, 20, 7)

	snap1 := rt.Snapshot(200, 400)
	if !snap1.Available {
		t.Fatal("rates must be available after window 1")
	}
	if snap1.RxBps != 8000 || snap1.TxBps != 16000 || snap1.RxPps != 100 || snap1.TxPps != 200 || snap1.DropRatePps != 10 {
		t.Fatalf("window 1 rates mismatch: %+v", snap1)
	}
	if snap1.RxBpsAvg5m <= 0 || snap1.TxBpsAvg5m <= 0 || snap1.RxBpsAvg1h <= 0 || snap1.TxBpsAvg1h <= 0 {
		t.Fatalf("window 1 EWMA must be positive: %+v", snap1)
	}
	pressure1 := rt.PressureSnapshot(50, 100, 80, 7)
	if pressure1.QueueFullDropRate != 2 {
		t.Fatalf("window 1 QueueFullDropRate=%v, want 2", pressure1.QueueFullDropRate)
	}

	// Verify accepted baselines and timestamp at t1
	wantBaselines1 := []uint64{2000, 4000, 200, 400, 20, 7}
	for i, want := range wantBaselines1 {
		val, at, primed, gen := rt.sampler.Baseline(i)
		if !primed || gen != 0 || val != want || !at.Equal(t1) {
			t.Fatalf("baseline[%d] mismatch at t1: val=%d at=%v primed=%v gen=%d", i, val, at, primed, gen)
		}
	}

	// 3. Stale same-generation lower + equal snapshot at tStale = base + 10s
	// Lower rxPackets (150 < 200), equal remaining counters
	tStale := base.Add(10 * time.Second)
	rt.Sample(0, tStale, 2000, 4000, 150, 400, 20, 7)

	// Verify that RateTracker rejects it:
	// - baselines and sampling timestamp completely unchanged
	for i, want := range wantBaselines1 {
		val, at, primed, gen := rt.sampler.Baseline(i)
		if !primed || gen != 0 || val != want || !at.Equal(t1) {
			t.Fatalf("baseline[%d] mutated after stale sample: val=%d at=%v (want %v)", i, val, at, t1)
		}
	}

	// - published rates (Snapshot) completely unchanged
	snapStale := rt.Snapshot(200, 400)
	if !snapStale.Available {
		t.Fatal("rates must remain available after rejected stale sample")
	}
	if snapStale.RxBps != snap1.RxBps || snapStale.TxBps != snap1.TxBps ||
		snapStale.RxPps != snap1.RxPps || snapStale.TxPps != snap1.TxPps ||
		snapStale.DropRatePps != snap1.DropRatePps {
		t.Fatalf("published rates mutated by rejected sample: got %+v, want %+v", snapStale, snap1)
	}

	// - EWMA completely unchanged
	if snapStale.RxBpsAvg5m != snap1.RxBpsAvg5m || snapStale.TxBpsAvg5m != snap1.TxBpsAvg5m ||
		snapStale.RxBpsAvg1h != snap1.RxBpsAvg1h || snapStale.TxBpsAvg1h != snap1.TxBpsAvg1h {
		t.Fatalf("EWMA mutated by rejected sample: got %+v, want %+v", snapStale, snap1)
	}

	// - QueuePressure completely unchanged
	pressureStale := rt.PressureSnapshot(50, 100, 80, 7)
	if pressureStale.QueueFullDropRate != pressure1.QueueFullDropRate {
		t.Fatalf("QueueFullDropRate mutated by rejected sample: got %v, want %v", pressureStale.QueueFullDropRate, pressure1.QueueFullDropRate)
	}

	// 4. Next genuine sample at t2 = base + 11s (10s elapsed since t1)
	// rxBytes: 2000 -> 3000 (+1000B)
	// txBytes: 4000 -> 6000 (+2000B)
	// rxPackets: 200 -> 250 (+50)
	// txPackets: 400 -> 500 (+100)
	// totalDrops: 20 -> 30 (+10)
	// queueDrops: 7 -> 12 (+5)
	t2 := base.Add(11 * time.Second)
	rt.Sample(0, t2, 3000, 6000, 250, 500, 30, 12)

	// Denominator must be preserved: 11s - 1s = 10s!
	// If the stale read had corrupted the denominator to 1s (11s - 10s),
	// rates would be inflated 10x (8000 bps instead of 800 bps).
	const wantElapsed = 10.0
	wantRxBps := float64(1000*8) / wantElapsed    // 800.0
	wantTxBps := float64(2000*8) / wantElapsed    // 1600.0
	wantRxPps := float64(50) / wantElapsed        // 5.0
	wantTxPps := float64(100) / wantElapsed       // 10.0
	wantDropPps := float64(10) / wantElapsed      // 1.0
	wantQueueDropRate := float64(5) / wantElapsed // 0.5

	snap2 := rt.Snapshot(250, 500)
	if math.Abs(snap2.RxBps-wantRxBps) > 1e-9 {
		t.Fatalf("RxBps inflated: got %v, want %v", snap2.RxBps, wantRxBps)
	}
	if math.Abs(snap2.TxBps-wantTxBps) > 1e-9 {
		t.Fatalf("TxBps inflated: got %v, want %v", snap2.TxBps, wantTxBps)
	}
	if math.Abs(snap2.RxPps-wantRxPps) > 1e-9 {
		t.Fatalf("RxPps inflated: got %v, want %v", snap2.RxPps, wantRxPps)
	}
	if math.Abs(snap2.TxPps-wantTxPps) > 1e-9 {
		t.Fatalf("TxPps inflated: got %v, want %v", snap2.TxPps, wantTxPps)
	}
	if math.Abs(snap2.DropRatePps-wantDropPps) > 1e-9 {
		t.Fatalf("DropRatePps inflated: got %v, want %v", snap2.DropRatePps, wantDropPps)
	}

	pressure2 := rt.PressureSnapshot(50, 100, 80, 12)
	if math.Abs(pressure2.QueueFullDropRate-wantQueueDropRate) > 1e-9 {
		t.Fatalf("QueueFullDropRate inflated: got %v, want %v", pressure2.QueueFullDropRate, wantQueueDropRate)
	}

	// Verify EWMA advanced
	if snap2.RxBpsAvg5m == snap1.RxBpsAvg5m || snap2.TxBpsAvg5m == snap1.TxBpsAvg5m {
		t.Fatalf("EWMA should advance after genuine window: snap1=%+v snap2=%+v", snap1, snap2)
	}

	// Verify baselines and timestamp advanced to t2
	wantBaselines2 := []uint64{3000, 6000, 250, 500, 30, 12}
	for i, want := range wantBaselines2 {
		val, at, primed, gen := rt.sampler.Baseline(i)
		if !primed || gen != 0 || val != want || !at.Equal(t2) {
			t.Fatalf("baseline[%d] mismatch at t2: val=%d at=%v (want %v)", i, val, at, t2)
		}
	}
}
