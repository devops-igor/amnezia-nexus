package forwarder

import (
	"math"
	"testing"
	"time"
)

// TestGenerationTrafficWindow_WholeVectorMonotonicity tests whole-vector
// monotonicity in generationTrafficWindow.observe (issue #429 review blocker 1).
// If ANY counter is retrograde, the observation must be rejected wholesale
// without mutating baselines, timestamp anchors, or published snapshots.
func TestGenerationTrafficWindow_WholeVectorMonotonicity(t *testing.T) {
	var w generationTrafficWindow
	base := time.Now()

	// 1. Initial observation primes the window (accepted=false, elapsed=0)
	primeSnap := TrafficSnapshot{
		RxBytes:   1000,
		TxBytes:   2000,
		RxPackets: 10,
		TxPackets: 20,
	}
	snap, elapsed, accepted := w.observe(1, base, primeSnap)
	if accepted || elapsed != 0 || snap.Available {
		t.Fatalf("priming: got accepted=%v elapsed=%v available=%v; want false/0/false", accepted, elapsed, snap.Available)
	}

	// 2. Valid observation at t1 = base + 1s: Rx +500B (+5 pkts), Tx +1000B (+10 pkts)
	t1 := base.Add(1 * time.Second)
	t1Snap := TrafficSnapshot{
		RxBytes:   1500,
		TxBytes:   3000,
		RxPackets: 15,
		TxPackets: 30,
	}
	snap1, elapsed1, accepted1 := w.observe(1, t1, t1Snap)
	if !accepted1 || elapsed1 != 1.0 || !snap1.Available {
		t.Fatalf("t1 observation: got accepted=%v elapsed=%v available=%v; want true/1.0/true", accepted1, elapsed1, snap1.Available)
	}
	if snap1.RxBytesPerSec != 500.0 || snap1.TxBytesPerSec != 1000.0 {
		t.Fatalf("t1 rates: RxBps=%v TxBps=%v; want 500/1000", snap1.RxBytesPerSec, snap1.TxBytesPerSec)
	}
	if snap1.RxPps != 5.0 || snap1.TxPps != 10.0 {
		t.Fatalf("t1 pps: RxPps=%v TxPps=%v; want 5/10", snap1.RxPps, snap1.TxPps)
	}

	// Case A: Lower RX bytes (1400 < 1500), equal TX bytes/packets -> rejected wholesale, w.at untouched
	tA := t1.Add(500 * time.Millisecond)
	snapA := TrafficSnapshot{
		RxBytes:   1400,
		TxBytes:   3000,
		RxPackets: 15,
		TxPackets: 30,
	}
	resA, elA, accA := w.observe(1, tA, snapA)
	if accA || elA != 0 {
		t.Fatalf("Case A lower RxBytes: want rejected, got accepted=%v elapsed=%v", accA, elA)
	}
	if w.at != t1 {
		t.Fatalf("Case A mutated w.at: got %v, want %v", w.at, t1)
	}
	if resA != snap1 {
		t.Fatalf("Case A mutated published snapshot: got %+v, want %+v", resA, snap1)
	}

	// Case B: Lower RX packets (14 < 15), higher RX bytes (1600 >= 1500) -> rejected wholesale
	tB := t1.Add(600 * time.Millisecond)
	snapB := TrafficSnapshot{
		RxBytes:   1600,
		TxBytes:   3000,
		RxPackets: 14,
		TxPackets: 30,
	}
	resB, elB, accB := w.observe(1, tB, snapB)
	if accB || elB != 0 {
		t.Fatalf("Case B lower RxPackets: want rejected, got accepted=%v elapsed=%v", accB, elB)
	}
	if w.at != t1 {
		t.Fatalf("Case B mutated w.at: got %v, want %v", w.at, t1)
	}
	if resB != snap1 {
		t.Fatalf("Case B mutated published snapshot: got %+v, want %+v", resB, snap1)
	}

	// Case B2: Lower TX bytes or packets -> rejected wholesale
	tB2 := t1.Add(700 * time.Millisecond)
	snapB2 := TrafficSnapshot{
		RxBytes:   1600,
		TxBytes:   2900,
		RxPackets: 16,
		TxPackets: 30,
	}
	_, _, accB2 := w.observe(1, tB2, snapB2)
	if accB2 || w.at != t1 {
		t.Fatalf("Case B2 lower TxBytes: want rejected with w.at untouched, got acc=%v at=%v", accB2, w.at)
	}

	snapB3 := TrafficSnapshot{
		RxBytes:   1600,
		TxBytes:   3000,
		RxPackets: 16,
		TxPackets: 29,
	}
	_, _, accB3 := w.observe(1, tB2, snapB3)
	if accB3 || w.at != t1 {
		t.Fatalf("Case B3 lower TxPackets: want rejected with w.at untouched, got acc=%v at=%v", accB3, w.at)
	}

	// Case D: Subsequent valid observation after rejected retrograde samples
	// at t2 = t1 + 2.0s (elapsed must be 2.0s, NOT 2.0s - 0.7s)
	// Rx +1000B (+10 pkts), Tx +2000B (+20 pkts)
	t2 := t1.Add(2 * time.Second)
	snap2In := TrafficSnapshot{
		RxBytes:   2500, // 2500 - 1500 = 1000B
		TxBytes:   5000, // 5000 - 3000 = 2000B
		RxPackets: 25,   // 25 - 15 = 10
		TxPackets: 50,   // 50 - 30 = 20
	}
	snap2, el2, acc2 := w.observe(1, t2, snap2In)
	if !acc2 {
		t.Fatalf("Case D: valid observation must be accepted, got false")
	}
	if math.Abs(el2-2.0) > 1e-9 {
		t.Fatalf("Case D denominator corrupted: got %v, want 2.0s (rejected samples corrupted clock)", el2)
	}
	// RxBps = 1000 / 2.0 = 500.0, TxBps = 2000 / 2.0 = 1000.0
	if snap2.RxBytesPerSec != 500.0 || snap2.TxBytesPerSec != 1000.0 {
		t.Fatalf("Case D rates corrupted: RxBps=%v TxBps=%v; want 500/1000", snap2.RxBytesPerSec, snap2.TxBytesPerSec)
	}
	if snap2.RxPps != 5.0 || snap2.TxPps != 10.0 {
		t.Fatalf("Case D pps corrupted: RxPps=%v TxPps=%v; want 5/10", snap2.RxPps, snap2.TxPps)
	}

	// Case C: All equal (idle) after minInterval (0.5s >= 0.2s) -> accepted, deltas = 0, rates = 0
	t3 := t2.Add(500 * time.Millisecond)
	snap3, el3, acc3 := w.observe(1, t3, snap2In)
	if !acc3 || el3 != 0.5 {
		t.Fatalf("Case C idle: got accepted=%v elapsed=%v; want true/0.5", acc3, el3)
	}
	if snap3.RxBytesPerSec != 0 || snap3.TxBytesPerSec != 0 || snap3.RxPps != 0 || snap3.TxPps != 0 {
		t.Fatalf("Case C idle non-zero rates: %+v", snap3)
	}
	if !snap3.Available {
		t.Fatalf("Case C idle should remain Available=true")
	}

	// Older generation rejection
	tOlder := t3.Add(1 * time.Second)
	_, _, accOlder := w.observe(0, tOlder, snap2In)
	if accOlder {
		t.Fatalf("older generation observation must be rejected")
	}

	// Generation reset & re-priming
	w.reset(2)
	if w.gen != 2 || w.primed {
		t.Fatalf("reset(2): gen=%v primed=%v; want 2/false", w.gen, w.primed)
	}
	// First observation of gen 2 primes only
	t4 := tOlder.Add(1 * time.Second)
	_, el4, acc4 := w.observe(2, t4, snap2In)
	if acc4 || el4 != 0 {
		t.Fatalf("gen 2 first observation should only prime: got acc=%v el=%v", acc4, el4)
	}
}
