package vpn

import (
	"testing"
	"time"
)

// Issue #424 round 8, finding 2: newDiagRatesTracker used to seed lastSampleTime
// with time.Now(), which made the priming branch in Sample dead code. Every
// counter baseline stayed 0, so the very first window computed
// (cumulative - 0)/elapsed and reported lifetime totals as an ACTIVE per-second
// rate. At the pre-change head this test measured 3217.99 drops/sec on a
// completely idle server, which is DEGRADED at the >= 10 threshold.
//
// Times are relative to time.Now() on purpose: the pre-change constructor seeds
// lastSampleTime with time.Now(), so a synthetic past timestamp would make the
// elapsed time negative and the tracker would short-circuit on the throttle
// instead of exposing the defect.
func TestDiagRatesTracker_FirstSamplePrimesBaselinesNotLifetimeTotals(t *testing.T) {
	const (
		historyClientDrops = uint64(3217)
		historyReturnDrops = uint64(1)
		historyTotalDrops  = uint64(3218)
		historyWriteErrors = uint64(9)
	)

	tk := newDiagRatesTracker()
	base := time.Now().Add(time.Second)

	// Step 1+2: the first sample primes time AND every counter baseline. All
	// four rates must be zero even though the counters carry real history.
	client, ret, total, writeErr := tk.Sample(base, historyClientDrops, historyReturnDrops, historyTotalDrops, historyWriteErrors)
	if client != 0 || ret != 0 || total != 0 || writeErr != 0 {
		t.Fatalf("STEP1 first sample must report zero rates, got client=%v return=%v total=%v writeErr=%v",
			client, ret, total, writeErr)
	}

	// The baselines must have been captured, otherwise step 3 cannot hold.
	// They live in the generation-aware window since issue #429 review
	// blocker 1 (layout: client, return, total, writeErrors).
	tk.mu.Lock()
	captured := tk.window.baseline[0] == historyClientDrops &&
		tk.window.baseline[1] == historyReturnDrops &&
		tk.window.baseline[2] == historyTotalDrops &&
		tk.window.baseline[3] == historyWriteErrors &&
		tk.lastSampleTime.Equal(base)
	tk.mu.Unlock()
	if !captured {
		t.Fatal("STEP2 first sample did not capture the counter baselines")
	}

	// Step 3: THIS is the assertion that fails against the pre-fix tracker.
	// Counters are UNCHANGED, so no new loss occurred, yet the sample is well
	// past the 200ms throttle. Pre-fix behaviour divides the full lifetime
	// totals by the elapsed seconds and reports a large non-zero rate.
	client, ret, total, writeErr = tk.Sample(
		base.Add(10*time.Second),
		historyClientDrops, historyReturnDrops, historyTotalDrops, historyWriteErrors,
	)
	if client != 0 || ret != 0 || total != 0 || writeErr != 0 {
		t.Fatalf("STEP3 unchanged counters must still report zero rates after the throttle, got client=%v return=%v total=%v writeErr=%v",
			client, ret, total, writeErr)
	}

	// Step 4: a real increment is reported as a rate over the new window, and
	// only over that increment.
	_, _, total, _ = tk.Sample(
		base.Add(20*time.Second),
		historyClientDrops+50, historyReturnDrops, historyTotalDrops+50, historyWriteErrors,
	)
	if want := 5.0; total != want {
		t.Errorf("STEP4 50 drops over 10s should report %v drops/sec, got %v", want, total)
	}
}

// The priming path must be genuinely reachable: an unprimed tracker must exist
// after construction, and the first status collection must report zero rates.
func TestDiagRatesTracker_PrimingIsReachableAfterConstruction(t *testing.T) {
	tk := newDiagRatesTracker()

	tk.mu.Lock()
	preSeededTime := tk.lastSampleTime
	tk.mu.Unlock()
	if !preSeededTime.IsZero() {
		t.Fatalf("constructor must not pre-seed lastSampleTime, got %v", preSeededTime)
	}

	base := time.Now().Add(time.Second)
	if _, _, total, _ := tk.Sample(base, 0, 0, 0, 0); total != 0 {
		t.Fatalf("first status response must report zero rate, got %v", total)
	}
	if _, _, total, _ := tk.Sample(base.Add(30*time.Second), 0, 0, 0, 0); total != 0 {
		t.Fatalf("idle server must report zero rate on later windows, got %v", total)
	}
}
