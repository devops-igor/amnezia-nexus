package vpn

import (
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestRollingHistory_WindowsAndConcurrency(t *testing.T) {
	rh := NewRollingHistory()
	now := time.Now()

	// Add 100 points spaced by 10 seconds (total 1000s ~ 16m)
	for i := 0; i < 100; i++ {
		tPoint := now.Add(time.Duration(i*10) * time.Second)
		rh.Add(HistoryPoint{
			Timestamp:      tPoint.Unix(),
			RxBps:          float64(i * 1000),
			TxBps:          float64(i * 2000),
			QueueUtilPct:   float64(i % 100),
			TotalDropRate:  float64(i % 5),
			ForwardP95MS:   1.5,
			ActiveSessions: i,
			BackendP95MS:   10.0,
		})
	}

	snap := rh.Snapshot()
	// buf1m has maxCap 6, so len must be exactly 6
	if len(snap.Window1m) != 6 {
		t.Errorf("expected Window1m len=6, got %d", len(snap.Window1m))
	}
	// buf5m has maxCap 30, so len must be exactly 30
	if len(snap.Window5m) != 30 {
		t.Errorf("expected Window5m len=30, got %d", len(snap.Window5m))
	}
	// buf15m has maxCap 90, so len must be exactly 90
	if len(snap.Window15m) != 90 {
		t.Errorf("expected Window15m len=90, got %d", len(snap.Window15m))
	}
	// buf1h has samples every 1m, so in 1000s (~16m) we expect ~17 points
	if len(snap.Window1h) < 15 || len(snap.Window1h) > 20 {
		t.Errorf("expected Window1h len between 15 and 20, got %d", len(snap.Window1h))
	}

	// Concurrent read and write stress
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				rh.Add(HistoryPoint{
					Timestamp: time.Now().Unix(),
					RxBps:     float64(workerID * 100),
				})
			}
		}(w)
	}

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = rh.Snapshot()
			}
		}()
	}

	wg.Wait()
}

func TestHistoricalSeries_Populates1mAnd5m(t *testing.T) {
	rh := NewRollingHistory()
	baseTime := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	// Before adding any points, windows must be initialized non-nil empty slices
	initial := rh.Snapshot()
	if initial.Window1m == nil || initial.Window5m == nil || initial.Window15m == nil {
		t.Fatal("expected non-nil windows in initial snapshot")
	}
	if len(initial.Window1m) != 0 || len(initial.Window5m) != 0 {
		t.Fatalf("expected empty initial windows, got 1m=%d 5m=%d", len(initial.Window1m), len(initial.Window5m))
	}

	// Add 3 samples at 10s intervals
	for i := 0; i < 3; i++ {
		rh.Add(HistoryPoint{
			Timestamp: baseTime.Add(time.Duration(i*10) * time.Second).Unix(),
			RxBps:     float64((i + 1) * 1000),
		})
	}
	snap3 := rh.Snapshot()
	if len(snap3.Window1m) != 3 {
		t.Fatalf("expected Window1m len=3, got %d", len(snap3.Window1m))
	}
	if len(snap3.Window5m) != 3 {
		t.Fatalf("expected Window5m len=3, got %d", len(snap3.Window5m))
	}

	// Add up to 50 samples to saturate 1m (cap 6) and 5m (cap 30)
	for i := 3; i < 50; i++ {
		rh.Add(HistoryPoint{
			Timestamp: baseTime.Add(time.Duration(i*10) * time.Second).Unix(),
			RxBps:     float64((i + 1) * 1000),
		})
	}
	snapFull := rh.Snapshot()
	if len(snapFull.Window1m) != 6 {
		t.Fatalf("expected Window1m capped at 6, got %d", len(snapFull.Window1m))
	}
	if len(snapFull.Window5m) != 30 {
		t.Fatalf("expected Window5m capped at 30, got %d", len(snapFull.Window5m))
	}
	if len(snapFull.Window15m) != 50 {
		t.Fatalf("expected Window15m len=50, got %d", len(snapFull.Window15m))
	}

	// Verify the latest point in Window1m is the last added sample
	lastSampleTime := baseTime.Add(49 * 10 * time.Second).Unix()
	if snapFull.Window1m[5].Timestamp != lastSampleTime {
		t.Errorf("Window1m last point timestamp=%d, want %d", snapFull.Window1m[5].Timestamp, lastSampleTime)
	}
	if snapFull.Window5m[29].Timestamp != lastSampleTime {
		t.Errorf("Window5m last point timestamp=%d, want %d", snapFull.Window5m[29].Timestamp, lastSampleTime)
	}
}

func TestDiagnosticWrappers_ResetStaleGenerationNoOp(t *testing.T) {
	base := time.Unix(1000, 0)
	t.Run("diagRatesTracker", func(t *testing.T) {
		tk := newDiagRatesTracker()
		tk.reset(2)
		tk.Sample(2, base, 100, 200, 300, 10)
		tk.Sample(2, base.Add(time.Second), 110, 220, 330, 11)
		before := []float64{tk.clientDropRate, tk.returnDropRate, tk.totalDropRate, tk.writeErrorRate}
		if before[0] != 10 || !tk.primed {
			t.Fatal("invalid measured fixture")
		}
		tk.reset(1)
		after := []float64{tk.clientDropRate, tk.returnDropRate, tk.totalDropRate, tk.writeErrorRate}
		if !reflect.DeepEqual(before, after) || !tk.primed || !tk.lastSampleTime.Equal(base.Add(time.Second)) {
			t.Errorf("stale reset changed wrapper publication: before=%v after=%v primed=%v", before, after, tk.primed)
		}
	})
	t.Run("diagDeltaTracker", func(t *testing.T) {
		tk := &diagDeltaTracker{}
		tk.reset(2)
		tk.Sample(2, base, 100)
		before := tk.Sample(2, base.Add(time.Second), 110)
		if before.delta != 10 || before.windowSeconds != 1 {
			t.Fatal("invalid measured fixture")
		}
		tk.reset(1)
		after := deltaSnapshot{delta: tk.delta, windowSeconds: tk.windowSeconds}
		if before != after {
			t.Errorf("stale reset changed wrapper publication: before=%+v after=%+v", before, after)
		}
	})
}
