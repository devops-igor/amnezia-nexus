package vpn

import (
	"testing"
	"time"
)

// Every windowed tracker in this package must prime on its first sample rather
// than relying on a zero-value sentinel that a constructor could pre-seed. A
// pre-seeded sentinel makes the priming branch dead code and leaves every
// counter baseline at zero, which turns lifetime history into an active rate
// (issue #424 round 8, finding 2).
func TestWindowedTrackersAudit_NoneHasADeadPrimingBranch(t *testing.T) {
	t.Run("diagDeltaTracker", func(t *testing.T) {
		var d diagDeltaTracker
		if d.primed {
			t.Fatal("zero-value diagDeltaTracker must be unprimed")
		}
		if snap := d.Sample(time.Now(), 5_000); snap.delta != 0 {
			t.Fatalf("first sample must prime and report zero delta, got %d", snap.delta)
		}
		if snap := d.Sample(time.Now().Add(5*time.Second), 5_000); snap.delta != 0 {
			t.Fatalf("unchanged counter must report zero delta, got %d", snap.delta)
		}
	})

	t.Run("diagRatesTracker", func(t *testing.T) {
		tk := newDiagRatesTracker()
		if tk.primed {
			t.Fatal("newDiagRatesTracker must return an unprimed tracker")
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
