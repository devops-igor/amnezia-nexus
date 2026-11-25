package orchestrator

// The DB-only rebalance path must refuse a move when it cannot read the marks.
//
// Round 18 let this path fall back to the pass snapshot when the fresh read failed. The
// snapshot predates the decision, so that fallback re-opened exactly the window the re-read
// exists to close. The required behaviour is "unknown", which is distinct from both "nothing is
// absent" (a real answer) and "everything is absent" (a different, wrong conclusion).

import (
	"context"
	"testing"
)

// TestRebalanceFallbackRefusesWhenTheMarkReadFails induces a real SQL failure by removing the
// table the mark read needs, and requires the fallback to refuse the move.
func TestRebalanceFallbackRefusesWhenTheMarkReadFails(t *testing.T) {
	f := setupRebalanceFixture(t)
	for i := 1; i <= 9; i++ {
		f.session(t, fmtSessionID(i), f.t1, "connected")
	}
	f.session(t, fmtSessionID(10), f.t2, "connected")

	orch := New(f.db, nil)

	// Control first, while the store is healthy: the destination is eligible and the ordinary
	// move is allowed. Without this, a helper that always refuses would pass the test below.
	if !orch.dbTargetEligible(context.Background(), f.t2, nil) {
		t.Fatal("a healthy destination was refused before the failure was induced")
	}

	// Break exactly the read this path depends on, then require a refusal.
	if _, err := f.db.ExecContext(context.Background(), "DROP TABLE servers"); err != nil {
		t.Fatalf("dropping the mark source: %v", err)
	}
	if orch.dbTargetEligible(context.Background(), f.t2, nil) {
		t.Fatal("the destination was treated as eligible on an UNREADABLE mark store; unknown must not be allowed")
	}
}

// And an empty answer must stay an answer: when the marks are readable and nothing is marked,
// the destination is eligible. Unknown and empty must not be conflated in either direction.
func TestRebalanceFallbackAllowsWhenMarksAreReadableAndEmpty(t *testing.T) {
	f := setupRebalanceFixture(t)
	orch := New(f.db, nil)

	absent, known := orch.currentAbsentServers(context.Background())
	if !known {
		t.Fatal("a healthy store reported unknown")
	}
	if len(absent) != 0 {
		t.Fatalf("an unmarked store reported %d absent servers", len(absent))
	}
	if !orch.dbTargetEligible(context.Background(), f.t2, absent) {
		t.Fatal("an eligible destination was refused")
	}

	// A mark makes the same destination ineligible.
	markServerAbsent(t, f, f.t2)
	absent, known = orch.currentAbsentServers(context.Background())
	if !known || len(absent) != 1 {
		t.Fatalf("a marked store reported known=%v with %d marks", known, len(absent))
	}
	if orch.dbTargetEligible(context.Background(), f.t2, absent) {
		t.Fatal("a marked destination was treated as eligible")
	}
}
