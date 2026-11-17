package dnsledger

import (
	"fmt"
	"testing"
	"time"
)

// Lifetime regression for the two stores that share one session log (issue #861,
// R13).
//
// A terminal query can legitimately leave an event without an answer record: a
// refusal, an upstream failure, a non-A answer and a TCP query all do. The answer
// side prunes and evicts on its own schedule, and it used to delete the whole
// session entry when the answer slice became empty, taking the event history with
// it. These cases pin the corrected lifetime at each of the three answer-side
// deletion sites: only a session that holds NOTHING is removed.

func TestEventOnlySessionSurvivesAnswerAging(t *testing.T) {
	ledger := New()
	now := time.Now()
	aged := now.Add(-2 * MaxRecordAge)

	// An aged-out answer record and a FRESH terminal event for the same session. The
	// next write prunes the answer while the event is still inside its window, which
	// is the case the answer-side deletion got wrong.
	if !ledger.Record(sampleInput("sess-shared", "plain.example", aged, 5*time.Minute), aged) {
		t.Fatal("the aged answer record was rejected")
	}
	if !ledger.RecordEvent(eventInput("sess-shared", "failed.example", now), now) {
		t.Fatal("the terminal event was rejected")
	}

	// A write for another session runs the answer prune.
	if !ledger.Record(sampleInput("sess-other", "other.example", now, 5*time.Minute), now) {
		t.Fatal("the trigger record was rejected")
	}
	if got := ledger.Snapshot("sess-shared", 0).Total; got != 0 {
		t.Errorf("answer records after aging = %d, want 0", got)
	}
	if got := ledger.SnapshotEvents("sess-shared", 0).Total; got != 1 {
		t.Errorf("events after answer aging = %d, want the live event kept", got)
	}
}

func TestEventOnlySessionSurvivesPerSessionAnswerEviction(t *testing.T) {
	ledger := New()
	now := time.Now()

	// One event for a session that will hold answer records too.
	ledger.RecordEvent(eventInput("sess-evict", "nx.example", now), now)
	if !ledger.Record(sampleInput("sess-evict", "plain.example", now, 5*time.Minute), now) {
		t.Fatal("the answer record was rejected")
	}

	// Push the answer side past the per-session cap: the oldest answer records are
	// evicted one by one, and the last eviction used to delete the session.
	for i := 0; i < MaxRecordsPerSession+2; i++ {
		at := now.Add(time.Duration(i+1) * time.Millisecond)
		if !ledger.Record(sampleInput("sess-evict", fmt.Sprintf("host%d.example", i), at, 5*time.Minute), at) {
			t.Fatalf("answer record %d was rejected", i)
		}
	}
	if got := ledger.SnapshotEvents("sess-evict", 0).Total; got != 1 {
		t.Fatalf("events after answer eviction = %d, want the event kept while the session is live", got)
	}
}

func TestEventOnlySessionSurvivesGlobalAnswerEviction(t *testing.T) {
	ledger := New()
	now := time.Now()

	// The event-only session is the one whose answers will be evicted globally.
	ledger.RecordEvent(eventInput("sess-global", "nx.example", now), now)
	ledger.Record(sampleInput("sess-global", "plain.example", now, 5*time.Minute), now)

	// Fill many other sessions so the global answer cap evicts the oldest answers,
	// including this session's only record.
	sessions := MaxRecordsTotal/MaxRecordsPerSession + 2
	for s := 0; s < sessions; s++ {
		for i := 0; i < MaxRecordsPerSession; i++ {
			at := now.Add(time.Duration(s*MaxRecordsPerSession+i) * time.Millisecond)
			ledger.Record(sampleInput(fmt.Sprintf("fill-%03d", s), fmt.Sprintf("h%d.example", i), at, 5*time.Minute), at)
		}
	}
	if got := ledger.SnapshotEvents("sess-global", 0).Total; got != 1 {
		t.Errorf("events after global answer eviction = %d, want the event kept", got)
	}
}
