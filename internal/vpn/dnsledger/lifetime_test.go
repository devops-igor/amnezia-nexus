package dnsledger

import (
	"fmt"
	"testing"
	"time"
)

// Lifetime and accounting coverage for the two stores that share one session log
// (issue #861, R13 + R14).
//
// A terminal query can legitimately leave an event without an answer record: a
// refusal, an upstream failure, a non-A answer and a TCP query all do. The answer
// side prunes and evicts on its own schedule, and it used to delete the whole session
// entry when the answer slice became empty, taking the event history with it.
//
// Reach matters as much as the assertion. `makeRoomLocked` calls `dropOldestLocked`
// only while a session holds at least MaxRecordsPerSession records, so after one drop
// it still holds 127 and that caller can never drive the last-record branch. The
// per-session branch is therefore covered at its helper boundary
// (TestDropOldestLockedRetainsTheEventsOfAFullSession), labelled as such, while the
// ordinary cap-eviction case stays a distinct consumer-level positive.

func newLifetimeLedger(t *testing.T) *Ledger {
	t.Helper()
	return New()
}

// storedAnswerBytes recomputes the answer accounting from the stored records.
func storedAnswerBytes(ledger *Ledger) int {
	total := 0
	for _, session := range ledger.sessions {
		for _, record := range session.records {
			total += recordSize(record)
		}
	}
	return total
}

// storedEventBytesTotal recomputes the event accounting from the stored events.
func storedEventBytesTotal(ledger *Ledger) int {
	total := 0
	for _, session := range ledger.sessions {
		for _, event := range session.events {
			total += eventSize(event)
		}
	}
	return total
}

// assertSettledAccounting pins both counters to the stored state, so a guard that
// deletes a session without returning its bytes cannot pass.
func assertSettledAccounting(t *testing.T, ledger *Ledger) {
	t.Helper()
	answers, answersBytes := 0, 0
	events, eventsBytes := 0, 0
	for _, session := range ledger.sessions {
		answers += len(session.records)
		events += len(session.events)
		for _, record := range session.records {
			answersBytes += recordSize(record)
		}
		for _, event := range session.events {
			eventsBytes += eventSize(event)
		}
	}
	if ledger.total != answers {
		t.Errorf("answer count = %d, stored records = %d", ledger.total, answers)
	}
	if ledger.bytes != answersBytes || ledger.bytes != storedAnswerBytes(ledger) {
		t.Errorf("answer bytes = %d, stored sizes = %d/%d", ledger.bytes, answersBytes, storedAnswerBytes(ledger))
	}
	if ledger.eventTotal != events {
		t.Errorf("event count = %d, stored events = %d", ledger.eventTotal, events)
	}
	if ledger.eventBytes != eventsBytes || ledger.eventBytes != storedEventBytesTotal(ledger) {
		t.Errorf("event bytes = %d, stored sizes = %d/%d", ledger.eventBytes, eventsBytes, storedEventBytesTotal(ledger))
	}
}

func TestEventOnlySessionSurvivesAnswerAging(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()
	aged := now.Add(-2 * MaxRecordAge)

	// An aged-out answer record and a FRESH terminal event for the same session.
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
	assertSettledAccounting(t, ledger)
}

// TestEventOnlySessionSurvivesOrdinaryPerSessionEviction is the consumer-level
// positive for the per-session cap: filling the session past its answer cap evicts
// answers and must leave the terminal events of that session untouched.
//
// It deliberately does NOT claim to exercise the "last answer record removed" branch:
// with a cap of 128 the caller stops one record above zero, which is why that branch
// has its own helper-boundary test below.
func TestEventOnlySessionSurvivesOrdinaryPerSessionEviction(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()

	if !ledger.RecordEvent(eventInput("sess-evict", "nx.example", now), now) {
		t.Fatal("the terminal event was rejected")
	}
	if !ledger.Record(sampleInput("sess-evict", "plain.example", now, 5*time.Minute), now) {
		t.Fatal("the first answer record was rejected")
	}
	for i := 0; i < MaxRecordsPerSession+2; i++ {
		at := now.Add(time.Duration(i+1) * time.Millisecond)
		if !ledger.Record(sampleInput("sess-evict", fmt.Sprintf("host%d.example", i), at, 5*time.Minute), at) {
			t.Fatalf("answer record %d was rejected", i)
		}
	}

	if got := ledger.Snapshot("sess-evict", 0).Total; got != MaxRecordsPerSession {
		t.Errorf("answers = %d, want the per-session cap", got)
	}
	if got := ledger.SnapshotEvents("sess-evict", 0).Total; got != 1 {
		t.Errorf("events after ordinary cap eviction = %d, want the event kept", got)
	}
	assertSettledAccounting(t, ledger)
}

// TestDropOldestLockedRetainsTheEventsOfAFullSession is a DIRECT HELPER CONTRACT,
// not a consumer path.
//
// The ordinary caller cannot remove the last answer of a session (see the test
// above), so this branch is exercised here: a real initialised Ledger with a real
// session holding exactly one answer record and one live event, and the real helper
// called under the ledger lock. It asserts the session survives, the event is
// retained, and both accounting pairs are exact.
func TestDropOldestLockedRetainsTheEventsOfAFullSession(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()

	if !ledger.RecordEvent(eventInput("sess-helper", "nx.example", now), now) {
		t.Fatal("the terminal event was rejected")
	}
	if !ledger.Record(sampleInput("sess-helper", "plain.example", now, 5*time.Minute), now) {
		t.Fatal("the answer record was rejected")
	}
	ledger.mu.Lock()
	session := ledger.sessions["sess-helper"]
	if session == nil || len(session.records) != 1 || len(session.events) != 1 {
		ledger.mu.Unlock()
		t.Fatalf("fixture state = %+v, want one record and one event", session)
	}
	ledger.dropOldestLocked("sess-helper", session)
	remainingRecords := len(session.records)
	remainingEvents := len(session.events)
	sessionBytes := session.bytes
	ledger.mu.Unlock()

	if remainingRecords != 0 {
		t.Fatalf("records after the helper = %d, want the one record dropped", remainingRecords)
	}
	if remainingEvents != 1 {
		t.Errorf("events after the helper = %d, want the event retained", remainingEvents)
	}
	if sessionBytes != 0 {
		t.Errorf("session answer bytes = %d, want 0 after the drop", sessionBytes)
	}
	if _, ok := ledger.sessions["sess-helper"]; !ok {
		t.Error("the session was deleted while it still held a terminal event")
	}
	assertSettledAccounting(t, ledger)
}

func TestEventOnlySessionSurvivesGlobalAnswerEviction(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()

	ledger.RecordEvent(eventInput("sess-global", "nx.example", now), now)
	ledger.Record(sampleInput("sess-global", "plain.example", now, 5*time.Minute), now)

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
	assertSettledAccounting(t, ledger)
}

// TestEventAndAnswerAccountingSettleTogether covers the mixed case the two stores
// exist for: a session that records a failed and a non-A terminal event, then a real
// answer, then has that answer aged away. Both accounting pairs must equal the stored
// state at every step.
func TestEventAndAnswerAccountingSettleTogether(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()

	if !ledger.RecordEvent(eventInput("sess-mixed", "fail.example", now), now) {
		t.Fatal("the failed-query event was rejected")
	}
	if !ledger.RecordEvent(eventInput("sess-mixed", "plain.example", now.Add(time.Millisecond)), now.Add(time.Millisecond)) {
		t.Fatal("the non-A event was rejected")
	}
	assertSettledAccounting(t, ledger)

	if !ledger.Record(sampleInput("sess-mixed", "plain.example", now.Add(2*time.Millisecond), 5*time.Minute), now.Add(2*time.Millisecond)) {
		t.Fatal("the answer record was rejected")
	}
	assertSettledAccounting(t, ledger)
	if got := ledger.SnapshotEvents("sess-mixed", 0).Total; got != 2 {
		t.Errorf("events = %d, want both kept", got)
	}
	if got := ledger.Snapshot("sess-mixed", 0).Total; got != 1 {
		t.Errorf("answers = %d, want the one record", got)
	}

	later := now.Add(MaxRecordAge + time.Minute)
	if !ledger.Record(sampleInput("sess-other", "other.example", later, 5*time.Minute), later) {
		t.Fatal("the trigger record was rejected")
	}
	assertSettledAccounting(t, ledger)
}

// TestRetirementClearsBothAccountings pins the one path that intentionally removes a
// whole session: retirement returns both budgets and leaves no residue.
func TestRetirementClearsBothAccountings(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()

	if !ledger.RecordEvent(eventInput("sess-retire", "nx.example", now), now) {
		t.Fatal("the terminal event was rejected")
	}
	if !ledger.Record(sampleInput("sess-retire", "plain.example", now, 5*time.Minute), now) {
		t.Fatal("the answer record was rejected")
	}
	if beforeAnswers, beforeEvents := ledger.Snapshot("sess-retire", 0), ledger.SnapshotEvents("sess-retire", 0); beforeAnswers.Total != 1 || beforeEvents.Total != 1 {
		t.Fatalf("fixture = %d answers / %d events, want one each", beforeAnswers.Total, beforeEvents.Total)
	}

	ledger.RetireSession("sess-retire")

	ledger.mu.Lock()
	answers, answersBytes := ledger.total, ledger.bytes
	events, eventsBytes := ledger.eventTotal, ledger.eventBytes
	_, exists := ledger.sessions["sess-retire"]
	ledger.mu.Unlock()
	if answers != 0 || answersBytes != 0 {
		t.Errorf("answer accounting after retirement = %d/%d, want 0/0", answers, answersBytes)
	}
	if events != 0 || eventsBytes != 0 {
		t.Errorf("event accounting after retirement = %d/%d, want 0/0", events, eventsBytes)
	}
	if exists {
		t.Error("the retired session is still present")
	}
	if got := ledger.Snapshot("sess-retire", 0).Total; got != 0 {
		t.Errorf("answers after retirement = %d, want 0", got)
	}
	if got := ledger.SnapshotEvents("sess-retire", 0).Total; got != 0 {
		t.Errorf("events after retirement = %d, want 0", got)
	}
	assertSettledAccounting(t, ledger)
}

// TestLifetimeReadsDoNotMutate proves the reads used above change nothing, so no
// accounting assertion above can be satisfied by a read's side effect.
func TestLifetimeReadsDoNotMutate(t *testing.T) {
	ledger := newLifetimeLedger(t)
	now := time.Now()
	ledger.RecordEvent(eventInput("sess-read", "nx.example", now), now)
	ledger.Record(sampleInput("sess-read", "plain.example", now, 5*time.Minute), now)

	ledger.mu.Lock()
	before := [4]int{ledger.total, ledger.bytes, ledger.eventTotal, ledger.eventBytes}
	ledger.mu.Unlock()

	ledger.Snapshot("sess-read", 0)
	ledger.SnapshotEvents("sess-read", 0)

	ledger.mu.Lock()
	after := [4]int{ledger.total, ledger.bytes, ledger.eventTotal, ledger.eventBytes}
	ledger.mu.Unlock()
	if before != after {
		t.Errorf("a read changed the accounting: %v -> %v", before, after)
	}
	assertSettledAccounting(t, ledger)
}
