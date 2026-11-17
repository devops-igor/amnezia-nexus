package dnsledger

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Invariant coverage for the terminal-event store (issue #861, R10).
//
// The event store is bounded by counts AND by estimated bytes. The byte counter was
// previously only incremented, so a test that merely observed the counter moving
// would not have caught an unbounded store. These cases assert the invariant the
// code promises: the reported bytes equal the sum of the stored events' sizes and
// never exceed the budget, a name is cut at the wire limit, and retirement returns
// the session's bytes.

func eventInput(sessionID, name string, at time.Time) InputEvent {
	return InputEvent{
		SessionID:  sessionID,
		Transport:  "udp",
		Name:       name,
		QType:      1,
		RCode:      0,
		Kind:       "answered",
		Delivered:  true,
		ReceivedAt: at,
		AnsweredAt: at,
	}
}

func TestEventByteBudgetIsEnforcedAndExact(t *testing.T) {
	ledger := New()
	base := time.Now().Add(-time.Minute)

	// Names at the wire limit across many sessions, so the binding fence is the byte
	// budget rather than one session's count cap.
	longPrefix := strings.Repeat("a", 200)
	for i := 0; i < MaxEventsPerSession*30; i++ {
		name := fmt.Sprintf("%s-%d.example", longPrefix, i)
		at := base.Add(time.Duration(i) * time.Millisecond)
		ledger.RecordEvent(eventInput(fmt.Sprintf("sess-%02d", i%30), name, at), at)
		ledger.mu.Lock()
		live := ledger.eventBytes
		ledger.mu.Unlock()
		if live > MaxEventBytesTotal {
			t.Fatalf("live event bytes = %d exceeded the budget %d", live, MaxEventBytesTotal)
		}
	}

	snapshot := ledger.SnapshotEvents("sess-00", MaxEventsPerSession)
	if snapshot.Stats.Bytes > MaxEventBytesTotal {
		t.Fatalf("event bytes = %d, want at most %d", snapshot.Stats.Bytes, MaxEventBytesTotal)
	}
	if snapshot.Stats.EvictedGlobal == 0 {
		t.Error("the byte budget was reached without reporting a global eviction")
	}
	if snapshot.Stats.Bytes < MaxEventBytesTotal/2 {
		t.Errorf("bytes = %d, want the budget to be the binding fence (near %d)", snapshot.Stats.Bytes, MaxEventBytesTotal)
	}

	// The invariant: the counter equals the sum of the stored events' sizes. A
	// counter that only ever increments would fail this once anything is evicted or
	// aged out.
	ledger.mu.Lock()
	exact := ledger.eventBytes
	sessions := len(ledger.sessions)
	ledger.mu.Unlock()
	sum := 0
	ledger.mu.Lock()
	for _, session := range ledger.sessions {
		for _, event := range session.events {
			sum += eventSize(event)
		}
	}
	ledger.mu.Unlock()
	if exact != sum {
		t.Errorf("event byte counter = %d, stored sizes sum to %d", exact, sum)
	}
	if sessions == 0 {
		t.Error("no session survived the fill")
	}
}

func TestEventNameIsCutAtTheWireLimit(t *testing.T) {
	ledger := New()
	now := time.Now()
	oversized := strings.Repeat("x", MaxEventNameBytes+40) + ".example"
	if !ledger.RecordEvent(eventInput("sess-name", oversized, now), now) {
		t.Fatal("the store rejected an oversized name instead of cutting it")
	}
	events := ledger.SnapshotEvents("sess-name", 0).Events
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if len(events[0].Name) != MaxEventNameBytes {
		t.Errorf("stored name length = %d, want the cap %d", len(events[0].Name), MaxEventNameBytes)
	}
	if snapshot := ledger.SnapshotEvents("sess-name", 0); snapshot.Limits.MaxNameBytes != MaxEventNameBytes {
		t.Errorf("reported name limit = %d, want %d", snapshot.Limits.MaxNameBytes, MaxEventNameBytes)
	}
}

func TestEventRetirementReturnsTheBudget(t *testing.T) {
	ledger := New()
	now := time.Now()
	for i := 0; i < 10; i++ {
		ledger.RecordEvent(eventInput("sess-retire", fmt.Sprintf("host%d.example", i), now), now)
	}
	before := ledger.SnapshotEvents("sess-retire", 0).Stats.Bytes
	if before == 0 {
		t.Fatal("the fixture stored no bytes")
	}

	ledger.RetireSession("sess-retire")

	ledger.mu.Lock()
	remainingBytes := ledger.eventBytes
	remainingRecords := ledger.eventTotal
	_, sessionExists := ledger.sessions["sess-retire"]
	ledger.mu.Unlock()
	if remainingBytes >= before || remainingRecords != 0 || sessionExists {
		t.Fatalf("retirement left bytes=%d (was %d), records=%d, session=%v",
			remainingBytes, before, remainingRecords, sessionExists)
	}
	if got := ledger.SnapshotEvents("sess-retire", 0).Total; got != 0 {
		t.Errorf("events after retirement = %d, want 0", got)
	}
}

func TestEventReadDoesNotMoveTheCounter(t *testing.T) {
	ledger := New()
	now := time.Now()
	ledger.RecordEvent(eventInput("sess-read", "plain.example", now), now)

	first := ledger.SnapshotEvents("sess-read", 0)
	second := ledger.SnapshotEvents("sess-read", 0)
	if first.Stats.Bytes != second.Stats.Bytes || first.Stats.Written != second.Stats.Written || first.Total != second.Total {
		t.Errorf("a read changed the store: %+v -> %+v", first.Stats, second.Stats)
	}
}
