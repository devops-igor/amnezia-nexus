package dnsledger

import (
	"fmt"
	"testing"
	"time"
)

// Global-capacity insertion for the incoming session (issue #861).
//
// Both stores are bounded globally and both delete a session's bucket once its last row
// is evicted. When that last row belongs to the session that is being written, the
// writer must still store its newest row where a reader looks: the bucket may be
// evicted, but it must not stay detached from the session map. These cases reach exactly
// that state through the public write path, then require the accepted row to be
// reachable, the counters to equal the rows that exist, and retirement to refund the
// whole occupancy.
//
// The companion cases are the neighbouring state: a row in the other store keeps the
// bucket non-empty, so eviction does not delete it. They must keep working.

// occupancy is the number of rows and estimated bytes that exist in both stores.
type occupancy struct {
	answerRows  int
	answerBytes int
	eventRows   int
	eventBytes  int
}

// reachableOccupancy walks the session map and counts what a reader can reach.
func reachableOccupancy(l *Ledger) occupancy {
	var out occupancy
	for _, session := range l.sessions {
		out.answerRows += len(session.records)
		out.answerBytes += session.bytes
		out.eventRows += len(session.events)
		out.eventBytes += session.eventBytes
	}
	return out
}

// requireExactAccounting pins the global counters to the rows that exist. A writer that
// appends to a detached bucket leaves the counters above the reachable rows, which is the
// capacity leak this file exists to catch.
func requireExactAccounting(t *testing.T, l *Ledger) {
	t.Helper()
	l.mu.Lock()
	reachable := reachableOccupancy(l)
	counters := occupancy{l.total, l.bytes, l.eventTotal, l.eventBytes}
	sessions := len(l.sessions)
	l.mu.Unlock()
	if counters != reachable {
		t.Fatalf("accounted occupancy %+v != reachable rows %+v across %d sessions",
			counters, reachable, sessions)
	}
}

// requireZeroOccupancyAfterRetirement retires every session and requires both stores to
// hold nothing, so the capacity the evicted rows freed is actually usable again.
func requireZeroOccupancyAfterRetirement(t *testing.T, l *Ledger, fillers int) {
	t.Helper()
	l.RetireSession("target")
	for i := 0; i < fillers; i += MaxRecordsPerSession {
		l.RetireSession(fmt.Sprintf("filler-%d", i/MaxRecordsPerSession))
	}
	l.mu.Lock()
	counters := occupancy{l.total, l.bytes, l.eventTotal, l.eventBytes}
	sessions := len(l.sessions)
	l.mu.Unlock()
	if counters != (occupancy{}) || sessions != 0 {
		t.Fatalf("retirement left events=%d/%d answers=%d/%d across %d sessions, want zero",
			counters.eventRows, counters.eventBytes, counters.answerRows, counters.answerBytes, sessions)
	}
}

func TestGlobalEvictionKeepsTheIncomingSessionBucket(t *testing.T) {
	for _, events := range []bool{false, true} {
		for _, companion := range []bool{false, true} {
			t.Run(fmt.Sprintf("events=%t/companion=%t", events, companion), func(t *testing.T) {
				l := New()
				now := time.Now()
				old := now.Add(-time.Minute)
				// put writes to the store under test.
				put := func(sessionID, name string, at time.Time) bool {
					if events {
						return l.RecordEvent(InputEvent{
							SessionID: sessionID, Name: name, Kind: "upstream_error",
							Transport: "udp", ReceivedAt: at, AnsweredAt: at,
						}, now)
					}
					return l.Record(Input{
						SessionID: sessionID, Name: name, ObservedAt: at,
						ExpiresAt: at.Add(5 * time.Minute),
					}, now)
				}
				// The target session's sole row in this store is the globally oldest.
				if !put("target", "old.example", old) {
					t.Fatal("seed row refused")
				}
				if companion {
					// A row in the OTHER store, so the bucket is not empty when its last
					// row in this store is evicted.
					if events {
						if !l.Record(Input{SessionID: "target", Name: "companion.example",
							ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, now) {
							t.Fatal("answer companion refused")
						}
					} else if !l.RecordEvent(InputEvent{SessionID: "target",
						Name: "companion.example", ReceivedAt: now}, now) {
						t.Fatal("event companion refused")
					}
				}
				// Fill to exactly the global cap, so the write below is what evicts.
				const fillers = MaxRecordsTotal - 1
				for i := 0; i < fillers; i++ {
					if !put(fmt.Sprintf("filler-%d", i/MaxRecordsPerSession), fmt.Sprintf("n%d.example", i), now) {
						t.Fatalf("filler %d refused", i)
					}
				}

				// The incoming write evicts the target's own last row in this store.
				if !put("target", "new.example", now) {
					t.Fatal("incoming row refused")
				}
				retained := l.Snapshot("target", 0).Total
				if events {
					retained = l.SnapshotEvents("target", 0).Total
				}
				if retained != 1 {
					t.Fatalf("accepted row unreachable: target holds %d rows in this store, want the one just written",
						retained)
				}
				requireExactAccounting(t, l)
				requireZeroOccupancyAfterRetirement(t, l, fillers)
			})
		}
	}
}
