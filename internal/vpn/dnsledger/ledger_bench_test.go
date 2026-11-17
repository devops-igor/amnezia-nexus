package dnsledger

import (
	"fmt"
	"testing"
	"time"
)

// Measured cost of the write path (issue #861, slice 2).
//
// The collector is written from the intercepted-DNS observer, which runs after the
// answer has been delivered — not on the packet path — and it takes only its own
// mutex. The measurement exists so "bounded" is a number rather than a claim: a
// write is O(records in the session) for the collapse check and O(records) for a
// global eviction, both capped by the constants above.
//
// Run with: go test -run '^$' -bench 'BenchmarkRecord' -benchmem ./internal/vpn/dnsledger/

// fillLedger brings the collector to its record caps: every session full, the
// global table full.
func fillLedger(tb testing.TB, ledger *Ledger, sessions, perSession int, base time.Time) {
	tb.Helper()
	for s := 0; s < sessions; s++ {
		for i := 0; i < perSession; i++ {
			at := base.Add(time.Duration(s*perSession+i) * time.Millisecond)
			in := sampleInput(fmt.Sprintf("sess-%03d", s), fmt.Sprintf("host%d.example", i), at, 5*time.Minute)
			ledger.Record(in, at)
		}
	}
	snapshot := ledger.Snapshot("sess-000", 1)
	if snapshot.Stats.Records == 0 {
		tb.Fatal("the fixture stored nothing; the measurement would be meaningless")
	}
}

// BenchmarkRecordIntoFullLedger measures one write when the target session is full
// and the global table is at its cap, which is the worst case for the write path.
func BenchmarkRecordIntoFullLedger(b *testing.B) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	fillLedger(b, ledger, MaxRecordsTotal/MaxRecordsPerSession, MaxRecordsPerSession, base)

	now := base.Add(time.Minute)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := sampleInput("sess-000", fmt.Sprintf("new%d.example", i), now, 5*time.Minute)
		ledger.Record(in, now)
	}
	b.StopTimer()
	snapshot := ledger.Snapshot("sess-000", 0)
	b.ReportMetric(float64(snapshot.Stats.Records), "records_stored")
	b.ReportMetric(float64(snapshot.Stats.Bytes), "estimated_bytes")
}

// BenchmarkRecordNewSessionIntoFullLedger measures the same write when the
// session is new, so the global eviction path runs on every iteration.
func BenchmarkRecordNewSessionIntoFullLedger(b *testing.B) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	fillLedger(b, ledger, MaxRecordsTotal/MaxRecordsPerSession, MaxRecordsPerSession, base)

	now := base.Add(time.Minute)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in := sampleInput(fmt.Sprintf("sess-new-%d", i), "new.example", now, 5*time.Minute)
		ledger.Record(in, now)
	}
	b.StopTimer()
	b.ReportMetric(float64(ledger.Snapshot("sess-new-0", 0).Stats.Records), "records_stored")
}

// BenchmarkSnapshotFullSession measures one diagnosis read of a full session.
func BenchmarkSnapshotFullSession(b *testing.B) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	fillLedger(b, ledger, 1, MaxRecordsPerSession, base)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snapshot := ledger.Snapshot("sess-000", MaxRecordsPerSession)
		if len(snapshot.Records) == 0 {
			b.Fatal("empty snapshot; the measurement would be meaningless")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(MaxRecordsPerSession), "records_in_session")
}
