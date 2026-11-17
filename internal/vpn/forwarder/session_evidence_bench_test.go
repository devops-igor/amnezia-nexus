package forwarder

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// Measured cost boundary for the per-session flow listing (issue #861).
//
// A per-session listing has to visit the whole flow table: records are keyed by
// 5-tuple, and no per-session index exists yet. The design gate is therefore to
// measure the real scan at the supported capacity instead of asserting a bound,
// and to publish the number that came out. `TestSnapshotSessionFlowsWorksAtCapacity`
// asserts the listing still returns the right record when the table is full, so
// the benchmark measures the same work the endpoint does and not a warm-up.
//
// Run with: go test -run '^$' -bench 'BenchmarkSnapshotSessionFlows' -benchmem

func fillFlowTableAtCapacity(tb testing.TB, fwd *Forwarder, dem *DirectEgressManager, flows int) (string, uint64) {
	tb.Helper()
	const sessionID = "sess-capacity"
	const peerKey = "peer-capacity"
	fwd.RegisterSession(sessionID, "conn-capacity", peerKey, "10.100.0.5", 11)
	generation := fwd.PeerRegistration(peerKey)

	// Every record gets a distinct destination port and a rotating destination
	// address, so the table holds `flows` genuinely distinct 5-tuples.
	for i := 0; i < flows; i++ {
		dst := netip.AddrFrom4([4]byte{93, 184, byte((i / 250) % 200), byte(i % 250)})
		port := uint16(1024 + i%60000)                                                                               // #nosec G115 -- bounded by the expression.
		pkt := buildTestIPv4TCPPacket(netip.MustParseAddr("10.100.0.5"), dst, uint16(40000+i%2000), port, 0x02, nil) // #nosec G115 -- bounded above.
		if err := dem.RecordFlow(peerKey, sessionID, generation, pkt, EgressChoiceProxy); err != nil {
			tb.Fatalf("RecordFlow %d/%d: %v", i, flows, err)
		}
	}
	dem.mu.RLock()
	filled := len(dem.flows)
	dem.mu.RUnlock()
	if filled != flows {
		tb.Fatalf("flow table holds %d records, want %d; the measurement would be of a smaller table", filled, flows)
	}
	return sessionID, generation
}

// TestSnapshotSessionFlowsWorksAtCapacity is the correctness half of the
// measurement: at the supported table size the listing still filters correctly
// and reports the real scan count.
func TestSnapshotSessionFlowsWorksAtCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("capacity fixture fills the default flow table")
	}
	fwd, dem, _ := newSessionEvidenceFixture(t, defaultMaxFlows)
	sessionID, generation := fillFlowTableAtCapacity(t, fwd, dem, defaultMaxFlows)

	// The visit is capped at SessionFlowScanRecords as a safety bound, while the total comes
	// from the selection's own membership and stays exact. The answer is therefore "this
	// client owns defaultMaxFlows flows, of which this page shows SessionFlowSnapshotMaxLimit
	// and this visit examined SessionFlowScanRecords" - not a windowed total.
	list := dem.SnapshotSessionFlows(sessionID, generation, time.Now(), SessionFlowSnapshotMaxLimit)
	if list.ScanComplete {
		t.Errorf("scan_complete = true for a %d-record selection visited with a %d-record window",
			defaultMaxFlows, SessionFlowScanRecords)
	}
	if list.Scanned != SessionFlowScanRecords {
		t.Errorf("scanned = %d, want the visit bound %d", list.Scanned, SessionFlowScanRecords)
	}
	if list.Total != defaultMaxFlows {
		t.Errorf("total = %d, want the selection's complete %d, not the visited window", list.Total, defaultMaxFlows)
	}
	if !list.Truncated || len(list.Flows) != SessionFlowSnapshotMaxLimit {
		t.Fatalf("page = %d truncated=%v, want %d truncated", len(list.Flows), list.Truncated, SessionFlowSnapshotMaxLimit)
	}
	// Another session owns nothing in this table.
	if other := dem.SnapshotSessionFlows("sess-other", generation, time.Now(), 0); other.Total != 0 {
		t.Errorf("unrelated session listing = %d, want 0", other.Total)
	}
}

// BenchmarkSnapshotSessionFlows measures one full page read of a full table:
// every one of the 65536 records belongs to the selected session, so the scan
// has no early exit and every record is copied and sorted. This is the worst
// case, not the typical one.
func BenchmarkSnapshotSessionFlows(b *testing.B) {
	fwd, dem, _ := newSessionEvidenceFixture(b, defaultMaxFlows)
	sessionID, generation := fillFlowTableAtCapacity(b, fwd, dem, defaultMaxFlows)
	now := time.Now()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		list := dem.SnapshotSessionFlows(sessionID, generation, now, SessionFlowSnapshotDefaultLimit)
		if len(list.Flows) == 0 {
			b.Fatal("empty listing; the measurement would be meaningless")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(defaultMaxFlows), "flows_in_table")
}

// BenchmarkSnapshotSessionFlowsSharedTable measures the same read when a full
// table is shared by 64 sessions: the scan still visits every record, but only
// one session's 1024 flows are copied and sorted.
func BenchmarkSnapshotSessionFlowsSharedTable(b *testing.B) {
	const sessions = 64
	const owner = "sess-00"

	fwd, dem, _ := newSessionEvidenceFixture(b, defaultMaxFlows)
	var ownerGeneration uint64
	for s := 0; s < sessions; s++ {
		sessionID := fmt.Sprintf("sess-%02d", s)
		peerKey := fmt.Sprintf("peer-%02d", s)
		fwd.RegisterSession(sessionID, "conn-"+sessionID, peerKey, fmt.Sprintf("10.100.%d.%d", s/250, s%250+1), 11)
		generation := fwd.PeerRegistration(peerKey)
		if sessionID == owner {
			ownerGeneration = generation
		}
		for i := 0; i < defaultMaxFlows/sessions; i++ {
			dst := netip.AddrFrom4([4]byte{93, 184, byte(s), byte(i % 250)})
			pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(fmt.Sprintf("10.100.%d.%d", s/250, s%250+1)),
				dst, uint16(40000+i%2000), uint16(1024+i%60000), 0x02, nil) // #nosec G115 -- bounded above.
			if err := dem.RecordFlow(peerKey, sessionID, generation, pkt, EgressChoiceProxy); err != nil {
				b.Fatalf("RecordFlow %s/%d: %v", sessionID, i, err)
			}
		}
	}
	dem.mu.RLock()
	filled := len(dem.flows)
	dem.mu.RUnlock()
	if filled != defaultMaxFlows {
		b.Fatalf("table holds %d records, want %d", filled, defaultMaxFlows)
	}

	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		list := dem.SnapshotSessionFlows(owner, ownerGeneration, now, SessionFlowSnapshotDefaultLimit)
		if len(list.Flows) != SessionFlowSnapshotDefaultLimit {
			b.Fatalf("listing returned %d flows, want a full page", len(list.Flows))
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(filled), "flows_in_table")
	b.ReportMetric(float64(filled/sessions), "flows_owned")
}
