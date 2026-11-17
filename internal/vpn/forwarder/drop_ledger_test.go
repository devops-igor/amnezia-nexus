package forwarder

import (
	"net/netip"
	"testing"
	"time"
)

// Bounds, purity and lifetime of the pre-flow drop ledger (issue #861).

func TestDropLedgerAggregatesByReasonAndTuple(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	dst := netip.MustParseAddr("8.8.4.4")

	for range 3 {
		ledger.Record("sess", 7, DropReasonProhibitedDestination, 6, dst, 443, true, 60, now)
	}
	ledger.Record("sess", 7, DropReasonInvalidPacket, 0, netip.Addr{}, 0, false, 12, now)

	snap := ledger.SessionSnapshot("sess", 0, 0, now)
	if snap.Total != 2 {
		t.Fatalf("records = %d, want the prohibited destination and the invalid packet", snap.Total)
	}
	var prohibited DropRecord
	for _, rec := range snap.Entries {
		if rec.Key.Reason == DropReasonProhibitedDestination {
			prohibited = rec
		}
	}
	if prohibited.Count != 3 {
		t.Errorf("aggregated count = %d, want 3 identical refusals collapsed", prohibited.Count)
	}
	if !prohibited.Key.HasTuple || prohibited.Key.DstIP != dst.As4() || prohibited.Key.DstPort != 443 {
		t.Errorf("tuple = %+v, want the parsed destination retained", prohibited.Key)
	}
	if prohibited.Bytes != 180 {
		t.Errorf("bytes = %d, want 3x60", prohibited.Bytes)
	}
}

func TestDropLedgerNeverInventsTupleForMalformedPackets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	// A malformed packet has no trusted destination, even if the caller passes one.
	ledger.Record("sess", 1, DropReasonInvalidPacket, 6, netip.MustParseAddr("1.2.3.4"), 80, false, 8, now)

	snap := ledger.SessionSnapshot("sess", 0, 0, now)
	if len(snap.Entries) != 1 {
		t.Fatalf("records = %d, want 1", len(snap.Entries))
	}
	if snap.Entries[0].Key.HasTuple {
		t.Error("a malformed packet was recorded with a tuple it never carried")
	}
	if snap.Entries[0].Key.DstIP != ([4]byte{}) || snap.Entries[0].Key.DstPort != 0 {
		t.Errorf("tuple = %+v, want empty metadata", snap.Entries[0].Key)
	}
}

func TestDropLedgerSessionCapEvictsAndCounts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })

	for i := range DropSessionKeyMax + 10 {
		dst := netip.AddrFrom4([4]byte{10, 1, byte(i / 256), byte(i % 256)})
		ledger.Record("sess", 1, DropReasonProhibitedDestination, 6, dst, 443, true, 40, now.Add(time.Duration(i)*time.Millisecond))
	}

	snap := ledger.SessionSnapshot("sess", 0, DropSnapshotMaxLimit, now.Add(time.Second))
	if snap.Total > DropSessionKeyMax {
		t.Errorf("session keys = %d, want the cap %d", snap.Total, DropSessionKeyMax)
	}
	if snap.Coverage.Evicted == 0 {
		t.Error("eviction was not reported, so a lost refusal would look like never-dropped")
	}
	if snap.Coverage.Keys > DropGlobalKeyMax {
		t.Errorf("global keys = %d, want at most %d", snap.Coverage.Keys, DropGlobalKeyMax)
	}
}

func TestDropLedgerAgeRetainsNothingPastTheWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	dst := netip.MustParseAddr("9.9.9.9")
	ledger.Record("sess", 1, DropReasonProhibitedDestination, 17, dst, 53, true, 40, now)

	fresh := ledger.SessionSnapshot("sess", 0, 0, now.Add(time.Minute))
	if fresh.Total != 1 {
		t.Fatalf("inside the window records = %d, want 1", fresh.Total)
	}
	// A read past the window reports nothing without deleting the record: retention is the
	// writer's business, and the read stays pure.
	stale := ledger.SessionSnapshot("sess", 0, 0, now.Add(DropMaxAge+time.Minute))
	if stale.Total != 0 {
		t.Errorf("past the window records = %d, want 0", stale.Total)
	}
	// The next write prunes it and says so.
	ledger.Record("sess", 1, DropReasonInvalidPacket, 0, netip.Addr{}, 0, false, 8, now.Add(DropMaxAge+2*time.Minute))
	if pruned := ledger.SessionSnapshot("sess", 0, 0, now.Add(DropMaxAge+2*time.Minute)).Coverage.Pruned; pruned == 0 {
		t.Error("aged records were not pruned on write, so the store would grow past its window")
	}
}

func TestDropLedgerIsolatesSessionsAndRetirement(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	dst := netip.MustParseAddr("7.7.7.7")
	ledger.Record("sess-a", 1, DropReasonProhibitedDestination, 6, dst, 443, true, 40, now)
	ledger.Record("sess-b", 2, DropReasonProhibitedDestination, 6, dst, 443, true, 40, now)

	if a := ledger.SessionSnapshot("sess-a", 0, 0, now); a.Total != 1 {
		t.Fatalf("sess-a records = %d, want only its own", a.Total)
	}
	if b := ledger.SessionSnapshot("sess-b", 0, 0, now); b.Total != 1 {
		t.Fatalf("sess-b records = %d, want only its own", b.Total)
	}

	ledger.ForgetSession("sess-a")
	if a := ledger.SessionSnapshot("sess-a", 0, 0, now); a.Total != 0 {
		t.Errorf("retired session still reports %d records", a.Total)
	}
	if b := ledger.SessionSnapshot("sess-b", 0, 0, now); b.Total != 1 {
		t.Errorf("retiring sess-a removed sess-b's evidence")
	}
}

func TestDropLedgerReadDoesNotMutate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	dst := netip.MustParseAddr("6.6.6.6")
	ledger.Record("sess", 1, DropReasonProhibitedDestination, 6, dst, 443, true, 40, now)

	before := ledger.SessionSnapshot("sess", 0, 0, now)
	for range 5 {
		_ = ledger.SessionSnapshot("sess", 0, DropSnapshotMaxLimit, now.Add(time.Second))
	}
	after := ledger.SessionSnapshot("sess", 0, 0, now)
	if before.Coverage.Stored != after.Coverage.Stored || before.Coverage.Pruned != after.Coverage.Pruned {
		t.Errorf("reads changed the store: stored %d->%d pruned %d->%d",
			before.Coverage.Stored, after.Coverage.Stored, before.Coverage.Pruned, after.Coverage.Pruned)
	}
	if before.Entries[0].LastSeen != after.Entries[0].LastSeen {
		t.Error("a read refreshed the record's recency")
	}
}

func TestDropLedgerPageBoundTruncates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ledger := newDropLedger(func() time.Time { return now })
	for i := range 8 {
		dst := netip.AddrFrom4([4]byte{10, 2, 0, byte(i + 1)})
		ledger.Record("sess", 1, DropReasonProhibitedDestination, 6, dst, 443, true, 40, now.Add(time.Duration(i)*time.Millisecond))
	}
	snap := ledger.SessionSnapshot("sess", 0, 3, now.Add(time.Second))
	if len(snap.Entries) != 3 || !snap.Truncated || snap.Total != 8 {
		t.Errorf("page = %d entries, truncated %v, total %d; want 3/true/8", len(snap.Entries), snap.Truncated, snap.Total)
	}
}
