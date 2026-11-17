package dnsledger

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Behavioural coverage for the bounded DNS record store (issue #861, slice 2).
//
// The properties under test are the ones an administrator's diagnosis depends on:
// every bound is enforced and reported, identical answers collapse instead of
// consuming slots, reads change nothing, and a retired session leaves no history.

func sampleInput(sessionID, name string, at time.Time, ttl time.Duration) Input {
	return Input{
		SessionID:            sessionID,
		RouteGeneration:      3,
		RouteGenerationKnown: true,
		Name:                 name,
		QType:                1,
		RCode:                0,
		ObservedAt:           at,
		ExpiresAt:            at.Add(ttl),
		PolicyGeneration:     "gen-1",
		ClassificationValid:  true,
		Addresses: []AddressDecision{{
			Address:  netip.MustParseAddr("93.184.216.34"),
			Decision: "DIRECT",
		}},
		ResolvedAddressCount: 1,
		CacheVerdict:         "ok",
	}
}

func TestRecordStoresAnObservedAnswer(t *testing.T) {
	ledger := New()
	now := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	in := sampleInput("sess-a", "plain.example", now, 5*time.Minute)
	in.Aliases = []string{"edge.cdn.example"}

	if !ledger.Record(in, now) {
		t.Fatal("Record rejected a valid observation")
	}

	snapshot := ledger.Snapshot("sess-a", 0)
	if len(snapshot.Records) != 1 || snapshot.Total != 1 || snapshot.Truncated {
		t.Fatalf("snapshot = %d records (total %d, truncated %v), want 1", len(snapshot.Records), snapshot.Total, snapshot.Truncated)
	}
	record := snapshot.Records[0]
	if record.Name != "plain.example" || record.QType != 1 || record.RCode != 0 {
		t.Errorf("record = %+v, want the stored name/type/rcode", record)
	}
	if len(record.Aliases) != 1 || record.Aliases[0] != "edge.cdn.example" {
		t.Errorf("aliases = %v, want the validated chain tail", record.Aliases)
	}
	if len(record.Addresses) != 1 || record.Addresses[0].Decision != "DIRECT" {
		t.Errorf("addresses = %v, want the written decision", record.Addresses)
	}
	if !record.RouteGenerationKnown || record.RouteGeneration != 3 {
		t.Errorf("incarnation = %d/%v, want the registered generation 3", record.RouteGeneration, record.RouteGenerationKnown)
	}
	if record.Count != 1 || !record.LastSeen.Equal(now) || !record.FirstSeen.Equal(now) {
		t.Errorf("count/first/last = %d/%v/%v, want one observation", record.Count, record.FirstSeen, record.LastSeen)
	}
	if snapshot.Stats.Written != 1 || snapshot.Stats.Records != 1 || snapshot.Stats.Sessions != 1 {
		t.Errorf("stats = %+v, want one written record in one session", snapshot.Stats)
	}
	if snapshot.Stats.StartedAt.IsZero() {
		t.Error("the store must report when it began")
	}
	if snapshot.Limits.RecordsPerSession != MaxRecordsPerSession || snapshot.Limits.MaxAgeSeconds != int64(MaxRecordAge/time.Second) {
		t.Errorf("limits = %+v, want the bounds in force", snapshot.Limits)
	}
}

func TestRecordCollapsesIdenticalActiveAnswers(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		in := sampleInput("sess-a", "plain.example", base.Add(time.Duration(i)*time.Second), 5*time.Minute)
		if !ledger.Record(in, base.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("Record %d rejected", i)
		}
	}
	snapshot := ledger.Snapshot("sess-a", 0)
	if len(snapshot.Records) != 1 {
		t.Fatalf("records = %d, want the three identical answers collapsed into one", len(snapshot.Records))
	}
	record := snapshot.Records[0]
	if record.Count != 3 {
		t.Errorf("count = %d, want 3", record.Count)
	}
	if !record.FirstSeen.Equal(base) {
		t.Errorf("first seen = %v, want the first observation", record.FirstSeen)
	}
	if !record.LastSeen.Equal(base.Add(2 * time.Second)) {
		t.Errorf("last seen = %v, want the newest observation", record.LastSeen)
	}
	if !record.ObservedAt.Equal(base) || !record.ExpiresAt.Equal(base.Add(5*time.Minute)) {
		t.Errorf("the record must keep its original instant and deadline, got %v/%v", record.ObservedAt, record.ExpiresAt)
	}
	if snapshot.Stats.Collapsed != 2 {
		t.Errorf("collapsed = %d, want 2", snapshot.Stats.Collapsed)
	}

	// A different decision is a different fact and must not collapse.
	other := sampleInput("sess-a", "plain.example", base.Add(3*time.Second), 5*time.Minute)
	other.Addresses = []AddressDecision{{Address: netip.MustParseAddr("93.184.216.34"), Decision: "PROXY"}}
	if !ledger.Record(other, base.Add(3*time.Second)) {
		t.Fatal("Record rejected the differing answer")
	}
	if got := len(ledger.Snapshot("sess-a", 0).Records); got != 2 {
		t.Errorf("records = %d, want the differing decision stored separately", got)
	}

	// An expired record is history: a later identical answer is a new record.
	later := base.Add(10 * time.Minute)
	if !ledger.Record(sampleInput("sess-a", "plain.example", later, 5*time.Minute), later) {
		t.Fatal("Record rejected the post-expiry answer")
	}
	if got := len(ledger.Snapshot("sess-a", 0).Records); got != 3 {
		t.Errorf("records = %d, want a new record after the previous evidence expired", got)
	}
}

func TestRecordEnforcesThePerSessionCap(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	for i := 0; i < MaxRecordsPerSession+5; i++ {
		in := sampleInput("sess-a", fmt.Sprintf("host%d.example", i), base.Add(time.Duration(i)*time.Second), 5*time.Minute)
		if !ledger.Record(in, base.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("Record %d rejected while the cap should have evicted instead", i)
		}
	}
	snapshot := ledger.Snapshot("sess-a", 0)
	if snapshot.Total != MaxRecordsPerSession {
		t.Fatalf("stored = %d, want the per-session cap %d", snapshot.Total, MaxRecordsPerSession)
	}
	if snapshot.Stats.EvictedSession != 5 {
		t.Errorf("evicted per session = %d, want 5", snapshot.Stats.EvictedSession)
	}
	// The oldest records are the ones gone; the newest survive.
	for _, record := range snapshot.Records {
		if record.Name == "host0.example" {
			t.Error("the oldest record survived the cap")
		}
	}
}

func TestRecordEnforcesTheGlobalRecordCap(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	// Enough sessions to exceed the global cap while staying under the
	// per-session one. The whole run has to fit inside the age window, or aging
	// would keep the total under the cap and the eviction path would never run.
	sessions := MaxRecordsTotal/MaxRecordsPerSession + 2
	for s := 0; s < sessions; s++ {
		for i := 0; i < MaxRecordsPerSession; i++ {
			at := base.Add(time.Duration(s*MaxRecordsPerSession+i) * time.Millisecond)
			in := sampleInput(fmt.Sprintf("sess-%03d", s), fmt.Sprintf("host%d.example", i), at, 5*time.Minute)
			ledger.Record(in, at)
		}
	}
	snapshot := ledger.Snapshot("sess-000", 1)
	if snapshot.Stats.Records > MaxRecordsTotal {
		t.Fatalf("stored = %d, want at most the global cap %d", snapshot.Stats.Records, MaxRecordsTotal)
	}
	if snapshot.Stats.EvictedGlobal == 0 {
		t.Error("the global cap was reached without reporting an eviction")
	}
	if snapshot.Stats.Sessions > sessions {
		t.Errorf("sessions = %d, want at most the created %d", snapshot.Stats.Sessions, sessions)
	}
}

func TestRecordEnforcesTheByteBudget(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	// Long-but-legal names and alias chains push record sizes up, so the byte
	// budget is reached before the record caps.
	label := strings.Repeat("a", 60)
	written := 0
	for i := 0; i < MaxRecordsTotal; i++ {
		name := fmt.Sprintf("%s%d.example", label, i)
		in := sampleInput("sess-bytes", name, base.Add(time.Duration(i)*time.Second), 5*time.Minute)
		in.Aliases = []string{label + ".alias.example", label + "2.alias.example"}
		if ledger.Record(in, base.Add(time.Duration(i)*time.Second)) {
			written++
		}
		if snapshot := ledger.Snapshot("sess-bytes", 1); snapshot.Stats.Bytes > MaxBytesTotal {
			t.Fatalf("estimated bytes = %d exceeded the budget %d", snapshot.Stats.Bytes, MaxBytesTotal)
		}
	}
	if written == 0 {
		t.Fatal("no record was stored at all")
	}
	snapshot := ledger.Snapshot("sess-bytes", 1)
	if snapshot.Stats.Bytes > MaxBytesTotal {
		t.Errorf("estimated bytes = %d, want at most %d", snapshot.Stats.Bytes, MaxBytesTotal)
	}
}

func TestRecordPrunesAgedRecordsOnWrite(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	if !ledger.Record(sampleInput("sess-a", "old.example", base, 5*time.Minute), base) {
		t.Fatal("Record rejected the old observation")
	}
	// One minute later the record is still inside the age window...
	if !ledger.Record(sampleInput("sess-a", "new.example", base.Add(time.Minute), 5*time.Minute), base.Add(time.Minute)) {
		t.Fatal("Record rejected the new observation")
	}
	if got := ledger.Snapshot("sess-a", 0).Total; got != 2 {
		t.Fatalf("stored = %d, want both records inside the age window", got)
	}

	// ...and one window later a write prunes it, without any timer.
	later := base.Add(MaxRecordAge + time.Minute)
	if !ledger.Record(sampleInput("sess-a", "newer.example", later, 5*time.Minute), later) {
		t.Fatal("Record rejected the newest observation")
	}
	snapshot := ledger.Snapshot("sess-a", 0)
	for _, record := range snapshot.Records {
		if record.Name == "old.example" {
			t.Error("a record older than the age window survived a write")
		}
	}
	if snapshot.Stats.AgedOut == 0 {
		t.Error("aging out was not reported")
	}
}

func TestSnapshotDoesNotMutateOrPrune(t *testing.T) {
	ledger := New()
	// The record is dated well past the age window in real time, so a read that
	// pruned (with its own clock, or with any clock) would drop it. A read must
	// report it as found instead.
	base := time.Now().Add(-3 * MaxRecordAge)
	ledger.Record(sampleInput("sess-a", "plain.example", base, time.Minute), base)

	first := ledger.Snapshot("sess-a", 0)
	second := ledger.Snapshot("sess-a", 0)

	if first.Total != 1 || len(second.Records) != 1 {
		t.Fatalf("reads dropped the record: %d/%d", first.Total, len(second.Records))
	}
	if first.Stats.AgedOut != 0 || second.Stats.AgedOut != 0 {
		t.Error("a read aged a record out")
	}
	if first.Stats.Written != second.Stats.Written || first.Stats.Records != second.Stats.Records {
		t.Error("a read changed the collector's counters")
	}
	if !first.Records[0].ExpiresAt.Equal(second.Records[0].ExpiresAt) {
		t.Error("a read changed a stored deadline")
	}
}

func TestSnapshotOrdersNewestFirstAndTruncates(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		ledger.Record(sampleInput("sess-a", fmt.Sprintf("host%d.example", i), at, 5*time.Minute), at)
	}

	snapshot := ledger.Snapshot("sess-a", 2)
	if snapshot.Total != 3 || !snapshot.Truncated || len(snapshot.Records) != 2 {
		t.Fatalf("page = %d (total %d, truncated %v), want 2 of 3", len(snapshot.Records), snapshot.Total, snapshot.Truncated)
	}
	if snapshot.Records[0].Name != "host2.example" || snapshot.Records[1].Name != "host1.example" {
		t.Errorf("order = %s,%s, want newest first", snapshot.Records[0].Name, snapshot.Records[1].Name)
	}

	full := ledger.Snapshot("sess-a", 0)
	if full.Truncated || len(full.Records) != 3 {
		t.Errorf("default page = %d truncated=%v, want all 3", len(full.Records), full.Truncated)
	}
}

func TestRetireSessionDropsItsHistory(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	ledger.Record(sampleInput("sess-a", "a.example", base, 5*time.Minute), base)
	ledger.Record(sampleInput("sess-b", "b.example", base, 5*time.Minute), base)

	ledger.RetireSession("sess-a")

	if got := ledger.Snapshot("sess-a", 0); got.Total != 0 || len(got.Records) != 0 {
		t.Fatalf("retired session holds %d records, want none", got.Total)
	}
	other := ledger.Snapshot("sess-b", 0)
	if other.Total != 1 {
		t.Errorf("another session's records moved: %d", other.Total)
	}
	if other.Stats.Records != 1 || other.Stats.Sessions != 1 {
		t.Errorf("stats after retirement = %+v, want one record in one session", other.Stats)
	}
	// Idempotent: retiring twice is not an error and does not move counters.
	ledger.RetireSession("sess-a")
	if got := ledger.Snapshot("sess-b", 0).Stats.Records; got != 1 {
		t.Errorf("records after a second retirement = %d, want 1", got)
	}
}

func TestCanonicalNameIsStableForComparison(t *testing.T) {
	cases := map[string]string{
		"Plain.Example.":   "plain.example",
		"  spaced.example": "spaced.example",
		"UPPER.EXAMPLE":    "upper.example",
	}
	for input, want := range cases {
		if got := CanonicalName(input); got != want {
			t.Errorf("CanonicalName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSameObservationComparesEveryStoredFact(t *testing.T) {
	base := Record{
		Name:                "plain.example",
		QType:               1,
		RCode:               0,
		CacheVerdict:        "ok",
		PolicyGeneration:    "gen-1",
		RouteGeneration:     3,
		ClassificationValid: true,
		Addresses:           []AddressDecision{{Address: netip.MustParseAddr("93.184.216.34"), Decision: "DIRECT"}},
	}
	if !sameObservation(base, base) {
		t.Fatal("a record must equal itself")
	}
	differences := map[string]Record{
		"Name":             {Name: "other.example", QType: 1, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 3, ClassificationValid: true, Addresses: base.Addresses},
		"QType":            {Name: "plain.example", QType: 28, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 3, ClassificationValid: true, Addresses: base.Addresses},
		"RCode":            {Name: "plain.example", QType: 1, RCode: 3, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 3, ClassificationValid: true, Addresses: base.Addresses},
		"CacheVerdict":     {Name: "plain.example", QType: 1, CacheVerdict: "quarantined", PolicyGeneration: "gen-1", RouteGeneration: 3, ClassificationValid: true, Addresses: base.Addresses},
		"PolicyGeneration": {Name: "plain.example", QType: 1, CacheVerdict: "ok", PolicyGeneration: "gen-2", RouteGeneration: 3, ClassificationValid: true, Addresses: base.Addresses},
		"RouteGeneration":  {Name: "plain.example", QType: 1, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 4, ClassificationValid: true, Addresses: base.Addresses},
		"IncarnationKnown": {Name: "plain.example", QType: 1, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 3, RouteGenerationKnown: true, ClassificationValid: true, Addresses: base.Addresses},
		"Classification":   {Name: "plain.example", QType: 1, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 3},
		"Addresses":        {Name: "plain.example", QType: 1, CacheVerdict: "ok", PolicyGeneration: "gen-1", RouteGeneration: 3, ClassificationValid: true, Addresses: []AddressDecision{{Address: netip.MustParseAddr("93.184.216.34"), Decision: "PROXY"}}},
	}
	for name, other := range differences {
		if sameObservation(base, other) {
			t.Errorf("a record differing in %s compared equal", name)
		}
	}
}

func TestRecordRejectsUnusableInput(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	noSession := sampleInput("", "plain.example", base, time.Minute)
	if ledger.Record(noSession, base) {
		t.Error("a record without a session id was accepted")
	}
	noName := sampleInput("sess-a", "", base, time.Minute)
	if ledger.Record(noName, base) {
		t.Error("a record without a name was accepted")
	}
	var nilLedger *Ledger
	if nilLedger.Record(sampleInput("sess-a", "x.example", base, time.Minute), base) {
		t.Error("a nil ledger accepted a record")
	}
	if got := nilLedger.Snapshot("sess-a", 0); got.Total != 0 || got.Records == nil {
		t.Error("a nil ledger must answer an empty snapshot")
	}
}

func TestRecordTruncatesThePerRecordLists(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	in := sampleInput("sess-a", "chain.example", base, 5*time.Minute)
	in.Aliases = nil
	for i := 0; i < MaxNamesPerRecord+4; i++ {
		in.Aliases = append(in.Aliases, fmt.Sprintf("alias%d.example", i))
	}
	in.Addresses = nil
	for i := 0; i < MaxAddressesPerRecord+6; i++ {
		in.Addresses = append(in.Addresses, AddressDecision{
			Address:  netip.AddrFrom4([4]byte{93, 184, 216, byte(i)}),
			Decision: "DIRECT",
		})
	}
	if !ledger.Record(in, base) {
		t.Fatal("Record rejected an answer that only needed truncation")
	}
	record := ledger.Snapshot("sess-a", 0).Records[0]
	if len(record.Aliases) != MaxNamesPerRecord {
		t.Errorf("aliases = %d, want the cap %d", len(record.Aliases), MaxNamesPerRecord)
	}
	if len(record.Addresses) != MaxAddressesPerRecord {
		t.Errorf("addresses = %d, want the cap %d", len(record.Addresses), MaxAddressesPerRecord)
	}
	if !record.Truncated {
		t.Error("a cut record must report the truncation")
	}
}

func TestRecordCountsMissingIncarnation(t *testing.T) {
	ledger := New()
	base := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)

	in := sampleInput("sess-a", "unbound.example", base, 5*time.Minute)
	in.RouteGenerationKnown = false
	in.RouteGeneration = 0
	ledger.Record(in, base)

	snapshot := ledger.Snapshot("sess-a", 0)
	if snapshot.Records[0].RouteGenerationKnown {
		t.Error("an unestablished incarnation was stored as known")
	}
	if snapshot.Stats.WithoutIncarnate != 1 {
		t.Errorf("without incarnation = %d, want 1", snapshot.Stats.WithoutIncarnate)
	}
}
