package forwarder

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Per-client DROP evidence (issue #861).
//
// Some client packets are refused before any flow exists: the destination is prohibited,
// or the packet is not shaped well enough to be a flow at all. The global drop counters
// prove that something was dropped, never which client's packet it was or why, so the
// per-client answer cannot explain this client's failure.
//
// This ledger records those refusals at the producer that made them. It is bounded in
// every direction: keys are aggregated by reason plus whatever tuple metadata the packet
// legitimately carries, older than a fixed window is pruned on write, and the per-session
// and global key counts are capped with an explicit eviction count. A read is pure: it
// sorts and copies, never prunes, never refreshes recency, never resurrects a retired
// session.
//
// No payload, no peer key, no credential and no history beyond the age window is stored.
// Nothing here decides anything: the producer has already refused the packet, and this
// only records why.

// Drop reason tokens. They name the producer that refused the packet.
const (
	DropReasonProhibitedDestination = "prohibited_destination"
	DropReasonInvalidPacket         = "invalid_client_packet"
	// The three refusals below happen while the packet path is trying to install flow state.
	// They are refusals of the packet (it is not forwarded), so they belong in this ledger
	// even though the reason is about the table or the WAN rather than the destination.
	DropReasonNATPortExhaustion = "nat_port_exhaustion"
	DropReasonEgressUnavailable = "direct_egress_unavailable"
	DropReasonFlowTableFull     = "flow_table_full"
)

// Drop ledger bounds.
const (
	// DropMaxAge is the longest a drop record is retained.
	DropMaxAge = 10 * time.Minute
	// DropSessionKeyMax bounds the distinct keys one session may retain. A client that
	// sprays destinations must not grow the ledger without limit, and the oldest key is
	// evicted (and counted) rather than silently dropped.
	DropSessionKeyMax = 64
	// DropGlobalKeyMax bounds the whole ledger across sessions.
	DropGlobalKeyMax = 2048
	// DropSnapshotDefaultLimit is the page size a session read returns by default.
	DropSnapshotDefaultLimit = 32
	// DropSnapshotMaxLimit bounds one page, so a caller cannot request the whole ledger.
	DropSnapshotMaxLimit = 128
)

// DropKey aggregates refusals that differ only by when they happened.
type DropKey struct {
	SessionID  string
	Generation uint64
	Reason     string
	// Protocol and the destination are recorded only when the packet carried them
	// legitimately. HasTuple says whether the tuple fields mean anything at all, so a
	// malformed packet never appears with a destination it did not have.
	Protocol uint8
	DstIP    [4]byte
	DstPort  uint16
	HasTuple bool
}

// DropRecord is one aggregated refusal.
type DropRecord struct {
	Key       DropKey
	Count     uint64
	Bytes     uint64
	FirstSeen time.Time
	LastSeen  time.Time
}

// DropCoverage states what the ledger holds and what it lost.
type DropCoverage struct {
	StartedAt time.Time
	Stored    uint64
	Merged    uint64
	Evicted   uint64
	Pruned    uint64
	// Keys is the ledger-wide key count and SessionKeys the selected session's, so a
	// client-scoped page never presents other clients' retention as its own.
	Keys        int
	SessionKeys int
}

// DropSnapshot is one bounded, pure read of a session's refusals.
type DropSnapshot struct {
	Entries      []DropRecord
	Total        int
	Truncated    bool
	Generation   uint64
	Keys         int
	SessionLimit int
	GlobalLimit  int
	Coverage     DropCoverage
}

// dropLedger is the bounded store. It is deliberately small and lock-scoped: writes are
// one lock for a map update, reads are one lock for a copy, and there is no background
// goroutine or timer.
type dropLedger struct {
	mu     sync.Mutex
	now    func() time.Time
	byKey  map[DropKey]*DropRecord
	keys   int
	cov    DropCoverage
	maxAge time.Duration
}

func newDropLedger(now func() time.Time) *dropLedger {
	if now == nil {
		now = time.Now
	}
	return &dropLedger{
		now:    now,
		byKey:  make(map[DropKey]*DropRecord),
		cov:    DropCoverage{StartedAt: now()},
		maxAge: DropMaxAge,
	}
}

// Record aggregates one refused packet under its reason and available tuple.
func (l *dropLedger) Record(sessionID string, generation uint64, reason string, protocol uint8, dst netip.Addr, dstPort uint16, hasTuple bool, bytes int64, now time.Time) {
	if l == nil || sessionID == "" || reason == "" {
		return
	}
	if now.IsZero() {
		now = l.now()
	}
	key := DropKey{SessionID: sessionID, Generation: generation, Reason: reason, Protocol: protocol, HasTuple: hasTuple}
	if hasTuple && dst.Is4() {
		key.DstIP = dst.As4()
		key.DstPort = dstPort
	}
	if !hasTuple {
		key.DstIP = [4]byte{}
		key.DstPort = 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)
	if rec, ok := l.byKey[key]; ok {
		rec.Count++
		if bytes > 0 {
			rec.Bytes += uint64(bytes) // #nosec G115 -- bytes is a packet length, never negative.
		}
		rec.LastSeen = now
		l.cov.Merged++
		return
	}
	// Make room before inserting, so the cap is a hard bound rather than a target.
	for l.keys >= DropGlobalKeyMax {
		if !l.evictOldestLocked("", now) {
			return
		}
	}
	for l.sessionKeysLocked(sessionID) >= DropSessionKeyMax {
		if !l.evictOldestLocked(sessionID, now) {
			return
		}
	}
	rec := &DropRecord{Key: key, Count: 1, FirstSeen: now, LastSeen: now}
	if bytes > 0 {
		rec.Bytes = uint64(bytes) // #nosec G115 -- packet length.
	}
	l.byKey[key] = rec
	l.keys++
	l.cov.Stored++
}

// pruneLocked drops records that aged out. It runs on write only: a read must not mutate
// the store. Retention is therefore physical-until-the-next-write, and a read is
// age-filtered, so a record can still occupy memory past the window while being invisible
// to every reader. This is a bound, not an erasure guarantee at the exact instant.
func (l *dropLedger) pruneLocked(now time.Time) {
	if l.maxAge <= 0 {
		return
	}
	cutoff := now.Add(-l.maxAge)
	for key, rec := range l.byKey {
		if rec.LastSeen.Before(cutoff) {
			delete(l.byKey, key)
			l.keys--
			l.cov.Pruned++
		}
	}
}

// evictOldestLocked removes the oldest record, optionally only within one session.
func (l *dropLedger) evictOldestLocked(sessionID string, _ time.Time) bool {
	var oldestKey DropKey
	var oldest time.Time
	found := false
	for key, rec := range l.byKey {
		if sessionID != "" && key.SessionID != sessionID {
			continue
		}
		if !found || rec.LastSeen.Before(oldest) {
			oldestKey, oldest, found = key, rec.LastSeen, true
		}
	}
	if !found {
		return false
	}
	delete(l.byKey, oldestKey)
	l.keys--
	l.cov.Evicted++
	return true
}

func (l *dropLedger) sessionKeysLocked(sessionID string) int {
	n := 0
	for key := range l.byKey {
		if key.SessionID == sessionID {
			n++
		}
	}
	return n
}

// SessionSnapshot returns this session's refusals, newest first, bounded to limit.
//
// It is a pure read: no pruning, no recency update, no cross-session data. A session whose
// records were retired reports an empty snapshot, never another session's evidence.
func (l *dropLedger) SessionSnapshot(sessionID string, generation uint64, limit int, now time.Time) DropSnapshot {
	if limit <= 0 {
		limit = DropSnapshotDefaultLimit
	}
	if limit > DropSnapshotMaxLimit {
		limit = DropSnapshotMaxLimit
	}
	out := DropSnapshot{SessionLimit: DropSessionKeyMax, GlobalLimit: DropGlobalKeyMax, Generation: generation}
	if l == nil || sessionID == "" {
		return out
	}
	if now.IsZero() {
		now = l.now()
	}
	cutoff := now.Add(-l.maxAge)

	l.mu.Lock()
	out.Coverage = l.cov
	out.Coverage.Keys = l.keys
	out.Keys = l.keys
	for key, rec := range l.byKey {
		if key.SessionID != sessionID {
			continue
		}
		// Only the selected incarnation's refusals are current. A row from a replaced
		// generation is not returned as this client's present evidence.
		if generation != 0 && key.Generation != generation {
			continue
		}
		// An aged record is reported as absent rather than as fresh evidence, and the read
		// does not delete it: retention is the writer's business.
		if rec.LastSeen.Before(cutoff) {
			continue
		}
		out.Total++
		out.Coverage.SessionKeys++
		out.Entries = append(out.Entries, *rec)
	}
	l.mu.Unlock()

	sort.Slice(out.Entries, func(i, j int) bool {
		if !out.Entries[i].LastSeen.Equal(out.Entries[j].LastSeen) {
			return out.Entries[i].LastSeen.After(out.Entries[j].LastSeen)
		}
		if out.Entries[i].Key.Reason != out.Entries[j].Key.Reason {
			return out.Entries[i].Key.Reason < out.Entries[j].Key.Reason
		}
		return out.Entries[i].Key.DstPort > out.Entries[j].Key.DstPort
	})
	if len(out.Entries) > limit {
		out.Entries = out.Entries[:limit]
		out.Truncated = true
	}
	return out
}

// ForgetSession removes every record of one session. It is called when the session is
// retired, so a read after retirement cannot resurrect ended evidence.
func (l *dropLedger) ForgetSession(sessionID string) {
	if l == nil || sessionID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for key := range l.byKey {
		if key.SessionID == sessionID {
			delete(l.byKey, key)
			l.keys--
		}
	}
}
