// Package dnsledger keeps a bounded, in-memory record of the DNS answers the
// router actually observed for a client session (issue #861, slice 2).
//
// It is a leaf package: standard library only, no lock from another subsystem
// and no I/O. The only writer is the intercepted-DNS observer, and everything it
// stores is what that observer already decided: the names it validated, the
// addresses whose decisions it wrote into the route cache, and the instant and
// deadline of that write. It performs no classification of its own, so it cannot
// turn a rejected answer into trusted evidence.
//
// Storage is bounded four ways and every bound is reported:
//
//   - per session records (MaxRecordsPerSession),
//   - total records across sessions (MaxRecordsTotal),
//   - estimated bytes across sessions (MaxBytesTotal),
//   - age (MaxRecordAge), pruned on write.
//
// Reads never mutate: expired records are reported as expired rather than
// removed, and no counter moves because a diagnosis was requested. Pruning
// happens only on the write path, so the collector is a function of the traffic
// and not of who is watching.
package dnsledger

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// MaxRecordsPerSession bounds one session's history. 128 records is about a
	// minute of ordinary browsing per client and matches the DNS-ledger
	// proposal; a chatty client that repeats an answer collapses instead of
	// consuming slots (see the collapse rule on Record).
	MaxRecordsPerSession = 128
	// MaxRecordsTotal bounds the whole ledger independently of the session
	// count, so the memory a hundred connected clients can consume does not
	// depend on how many of them happen to be browsing.
	MaxRecordsTotal = 4096
	// MaxRecordAge is how long one record may live. It is deliberately much
	// shorter than a DNS TTL ceiling: a diagnosis is about what just happened,
	// and post-retirement browsing history is out of scope.
	MaxRecordAge = 30 * time.Minute
	// MaxBytesTotal is the estimated-byte budget for stored records. Per-record
	// sizes are dominated by the name and the address list, so the estimate is
	// name bytes + alias bytes + 4 bytes per address + a fixed record overhead.
	MaxBytesTotal = 4 << 20
	// MaxNamesPerRecord bounds the validated alias chain stored for one answer.
	MaxNamesPerRecord = 8
	// MaxAddressesPerRecord bounds the addresses stored for one answer.
	MaxAddressesPerRecord = 16
	// recordOverheadBytes is the estimated fixed cost of one stored record
	// (struct, seq, timestamps, generation and the collapse counters).
	recordOverheadBytes = 160
)

// AddressDecision is one address the observer wrote into the route cache, with
// the decision it wrote. It is a copy of a decision that already happened; the
// ledger never decides anything.
type AddressDecision struct {
	Address  netip.Addr
	Decision string
}

// Input is what the observer hands to the ledger: one observed answer, already
// classified and already applied to the route cache.
type Input struct {
	SessionID            string
	RouteGeneration      uint64
	RouteGenerationKnown bool
	Name                 string
	Aliases              []string
	QType                uint16
	RCode                int
	ObservedAt           time.Time
	ExpiresAt            time.Time
	PolicyGeneration     string
	ClassificationValid  bool
	ClassificationReason string
	Addresses            []AddressDecision
	ResolvedAddressCount int
	// CacheVerdict is the route cache's answer to the write: "ok", or a short
	// reason when it refused (quarantined, generation mismatch, retired).
	CacheVerdict string
}

// Record is one stored observation.
type Record struct {
	Seq                  uint64
	SessionID            string
	RouteGeneration      uint64
	RouteGenerationKnown bool
	Name                 string
	Aliases              []string
	QType                uint16
	RCode                int
	ObservedAt           time.Time
	ExpiresAt            time.Time
	PolicyGeneration     string
	ClassificationValid  bool
	ClassificationReason string
	Addresses            []AddressDecision
	ResolvedAddressCount int
	CacheVerdict         string
	// Count is how many identical observations collapsed into this record, and
	// LastSeen is the most recent of them. FirstSeen is ObservedAt.
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	// Truncated reports that the stored alias chain or address list was cut by
	// the per-record caps.
	Truncated bool
}

// Stats is the collector's own accounting. It is read once per diagnosis and
// never changed by the read.
type Stats struct {
	StartedAt        time.Time
	Written          int64
	Collapsed        int64
	EvictedSession   int64
	EvictedGlobal    int64
	AgedOut          int64
	RejectedNoRoom   int64
	WithoutIncarnate int64
	Sessions         int
	Records          int
	Bytes            int
}

// Limits reports the bounds in force, so an answer can state them instead of
// describing them in prose.
type Limits struct {
	RecordsPerSession  int
	RecordsTotal       int
	MaxAgeSeconds      int64
	BytesTotal         int
	NamesPerRecord     int
	AddressesPerRecord int
}

// Limits returns the bounds this ledger enforces.
func (l *Ledger) Limits() Limits {
	return Limits{
		RecordsPerSession:  MaxRecordsPerSession,
		RecordsTotal:       MaxRecordsTotal,
		MaxAgeSeconds:      int64(MaxRecordAge / time.Second),
		BytesTotal:         MaxBytesTotal,
		NamesPerRecord:     MaxNamesPerRecord,
		AddressesPerRecord: MaxAddressesPerRecord,
	}
}

type sessionLog struct {
	records []Record
	bytes   int
}

// Ledger is the bounded in-memory DNS record store.
type Ledger struct {
	mu       sync.Mutex
	started  time.Time
	seq      uint64
	sessions map[string]*sessionLog
	total    int
	bytes    int
	stats    Stats
}

// New returns an empty ledger. The start instant is the ledger's own, not the
// process's: a diagnosis that reports a window must report when this store began.
func New() *Ledger {
	return &Ledger{
		started:  time.Now(),
		sessions: make(map[string]*sessionLog),
	}
}

// Record stores one observed answer. It returns false when the record could not
// be kept at all (no session id, or a single record larger than the whole
// budget), which the caller reports as truncation rather than silently dropping.
//
// The write path is the only place that prunes: records older than MaxRecordAge
// are removed here, on the same lock, so the store's size is a function of the
// traffic and never of a timer.
func (l *Ledger) Record(in Input, now time.Time) bool {
	in, ok := normalizeInput(in, now)
	if l == nil || !ok {
		return false
	}
	built := buildRecord(l.nextSeq(), in)
	built.FirstSeen = in.ObservedAt
	built.LastSeen = in.ObservedAt
	built.Count = 1
	size := recordSize(built)

	l.mu.Lock()
	defer l.mu.Unlock()

	if size > MaxBytesTotal {
		l.stats.RejectedNoRoom++
		return false
	}
	l.pruneLocked(now)

	session := l.sessions[in.SessionID]
	if session == nil {
		session = &sessionLog{}
		l.sessions[in.SessionID] = session
	}
	if l.collapseLocked(session, built, now) {
		l.stats.Collapsed++
		return true
	}
	if !l.makeRoomLocked(in.SessionID, session, size) {
		l.stats.RejectedNoRoom++
		return false
	}

	session.records = append(session.records, built)
	session.bytes += size
	l.total++
	l.bytes += size
	l.stats.Written++
	if !built.RouteGenerationKnown {
		l.stats.WithoutIncarnate++
	}
	return true
}

// normalizeInput fills the instants a caller may leave unset and rejects the two
// inputs a record cannot exist without.
func normalizeInput(in Input, now time.Time) (Input, bool) {
	if in.SessionID == "" || in.Name == "" {
		return Input{}, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if in.ObservedAt.IsZero() {
		in.ObservedAt = now
	}
	return in, true
}

// makeRoomLocked evicts until the incoming record fits both the per-session and
// the global bounds. It reports false only when the ledger is empty and the
// record still does not fit, which is the one case where the write is refused.
func (l *Ledger) makeRoomLocked(sessionID string, session *sessionLog, size int) bool {
	for len(session.records) >= MaxRecordsPerSession {
		l.dropOldestLocked(sessionID, session)
		l.stats.EvictedSession++
	}
	for l.total >= MaxRecordsTotal || l.bytes+size > MaxBytesTotal {
		if !l.dropOldestGlobalLocked() {
			return false
		}
		l.stats.EvictedGlobal++
	}
	return true
}

// nextSeq hands out the record sequence number. It is called before the lock is
// taken, so a sequence may be skipped when a record is rejected; a diagnosis
// never treats the numbers as contiguous.
func (l *Ledger) nextSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	return l.seq
}

// collapseLocked folds an identical, still-active observation into its existing
// record. "Identical" is the whole stored fact: canonical name, qtype, rcode, the
// addresses with their decisions and the cache verdict. The record keeps its
// original observation time and deadline, because it describes the answer that
// created it; only Count and LastSeen move.
func (l *Ledger) collapseLocked(session *sessionLog, incoming Record, now time.Time) bool {
	for i := range session.records {
		existing := &session.records[i]
		if !existing.ExpiresAt.After(now) || !sameObservation(*existing, incoming) {
			continue
		}
		existing.Count++
		existing.LastSeen = incoming.LastSeen
		return true
	}
	return false
}

// sameObservation reports whether two records describe the same stored fact: the
// canonical name, the query type and response code, the addresses with their
// decisions, the cache verdict, the classification and the two generations.
func sameObservation(a, b Record) bool {
	if a.Name != b.Name ||
		a.QType != b.QType ||
		a.RCode != b.RCode ||
		a.CacheVerdict != b.CacheVerdict ||
		a.ClassificationValid != b.ClassificationValid ||
		a.PolicyGeneration != b.PolicyGeneration ||
		a.RouteGeneration != b.RouteGeneration ||
		a.RouteGenerationKnown != b.RouteGenerationKnown {
		return false
	}
	return sameAddresses(a.Addresses, b.Addresses)
}

// pruneLocked removes aged records and keeps the counters in step.
func (l *Ledger) pruneLocked(now time.Time) {
	cutoff := now.Add(-MaxRecordAge)
	for sessionID, session := range l.sessions {
		kept := session.records[:0]
		for _, record := range session.records {
			if record.LastSeen.Before(cutoff) {
				session.bytes -= recordSize(record)
				l.bytes -= recordSize(record)
				l.total--
				l.stats.AgedOut++
				continue
			}
			kept = append(kept, record)
		}
		session.records = kept
		if len(session.records) == 0 {
			delete(l.sessions, sessionID)
		}
	}
}

// dropOldestLocked removes the oldest record of one session.
func (l *Ledger) dropOldestLocked(sessionID string, session *sessionLog) {
	if len(session.records) == 0 {
		return
	}
	index := oldestIndex(session.records)
	record := session.records[index]
	session.records = append(session.records[:index], session.records[index+1:]...)
	size := recordSize(record)
	session.bytes -= size
	l.bytes -= size
	l.total--
	if len(session.records) == 0 {
		delete(l.sessions, sessionID)
	}
}

// dropOldestGlobalLocked removes the globally oldest record. It reports false
// when the ledger is empty, which is the only case where a record cannot be
// stored at all.
func (l *Ledger) dropOldestGlobalLocked() bool {
	var oldestSessionID string
	var oldest *sessionLog
	index := -1
	var oldestSeen time.Time
	for sessionID, session := range l.sessions {
		candidate := oldestIndex(session.records)
		if candidate < 0 {
			continue
		}
		seen := session.records[candidate].LastSeen
		if index < 0 || seen.Before(oldestSeen) {
			oldestSessionID, oldest, index, oldestSeen = sessionID, session, candidate, seen
		}
	}
	if index < 0 {
		return false
	}
	record := oldest.records[index]
	oldest.records = append(oldest.records[:index], oldest.records[index+1:]...)
	size := recordSize(record)
	oldest.bytes -= size
	l.bytes -= size
	l.total--
	if len(oldest.records) == 0 {
		delete(l.sessions, oldestSessionID)
	}
	return true
}

func oldestIndex(records []Record) int {
	if len(records) == 0 {
		return -1
	}
	index := 0
	for i := 1; i < len(records); i++ {
		if records[i].LastSeen.Before(records[index].LastSeen) {
			index = i
		}
	}
	return index
}

// RetireSession drops every record a retired session owns. The forwarder calls
// it from the same write section that releases the session's cache scope, so a
// retired incarnation leaves no browsing history behind.
func (l *Ledger) RetireSession(sessionID string) {
	if l == nil || sessionID == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	session := l.sessions[sessionID]
	if session == nil {
		return
	}
	l.bytes -= session.bytes
	l.total -= len(session.records)
	delete(l.sessions, sessionID)
}

// SessionSnapshot is one session's records plus the store's own accounting.
type SessionSnapshot struct {
	Records   []Record
	Total     int
	Truncated bool
	Stats     Stats
	Limits    Limits
}

// Snapshot returns the session's records newest-first, at most limit of them.
// It writes nothing: no prune, no counter, no cache interaction. An expired
// record is returned as found; the caller decides how to label it.
func (l *Ledger) Snapshot(sessionID string, limit int) SessionSnapshot {
	if l == nil {
		return SessionSnapshot{Records: []Record{}, Limits: Limits{}}
	}
	if limit <= 0 {
		limit = MaxRecordsPerSession
	}
	if limit > MaxRecordsPerSession {
		limit = MaxRecordsPerSession
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	out := SessionSnapshot{
		Records: []Record{},
		Stats:   l.stats,
		Limits:  l.Limits(),
	}
	out.Stats.Sessions = len(l.sessions)
	out.Stats.Records = l.total
	out.Stats.Bytes = l.bytes
	if out.Stats.StartedAt.IsZero() {
		out.Stats.StartedAt = l.started
	}

	session := l.sessions[sessionID]
	if session == nil {
		return out
	}
	out.Total = len(session.records)
	ordered := make([]Record, len(session.records))
	copy(ordered, session.records)
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].ObservedAt.Equal(ordered[j].ObservedAt) {
			return ordered[i].ObservedAt.After(ordered[j].ObservedAt)
		}
		return ordered[i].Seq > ordered[j].Seq
	})
	if len(ordered) > limit {
		out.Records = ordered[:limit]
		out.Truncated = true
		return out
	}
	out.Records = ordered
	return out
}

// buildRecord copies the observer's input into its stored form, applying the
// per-record name and address caps.
func buildRecord(seq uint64, in Input) Record {
	record := Record{
		Seq:                  seq,
		SessionID:            in.SessionID,
		RouteGeneration:      in.RouteGeneration,
		RouteGenerationKnown: in.RouteGenerationKnown,
		Name:                 in.Name,
		QType:                in.QType,
		RCode:                in.RCode,
		ObservedAt:           in.ObservedAt,
		ExpiresAt:            in.ExpiresAt,
		PolicyGeneration:     in.PolicyGeneration,
		ClassificationValid:  in.ClassificationValid,
		ClassificationReason: in.ClassificationReason,
		ResolvedAddressCount: in.ResolvedAddressCount,
		CacheVerdict:         in.CacheVerdict,
	}
	if len(in.Aliases) > MaxNamesPerRecord {
		record.Aliases = append([]string{}, in.Aliases[:MaxNamesPerRecord]...)
		record.Truncated = true
	} else {
		record.Aliases = append([]string{}, in.Aliases...)
	}
	if len(in.Addresses) > MaxAddressesPerRecord {
		record.Addresses = append([]AddressDecision{}, in.Addresses[:MaxAddressesPerRecord]...)
		record.Truncated = true
	} else {
		record.Addresses = append([]AddressDecision{}, in.Addresses...)
	}
	return record
}

// recordSize estimates one record's memory cost for the byte budget.
func recordSize(record Record) int {
	size := recordOverheadBytes + len(record.Name) + len(record.ClassificationReason) + len(record.CacheVerdict)
	for _, alias := range record.Aliases {
		size += len(alias)
	}
	size += 4 * len(record.Addresses)
	return size
}

// sameAddresses reports whether two stored address lists describe the same
// answer, in the same order, with the same decisions.
func sameAddresses(a, b []AddressDecision) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Address != b[i].Address || a[i].Decision != b[i].Decision {
			return false
		}
	}
	return true
}

// CanonicalName lowercases and trims a stored name for comparison. It is not a
// validator: the observer stores names the classifier already normalized, and
// this only guards the collapse key against case differences.
func CanonicalName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
