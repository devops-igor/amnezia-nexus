package dnsledger

import (
	"sort"
	"time"
)

// Terminal DNS query events (issue #861, R9).
//
// These are the queries a client actually sent, including the ones that produced
// no usable answer: a refused admission, a failed upstream exchange, NXDOMAIN, a
// truncated reply, a non-A type, a reply that never reached the client. They are a
// separate store from the answer records because they are a different fact: an
// answer record is what the route cache was told, an event is what the query did.
//
// The same discipline applies: bounded per session and globally, aged out on the
// write path only, collapsed when identical, retired with the session, and never
// mutated by a read.

const (
	// MaxEventsPerSession bounds one session's terminal-event history. It matches
	// the answer-record bound so a diagnosis shows a comparable window of each.
	MaxEventsPerSession = 128
	// MaxEventsTotal bounds the whole event store independently of the session
	// count.
	MaxEventsTotal = 4096
	// eventOverheadBytes is the estimated fixed cost of one stored event.
	eventOverheadBytes = 96
	// MaxEventBytesTotal bounds the estimated bytes the event store may hold. It is
	// deliberately reachable: 4096 events with 253-byte names are about 1.5 MB, so a
	// budget above that would be a fence that never closes. At 1 MiB the byte budget
	// is the binding fence for long names, and the count caps bind first for short
	// ones.
	MaxEventBytesTotal = 1 << 20
	// MaxEventNameBytes bounds one stored query name. The DNS wire limit is 253
	// octets; a caller that hands over a longer string is cut here rather than
	// trusted.
	MaxEventNameBytes = 253
)

// InputEvent is what the DNS server hands to the store: one terminal query.
type InputEvent struct {
	SessionID            string
	RouteGeneration      uint64
	RouteGenerationKnown bool
	Transport            string
	Name                 string
	QType                uint16
	RCode                int
	Kind                 string
	UpstreamError        string
	Truncated            bool
	Delivered            bool
	ReceivedAt           time.Time
	AnsweredAt           time.Time
	PolicyGeneration     string
}

// Event is one stored terminal query.
type Event struct {
	Seq                  uint64
	SessionID            string
	RouteGeneration      uint64
	RouteGenerationKnown bool
	Transport            string
	Name                 string
	QType                uint16
	RCode                int
	Kind                 string
	UpstreamError        string
	Truncated            bool
	Delivered            bool
	ReceivedAt           time.Time
	AnsweredAt           time.Time
	PolicyGeneration     string
	// Count is how many identical terminal events collapsed into this one.
	Count int
	// FirstSeen and LastSeen bound the collapsed repeats.
	FirstSeen time.Time
	LastSeen  time.Time
}

// EventStats is the event store's accounting.
type EventStats struct {
	StartedAt      time.Time
	Written        int64
	Collapsed      int64
	EvictedSession int64
	EvictedGlobal  int64
	AgedOut        int64
	RejectedNoRoom int64
	Events         int
	Bytes          int
}

// EventLimits reports the bounds in force for events.
type EventLimits struct {
	EventsPerSession int
	EventsTotal      int
	MaxAgeSeconds    int64
	BytesTotal       int
	MaxNameBytes     int
}

// EventLimits returns the event bounds this ledger enforces.
func (l *Ledger) EventLimits() EventLimits {
	return EventLimits{
		EventsPerSession: MaxEventsPerSession,
		EventsTotal:      MaxEventsTotal,
		MaxAgeSeconds:    int64(MaxRecordAge / time.Second),
		BytesTotal:       MaxEventBytesTotal,
		MaxNameBytes:     MaxEventNameBytes,
	}
}

// RecordEvent stores one terminal query. It returns false only for an input that
// cannot be stored at all (no session or no name), which the caller reports as a
// gap rather than inventing a record.
func (l *Ledger) RecordEvent(in InputEvent, now time.Time) bool {
	if l == nil || in.SessionID == "" || in.Name == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	if in.ReceivedAt.IsZero() {
		in.ReceivedAt = now
	}
	if in.AnsweredAt.IsZero() {
		in.AnsweredAt = in.ReceivedAt
	}
	if len(in.Name) > MaxEventNameBytes {
		in.Name = in.Name[:MaxEventNameBytes]
	}

	built := Event{
		Seq:                  l.nextEventSeq(),
		SessionID:            in.SessionID,
		RouteGeneration:      in.RouteGeneration,
		RouteGenerationKnown: in.RouteGenerationKnown,
		Transport:            in.Transport,
		Name:                 in.Name,
		QType:                in.QType,
		RCode:                in.RCode,
		Kind:                 in.Kind,
		UpstreamError:        in.UpstreamError,
		Truncated:            in.Truncated,
		Delivered:            in.Delivered,
		ReceivedAt:           in.ReceivedAt,
		AnsweredAt:           in.AnsweredAt,
		PolicyGeneration:     in.PolicyGeneration,
		Count:                1,
		FirstSeen:            in.ReceivedAt,
		LastSeen:             in.ReceivedAt,
	}
	size := eventSize(built)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneEventsLocked(now)

	session := l.sessions[in.SessionID]
	if session == nil {
		session = &sessionLog{}
		l.sessions[in.SessionID] = session
	}
	if l.collapseEventLocked(session, built, now) {
		l.stats.Events.Collapsed++
		return true
	}
	for len(session.events) >= MaxEventsPerSession {
		l.dropOldestEventLocked(in.SessionID, session)
		l.stats.Events.EvictedSession++
	}
	for l.eventTotal >= MaxEventsTotal || l.eventBytes+size > MaxEventBytesTotal {
		if !l.dropOldestEventGlobalLocked() {
			// Nothing left to evict and the record still does not fit.
			l.stats.Events.RejectedNoRoom++
			return false
		}
		l.stats.Events.EvictedGlobal++
	}
	// Global eviction may have deleted this session's bucket when its last row was the
	// victim, so the append below must go to the bucket the map can reach.
	session = l.attachSessionLocked(in.SessionID, session)

	session.events = append(session.events, built)
	session.eventBytes += size
	l.eventTotal++
	l.eventBytes += size
	l.stats.Events.Written++
	return true
}

// nextEventSeq hands out an event sequence number.
func (l *Ledger) nextEventSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.eventSeq++
	return l.eventSeq
}

// collapseEventLocked folds an identical terminal event into its existing record.
// "Identical" is the whole terminal fact except the instants: the same transport,
// name, type, response code, kind, delivery and truncation outcome. The record
// keeps its first instants and only Count/LastSeen move, so a chatty client cannot
// turn the window over.
func (l *Ledger) collapseEventLocked(session *sessionLog, incoming Event, now time.Time) bool {
	for i := range session.events {
		existing := &session.events[i]
		if existing.LastSeen.Before(now.Add(-MaxRecordAge)) {
			continue
		}
		if existing.Transport != incoming.Transport ||
			existing.Name != incoming.Name ||
			existing.QType != incoming.QType ||
			existing.RCode != incoming.RCode ||
			existing.Kind != incoming.Kind ||
			existing.UpstreamError != incoming.UpstreamError ||
			existing.Truncated != incoming.Truncated ||
			existing.Delivered != incoming.Delivered ||
			existing.PolicyGeneration != incoming.PolicyGeneration ||
			existing.RouteGeneration != incoming.RouteGeneration {
			continue
		}
		existing.Count++
		existing.LastSeen = incoming.LastSeen
		return true
	}
	return false
}

// pruneEventsLocked ages out terminal events, on the write path only.
func (l *Ledger) pruneEventsLocked(now time.Time) {
	cutoff := now.Add(-MaxRecordAge)
	for sessionID, session := range l.sessions {
		kept := session.events[:0]
		for _, event := range session.events {
			if event.LastSeen.Before(cutoff) {
				size := eventSize(event)
				session.eventBytes -= size
				l.eventBytes -= size
				l.eventTotal--
				l.stats.Events.AgedOut++
				continue
			}
			kept = append(kept, event)
		}
		session.events = kept
		if len(session.events) == 0 && len(session.records) == 0 {
			delete(l.sessions, sessionID)
		}
	}
}

func (l *Ledger) dropOldestEventLocked(sessionID string, session *sessionLog) {
	if len(session.events) == 0 {
		return
	}
	index := oldestEventIndex(session.events)
	event := session.events[index]
	session.events = append(session.events[:index], session.events[index+1:]...)
	size := eventSize(event)
	session.eventBytes -= size
	l.eventBytes -= size
	l.eventTotal--
	if len(session.events) == 0 && len(session.records) == 0 {
		delete(l.sessions, sessionID)
	}
}

func (l *Ledger) dropOldestEventGlobalLocked() bool {
	var oldestSessionID string
	var oldest *sessionLog
	index := -1
	var oldestSeen time.Time
	for sessionID, session := range l.sessions {
		candidate := oldestEventIndex(session.events)
		if candidate < 0 {
			continue
		}
		seen := session.events[candidate].LastSeen
		if index < 0 || seen.Before(oldestSeen) {
			oldestSessionID, oldest, index, oldestSeen = sessionID, session, candidate, seen
		}
	}
	if index < 0 {
		return false
	}
	event := oldest.events[index]
	oldest.events = append(oldest.events[:index], oldest.events[index+1:]...)
	size := eventSize(event)
	oldest.eventBytes -= size
	l.eventBytes -= size
	l.eventTotal--
	if len(oldest.events) == 0 && len(oldest.records) == 0 {
		delete(l.sessions, oldestSessionID)
	}
	return true
}

func oldestEventIndex(events []Event) int {
	if len(events) == 0 {
		return -1
	}
	index := 0
	for i := 1; i < len(events); i++ {
		if events[i].LastSeen.Before(events[index].LastSeen) {
			index = i
		}
	}
	return index
}

// EventSnapshot is one session's terminal events plus the store's accounting.
type EventSnapshot struct {
	Events    []Event
	Total     int
	Truncated bool
	Stats     EventStats
	Limits    EventLimits
}

// SnapshotEvents returns the session's terminal events newest-first, at most limit
// of them. It writes nothing: no prune, no counter, no cache interaction.
func (l *Ledger) SnapshotEvents(sessionID string, limit int) EventSnapshot {
	if l == nil {
		return EventSnapshot{Events: []Event{}, Limits: EventLimits{}}
	}
	if limit <= 0 {
		limit = MaxEventsPerSession
	}
	if limit > MaxEventsPerSession {
		limit = MaxEventsPerSession
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	out := EventSnapshot{
		Events: []Event{},
		Stats:  l.stats.Events,
		Limits: l.EventLimits(),
	}
	if out.Stats.StartedAt.IsZero() {
		out.Stats.StartedAt = l.started
	}
	out.Stats.Events = l.eventTotal
	out.Stats.Bytes = l.eventBytes

	session := l.sessions[sessionID]
	if session == nil {
		return out
	}
	out.Total = len(session.events)
	ordered := make([]Event, len(session.events))
	copy(ordered, session.events)
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].ReceivedAt.Equal(ordered[j].ReceivedAt) {
			return ordered[i].ReceivedAt.After(ordered[j].ReceivedAt)
		}
		return ordered[i].Seq > ordered[j].Seq
	})
	if len(ordered) > limit {
		out.Events = ordered[:limit]
		out.Truncated = true
		return out
	}
	out.Events = ordered
	return out
}

// eventSize estimates one event's memory cost.
func eventSize(event Event) int {
	return eventOverheadBytes + len(event.Name) + len(event.Kind) + len(event.UpstreamError) + len(event.Transport)
}
