package policy

import (
	"net/netip"
	"slices"
	"time"
)

// This file is the listing counterpart of Inspect (issue #861).
//
// Inspect answers "what does this session hold for this address?". A per-client
// diagnosis needs the session's whole retained set at once: every address it
// observed, the decision stored for it, the recorded observation instant, the
// deadline and whether it is still usable. Entries answers that from one atomic
// view load and writes nothing: it does not prune, extend, quarantine, store or
// record, never opens a scope and never touches a deadline, so reading it
// cannot change what the packet path later decides.
//
// What it returns is retained ROUTE EVIDENCE, not DNS history. The cache is
// keyed by address and merged PROXY-wins, so an entry names no query, no
// CNAME chain and no original TTL; a listing cannot be presented as the client's
// DNS questions. Callers state that limitation.

const (
	// SessionEntriesDefaultLimit is the page size used when a caller does not
	// ask for a smaller one.
	SessionEntriesDefaultLimit = 256
	// SessionEntriesMaxLimit bounds one page. The cache holds at most
	// MaxEntriesPerSession entries per session, so this is a transport bound,
	// not a second capacity policy, and it never exceeds that per-session cap.
	SessionEntriesMaxLimit = 1024
)

// SessionEntry is one retained address decision.
type SessionEntry struct {
	Address    netip.Addr
	Decision   Decision
	ObservedAt time.Time
	ExpiresAt  time.Time
	// State is the per-entry lifecycle state: fresh or expired. It is never
	// quarantined, retired, stale_generation or absent, because those describe
	// the session's view and no entry is reported in such a view.
	State EvidenceState
}

// SessionEntryList is a bounded, ordered page of one session's retained
// evidence plus the state of the session's view.
type SessionEntryList struct {
	// State describes the whole view: fresh means the entries below are the
	// session's retained set as of the caller's instant; absent means the
	// session holds nothing at all (no scope, or an empty one); quarantined,
	// retired and stale_generation mean the view cannot answer for any address
	// and no entries are returned.
	State EvidenceState
	// Generation is the policy generation the view was built for, empty when
	// there is no view.
	Generation string
	// QuarantinedUntil is the instant the capacity quarantine ends. It is set
	// only for the quarantined state and is never derived from an entry.
	QuarantinedUntil time.Time
	// Entries are the retained decisions, newest observation first. The slice
	// is always non-nil so a caller can distinguish "no entries" from an
	// unfilled answer.
	Entries []SessionEntry
	// Total is how many entries the session retains, before truncation.
	Total int
	// Truncated reports that the page cut the retained set.
	Truncated bool
}

// Entries lists the evidence this session holds under policyGeneration at now,
// newest observation first, at most limit entries.
//
// A nil scope means the session holds nothing: the cache keeps no retirement
// record, so an absent listing cannot distinguish a session that never
// observed an answer from one whose scope was already released. It never
// claims the second, because only the route lifecycle knows it.
func (s *SessionCache) Entries(policyGeneration string, now time.Time, limit int) SessionEntryList {
	limit = sessionEntriesPageSize(limit)
	if s == nil {
		return SessionEntryList{State: EvidenceAbsent, Entries: []SessionEntry{}}
	}

	v := s.view.Load()
	if state, decided := viewEvidenceState(v, policyGeneration, now); decided {
		out := SessionEntryList{
			State:      state.State,
			Generation: state.Generation,
			Entries:    []SessionEntry{},
		}
		if state.State == EvidenceQuarantined {
			// The quarantine deadline is the view's own field; the per-address
			// helper reuses ExpiresAt for it, and copying it here keeps the
			// caller from reading an entry deadline that was never stored.
			out.QuarantinedUntil = v.unknownUntil
		}
		return out
	}

	out := SessionEntryList{
		State:      EvidenceAbsent,
		Generation: v.policyGeneration,
		Entries:    make([]SessionEntry, 0, min(len(v.entries), limit)),
		Total:      len(v.entries),
	}
	if len(v.entries) == 0 {
		return out
	}
	out.State = EvidenceFresh

	all := make([]SessionEntry, 0, len(v.entries))
	for addr, entry := range v.entries {
		all = append(all, SessionEntry{
			Address:    netip.AddrFrom4(addr),
			Decision:   entry.decision,
			ObservedAt: entry.observedAt,
			ExpiresAt:  entry.expiresAt,
			State:      evidenceState(entry, now),
		})
	}
	// Newest observation first, then address, so a page is a stable prefix of
	// the retained set rather than an arbitrary map slice.
	slices.SortFunc(all, compareSessionEntry)

	if len(all) > limit {
		out.Entries = append(out.Entries, all[:limit]...)
		out.Truncated = true
		return out
	}
	out.Entries = append(out.Entries, all...)
	return out
}

// sessionEntriesPageSize clamps a requested page to the documented bounds.
func sessionEntriesPageSize(limit int) int {
	if limit <= 0 {
		return SessionEntriesDefaultLimit
	}
	if limit > SessionEntriesMaxLimit {
		return SessionEntriesMaxLimit
	}
	return limit
}

// compareSessionEntry orders retained decisions: newest observation first, then
// address. An entry without a recorded instant sorts last, because nothing says
// when it was seen and it cannot claim to be the newest.
func compareSessionEntry(a, b SessionEntry) int {
	if !a.ObservedAt.Equal(b.ObservedAt) {
		if a.ObservedAt.IsZero() != b.ObservedAt.IsZero() {
			if b.ObservedAt.IsZero() {
				return -1
			}
			return 1
		}
		return b.ObservedAt.Compare(a.ObservedAt)
	}
	return a.Address.Compare(b.Address)
}

// Count reports how many entries the session currently retains, without
// copying them. It is the cheap form used by a client picker: one view load and
// one map length.
func (s *SessionCache) Count() int {
	if s == nil {
		return 0
	}
	v := s.view.Load()
	if v == nil || v.retired {
		return 0
	}
	return len(v.entries)
}
