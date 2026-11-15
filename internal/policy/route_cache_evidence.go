package policy

import (
	"net/netip"
	"time"
)

// This file is the read-only evidence half of the route cache (issue #825).
//
// Lookup answers "what decision does this session hold for this address?" and is
// the only question the packet path asks. A dry run needs more: whether anything
// is held at all, whether it has expired, whether the session was quarantined
// for capacity, and whether the evidence belongs to the current policy
// generation. Inspect answers those without changing a single byte of the
// cache, and it is the only route-cache entry point the explain path uses
// besides the non-creating Get/SessionScope accessors.

// EvidenceState is the lifecycle state of the evidence a session holds for one
// destination.
type EvidenceState string

const (
	// EvidenceFresh means a decision is stored and its deadline is in the future.
	EvidenceFresh EvidenceState = "fresh"
	// EvidenceExpired means a decision is stored but its deadline has passed. The
	// packet path treats it as no evidence (Unknown → PROXY); Inspect reports it
	// separately so an explanation can name staleness instead of absence.
	EvidenceExpired EvidenceState = "expired"
	// EvidenceQuarantined means the session overflowed its cache capacity, so its
	// entries were dropped and the session answers Unknown until the quarantine
	// deadline passes. This is the only eviction the cache performs, and it is
	// what "evicted evidence" means.
	EvidenceQuarantined EvidenceState = "quarantined"
	// EvidenceAbsent means the session holds nothing for this address: it never
	// observed a DNS answer for it.
	EvidenceAbsent EvidenceState = "absent"
	// EvidenceStaleGeneration means the evidence belongs to a previous policy
	// generation and was discarded when the policy was refreshed.
	EvidenceStaleGeneration EvidenceState = "stale_generation"
	// EvidenceRetired means the session scope was released and can record
	// nothing more.
	EvidenceRetired EvidenceState = "retired"
)

// Evidence is a read-only view of one session's route evidence for a
// destination.
type Evidence struct {
	State      EvidenceState
	Decision   Decision
	ExpiresAt  time.Time
	Generation string
}

// Valid reports whether the evidence carries anything actionable.
func (e Evidence) Valid() bool {
	return e.State != ""
}

// Remaining returns how long the stored deadline still has to run at now. A
// non-positive result means the evidence has expired.
func (e Evidence) Remaining(now time.Time) time.Duration {
	if e.ExpiresAt.IsZero() {
		return 0
	}
	return e.ExpiresAt.Sub(now)
}

// Inspect reports the evidence this session holds for ip under
// policyGeneration at now.
//
// It is deliberately the read-only counterpart of Lookup: it loads the current
// view once, reads the map, and computes the state. It never stores a view,
// never prunes expired entries, never extends a deadline, never opens a scope
// and never records anything, so calling it cannot change what the packet path
// later decides.
func (s *SessionCache) Inspect(ip netip.Addr, policyGeneration string, now time.Time) Evidence {
	if s == nil {
		return Evidence{State: EvidenceRetired}
	}
	v := s.view.Load()
	if v == nil {
		return Evidence{State: EvidenceRetired}
	}
	if v.retired {
		return Evidence{State: EvidenceRetired, Generation: v.policyGeneration}
	}
	if v.policyGeneration == "" || v.policyGeneration != policyGeneration {
		return Evidence{State: EvidenceStaleGeneration, Generation: v.policyGeneration}
	}
	if !v.unknownUntil.IsZero() && now.Before(v.unknownUntil) {
		return Evidence{State: EvidenceQuarantined, ExpiresAt: v.unknownUntil, Generation: v.policyGeneration}
	}
	if !ip.IsValid() || !ip.Is4() {
		return Evidence{State: EvidenceAbsent, Generation: v.policyGeneration}
	}
	entry, ok := v.entries[ip.As4()]
	if !ok {
		return Evidence{State: EvidenceAbsent, Generation: v.policyGeneration}
	}
	return Evidence{
		State:      evidenceState(entry, now),
		Decision:   entry.decision,
		ExpiresAt:  entry.expiresAt,
		Generation: v.policyGeneration,
	}
}

// evidenceState classifies a stored entry against now with the same boundary
// Lookup uses: an entry is usable only while now is strictly before its
// deadline.
func evidenceState(e routeEntry, now time.Time) EvidenceState {
	if now.Before(e.expiresAt) {
		return EvidenceFresh
	}
	return EvidenceExpired
}
