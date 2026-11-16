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
	// ObservedAt is the instant the stored observation was made, as recorded when
	// it was written. It is zero when the entry carries no recorded instant, and
	// for every state that has no stored entry.
	ObservedAt time.Time
}

// AgeReason names why an evidence age cannot be reported. The empty value means
// an age is available. The tokens are part of the explain response.
type AgeReason string

const (
	// AgeReported means Age returned a measured value.
	AgeReported AgeReason = ""
	// AgeNoEvidence means the session holds nothing for the address.
	AgeNoEvidence AgeReason = "no_evidence"
	// AgeNotFresh means the stored evidence is no longer usable (expired,
	// quarantined, from a previous generation or retired), so an age would
	// describe evidence the data path ignores.
	AgeNotFresh AgeReason = "evidence_not_fresh"
	// AgeInstantNotRecorded means fresh evidence is stored but was written
	// without an observation instant. The age is not derived from the deadline.
	AgeInstantNotRecorded AgeReason = "observation_instant_not_recorded"
)

// Age returns how long ago the fresh evidence was observed, measured from the
// recorded observation instant to now. It is never computed from the deadline or
// from a TTL: a stored deadline says how long evidence may be used, and the
// cache does not know the TTL it was granted. When no age can be stated the
// reason says why and the duration is zero.
//
// A recorded instant later than now (a response stamped after the evaluation
// instant was sampled) is reported as zero rather than a negative age.
func (e Evidence) Age(now time.Time) (time.Duration, AgeReason) {
	switch {
	case e.State == EvidenceAbsent:
		return 0, AgeNoEvidence
	case e.State != EvidenceFresh:
		return 0, AgeNotFresh
	case e.ObservedAt.IsZero():
		return 0, AgeInstantNotRecorded
	}
	return max(now.Sub(e.ObservedAt), 0), AgeReported
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
	if state, decided := viewEvidenceState(v, policyGeneration, now); decided {
		return state
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
		ObservedAt: entry.observedAt,
	}
}

// viewEvidenceState reports a state that is decided by the view alone: retired or
// replaced authority, a stale policy generation, or an active capacity
// quarantine. The second result is false when the view is usable for a per-address
// lookup, which is what keeps Inspect's own body about one entry.
func viewEvidenceState(v *routeView, policyGeneration string, now time.Time) (Evidence, bool) {
	if v == nil {
		return Evidence{State: EvidenceRetired}, true
	}
	if v.retired {
		return Evidence{State: EvidenceRetired, Generation: v.policyGeneration}, true
	}
	if v.policyGeneration == "" || v.policyGeneration != policyGeneration {
		return Evidence{State: EvidenceStaleGeneration, Generation: v.policyGeneration}, true
	}
	if !v.unknownUntil.IsZero() && now.Before(v.unknownUntil) {
		return Evidence{State: EvidenceQuarantined, ExpiresAt: v.unknownUntil, Generation: v.policyGeneration}, true
	}
	return Evidence{}, false
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
