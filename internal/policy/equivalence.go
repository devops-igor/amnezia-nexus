package policy

import (
	"fmt"
	"time"
)

// This file owns the question a refresh cycle has to answer before it publishes:
// "does this candidate change the effective policy?".
//
// The answer matters because the published generation is stamped on what the
// forwarder records. Every routed flow carries the generation of the snapshot its
// decision was taken against, so a refresh that republishes an identical rule set
// under a new generation changes what those flows report — a new attribution for
// traffic that runs exactly the same policy — and it replaces the live snapshot
// under a policy the operator did not change. Scheduled refreshes run every
// SyncConfig.RefreshInterval and an upstream answering 304 — or an unchanged 200 —
// is the ordinary case, so publishing a new generation for identical rules would
// rewrite that attribution on a timer.
//
// Equivalence is about effective content, never about a rule count or a single
// source digest:
//
//   - the source configuration is compared through the syncer's config hash
//     (source identity, order, URL, format and bare-domain mode), so an added,
//     removed or reconfigured source always publishes;
//   - IPv4 prefixes are compared as a canonical set, so declaration order,
//     duplicate declarations and map iteration order can neither fake a change
//     nor hide one;
//   - each source's own rules are compared too, so a rule that is supplied by a
//     different list is a change even when the merged rule set is identical.
//     Provenance is positional (CompileSnapshot packs one bit per source), so
//     the same rule from another list changes the attribution an explanation
//     reports. The comparison reads the durable per-source digest recorded with
//     the generation (provenance.go), which is what keeps it answerable after a
//     restart or after a save adopted the durable generation.

// candidateIdentity returns the version, generation identifier and creation
// instant the current cycle must publish under.
//
// A content-equivalent refresh reuses the incumbent identity, so the generation
// the forwarder stamps on the flows it records does not move; everything else
// about the cycle (durable commit, atomic publication, status) is unchanged.
func (s *Syncer) candidateIdentity(startTime time.Time, cidrs []string, perSource []SourceParsedRules) (uint64, string, time.Time) {
	retain := s.retainableGeneration()
	if s.equivalentTo(retain, cidrs, perSource) {
		return retain.Version, retain.GenerationID, retain.CreatedAt
	}
	version := s.nextVersion()
	return version, fmt.Sprintf("gen-%d-%d", version, startTime.UnixNano()), startTime
}

// retainableGeneration returns the generation a content-equivalent refresh may
// keep, or nil when this syncer cannot vouch for one.
func (s *Syncer) retainableGeneration() *Generation {
	gen := s.cachedGen
	if gen == nil || gen.ConfigHash != s.computeConfigHash() {
		return nil
	}
	// The durable record and the live snapshot must name the same generation.
	// If they disagree, another path has replaced the live policy and this cycle
	// has to publish rather than assert that the fetched rules are already live.
	live := s.matcher.Current()
	if live == nil || live.Generation() != gen.GenerationID || live.Version() != gen.Version {
		return nil
	}
	return gen
}

// equivalentTo reports whether the candidate rules are the effective content of
// gen. Attribution needs no second comparison any more: the operator's exception
// list is the only rule source, so a change that moves a rule between sources
// cannot happen, and the durable digest covers exactly the prefixes compared
// here.
func (s *Syncer) equivalentTo(gen *Generation, cidrs []string, perSource []SourceParsedRules) bool {
	if gen == nil {
		return false
	}
	return equalStringSet(gen.CIDRs, cidrs)
}

// equalStringSet compares two canonical prefix lists as sets. A list that only
// repeats an entry describes the same rules, so duplicate declarations collapse
// instead of counting as a change.
func equalStringSet(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, item := range a {
		set[item] = struct{}{}
	}
	other := make(map[string]struct{}, len(b))
	for _, item := range b {
		other[item] = struct{}{}
	}
	if len(set) != len(other) {
		return false
	}
	for item := range set {
		if _, ok := other[item]; !ok {
			return false
		}
	}
	return true
}
