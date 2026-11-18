package policy

import (
	"fmt"
	"net/netip"
	"time"
)

// This file owns the question a refresh cycle has to answer before it publishes:
// "does this candidate change the effective policy?".
//
// The answer matters because route evidence is keyed on the policy generation.
// The forwarder's cache adapter (MemoryRouteCache) compares the matcher's
// generation with the one its evidence was recorded under and clears every
// session view when they differ, which turns each client's unresolved flows into
// the fail-closed PROXY path until it resolves again. Scheduled refreshes run
// every SyncConfig.RefreshInterval and an upstream answering 304 — or an
// unchanged 200 — is the ordinary case, so publishing a new generation for
// identical rules would discard usable evidence on a timer.
//
// Equivalence is about effective content, never about a rule count or a single
// source digest:
//
//   - the source configuration is compared through the syncer's config hash
//     (source identity, order, URL, format and bare-domain mode), so an added,
//     removed or reconfigured source always publishes;
//   - merged domain rules are compared entry by entry including their match
//     flags, and IPv4 prefixes as a canonical set, so declaration order,
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
// the forwarder's route cache keys client evidence on does not move; everything
// else about the cycle (durable commit, atomic publication, status) is unchanged.
func (s *Syncer) candidateIdentity(startTime time.Time, domains map[string]uint32, cidrs []string, perSource []SourceParsedRules) (uint64, string, time.Time) {
	retain := s.retainableGeneration()
	if s.equivalentTo(retain, domains, cidrs, perSource) {
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

// equivalentTo reports whether the candidate aggregated rules are the effective
// content of gen, attribution included. Attribution is compared through the
// durable digest when the generation has one, and through the syncer's own
// previous cycle otherwise; see sameSourceAttribution.
func (s *Syncer) equivalentTo(gen *Generation, domains map[string]uint32, cidrs []string, perSource []SourceParsedRules) bool {
	if gen == nil {
		return false
	}
	if !equalFlagMap(gen.Domains, domains) {
		return false
	}
	if !equalStringSet(gen.CIDRs, cidrs) {
		return false
	}
	return s.sameSourceAttribution(gen, perSource)
}

// sameSourceAttribution reports whether every configured source still supplies
// exactly the rules the live generation was compiled from.
//
// The syncer's own record of its last cycle is the most direct answer, and it is
// what this decision always used while a syncer is alive. Once the syncer is
// gone — the first refresh after a restart, or the cycle a save's replacement
// syncer runs after adopting the last-known-good policy — only the durable
// generation is left. The attribution digest recorded with it (provenance.go) is
// what keeps the question answerable then: routing is identical in that case, but
// which list an explanation names is not, and that is a real change.
//
// A generation written before the digest existed has neither, and attribution
// genuinely cannot be compared against it. Answering true there is the honest
// answer: an unchanged merged policy is not a change, and publishing would
// re-derive attribution the durable generation never recorded. The next
// successful cycle records the digest, so that gap is one cycle and never
// recurring: from then on attribution-only moves publish.
func (s *Syncer) sameSourceAttribution(gen *Generation, perSource []SourceParsedRules) bool {
	external := perSource
	if len(external) == len(s.cfg.Sources)+1 && external[len(external)-1].SourceID == "local" {
		external = external[:len(external)-1]
	}
	if len(external) != len(s.cfg.Sources) {
		return true
	}
	if len(s.cachedSources) == len(s.cfg.Sources) {
		return s.sameCachedSourceAttribution(external)
	}
	if candidate, ok := attributionDigest(external); ok && gen.AttributionHash != "" {
		return gen.AttributionHash == candidate
	}
	return true
}

// sameCachedSourceAttribution compares the candidate per-source rules with the
// per-source rules of this syncer's own last cycle.
func (s *Syncer) sameCachedSourceAttribution(perSource []SourceParsedRules) bool {
	for _, item := range perSource {
		previous, ok := s.cachedSources[item.SourceID]
		if !ok {
			return true
		}
		if !equalFlagMap(previous.rules.Domains, item.Rules.Domains) {
			return false
		}
		if !equalPrefixSet(previous.rules.CIDRs, item.Rules.CIDRs) {
			return false
		}
	}
	return true
}

// equalFlagMap compares two rule flag maps. Parsing collapses duplicate
// declarations into one entry per base domain, so equality here is equality of
// the effective rule set however the list was written.
func equalFlagMap[T ~uint32](a, b map[string]T) bool {
	if len(a) != len(b) {
		return false
	}
	for key, aFlags := range a {
		bFlags, ok := b[key]
		if !ok || bFlags != aFlags {
			return false
		}
	}
	return true
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

// equalPrefixSet compares two parsed prefix lists as canonical sets, for the same
// reason as equalStringSet: declaration order and duplicates are not changes.
func equalPrefixSet(a, b []netip.Prefix) bool {
	set := make(map[netip.Prefix]struct{}, len(a))
	for _, prefix := range a {
		set[prefix.Masked()] = struct{}{}
	}
	other := make(map[netip.Prefix]struct{}, len(b))
	for _, prefix := range b {
		other[prefix.Masked()] = struct{}{}
	}
	if len(set) != len(other) {
		return false
	}
	for prefix := range set {
		if _, ok := other[prefix]; !ok {
			return false
		}
	}
	return true
}
