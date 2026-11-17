package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
)

// This file owns the durable half of the attribution question: "which list
// supplied these rules?".
//
// The equivalence decision in equivalence.go compares everything a refresh can
// see about effective content. Merged domain flags and prefixes answer "does the
// policy still route the same way"; they cannot answer "does an explanation still
// name the same list", because a rule that moves from one source to another
// leaves the merged rule set identical while the attribution a dry run reports
// changes.
//
// While a syncer is running it holds the per-source rules of its own last cycle
// (cachedSources), which is enough for that lifetime. A syncer that adopted the
// durable generation — after a restart, or after an operator save reused the
// last-known-good policy — has only merged rules and source metadata, so the
// attribution of the live generation would be unknown and every attribution-only
// change would look like a no-op. The digest below is what makes that question
// answerable from durable state without storing the rule lists twice: one
// SHA-256 over the canonical per-source rule sets, which is all the identity
// decision needs.
//
// Canonicalization matches the merged comparison exactly: domains are keyed by
// base entry with their match flags, prefixes are masked and deduplicated,
// declaration order and duplicate lines are not changes, and the sources are
// sorted by identifier so the digest does not depend on configuration order
// (which the config hash already covers).

// attributionDigest returns a canonical digest of the per-source rules a cycle
// would compile, and whether the list could be attributed at all.
//
// The bool is false for a list that cannot be represented — no sources, an empty
// or repeated source identifier — because recording a digest for such a list
// would later compare equal only by accident. The caller treats false as "not
// comparable", never as "equal".
func attributionDigest(sources []SourceParsedRules) (string, bool) {
	if len(sources) == 0 {
		return "", false
	}

	rulesBySource := make(map[string]ParsedRules, len(sources))
	ids := make([]string, 0, len(sources))
	for _, item := range sources {
		if item.SourceID == "" {
			return "", false
		}
		if _, exists := rulesBySource[item.SourceID]; exists {
			return "", false
		}
		rulesBySource[item.SourceID] = item.Rules
		ids = append(ids, item.SourceID)
	}
	sort.Strings(ids)

	h := sha256.New()
	for _, id := range ids {
		rules := rulesBySource[id]
		domains := make(map[string]uint8, len(rules.Domains))
		for base, flags := range rules.Domains {
			domains[base] = uint8(flags)
		}
		_, _ = fmt.Fprintf(h, "S:%s:%s\n", id, ComputeContentHash(domains, canonicalPrefixStrings(rules.CIDRs)))
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// canonicalPrefixStrings returns the distinct masked prefixes of one source in
// string form. ComputeContentHash sorts what it is given, so the order of the
// input list cannot influence the digest, and a source that lists the same
// prefix twice supplies the same rules once.
func canonicalPrefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		canon := prefix.Masked()
		if _, exists := seen[canon]; exists {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, canon.String())
	}
	return out
}
