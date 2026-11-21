package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// This file owns the durable half of the attribution question: "which rule set
// supplied these rules?".
//
// The equivalence decision in equivalence.go compares the effective content a
// cycle would publish. The digest below records that content in canonical form on
// the durable generation, so a cycle that has only durable state — the first
// refresh after a restart, or the cycle a save's replacement syncer runs after
// adopting the last-known-good policy — can answer whether the prefix set it holds
// is the one that generation was compiled from.
//
// Canonicalization: prefixes are masked and deduplicated, declaration order and
// duplicate lines are not changes, and the sources are sorted by identifier so
// the digest does not depend on configuration order.

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
		_, _ = fmt.Fprintf(h, "S:%s:%s\n", id, ComputeContentHash(canonicalPrefixStrings(rules.CIDRs)))
	}
	return hex.EncodeToString(h.Sum(nil)), true
}
