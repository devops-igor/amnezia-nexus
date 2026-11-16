package policy

import (
	"net/netip"
	"strings"
)

// This file is the read-only explanation half of the matcher (issue #825).
//
// MatchDomain and MatchIPv4 answer "would this match?" on the packet and DNS
// observation paths, where allocation matters. These accessors answer the same
// question for an operator and add the two things a verdict cannot carry on its
// own: which rule matched, and which list supplied it. They read the immutable
// snapshot only — no lock, no mutation, no publication — and they never change
// what the matchers decide. snapshot_explain_test.go pins that equivalence on
// every name and address it exercises.

// DomainRuleShape describes how a matched domain rule applies to a name.
type DomainRuleShape string

const (
	// DomainRuleApex means the rule matches the bare name only ("example.com").
	DomainRuleApex DomainRuleShape = "apex"
	// DomainRuleApexAndSubdomains means the rule matches the name and every
	// subdomain of it (a bare entry in an inclusive-suffix list, or ".example.com").
	DomainRuleApexAndSubdomains DomainRuleShape = "apex_and_subdomains"
	// DomainRuleSubdomains means the rule matches subdomains but not the apex
	// itself ("*.example.com").
	DomainRuleSubdomains DomainRuleShape = "subdomains"
)

// DomainRuleMatch is a matched domain rule.
//
// Base is the canonical rule entry ("example.com") rather than the queried
// name, so an operator can find the line in the list that supplied it.
//
// Contributors names the lists that contributed to that BASE ENTRY. A base
// entry's flags are merged across sources, so a contributor may supply only a
// shape this name does not use: with "*.shared.example" from one list and a
// bare "shared.example" from another, explaining the apex reports both lists
// even though only the second can match an apex. It is a base-entry
// contributor list, not a proven supplier of the matched shape; the snapshot
// keeps one provenance mask per base entry and cannot distinguish shapes
// without a second per-rule index. Contributors is empty when the snapshot was
// compiled from a durable last-known-good generation, which stores merged rules
// without per-rule attribution, or when the snapshot was compiled from more
// sources than the provenance encoding holds.
type DomainRuleMatch struct {
	Base         string          `json:"base"`
	Shape        DomainRuleShape `json:"shape"`
	Contributors []string        `json:"contributors"`
}

// CIDRRuleMatch is the most specific prefix of the snapshot that contains an
// address, with the sources that supplied that exact prefix. Unlike a merged
// domain base entry, a prefix's provenance is exact: each source either
// contains that prefix or does not.
type CIDRRuleMatch struct {
	Prefix  netip.Prefix `json:"prefix"`
	Sources []string     `json:"sources"`
}

// ExplainCanonicalDomain reports which rule matches a canonical domain (ASCII
// lowercase, no trailing dot), if any.
//
// The walk is the same dot-boundary walk MatchCanonicalDomain performs, so the
// most specific rule wins for both. Splitting it into the shape and the sources
// is the only difference: MatchCanonicalDomain still runs on the observation
// path and still allocates nothing.
func (s *Snapshot) ExplainCanonicalDomain(name string) (DomainRuleMatch, bool) {
	if s == nil || len(s.domains) == 0 || name == "" {
		return DomainRuleMatch{}, false
	}

	orig := true
	q := name
	for {
		if f, ok := s.domains[q]; ok {
			if shape, matched := domainRuleShape(f, orig); matched {
				return DomainRuleMatch{Base: q, Shape: shape, Contributors: s.sourcesForMask(f)}, true
			}
		}
		i := strings.IndexByte(q, '.')
		if i < 0 {
			return DomainRuleMatch{}, false
		}
		q = q[i+1:]
		orig = false
	}
}

// domainRuleShape mirrors the match condition in MatchCanonicalDomain exactly:
// an inclusive-suffix entry matches at any depth, an exact entry only at the
// queried name, and a descendants entry only below it.
func domainRuleShape(f domainFlags, orig bool) (DomainRuleShape, bool) {
	switch {
	case f&domainInclusiveSuffix != 0:
		return DomainRuleApexAndSubdomains, true
	case orig && f&domainExact != 0:
		return DomainRuleApex, true
	case !orig && f&domainDescendants != 0:
		return DomainRuleSubdomains, true
	default:
		return "", false
	}
}

// ExplainDomain normalizes name and reports the matching rule. A name that
// cannot be normalized matches nothing, exactly like MatchDomain.
func (s *Snapshot) ExplainDomain(name string) (DomainRuleMatch, bool) {
	canon, err := NormalizeDomain(name)
	if err != nil {
		return DomainRuleMatch{}, false
	}
	return s.ExplainCanonicalDomain(canon)
}

// ExplainIPv4 reports the most specific prefix of the snapshot that contains
// addr, if any. "Most specific" is the prefix with the longest mask, so an
// operator sees the narrow rule that decided rather than a broader one that
// happens to contain it as well. The scan is linear in the number of distinct
// prefixes; it runs on an admin dry run, never on the packet path.
func (s *Snapshot) ExplainIPv4(addr netip.Addr) (CIDRRuleMatch, bool) {
	if s == nil {
		return CIDRRuleMatch{}, false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.Is4() {
		return CIDRRuleMatch{}, false
	}
	best := -1
	for i := range s.cidrRules {
		if !s.cidrRules[i].prefix.Contains(addr) {
			continue
		}
		if best < 0 || s.cidrRules[i].prefix.Bits() > s.cidrRules[best].prefix.Bits() {
			best = i
		}
	}
	if best < 0 {
		return CIDRRuleMatch{}, false
	}
	return CIDRRuleMatch{
		Prefix:  s.cidrRules[best].prefix,
		Sources: s.sourcesForMask(s.cidrRules[best].sources),
	}, true
}

// sourcesForMask resolves the packed provenance bits of one rule to the source
// identifiers that supplied it, in the snapshot's source order.
func (s *Snapshot) sourcesForMask(f domainFlags) []string {
	mask := f & domainSourceMask
	if mask == 0 || len(s.sourceIDs) == 0 {
		return nil
	}
	out := make([]string, 0, maxSnapshotSources)
	for i := 0; i < len(s.sourceIDs) && i < maxSnapshotSources; i++ {
		bit := domainFlags(1<<uint(i)) << domainSourceShift
		if mask&bit != 0 {
			out = append(out, s.sourceIDs[i])
		}
	}
	return out
}
