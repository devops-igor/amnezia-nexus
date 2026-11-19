package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// This file owns the operator override for the committed Russian inventory
// (issue #919).
//
// The override exists so an operator can correct or extend the shipped
// allocation set without waiting for a release, which is what the epic agreed:
// the committed artifact is the baseline and an operator-supplied set takes
// precedence over it. It deliberately accepts the formats the panel already
// speaks — FormatIPv4 and FormatMixed — so an operator can paste the same list
// they would put in a custom source, rather than learning a second syntax.
//
// Only prefixes participate in the inventory question. A mixed body may also
// carry domain rules; they are proxy policy rules and say nothing about whether
// an ADDRESS is inside the Russian allocation, so they are reported as ignored
// instead of being silently interpreted. A body with no prefixes at all is an
// error, because accepting it would turn an operator's intended override into a
// no-op that looks applied.
//
// The override is not a license to widen routing blindly: it answers set
// membership only. Consumers keep their existing precedence rules (explicit
// proxy rules, prohibited destinations) above it.

// InventoryOverride is an operator-supplied address set that takes precedence
// over the committed inventory. A parsed override is immutable.
type InventoryOverride struct {
	prefixes []netip.Prefix
	// domainRules counts mixed-format domain lines that were accepted by the
	// parser and are not part of the address set, so reporting can say they
	// were seen rather than pretend the body held only prefixes.
	domainRules int
	digest      string
}

// ParseInventoryOverride parses an operator override body written in the
// existing IPv4 or mixed source format.
//
// Every non-comment line must parse; unlike a built-in preset this is not
// tolerant of a partial body, because an override that half-applied would route
// some of the operator's addresses and not others. A line that is neither a
// prefix nor a dotted name is refused rather than read as an inert domain rule,
// so a mistyped prefix is reported instead of dropped. A body with no IPv4
// prefix is refused: there would be nothing to override.
func ParseInventoryOverride(body []byte) (*InventoryOverride, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("inventory override is empty")
	}
	if looksLikeMarkupDocument(body) {
		return nil, fmt.Errorf("%w: inventory override looks like a markup or data document, not a prefix list", ErrInventoryNotPrefixList)
	}

	src := Source{
		ID:             "inventory-override",
		Format:         FormatMixed,
		BareDomainMode: DomainModeInclusiveSuffix,
		IsPreset:       false,
	}
	if err := validateOverrideLines(body); err != nil {
		return nil, err
	}
	parsed, _, err := Parse(context.Background(), bytes.NewReader(body), src, DefaultParseLimits())
	if err != nil {
		return nil, fmt.Errorf("inventory override: %w", err)
	}
	prefixes := distinctMaskedPrefixes(parsed.CIDRs)
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("%w: inventory override carries %d domain rules and no IPv4 prefix, so it would override nothing",
			ErrInventoryNotPrefixList, len(parsed.Domains))
	}
	return &InventoryOverride{
		prefixes:    prefixes,
		domainRules: len(parsed.Domains),
		digest:      digestHex(body),
	}, nil
}

// validateOverrideLines rejects an override line that is neither an IPv4 prefix
// nor a name. The mixed parser would otherwise accept a bare token such as
// "not-a-prefix" as a domain rule and silently drop it from the address set,
// which is exactly the typo an operator needs to hear about. Explicit suffix and
// wildcard forms have no dot in their base either, so they are exempt.
//
// A dotted-numeric token gets its own rejection: "203.0.113.999" is a mistyped
// address, but a dotted token is a syntactically valid domain, so without this
// rule the parser would file it as an inert domain rule and the operator would
// see the prefix silently missing from their override. Only the shape is judged
// here — digits and dots, with an optional /digits mask — never general domain
// syntax.
func validateOverrideLines(body []byte) error {
	for i, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if isIgnoredLine(line) {
			continue
		}
		if _, err := ParseIPv4Rule(line); err == nil {
			continue
		}
		if isDottedNumeric(line) {
			return fmt.Errorf("inventory override line %d: %q looks like an IPv4 address or prefix but is not a valid one", i+1, line)
		}
		if strings.HasPrefix(line, "*.") || strings.HasPrefix(line, ".") || strings.Contains(line, ".") {
			continue
		}
		return fmt.Errorf("inventory override line %d: %q is neither an IPv4 prefix nor a domain name", i+1, line)
	}
	return nil
}

// isDottedNumeric reports whether a token has the shape of an IPv4 address or
// prefix: digits and dots only, optionally followed by / and digits. A token with
// any other character — a letter, a wildcard, a leading dot — is not this shape
// and is left to the domain parser.
func isDottedNumeric(line string) bool {
	addr := line
	if slash := strings.IndexByte(addr, '/'); slash >= 0 {
		mask := addr[slash+1:]
		addr = addr[:slash]
		if mask == "" || !allDigits(mask) {
			return false
		}
	}
	if addr == "" || !allDigitsAndDots(addr) {
		return false
	}
	return strings.Contains(addr, ".")
}

// allDigits reports whether s is non-empty and holds only ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// allDigitsAndDots reports whether s holds only ASCII digits and dots.
func allDigitsAndDots(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

// PrefixCount returns the number of distinct prefixes in the override.
func (o *InventoryOverride) PrefixCount() int {
	if o == nil {
		return 0
	}
	return len(o.prefixes)
}

// DomainRuleCount returns how many domain rules a mixed-format override carried.
// They are not part of the address set; the count is reported so that "accepted
// but not applied here" is visible instead of assumed.
func (o *InventoryOverride) DomainRuleCount() int {
	if o == nil {
		return 0
	}
	return o.domainRules
}

// Digest returns the SHA-256 of the override body as submitted, so a
// deployment's override is identifiable by content.
func (o *InventoryOverride) Digest() string {
	if o == nil {
		return ""
	}
	return o.digest
}

// WithOverride returns a copy of the resolved inventory in which override takes
// precedence for every address it contains. A nil override returns the receiver
// unchanged.
//
// The receiver is not modified: the cached shipped set stays shareable, and a
// caller holding the previous resolution keeps seeing it.
func (inv *Inventory) WithOverride(override *InventoryOverride) *Inventory {
	if inv == nil {
		return nil
	}
	out := *inv
	if override != nil && len(override.prefixes) > 0 {
		out.override = newIPv4Index(override.prefixes)
		out.overrideCount = len(override.prefixes)
		out.overrideHash = override.digest
	}
	return &out
}
