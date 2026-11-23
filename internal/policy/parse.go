package policy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

var (
	// ErrNoValidRules indicates that the parsed list yielded zero valid rules.
	ErrNoValidRules = errors.New("list contained no valid rules")
	// ErrEmptyFeed is an alias for ErrNoValidRules.
	ErrEmptyFeed = ErrNoValidRules
)

// ParseLimits bounds list processing to prevent memory or CPU exhaustion.
type ParseLimits struct {
	MaxLines        int
	MaxLineBytes    int
	MaxRules        int
	RejectionBudget float64 // Fraction of rejected rows allowed (e.g. 0.005)
	MaxRejectedRows int     // Absolute cap on rejected rows (e.g. 10000)
	// Strict refuses the first row the parser cannot accept instead of applying
	// the rejection budget. Operator-submitted bodies are strict: an override that
	// half-applied would route some of the operator's addresses and not others,
	// and that must be reported at the line rather than silently tolerated.
	Strict bool
	// AllowNonPrefixRows counts a row that is not an IPv4 prefix as ignored
	// instead of rejected. The inventory override accepts a mixed body and
	// reports its domain lines as "accepted but not applied here", which is a
	// documented contract rather than tolerance of a malformed prefix.
	AllowNonPrefixRows bool
}

// DefaultParseLimits returns recommended defaults for production operation.
func DefaultParseLimits() ParseLimits {
	return ParseLimits{
		MaxLines:        3_000_000,
		MaxLineBytes:    4096,
		MaxRules:        3_000_000,
		RejectionBudget: 0.005,
		MaxRejectedRows: 10_000,
	}
}

// ParseReport records accounting stats from parsing a list.
type ParseReport struct {
	TotalLines int `json:"total_lines"`
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
}

// ParsedRules holds the extracted IPv4 prefixes.
//
// It is deliberately an address-only structure. A domain-name rule never
// determined a packet's route, and the routing authority is the destination
// address classifier, so carrying names here would describe a policy input that
// cannot be applied.
type ParsedRules struct {
	CIDRs []netip.Prefix
}

func isIgnoredLine(line string) bool {
	if line == "" {
		return true
	}
	return strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "!") ||
		strings.HasPrefix(line, ";") ||
		strings.HasPrefix(line, "//")
}

func normalizeParseLimits(limits ParseLimits) ParseLimits {
	if limits.MaxLines <= 0 {
		limits.MaxLines = 3_000_000
	}
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = 4096
	}
	if limits.MaxRules <= 0 {
		limits.MaxRules = 3_000_000
	}
	if limits.MaxRejectedRows <= 0 {
		limits.MaxRejectedRows = 10_000
	}
	if limits.RejectionBudget <= 0 {
		limits.RejectionBudget = 0.005
	}
	return limits
}

func checkPostParseLimits(limits ParseLimits, cidrs []netip.Prefix, report ParseReport) error {
	if report.Accepted == 0 || len(cidrs) == 0 {
		return ErrNoValidRules
	}
	if limits.RejectionBudget > 0 && !limits.AllowNonPrefixRows {
		totalDataRows := report.Accepted + report.Duplicates + report.Rejected
		if totalDataRows > 0 && float64(report.Rejected)/float64(totalDataRows) > limits.RejectionBudget {
			return fmt.Errorf("rejection budget exceeded: %d of %d data rows rejected (%.2f%% > %.2f%%)",
				report.Rejected, totalDataRows,
				float64(report.Rejected)/float64(totalDataRows)*100,
				limits.RejectionBudget*100)
		}
	}
	if len(cidrs) > limits.MaxRules {
		return fmt.Errorf("rule count %d exceeds maximum rule limit %d", len(cidrs), limits.MaxRules)
	}
	return nil
}

// Parse reads IPv4 prefixes from r and validates them.
//
// There is one accepted format: CIDR prefixes and bare IPv4 addresses, with
// blank and comment lines ignored. The domain and mixed formats are gone
// alongside the external list feeds that used them.
func Parse(ctx context.Context, r io.Reader, limits ParseLimits) (ParsedRules, ParseReport, error) {
	limits = normalizeParseLimits(limits)

	bufReader := bufio.NewReader(r)

	// Strip UTF-8 BOM if present at the start of the stream
	bom, err := bufReader.Peek(3)
	if err == nil && bytes.Equal(bom, []byte{0xef, 0xbb, 0xbf}) {
		_, _ = bufReader.Discard(3)
	}

	scanner := bufio.NewScanner(bufReader)
	scanner.Buffer(make([]byte, limits.MaxLineBytes), limits.MaxLineBytes)

	report := ParseReport{}
	cidrs := make([]netip.Prefix, 0)
	seen := make(map[netip.Prefix]struct{}, 1024)

	for scanner.Scan() {
		report.TotalLines++
		if report.TotalLines%10000 == 0 && ctx.Err() != nil {
			return ParsedRules{}, report, ctx.Err()
		}

		if report.TotalLines > limits.MaxLines {
			return ParsedRules{}, report, fmt.Errorf("line limit %d exceeded", limits.MaxLines)
		}

		line := strings.TrimSpace(scanner.Text())
		if isIgnoredLine(line) {
			continue
		}

		prefix, ruleErr := ParseIPv4Rule(line)
		if ruleErr != nil {
			if limits.AllowNonPrefixRows {
				// A non-prefix row is permitted by this body's contract and is
				// reported separately by the caller, never as a rejection.
				continue
			}
			report.Rejected++
			if limits.Strict {
				return ParsedRules{}, report, fmt.Errorf("line %d: invalid IPv4 rule %q: %w", report.TotalLines, line, ruleErr)
			}
			if limits.MaxRejectedRows > 0 && report.Rejected > limits.MaxRejectedRows {
				return ParsedRules{}, report, fmt.Errorf(
					"rejection budget exceeded: %d rejected rows, last at line %d: %q: %w",
					report.Rejected, report.TotalLines, line, ruleErr)
			}
			continue
		}
		if _, duplicate := seen[prefix]; duplicate {
			report.Duplicates++
			continue
		}
		seen[prefix] = struct{}{}
		cidrs = append(cidrs, prefix)
		report.Accepted++
	}

	if err := scanner.Err(); err != nil {
		return ParsedRules{}, report, fmt.Errorf("scanner error during parse: %w", err)
	}

	if err := checkPostParseLimits(limits, cidrs, report); err != nil {
		return ParsedRules{}, report, err
	}

	return ParsedRules{CIDRs: cidrs}, report, nil
}
