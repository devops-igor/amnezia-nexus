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

// Format indicates whether a rule list source contains domains, IPv4 ranges, or mixed rules.
type Format uint8

const (
	// FormatDomains parses domain names and converts IPv4 literals to /32 prefixes.
	FormatDomains Format = iota + 1
	// FormatIPv4 parses CIDR prefixes and bare IPv4 addresses.
	FormatIPv4
	// FormatMixed parses both IPv4 prefixes and domain rules.
	FormatMixed
)

// String returns human-readable format name.
func (f Format) String() string {
	switch f {
	case FormatDomains:
		return "domains"
	case FormatIPv4:
		return "ipv4"
	case FormatMixed:
		return "mixed"
	default:
		return "unknown"
	}
}

// Source identifies a rule list feed and its parsing configuration.
type Source struct {
	ID             string     `json:"id"`
	URL            string     `json:"url"`
	Format         Format     `json:"format"`
	BareDomainMode DomainMode `json:"bare_domain_mode"`
	IsPreset       bool       `json:"is_preset"`
}

// ParseLimits bounds list processing to prevent memory or CPU exhaustion.
type ParseLimits struct {
	MaxLines        int
	MaxLineBytes    int
	MaxRules        int
	RejectionBudget float64 // Fraction of rejected rows allowed for built-in feeds (e.g. 0.005)
	MaxRejectedRows int     // Absolute cap on rejected rows for built-in feeds (e.g. 10000)
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

// ParseReport records accounting stats from parsing a rule feed.
type ParseReport struct {
	TotalLines int `json:"total_lines"`
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
}

// ParsedRules holds the extracted domain map and CIDR prefixes.
type ParsedRules struct {
	Domains map[string]domainFlags
	CIDRs   []netip.Prefix
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

func recordDomainRule(base string, flags domainFlags, domains map[string]domainFlags, report *ParseReport) {
	if existing, exists := domains[base]; exists {
		if existing&flags == flags {
			report.Duplicates++
		} else {
			domains[base] |= flags
			report.Accepted++
		}
	} else {
		domains[base] = flags
		report.Accepted++
	}
}

func checkRejectionBudget(lineNo int, line string, err error, src Source, limits ParseLimits, report *ParseReport) error {
	report.Rejected++
	if !src.IsPreset {
		if src.Format == FormatDomains {
			return fmt.Errorf("line %d: invalid domain rule %q: %w", lineNo, line, err)
		}
		return fmt.Errorf("line %d: invalid rule %q: %w", lineNo, line, err)
	}
	if report.Rejected > limits.MaxRejectedRows ||
		(report.Accepted+report.Rejected > 0 &&
			float64(report.Rejected)/float64(report.Accepted+report.Rejected) > limits.RejectionBudget) {
		return fmt.Errorf("rejection budget exceeded at line %d: %d rejected rows: %w", lineNo, report.Rejected, err)
	}
	return nil
}

func parseDomainsRow(line string, src Source, limits ParseLimits, domains map[string]domainFlags, cidrs *[]netip.Prefix, report *ParseReport) error {
	base, flags, isIP, ip, ruleErr := ParseDomainRule(line, src.BareDomainMode)
	if isIP {
		*cidrs = append(*cidrs, netip.PrefixFrom(ip, 32))
		report.Accepted++
		return nil
	}
	if ruleErr != nil {
		return checkRejectionBudget(report.TotalLines, line, ruleErr, src, limits, report)
	}
	recordDomainRule(base, flags, domains, report)
	return nil
}

func parseIPv4Row(line string, cidrs *[]netip.Prefix, report *ParseReport) error {
	prefix, ruleErr := ParseIPv4Rule(line)
	if ruleErr != nil {
		report.Rejected++
		return fmt.Errorf("line %d: invalid IPv4 rule %q: %w", report.TotalLines, line, ruleErr)
	}
	*cidrs = append(*cidrs, prefix)
	report.Accepted++
	return nil
}

func parseMixedRow(line string, src Source, limits ParseLimits, domains map[string]domainFlags, cidrs *[]netip.Prefix, report *ParseReport) error {
	// Try IPv4 rule first
	if prefix, ruleErr := ParseIPv4Rule(line); ruleErr == nil {
		*cidrs = append(*cidrs, prefix)
		report.Accepted++
		return nil
	}

	// Try domain rule
	base, flags, isIP, ip, ruleErr := ParseDomainRule(line, src.BareDomainMode)
	if isIP {
		*cidrs = append(*cidrs, netip.PrefixFrom(ip, 32))
		report.Accepted++
		return nil
	}
	if ruleErr != nil {
		return checkRejectionBudget(report.TotalLines, line, ruleErr, src, limits, report)
	}
	recordDomainRule(base, flags, domains, report)
	return nil
}

// Parse reads list rules from r, validates and normalizes entries according to src configuration.
func Parse(ctx context.Context, r io.Reader, src Source, limits ParseLimits) (ParsedRules, ParseReport, error) {
	if limits.MaxLines <= 0 {
		limits.MaxLines = 3_000_000
	}
	if limits.MaxLineBytes <= 0 {
		limits.MaxLineBytes = 4096
	}
	if limits.MaxRules <= 0 {
		limits.MaxRules = 3_000_000
	}

	bufReader := bufio.NewReader(r)

	// Strip UTF-8 BOM if present at the start of the stream
	bom, err := bufReader.Peek(3)
	if err == nil && bytes.Equal(bom, []byte{0xef, 0xbb, 0xbf}) {
		_, _ = bufReader.Discard(3)
	}

	scanner := bufio.NewScanner(bufReader)
	scanner.Buffer(make([]byte, limits.MaxLineBytes), limits.MaxLineBytes)

	report := ParseReport{}
	domains := make(map[string]domainFlags)
	cidrs := make([]netip.Prefix, 0)

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

		var rowErr error
		switch src.Format {
		case FormatDomains:
			rowErr = parseDomainsRow(line, src, limits, domains, &cidrs, &report)
		case FormatIPv4:
			rowErr = parseIPv4Row(line, &cidrs, &report)
		case FormatMixed:
			rowErr = parseMixedRow(line, src, limits, domains, &cidrs, &report)
		default:
			return ParsedRules{}, report, fmt.Errorf("unsupported source format: %d", src.Format)
		}
		if rowErr != nil {
			return ParsedRules{}, report, rowErr
		}
	}

	if err := scanner.Err(); err != nil {
		return ParsedRules{}, report, fmt.Errorf("scanner error during parse: %w", err)
	}

	if report.TotalLines > 0 && report.Accepted == 0 {
		return ParsedRules{}, report, errors.New("feed contained no valid rules")
	}

	if len(domains)+len(cidrs) > limits.MaxRules {
		return ParsedRules{}, report, fmt.Errorf("rule count %d exceeds maximum rule limit %d", len(domains)+len(cidrs), limits.MaxRules)
	}

	return ParsedRules{
		Domains: domains,
		CIDRs:   cidrs,
	}, report, nil
}
