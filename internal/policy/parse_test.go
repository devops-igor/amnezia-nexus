package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParse_DomainsPresetTolerant(t *testing.T) {
	// Sample containing valid domains, comments, whitespace, BOM, IP literals, and a few malformed rows
	input := "\xef\xbb\xbf# Header comment\n" +
		"! Another comment\n" +
		"; Semicolon comment\n" +
		"// C-style comment\n" +
		"\n" +
		"example.com\n" +
		"EXAMPLE.COM\n" + // duplicate
		".google.com\n" +
		"*.yahoo.com\n" +
		"пример.рф\n" +
		"198.51.100.7\n" + // IPv4 literal in domain list
		"\"quoted-bad.ru\n" + // malformed line
		"-bad-hyphen.com\n" + // malformed line
		"ok.org\n"

	src := Source{
		ID:             "antifilter-domains",
		URL:            "https://antifilter.download/list/domains.lst",
		Format:         FormatDomains,
		BareDomainMode: DomainModeInclusiveSuffix,
		IsPreset:       true,
	}

	limits := DefaultParseLimits()
	limits.RejectionBudget = 0.5 // allow high fraction for this tiny fixture

	rules, report, err := Parse(context.Background(), strings.NewReader(input), src, limits)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if report.Rejected != 2 {
		t.Errorf("report.Rejected = %d, want 2", report.Rejected)
	}
	if report.Duplicates != 1 {
		t.Errorf("report.Duplicates = %d, want 1", report.Duplicates)
	}
	// example.com, google.com, yahoo.com, xn--e1afmkfd.xn--p1ai, ok.org = 5 domains
	if len(rules.Domains) != 5 {
		t.Errorf("len(rules.Domains) = %d, want 5", len(rules.Domains))
	}
	// 198.51.100.7/32
	if len(rules.CIDRs) != 1 {
		t.Fatalf("len(rules.CIDRs) = %d, want 1", len(rules.CIDRs))
	}
	if rules.CIDRs[0].String() != "198.51.100.7/32" {
		t.Errorf("CIDR = %s, want 198.51.100.7/32", rules.CIDRs[0].String())
	}

	// Verify domain flags
	if f := rules.Domains["example.com"]; f != domainInclusiveSuffix {
		t.Errorf("example.com flags = %d, want %d", f, domainInclusiveSuffix)
	}
	if f := rules.Domains["yahoo.com"]; f != domainDescendants {
		t.Errorf("yahoo.com flags = %d, want %d", f, domainDescendants)
	}
}

func TestParse_CustomStrictRejection(t *testing.T) {
	input := "good.com\n\"bad.com\n"
	src := Source{
		ID:             "custom",
		URL:            "https://custom.example.com/rules.lst",
		Format:         FormatDomains,
		BareDomainMode: DomainModeExact,
		IsPreset:       false, // strict!
	}

	_, _, err := Parse(context.Background(), strings.NewReader(input), src, DefaultParseLimits())
	if err == nil || !strings.Contains(err.Error(), "invalid domain rule") {
		t.Fatalf("expected strict parse error on line 2, got %v", err)
	}
}

func TestParse_RejectionBudgetExceeded(t *testing.T) {
	input := "good.com\n\"bad1.com\n\"bad2.com\n\"bad3.com\n"
	src := Source{
		ID:             "preset",
		URL:            "https://preset.example.com/rules.lst",
		Format:         FormatDomains,
		BareDomainMode: DomainModeInclusiveSuffix,
		IsPreset:       true,
	}

	limits := DefaultParseLimits()
	limits.RejectionBudget = 0.1 // 10% budget, input has 75% bad

	_, _, err := Parse(context.Background(), strings.NewReader(input), src, limits)
	if err == nil || !strings.Contains(err.Error(), "rejection budget exceeded") {
		t.Fatalf("expected rejection budget exceeded error, got %v", err)
	}
}

func TestParse_IPv4List(t *testing.T) {
	input := "# Antifilter subnet list\n" +
		"198.51.100.0/24\n" +
		"203.0.113.128/25\n" +
		"10.0.0.1\n" // bare ip treated as /32

	src := Source{
		ID:       "antifilter-subnets",
		URL:      "https://antifilter.download/list/subnet.lst",
		Format:   FormatIPv4,
		IsPreset: true,
	}

	rules, report, err := Parse(context.Background(), strings.NewReader(input), src, DefaultParseLimits())
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if report.Accepted != 3 {
		t.Errorf("report.Accepted = %d, want 3", report.Accepted)
	}
	if len(rules.CIDRs) != 3 {
		t.Fatalf("len(rules.CIDRs) = %d, want 3", len(rules.CIDRs))
	}
	if rules.CIDRs[2].String() != "10.0.0.1/32" {
		t.Errorf("rules.CIDRs[2] = %s, want 10.0.0.1/32", rules.CIDRs[2].String())
	}
}

func TestParse_MixedFormat(t *testing.T) {
	input := "example.com\n" +
		"192.168.1.0/24\n" +
		"10.0.0.1\n" +
		".suffix.com\n"

	src := Source{
		ID:             "mixed-feed",
		URL:            "https://mixed.example.com/rules.lst",
		Format:         FormatMixed,
		BareDomainMode: DomainModeExact,
		IsPreset:       true,
	}

	rules, report, err := Parse(context.Background(), strings.NewReader(input), src, DefaultParseLimits())
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if report.Accepted != 4 {
		t.Errorf("report.Accepted = %d, want 4", report.Accepted)
	}
	if len(rules.Domains) != 2 {
		t.Errorf("len(rules.Domains) = %d, want 2", len(rules.Domains))
	}
	if len(rules.CIDRs) != 2 {
		t.Errorf("len(rules.CIDRs) = %d, want 2", len(rules.CIDRs))
	}
}

func TestParse_EmptyFeedError(t *testing.T) {
	input := "# only comments\n\n   \n"
	src := Source{
		ID:       "empty-feed",
		URL:      "https://empty.example.com/rules.lst",
		Format:   FormatDomains,
		IsPreset: true,
	}

	_, _, err := Parse(context.Background(), strings.NewReader(input), src, DefaultParseLimits())
	if err == nil || !strings.Contains(err.Error(), "contained no valid rules") {
		t.Fatalf("expected error for empty feed, got %v", err)
	}
	if !errors.Is(err, ErrNoValidRules) {
		t.Errorf("expected errors.Is(err, ErrNoValidRules), got %v", err)
	}
}

func TestParse_ZeroByteFeedError(t *testing.T) {
	formats := []Format{FormatDomains, FormatIPv4, FormatMixed}
	for _, fmtType := range formats {
		t.Run(fmtType.String(), func(t *testing.T) {
			src := Source{
				ID:       "zero-byte-feed",
				URL:      "https://empty.example.com/zero.lst",
				Format:   fmtType,
				IsPreset: true,
			}

			rules, report, err := Parse(context.Background(), strings.NewReader(""), src, DefaultParseLimits())
			if err == nil {
				t.Fatalf("expected error for zero-byte feed, got nil")
			}
			if !errors.Is(err, ErrNoValidRules) {
				t.Errorf("expected ErrNoValidRules, got %v", err)
			}
			if report.TotalLines != 0 || report.Accepted != 0 {
				t.Errorf("expected 0 TotalLines and 0 Accepted, got %+v", report)
			}
			if len(rules.Domains) != 0 || len(rules.CIDRs) != 0 {
				t.Errorf("expected 0 rules, got %d domains, %d cidrs", len(rules.Domains), len(rules.CIDRs))
			}
		})
	}
}

func TestParse_LeadingMalformedRowsWithinBudget(t *testing.T) {
	// Construct 1 malformed row followed by 999 valid domains
	var sb strings.Builder
	sb.WriteString("\"certr.ru\n") // Antifilter-style malformed leading line
	for i := 0; i < 999; i++ {
		fmt.Fprintf(&sb, "valid%d.example.com\n", i)
	}
	input := sb.String()

	// 1. Preset feed should tolerate leading malformed row because overall rejection rate is 1/1000 = 0.1% <= 0.5%
	presetSrc := Source{
		ID:             "preset-feed",
		URL:            "https://preset.example.com/domains.lst",
		Format:         FormatDomains,
		BareDomainMode: DomainModeInclusiveSuffix,
		IsPreset:       true,
	}

	rules, report, err := Parse(context.Background(), strings.NewReader(input), presetSrc, DefaultParseLimits())
	if err != nil {
		t.Fatalf("expected preset feed to succeed despite leading malformed line, got: %v", err)
	}
	if report.Rejected != 1 {
		t.Errorf("report.Rejected = %d, want 1", report.Rejected)
	}
	if report.Accepted != 999 {
		t.Errorf("report.Accepted = %d, want 999", report.Accepted)
	}
	if len(rules.Domains) != 999 {
		t.Errorf("len(rules.Domains) = %d, want 999", len(rules.Domains))
	}

	// 2. Custom feed should reject immediately on line 1 (strict parsing)
	customSrc := Source{
		ID:             "custom-feed",
		URL:            "https://custom.example.com/domains.lst",
		Format:         FormatDomains,
		BareDomainMode: DomainModeExact,
		IsPreset:       false,
	}

	_, _, err = Parse(context.Background(), strings.NewReader(input), customSrc, DefaultParseLimits())
	if err == nil || !strings.Contains(err.Error(), "invalid domain rule") {
		t.Fatalf("expected strict custom feed to reject on line 1, got %v", err)
	}
}
