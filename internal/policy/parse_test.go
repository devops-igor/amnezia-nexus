package policy

import (
	"context"
	"strings"
	"testing"
)

// The parser is address-only now, and its two acceptance modes are the whole
// contract: a prefix list (the local exception list and the committed inventory)
// and the mixed override body that reports its name lines as ignored.

func TestParseIPV4List(t *testing.T) {
	body := strings.Join([]string{
		"# comment",
		"! another comment",
		"203.0.113.0/24",
		"198.51.100.7",
		"203.0.113.0/24", // duplicate
		"",
	}, "\n")

	parsed, report, err := Parse(context.Background(), strings.NewReader(body), DefaultParseLimits())
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if len(parsed.CIDRs) != 2 {
		t.Fatalf("prefixes = %d, want 2 after collapsing the duplicate", len(parsed.CIDRs))
	}
	if report.Accepted != 2 {
		t.Errorf("Accepted = %d, want 2", report.Accepted)
	}
	if report.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", report.Duplicates)
	}
	if report.Rejected != 0 {
		t.Errorf("Rejected = %d, want 0", report.Rejected)
	}
	// A bare address is a /32 so the packet path matches it exactly.
	if got := parsed.CIDRs[1].String(); got != "198.51.100.7/32" {
		t.Errorf("bare address parsed as %q, want 198.51.100.7/32", got)
	}
}

func TestParseEmptyBodies(t *testing.T) {
	for name, body := range map[string]string{
		"empty":         "",
		"whitespace":    "   \n\n\t\n",
		"only_comments": "# nothing here\n// nor here\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Parse(context.Background(), strings.NewReader(body), DefaultParseLimits())
			if err == nil {
				t.Fatal("Parse() accepted a body with no rules")
			}
			if !strings.Contains(err.Error(), "no valid rules") {
				t.Fatalf("Parse() = %v, want the empty-list reason", err)
			}
		})
	}
}

// A strict body reports the offending line, which is what an operator pasting a
// mistyped prefix needs to see.
func TestParseStrictReportsTheOffendingLine(t *testing.T) {
	limits := DefaultParseLimits()
	limits.Strict = true
	body := "203.0.113.0/24\nnot-a-prefix\n198.51.100.0/24\n"

	_, _, err := Parse(context.Background(), strings.NewReader(body), limits)
	if err == nil {
		t.Fatal("a strict parse accepted a non-prefix line")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("Parse() = %v, want the failing line number", err)
	}
	if !strings.Contains(err.Error(), "not-a-prefix") {
		t.Fatalf("Parse() = %v, want the offending row quoted", err)
	}
}

// A tolerant body that exceeds the rejection budget fails rather than publishing
// a partly-applied list.
func TestParseRejectionBudgetExceeded(t *testing.T) {
	limits := DefaultParseLimits()
	limits.MaxRejectedRows = 2
	var b strings.Builder
	b.WriteString("203.0.113.0/24\n")
	for i := 0; i < 5; i++ {
		b.WriteString("not-a-prefix\n")
	}

	_, _, err := Parse(context.Background(), strings.NewReader(b.String()), limits)
	if err == nil {
		t.Fatal("Parse() published a body past the rejection budget")
	}
	if !strings.Contains(err.Error(), "rejection budget exceeded") {
		t.Fatalf("Parse() = %v, want the rejection budget reason", err)
	}
}

// The override body accepts name lines and reports prefix rows; that is what
// lets the record say "accepted but not applied here" instead of silently
// dropping them.
func TestParseAllowNonPrefixRowsKeepsPrefixes(t *testing.T) {
	limits := DefaultParseLimits()
	limits.AllowNonPrefixRows = true
	body := "203.0.113.0/24\nexample.com\n198.51.100.0/24\n"

	parsed, report, err := Parse(context.Background(), strings.NewReader(body), limits)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if len(parsed.CIDRs) != 2 {
		t.Fatalf("prefixes = %d, want 2", len(parsed.CIDRs))
	}
	if report.Rejected != 0 {
		t.Errorf("Rejected = %d; a permitted name line is not a rejection", report.Rejected)
	}
}

// A body with name lines and no prefix yields nothing usable, which the caller
// must be able to detect as "would override nothing".
func TestParseAllowNonPrefixRowsWithNoPrefixIsEmpty(t *testing.T) {
	limits := DefaultParseLimits()
	limits.AllowNonPrefixRows = true

	_, _, err := Parse(context.Background(), strings.NewReader("example.com\nexample.org\n"), limits)
	if err == nil {
		t.Fatal("Parse() accepted a body with names but no prefix")
	}
}
