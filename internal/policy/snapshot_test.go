package policy

import (
	"net/netip"
	"testing"
	"time"
)

func TestSnapshot_NilSafety(t *testing.T) {
	var s *Snapshot

	if s.Version() != 0 {
		t.Errorf("s.Version() = %d, want 0", s.Version())
	}
	if s.Generation() != "" {
		t.Errorf("s.Generation() = %q, want empty", s.Generation())
	}
	if !s.CreatedAt().IsZero() {
		t.Errorf("s.CreatedAt() = %v, want zero", s.CreatedAt())
	}
	if s.DomainCount() != 0 {
		t.Errorf("s.DomainCount() = %d, want 0", s.DomainCount())
	}
	if s.CIDRCount() != 0 {
		t.Errorf("s.CIDRCount() = %d, want 0", s.CIDRCount())
	}
	if s.SourceIDs() != nil {
		t.Errorf("s.SourceIDs() = %v, want nil", s.SourceIDs())
	}
	if s.MatchCanonicalDomain("example.com") {
		t.Error("s.MatchCanonicalDomain() want false")
	}
	if s.MatchDomain("example.com") {
		t.Error("s.MatchDomain() want false")
	}
	if s.MatchIPv4(netip.MustParseAddr("1.1.1.1")) {
		t.Error("s.MatchIPv4() want false")
	}
}

func TestSnapshot_CompileValidation(t *testing.T) {
	if _, err := CompileSnapshot(1, "gen-0", nil); err == nil {
		t.Fatal("expected error on zero sources compile")
	}

	snap, err := CompileSnapshot(1, "gen-1", []SourceParsedRules{
		{
			SourceID: "src-1",
			Rules: ParsedRules{
				Domains: map[string]domainFlags{"example.com": domainExact},
				CIDRs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	if snap.Generation() != "gen-1" {
		t.Errorf("Generation() = %s, want gen-1", snap.Generation())
	}
	if snap.CreatedAt().IsZero() {
		t.Error("CreatedAt() should not be zero")
	}
	if len(snap.SourceIDs()) != 1 || snap.SourceIDs()[0] != "src-1" {
		t.Errorf("SourceIDs() = %v, want [src-1]", snap.SourceIDs())
	}
	if !snap.MatchDomain("EXAMPLE.COM.") {
		t.Error("MatchDomain(EXAMPLE.COM.) should match")
	}
	if snap.MatchDomain("notfound.com") {
		t.Error("MatchDomain(notfound.com) should not match")
	}
	if snap.MatchDomain("invalid..domain") {
		t.Error("MatchDomain(invalid..domain) should return false")
	}
}

func TestFormat_String(t *testing.T) {
	if FormatDomains.String() != "domains" {
		t.Errorf("FormatDomains = %s, want domains", FormatDomains.String())
	}
	if FormatIPv4.String() != "ipv4" {
		t.Errorf("FormatIPv4 = %s, want ipv4", FormatIPv4.String())
	}
	if FormatMixed.String() != "mixed" {
		t.Errorf("FormatMixed = %s, want mixed", FormatMixed.String())
	}
	if Format(99).String() != "unknown" {
		t.Errorf("Format(99) = %s, want unknown", Format(99).String())
	}
}

func TestSyncer_Status(t *testing.T) {
	matcher := NewMatcher()
	store := NewFileStore(t.TempDir())
	cfg := SyncConfig{
		Sources: []Source{
			{ID: "s1", URL: "https://example.com/rules.lst", Format: FormatDomains},
		},
		RefreshInterval: MinRefreshInterval,
	}
	syncer, err := NewSyncer(matcher, nil, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	st := syncer.Status()
	if st.Ready {
		t.Error("newly created syncer should not be ready")
	}

	// Test NewSyncer validation
	if _, err := NewSyncer(nil, nil, store, cfg); err == nil {
		t.Error("expected error for nil matcher")
	}
	if _, err := NewSyncer(matcher, nil, nil, cfg); err == nil {
		t.Error("expected error for nil store")
	}
	if _, err := NewSyncer(matcher, nil, store, SyncConfig{}); err == nil {
		t.Error("expected error for empty sources")
	}
	if _, err := NewSyncer(matcher, nil, store, SyncConfig{
		Sources: []Source{{ID: "1"}, {ID: "2"}, {ID: "3"}, {ID: "4"}, {ID: "5"}},
	}); err == nil {
		t.Error("expected error for > 4 sources")
	}
	if _, err := NewSyncer(matcher, nil, store, SyncConfig{
		Sources:         []Source{{ID: "1", URL: "https://example.com/r.lst"}},
		RefreshInterval: 5 * time.Minute, // less than MinRefreshInterval (30m)
	}); err == nil {
		t.Error("expected error for refresh interval < 30m")
	}
}
