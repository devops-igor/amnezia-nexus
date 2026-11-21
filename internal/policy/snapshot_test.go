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
	if s.CIDRCount() != 0 {
		t.Errorf("s.CIDRCount() = %d, want 0", s.CIDRCount())
	}
	if s.SourceIDs() != nil {
		t.Errorf("s.SourceIDs() = %v, want nil", s.SourceIDs())
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
				CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
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
	if !snap.MatchIPv4(netip.MustParseAddr("10.1.2.3")) {
		t.Error("MatchIPv4(10.1.2.3) should match")
	}
	if snap.MatchIPv4(netip.MustParseAddr("11.0.0.1")) {
		t.Error("MatchIPv4(11.0.0.1) should not match")
	}
}

func TestSyncer_Status(t *testing.T) {
	matcher := NewMatcher()
	store := NewFileStore(t.TempDir())
	cfg := SyncConfig{
		LocalRules:      ParsedRules{CIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		RefreshInterval: MinRefreshInterval,
	}
	syncer, err := NewSyncer(matcher, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncer error: %v", err)
	}

	st := syncer.Status()
	if st.Ready {
		t.Error("newly created syncer should not be ready")
	}

	// Constructor validation. A configuration with no rules is a valid shape:
	// the empty-policy refusal belongs to the publication guard, which is where
	// the operator-facing activation error comes from.
	if _, err := NewSyncer(nil, store, cfg); err == nil {
		t.Error("expected error for nil matcher")
	}
	if _, err := NewSyncer(matcher, nil, cfg); err == nil {
		t.Error("expected error for nil store")
	}
	if _, err := NewSyncer(matcher, store, SyncConfig{}); err != nil {
		t.Errorf("NewSyncer rejected a rule-less configuration: %v", err)
	}
	if _, err := NewSyncer(matcher, store, SyncConfig{
		RefreshInterval: 5 * time.Minute, // less than MinRefreshInterval (30m)
	}); err == nil {
		t.Error("expected error for refresh interval < 30m")
	}
}

func TestCompileSnapshot_DeduplicateCIDRs(t *testing.T) {
	sources := []SourceParsedRules{
		{
			SourceID: "s1",
			Rules: ParsedRules{
				CIDRs: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("192.168.1.1/32"),
				},
			},
		},
		{
			SourceID: "s2",
			Rules: ParsedRules{
				CIDRs: []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),     // exact duplicate across sources
					netip.MustParsePrefix("192.168.1.1/32"), // exact duplicate across sources
					netip.MustParsePrefix("172.16.0.0/12"),
				},
			},
		},
	}

	snap, err := CompileSnapshot(1, "gen-dedup", sources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if snap.CIDRCount() != 3 {
		t.Errorf("snap.CIDRCount() = %d, want 3", snap.CIDRCount())
	}
	if !snap.MatchIPv4(netip.MustParseAddr("10.5.0.1")) {
		t.Error("expected 10.5.0.1 to match")
	}
	if !snap.MatchIPv4(netip.MustParseAddr("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to match")
	}
	if !snap.MatchIPv4(netip.MustParseAddr("172.16.1.1")) {
		t.Error("expected 172.16.1.1 to match")
	}
	if snap.MatchIPv4(netip.MustParseAddr("192.168.2.1")) {
		t.Error("expected 192.168.2.1 not to match")
	}
}
