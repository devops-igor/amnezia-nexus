package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These oracles pin the contract of AdoptBaseline, which the live-policy
// replacement path uses to recognise that a settings save left the effective rules
// unchanged. The decisive property is that adoption is a read: it records the
// durable generation for comparison and publishes nothing, so it cannot take write
// ownership from the runtime that is still serving.
func TestSyncer_AdoptBaseline(t *testing.T) {
	newSyncer := func(t *testing.T, dir string, cfg SyncConfig) (*Syncer, *Matcher) {
		t.Helper()
		matcher := NewMatcher()
		syncer, err := NewSyncer(matcher, nil, NewFileStore(dir), cfg)
		if err != nil {
			t.Fatalf("NewSyncer: %v", err)
		}
		return syncer, matcher
	}
	cfgFor := func(url string) SyncConfig {
		return SyncConfig{
			Sources: []Source{{
				ID:             "source-1",
				URL:            url,
				Format:         FormatMixed,
				BareDomainMode: DomainModeExact,
				IsPreset:       true,
			}},
			RefreshInterval: time.Hour,
			FetchLimits:     DefaultFetchLimits(),
			ParseLimits:     DefaultParseLimits(),
		}
	}

	t.Run("absent store records nothing", func(t *testing.T) {
		syncer, matcher := newSyncer(t, t.TempDir(), cfgFor("https://rules.example.com/a.lst"))
		status, err := syncer.AdoptBaseline(context.Background())
		if err != nil {
			t.Fatalf("AdoptBaseline on an empty store: %v", err)
		}
		if status != BaselineAbsent {
			t.Errorf("baseline status = %v, want BaselineAbsent", status)
		}
		if syncer.cachedGen != nil {
			t.Error("AdoptBaseline adopted a generation that does not exist")
		}
		if matcher.Current() != nil {
			t.Error("AdoptBaseline published a snapshot")
		}
	})

	t.Run("unreadable store is reported, not published", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, cacheFileName), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write corrupt cache: %v", err)
		}
		syncer, matcher := newSyncer(t, dir, cfgFor("https://rules.example.com/a.lst"))
		status, err := syncer.AdoptBaseline(context.Background())
		if err == nil {
			t.Fatal("AdoptBaseline accepted an unreadable stored generation")
		}
		if status != BaselineAbsent {
			t.Errorf("baseline status = %v, want BaselineAbsent", status)
		}
		if syncer.cachedGen != nil || matcher.Current() != nil {
			t.Error("AdoptBaseline used an unreadable stored generation")
		}
	})

	t.Run("foreign configuration is not adopted", func(t *testing.T) {
		dir := t.TempDir()
		seeder, _ := newSyncer(t, dir, cfgFor("https://rules.example.com/a.lst"))
		if err := seeder.store.Commit(context.Background(), &Generation{
			SchemaVersion: SchemaVersion,
			GenerationID:  "gen-adopt-seed",
			Version:       3,
			CreatedAt:     time.Now().UTC(),
			ConfigHash:    seeder.ConfigHash(),
			Domains:       map[string]uint32{"listed.example.com": uint32(domainExact)},
		}); err != nil {
			t.Fatalf("seed generation: %v", err)
		}

		other, matcher := newSyncer(t, dir, cfgFor("https://rules.example.com/b.lst"))
		status, err := other.AdoptBaseline(context.Background())
		if err != nil {
			t.Fatalf("AdoptBaseline for a different configuration: %v", err)
		}
		if status != BaselineForeign {
			t.Errorf("baseline status = %v, want BaselineForeign", status)
		}
		if other.cachedGen != nil {
			t.Error("AdoptBaseline adopted a generation belonging to a different configuration")
		}
		if matcher.Current() != nil {
			t.Error("AdoptBaseline published a foreign configuration's rules")
		}
	})

	t.Run("matching configuration is recorded without publication", func(t *testing.T) {
		dir := t.TempDir()
		cfg := cfgFor("https://rules.example.com/a.lst")
		seeder, _ := newSyncer(t, dir, cfg)
		seeded := &Generation{
			SchemaVersion: SchemaVersion,
			GenerationID:  "gen-adopt-match",
			Version:       4,
			CreatedAt:     time.Now().UTC(),
			ConfigHash:    seeder.ConfigHash(),
			Domains:       map[string]uint32{"listed.example.com": uint32(domainExact)},
			CIDRs:         []string{"198.51.100.0/24"},
		}
		if err := seeder.store.Commit(context.Background(), seeded); err != nil {
			t.Fatalf("seed generation: %v", err)
		}

		replacement, matcher := newSyncer(t, dir, cfg)
		status, err := replacement.AdoptBaseline(context.Background())
		if err != nil {
			t.Fatalf("AdoptBaseline: %v", err)
		}
		if status != BaselinePrimed {
			t.Fatalf("baseline status = %v, want BaselinePrimed", status)
		}
		if replacement.cachedGen == nil || replacement.cachedGen.GenerationID != "gen-adopt-match" {
			t.Fatalf("adopted generation = %+v, want gen-adopt-match", replacement.cachedGen)
		}
		// The whole point of adoption: the live policy is not touched, so the runtime
		// that is still serving keeps the boundary and its own publication.
		if matcher.Current() != nil {
			t.Error("AdoptBaseline published the adopted generation")
		}
	})
}
