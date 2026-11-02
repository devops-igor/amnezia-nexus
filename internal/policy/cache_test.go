package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCache_ErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	store := NewFileStore(tempDir)

	ctx := context.Background()

	// Commit nil generation
	if err := store.Commit(ctx, nil); err == nil {
		t.Fatal("expected error on committing nil generation")
	}

	// Commit incompatible schema version
	badGen := &Generation{
		SchemaVersion: 999,
		GenerationID:  "gen-bad",
		Version:       1,
	}
	if err := store.Commit(ctx, badGen); err == nil {
		t.Fatal("expected error on committing bad schema version")
	}

	// Load non-existent file
	if _, err := store.Load(ctx); !os.IsNotExist(err) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}

	// Commit valid generation
	goodGen := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  "gen-1",
		Version:       1,
		CreatedAt:     time.Now().UTC(),
		Domains:       map[string]uint8{"example.com": uint8(domainExact)},
		CIDRs:         []string{"10.0.0.0/24"},
	}
	if err := store.Commit(ctx, goodGen); err != nil {
		t.Fatalf("unexpected commit error: %v", err)
	}

	// Load and verify
	loaded, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if loaded.GenerationID != "gen-1" || loaded.Version != 1 {
		t.Fatalf("mismatched loaded generation: %+v", loaded)
	}

	// Corrupt content hash in cache file
	cachePath := filepath.Join(tempDir, cacheFileName)
	corruptData := []byte(`{
		"schema_version": 1,
		"generation_id": "gen-1",
		"version": 1,
		"content_hash": "corrupted-hash",
		"domains": {"example.com": 1},
		"cidrs": ["10.0.0.0/24"]
	}`)
	if err := os.WriteFile(cachePath, corruptData, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load(ctx); err == nil {
		t.Fatal("expected error on loading corrupted content hash")
	}

	// GenerationToSnapshot error handling
	if _, err := GenerationToSnapshot(nil); err == nil {
		t.Fatal("expected error on GenerationToSnapshot(nil)")
	}
	badCIDRGen := &Generation{
		Domains: map[string]uint8{"example.com": 1},
		CIDRs:   []string{"not-a-valid-cidr"},
	}
	if _, err := GenerationToSnapshot(badCIDRGen); err == nil {
		t.Fatal("expected error on bad CIDR in GenerationToSnapshot")
	}
}
