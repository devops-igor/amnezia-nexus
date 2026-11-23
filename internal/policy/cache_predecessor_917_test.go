package policy

// The last-known-good cache changed representation when domain rules were retired:
// the predecessor writer digested its domain entries as well as its prefixes, while
// this build digests prefixes only and stores no domains. The schema version stayed
// 1 across that change, because a generation is still a compiled snapshot of what
// was published.
//
// Those two facts together used to make an upgrade unreadable: the current loader
// recomputed the prefix-only digest, compared it with a stored digest that also
// covered the domain half, and reported corruption. FileStore.Load failed before
// PrimeBaseline could recognize a foreign configuration and rebuild, so PBR could
// not activate on an installation whose only problem was that it had been running
// the earlier release.
//
// The fixture below is not hand-written. It was produced by the predecessor build's
// own Commit (its own ComputeContentHash and its own ConfigHash), so these bytes are
// exactly what an earlier release left on disk. Every case feeds the current reader
// and the current activation path — the same code production runs — so a regression
// here is a real upgrade failure, not a disagreement with a fixture.
//
// The positive case alone would be satisfied by a loader that trusts any file, so
// it is paired with the corrupt-cache control that must still be refused and with
// the fresh-store control where there is nothing to load at all.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// predecessorFixturePath is the durable cache an earlier release wrote, embedded
// here because it is a byte-format contract rather than a test input.
const predecessorFixturePath = "testdata/policy_lkg_predecessor.json"

// writePredecessorCache installs the predecessor fixture in a fresh directory and
// returns a store over it.
func writePredecessorCache(t *testing.T) (*FileStore, string) {
	t.Helper()
	body, err := os.ReadFile(predecessorFixturePath)
	if err != nil {
		t.Fatalf("read the predecessor cache fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cacheFileName), body, 0600); err != nil {
		t.Fatalf("install the predecessor cache: %v", err)
	}
	return NewFileStore(dir), dir
}

// TestFileStoreLoadsPredecessorGeneration is the F957-01 regression: a valid
// predecessor cache is a usable last-known-good policy, not corruption.
func TestFileStoreLoadsPredecessorGeneration(t *testing.T) {
	store, _ := writePredecessorCache(t)

	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("a valid predecessor cache must load; refusing it is what prevents activation after "+
			"an upgrade even when the operator supplied usable exceptions: %v", err)
	}
	if gen == nil {
		t.Fatal("Load returned no generation and no error")
	}
	if len(gen.CIDRs) != 1 || gen.CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("loaded prefixes = %v, want the stored 198.51.100.0/24", gen.CIDRs)
	}
	if gen.LegacyDomains != nil {
		t.Fatalf("the retired domain half survived into the loaded record: %v", gen.LegacyDomains)
	}
	if gen.GenerationID != "gen-pre957" || gen.Version != 7 {
		t.Fatalf("loaded identity = %q v%d, want gen-pre957 v7", gen.GenerationID, gen.Version)
	}

	// The prefixes must compile into a snapshot, because that is what activation
	// publishes: a load that returned unusable rules would still leave PBR off.
	snap, err := GenerationToSnapshot(gen)
	if err != nil {
		t.Fatalf("the loaded predecessor generation does not compile: %v", err)
	}
	if snap.CIDRCount() != 1 {
		t.Fatalf("compiled %d prefixes, want 1", snap.CIDRCount())
	}
}

// TestFileStoreStillRefusesCorruptCache is the F957-01 negative control. The fix
// recognizes one specific predecessor representation; it must not weaken the guard
// that refuses bytes which are genuinely damaged.
func TestFileStoreStillRefusesCorruptCache(t *testing.T) {
	body, err := os.ReadFile(predecessorFixturePath)
	if err != nil {
		t.Fatalf("read the predecessor cache fixture: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(string) string
		wantMsg string
	}{
		{
			name: "prefix_altered_under_stored_digest",
			mutate: func(s string) string {
				return strings.Replace(s, `"198.51.100.0/24"`, `"203.0.113.0/24"`, 1)
			},
			wantMsg: "content hash mismatch",
		},
		{
			name: "domain_altered_under_stored_digest",
			mutate: func(s string) string {
				return strings.Replace(s, `"example.com": 2`, `"example.org": 2`, 1)
			},
			wantMsg: "content hash mismatch",
		},
		{
			name: "digest_replaced",
			mutate: func(s string) string {
				return strings.Replace(s,
					"fdc8039b57485f31c966bb5f79cd317b1f1fca859c3da974e60b421a6ce75cfe",
					strings.Repeat("0", 64), 1)
			},
			wantMsg: "content hash mismatch",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			damaged := tc.mutate(string(body))
			if damaged == string(body) {
				t.Fatal("the mutation did not change the fixture; the control would prove nothing")
			}
			if err := os.WriteFile(filepath.Join(dir, cacheFileName), []byte(damaged), 0600); err != nil {
				t.Fatalf("write the damaged cache: %v", err)
			}
			_, err := NewFileStore(dir).Load(context.Background())
			if err == nil {
				t.Fatal("a damaged cache loaded successfully; the corruption guard must still refuse it")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("refusal = %v, want it to report %q so the operator learns the file is damaged", err, tc.wantMsg)
			}
		})
	}
}

// TestFileStoreFreshStoreStillReportsAbsent is the other half of the loader's
// contract: with no cache at all there is nothing to migrate, and the caller must
// still see an ordinary absence rather than a migration or a corruption report.
func TestFileStoreFreshStoreStillReportsAbsent(t *testing.T) {
	_, err := NewFileStore(t.TempDir()).Load(context.Background())
	if !os.IsNotExist(err) {
		t.Fatalf("a fresh store returned %v, want os.ErrNotExist", err)
	}
}

// TestFileStorePredecessorMigratesOnNextCommit proves the load is a migration and
// not a permanent second format: the next commit writes the current representation,
// so the operator's cache does not stay in the predecessor shape forever.
func TestFileStorePredecessorMigratesOnNextCommit(t *testing.T) {
	store, dir := writePredecessorCache(t)

	gen, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("load the predecessor cache: %v", err)
	}
	gen.GenerationID = "gen-migrated"
	gen.Version = 8
	if err := store.Commit(context.Background(), gen); err != nil {
		t.Fatalf("commit the migrated generation: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, cacheFileName))
	if err != nil {
		t.Fatalf("read the rewritten cache: %v", err)
	}
	if strings.Contains(string(body), `"domains"`) {
		t.Fatalf("the rewritten cache still carries the retired domain half:\n%s", body)
	}

	// The rewritten file must verify under the current grammar and stay readable,
	// which is what stops a migrated installation from failing on its next start.
	reloaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("reload the rewritten cache: %v", err)
	}
	if reloaded.GenerationID != "gen-migrated" || reloaded.Version != 8 {
		t.Fatalf("reloaded identity = %q v%d, want gen-migrated v8", reloaded.GenerationID, reloaded.Version)
	}
	if len(reloaded.CIDRs) != 1 || reloaded.CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("reloaded prefixes = %v, want the preserved 198.51.100.0/24", reloaded.CIDRs)
	}
}

// TestVerifyStoredGenerationAcceptsBothGrammarsDirectly pins the verification
// decision itself, including the ordering that makes it safe: a record whose stored
// digest matches the current grammar is not re-interpreted through the predecessor
// grammar even if it happens to carry a domains field.
func TestVerifyStoredGenerationAcceptsBothGrammarsDirectly(t *testing.T) {
	predecessor, err := os.ReadFile(predecessorFixturePath)
	if err != nil {
		t.Fatalf("read the predecessor cache fixture: %v", err)
	}

	t.Run("predecessor_bytes", func(t *testing.T) {
		gen, retired, err := verifyStoredGeneration(predecessor)
		if err != nil {
			t.Fatalf("predecessor bytes refused: %v", err)
		}
		if retired != 1 {
			t.Fatalf("retired domain count = %d, want 1", retired)
		}
		if gen.LegacyDomains != nil {
			t.Fatal("the loaded generation kept its retired domains")
		}
	})

	t.Run("current_bytes_with_no_domains", func(t *testing.T) {
		current := []byte(`{"schema_version":1,"generation_id":"gen-cur","version":3,` +
			`"cidrs":["203.0.113.0/24"],"content_hash":"` + ComputeContentHash([]string{"203.0.113.0/24"}) + `"}`)
		gen, retired, err := verifyStoredGeneration(current)
		if err != nil {
			t.Fatalf("current bytes refused: %v", err)
		}
		if retired != 0 {
			t.Fatalf("retired domain count = %d, want 0 for a current-shape record", retired)
		}
		if len(gen.CIDRs) != 1 {
			t.Fatalf("loaded prefixes = %v, want 1", gen.CIDRs)
		}
	})

	t.Run("zero_version_still_refused", func(t *testing.T) {
		degraded := strings.Replace(string(predecessor), `"version": 7`, `"version": 0`, 1)
		if _, _, err := verifyStoredGeneration([]byte(degraded)); err == nil {
			t.Fatal("a generation with a zero version loaded")
		}
	})

	t.Run("wrong_schema_still_refused", func(t *testing.T) {
		degraded := strings.Replace(string(predecessor), `"schema_version": 1`, `"schema_version": 2`, 1)
		if _, _, err := verifyStoredGeneration([]byte(degraded)); err == nil {
			t.Fatal("a generation with an unsupported schema version loaded")
		}
	})
}

// The atomic-write contract, asserted on observable state rather than on which
// syscall returned which error: a commit either replaces the file completely, or
// leaves the previous recoverable copy exactly as it was. The long-lived cache
// directory and its file modes are part of that contract because they are what
// keeps a half-written or over-permissive policy file from being readable.
func TestFileStoreCommitWritesAtomicallyWithBoundedMode(t *testing.T) {
	base := t.TempDir()
	// A directory that does not exist yet: Commit is the entry point that creates
	// it, so a first-ever start writes no policy outside the intended mode.
	dir := filepath.Join(base, "policy")
	store := NewFileStore(dir)

	first := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  "gen-first",
		Version:       1,
		CIDRs:         []string{"198.51.100.0/24"},
	}
	if err := store.Commit(context.Background(), first); err != nil {
		t.Fatalf("first commit: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat the cache directory: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("cache directory mode = %o, want 0700", perm)
	}
	fileInfo, err := os.Stat(filepath.Join(dir, cacheFileName))
	if err != nil {
		t.Fatalf("stat the cache file: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("cache file mode = %o, want 0600", perm)
	}

	// A failed commit must not damage the previous copy. An empty directory path
	// component that cannot be created produces the failure; the durable file from
	// the successful commit above must still load.
	blocked := NewFileStore(filepath.Join(base, "not-a-directory", "policy"))
	if err := os.WriteFile(filepath.Join(base, "not-a-directory"), []byte("x"), 0600); err != nil {
		t.Fatalf("create the blocking file: %v", err)
	}
	replacement := &Generation{
		SchemaVersion: SchemaVersion,
		GenerationID:  "gen-blocked",
		Version:       2,
		CIDRs:         []string{"203.0.113.0/24"},
	}
	if err := blocked.Commit(context.Background(), replacement); err == nil {
		t.Fatal("Commit reported success into an unusable directory")
	}

	reloaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("the previous cache must survive a failed commit elsewhere: %v", err)
	}
	if reloaded.GenerationID != "gen-first" || len(reloaded.CIDRs) != 1 || reloaded.CIDRs[0] != "198.51.100.0/24" {
		t.Fatalf("previous cache changed after a failed commit: %+v", reloaded)
	}
}

// A replacement commit must leave no temporary file behind, so a cache directory
// does not accumulate orphaned candidate files across restarts.
func TestFileStoreCommitLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	for i, cidr := range []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"} {
		gen := &Generation{
			SchemaVersion: SchemaVersion,
			GenerationID:  fmt.Sprintf("gen-%d", i),
			Version:       uint64(i + 1),
			CIDRs:         []string{cidr},
		}
		if err := store.Commit(context.Background(), gen); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the cache directory: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !slices.Equal(names, []string{cacheFileName}) {
		t.Fatalf("cache directory holds %v, want only %q", names, cacheFileName)
	}
}

// The temp-file step fails closed when the cache directory is not there. The caller
// (writeAtomically) creates it first, so reaching this branch means the directory
// disappeared or could never be created — either way the commit must report the
// failure instead of returning a path to a file that does not exist, which the
// rename would then turn into a missing live policy.
func TestWriteDurableTempFileRefusesAMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	store := NewFileStore(dir)

	path, err := store.writeDurableTempFile([]byte("{}"))
	if err == nil {
		t.Fatalf("writeDurableTempFile succeeded into a directory that does not exist (path=%q)", path)
	}
	if path != "" {
		t.Fatalf("a failed temp write returned path %q, want none", path)
	}
	if !strings.Contains(err.Error(), "failed creating temp cache file") {
		t.Fatalf("failure = %v, want it to name the step that failed", err)
	}
	// Nothing may have been created on the way, so a retry after the directory
	// becomes usable starts from a clean directory.
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("the failed write left %q behind: %v", dir, statErr)
	}
}
