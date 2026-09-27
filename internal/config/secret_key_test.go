package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// TestResolveSecretKey_Invariant1_FailedWriteReturnsError tests Invariant 1:
// Failed key-file creation/write returns an error from ResolveSecretKey; process fails fast.
func TestResolveSecretKey_Invariant1_FailedWriteReturnsError(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("ReadOnlyDir", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("skipping read-only directory test as root")
		}
		tmpDir := t.TempDir()
		if err := os.Chmod(tmpDir, 0500); err != nil {
			t.Fatalf("failed to chmod tmpDir: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(tmpDir, 0700)
		})

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error when data dir is read-only, got key: %q", key)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Also verify LoadConfig fails fast
		os.Setenv("DATA_DIR", tmpDir)
		defer os.Unsetenv("DATA_DIR")
		cfg, loadErr := LoadConfig()
		if loadErr == nil {
			t.Fatalf("expected LoadConfig to fail on unwritable data dir, got cfg: %+v", cfg)
		}
	})

	t.Run("DataDirIsFile", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "datadir-file-*")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		filePath := tmpFile.Name()
		_ = tmpFile.Close()
		defer func() { _ = os.Remove(filePath) }()

		key, err := ResolveSecretKey(filePath)
		if err == nil {
			t.Fatalf("expected error when data dir is a regular file, got key: %q", key)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		os.Setenv("DATA_DIR", filePath)
		defer os.Unsetenv("DATA_DIR")
		cfg, loadErr := LoadConfig()
		if loadErr == nil {
			t.Fatalf("expected LoadConfig to fail when data dir is a file, got: %+v", cfg)
		}
	})
}

// TestResolveSecretKey_Invariant2_ExistingUnreadableKeyFileReturnsError tests Invariant 2:
// Existing unreadable key file (e.g., permission denied) returns an error; does not regenerate or overwrite.
func TestResolveSecretKey_Invariant2_ExistingUnreadableKeyFileReturnsError(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("PermissionDenied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("skipping 0000 permission test as root")
		}
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		originalKey := "unreadable-key-1234567890abcdef1234567890abcdef"
		if err := os.WriteFile(keyPath, []byte(originalKey), 0600); err != nil {
			t.Fatalf("failed to write original key: %v", err)
		}

		if err := os.Chmod(keyPath, 0000); err != nil {
			t.Fatalf("failed to chmod 0000: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Chmod(keyPath, 0600)
		})

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error for unreadable key file, got key: %q", key)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Restore read permissions to verify original file was not overwritten
		if err := os.Chmod(keyPath, 0600); err != nil {
			t.Fatalf("failed to restore chmod: %v", err)
		}
		data, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("failed to read key file after test: %v", err)
		}
		if string(data) != originalKey {
			t.Errorf("expected file to remain untouched, got: %q", string(data))
		}
	})

	t.Run("KeyPathIsDirectory", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		if err := os.Mkdir(keyPath, 0755); err != nil {
			t.Fatalf("failed to create directory at key path: %v", err)
		}

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error when key path is a directory, got key: %q", key)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}
	})
}

// TestResolveSecretKey_Invariant3_ExistingEmptyOrWhitespaceKeyFileReturnsError tests Invariant 3:
// Existing empty or whitespace-only key file returns an error; does not silently regenerate.
func TestResolveSecretKey_Invariant3_ExistingEmptyOrWhitespaceKeyFileReturnsError(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("EmptyFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		if err := os.WriteFile(keyPath, []byte(""), 0600); err != nil {
			t.Fatalf("failed to write empty key file: %v", err)
		}

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error for empty key file, got: %q", key)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error message to mention 'empty', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Verify file was NOT overwritten with a generated key
		data, readErr := os.ReadFile(keyPath)
		if readErr != nil {
			t.Fatalf("failed to read key file: %v", readErr)
		}
		if len(data) != 0 {
			t.Errorf("expected key file to remain empty, got %d bytes: %q", len(data), string(data))
		}
	})

	t.Run("WhitespaceOnlyFile", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		whitespaceContent := "  \t \r\n  \n\t "
		if err := os.WriteFile(keyPath, []byte(whitespaceContent), 0600); err != nil {
			t.Fatalf("failed to write whitespace key file: %v", err)
		}

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error for whitespace-only key file, got: %q", key)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected error message to mention 'empty', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Verify file was NOT overwritten
		data, readErr := os.ReadFile(keyPath)
		if readErr != nil {
			t.Fatalf("failed to read key file: %v", readErr)
		}
		if string(data) != whitespaceContent {
			t.Errorf("expected key file to remain unchanged, got: %q", string(data))
		}
	})
}

// TestResolveSecretKey_Invariant4_FirstBootAtomic0600Permissions tests Invariant 4:
// First-boot key generation creates the file atomically with 0600 permissions.
func TestResolveSecretKey_Invariant4_FirstBootAtomic0600Permissions(t *testing.T) {
	os.Unsetenv("SECRET_KEY")
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, ".secret_key")

	key, err := ResolveSecretKey(tmpDir)
	if err != nil {
		t.Fatalf("ResolveSecretKey failed: %v", err)
	}

	if len(key) != 64 {
		t.Errorf("expected 64-character hex key, got len=%d: %q", len(key), key)
	}

	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected key file to exist at %s: %v", keyPath, err)
	}

	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permissions 0600, got: %04o", perm)
	}

	// Verify content matches returned key
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	if strings.TrimSpace(string(data)) != key {
		t.Errorf("file content %q does not match returned key %q", strings.TrimSpace(string(data)), key)
	}

	// Verify no temporary files remain in data dir
	matches, err := filepath.Glob(filepath.Join(tmpDir, ".secret_key.tmp.*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("expected no leftover temp files, found: %v", matches)
	}
}

// TestResolveSecretKey_Invariant5_CleanRestartLoadsPersistedKey tests Invariant 5:
// Clean restart loads the persisted key without re-generation or modification.
func TestResolveSecretKey_Invariant5_CleanRestartLoadsPersistedKey(t *testing.T) {
	os.Unsetenv("SECRET_KEY")
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, ".secret_key")
	expectedKey := "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

	if err := os.WriteFile(keyPath, []byte(expectedKey+"\n"), 0600); err != nil {
		t.Fatalf("failed to write initial key: %v", err)
	}

	statBefore, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}

	for i := 1; i <= 3; i++ {
		key, err := ResolveSecretKey(tmpDir)
		if err != nil {
			t.Fatalf("iteration %d: ResolveSecretKey failed: %v", i, err)
		}
		if key != expectedKey {
			t.Errorf("iteration %d: expected key %q, got %q", i, expectedKey, key)
		}
	}

	statAfter, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file after reads: %v", err)
	}

	// Content must remain identical
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	if string(data) != expectedKey+"\n" {
		t.Errorf("file was modified: got %q, want %q", string(data), expectedKey+"\n")
	}

	if !statBefore.ModTime().Equal(statAfter.ModTime()) {
		t.Errorf("file modification time changed: was %v, now %v", statBefore.ModTime(), statAfter.ModTime())
	}
}

// TestResolveSecretKey_EnvPrecedence tests that SECRET_KEY env var takes precedence
// even when an empty, unreadable, or missing key file exists.
func TestResolveSecretKey_EnvPrecedence(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, ".secret_key")
	// Put an empty key file that would normally error
	if err := os.WriteFile(keyPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write empty key file: %v", err)
	}

	envKey := "env-secret-key-abcdef1234567890abcdef1234567890"
	os.Setenv("SECRET_KEY", envKey)
	defer os.Unsetenv("SECRET_KEY")

	key, err := ResolveSecretKey(tmpDir)
	if err != nil {
		t.Fatalf("expected env key to take precedence, got error: %v", err)
	}
	if key != envKey {
		t.Errorf("expected %q, got %q", envKey, key)
	}
}

// TestResolveSecretKey_ConcurrentFirstBoot tests concurrent startup safety.
func TestResolveSecretKey_ConcurrentFirstBoot(t *testing.T) {
	os.Unsetenv("SECRET_KEY")
	tmpDir := t.TempDir()

	const concurrency = 20
	keys := make([]string, concurrency)
	errs := make([]error, concurrency)

	var wg sync.WaitGroup
	wg.Add(concurrency)
	barrier := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-barrier
			keys[idx], errs[idx] = ResolveSecretKey(tmpDir)
		}()
	}

	close(barrier)
	wg.Wait()

	for i := 0; i < concurrency; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d failed: %v", i, errs[i])
		}
		if keys[i] != keys[0] {
			t.Errorf("goroutine %d returned different key %q vs %q", i, keys[i], keys[0])
		}
	}

	if len(keys[0]) != 64 {
		t.Errorf("expected 64-char key, got len=%d: %q", len(keys[0]), keys[0])
	}

	// Verify file permissions
	keyPath := filepath.Join(tmpDir, ".secret_key")
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got: %04o", fi.Mode().Perm())
	}

	// Verify no leftover temp files
	matches, err := filepath.Glob(filepath.Join(tmpDir, ".secret_key.tmp.*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("leftover temp files found: %v", matches)
	}
}

// TestResolveSecretKey_Invariant6_DirectoryDurability tests Invariant 6:
// Parent directory is durably synchronized (dir.Sync()) before returning success,
// and returns an error if directory sync fails.
func TestResolveSecretKey_Invariant6_DirectoryDurability(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("NormalDurabilitySync", func(t *testing.T) {
		tmpDir := t.TempDir()
		key, err := ResolveSecretKey(tmpDir)
		if err != nil {
			t.Fatalf("expected ResolveSecretKey to succeed with directory sync, got: %v", err)
		}
		if len(key) != 64 {
			t.Errorf("unexpected key length %d: %q", len(key), key)
		}
	})

	t.Run("DirectorySyncFailureReturnsError", func(t *testing.T) {
		tmpDir := t.TempDir()
		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncErr := errors.New("simulated I/O error syncing parent directory")
		syncDirFunc = func(dirPath string) error {
			return syncErr
		}

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error when directory sync fails, got key: %q", key)
		}
		if !strings.Contains(err.Error(), "failed to sync data directory") {
			t.Errorf("expected error message to mention 'failed to sync data directory', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Verify un-persisted key file was cleaned up and not left behind
		keyPath := filepath.Join(tmpDir, ".secret_key")
		if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
			t.Errorf("expected key file to not exist after sync failure, statErr: %v", statErr)
		}
	})
}

// TestResolveSecretKey_FallbackNoHardLinks tests the fallback behavior when hard links
// are not supported on the underlying filesystem.
func TestResolveSecretKey_FallbackNoHardLinks(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("SuccessViaRenameNoReplace", func(t *testing.T) {
		tmpDir := t.TempDir()
		origLink := linkFile
		defer func() { linkFile = origLink }()

		linkFile = func(oldname, newname string) error {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
		}

		key, err := ResolveSecretKey(tmpDir)
		if err != nil {
			t.Fatalf("expected success via renameNoReplace, got: %v", err)
		}
		if len(key) != 64 {
			t.Errorf("expected 64-char key, got %d: %q", len(key), key)
		}

		keyPath := filepath.Join(tmpDir, ".secret_key")
		fi, statErr := os.Stat(keyPath)
		if statErr != nil {
			t.Fatalf("stat failed: %v", statErr)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("expected 0600, got: %04o", fi.Mode().Perm())
		}
	})

	t.Run("TargetAlreadyExistsDuringFallback", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		winningKey := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
		if err := os.WriteFile(keyPath, []byte(winningKey+"\n"), 0600); err != nil {
			t.Fatalf("failed to write key file: %v", err)
		}

		readKey, readErr := readWinningKey(keyPath)
		if readErr != nil {
			t.Fatalf("readWinningKey failed: %v", readErr)
		}
		if readKey != winningKey {
			t.Errorf("expected winning key %q, got %q", winningKey, readKey)
		}
	})

	t.Run("FailClosedWhenNoReplaceUnsupported", func(t *testing.T) {
		tmpDir := t.TempDir()
		origLink := linkFile
		origRename := renameNoReplaceFunc
		defer func() {
			linkFile = origLink
			renameNoReplaceFunc = origRename
		}()

		linkFile = func(oldname, newname string) error {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
		}
		renameNoReplaceFunc = func(src, dst string) error {
			return errors.ErrUnsupported
		}

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected fail-closed error, got key: %q", key)
		}
		if !strings.Contains(err.Error(), "without clobbering") {
			t.Errorf("expected error message to mention 'without clobbering', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}
	})
}

// TestHelperProcess provides the entrypoint for child processes spawned during
// multi-process regression testing of ResolveSecretKey.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SECRET_KEY_HELPER") != "1" {
		return
	}
	dataDir := os.Getenv("HELPER_DATA_DIR")
	if dataDir == "" {
		fmt.Fprintln(os.Stderr, "HELPER_DATA_DIR not set")
		os.Exit(2)
	}

	key, err := ResolveSecretKey(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(key)
	os.Exit(0)
}

func runConcurrentSubprocessTest(t *testing.T, extraEnv ...string) {
	os.Unsetenv("SECRET_KEY")
	tmpDir := t.TempDir()

	const numProcs = 10
	type procResult struct {
		key string
		err error
	}
	results := make([]procResult, numProcs)
	var wg sync.WaitGroup
	wg.Add(numProcs)

	barrier := make(chan struct{})

	for i := 0; i < numProcs; i++ {
		idx := i
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			env := make([]string, 0, len(os.Environ())+len(extraEnv)+2)
			for _, e := range os.Environ() {
				if !strings.HasPrefix(e, "SECRET_KEY=") &&
					!strings.HasPrefix(e, "GO_WANT_SECRET_KEY_HELPER=") &&
					!strings.HasPrefix(e, "HELPER_DATA_DIR=") {
					env = append(env, e)
				}
			}
			env = append(env, "GO_WANT_SECRET_KEY_HELPER=1", "HELPER_DATA_DIR="+tmpDir)
			env = append(env, extraEnv...)
			cmd.Env = env

			<-barrier // Synchronize start of all child processes
			err := cmd.Run()
			if err != nil {
				results[idx] = procResult{err: fmt.Errorf("subprocess %d failed (%w): %s", idx, err, stderr.String())}
				return
			}
			results[idx] = procResult{key: strings.TrimSpace(stdout.String())}
		}()
	}

	close(barrier)
	wg.Wait()

	for i := 0; i < numProcs; i++ {
		if results[i].err != nil {
			t.Fatalf("subprocess %d error: %v", i, results[i].err)
		}
		if results[i].key != results[0].key {
			t.Errorf("subprocess %d produced key %q, but subprocess 0 produced %q", i, results[i].key, results[0].key)
		}
	}

	if len(results[0].key) != 64 {
		t.Errorf("expected 64-character hex key, got len=%d: %q", len(results[0].key), results[0].key)
	}

	keyPath := filepath.Join(tmpDir, ".secret_key")
	diskData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read persisted key file: %v", err)
	}
	if strings.TrimSpace(string(diskData)) != results[0].key {
		t.Errorf("disk key %q does not match subprocess key %q", strings.TrimSpace(string(diskData)), results[0].key)
	}

	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat failed on key file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected file mode 0600, got: %04o", fi.Mode().Perm())
	}

	matches, err := filepath.Glob(filepath.Join(tmpDir, ".secret_key.tmp.*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) > 0 {
		t.Errorf("leftover temporary files found: %v", matches)
	}
}

// TestResolveSecretKey_Invariant7_ConcurrentSubprocessesConverge_HardLinks tests Invariant 7:
// Concurrent startup across multiple separate OS processes converges on a single persisted key;
// no process overwrites another's key (standard hard link atomic placement).
func TestResolveSecretKey_Invariant7_ConcurrentSubprocessesConverge_HardLinks(t *testing.T) {
	runConcurrentSubprocessTest(t)
}

// TestResolveSecretKey_Invariant7_ConcurrentSubprocessesConverge_NoHardLinksFallback tests Invariant 7:
// Concurrent startup across multiple separate OS processes converges on a single persisted key
// even when hard links are unsupported and the fallback to renameat2(RENAME_NOREPLACE) is used.
func TestResolveSecretKey_Invariant7_ConcurrentSubprocessesConverge_NoHardLinksFallback(t *testing.T) {
	runConcurrentSubprocessTest(t, "AMNEZIA_TEST_SIMULATE_NO_HARDLINKS=1")
}
