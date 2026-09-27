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
	"time"
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

		syncErr := errors.New("simulated I/O error syncing data directory")
		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == filepath.Clean(tmpDir) {
				return syncErr
			}
			return origSync(dirPath)
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

	mode := os.Getenv("HELPER_MODE")
	switch mode {
	case "process_a_fail_sync":
		cleanDataDir := filepath.Clean(dataDir)
		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == cleanDataDir {
				// Signal that Process A has placed the file and is paused in syncDir with the lock held
				markerSync := filepath.Join(dataDir, ".marker_a_in_sync")
				_ = os.WriteFile(markerSync, []byte("ready"), 0600)

				// Wait for release signal from test coordinator
				releaseMarker := filepath.Join(dataDir, ".marker_release_a")
				for attempt := 0; attempt < 500; attempt++ {
					if _, err := os.Stat(releaseMarker); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				return errors.New("simulated syncDir failure in Process A")
			}
			return syncDir(dirPath)
		}

	case "process_b_monitor":
		markerB := filepath.Join(dataDir, ".marker_b_started")
		_ = os.WriteFile(markerB, []byte("started"), 0600)

	case "process_b_fail_sync":
		markerB := filepath.Join(dataDir, ".marker_b_started")
		_ = os.WriteFile(markerB, []byte("started"), 0600)
		cleanDataDir := filepath.Clean(dataDir)
		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == cleanDataDir {
				return errors.New("simulated syncDir failure in Process B")
			}
			return syncDir(dirPath)
		}

	case "process_a_parent_fail_sync":
		parentDir := filepath.Clean(filepath.Dir(dataDir))
		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == parentDir {
				// Signal that Process A has created dataDir and reached parent syncDir
				markerSync := filepath.Join(parentDir, ".marker_a_in_parent_sync")
				_ = os.WriteFile(markerSync, []byte("ready"), 0600)

				// Wait for release signal from test coordinator
				releaseMarker := filepath.Join(parentDir, ".marker_release_parent_a")
				for attempt := 0; attempt < 500; attempt++ {
					if _, err := os.Stat(releaseMarker); err == nil {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				return errors.New("simulated parent sync failure in Process A")
			}
			return syncDir(dirPath)
		}

	case "process_b_parent_fail_sync":
		parentDir := filepath.Clean(filepath.Dir(dataDir))
		markerB := filepath.Join(parentDir, ".marker_b_parent_started")
		_ = os.WriteFile(markerB, []byte("started"), 0600)
		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == parentDir {
				return errors.New("simulated parent sync failure in Process B")
			}
			return syncDir(dirPath)
		}
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

// TestResolveSecretKey_Invariant8_PublishVsDirectorySyncRaceBarrier_MultiProcess tests Invariant 8:
// When Process A publishes a key and pauses inside syncDir, and Process B is spawned concurrently,
// if Process A receives a simulated syncDir error and deletes its unpersisted key, it is impossible
// for Process B to return success with an unpersisted/deleted key.
func TestResolveSecretKey_Invariant8_PublishVsDirectorySyncRaceBarrier_MultiProcess(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("ProcessBFailsOrGeneratesOwnPersistedKey", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Start Process A
		cmdA := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		var stdoutA, stderrA bytes.Buffer
		cmdA.Stdout = &stdoutA
		cmdA.Stderr = &stderrA
		envA := make([]string, 0, len(os.Environ())+3)
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "SECRET_KEY=") &&
				!strings.HasPrefix(e, "GO_WANT_SECRET_KEY_HELPER=") &&
				!strings.HasPrefix(e, "HELPER_DATA_DIR=") &&
				!strings.HasPrefix(e, "HELPER_MODE=") {
				envA = append(envA, e)
			}
		}
		cmdA.Env = append(envA,
			"GO_WANT_SECRET_KEY_HELPER=1",
			"HELPER_DATA_DIR="+tmpDir,
			"HELPER_MODE=process_a_fail_sync",
		)

		if err := cmdA.Start(); err != nil {
			t.Fatalf("failed to start Process A: %v", err)
		}

		// Wait for Process A to signal it is paused inside syncDir with the file placed
		markerSyncA := filepath.Join(tmpDir, ".marker_a_in_sync")
		syncReached := false
		for attempt := 0; attempt < 500; attempt++ {
			if _, err := os.Stat(markerSyncA); err == nil {
				syncReached = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !syncReached {
			_ = cmdA.Process.Kill()
			t.Fatalf("Process A failed to reach syncDir pause within timeout; stderr: %s", stderrA.String())
		}

		// Process A is now holding the process lock inside syncDir.
		// Spawn Process B concurrently.
		cmdB := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		var stdoutB, stderrB bytes.Buffer
		cmdB.Stdout = &stdoutB
		cmdB.Stderr = &stderrB
		envB := make([]string, 0, len(envA))
		envB = append(envB, envA...)
		envB = append(envB,
			"GO_WANT_SECRET_KEY_HELPER=1",
			"HELPER_DATA_DIR="+tmpDir,
			"HELPER_MODE=process_b_monitor",
		)
		cmdB.Env = envB

		if err := cmdB.Start(); err != nil {
			_ = cmdA.Process.Kill()
			t.Fatalf("failed to start Process B: %v", err)
		}

		// Wait for Process B to start and attempt ResolveSecretKey
		markerB := filepath.Join(tmpDir, ".marker_b_started")
		bStarted := false
		for attempt := 0; attempt < 500; attempt++ {
			if _, err := os.Stat(markerB); err == nil {
				bStarted = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !bStarted {
			_ = cmdA.Process.Kill()
			_ = cmdB.Process.Kill()
			t.Fatalf("Process B failed to start within timeout; stderr: %s", stderrB.String())
		}

		// Allow Process B a brief moment to be blocked waiting on .secret_key.lock
		time.Sleep(50 * time.Millisecond)

		// Release Process A, causing it to return the simulated syncDir error
		releaseMarker := filepath.Join(tmpDir, ".marker_release_a")
		if err := os.WriteFile(releaseMarker, []byte("release"), 0600); err != nil {
			_ = cmdA.Process.Kill()
			_ = cmdB.Process.Kill()
			t.Fatalf("failed to write release marker: %v", err)
		}

		// Wait for Process A to exit. It MUST fail because its syncDir returned an error.
		errA := cmdA.Wait()
		if errA == nil {
			t.Fatalf("Process A was expected to fail with sync error, but exited successfully")
		}
		if !strings.Contains(stderrA.String(), "failed to sync data directory") {
			t.Errorf("Process A stderr expected to mention 'failed to sync data directory', got: %s", stderrA.String())
		}

		// Wait for Process B to complete
		errB := cmdB.Wait()
		keyB := strings.TrimSpace(stdoutB.String())

		keyPath := filepath.Join(tmpDir, ".secret_key")
		diskData, readErr := os.ReadFile(keyPath)

		if errB != nil {
			// If Process B also failed (e.g. could not obtain key or sync), verify no phantom key exists
			if readErr == nil && len(diskData) > 0 {
				t.Errorf("Process B failed, but a key was left on disk: %q", string(diskData))
			}
		} else {
			// If Process B succeeded:
			// 1. It must have produced a valid 64-char key
			if len(keyB) != 64 {
				t.Fatalf("Process B produced invalid key len=%d: %q", len(keyB), keyB)
			}
			// 2. The key file MUST exist on disk! It must NOT be deleted or disappeared!
			if readErr != nil {
				t.Fatalf("CRITICAL RACE: Process B returned success (%s) but .secret_key is missing on disk (%v)!", keyB, readErr)
			}
			// 3. The disk content must strictly match Process B's returned key
			if strings.TrimSpace(string(diskData)) != keyB {
				t.Fatalf("CRITICAL RACE: Process B returned key %s, but disk contains different key %s!", keyB, strings.TrimSpace(string(diskData)))
			}
			// 4. Verify file permissions 0600
			fi, statErr := os.Stat(keyPath)
			if statErr != nil {
				t.Fatalf("failed to stat key file: %v", statErr)
			}
			if fi.Mode().Perm() != 0600 {
				t.Errorf("expected 0600 permissions, got: %04o", fi.Mode().Perm())
			}
		}
	})

	t.Run("BothProcessesFailSync", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Start Process A
		cmdA := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		var stdoutA, stderrA bytes.Buffer
		cmdA.Stdout = &stdoutA
		cmdA.Stderr = &stderrA
		envA := make([]string, 0, len(os.Environ())+3)
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "SECRET_KEY=") &&
				!strings.HasPrefix(e, "GO_WANT_SECRET_KEY_HELPER=") &&
				!strings.HasPrefix(e, "HELPER_DATA_DIR=") &&
				!strings.HasPrefix(e, "HELPER_MODE=") {
				envA = append(envA, e)
			}
		}
		cmdA.Env = append(envA,
			"GO_WANT_SECRET_KEY_HELPER=1",
			"HELPER_DATA_DIR="+tmpDir,
			"HELPER_MODE=process_a_fail_sync",
		)

		if err := cmdA.Start(); err != nil {
			t.Fatalf("failed to start Process A: %v", err)
		}

		// Wait for Process A to signal it is paused inside syncDir
		markerSyncA := filepath.Join(tmpDir, ".marker_a_in_sync")
		syncReached := false
		for attempt := 0; attempt < 500; attempt++ {
			if _, err := os.Stat(markerSyncA); err == nil {
				syncReached = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !syncReached {
			_ = cmdA.Process.Kill()
			t.Fatalf("Process A failed to reach syncDir pause within timeout; stderr: %s", stderrA.String())
		}

		// Spawn Process B with fail_sync
		cmdB := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		var stdoutB, stderrB bytes.Buffer
		cmdB.Stdout = &stdoutB
		cmdB.Stderr = &stderrB
		envB := make([]string, 0, len(envA))
		envB = append(envB, envA...)
		envB = append(envB,
			"GO_WANT_SECRET_KEY_HELPER=1",
			"HELPER_DATA_DIR="+tmpDir,
			"HELPER_MODE=process_b_fail_sync",
		)
		cmdB.Env = envB

		if err := cmdB.Start(); err != nil {
			_ = cmdA.Process.Kill()
			t.Fatalf("failed to start Process B: %v", err)
		}

		markerB := filepath.Join(tmpDir, ".marker_b_started")
		bStarted := false
		for attempt := 0; attempt < 500; attempt++ {
			if _, err := os.Stat(markerB); err == nil {
				bStarted = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !bStarted {
			_ = cmdA.Process.Kill()
			_ = cmdB.Process.Kill()
			t.Fatalf("Process B failed to start within timeout; stderr: %s", stderrB.String())
		}

		time.Sleep(50 * time.Millisecond)

		releaseMarker := filepath.Join(tmpDir, ".marker_release_a")
		if err := os.WriteFile(releaseMarker, []byte("release"), 0600); err != nil {
			_ = cmdA.Process.Kill()
			_ = cmdB.Process.Kill()
			t.Fatalf("failed to write release marker: %v", err)
		}

		_ = cmdA.Wait()
		errB := cmdB.Wait()

		if errB == nil {
			t.Fatalf("expected Process B to fail when syncDir fails, but it succeeded: %s", stdoutB.String())
		}

		// Verify no unpersisted key file remains on disk
		keyPath := filepath.Join(tmpDir, ".secret_key")
		if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
			t.Errorf("expected .secret_key to not exist on disk after both failed, statErr: %v", statErr)
		}
	})
}

// TestResolveSecretKey_Invariant8_ReaderDurabilityBarrier verifies that any reader path
// (initial read of existing key and readWinningKey) enforces directory durability
// and fails fast if syncDir fails, without deleting the pre-existing file.
func TestResolveSecretKey_Invariant8_ReaderDurabilityBarrier(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("ExistingKeyReadSyncFailure", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		existingKey := "99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff"
		if err := os.WriteFile(keyPath, []byte(existingKey+"\n"), 0600); err != nil {
			t.Fatalf("failed to write existing key: %v", err)
		}

		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == filepath.Clean(tmpDir) {
				return errors.New("simulated syncDir failure during reader check")
			}
			return origSync(dirPath)
		}

		key, err := ResolveSecretKey(tmpDir)
		if err == nil {
			t.Fatalf("expected error when syncDir fails on existing key read, got key: %q", key)
		}
		if !strings.Contains(err.Error(), "failed to sync data directory") {
			t.Errorf("expected error message to mention 'failed to sync data directory', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Crucial: pre-existing file must NOT be deleted by a reader
		data, readErr := os.ReadFile(keyPath)
		if readErr != nil {
			t.Fatalf("pre-existing key file was deleted or unreadable: %v", readErr)
		}
		if strings.TrimSpace(string(data)) != existingKey {
			t.Errorf("pre-existing key content altered: %q vs %q", strings.TrimSpace(string(data)), existingKey)
		}
	})

	t.Run("ReadWinningKeySyncFailure", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, ".secret_key")
		winningKey := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		if err := os.WriteFile(keyPath, []byte(winningKey+"\n"), 0600); err != nil {
			t.Fatalf("failed to write winning key: %v", err)
		}

		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncDirFunc = func(dirPath string) error {
			return errors.New("simulated syncDir failure in readWinningKey")
		}

		key, err := readWinningKey(keyPath)
		if err == nil {
			t.Fatalf("expected readWinningKey to fail when syncDir fails, got key: %q", key)
		}
		if !strings.Contains(err.Error(), "failed to sync data directory") {
			t.Errorf("expected error message to mention 'failed to sync data directory', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}
	})
}

// TestResolveSecretKey_Invariant9_ParentDirectoryDurabilityOnDataDirCreation tests Invariant 9:
// Parent directory of DATA_DIR is unconditionally synchronized for all callers to prevent
// the directory entry from disappearing under crash/power loss, even under concurrent startup.
func TestResolveSecretKey_Invariant9_ParentDirectoryDurabilityOnDataDirCreation(t *testing.T) {
	os.Unsetenv("SECRET_KEY")

	t.Run("ParentDirectorySyncedWhenDataDirCreated", func(t *testing.T) {
		parentDir := t.TempDir()
		newDataDir := filepath.Join(parentDir, "brand_new_datadir")

		var syncedDirs []string
		var mu sync.Mutex
		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncDirFunc = func(dirPath string) error {
			mu.Lock()
			syncedDirs = append(syncedDirs, filepath.Clean(dirPath))
			mu.Unlock()
			return origSync(dirPath)
		}

		key, err := ResolveSecretKey(newDataDir)
		if err != nil {
			t.Fatalf("ResolveSecretKey failed: %v", err)
		}
		if len(key) != 64 {
			t.Errorf("expected 64-char key, got %d: %q", len(key), key)
		}

		mu.Lock()
		defer mu.Unlock()

		hasParent := false
		hasData := false
		for _, d := range syncedDirs {
			if d == filepath.Clean(parentDir) {
				hasParent = true
			}
			if d == filepath.Clean(newDataDir) {
				hasData = true
			}
		}

		if !hasParent {
			t.Errorf("parent directory %s was not synced on creation; synced dirs: %v", parentDir, syncedDirs)
		}
		if !hasData {
			t.Errorf("new data directory %s was not synced; synced dirs: %v", newDataDir, syncedDirs)
		}
	})

	t.Run("ParentDirectorySyncFailureFailsFast", func(t *testing.T) {
		parentDir := t.TempDir()
		newDataDir := filepath.Join(parentDir, "fail_parent_datadir")

		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == filepath.Clean(parentDir) {
				return errors.New("simulated parent directory sync failure")
			}
			return origSync(dirPath)
		}

		key, err := ResolveSecretKey(newDataDir)
		if err == nil {
			t.Fatalf("expected error when parent directory sync fails, got key: %q", key)
		}
		if !strings.Contains(err.Error(), "failed to sync parent directory") {
			t.Errorf("expected error message to mention 'failed to sync parent directory', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}

		// Verify key was not created
		keyPath := filepath.Join(newDataDir, ".secret_key")
		if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
			t.Errorf("secret key file should not exist, statErr: %v", statErr)
		}
	})

	t.Run("ParentDirectorySyncedEvenWhenDataDirAlreadyExists", func(t *testing.T) {
		dataDir := t.TempDir() // already exists

		var syncedDirs []string
		var mu sync.Mutex
		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncDirFunc = func(dirPath string) error {
			mu.Lock()
			syncedDirs = append(syncedDirs, filepath.Clean(dirPath))
			mu.Unlock()
			return origSync(dirPath)
		}

		key, err := ResolveSecretKey(dataDir)
		if err != nil {
			t.Fatalf("ResolveSecretKey failed: %v", err)
		}
		if len(key) != 64 {
			t.Errorf("expected 64-char key, got: %q", key)
		}

		mu.Lock()
		defer mu.Unlock()

		parentOfDataDir := filepath.Clean(filepath.Dir(dataDir))
		foundParent := false
		for _, d := range syncedDirs {
			if d == parentOfDataDir {
				foundParent = true
				break
			}
		}
		if !foundParent {
			t.Errorf("parent directory %s should have been unconditionally synced even when dataDir already existed; synced dirs: %v", parentOfDataDir, syncedDirs)
		}
	})

	t.Run("ParentDirectorySyncFailureFailsFastWhenDataDirAlreadyExists", func(t *testing.T) {
		dataDir := t.TempDir() // already exists
		parentDir := filepath.Dir(dataDir)

		origSync := syncDirFunc
		defer func() { syncDirFunc = origSync }()

		syncDirFunc = func(dirPath string) error {
			if filepath.Clean(dirPath) == filepath.Clean(parentDir) {
				return errors.New("simulated parent directory sync failure on existing data dir")
			}
			return origSync(dirPath)
		}

		key, err := ResolveSecretKey(dataDir)
		if err == nil {
			t.Fatalf("expected error when parent directory sync fails, got key: %q", key)
		}
		if !strings.Contains(err.Error(), "failed to sync parent directory") {
			t.Errorf("expected error message to mention 'failed to sync parent directory', got: %v", err)
		}
		if key != "" {
			t.Errorf("expected empty key on failure, got: %q", key)
		}
	})

	t.Run("ConcurrentStartupCannotBypassParentDurabilityOnFailure", func(t *testing.T) {
		parentDir := t.TempDir()
		dataDir := filepath.Join(parentDir, "concurrent_datadir")

		// Start Process A
		cmdA := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		var stdoutA, stderrA bytes.Buffer
		cmdA.Stdout = &stdoutA
		cmdA.Stderr = &stderrA
		envA := make([]string, 0, len(os.Environ())+3)
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "SECRET_KEY=") &&
				!strings.HasPrefix(e, "GO_WANT_SECRET_KEY_HELPER=") &&
				!strings.HasPrefix(e, "HELPER_DATA_DIR=") &&
				!strings.HasPrefix(e, "HELPER_MODE=") {
				envA = append(envA, e)
			}
		}
		cmdA.Env = append(envA,
			"GO_WANT_SECRET_KEY_HELPER=1",
			"HELPER_DATA_DIR="+dataDir,
			"HELPER_MODE=process_a_parent_fail_sync",
		)

		if err := cmdA.Start(); err != nil {
			t.Fatalf("failed to start Process A: %v", err)
		}

		// Wait for Process A to signal it is paused inside parent syncDir
		// Note: at this point, Process A has executed MkdirAll(dataDir), so dataDir exists on disk.
		markerSyncA := filepath.Join(parentDir, ".marker_a_in_parent_sync")
		syncReached := false
		for attempt := 0; attempt < 500; attempt++ {
			if _, err := os.Stat(markerSyncA); err == nil {
				syncReached = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !syncReached {
			_ = cmdA.Process.Kill()
			t.Fatalf("Process A failed to reach parent syncDir pause within timeout; stderr: %s", stderrA.String())
		}

		// Verify dataDir was created by Process A
		if _, statErr := os.Stat(dataDir); statErr != nil {
			_ = cmdA.Process.Kill()
			t.Fatalf("expected dataDir to exist after Process A MkdirAll: %v", statErr)
		}

		// Spawn Process B concurrently with parent sync failure simulation
		cmdB := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
		var stdoutB, stderrB bytes.Buffer
		cmdB.Stdout = &stdoutB
		cmdB.Stderr = &stderrB
		envB := make([]string, 0, len(envA))
		envB = append(envB, envA...)
		envB = append(envB,
			"GO_WANT_SECRET_KEY_HELPER=1",
			"HELPER_DATA_DIR="+dataDir,
			"HELPER_MODE=process_b_parent_fail_sync",
		)
		cmdB.Env = envB

		if err := cmdB.Start(); err != nil {
			_ = cmdA.Process.Kill()
			t.Fatalf("failed to start Process B: %v", err)
		}

		markerB := filepath.Join(parentDir, ".marker_b_parent_started")
		bStarted := false
		for attempt := 0; attempt < 500; attempt++ {
			if _, err := os.Stat(markerB); err == nil {
				bStarted = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !bStarted {
			_ = cmdA.Process.Kill()
			_ = cmdB.Process.Kill()
			t.Fatalf("Process B failed to start within timeout; stderr: %s", stderrB.String())
		}

		// Release Process A
		releaseMarker := filepath.Join(parentDir, ".marker_release_parent_a")
		if err := os.WriteFile(releaseMarker, []byte("release"), 0600); err != nil {
			_ = cmdA.Process.Kill()
			_ = cmdB.Process.Kill()
			t.Fatalf("failed to write release marker: %v", err)
		}

		errA := cmdA.Wait()
		errB := cmdB.Wait()

		// Both processes MUST fail because parent sync failed.
		// In particular, Process B MUST NOT bypass parent durability even though dataDir already existed!
		if errA == nil {
			t.Fatalf("Process A was expected to fail on parent sync, but exited successfully")
		}
		if !strings.Contains(stderrA.String(), "failed to sync parent directory") {
			t.Errorf("Process A stderr expected to mention 'failed to sync parent directory', got: %s", stderrA.String())
		}

		if errB == nil {
			t.Fatalf("REGRESSION: Process B bypassed parent durability and succeeded! key=%s", stdoutB.String())
		}
		if !strings.Contains(stderrB.String(), "failed to sync parent directory") {
			t.Errorf("Process B stderr expected to mention 'failed to sync parent directory', got: %s", stderrB.String())
		}

		// Verify no secret key was created on disk
		keyPath := filepath.Join(dataDir, ".secret_key")
		if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
			t.Errorf("expected .secret_key to not exist on disk after both failed, statErr: %v", statErr)
		}
	})
}
