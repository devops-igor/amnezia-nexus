package awg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemoteLock_SuccessorLockTOCTOU_PreservesSuccessor(t *testing.T) {
	ctx := context.Background()

	// 1. Verify that remoteLockAcquireCmd contains the successor TOCTOU verification and rollback logic
	cmdStr := remoteLockAcquireCmd("test_resource", "test_token")
	expectedTokens := []string{
		`if [ "$(cat "$flock_path/owner" 2>/dev/null)" = "$stale_token" ]; then if mv "$flock_path" "$flock_path.stale.$now.$$" 2>/dev/null; then if [ "$(cat "$flock_path.stale.$now.$$/owner" 2>/dev/null)" = "$stale_token" ]; then rm -rf "$flock_path.stale.$now.$$"; else mv "$flock_path.stale.$now.$$" "$flock_path" 2>/dev/null; fi; fi; fi`,
		`elif [ ! -s "$flock_path/owner" ] || [ -z "$stale_token" ]; then if mv "$flock_path" "$flock_path.ownerless.$now.$$" 2>/dev/null; then if [ ! -s "$flock_path.ownerless.$now.$$/owner" ]; then rm -rf "$flock_path.ownerless.$now.$$"; else mv "$flock_path.ownerless.$now.$$" "$flock_path" 2>/dev/null; fi; fi; fi`,
	}
	for _, expected := range expectedTokens {
		if !strings.Contains(cmdStr, expected) {
			t.Fatalf("remoteLockAcquireCmd missing expected TOCTOU protection snippet:\nExpected: %s\nGot cmd: %s", expected, cmdStr)
		}
	}

	// 2. Functional test: Existing owner token mismatch rolls back and preserves successor
	t.Run("ExistingOwner_SuccessorTokenMismatch_RollsBackAndPreservesSuccessor", func(t *testing.T) {
		tempDir := t.TempDir()
		flockPath := filepath.Join(tempDir, "test.lock")
		staleToken := "stale-owner-token"
		successorToken := "successor-owner-token"

		// Simulate state where flock_path was renamed to flock_path.stale.$now.$$,
		// but inside the renamed directory, the owner belongs to a successor.
		now := time.Now().Unix()
		pid := os.Getpid()
		staleRenamedDir := fmt.Sprintf("%s.stale.%d.%d", flockPath, now, pid)

		if err := os.MkdirAll(staleRenamedDir, 0755); err != nil {
			t.Fatalf("failed to create simulated stale directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(staleRenamedDir, "owner"), []byte(successorToken+"\n"), 0644); err != nil {
			t.Fatalf("failed to write successor owner file: %v", err)
		}

		// Execute TOCTOU verification block
		shCmd := fmt.Sprintf(
			`flock_path="%s"; stale_token="%s"; now="%d"; if [ "$(cat "$flock_path.stale.%d.%d/owner" 2>/dev/null)" = "$stale_token" ]; then rm -rf "$flock_path.stale.%d.%d"; else mv "$flock_path.stale.%d.%d" "$flock_path" 2>/dev/null; fi`,
			flockPath, staleToken, now, now, pid, now, pid, now, pid,
		)
		out, err := exec.CommandContext(ctx, "bash", "-c", shCmd).CombinedOutput()
		if err != nil {
			t.Fatalf("failed executing shell TOCTOU block: %v (out: %s)", err, string(out))
		}

		// Successor lock directory must be preserved at flockPath
		if _, err := os.Stat(flockPath); os.IsNotExist(err) {
			t.Fatalf("successor lock directory was not restored after token mismatch!")
		}

		// Owner must still be successorToken
		ownerBytes, err := os.ReadFile(filepath.Join(flockPath, "owner"))
		if err != nil {
			t.Fatalf("failed to read restored owner file: %v", err)
		}
		if strings.TrimSpace(string(ownerBytes)) != successorToken {
			t.Fatalf("expected restored owner %s, got: %s", successorToken, strings.TrimSpace(string(ownerBytes)))
		}

		// Renamed directory must no longer exist
		if _, err := os.Stat(staleRenamedDir); !os.IsNotExist(err) {
			t.Fatalf("stale renamed directory still exists after restore!")
		}
	})

	// 3. Functional test: Ownerless directory where owner appears rolls back and preserves successor
	t.Run("OwnerlessStale_SuccessorWritesOwner_RollsBackAndPreservesSuccessor", func(t *testing.T) {
		tempDir := t.TempDir()
		flockPath := filepath.Join(tempDir, "test.lock")
		successorToken := "successor-ownerless-token"

		now := time.Now().Unix()
		pid := os.Getpid()
		ownerlessRenamedDir := fmt.Sprintf("%s.ownerless.%d.%d", flockPath, now, pid)

		if err := os.MkdirAll(ownerlessRenamedDir, 0755); err != nil {
			t.Fatalf("failed to create simulated ownerless directory: %v", err)
		}
		// Successor wrote an owner file into directory
		if err := os.WriteFile(filepath.Join(ownerlessRenamedDir, "owner"), []byte(successorToken+"\n"), 0644); err != nil {
			t.Fatalf("failed to write successor owner file: %v", err)
		}

		shCmd := fmt.Sprintf(
			`flock_path="%s"; now="%d"; if [ ! -s "$flock_path.ownerless.%d.%d/owner" ]; then rm -rf "$flock_path.ownerless.%d.%d"; else mv "$flock_path.ownerless.%d.%d" "$flock_path" 2>/dev/null; fi`,
			flockPath, now, now, pid, now, pid, now, pid,
		)
		out, err := exec.CommandContext(ctx, "bash", "-c", shCmd).CombinedOutput()
		if err != nil {
			t.Fatalf("failed executing shell TOCTOU block: %v (out: %s)", err, string(out))
		}

		// Successor lock directory must be preserved at flockPath
		if _, err := os.Stat(flockPath); os.IsNotExist(err) {
			t.Fatalf("successor lock directory was not restored after owner file detected!")
		}

		ownerBytes, err := os.ReadFile(filepath.Join(flockPath, "owner"))
		if err != nil {
			t.Fatalf("failed to read restored owner file: %v", err)
		}
		if strings.TrimSpace(string(ownerBytes)) != successorToken {
			t.Fatalf("expected restored owner %s, got: %s", successorToken, strings.TrimSpace(string(ownerBytes)))
		}
	})

	// 4. Functional test: Matching stale token correctly reclaims and deletes stale directory
	t.Run("MatchingStaleToken_RemovesStaleDirAndAllowsAcquisition", func(t *testing.T) {
		tempDir := t.TempDir()
		flockPath := filepath.Join(tempDir, "test.lock")
		staleToken := "matching-stale-token"

		now := time.Now().Unix()
		pid := os.Getpid()
		staleRenamedDir := fmt.Sprintf("%s.stale.%d.%d", flockPath, now, pid)

		if err := os.MkdirAll(staleRenamedDir, 0755); err != nil {
			t.Fatalf("failed to create simulated stale directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(staleRenamedDir, "owner"), []byte(staleToken+"\n"), 0644); err != nil {
			t.Fatalf("failed to write stale owner file: %v", err)
		}

		shCmd := fmt.Sprintf(
			`flock_path="%s"; stale_token="%s"; now="%d"; if [ "$(cat "$flock_path.stale.%d.%d/owner" 2>/dev/null)" = "$stale_token" ]; then rm -rf "$flock_path.stale.%d.%d"; else mv "$flock_path.stale.%d.%d" "$flock_path" 2>/dev/null; fi`,
			flockPath, staleToken, now, now, pid, now, pid, now, pid,
		)
		out, err := exec.CommandContext(ctx, "bash", "-c", shCmd).CombinedOutput()
		if err != nil {
			t.Fatalf("failed executing shell TOCTOU block: %v (out: %s)", err, string(out))
		}

		// Directory must be removed
		if _, err := os.Stat(staleRenamedDir); !os.IsNotExist(err) {
			t.Fatalf("stale directory should have been removed when tokens matched!")
		}
	})

	// 5. End-to-end acquire and release execution with stale reclamation
	t.Run("EndToEnd_RemoteLockAcquireCmd_ReclaimsStaleLockCleanly", func(t *testing.T) {
		resName := fmt.Sprintf("toctou_e2e_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		_ = os.RemoveAll(lockPath)
		defer func() { _ = os.RemoveAll(lockPath) }()

		if err := os.MkdirAll(lockPath, 0755); err != nil {
			t.Fatalf("failed to create lock directory: %v", err)
		}
		staleToken := "old-stale-token-123"
		if err := os.WriteFile(filepath.Join(lockPath, "owner"), []byte(staleToken+"\n"), 0644); err != nil {
			t.Fatalf("failed to write owner file: %v", err)
		}
		// Set mtime to 120 seconds in past
		past := time.Now().Add(-120 * time.Second)
		_ = os.Chtimes(lockPath, past, past)

		newToken := "new-successor-token-456"
		acqCmd := remoteLockAcquireCmd(resName, newToken)
		cmd := exec.CommandContext(ctx, "bash", "-c", acqCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to acquire lock after stale reclamation: %v (out: %s)", err, string(out))
		}

		// Verify owner is newToken
		ownerData, err := os.ReadFile(filepath.Join(lockPath, "owner"))
		if err != nil {
			t.Fatalf("failed to read acquired owner: %v", err)
		}
		if strings.TrimSpace(string(ownerData)) != newToken {
			t.Fatalf("expected owner token %s, got: %s", newToken, strings.TrimSpace(string(ownerData)))
		}

		// Release lock
		relCmd := remoteLockReleaseCmd(resName, newToken)
		if relOut, relErr := exec.CommandContext(ctx, "bash", "-c", relCmd).CombinedOutput(); relErr != nil {
			t.Fatalf("failed to release lock: %v (out: %s)", relErr, string(relOut))
		}
		if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
			t.Fatalf("lock directory still exists after release!")
		}
	})
}

func TestAWGManager_ResolveLockResource_StableUnderTransientDiscoveryGlitch(t *testing.T) {
	ctx := context.Background()

	// 1. Transient error during Docker discovery retries up to 2 times and succeeds
	t.Run("TransientDiscoveryError_RetriesAndResolvesContainer", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.host = "192.0.2.1"
		client.port = 22

		var callCount atomic.Int32
		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "docker ps") {
				count := callCount.Add(1)
				if count == 1 {
					// First attempt fails with transient error
					return "", "transient docker daemon glitch", 1, errors.New("transient docker daemon glitch")
				}
				// Second attempt (first retry) succeeds
				return "amnezia-awg\n", "", 0, nil
			}
			return "OK", "", 0, nil
		}

		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
		res := mgr.ResolveLockResource(ctx, client, 42)

		if res != "amnezia-awg_awg0" {
			t.Fatalf("expected amnezia-awg_awg0 after retry, got: %s", res)
		}
		if callCount.Load() < 2 {
			t.Fatalf("expected at least 2 docker ps calls due to retry, got: %d", callCount.Load())
		}
	})

	// 2. Cached container for server keeps resolution stable when discovery permanently fails
	t.Run("CachedContainerForServer_StableWhenClientDiscoveryFails", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.host = "192.0.2.2"
		client.port = 22

		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "docker ps") {
				return "", "docker daemon unreachable", 1, errors.New("docker daemon unreachable")
			}
			return "OK", "", 0, nil
		}

		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
		// Pre-populate container cache for server ID 42
		mgr.setCachedContainer("id:42", "amnezia-awg")

		res := mgr.ResolveLockResource(ctx, client, 42)
		if res != "amnezia-awg_awg0" {
			t.Fatalf("expected cached container amnezia-awg_awg0, got: %s", res)
		}
	})

	// 3. Cached container for client keeps resolution stable
	t.Run("CachedContainerForClient_StableAcrossCalls", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.host = "192.0.2.3"
		client.port = 22

		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
		mgr.setCachedContainerForClient(client, "amnezia-awg")

		res := mgr.ResolveLockResource(ctx, client, 42)
		if res != "amnezia-awg_awg0" {
			t.Fatalf("expected cached container amnezia-awg_awg0, got: %s", res)
		}
	})

	// 4. Nil client uses cached container for server
	t.Run("NilClient_UsesCachedServerContainer", func(t *testing.T) {
		mgr := NewAWGManager(nil)
		mgr.setCachedContainer("id:55", "amnezia-awg")

		res := mgr.ResolveLockResource(ctx, nil, 55)
		if res != "amnezia-awg_awg0" {
			t.Fatalf("expected amnezia-awg_awg0 from cached server container, got: %s", res)
		}
	})

	// 5. Nil client without cache falls back to server ID
	t.Run("NilClient_NoCache_FallsBackToServerID", func(t *testing.T) {
		mgr := NewAWGManager(nil)
		res := mgr.ResolveLockResource(ctx, nil, 99)
		if res != "server_99" {
			t.Fatalf("expected server_99 fallback for uncached nil client, got: %s", res)
		}
	})
}
