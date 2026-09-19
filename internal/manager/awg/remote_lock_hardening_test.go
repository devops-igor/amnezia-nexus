package awg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

func TestRemoteLock_SuccessorLockTOCTOU_PreservesSuccessor(t *testing.T) {
	ctx := context.Background()

	// 1. Verify that remoteLockAcquireCmd contains the generation-safe TOCTOU verification and rollback logic
	cmdStr := remoteLockAcquireCmd("test_resource", "test_token")
	expectedTokens := []string{
		`gate_path="$flock_path.gate"`,
		`if ! mkdir "$gate_path" 2>/dev/null; then`,
		`g_info=$(cat "$gate_path/owner" 2>/dev/null)`,
		`if [ $((g_now - g_mtime)) -ge 15 ] && { [ -z "$g_ts" ] || [ $((g_now - g_ts)) -ge 15 ]; }; then`,
		`g_ren_dir="$gate_path.stale.$g_now.$$"`,
		`if [ "$g_ren_tok" = "$g_tok" ] && [ $((g_ren_now - g_ren_mtime)) -ge 15 ] && { [ -z "$g_ts" ] || [ "$g_ren_ts" = "$g_ts" ]; } && { [ -z "$g_ren_ts" ] || [ $((g_ren_now - g_ren_ts)) -ge 15 ]; }; then rm -rf "$g_ren_dir"; else if [ ! -d "$gate_path" ]; then mv "$g_ren_dir" "$gate_path" 2>/dev/null; else rm -rf "$g_ren_dir"; fi; fi`,
		`g_acq_ts=$(date +%s); echo 'test_token' "$g_acq_ts" > "$gate_path/owner" 2>/dev/null;`,
		`if [ "$ren_token" = "$stale_token" ] && [ $((ren_now - ren_mtime)) -ge 60 ] && { [ -z "$stale_ts" ] || [ "$ren_ts" = "$stale_ts" ]; } && { [ -z "$ren_ts" ] || [ $((ren_now - ren_ts)) -ge 60 ]; }; then rm -rf "$flock_path.stale.$now.$$"; if mkdir "$flock_path" 2>/dev/null; then rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; break; fi; else if [ ! -d "$flock_path" ]; then mv "$flock_path.stale.$now.$$" "$flock_path" 2>/dev/null; else rm -rf "$flock_path.stale.$now.$$"; fi; fi`,
		`if { [ ! -s "$flock_path.ownerless.$now.$$/owner" ] || [ -z "$ren_token" ]; } && [ $((ren_now - ren_mtime)) -ge 60 ]; then rm -rf "$flock_path.ownerless.$now.$$"; if mkdir "$flock_path" 2>/dev/null; then rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; break; fi; else if [ ! -d "$flock_path" ]; then mv "$flock_path.ownerless.$now.$$" "$flock_path" 2>/dev/null; else rm -rf "$flock_path.ownerless.$now.$$"; fi; fi`,
	}
	for _, expected := range expectedTokens {
		if !strings.Contains(cmdStr, expected) {
			t.Fatalf("remoteLockAcquireCmd missing expected TOCTOU protection snippet:\nExpected: %s\nGot cmd: %s", expected, cmdStr)
		}
	}

	// 2. Functional test: Existing owner token mismatch rolls back and preserves successor
	t.Run("ExistingOwner_SuccessorTokenMismatch_RollsBackAndPreservesSuccessor", func(t *testing.T) {
		runExistingOwnerMismatchRollbackTest(t, ctx)
	})

	// 3. Functional test: Ownerless directory where owner appears rolls back and preserves successor
	t.Run("OwnerlessStale_SuccessorWritesOwner_RollsBackAndPreservesSuccessor", func(t *testing.T) {
		runOwnerlessSuccessorWritesOwnerRollbackTest(t, ctx)
	})

	// 4. Functional test: Matching stale token correctly reclaims and deletes stale directory
	t.Run("MatchingStaleToken_RemovesStaleDirAndAllowsAcquisition", func(t *testing.T) {
		runMatchingStaleTokenReclaimTest(t, ctx)
	})

	// 5. End-to-end acquire and release execution with stale reclamation
	t.Run("EndToEnd_RemoteLockAcquireCmd_ReclaimsStaleLockCleanly", func(t *testing.T) {
		runEndToEndStaleReclaimTest(t, ctx)
	})
}

func runExistingOwnerMismatchRollbackTest(t *testing.T, ctx context.Context) {
	tempDir := t.TempDir()
	flockPath := filepath.Join(tempDir, "test.lock")
	staleToken := "stale-owner-token"
	successorToken := "successor-owner-token"

	now := time.Now().Unix()
	pid := os.Getpid()
	staleRenamedDir := fmt.Sprintf("%s.stale.%d.%d", flockPath, now, pid)

	if err := os.MkdirAll(staleRenamedDir, 0755); err != nil {
		t.Fatalf("failed to create simulated stale directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staleRenamedDir, "owner"), []byte(successorToken+"\n"), 0644); err != nil {
		t.Fatalf("failed to write successor owner file: %v", err)
	}

	shCmd := fmt.Sprintf(
		`flock_path="%s"; stale_token="%s"; now="%d"; ren_now="%d"; ren_mtime=0; ren_info=$(cat "%s.stale.%d.%d/owner" 2>/dev/null); set -- $ren_info; ren_token="$1"; ren_ts="$2"; if [ "$ren_token" = "$stale_token" ] && [ $((ren_now - ren_mtime)) -ge 60 ] && { [ -z "$stale_ts" ] || [ "$ren_ts" = "$stale_ts" ]; } && { [ -z "$ren_ts" ] || [ $((ren_now - ren_ts)) -ge 60 ]; }; then rm -rf "%s.stale.%d.%d"; else mv "%s.stale.%d.%d" "$flock_path" 2>/dev/null; fi`,
		flockPath, staleToken, now, now+100, flockPath, now, pid, flockPath, now, pid, flockPath, now, pid,
	)
	out, err := exec.CommandContext(ctx, "bash", "-c", shCmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed executing shell TOCTOU block: %v (out: %s)", err, string(out))
	}

	if _, err := os.Stat(flockPath); os.IsNotExist(err) {
		t.Fatalf("successor lock directory was not restored after token mismatch!")
	}

	ownerBytes, err := os.ReadFile(filepath.Join(flockPath, "owner"))
	if err != nil {
		t.Fatalf("failed to read restored owner file: %v", err)
	}
	if strings.TrimSpace(string(ownerBytes)) != successorToken {
		t.Fatalf("expected restored owner %s, got: %s", successorToken, strings.TrimSpace(string(ownerBytes)))
	}

	if _, err := os.Stat(staleRenamedDir); !os.IsNotExist(err) {
		t.Fatalf("stale renamed directory still exists after restore!")
	}
}

func runOwnerlessSuccessorWritesOwnerRollbackTest(t *testing.T, ctx context.Context) {
	tempDir := t.TempDir()
	flockPath := filepath.Join(tempDir, "test.lock")
	successorToken := "successor-ownerless-token"

	now := time.Now().Unix()
	pid := os.Getpid()
	ownerlessRenamedDir := fmt.Sprintf("%s.ownerless.%d.%d", flockPath, now, pid)

	if err := os.MkdirAll(ownerlessRenamedDir, 0755); err != nil {
		t.Fatalf("failed to create simulated ownerless directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ownerlessRenamedDir, "owner"), []byte(successorToken+"\n"), 0644); err != nil {
		t.Fatalf("failed to write successor owner file: %v", err)
	}

	shCmd := fmt.Sprintf(
		`flock_path="%s"; now="%d"; ren_now="%d"; ren_mtime=0; ren_info=$(cat "%s.ownerless.%d.%d/owner" 2>/dev/null); set -- $ren_info; ren_token="$1"; if { [ ! -s "%s.ownerless.%d.%d/owner" ] || [ -z "$ren_token" ]; } && [ $((ren_now - ren_mtime)) -ge 60 ]; then rm -rf "%s.ownerless.%d.%d"; else mv "%s.ownerless.%d.%d" "$flock_path" 2>/dev/null; fi`,
		flockPath, now, now+100, flockPath, now, pid, flockPath, now, pid, flockPath, now, pid, flockPath, now, pid,
	)
	out, err := exec.CommandContext(ctx, "bash", "-c", shCmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed executing shell TOCTOU block: %v (out: %s)", err, string(out))
	}

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
}

func runMatchingStaleTokenReclaimTest(t *testing.T, ctx context.Context) {
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
		`flock_path="%s"; stale_token="%s"; now="%d"; ren_now="%d"; ren_mtime=0; ren_info=$(cat "%s.stale.%d.%d/owner" 2>/dev/null); set -- $ren_info; ren_token="$1"; ren_ts="$2"; if [ "$ren_token" = "$stale_token" ] && [ $((ren_now - ren_mtime)) -ge 60 ] && { [ -z "$stale_ts" ] || [ "$ren_ts" = "$stale_ts" ]; } && { [ -z "$ren_ts" ] || [ $((ren_now - ren_ts)) -ge 60 ]; }; then rm -rf "%s.stale.%d.%d"; else mv "%s.stale.%d.%d" "$flock_path" 2>/dev/null; fi`,
		flockPath, staleToken, now, now+100, flockPath, now, pid, flockPath, now, pid, flockPath, now, pid,
	)
	out, err := exec.CommandContext(ctx, "bash", "-c", shCmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed executing shell TOCTOU block: %v (out: %s)", err, string(out))
	}

	if _, err := os.Stat(staleRenamedDir); !os.IsNotExist(err) {
		t.Fatalf("stale directory should have been removed when tokens matched!")
	}
}

func runEndToEndStaleReclaimTest(t *testing.T, ctx context.Context) {
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
	past := time.Now().Add(-120 * time.Second)
	_ = os.Chtimes(lockPath, past, past)

	newToken := "new-successor-token-456"
	acqCmd := remoteLockAcquireCmd(resName, newToken)
	cmd := exec.CommandContext(ctx, "bash", "-c", acqCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to acquire lock after stale reclamation: %v (out: %s)", err, string(out))
	}

	ownerData, err := os.ReadFile(filepath.Join(lockPath, "owner"))
	if err != nil {
		t.Fatalf("failed to read acquired owner: %v", err)
	}
	fields := strings.Fields(string(ownerData))
	if len(fields) == 0 || fields[0] != newToken {
		t.Fatalf("expected owner token %s, got: %s", newToken, strings.TrimSpace(string(ownerData)))
	}
	if len(fields) < 2 {
		t.Fatalf("expected generation metadata timestamp in owner file, got: %s", strings.TrimSpace(string(ownerData)))
	}

	relCmd := remoteLockReleaseCmd(resName, newToken)
	if relOut, relErr := exec.CommandContext(ctx, "bash", "-c", relCmd).CombinedOutput(); relErr != nil {
		t.Fatalf("failed to release lock: %v (out: %s)", relErr, string(relOut))
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after release!")
	}
}

func setupAbandonedStaleLock(t *testing.T, lockPath, token string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(lockPath, 0755); err != nil {
		t.Fatalf("failed to create initial lock dir: %v", err)
	}
	pastTime := time.Now().Add(-age)
	if err := os.WriteFile(filepath.Join(lockPath, "owner"), []byte(fmt.Sprintf("%s %d\n", token, pastTime.Unix())), 0644); err != nil {
		t.Fatalf("failed to write initial owner: %v", err)
	}
	if err := os.Chtimes(lockPath, pastTime, pastTime); err != nil {
		t.Fatalf("failed to set past mtime: %v", err)
	}
}

func setupAbandonedStaleGate(t *testing.T, gatePath, token string, age time.Duration) {
	t.Helper()
	if err := os.MkdirAll(gatePath, 0755); err != nil {
		t.Fatalf("failed to create initial gate dir: %v", err)
	}
	pastTime := time.Now().Add(-age)
	if token != "" {
		if err := os.WriteFile(filepath.Join(gatePath, "owner"), []byte(fmt.Sprintf("%s %d\n", token, pastTime.Unix())), 0644); err != nil {
			t.Fatalf("failed to write initial gate owner: %v", err)
		}
	}
	if err := os.Chtimes(gatePath, pastTime, pastTime); err != nil {
		t.Fatalf("failed to set past mtime on gate: %v", err)
	}
}

func waitForBarrierFile(t *testing.T, barrierFile string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(barrierFile); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for barrier file: %s", barrierFile)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertLockOwnerEquals(t *testing.T, lockPath, expectedToken, errorContext string) {
	t.Helper()
	ownerBytes, err := os.ReadFile(filepath.Join(lockPath, "owner"))
	if err != nil {
		t.Fatalf("%s: failed to read owner file: %v", errorContext, err)
	}
	fields := strings.Fields(string(ownerBytes))
	if len(fields) == 0 || fields[0] != expectedToken {
		t.Fatalf("%s: expected owner %s, got %s", errorContext, expectedToken, strings.TrimSpace(string(ownerBytes)))
	}
}

func releaseLockAssertSuccess(t *testing.T, ctx context.Context, resName, token string) {
	t.Helper()
	relCmd := remoteLockReleaseCmd(resName, token)
	out, err := exec.CommandContext(ctx, "bash", "-c", relCmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to release lock for %s: %v (out: %s)", token, err, string(out))
	}
}

func TestRemoteLock_GenerationRace_StaleReclaimerPreservesActiveSuccessor(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	resName := fmt.Sprintf("gen_race_%d", time.Now().UnixNano())
	lockPath := remoteLockPath(resName)
	_ = os.RemoveAll(lockPath)
	defer os.RemoveAll(lockPath)

	tempDir := t.TempDir()
	barrierReached := filepath.Join(tempDir, "barrier_reached")
	barrierResume := filepath.Join(tempDir, "barrier_resume")

	// 1. Setup an abandoned stale lock directory with past timestamp (>60s)
	setupAbandonedStaleLock(t, lockPath, "abandoned-owner-101", 120*time.Second)

	// 2. Slow Reclaimer command with an artificial barrier between the timestamp measurement and the token inspection
	slowToken := "slow-reclaimer-token"
	slowCmd := remoteLockAcquireCmd(resName, slowToken)

	barrierInjection := fmt.Sprintf(
		`if [ $((now - mtime)) -ge 60 ]; then rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; touch %s; while [ ! -f %s ]; do sleep 0.01; done; while ! mkdir "$gate_path" 2>/dev/null; do sleep 0.01; done;`,
		ssh.EscapeShellArg(barrierReached),
		ssh.EscapeShellArg(barrierResume),
	)
	targetPattern := `if [ $((now - mtime)) -ge 60 ]; then`
	if !strings.Contains(slowCmd, targetPattern) {
		t.Fatalf("slowCmd missing target pattern for barrier injection: %s", slowCmd)
	}
	slowInjectedCmd := strings.Replace(slowCmd, targetPattern, barrierInjection, 1)

	// 3. Launch Slow Reclaimer in a background goroutine
	slowDone := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(ctx, "bash", "-c", slowInjectedCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			slowDone <- fmt.Errorf("slow reclaimer exited with error: %w (out: %s)", err, string(out))
			return
		}
		slowDone <- nil
	}()

	// 4. Wait deterministically until Slow Reclaimer has measured the old mtime and paused at the barrier
	waitForBarrierFile(t, barrierReached, 5*time.Second)

	// 5. Fast Reclaimer executes standard acquisition: reclaims stale lock, acquires fresh lock
	fastToken := "fast-reclaimer-token"
	fastCmd := remoteLockAcquireCmd(resName, fastToken)
	if fastOut, fastErr := exec.CommandContext(ctx, "bash", "-c", fastCmd).CombinedOutput(); fastErr != nil {
		t.Fatalf("fast reclaimer failed to acquire: %v (out: %s)", fastErr, string(fastOut))
	}
	assertLockOwnerEquals(t, lockPath, fastToken, "after fast acquire")

	// 6. Signal Slow Reclaimer to resume
	if err := os.WriteFile(barrierResume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write barrier resume: %v", err)
	}

	// 7. Verify Slow Reclaimer DOES NOT steal or delete Fast Reclaimer's active lock
	select {
	case err := <-slowDone:
		t.Fatalf("MUTUAL EXCLUSION BROKEN: slow reclaimer acquired or exited while fast reclaimer was active: %v", err)
	case <-time.After(350 * time.Millisecond):
		// Expected: slow reclaimer is blocked
	}
	assertLockOwnerEquals(t, lockPath, fastToken, "while fast active")

	// 8. Fast Reclaimer releases the lock
	releaseLockAssertSuccess(t, ctx, resName, fastToken)

	// 9. Now Slow Reclaimer can proceed to acquire the lock
	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatalf("slow reclaimer failed to acquire after fast release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("slow reclaimer timed out waiting to acquire lock after release")
	}
	assertLockOwnerEquals(t, lockPath, slowToken, "after slow reclaimer acquired")

	// 10. Clean up: Slow Reclaimer releases lock
	releaseLockAssertSuccess(t, ctx, resName, slowToken)

	// Lock dir must be gone
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after final release")
	}
}

func TestAWGManager_ResolveLockResource_StableUnderTransientDiscoveryGlitch(t *testing.T) {
	ctx := context.Background()

	// 1. Transient discovery error resolves to physical interface target
	t.Run("TransientDiscoveryError_ResolvesPhysicalInterface", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.host = "192.0.2.1"
		client.port = 22

		client.sudoCmdHandler = func(cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "docker ps") {
				return "", "transient docker daemon glitch", 1, errors.New("transient docker daemon glitch")
			}
			return "OK", "", 0, nil
		}

		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
		res := mgr.ResolveLockResource(ctx, client, 42)

		if res != "iface_awg0" {
			t.Fatalf("expected iface_awg0 under transient error, got: %s", res)
		}
		if p := remoteLockPath(res); p != "/tmp/amnezia_awg_iface_awg0.lock" {
			t.Fatalf("expected lock path /tmp/amnezia_awg_iface_awg0.lock, got: %s", p)
		}
	})

	// 2. Cached container for server keeps resolution stable on physical interface
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
		mgr.setCachedContainer("id:42", "amnezia-awg")

		res := mgr.ResolveLockResource(ctx, client, 42)
		if res != "iface_awg0" {
			t.Fatalf("expected iface_awg0, got: %s", res)
		}
	})

	// 3. Cached container for client keeps resolution stable on physical interface
	t.Run("CachedContainerForClient_StableAcrossCalls", func(t *testing.T) {
		client := newMockAWGSSHClient()
		client.host = "192.0.2.3"
		client.port = 22

		mgr := NewAWGManager(&mockAWGSSHProvider{client: client})
		mgr.setCachedContainerForClient(client, "amnezia-awg")

		res := mgr.ResolveLockResource(ctx, client, 42)
		if res != "iface_awg0" {
			t.Fatalf("expected iface_awg0, got: %s", res)
		}
	})

	// 4. Nil client resolves to physical interface target
	t.Run("NilClient_UsesCachedServerContainer", func(t *testing.T) {
		mgr := NewAWGManager(nil)
		mgr.setCachedContainer("id:55", "amnezia-awg")

		res := mgr.ResolveLockResource(ctx, nil, 55)
		if res != "iface_awg0" {
			t.Fatalf("expected iface_awg0 from cached server container, got: %s", res)
		}
	})

	// 5. Distinct server IDs resolve to identical physical interface lock
	t.Run("NilClient_NoCache_FallsBackToServerID", func(t *testing.T) {
		mgr := NewAWGManager(nil)
		res1 := mgr.ResolveLockResource(ctx, nil, 99)
		res2 := mgr.ResolveLockResource(ctx, nil, 101)
		if res1 != "iface_awg0" || res2 != "iface_awg0" {
			t.Fatalf("expected iface_awg0 for both server IDs, got %s and %s", res1, res2)
		}
		if res1 != res2 {
			t.Fatalf("distinct server IDs must resolve to identical lock resource: %s != %s", res1, res2)
		}
	})
}

func TestRemoteLock_GenerationRace_PauseBeforeRename_PreservesSuccessor(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	resName := fmt.Sprintf("gen_race_rename_%d", time.Now().UnixNano())
	lockPath := remoteLockPath(resName)
	_ = os.RemoveAll(lockPath)
	defer os.RemoveAll(lockPath)

	tempDir := t.TempDir()
	barrierReached := filepath.Join(tempDir, "barrier_reached")
	barrierResume := filepath.Join(tempDir, "barrier_resume")

	// 1. Setup an abandoned stale lock directory with past timestamp (>60s)
	setupAbandonedStaleLock(t, lockPath, "abandoned-owner-202", 120*time.Second)

	// 2. Slow Reclaimer command with barrier injected right before mv rename
	slowToken := "slow-reclaimer-token-2"
	slowCmd := remoteLockAcquireCmd(resName, slowToken)

	targetPattern := `if mv "$flock_path" "$flock_path.stale.$now.$$"`
	barrierInjection := fmt.Sprintf(
		`rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; touch %s; while [ ! -f %s ]; do sleep 0.01; done; while ! mkdir "$gate_path" 2>/dev/null; do sleep 0.01; done; if mv "$flock_path" "$flock_path.stale.$now.$$"`,
		ssh.EscapeShellArg(barrierReached),
		ssh.EscapeShellArg(barrierResume),
	)
	if !strings.Contains(slowCmd, targetPattern) {
		t.Fatalf("slowCmd missing target pattern for barrier injection: %s", slowCmd)
	}
	slowInjectedCmd := strings.Replace(slowCmd, targetPattern, barrierInjection, 1)

	// 3. Launch Slow Reclaimer in a background goroutine
	slowDone := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(ctx, "bash", "-c", slowInjectedCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			slowDone <- fmt.Errorf("slow reclaimer exited with error: %w (out: %s)", err, string(out))
			return
		}
		slowDone <- nil
	}()

	// 4. Wait until Slow Reclaimer has verified the old mtime and paused right before mv
	waitForBarrierFile(t, barrierReached, 5*time.Second)

	// 5. Fast Reclaimer acquires fresh lock
	fastToken := "fast-reclaimer-token-2"
	fastCmd := remoteLockAcquireCmd(resName, fastToken)
	if fastOut, fastErr := exec.CommandContext(ctx, "bash", "-c", fastCmd).CombinedOutput(); fastErr != nil {
		t.Fatalf("fast reclaimer failed to acquire: %v (out: %s)", fastErr, string(fastOut))
	}
	assertLockOwnerEquals(t, lockPath, fastToken, "after fast acquire")

	// 6. Signal Slow Reclaimer to resume and attempt mv
	if err := os.WriteFile(barrierResume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write barrier resume: %v", err)
	}

	// 7. Slow Reclaimer renames, detects token/timestamp mismatch inside renamed directory,
	// and rolls back (restoring Fast Reclaimer's lock). Slow Reclaimer remains blocked.
	select {
	case err := <-slowDone:
		t.Fatalf("MUTUAL EXCLUSION BROKEN: slow reclaimer acquired or exited while fast reclaimer was active: %v", err)
	case <-time.After(350 * time.Millisecond):
		// Expected: slow reclaimer is blocked
	}
	assertLockOwnerEquals(t, lockPath, fastToken, "while fast active")

	// 8. Fast Reclaimer releases the lock
	releaseLockAssertSuccess(t, ctx, resName, fastToken)

	// 9. Now Slow Reclaimer acquires the lock
	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatalf("slow reclaimer failed to acquire after fast release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("slow reclaimer timed out waiting to acquire lock after release")
	}
	assertLockOwnerEquals(t, lockPath, slowToken, "after slow reclaimer acquired")

	// 10. Clean up
	releaseLockAssertSuccess(t, ctx, resName, slowToken)
}

func prepareSlowReclaimerInjectedCmd(t *testing.T, resName, slowToken, b1Reached, b1Resume, b2Reached, b2Resume string) string {
	t.Helper()
	slowCmd := remoteLockAcquireCmd(resName, slowToken)

	targetPattern1 := `if mv "$flock_path" "$flock_path.stale.$now.$$"`
	barrier1Injection := fmt.Sprintf(
		`rmdir "$gate_path" 2>/dev/null || rm -rf "$gate_path" 2>/dev/null; touch %s; while [ ! -f %s ]; do sleep 0.01; done; while ! mkdir "$gate_path" 2>/dev/null; do sleep 0.01; done; if mv "$flock_path" "$flock_path.stale.$now.$$"`,
		ssh.EscapeShellArg(b1Reached),
		ssh.EscapeShellArg(b1Resume),
	)
	if !strings.Contains(slowCmd, targetPattern1) {
		t.Fatalf("slowCmd missing targetPattern1 for barrier1 injection: %s", slowCmd)
	}
	injected := strings.Replace(slowCmd, targetPattern1, barrier1Injection, 1)

	targetPattern2 := `else if [ ! -d "$flock_path" ]; then`
	barrier2Injection := fmt.Sprintf(
		`else touch %s; while [ ! -f %s ]; do sleep 0.01; done; if [ ! -d "$flock_path" ]; then`,
		ssh.EscapeShellArg(b2Reached),
		ssh.EscapeShellArg(b2Resume),
	)
	if !strings.Contains(injected, targetPattern2) {
		t.Fatalf("slowInjectedCmd missing targetPattern2 for barrier2 injection: %s", injected)
	}
	return strings.Replace(injected, targetPattern2, barrier2Injection, 1)
}

func verifyContenderCBlocked(t *testing.T, cDone chan error, lockPath, contenderToken string) {
	t.Helper()
	select {
	case err := <-cDone:
		t.Fatalf("MUTUAL EXCLUSION BROKEN: contender C acquired lock during reclamation window: %v", err)
	case <-time.After(350 * time.Millisecond):
		// Expected: contender C is blocked waiting on acquisition gate
	}

	if ownerBytes, err := os.ReadFile(filepath.Join(lockPath, "owner")); err == nil {
		if strings.Contains(string(ownerBytes), contenderToken) {
			t.Fatalf("MUTUAL EXCLUSION BROKEN: Contender C stole lock during reclamation window")
		}
	}
}

func verifySubsequentWinnersSerialized(t *testing.T, ctx context.Context, resName, lockPath, slowToken, contenderToken string, slowDone, cDone chan error) {
	t.Helper()

	var firstWinner string
	var otherDone chan error
	var otherToken string

	select {
	case err := <-slowDone:
		if err != nil {
			t.Fatalf("Slow Reclaimer A failed to acquire after B release: %v", err)
		}
		firstWinner = slowToken
		otherDone = cDone
		otherToken = contenderToken
	case err := <-cDone:
		if err != nil {
			t.Fatalf("Contender C failed to acquire after B release: %v", err)
		}
		firstWinner = contenderToken
		otherDone = slowDone
		otherToken = slowToken
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for next contender (A or C) to acquire lock after B release")
	}

	assertLockOwnerEquals(t, lockPath, firstWinner, "first winner holds lock")
	releaseLockAssertSuccess(t, ctx, resName, firstWinner)

	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("second contender failed to acquire after first winner release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for second contender to acquire lock")
	}

	assertLockOwnerEquals(t, lockPath, otherToken, "second contender holds lock")
	releaseLockAssertSuccess(t, ctx, resName, otherToken)
}

func TestRemoteLock_ThreeContender_StaleRecoveryDoesNotDisplaceLiveSuccessorToThirdParty(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	resName := fmt.Sprintf("three_contender_%d", time.Now().UnixNano())
	lockPath := remoteLockPath(resName)
	gatePath := lockPath + ".gate"
	_ = os.RemoveAll(lockPath)
	_ = os.RemoveAll(gatePath)
	defer func() {
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
	}()

	tempDir := t.TempDir()
	barrier1Reached := filepath.Join(tempDir, "barrier1_reached")
	barrier1Resume := filepath.Join(tempDir, "barrier1_resume")
	barrier2Reached := filepath.Join(tempDir, "barrier2_reached")
	barrier2Resume := filepath.Join(tempDir, "barrier2_resume")

	// 1. Setup an abandoned stale lock directory with past timestamp (>60s)
	setupAbandonedStaleLock(t, lockPath, "abandoned-owner-303", 120*time.Second)

	// 2. Prepare Slow Reclaimer A command with two synchronization barriers
	slowToken := "slow-reclaimer-token-A"
	slowInjectedCmd := prepareSlowReclaimerInjectedCmd(
		t, resName, slowToken,
		barrier1Reached, barrier1Resume,
		barrier2Reached, barrier2Resume,
	)

	// 3. Launch Slow Reclaimer A in a background goroutine
	slowDone := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(ctx, "bash", "-c", slowInjectedCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			slowDone <- fmt.Errorf("slow reclaimer A exited with error: %w (out: %s)", err, string(out))
			return
		}
		slowDone <- nil
	}()

	// 4. Wait deterministically until Slow Reclaimer A pauses at Barrier 1 (before rename)
	waitForBarrierFile(t, barrier1Reached, 5*time.Second)

	// 5. Fast Successor B executes standard acquisition, reclaims stale lock, and becomes active owner
	fastToken := "fast-successor-token-B"
	fastCmd := remoteLockAcquireCmd(resName, fastToken)
	if fastOut, fastErr := exec.CommandContext(ctx, "bash", "-c", fastCmd).CombinedOutput(); fastErr != nil {
		t.Fatalf("fast successor B failed to acquire lock: %v (out: %s)", fastErr, string(fastOut))
	}
	assertLockOwnerEquals(t, lockPath, fastToken, "after fast successor B acquire")

	// 6. Signal Slow Reclaimer A to resume from Barrier 1 and execute rename
	if err := os.WriteFile(barrier1Resume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write barrier1 resume: %v", err)
	}

	// 7. Wait until Slow Reclaimer A executes rename and pauses at Barrier 2 (between rename and restore)
	waitForBarrierFile(t, barrier2Reached, 5*time.Second)

	// Verify that canonical lock path does NOT exist at this moment (it was renamed to .stale...)
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected canonical lock path to be absent during rename window, but it exists")
	}

	// 8. Contender C attempts to acquire the lock during this window
	contenderToken := "contender-token-C"
	contenderCmd := remoteLockAcquireCmd(resName, contenderToken)
	cDone := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(ctx, "bash", "-c", contenderCmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			cDone <- fmt.Errorf("contender C exited with error: %w (out: %s)", err, string(out))
			return
		}
		cDone <- nil
	}()

	// 9. Assert that Contender C CANNOT acquire canonical lock or steal B's active ownership
	verifyContenderCBlocked(t, cDone, lockPath, contenderToken)

	// 10. Signal Slow Reclaimer A to resume from Barrier 2 (execute rollback/restoration)
	if err := os.WriteFile(barrier2Resume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write barrier2 resume: %v", err)
	}

	// Give A time to restore B's lock and verify B's ownership remains intact
	time.Sleep(100 * time.Millisecond)
	assertLockOwnerEquals(t, lockPath, fastToken, "after Slow Reclaimer A restored Fast Successor B lock")

	// Verify neither Slow Reclaimer A nor Contender C acquired while Fast Successor B is active
	select {
	case err := <-slowDone:
		t.Fatalf("MUTUAL EXCLUSION BROKEN: Slow Reclaimer A acquired while B was active: %v", err)
	case err := <-cDone:
		t.Fatalf("MUTUAL EXCLUSION BROKEN: Contender C acquired while B was active: %v", err)
	case <-time.After(200 * time.Millisecond):
		// Expected: both A and C remain blocked while B holds the lock
	}

	// 11. Fast Successor B finishes critical section and releases lock
	releaseLockAssertSuccess(t, ctx, resName, fastToken)

	// 12-15. Verify subsequent contenders (A and C) serialize cleanly and release
	verifySubsequentWinnersSerialized(t, ctx, resName, lockPath, slowToken, contenderToken, slowDone, cDone)

	// Final verification: lock directory is completely cleaned up
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("canonical lock directory still exists after final release")
	}
}

func newSharedHostSSHClient(serverID int64, dockerHealthy *atomic.Bool, configPath string) *mockAWGSSHClient {
	_ = configPath
	mock := newMockAWGSSHClient()
	mock.host = "192.0.2.100"
	mock.port = 22
	mock.serverID = &serverID

	mock.sudoCmdHandler = func(cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "docker ps") {
			if !dockerHealthy.Load() {
				return "", "docker daemon unreachable", 1, errors.New("docker daemon unreachable")
			}
			return "amnezia-awg\n", "", 0, nil
		}
		execCmd := exec.Command("bash", "-c", cmd)
		out, err := execCmd.CombinedOutput()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return string(out), string(out), exitErr.ExitCode(), err
			}
			return string(out), string(out), 1, err
		}
		return string(out), "", 0, nil
	}

	return mock
}

func runSharedHostWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	mgr *AWGManager,
	client ssh.SSHClient,
	serverID int64,
	peerBlock string,
	configPath string,
	startGate <-chan struct{},
	dockerHealthy *atomic.Bool,
	activeCount *atomic.Int32,
	maxConcurrent *atomic.Int32,
	errs chan<- error,
) {
	defer wg.Done()
	<-startGate

	unlock, err := mgr.acquireRemoteServerLock(ctx, client, serverID)
	if err != nil {
		errs <- fmt.Errorf("server %d failed to acquire lock: %w", serverID, err)
		return
	}
	defer unlock()

	cur := activeCount.Add(1)
	defer activeCount.Add(-1)

	for {
		max := maxConcurrent.Load()
		if cur > max {
			if maxConcurrent.CompareAndSwap(max, cur) {
				break
			}
		} else {
			break
		}
	}

	// Simulate Docker recovery during configuration read/write
	dockerHealthy.Store(true)

	currentBytes, err := os.ReadFile(configPath)
	if err != nil {
		errs <- fmt.Errorf("server %d failed to read config: %w", serverID, err)
		return
	}

	// Sleep briefly to force contention and verify mutual exclusion prevents lost updates
	time.Sleep(60 * time.Millisecond)

	newContent := string(currentBytes) + peerBlock
	if err := os.WriteFile(configPath, []byte(newContent), 0600); err != nil {
		errs <- fmt.Errorf("server %d failed to write updated config: %w", serverID, err)
		return
	}
}

func TestRemoteLock_DiscoveryFailureAndRecovery_ZeroLostUpdates(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	serverID1 := int64(301)
	serverID2 := int64(302)

	canonicalLockPath := "/tmp/amnezia_awg_iface_awg0.lock"
	_ = os.RemoveAll(canonicalLockPath)
	_ = os.RemoveAll(canonicalLockPath + ".gate")
	defer func() {
		_ = os.RemoveAll(canonicalLockPath)
		_ = os.RemoveAll(canonicalLockPath + ".gate")
	}()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "awg0.conf")
	initialConfig := "[Interface]\nAddress = 10.66.66.1/24\nListenPort = 51820\nPrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	if err := os.WriteFile(configPath, []byte(initialConfig), 0600); err != nil {
		t.Fatalf("failed to write initial config: %v", err)
	}

	var dockerHealthy atomic.Bool
	dockerHealthy.Store(false)

	client1 := newSharedHostSSHClient(serverID1, &dockerHealthy, configPath)
	client2 := newSharedHostSSHClient(serverID2, &dockerHealthy, configPath)

	mgr1 := NewAWGManager(&mockAWGSSHProvider{client: client1})
	mgr2 := NewAWGManager(&mockAWGSSHProvider{client: client2})

	// 1. Assert both distinct server IDs resolve to the exact same physical lock path under discovery failure
	res1 := mgr1.ResolveLockResource(ctx, client1, serverID1)
	res2 := mgr2.ResolveLockResource(ctx, client2, serverID2)

	if res1 != "iface_awg0" || res2 != "iface_awg0" {
		t.Fatalf("expected both to resolve to iface_awg0, got res1=%s res2=%s", res1, res2)
	}
	if res1 != res2 {
		t.Fatalf("expected identical resource across server IDs, got res1=%s res2=%s", res1, res2)
	}

	path1 := remoteLockPath(res1)
	path2 := remoteLockPath(res2)
	if path1 != canonicalLockPath || path2 != canonicalLockPath {
		t.Fatalf("expected canonical lock path %s, got path1=%s path2=%s", canonicalLockPath, path1, path2)
	}

	// 2. Assert concurrent lock acquisition serializes strictly and survives Docker recovery with zero lost updates
	var (
		activeCount   atomic.Int32
		maxConcurrent atomic.Int32
		wg            sync.WaitGroup
		errs          = make(chan error, 2)
	)

	startGate := make(chan struct{})

	peer1Block := "\n[Peer]\nPublicKey = PeerKey1111111111111111111111111111111111111\nAllowedIPs = 10.66.66.2/32\n"
	peer2Block := "\n[Peer]\nPublicKey = PeerKey2222222222222222222222222222222222222\nAllowedIPs = 10.66.66.3/32\n"

	wg.Add(2)
	go runSharedHostWorker(ctx, &wg, mgr1, client1, serverID1, peer1Block, configPath, startGate, &dockerHealthy, &activeCount, &maxConcurrent, errs)
	go runSharedHostWorker(ctx, &wg, mgr2, client2, serverID2, peer2Block, configPath, startGate, &dockerHealthy, &activeCount, &maxConcurrent, errs)

	close(startGate)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("worker failed: %v", err)
		}
	}

	if max := maxConcurrent.Load(); max != 1 {
		t.Fatalf("MUTUAL EXCLUSION BROKEN: expected maxConcurrent=1, got: %d", max)
	}

	finalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read final config: %v", err)
	}
	finalContent := string(finalBytes)

	if !strings.Contains(finalContent, "PeerKey1111111111111111111111111111111111111") {
		t.Fatalf("LOST UPDATE: Peer 1 was overwritten or missing from final config:\n%s", finalContent)
	}
	if !strings.Contains(finalContent, "PeerKey2222222222222222222222222222222222222") {
		t.Fatalf("LOST UPDATE: Peer 2 was overwritten or missing from final config:\n%s", finalContent)
	}

	if _, err := os.Stat(canonicalLockPath); !os.IsNotExist(err) {
		t.Fatalf("canonical lock directory still exists after both released")
	}
}

func TestRemoteLock_AtomicGateMutex_FencesCanonicalLockAndStaleReclamation(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()

	t.Run("LiveGateBlocksContenderFromVacantCanonicalLock", func(t *testing.T) {
		resName := fmt.Sprintf("gate_block_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Create active gate mutex; canonical lock path is intentionally left absent/vacant
		if err := os.MkdirAll(gatePath, 0755); err != nil {
			t.Fatalf("failed to create gate dir: %v", err)
		}

		contenderToken := "contender-blocked-token"
		contenderCmd := remoteLockAcquireCmd(resName, contenderToken)

		done := make(chan error, 1)
		go func() {
			out, err := exec.CommandContext(ctx, "bash", "-c", contenderCmd).CombinedOutput()
			if err != nil {
				done <- fmt.Errorf("contender error: %w (out: %s)", err, string(out))
				return
			}
			done <- nil
		}()

		// Contender must be blocked by the gate mutex even though canonical lock path is absent
		select {
		case err := <-done:
			t.Fatalf("MUTUAL EXCLUSION BROKEN: contender acquired vacant lock while gate mutex was held: %v", err)
		case <-time.After(350 * time.Millisecond):
			// Expected: blocked
		}

		if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
			t.Fatalf("canonical lock was created while gate mutex was held!")
		}

		// Release the gate mutex
		if err := os.RemoveAll(gatePath); err != nil {
			t.Fatalf("failed to remove gate dir: %v", err)
		}

		// Contender should now acquire the lock
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("contender failed to acquire after gate release: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("contender timed out waiting to acquire after gate release")
		}

		assertLockOwnerEquals(t, lockPath, contenderToken, "after gate release")
		releaseLockAssertSuccess(t, ctx, resName, contenderToken)
	})

	t.Run("StaleGateCleanedUpAndLockAcquired", func(t *testing.T) {
		resName := fmt.Sprintf("gate_stale_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Create stale gate mutex (>= 15s old)
		if err := os.MkdirAll(gatePath, 0755); err != nil {
			t.Fatalf("failed to create gate dir: %v", err)
		}
		pastTime := time.Now().Add(-20 * time.Second)
		if err := os.Chtimes(gatePath, pastTime, pastTime); err != nil {
			t.Fatalf("failed to set past mtime on gate: %v", err)
		}

		token := "reclaimer-stale-gate-token"
		cmdStr := remoteLockAcquireCmd(resName, token)
		out, err := exec.CommandContext(ctx, "bash", "-c", cmdStr).CombinedOutput()
		if err != nil {
			t.Fatalf("failed to acquire lock with stale gate: %v (out: %s)", err, string(out))
		}

		assertLockOwnerEquals(t, lockPath, token, "acquired after stale gate cleanup")
		releaseLockAssertSuccess(t, ctx, resName, token)

		if _, err := os.Stat(gatePath); !os.IsNotExist(err) {
			t.Fatalf("gate path still exists after acquisition and release")
		}
	})
}

func launchContenderAcquire(ctx context.Context, resName, token string) chan error {
	done := make(chan error, 1)
	cmd := remoteLockAcquireCmd(resName, token)
	go func() {
		out, err := exec.CommandContext(ctx, "bash", "-c", cmd).CombinedOutput()
		if err != nil {
			done <- fmt.Errorf("contender exited with error: %w (out: %s)", err, string(out))
			return
		}
		done <- nil
	}()
	return done
}

func assertContenderBlocked(t *testing.T, done chan error, waitDuration time.Duration, errMsg string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s: %v", errMsg, err)
	case <-time.After(waitDuration):
	}
}

func awaitCommandSuccess(t *testing.T, done chan error, timeout time.Duration, errMsg string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", errMsg, err)
		}
	case <-time.After(timeout):
		t.Fatalf("%s: timed out after %v", errMsg, timeout)
	}
}

func awaitNextContenderAcquisition(t *testing.T, numContenders int, completed []bool, contenderAcquired []chan struct{}, contenderErrs []chan error) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < numContenders; i++ {
			if completed[i] {
				continue
			}
			select {
			case <-contenderAcquired[i]:
				return i
			case err := <-contenderErrs[i]:
				t.Fatalf("contender %d error: %v", i+1, err)
			default:
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for next contender to acquire lock")
	return -1
}

func assertNoOtherContenderAcquired(t *testing.T, winnerIdx int, numContenders int, completed []bool, contenderAcquired []chan struct{}) {
	t.Helper()
	for i := 0; i < numContenders; i++ {
		if i == winnerIdx || completed[i] {
			continue
		}
		select {
		case <-contenderAcquired[i]:
			t.Fatalf("MUTUAL EXCLUSION BROKEN: contender %d acquired while contender %d was holding lock", i+1, winnerIdx+1)
		default:
		}
	}
}

func releaseAndAwaitContenderDone(t *testing.T, idx int, contenderReleaseSignal, contenderDone []chan struct{}) {
	t.Helper()
	contenderReleaseSignal[idx] <- struct{}{}
	select {
	case <-contenderDone[idx]:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for contender %d to release lock", idx+1)
	}
}

func TestRemoteLock_ContenderSerializedBehindGateMutex_DuringStaleReclamation(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	resName := fmt.Sprintf("gate_ser_%d", time.Now().UnixNano())
	lockPath := remoteLockPath(resName)
	gatePath := lockPath + ".gate"
	_ = os.RemoveAll(lockPath)
	_ = os.RemoveAll(gatePath)
	defer func() {
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
	}()

	tempDir := t.TempDir()
	barrierReached := filepath.Join(tempDir, "barrier_reached")
	barrierResume := filepath.Join(tempDir, "barrier_resume")

	// 1. Setup an abandoned stale lock directory with past timestamp (>60s)
	staleToken := "stale-owner-ser-101"
	setupAbandonedStaleLock(t, lockPath, staleToken, 120*time.Second)

	// 2. Reclaimer A starts acquiring. Inject barrier right after gate is acquired and owner written,
	// before it inspects or renames $flock_path.
	reclaimerToken := "reclaimer-gate-token-A"
	reclaimerCmd := remoteLockAcquireCmd(resName, reclaimerToken)

	targetPattern := fmt.Sprintf(`echo %s "$g_acq_ts" > "$gate_path/owner" 2>/dev/null;`, ssh.EscapeShellArg(reclaimerToken))
	if !strings.Contains(reclaimerCmd, targetPattern) {
		t.Fatalf("reclaimerCmd missing target pattern for gate barrier injection: %s", reclaimerCmd)
	}

	barrierInjection := fmt.Sprintf(
		`%s touch %s; while [ ! -f %s ]; do sleep 0.01; done;`,
		targetPattern,
		ssh.EscapeShellArg(barrierReached),
		ssh.EscapeShellArg(barrierResume),
	)
	reclaimerInjectedCmd := strings.Replace(reclaimerCmd, targetPattern, barrierInjection, 1)

	reclaimerDone := make(chan error, 1)
	go func() {
		out, err := exec.CommandContext(ctx, "bash", "-c", reclaimerInjectedCmd).CombinedOutput()
		if err != nil {
			reclaimerDone <- fmt.Errorf("reclaimer exited with error: %w (out: %s)", err, string(out))
			return
		}
		reclaimerDone <- nil
	}()

	// 3. Wait until Reclaimer A has acquired gate mutex and paused
	waitForBarrierFile(t, barrierReached, 5*time.Second)

	// Verify Reclaimer A holds the gate mutex
	if _, err := os.Stat(gatePath); os.IsNotExist(err) {
		t.Fatalf("expected gate directory to exist while Reclaimer A is inside critical section")
	}
	assertLockOwnerEquals(t, gatePath, reclaimerToken, "reclaimer holding gate")

	// 4. Start Contender B attempting to acquire the lock
	contenderToken := "contender-gate-token-B"
	contenderDone := launchContenderAcquire(ctx, resName, contenderToken)

	// 5. Verify Contender B is strictly blocked behind the gate mutex
	assertContenderBlocked(t, contenderDone, 350*time.Millisecond, "MUTUAL EXCLUSION BROKEN: contender acquired or exited while reclaimer held gate")

	// 6. Verify Contender B DID NOT touch or alter $flock_path
	assertLockOwnerEquals(t, lockPath, staleToken, "stale lock must remain untouched while contender is blocked")

	// Verify no stale rename dirs created by contender
	matches, _ := filepath.Glob(lockPath + ".stale.*")
	if len(matches) > 0 {
		t.Fatalf("unexpected stale renamed directory created before reclaimer executed: %v", matches)
	}

	// 7. Unblock Reclaimer A to proceed with stale reclamation
	if err := os.WriteFile(barrierResume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write barrier resume: %v", err)
	}

	// 8. Wait for Reclaimer A to complete stale reclamation and acquire canonical lock
	awaitCommandSuccess(t, reclaimerDone, 5*time.Second, "reclaimer failed")
	assertLockOwnerEquals(t, lockPath, reclaimerToken, "after reclaimer acquired")

	// 9. Contender B is now waiting on the active lock held by Reclaimer A
	assertContenderBlocked(t, contenderDone, 350*time.Millisecond, "contender acquired while reclaimer is actively holding lock")

	// 10. Reclaimer A releases the lock
	releaseLockAssertSuccess(t, ctx, resName, reclaimerToken)

	// 11. Contender B should now successfully acquire the lock
	awaitCommandSuccess(t, contenderDone, 5*time.Second, "contender failed to acquire lock after reclaimer release")
	assertLockOwnerEquals(t, lockPath, contenderToken, "after contender acquired")
	releaseLockAssertSuccess(t, ctx, resName, contenderToken)

	// Verify all lock directories are cleaned up
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after release")
	}
	if _, err := os.Stat(gatePath); !os.IsNotExist(err) {
		t.Fatalf("gate directory still exists after release")
	}
}

func TestRemoteLock_StaleReclaimerPausedInGate_AllContendersWaitOnGate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	resName := fmt.Sprintf("gate_multi_wait_%d", time.Now().UnixNano())
	lockPath := remoteLockPath(resName)
	gatePath := lockPath + ".gate"
	_ = os.RemoveAll(lockPath)
	_ = os.RemoveAll(gatePath)
	defer func() {
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
	}()

	tempDir := t.TempDir()
	barrierReached := filepath.Join(tempDir, "barrier_reached")
	barrierResume := filepath.Join(tempDir, "barrier_resume")

	// 1. Setup an abandoned stale lock directory (>60s)
	staleToken := "stale-owner-multi-101"
	setupAbandonedStaleLock(t, lockPath, staleToken, 120*time.Second)

	// 2. Reclaimer starts and pauses inside gate critical section while holding the gate
	reclaimerToken := "reclaimer-holding-gate"
	reclaimerCmd := remoteLockAcquireCmd(resName, reclaimerToken)

	targetPattern := fmt.Sprintf(`echo %s "$g_acq_ts" > "$gate_path/owner" 2>/dev/null;`, ssh.EscapeShellArg(reclaimerToken))
	if !strings.Contains(reclaimerCmd, targetPattern) {
		t.Fatalf("reclaimerCmd missing target pattern for gate barrier injection: %s", reclaimerCmd)
	}

	barrierInjection := fmt.Sprintf(
		`%s touch %s; while [ ! -f %s ]; do sleep 0.01; done;`,
		targetPattern,
		ssh.EscapeShellArg(barrierReached),
		ssh.EscapeShellArg(barrierResume),
	)
	reclaimerInjectedCmd := strings.Replace(reclaimerCmd, targetPattern, barrierInjection, 1)

	reclaimerDone := make(chan error, 1)
	go func() {
		out, err := exec.CommandContext(ctx, "bash", "-c", reclaimerInjectedCmd).CombinedOutput()
		if err != nil {
			reclaimerDone <- fmt.Errorf("reclaimer error: %w (out: %s)", err, string(out))
			return
		}
		reclaimerDone <- nil
	}()

	waitForBarrierFile(t, barrierReached, 5*time.Second)

	// 3. Launch 3 competing contenders simultaneously
	const numContenders = 3
	contenderAcquired := make([]chan struct{}, numContenders)
	contenderReleaseSignal := make([]chan struct{}, numContenders)
	contenderDone := make([]chan struct{}, numContenders)
	contenderErrs := make([]chan error, numContenders)
	contenderTokens := make([]string, numContenders)

	for i := 0; i < numContenders; i++ {
		contenderAcquired[i] = make(chan struct{}, 1)
		contenderReleaseSignal[i] = make(chan struct{}, 1)
		contenderDone[i] = make(chan struct{}, 1)
		contenderErrs[i] = make(chan error, 1)
		contenderTokens[i] = fmt.Sprintf("multi-contender-%d", i+1)
		cCmd := remoteLockAcquireCmd(resName, contenderTokens[i])
		idx := i
		go func() {
			out, err := exec.CommandContext(ctx, "bash", "-c", cCmd).CombinedOutput()
			if err != nil {
				contenderErrs[idx] <- fmt.Errorf("contender %d error: %w (out: %s)", idx+1, err, string(out))
				return
			}
			contenderAcquired[idx] <- struct{}{}
			<-contenderReleaseSignal[idx]
			relCmd := remoteLockReleaseCmd(resName, contenderTokens[idx])
			_, _ = exec.CommandContext(ctx, "bash", "-c", relCmd).CombinedOutput()
			contenderDone[idx] <- struct{}{}
		}()
	}

	// 4. Verify ALL contenders are waiting on the gate
	time.Sleep(350 * time.Millisecond)
	for i := 0; i < numContenders; i++ {
		select {
		case <-contenderAcquired[i]:
			t.Fatalf("contender %d bypassed gate mutex while reclaimer was holding gate", i+1)
		case err := <-contenderErrs[i]:
			t.Fatalf("contender %d failed while reclaimer held gate: %v", i+1, err)
		default:
			// Expected: still waiting
		}
	}

	// Canonical lock is still owned by stale token
	assertLockOwnerEquals(t, lockPath, staleToken, "stale lock preserved while contenders wait on gate")
	assertLockOwnerEquals(t, gatePath, reclaimerToken, "gate held by reclaimer")

	// 5. Unblock reclaimer
	if err := os.WriteFile(barrierResume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to write barrier resume: %v", err)
	}

	awaitCommandSuccess(t, reclaimerDone, 5*time.Second, "reclaimer timed out finishing reclamation")
	assertLockOwnerEquals(t, lockPath, reclaimerToken, "reclaimer holds lock after completing")

	// 6. Reclaimer releases the lock
	releaseLockAssertSuccess(t, ctx, resName, reclaimerToken)

	// 7. Exactly one contender acquires at a time, and all serialize cleanly
	completed := make([]bool, numContenders)
	for step := 0; step < numContenders; step++ {
		winnerIdx := awaitNextContenderAcquisition(t, numContenders, completed, contenderAcquired, contenderErrs)
		assertLockOwnerEquals(t, lockPath, contenderTokens[winnerIdx], fmt.Sprintf("winner at step %d", step+1))
		assertNoOtherContenderAcquired(t, winnerIdx, numContenders, completed, contenderAcquired)
		releaseAndAwaitContenderDone(t, winnerIdx, contenderReleaseSignal, contenderDone)
		completed[winnerIdx] = true
	}

	// Clean final state
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock dir still exists")
	}
	if _, err := os.Stat(gatePath); !os.IsNotExist(err) {
		t.Fatalf("gate dir still exists")
	}
}

func TestRemoteLock_SimultaneousGateReclaimers_OnlyOneEntersGate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()
	resName := fmt.Sprintf("gate_race_%d", time.Now().UnixNano())
	lockPath := remoteLockPath(resName)
	gatePath := lockPath + ".gate"
	_ = os.RemoveAll(lockPath)
	_ = os.RemoveAll(gatePath)
	defer func() {
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
	}()

	// Setup a stale gate directory (20s old) with crashed owner metadata
	setupAbandonedStaleGate(t, gatePath, "crashed-gate-token-99", 20*time.Second)

	var (
		activeLockHolders atomic.Int32
		maxConcurrent     atomic.Int32
		wg                sync.WaitGroup
		errs              = make(chan error, 3)
		startGate         = make(chan struct{})
	)

	tokens := []string{"reclaimer-race-alpha", "reclaimer-race-beta", "reclaimer-race-gamma"}
	const numReclaimers = 3
	wg.Add(numReclaimers)

	for i := 0; i < numReclaimers; i++ {
		tok := tokens[i]
		go func() {
			defer wg.Done()
			cmdStr := remoteLockAcquireCmd(resName, tok)

			<-startGate
			out, err := exec.CommandContext(ctx, "bash", "-c", cmdStr).CombinedOutput()
			if err != nil {
				errs <- fmt.Errorf("reclaimer %s failed to acquire: %w (out: %s)", tok, err, string(out))
				return
			}

			cur := activeLockHolders.Add(1)
			for {
				oldMax := maxConcurrent.Load()
				if cur <= oldMax || maxConcurrent.CompareAndSwap(oldMax, cur) {
					break
				}
			}

			// Hold the lock briefly to expose any overlap
			time.Sleep(50 * time.Millisecond)

			assertLockOwnerEquals(t, lockPath, tok, "holder verified")

			activeLockHolders.Add(-1)
			relCmd := remoteLockReleaseCmd(resName, tok)
			relOut, relErr := exec.CommandContext(ctx, "bash", "-c", relCmd).CombinedOutput()
			if relErr != nil {
				errs <- fmt.Errorf("reclaimer %s failed to release: %w (out: %s)", tok, relErr, string(relOut))
				return
			}
		}()
	}

	close(startGate)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrency race failure: %v", err)
		}
	}

	if max := maxConcurrent.Load(); max != 1 {
		t.Fatalf("MUTUAL EXCLUSION BROKEN on stale gate race: expected maxConcurrent=1, got %d", max)
	}

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after all completed")
	}
	if _, err := os.Stat(gatePath); !os.IsNotExist(err) {
		t.Fatalf("gate directory still exists after all completed")
	}
}

func TestRemoteLock_AbandonedGateRecovery_OwnerGenerationValidation(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	ctx := context.Background()

	t.Run("FreshGateWithMetadata_ProtectedFromEviction", func(t *testing.T) {
		resName := fmt.Sprintf("gate_fresh_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Create fresh gate (2s old)
		setupAbandonedStaleGate(t, gatePath, "active-gate-tok", 2*time.Second)

		contenderCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
		defer cancel()

		cmdStr := remoteLockAcquireCmd(resName, "contender-tok")
		out, err := exec.CommandContext(contenderCtx, "bash", "-c", cmdStr).CombinedOutput()
		if err == nil {
			t.Fatalf("expected contender to fail/timeout on fresh gate, but acquired! out: %s", string(out))
		}

		// Gate must remain intact
		if _, statErr := os.Stat(gatePath); os.IsNotExist(statErr) {
			t.Fatalf("fresh gate was erroneously evicted!")
		}
		assertLockOwnerEquals(t, gatePath, "active-gate-tok", "fresh gate owner preserved")
	})

	t.Run("ExpiredGateWithMetadata_SafelyReclaimed", func(t *testing.T) {
		resName := fmt.Sprintf("gate_exp_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Create expired gate (20s old)
		setupAbandonedStaleGate(t, gatePath, "stale-gate-tok", 20*time.Second)

		reclaimerToken := "reclaimer-gate-success"
		cmdStr := remoteLockAcquireCmd(resName, reclaimerToken)
		out, err := exec.CommandContext(ctx, "bash", "-c", cmdStr).CombinedOutput()
		if err != nil {
			t.Fatalf("failed to acquire lock with expired gate: %v (out: %s)", err, string(out))
		}

		assertLockOwnerEquals(t, lockPath, reclaimerToken, "reclaimed lock owner")
		releaseLockAssertSuccess(t, ctx, resName, reclaimerToken)

		if _, statErr := os.Stat(gatePath); !os.IsNotExist(statErr) {
			t.Fatalf("gate directory still exists after release")
		}
	})

	t.Run("MtimeExpiredButTimestampFresh_ProtectedFromEviction", func(t *testing.T) {
		resName := fmt.Sprintf("gate_mtime_skew_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Gate directory mtime is expired (25s ago), but owner timestamp is fresh (now)
		if err := os.MkdirAll(gatePath, 0755); err != nil {
			t.Fatalf("failed to create gate dir: %v", err)
		}
		nowTs := time.Now().Unix()
		if err := os.WriteFile(filepath.Join(gatePath, "owner"), []byte(fmt.Sprintf("skew-token %d\n", nowTs)), 0644); err != nil {
			t.Fatalf("failed to write owner: %v", err)
		}
		pastTime := time.Now().Add(-25 * time.Second)
		if err := os.Chtimes(gatePath, pastTime, pastTime); err != nil {
			t.Fatalf("failed to set past mtime: %v", err)
		}

		contenderCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
		defer cancel()

		cmdStr := remoteLockAcquireCmd(resName, "contender-tok")
		out, err := exec.CommandContext(contenderCtx, "bash", "-c", cmdStr).CombinedOutput()
		if err == nil {
			t.Fatalf("expected contender to fail/timeout when gate timestamp is fresh, but acquired! out: %s", string(out))
		}

		// Gate must NOT be evicted because owner timestamp is fresh
		if _, statErr := os.Stat(gatePath); os.IsNotExist(statErr) {
			t.Fatalf("gate with fresh timestamp was erroneously evicted!")
		}
		assertLockOwnerEquals(t, gatePath, "skew-token", "skew gate owner preserved")
	})

	t.Run("TimestampExpiredButMtimeFresh_ProtectedFromEviction", func(t *testing.T) {
		resName := fmt.Sprintf("gate_ts_skew_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Owner timestamp is expired (25s ago), but directory mtime is fresh (now)
		if err := os.MkdirAll(gatePath, 0755); err != nil {
			t.Fatalf("failed to create gate dir: %v", err)
		}
		pastTs := time.Now().Add(-25 * time.Second).Unix()
		if err := os.WriteFile(filepath.Join(gatePath, "owner"), []byte(fmt.Sprintf("ts-skew-token %d\n", pastTs)), 0644); err != nil {
			t.Fatalf("failed to write owner: %v", err)
		}
		now := time.Now()
		if err := os.Chtimes(gatePath, now, now); err != nil {
			t.Fatalf("failed to set fresh mtime: %v", err)
		}

		contenderCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
		defer cancel()

		cmdStr := remoteLockAcquireCmd(resName, "contender-tok")
		out, err := exec.CommandContext(contenderCtx, "bash", "-c", cmdStr).CombinedOutput()
		if err == nil {
			t.Fatalf("expected contender to fail/timeout when gate mtime is fresh, but acquired! out: %s", string(out))
		}

		// Gate must NOT be evicted because directory mtime is fresh
		if _, statErr := os.Stat(gatePath); os.IsNotExist(statErr) {
			t.Fatalf("gate with fresh mtime was erroneously evicted!")
		}
		assertLockOwnerEquals(t, gatePath, "ts-skew-token", "ts-skew gate owner preserved")
	})

	t.Run("OwnerlessCrashedGate_Expired_SafelyReclaimed", func(t *testing.T) {
		resName := fmt.Sprintf("gate_ownerless_%d", time.Now().UnixNano())
		lockPath := remoteLockPath(resName)
		gatePath := lockPath + ".gate"
		_ = os.RemoveAll(lockPath)
		_ = os.RemoveAll(gatePath)
		defer func() {
			_ = os.RemoveAll(lockPath)
			_ = os.RemoveAll(gatePath)
		}()

		// Ownerless gate (token=""), expired 20s ago
		setupAbandonedStaleGate(t, gatePath, "", 20*time.Second)

		reclaimerToken := "reclaimer-ownerless-gate"
		cmdStr := remoteLockAcquireCmd(resName, reclaimerToken)
		out, err := exec.CommandContext(ctx, "bash", "-c", cmdStr).CombinedOutput()
		if err != nil {
			t.Fatalf("failed to acquire lock with expired ownerless gate: %v (out: %s)", err, string(out))
		}

		assertLockOwnerEquals(t, lockPath, reclaimerToken, "ownerless reclaimed lock owner")
		releaseLockAssertSuccess(t, ctx, resName, reclaimerToken)

		if _, statErr := os.Stat(gatePath); !os.IsNotExist(statErr) {
			t.Fatalf("gate directory still exists after release")
		}
	})
}
