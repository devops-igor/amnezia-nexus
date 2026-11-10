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
)

// Real-builder controls. Invariant: a live or concurrent owner is never displaced, symlink
// targets are never followed, and unjustifiable objects fail closed.

func scratchLock(t *testing.T) (res, lockPath string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	res = fmt.Sprintf("objstale_%d_%d", time.Now().UnixNano(), os.Getpid())
	lockPath = remoteLockPath(res)
	if _, err := os.Lstat(lockPath); err == nil {
		t.Skipf("refusing to reuse pre-existing lock path %s", lockPath)
	}
	t.Cleanup(func() { _ = os.RemoveAll(lockPath); _ = os.RemoveAll(lockPath + ".gate") })
	return res, lockPath
}

// runShell returns the shell's own exit status; a spawn failure is fatal, not success.
func runShell(t *testing.T, cmd string) (int, string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "bash", "-c", cmd).CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("shell did not run: %v; output=%s", err, out)
	}
	return 0, string(out)
}

func bounded(cmd string) string { return strings.Replace(cmd, "timeout=30", "timeout=2", 1) }

func expectRefused(t *testing.T, res, want string) {
	t.Helper()
	if code, out := runShell(t, bounded(remoteLockAcquireCmd(res, "contender"))); code != 1 || !strings.Contains(out, want) {
		t.Fatalf("want refusal %q, got exit=%d out=%s", want, code, out)
	}
}

func staleFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte("poison\n"), 0o644); err != nil || os.Chtimes(path, time.Now().Add(-age), time.Now().Add(-age)) != nil {
		t.Fatalf("failed to stage stale obstruction at %s", path)
	}
}

func sq(t *testing.T, s string) string {
	t.Helper()
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// pauseAt parks the real builder at anchor until the test writes the resume marker.
func pauseAt(t *testing.T, cmd, anchor, snippet string) string {
	t.Helper()
	if !strings.Contains(cmd, anchor) {
		t.Fatalf("builder missing pause anchor %q", anchor)
	}
	return strings.Replace(cmd, anchor, snippet+anchor, 1)
}

// barrier returns a snippet that parks the builder, a wait for the park, and a resume. The
// park and the resume are separate so the caller can act in the window between them.
func barrier(t *testing.T) (snippet string, waitHit func(), resume func()) {
	t.Helper()
	d := t.TempDir()
	hit, goFile := filepath.Join(d, "hit"), filepath.Join(d, "go")
	return fmt.Sprintf("printf go > %s; while [ ! -f %s ]; do sleep 0.01; done; ", sq(t, hit), sq(t, goFile)),
		func() {
			for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(hit); err == nil {
					return
				}
			}
			t.Fatalf("timed out waiting for builder to reach the barrier")
		},
		func() {
			if err := os.WriteFile(goFile, []byte("go"), 0o644); err != nil {
				t.Fatalf("failed to resume builder: %v", err)
			}
		}
}

type pathCase struct {
	res, lockPath, target, label, pathVar string
	gate                                  bool
}

// bothPaths runs fn for the canonical lock path and for its acquisition gate.
func bothPaths(t *testing.T, fn func(t *testing.T, c pathCase)) {
	for _, gate := range []bool{false, true} {
		label, pv := "LockPath", "$flock_path"
		if gate {
			label, pv = "GatePath", "$gate_path"
		}
		t.Run(label, func(t *testing.T) {
			res, lockPath := scratchLock(t)
			target := lockPath
			if gate {
				target += ".gate"
			}
			fn(t, pathCase{res, lockPath, target, label, pv, gate})
		})
	}
}

// TestRemoteLock_StaleFileReclaimedAtBothPaths covers the demonstrated outage shape.
func TestRemoteLock_StaleFileReclaimedAtBothPaths(t *testing.T) {
	bothPaths(t, func(t *testing.T, c pathCase) {
		staleFile(t, c.target, time.Hour)
		token := "reclaimer-" + c.label
		if code, out := runShell(t, remoteLockAcquireCmd(c.res, token)); code != 0 {
			t.Fatalf("%s: acquire over stale file: exit=%d out=%s", c.label, code, out)
		}
		assertLockOwnerEquals(t, c.lockPath, token, c.label+" reclaimed")
		if !c.gate {
			// The canonical path now holds our own lock directory, owned by token.
			if fi, err := os.Lstat(c.target); err != nil || !fi.IsDir() {
				t.Fatalf("%s: lock path is not our acquired directory: err=%v", c.label, err)
			}
		} else if _, err := os.Lstat(c.target); !os.IsNotExist(err) {
			t.Fatalf("%s: gate obstruction survived acquisition", c.label)
		}
		releaseLockAssertSuccess(t, context.Background(), c.res, token)
		if _, err := os.Lstat(c.lockPath); !os.IsNotExist(err) {
			t.Fatalf("%s: lock survived release", c.label)
		}
	})
}

// TestRemoteLock_OwnershipPreserved proves age alone is not ownership proof.
func TestRemoteLock_OwnershipPreserved(t *testing.T) {
	check := func(t *testing.T, seed func(string), owner string) {
		res, lockPath := scratchLock(t)
		seed(lockPath)
		expectRefused(t, res, "timed out waiting for remote lock")
		if owner == "" {
			if fi, err := os.Lstat(lockPath); err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("recent obstruction removed or retyped: err=%v", err)
			}
			return
		}
		assertLockOwnerEquals(t, lockPath, owner, "owner preserved")
		releaseLockAssertSuccess(t, context.Background(), res, owner)
	}
	t.Run("RecentRegularFile", func(t *testing.T) {
		check(t, func(p string) { staleFile(t, p, 0) }, "")
	})
	t.Run("LiveDirectoryOwner", func(t *testing.T) {
		check(t, func(p string) { setupAbandonedStaleLock(t, p, "live-owner", 0) }, "live-owner")
	})
	t.Run("ForeignOwnerSurvivesRelease", func(t *testing.T) {
		res, lockPath := scratchLock(t)
		if code, out := runShell(t, remoteLockAcquireCmd(res, "original-owner")); code != 0 {
			t.Fatalf("acquire failed: exit=%d out=%s", code, out)
		}
		if err := os.WriteFile(filepath.Join(lockPath, "owner"), []byte("successor 1\n"), 0o644); err != nil {
			t.Fatalf("failed to rewrite owner: %v", err)
		}
		releaseLockAssertSuccess(t, context.Background(), res, "original-owner")
		assertLockOwnerEquals(t, lockPath, "successor", "foreign owner survived non-owner release")
	})
}

// TestRemoteLock_UnsafeObjectsFailClosed: symlinks are refused at both paths without being
// followed or having their targets touched; a fifo is refused and left in place.
func TestRemoteLock_UnsafeObjectsFailClosed(t *testing.T) {
	t.Run("FifoAtLockPath", func(t *testing.T) {
		res, lockPath := scratchLock(t)
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo not available")
		}
		if err := exec.Command("mkfifo", lockPath).Run(); err != nil {
			t.Fatalf("failed to create fifo: %v", err)
		}
		expectRefused(t, res, "unsafe object")
		if _, err := os.Lstat(lockPath); err != nil {
			t.Fatalf("unsafe object removed instead of refused: %v", err)
		}
	})
	bothPaths(t, func(t *testing.T, c pathCase) {
		dir := filepath.Join(t.TempDir(), "symlink-target")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("failed to create target: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "owner"), []byte("sentinel\n"), 0o644); err != nil {
			t.Fatalf("failed to seed sentinel: %v", err)
		}
		if err := os.Symlink(dir, c.target); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}
		expectRefused(t, c.res, "unsafe symbolic link")
		if fi, err := os.Lstat(c.target); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s: symlink was modified: err=%v", c.label, err)
		}
		if data, err := os.ReadFile(filepath.Join(dir, "owner")); err != nil || strings.TrimSpace(string(data)) != "sentinel" {
			t.Fatalf("%s: symlink target altered: data=%q err=%v", c.label, data, err)
		}
	})

}

// raceHeartbeat pauses the heartbeat between its passed checks and its touch, releases the
// lock, then resumes it; it reports whether a file was left at the lock path.
func raceHeartbeat(t *testing.T, heartbeat func(resource any, token string) string) bool {
	t.Helper()
	res, lockPath := scratchLock(t)
	if code, out := runShell(t, remoteLockAcquireCmd(res, "race-owner")); code != 0 {
		t.Fatalf("acquire failed: exit=%d out=%s", code, out)
	}
	snippet, waitHit, resume := barrier(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = runShell(t, pauseAt(t, heartbeat(res, "race-owner"), "then touch -m", snippet))
	}()
	// The heartbeat has already passed its directory/owner checks and is parked right
	// before its touch. Release the lock first, then let the touch land.
	waitHit()
	releaseLockAssertSuccess(t, context.Background(), res, "race-owner")
	resume()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("heartbeat did not finish after barrier release")
	}
	fi, err := os.Lstat(lockPath)
	return err == nil && fi.Mode().IsRegular()
}

// TestRemoteLock_HeartbeatRaceAfterRelease is the decisive creation oracle: corrected text
// must create nothing while the pre-repair text must create the obstruction.
func TestRemoteLock_HeartbeatRaceAfterRelease(t *testing.T) {
	if raceHeartbeat(t, remoteLockHeartbeatCmd) {
		t.Fatalf("corrected heartbeat created an obstruction racing release")
	}
	legacy := func(resource any, token string) string {
		return strings.Replace(remoteLockHeartbeatCmd(resource, token), "touch -m -c ", "touch -m ", 1)
	}
	if !raceHeartbeat(t, legacy) {
		t.Fatalf("pre-repair heartbeat created nothing, so this oracle is not discriminating")
	}
}

// TestRemoteLock_ReclaimPreservesSuccessor: a successor appearing between inspection and
// rename keeps its identity at the canonical path, is never acquired over, and is never
// nested inside the staging directory by mv semantics.
func TestRemoteLock_ReclaimPreservesSuccessor(t *testing.T) {
	bothPaths(t, func(t *testing.T, c pathCase) {
		staleFile(t, c.target, time.Hour)
		swapDir := c.target + "." + c.label + ".orig"
		script := fmt.Sprintf("mv %s %s; mkdir %s; printf 'live-successor %d\\n' > %s/owner; touch -m -c %s",
			sq(t, c.target), sq(t, swapDir), sq(t, c.target), time.Now().Unix(), sq(t, c.target), sq(t, c.target))
		swap := filepath.Join(t.TempDir(), "swap.sh")
		if err := os.WriteFile(swap, []byte(script), 0o600); err != nil {
			t.Fatalf("failed to write swap script: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(swapDir) })

		injected := pauseAt(t, remoteLockAcquireCmd(c.res, "contender"), `mv "`+c.pathVar+`" "$os_ren"`, ". "+swap+"; ")
		if code, out := runShell(t, bounded(injected)); code == 0 {
			t.Fatalf("%s: displaced a successor appearing during reclaim: out=%s", c.label, out)
		}
		assertLockOwnerEquals(t, c.target, "live-successor", c.label+" successor kept")
		if fi, err := os.Lstat(c.target); err != nil || !fi.IsDir() {
			t.Fatalf("%s: successor not a directory at canonical path: err=%v", c.label, err)
		}
		if _, err := os.Lstat(filepath.Join(swapDir, filepath.Base(c.target))); err == nil {
			t.Fatalf("%s: successor nested into staging instead of canonical path", c.label)
		}
	})
}

// TestRemoteLock_StagingReplacementRefused guards a demonstrated counterexample: after the
// reclaim rename a foreign directory at the staging name must be refused, never promoted
// onto the canonical path by mv's directory-into-absent-path semantics.
func TestRemoteLock_StagingReplacementRefused(t *testing.T) {
	res, lockPath := scratchLock(t)
	staleFile(t, lockPath, time.Hour)
	injected := pauseAt(t, remoteLockAcquireCmd(res, "contender"),
		`mv "$flock_path" "$os_ren" 2>/dev/null; then os_ren_ino=$(stat`,
		`rm -rf "$os_ren" 2>/dev/null; mkdir "$os_ren" 2>/dev/null; printf 'FOREIGN 1\n' > "$os_ren/owner" 2>/dev/null; `)
	if code, out := runShell(t, bounded(injected)); code != 1 || !strings.Contains(out, "concurrent replacement") {
		t.Fatalf("expected refusal for staging replacement, got exit=%d out=%s", code, out)
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("foreign staging object was promoted onto the canonical lock path")
	}
}

// TestRemoteLock_ConcurrentContendersPreserveMutualExclusion repeats acquire/release under
// contention, proving exclusion and that cleanup leaves the path reusable.
func TestRemoteLock_ConcurrentContendersPreserveMutualExclusion(t *testing.T) {
	res, lockPath := scratchLock(t)
	var inside, maxInside, failures atomic.Int32
	cycle := func(token string) bool {
		if out, err := exec.Command("bash", "-c", remoteLockAcquireCmd(res, token)).CombinedOutput(); err != nil {
			failures.Add(1)
			t.Logf("%s acquire: %v out=%s", token, err, out)
			return false
		}
		now := inside.Add(1)
		for seen := maxInside.Load(); now > seen; seen = maxInside.Load() {
			if maxInside.CompareAndSwap(seen, now) {
				break
			}
		}
		inside.Add(-1)
		if out, err := exec.Command("bash", "-c", remoteLockReleaseCmd(res, token)).CombinedOutput(); err != nil {
			failures.Add(1)
			t.Logf("%s release: %v out=%s", token, err, out)
			return false
		}
		return true
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for round := 0; round < 3; round++ {
				if !cycle(fmt.Sprintf("contender-%d", idx)) {
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if got := failures.Load(); got != 0 {
		t.Fatalf("%d contender operations failed", got)
	}
	if got := maxInside.Load(); got != 1 {
		t.Fatalf("mutual exclusion violated: %d concurrent holders", got)
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("repeated acquire/release left residue at %s", lockPath)
	}
}
