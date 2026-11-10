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

// These tests run the real shell builders under /bin/bash against disposable scratch
// lock paths. They cover the non-directory obstruction that strands acquisition and
// assert that ownership safeguards hold: a live owner is never displaced, symlink
// targets are never followed, and unsafe objects fail closed.

// scratchLock returns a unique resource and its canonical lock path, starting absent so
// a pre-existing host object can never be reclaimed by accident.
func scratchLock(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}
	res := fmt.Sprintf("objstale_%d_%d", time.Now().UnixNano(), os.Getpid())
	lockPath := remoteLockPath(res)
	if _, err := os.Lstat(lockPath); err == nil {
		t.Skipf("refusing to reuse pre-existing lock path %s", lockPath)
	}
	t.Cleanup(func() { _ = os.RemoveAll(lockPath); _ = os.RemoveAll(lockPath + ".gate") })
	return res, lockPath
}

func runShell(t *testing.T, cmd string) (int, string) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "bash", "-c", cmd).CombinedOutput()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out)
	}
	return 0, string(out)
}

// boundedAcquire shortens only the waiting budget, so "must keep refusing" cases stay
// cheap while the script text itself stays production-identical.
func boundedAcquire(res string) string {
	return strings.Replace(remoteLockAcquireCmd(res, "contender"), "timeout=30", "timeout=2", 1)
}

// expectRefused requires a bounded acquisition to fail closed with want in its output.
func expectRefused(t *testing.T, res, want string) {
	t.Helper()
	code, out := runShell(t, boundedAcquire(res))
	if code != 1 || !strings.Contains(out, want) {
		t.Fatalf("expected fail-closed refusal containing %q, got exit=%d out=%s", want, code, out)
	}
}

func staleFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	if err := os.WriteFile(path, []byte("poison\n"), 0o644); err != nil {
		t.Fatalf("failed to create obstruction at %s: %v", path, err)
	}
	past := time.Now().Add(-age)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatalf("failed to backdate %s: %v", path, err)
	}
}

// TestRemoteLock_ReclaimsStaleRegularFile covers the demonstrated outage shape: a stale
// non-directory at the lock or gate path must be reclaimed so acquisition proceeds.
func TestRemoteLock_ReclaimsStaleRegularFile(t *testing.T) {
	for _, atGate := range []bool{false, true} {
		name := "LockPath"
		if atGate {
			name = "GatePath"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			res, lockPath := scratchLock(t)
			target := lockPath
			if atGate {
				target += ".gate"
			}
			staleFile(t, target, time.Hour)

			token := "reclaimer-" + name
			if code, out := runShell(t, remoteLockAcquireCmd(res, token)); code != 0 {
				t.Fatalf("acquire over stale regular file at %s failed: exit=%d out=%s", name, code, out)
			}
			assertLockOwnerEquals(t, lockPath, token, "after reclaiming regular file at "+name)
			if _, err := os.Lstat(target); err == nil && atGate {
				t.Fatalf("gate obstruction still present after acquisition")
			}
			releaseLockAssertSuccess(t, ctx, res, token)
			if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
				t.Fatalf("lock path still present after release")
			}
		})
	}
}

// TestRemoteLock_RecentOrHeldObjectsArePreserved proves age alone is not ownership
// proof: a young regular file and a live directory owner both keep blocking.
func TestRemoteLock_RecentOrHeldObjectsArePreserved(t *testing.T) {
	t.Run("RecentRegularFile", func(t *testing.T) {
		res, lockPath := scratchLock(t)
		staleFile(t, lockPath, 0)
		expectRefused(t, res, "timed out waiting for remote lock")
		if fi, err := os.Lstat(lockPath); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("recent obstruction removed or retyped: err=%v", err)
		}
	})
	t.Run("LiveDirectoryOwner", func(t *testing.T) {
		res, lockPath := scratchLock(t)
		setupAbandonedStaleLock(t, lockPath, "live-owner", 0)
		expectRefused(t, res, "timed out waiting for remote lock")
		assertLockOwnerEquals(t, lockPath, "live-owner", "live owner preserved")
		releaseLockAssertSuccess(t, context.Background(), res, "live-owner")
	})
	t.Run("ForeignOwnerSurvivesRelease", func(t *testing.T) {
		ctx := context.Background()
		res, lockPath := scratchLock(t)
		if code, out := runShell(t, remoteLockAcquireCmd(res, "original-owner")); code != 0 {
			t.Fatalf("acquire failed: exit=%d out=%s", code, out)
		}
		// Lost ownership: a successor owns the directory under a different token.
		if err := os.WriteFile(filepath.Join(lockPath, "owner"), []byte("successor 1\n"), 0o644); err != nil {
			t.Fatalf("failed to rewrite owner: %v", err)
		}
		releaseLockAssertSuccess(t, ctx, res, "original-owner")
		assertLockOwnerEquals(t, lockPath, "successor", "foreign owner survived non-owner release")
	})
}

// TestRemoteLock_UnsafeObjectsFailClosed covers objects the protocol cannot justify:
// they are refused with a bounded error, never followed, and never removed.
func TestRemoteLock_UnsafeObjectsFailClosed(t *testing.T) {
	t.Run("SymlinkAtLockPath", func(t *testing.T) {
		res, lockPath := scratchLock(t)
		target := filepath.Join(t.TempDir(), "symlink-target")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatalf("failed to create symlink target: %v", err)
		}
		if err := os.WriteFile(filepath.Join(target, "owner"), []byte("sentinel\n"), 0o644); err != nil {
			t.Fatalf("failed to seed sentinel: %v", err)
		}
		if err := os.Symlink(target, lockPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}
		expectRefused(t, res, "unsafe symbolic link")
		if fi, err := os.Lstat(lockPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink at lock path was modified: err=%v", err)
		}
		if data, err := os.ReadFile(filepath.Join(target, "owner")); err != nil || strings.TrimSpace(string(data)) != "sentinel" {
			t.Fatalf("symlink target followed or altered: data=%q err=%v", data, err)
		}
	})
	t.Run("FifoAtLockPath", func(t *testing.T) {
		res, lockPath := scratchLock(t)
		if _, err := exec.LookPath("mkfifo"); err != nil {
			t.Skip("mkfifo not available on this environment")
		}
		if err := exec.Command("mkfifo", lockPath).Run(); err != nil {
			t.Fatalf("failed to create fifo: %v", err)
		}
		expectRefused(t, res, "unsafe object")
		if _, err := os.Lstat(lockPath); err != nil {
			t.Fatalf("unsafe object was removed instead of refused: %v", err)
		}
	})
}

// TestRemoteLock_HeartbeatNeverCreatesLockObject closes the creation race that seeds the
// obstruction: `touch -m` creates a zero-byte file when the path is absent.
func TestRemoteLock_HeartbeatNeverCreatesLockObject(t *testing.T) {
	res, lockPath := scratchLock(t)
	hb := remoteLockHeartbeatCmd(res, "absent-token")
	if !strings.Contains(hb, "touch -m -c ") {
		t.Fatalf("heartbeat must use touch -c so it cannot create the lock object: %s", hb)
	}
	if code, out := runShell(t, hb); code != 0 {
		t.Fatalf("heartbeat on absent lock failed: exit=%d out=%s", code, out)
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("heartbeat created an object at the absent lock path")
	}
	// Control: the replaced unguarded form does create that file, so the assertion is
	// discriminating rather than vacuous.
	probe := filepath.Join(t.TempDir(), "probe.lock")
	if code, out := runShell(t, "touch -m "+probe); code != 0 {
		t.Fatalf("control touch failed: exit=%d out=%s", code, out)
	}
	if _, err := os.Lstat(probe); err != nil {
		t.Fatalf("control touch -m created nothing, so the guard assertion is vacuous: %v", err)
	}

	// A heartbeat landing after release removed the lock must also create nothing.
	ctx := context.Background()
	if code, out := runShell(t, remoteLockAcquireCmd(res, "delayed-heartbeat")); code != 0 {
		t.Fatalf("acquire failed: exit=%d out=%s", code, out)
	}
	releaseLockAssertSuccess(t, ctx, res, "delayed-heartbeat")
	if code, out := runShell(t, remoteLockHeartbeatCmd(res, "delayed-heartbeat")); code != 0 {
		t.Fatalf("delayed heartbeat failed: exit=%d out=%s", code, out)
	}
	if _, err := os.Lstat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("heartbeat racing release recreated an obstruction at the lock path")
	}
}

// TestRemoteLock_ReplacementDuringReclaimPreservesSuccessor stalls the reclaimer between
// inspection and rename, installs a live successor in that window, and requires the
// reclaimer to put the successor back instead of acquiring over it.
func TestRemoteLock_ReplacementDuringReclaimPreservesSuccessor(t *testing.T) {
	res, lockPath := scratchLock(t)
	staleFile(t, lockPath, time.Hour)

	// The lock-path branch is targeted specifically: the gate branch has the same shape
	// with $gate_path, so the anchor must name $flock_path to stay unique.
	anchor := `if [ -n "$os_ino" ] && mv "$flock_path"`
	if !strings.Contains(remoteLockAcquireCmd(res, "x"), anchor) {
		t.Fatalf("acquire command missing lock-path reclaim anchor")
	}
	swap := filepath.Join(t.TempDir(), "swap.sh")
	script := fmt.Sprintf(`rm -f %[1]q; mkdir %[1]q; printf 'live-successor %[2]d\n' > %[1]q/owner; touch -m -c %[1]q`,
		lockPath, time.Now().Unix())
	if err := os.WriteFile(swap, []byte(script), 0o600); err != nil {
		t.Fatalf("failed to write swap script: %v", err)
	}
	injected := strings.Replace(remoteLockAcquireCmd(res, "contender"), anchor, ". "+swap+"; "+anchor, 1)
	if code, out := runShell(t, strings.Replace(injected, "timeout=30", "timeout=2", 1)); code == 0 {
		t.Fatalf("displaced a successor that appeared during reclaim: out=%s", out)
	}
	assertLockOwnerEquals(t, lockPath, "live-successor", "successor restored after reclaim race")
}

// TestRemoteLock_ConcurrentContendersPreserveMutualExclusion repeats acquire/release
// under contention, proving exclusion and that cleanup leaves the path reusable.
func TestRemoteLock_ConcurrentContendersPreserveMutualExclusion(t *testing.T) {
	res, lockPath := scratchLock(t)
	var inside, maxInside, failures atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token := fmt.Sprintf("contender-%d", idx)
			for round := 0; round < 3; round++ {
				if out, err := exec.Command("bash", "-c", remoteLockAcquireCmd(res, token)).CombinedOutput(); err != nil {
					failures.Add(1)
					t.Logf("contender %d round %d acquire: %v out=%s", idx, round, err, out)
					return
				}
				for now := inside.Add(1); ; {
					if seen := maxInside.Load(); now <= seen || maxInside.CompareAndSwap(seen, now) {
						break
					}
				}
				inside.Add(-1)
				if out, err := exec.Command("bash", "-c", remoteLockReleaseCmd(res, token)).CombinedOutput(); err != nil {
					failures.Add(1)
					t.Logf("contender %d round %d release: %v out=%s", idx, round, err, out)
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
