package awg_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
)

// This file holds the shell-script contention test together with the diagnostics a
// contention failure needs, so a CI failure is attributable instead of just red.
//
// The original assertions are unchanged: five workers compete for the same lock, at most
// one may be inside the critical section at a time, and the stale-lock and ownership
// invariants hold exactly as before. What is added is observation only - every worker
// records when its acquire completed and when its release started and finished, together
// with the owner record, the lock and gate directories, and a wall-clock comparison
// against those directories' modification times.
//
// The lock root is redirected into this test's own scratch directory, so the diagnostics
// cannot be confused by, and cannot disturb, artefacts from other tests or sessions that
// use the shared production lock path.
//
// An inode number is recorded as a supplementary hint only. On several filesystems an
// inode can be reused immediately after removal, so it is never treated as authority for
// which lock generation an observation belongs to.

// issue872AuditCap bounds the diagnostic trail so a failure report stays readable.
const issue872AuditCap = 512

// issue872Audit is a bounded, ordered, mutex-guarded observation trail.
type issue872Audit struct {
	mu      sync.Mutex
	lines   []string
	dropped int
}

func (a *issue872Audit) recordf(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.lines) >= issue872AuditCap {
		a.dropped++
		return
	}
	a.lines = append(a.lines, fmt.Sprintf(format, args...))
}

func (a *issue872Audit) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	var b strings.Builder
	for _, line := range a.lines {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	if a.dropped > 0 {
		fmt.Fprintf(&b, "  ... %d further observation(s) omitted by the bounded audit trail\n", a.dropped)
	}
	return b.String()
}

// issue872InodeOf reports a file's inode as a supplementary hint, or 0 when the platform
// does not expose one.
func issue872InodeOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// issue872LockObservation describes the lock artefacts as one wall-clock sample sees
// them, including how far the directories' modification times sit behind the wall clock.
func issue872LockObservation(lockPath string) string {
	gatePath := lockPath + ".gate"
	now := time.Now()
	parts := []string{fmt.Sprintf("wall=%d", now.Unix())}

	for _, probe := range []struct{ label, path string }{
		{label: "lock", path: lockPath},
		{label: "gate", path: gatePath},
	} {
		info, err := os.Stat(probe.path)
		switch {
		case err == nil:
			mtime := info.ModTime().Unix()
			parts = append(parts, fmt.Sprintf("%s=present mtime=%d mtime-skew=%ds inode=%d",
				probe.label, mtime, now.Unix()-mtime, issue872InodeOf(info)))
		case os.IsNotExist(err):
			parts = append(parts, probe.label+"=absent")
		default:
			parts = append(parts, fmt.Sprintf("%s=stat-error:%v", probe.label, err))
		}
	}

	owner := "absent"
	if raw, err := os.ReadFile(filepath.Join(lockPath, "owner")); err == nil {
		owner = strings.TrimSpace(string(raw))
	}
	parts = append(parts, fmt.Sprintf("owner=%q", owner))

	return strings.Join(parts, " ")
}

// issue872RedirectLockPath rewrites the production lock path of one generated command to
// this test's own scratch directory, and proves that nothing else changed.
func issue872RedirectLockPath(t *testing.T, cmd, prodLockPath, scratchLockPath string) string {
	t.Helper()

	if !strings.Contains(cmd, prodLockPath) {
		t.Fatalf("generated lock command does not reference the production lock path %q:\n%s", prodLockPath, cmd)
	}
	redirected := strings.ReplaceAll(cmd, prodLockPath, scratchLockPath)
	if restored := strings.ReplaceAll(redirected, scratchLockPath, prodLockPath); restored != cmd {
		t.Fatalf("lock path redirection altered more than the lock path of the generated command:\nproduction:\n%s\nredirected:\n%s", cmd, redirected)
	}
	return redirected
}

func TestRemoteLock_ShellScriptContentionAndStaleLockReclamation(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	serverID := int64(8888)
	prodLockPath := awg.RemoteLockPath(serverID)
	lockPath := filepath.Join(t.TempDir(), filepath.Base(prodLockPath))

	ctx := context.Background()
	audit := &issue872Audit{}
	audit.recordf("lock root: production %q redirected to owned scratch %q", prodLockPath, lockPath)

	acquireCmdFor := func(token string) string {
		return issue872RedirectLockPath(t, awg.RemoteLockAcquireCmd(serverID, token), prodLockPath, lockPath)
	}
	releaseCmdFor := func(token string) string {
		return issue872RedirectLockPath(t, awg.RemoteLockReleaseCmd(serverID, token), prodLockPath, lockPath)
	}

	// 1. Verify contention: run 5 workers concurrently competing for the lock
	const numWorkers = 5
	var (
		activeWorkers atomic.Int32
		maxConcurrent atomic.Int32
		wg            sync.WaitGroup
	)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			token := fmt.Sprintf("worker-%d-%d", wID, time.Now().UnixNano())

			audit.recordf("worker %d acquire start token=%s %s", wID, token, issue872LockObservation(lockPath))
			out, err := exec.CommandContext(ctx, "bash", "-c", acquireCmdFor(token)).CombinedOutput()
			audit.recordf("worker %d acquire done token=%s err=%v out=%q %s",
				wID, token, err, strings.TrimSpace(string(out)), issue872LockObservation(lockPath))
			if err != nil {
				t.Errorf("worker %d failed to acquire lock: %v (out: %s)\ncontention audit trail:\n%s",
					wID, err, string(out), audit.String())
				return
			}

			// In critical section
			curr := activeWorkers.Add(1)
			for {
				max := maxConcurrent.Load()
				if curr > max {
					if maxConcurrent.CompareAndSwap(max, curr) {
						break
					}
				} else {
					break
				}
			}
			audit.recordf("worker %d critical-section enter active=%d max=%d %s",
				wID, curr, maxConcurrent.Load(), issue872LockObservation(lockPath))

			time.Sleep(50 * time.Millisecond)
			activeWorkers.Add(-1)
			audit.recordf("worker %d critical-section exit active=%d %s",
				wID, activeWorkers.Load(), issue872LockObservation(lockPath))

			audit.recordf("worker %d release start token=%s %s", wID, token, issue872LockObservation(lockPath))
			relOut, relErr := exec.CommandContext(ctx, "bash", "-c", releaseCmdFor(token)).CombinedOutput()
			audit.recordf("worker %d release done token=%s err=%v out=%q %s",
				wID, token, relErr, strings.TrimSpace(string(relOut)), issue872LockObservation(lockPath))
			if relErr != nil {
				t.Errorf("worker %d failed to release lock: %v (out: %s)\ncontention audit trail:\n%s",
					wID, relErr, string(relOut), audit.String())
			}
		}(i)
	}

	wg.Wait()

	if max := maxConcurrent.Load(); max > 1 {
		t.Fatalf("expected mutual exclusion under contention, but max concurrent was %d\ncontention audit trail:\n%s",
			max, audit.String())
	}

	// 2. Verify stale lock reclamation & explicit ownership protection
	if err := os.Mkdir(lockPath, 0755); err != nil {
		t.Fatalf("failed to create stale lock dir: %v\ncontention audit trail:\n%s", err, audit.String())
	}
	oldOwnerToken := "stale-owner-token"
	ownerFile := filepath.Join(lockPath, "owner")
	if err := os.WriteFile(ownerFile, []byte(oldOwnerToken+"\n"), 0644); err != nil {
		t.Fatalf("failed to write owner file: %v\ncontention audit trail:\n%s", err, audit.String())
	}

	// Set directory mtime to 120 seconds in the past (> 60 seconds stale threshold)
	pastTime := time.Now().Add(-120 * time.Second)
	if err := os.Chtimes(lockPath, pastTime, pastTime); err != nil {
		t.Fatalf("failed to set past mtime: %v\ncontention audit trail:\n%s", err, audit.String())
	}
	audit.recordf("stale lock prepared with 120s-old mtime %s", issue872LockObservation(lockPath))

	newToken := "successor-token"
	out, err := exec.CommandContext(ctx, "bash", "-c", acquireCmdFor(newToken)).CombinedOutput()
	audit.recordf("stale reclaimer acquire done token=%s err=%v out=%q %s",
		newToken, err, strings.TrimSpace(string(out)), issue872LockObservation(lockPath))
	if err != nil {
		t.Fatalf("failed to reclaim stale lock: %v (out: %s)\ncontention audit trail:\n%s", err, string(out), audit.String())
	}

	// Lock dir must exist with the new token
	ownerData, err := os.ReadFile(ownerFile)
	if err != nil {
		t.Fatalf("failed to read owner file after reclamation: %v\ncontention audit trail:\n%s", err, audit.String())
	}
	if fields := strings.Fields(string(ownerData)); len(fields) == 0 || fields[0] != newToken {
		t.Fatalf("expected owner token %s, got: %s\ncontention audit trail:\n%s",
			newToken, strings.TrimSpace(string(ownerData)), audit.String())
	}

	// Old stale owner attempts release using old token - MUST NOT delete successor's lock!
	audit.recordf("stale owner release start token=%s %s", oldOwnerToken, issue872LockObservation(lockPath))
	relOut, relErr := exec.CommandContext(ctx, "bash", "-c", releaseCmdFor(oldOwnerToken)).CombinedOutput()
	audit.recordf("stale owner release done token=%s err=%v out=%q %s",
		oldOwnerToken, relErr, strings.TrimSpace(string(relOut)), issue872LockObservation(lockPath))
	if relErr != nil {
		t.Fatalf("stale release command failed: %v (out: %s)\ncontention audit trail:\n%s", relErr, string(relOut), audit.String())
	}

	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Fatalf("stale owner release erroneously removed successor's lock!\ncontention audit trail:\n%s", audit.String())
	}

	// Successor releases with its valid token: MUST remove lock dir
	audit.recordf("successor release start token=%s %s", newToken, issue872LockObservation(lockPath))
	succOut, succErr := exec.CommandContext(ctx, "bash", "-c", releaseCmdFor(newToken)).CombinedOutput()
	audit.recordf("successor release done token=%s err=%v out=%q %s",
		newToken, succErr, strings.TrimSpace(string(succOut)), issue872LockObservation(lockPath))
	if succErr != nil {
		t.Fatalf("successor release failed: %v (out: %s)\ncontention audit trail:\n%s", succErr, string(succOut), audit.String())
	}

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("expected lock dir to be deleted after valid successor release\ncontention audit trail:\n%s", audit.String())
	}

	if t.Failed() {
		t.Logf("contention audit trail:\n%s", audit.String())
	}
}
