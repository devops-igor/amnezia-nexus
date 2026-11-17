package awg

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

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

// This file holds the simultaneous stale-gate test together with the observations a
// recurrence needs in order to be attributable.
//
// The assertions are the originals: three reclaimers race one 20 s-old stale gate, the
// lock is held for 50 ms, each holder's ownership record must name that holder, and at
// most one participant may be inside the critical section at any moment.
//
// What is added is observation only, at the points where a gate race is decided: the
// canonical mkdir that admits a participant, the trailing ownership publication, the
// acquire subprocess exit, the release begin, and the release exit. Every entry carries
// the participant token, a wall clock, the owner record as it read at that instant, and
// whether the canonical directory and the gate directory existed with what modification
// time. Inode numbers are recorded as a supplementary hint only: an inode can be reused
// immediately after removal, so it is never treated as proof of which lock generation an
// observation belongs to, and the wall clock and mtimes are samples, not an atomic
// generation check.
//
// The executable shell is unchanged apart from the lock root: every insertion is a
// self-contained statement, and each instrumented command is proven to reduce back to the
// redirected generated command when those statements are removed.

const (
	// gateObsAcquireCreated is recorded when a participant's canonical mkdir succeeded.
	gateObsAcquireCreated = "MKOK"
	// gateObsOwnerPublished is recorded when the trailing ownership write completed.
	gateObsOwnerPublished = "OWNPUB"
	// gateObsReleaseBegin is recorded when a participant's release entered its removal branch.
	gateObsReleaseBegin = "RELBEGIN"

	// gateObsCap bounds the in-process trail so a failure report stays readable.
	gateObsCap = 512
)

// gateObsAudit is the bounded, ordered in-process observation trail.
type gateObsAudit struct {
	mu      sync.Mutex
	lines   []string
	dropped int
}

func (a *gateObsAudit) recordf(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.lines) >= gateObsCap {
		a.dropped++
		return
	}
	a.lines = append(a.lines, fmt.Sprintf(format, args...))
}

func (a *gateObsAudit) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	var b strings.Builder
	for _, line := range a.lines {
		b.WriteString("  ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	if a.dropped > 0 {
		fmt.Fprintf(&b, "  ... %d further observation(s) omitted by the bounded trail\n", a.dropped)
	}
	return b.String()
}

// gateObsInodeOf reports an inode as a supplementary hint only.
func gateObsInodeOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// gateObsState describes the lock artefacts as one sample sees them now.
func gateObsState(lockPath, gatePath string) string {
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
				probe.label, mtime, now.Unix()-mtime, gateObsInodeOf(info)))
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

// gateObsShellRecord returns a shell statement that appends one observation from inside a
// generated command, so the recorded instant is the protocol's own.
func gateObsShellRecord(kind, token, journalPath, lockPath, gatePath string) string {
	owner := fmt.Sprintf(`"$(cat %s/owner 2>/dev/null)"`, ssh.EscapeShellArg(lockPath))
	lockPresence := fmt.Sprintf(`"$([ -d %s ] && echo present || echo absent)"`, ssh.EscapeShellArg(lockPath))
	gatePresence := fmt.Sprintf(`"$([ -d %s ] && echo present || echo absent)"`, ssh.EscapeShellArg(gatePath))

	return fmt.Sprintf(
		`go_ts=$(date +%%s%%N 2>/dev/null); case "$go_ts" in ''|*[!0-9]*) go_ts=$(date +%%s) ;; esac; printf '%%s %%s %%s owner=%%s lock=%%s gate=%%s\n' %s "$go_ts" %s %s %s %s >> %s`,
		ssh.EscapeShellArg(kind),
		ssh.EscapeShellArg(token),
		owner,
		lockPresence,
		gatePresence,
		ssh.EscapeShellArg(journalPath),
	)
}

// gateObsRedirectRoot rewrites the production lock root of one generated command to this
// test's own scratch directory, and proves that nothing else changed.
func gateObsRedirectRoot(t *testing.T, cmd, prodLockPath, scratchLockPath string) string {
	t.Helper()

	if !strings.Contains(cmd, prodLockPath) {
		t.Fatalf("generated lock command does not reference the production lock path %q:\n%s", prodLockPath, cmd)
	}
	redirected := strings.ReplaceAll(cmd, prodLockPath, scratchLockPath)
	if restored := strings.ReplaceAll(redirected, scratchLockPath, prodLockPath); restored != cmd {
		t.Fatalf("lock root redirection altered more than the lock path:\nproduction:\n%s\nredirected:\n%s", cmd, redirected)
	}
	return redirected
}

// gateObsInsert inserts one observation statement at a unique anchor and returns the new
// command together with the exact text that was inserted.
func gateObsInsert(t *testing.T, cmd, anchor, inserted string) (string, string) {
	t.Helper()

	if got := strings.Count(cmd, anchor); got != 1 {
		t.Fatalf("expected exactly 1 anchor for observation insertion, found %d:\nanchor: %q", got, anchor)
	}
	return strings.Replace(cmd, anchor, anchor+inserted, 1), inserted
}

// gateObsAssertRemovable proves the instrumentation is purely observational: removing
// every inserted statement reproduces the generated command byte for byte, so the
// executable shell is the production one apart from the redirected lock root.
func gateObsAssertRemovable(t *testing.T, instrumented, redirected string, inserted []string) {
	t.Helper()

	reduced := instrumented
	for _, statement := range inserted {
		reduced = strings.ReplaceAll(reduced, statement, "")
	}
	if reduced != redirected {
		t.Fatalf("instrumentation is not purely observational: removing the inserted statements does not reproduce the generated command\ninstrumented:\n%s\nreduced:\n%s\ngenerated:\n%s",
			instrumented, reduced, redirected)
	}
}

// gateObsInstrumentAcquire adds the canonical-mkdir and ownership-publication
// observations to an already redirected acquire command.
func gateObsInstrumentAcquire(t *testing.T, cmd, token, journalPath, lockPath, gatePath string) (string, []string) {
	t.Helper()

	var inserted []string

	// The canonical mkdir that admits this participant. Anchored on the preceding gate
	// owner write so it is distinguished from the identical mkdir inside the stale-lock
	// reclaim branches.
	mkdirAnchor := fmt.Sprintf(`echo %s "$g_acq_ts" > "$gate_path/owner" 2>/dev/null; if mkdir "$flock_path" 2>/dev/null; then `,
		ssh.EscapeShellArg(token))
	var statement string
	statement = gateObsShellRecord(gateObsAcquireCreated, token, journalPath, lockPath, gatePath) + "; "
	cmd, used := gateObsInsert(t, cmd, mkdirAnchor, statement)
	inserted = append(inserted, used)

	// The trailing path-based ownership publication, the last statement of the script.
	// The redirect operator makes this anchor unique to that write.
	cmd, used = gateObsInsert(t, cmd, `> "$flock_path/owner"`,
		"; "+gateObsShellRecord(gateObsOwnerPublished, token, journalPath, lockPath, gatePath))
	inserted = append(inserted, used)

	return cmd, inserted
}

// gateObsInstrumentRelease adds the release-begin observation to an already redirected
// release command. The record is inserted between the ownership check and the removal
// call, so it observes the release while the lock is still held and before anything is
// taken away.
func gateObsInstrumentRelease(t *testing.T, cmd, token, journalPath, lockPath, gatePath string) (string, []string) {
	t.Helper()

	statement := gateObsShellRecord(gateObsReleaseBegin, token, journalPath, lockPath, gatePath) + "; "
	instrumented, used := gateObsInsert(t, cmd, "; then ", statement)
	return instrumented, []string{used}
}

// gateObsJournalLines returns the shell-side observations written so far.
func gateObsJournalLines(journalPath string) []string {
	raw, err := os.ReadFile(journalPath)
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// gateObsCountKind counts shell-side observations of one kind for one token.
func gateObsCountKind(lines []string, kind, token string) int {
	count := 0
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == kind && fields[2] == token {
			count++
		}
	}
	return count
}

// gateObsReport renders everything a recurrence needs: the in-process trail, the
// shell-side observations and a final sample of the artefacts.
func gateObsReport(audit *gateObsAudit, journalPath, lockPath, gatePath string) string {
	var b strings.Builder
	b.WriteString("observation trail (in-process, ordered):\n")
	b.WriteString(audit.String())

	b.WriteString("shell observations (")
	b.WriteString(journalPath)
	b.WriteString("):\n")
	if lines := gateObsJournalLines(journalPath); len(lines) > 0 {
		for _, line := range lines {
			b.WriteString("  ")
			b.WriteString(line)
			b.WriteString("\n")
		}
	} else {
		b.WriteString("  <none written>\n")
	}

	fmt.Fprintf(&b, "final sample: %s\n", gateObsState(lockPath, gatePath))
	return b.String()
}

// TestRemoteLock_SimultaneousGateReclaimers_OnlyOneEntersGate verifies that three
// reclaimers racing one abandoned stale gate still admit at most one of them to the
// canonical lock, and that each admitted holder owns the record it exits on.
func TestRemoteLock_SimultaneousGateReclaimers_OnlyOneEntersGate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	resName := fmt.Sprintf("gate_race_%d", time.Now().UnixNano())
	scratch := t.TempDir()
	prodLockPath := remoteLockPath(resName)
	lockPath := filepath.Join(scratch, filepath.Base(prodLockPath))
	gatePath := lockPath + ".gate"
	journalPath := filepath.Join(scratch, "gate.journal")

	// Setup a stale gate directory (20s old) with crashed owner metadata.
	setupAbandonedStaleGate(t, gatePath, "crashed-gate-token-99", 20*time.Second)

	audit := &gateObsAudit{}
	audit.recordf("lock root: production %q redirected to owned scratch %q", prodLockPath, lockPath)
	audit.recordf("stale gate prepared token=crashed-gate-token-99 %s", gateObsState(lockPath, gatePath))

	tokens := []string{"reclaimer-race-alpha", "reclaimer-race-beta", "reclaimer-race-gamma"}
	const numReclaimers = 3

	acquireCmds := make([]string, numReclaimers)
	releaseCmds := make([]string, numReclaimers)
	for i, tok := range tokens {
		redirectedAcquire := gateObsRedirectRoot(t, remoteLockAcquireCmd(resName, tok), prodLockPath, lockPath)
		acquireCmd, acquireInserted := gateObsInstrumentAcquire(t, redirectedAcquire, tok, journalPath, lockPath, gatePath)
		gateObsAssertRemovable(t, acquireCmd, redirectedAcquire, acquireInserted)
		acquireCmds[i] = acquireCmd

		redirectedRelease := gateObsRedirectRoot(t, remoteLockReleaseCmd(resName, tok), prodLockPath, lockPath)
		releaseCmd, releaseInserted := gateObsInstrumentRelease(t, redirectedRelease, tok, journalPath, lockPath, gatePath)
		gateObsAssertRemovable(t, releaseCmd, redirectedRelease, releaseInserted)
		releaseCmds[i] = releaseCmd
	}

	ctx, cancel := context.WithCancel(context.Background())
	var (
		wg   sync.WaitGroup
		live atomic.Int32
	)

	// Every owned shell and goroutine is joined before the fixture is removed, on the
	// success path and on every failure path.
	t.Cleanup(func() {
		cancel()
		joined := make(chan struct{})
		go func() {
			wg.Wait()
			close(joined)
		}()
		select {
		case <-joined:
		case <-time.After(10 * time.Second):
			t.Errorf("gate reclaimers did not join within 10s of cancellation (%d still live)", live.Load())
		}
	})

	var (
		activeLockHolders atomic.Int32
		maxConcurrent     atomic.Int32
		startGate         = make(chan struct{})
		failuresMu        sync.Mutex
		workerFailures    []string
	)
	// report records a worker failure without blocking and without dropping it. Workers
	// never fail the test themselves, so no assertion is left half-done.
	report := func(err error) {
		failuresMu.Lock()
		workerFailures = append(workerFailures, err.Error())
		failuresMu.Unlock()
	}

	for i := 0; i < numReclaimers; i++ {
		wg.Add(1)
		live.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer live.Add(-1)

			tok := tokens[idx]

			<-startGate
			out, err := exec.CommandContext(ctx, "bash", "-c", acquireCmds[idx]).CombinedOutput()
			audit.recordf("acquire exit token=%s err=%v out=%q %s", tok, err, strings.TrimSpace(string(out)), gateObsState(lockPath, gatePath))
			if err != nil {
				report(fmt.Errorf("reclaimer %s failed to acquire: %w (out: %s)", tok, err, string(out)))
				return
			}

			cur := activeLockHolders.Add(1)
			for {
				oldMax := maxConcurrent.Load()
				if cur <= oldMax || maxConcurrent.CompareAndSwap(oldMax, cur) {
					break
				}
			}
			audit.recordf("hold enter token=%s active=%d max=%d %s", tok, cur, maxConcurrent.Load(), gateObsState(lockPath, gatePath))

			// Hold the lock briefly to expose any overlap
			time.Sleep(50 * time.Millisecond)

			// The owner check reports through the error channel. A worker never fails the
			// test directly, so the hold counter and the release below always complete and
			// the other reclaimers are never left waiting on a lock this one still holds.
			owner, ownerErr := gateObsOwnerSample(lockPath)
			switch {
			case ownerErr != nil:
				report(fmt.Errorf("holder verified: could not read the owner record for %s: %w", tok, ownerErr))
			case owner != tok:
				audit.recordf("owner mismatch token=%s observed=%q %s", tok, owner, gateObsState(lockPath, gatePath))
				report(fmt.Errorf("holder verified: expected owner %s, got %s", tok, owner))
			default:
				audit.recordf("owner verified token=%s observed=%q", tok, owner)
			}

			activeLockHolders.Add(-1)
			audit.recordf("hold exit token=%s active=%d %s", tok, activeLockHolders.Load(), gateObsState(lockPath, gatePath))

			relOut, relErr := exec.CommandContext(ctx, "bash", "-c", releaseCmds[idx]).CombinedOutput()
			audit.recordf("release exit token=%s err=%v out=%q %s", tok, relErr, strings.TrimSpace(string(relOut)), gateObsState(lockPath, gatePath))
			if relErr != nil {
				report(fmt.Errorf("reclaimer %s failed to release: %w (out: %s)", tok, relErr, string(relOut)))
			}
		}(i)
	}

	close(startGate)
	wg.Wait()
	cancel()

	failuresMu.Lock()
	failures := append([]string(nil), workerFailures...)
	failuresMu.Unlock()

	if len(failures) > 0 {
		t.Fatalf("concurrency race failure: %s\n%s", strings.Join(failures, "; "), gateObsReport(audit, journalPath, lockPath, gatePath))
	}

	if max := maxConcurrent.Load(); max != 1 {
		t.Fatalf("MUTUAL EXCLUSION BROKEN on stale gate race: expected maxConcurrent=1, got %d\n%s",
			max, gateObsReport(audit, journalPath, lockPath, gatePath))
	}

	// Each participant must have been admitted exactly once and published its ownership
	// once; that is what makes the observations above attributable to the real protocol.
	journalLines := gateObsJournalLines(journalPath)
	for _, tok := range tokens {
		if got := gateObsCountKind(journalLines, gateObsAcquireCreated, tok); got != 1 {
			t.Fatalf("expected exactly 1 canonical admission for %s, observed %d\n%s",
				tok, got, gateObsReport(audit, journalPath, lockPath, gatePath))
		}
		if got := gateObsCountKind(journalLines, gateObsOwnerPublished, tok); got != 1 {
			t.Fatalf("expected exactly 1 ownership publication for %s, observed %d\n%s",
				tok, got, gateObsReport(audit, journalPath, lockPath, gatePath))
		}
	}

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after all completed\n%s", gateObsReport(audit, journalPath, lockPath, gatePath))
	}
	if _, err := os.Stat(gatePath); !os.IsNotExist(err) {
		t.Fatalf("gate directory still exists after all completed\n%s", gateObsReport(audit, journalPath, lockPath, gatePath))
	}

	if t.Failed() {
		t.Logf("gate race observation trail:\n%s", gateObsReport(audit, journalPath, lockPath, gatePath))
	}
}

// gateObsOwnerSample reads the lock's ownership record as text.
func gateObsOwnerSample(lockPath string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(lockPath, "owner"))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}
