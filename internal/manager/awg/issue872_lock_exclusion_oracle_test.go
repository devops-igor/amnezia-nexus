package awg

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

// This file is the stale-lock exclusion oracle. It replaces a channel-and-sleep
// oracle with one whose exclusion evidence comes from the lock protocol itself:
//
//   - every acquire subprocess appends counted attempt lines and one acquisition
//     line to a single journal, so the ownership sample and the release ordering
//     come from the real shell rather than from a Go channel notification;
//   - the legitimate winner is parked by its own acquire shell immediately after it
//     writes the ownership record, so the exclusion assertions run while the lock is
//     provably held instead of during a fixed sleep;
//   - every other participant must demonstrate a counted number of real acquisition
//     attempts against that held lock before the exclusion assertion is accepted (a
//     counted evidence floor, not a timing budget);
//   - the winner's Go notification is only released afterwards, so a channel event
//     can never stand in for continuous lock ownership.
//
// The production lock source is not modified. The generated acquire and release
// commands are preserved byte for byte apart from the lock root, which is redirected
// into this test's own scratch directory; that restriction is checked structurally
// rather than asserted in prose.

const (
	// issue872EventGateWait records one real retry pass while another token held the gate.
	issue872EventGateWait = "GATEWAIT"
	// issue872EventLockTry records one real retry pass while another token held the lock.
	issue872EventLockTry = "LOCKTRY"
	// issue872EventAcquire records that a token's acquire subprocess reached the point
	// where the lock is its own. The owner field is what the owner file said at that
	// instant, which is a sample, not a continuous claim.
	issue872EventAcquire = "ACQ"
	// issue872EventRelease records that a token's release subprocess ran.
	issue872EventRelease = "REL"

	// issue872RequiredAttempts is the number of journaled retry passes every participant
	// must demonstrably perform against a held resource before the exclusion assertion
	// is accepted. At the protocol's own 50 ms retry interval this is roughly 150 ms of
	// real protocol execution.
	issue872RequiredAttempts = 3

	// issue872AwaitBound bounds every readiness wait. Expiry fails with the full
	// journal; it is never a silent pass. It stays far below the protocol's own 30 s
	// acquisition timeout and 60 s stale window so the oracle cannot change which
	// protocol branch runs.
	issue872AwaitBound = 5 * time.Second

	// issue872PollInterval is the readiness poll interval for journal observations.
	issue872PollInterval = 5 * time.Millisecond

	// issue872GateRetryAnchor is the tail of the gate-contended branch of the generated
	// acquire command. It must occur exactly once or the injection is refused.
	issue872GateRetryAnchor = "sleep 0.05 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; continue;"
	// issue872LockRetryAnchor is the tail of the lock-contended branch.
	issue872LockRetryAnchor = "sleep 0.05 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; done"
)

// issue872JournalEvent is one parsed journal line: a counted attempt or a completed
// acquisition/release observed inside a real subprocess.
type issue872JournalEvent struct {
	kind  string
	token string
	owner string
}

// issue872Participant is one real lock client: an acquire subprocess, its post-acquire
// parking point, and the release subprocess that follows.
type issue872Participant struct {
	token      string
	acquireCmd string
	releaseCmd string
	parkPath   string
	resumePath string
	acquired   chan struct{}
	releaseSig chan struct{}
	done       chan struct{}
	errs       chan error
}

// issue872Oracle owns one scratch lock root, one protocol journal and every client
// competing on that root.
type issue872Oracle struct {
	t            *testing.T
	resName      string
	scratch      string
	prodLockPath string
	lockPath     string
	gatePath     string
	journalPath  string
	gatePark     string
	gateResume   string

	ctx    context.Context
	cancel context.CancelFunc

	participants []issue872Participant
	tokens       []string
	acquired     []chan struct{}
	releaseSig   []chan struct{}
	done         []chan struct{}
	errs         []chan error
	completed    []bool
}

func newIssue872Oracle(t *testing.T, resName string) *issue872Oracle {
	t.Helper()

	scratch := t.TempDir()
	prodLockPath := remoteLockPath(resName)
	lockPath := filepath.Join(scratch, filepath.Base(prodLockPath))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return &issue872Oracle{
		t:            t,
		resName:      resName,
		scratch:      scratch,
		prodLockPath: prodLockPath,
		lockPath:     lockPath,
		gatePath:     lockPath + ".gate",
		journalPath:  filepath.Join(scratch, "lock.journal"),
		gatePark:     filepath.Join(scratch, "gate.park"),
		gateResume:   filepath.Join(scratch, "gate.resume"),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// redirectLockRoot rewrites the production lock root of one generated command to this
// oracle's own scratch root.
//
// The generated command is preserved byte for byte apart from the lock path, and that
// is enforced structurally: substituting the scratch path back must reproduce the
// production command exactly. No other character of the acquire or release shell is
// altered here, and later injections only insert statements of their own.
func (o *issue872Oracle) redirectLockRoot(t *testing.T, cmd string) string {
	t.Helper()

	if !strings.Contains(cmd, o.prodLockPath) {
		t.Fatalf("generated lock command does not reference the production lock path %q:\n%s", o.prodLockPath, cmd)
	}
	redirected := strings.ReplaceAll(cmd, o.prodLockPath, o.lockPath)
	if restored := strings.ReplaceAll(redirected, o.lockPath, o.prodLockPath); restored != cmd {
		t.Fatalf("lock root redirection changed more than the lock path of the generated command:\nproduction:\n%s\nredirected:\n%s", cmd, redirected)
	}
	return redirected
}

// journalRecord returns a shell statement that appends one journal line. The owner
// reading is taken by the shell at that instant.
func issue872JournalRecord(kind, token, journalPath, lockPath string) string {
	ownerSample := fmt.Sprintf(`"$(cat %s/owner 2>/dev/null)"`, ssh.EscapeShellArg(lockPath))
	return fmt.Sprintf(
		`j_ts=$(date +%%s%%N 2>/dev/null); case "$j_ts" in ''|*[!0-9]*) j_ts=$(date +%%s) ;; esac; printf '%%s %%s %%s owner=%%s\n' %s "$j_ts" %s %s >> %s`,
		ssh.EscapeShellArg(kind),
		ssh.EscapeShellArg(token),
		ownerSample,
		ssh.EscapeShellArg(journalPath),
	)
}

// instrumentAcquire inserts the journal and the post-acquisition parking point into an
// already redirected acquire command.
func (o *issue872Oracle) instrumentAcquire(t *testing.T, cmd, token, parkPath, resumePath string) string {
	t.Helper()

	if got := strings.Count(cmd, issue872GateRetryAnchor); got != 1 {
		t.Fatalf("expected exactly 1 gate-retry anchor in the generated acquire command, found %d", got)
	}
	gateTail := strings.TrimSuffix(issue872GateRetryAnchor, "continue;") +
		issue872JournalRecord(issue872EventGateWait, token, o.journalPath, o.lockPath) + "; continue;"
	cmd = strings.Replace(cmd, issue872GateRetryAnchor, gateTail, 1)

	if got := strings.Count(cmd, issue872LockRetryAnchor); got != 1 {
		t.Fatalf("expected exactly 1 lock-retry anchor in the generated acquire command, found %d", got)
	}
	lockTail := strings.TrimSuffix(issue872LockRetryAnchor, " done") +
		issue872JournalRecord(issue872EventLockTry, token, o.journalPath, o.lockPath) + "; done"
	cmd = strings.Replace(cmd, issue872LockRetryAnchor, lockTail, 1)

	// Record the acquisition and park before the shell exits. The lock directory this
	// subprocess just created now belongs to a live shell that only this test releases,
	// which is the same ownership state a caller's heartbeat goroutine maintains.
	acquireRecord := issue872JournalRecord(issue872EventAcquire, token, o.journalPath, o.lockPath)
	park := fmt.Sprintf(`touch %s; while [ ! -f %s ]; do sleep 0.01; done`,
		ssh.EscapeShellArg(parkPath), ssh.EscapeShellArg(resumePath))
	return cmd + "; " + acquireRecord + "; " + park
}

// injectGateBarrier parks an acquire command inside the gate critical section, right
// after it writes the gate owner record and before it inspects the stale lock.
func (o *issue872Oracle) injectGateBarrier(t *testing.T, cmd, token string) string {
	t.Helper()

	anchor := fmt.Sprintf(`echo %s "$g_acq_ts" > "$gate_path/owner" 2>/dev/null;`, ssh.EscapeShellArg(token))
	if got := strings.Count(cmd, anchor); got != 1 {
		t.Fatalf("expected exactly 1 gate owner-write statement in the generated acquire command, found %d:\n%s", got, cmd)
	}
	park := fmt.Sprintf(` touch %s; while [ ! -f %s ]; do sleep 0.01; done;`,
		ssh.EscapeShellArg(o.gatePark), ssh.EscapeShellArg(o.gateResume))
	return strings.Replace(cmd, anchor, anchor+park, 1)
}

// addParticipant registers one real lock client. Registration only builds the byte
// exact (redirected) commands and the parking points; start launches the subprocess.
func (o *issue872Oracle) addParticipant(t *testing.T, token string, gateBarrier bool) {
	t.Helper()

	idx := len(o.participants)
	parkPath := filepath.Join(o.scratch, fmt.Sprintf("acquire-%d.park", idx))
	resumePath := filepath.Join(o.scratch, fmt.Sprintf("acquire-%d.resume", idx))

	acquireCmd := o.redirectLockRoot(t, remoteLockAcquireCmd(o.resName, token))
	if gateBarrier {
		acquireCmd = o.injectGateBarrier(t, acquireCmd, token)
	}
	acquireCmd = o.instrumentAcquire(t, acquireCmd, token, parkPath, resumePath)

	releaseCmd := o.redirectLockRoot(t, remoteLockReleaseCmd(o.resName, token)) + "; " +
		issue872JournalRecord(issue872EventRelease, token, o.journalPath, o.lockPath)

	o.participants = append(o.participants, issue872Participant{
		token:      token,
		acquireCmd: acquireCmd,
		releaseCmd: releaseCmd,
		parkPath:   parkPath,
		resumePath: resumePath,
		acquired:   make(chan struct{}, 1),
		releaseSig: make(chan struct{}, 1),
		done:       make(chan struct{}, 1),
		errs:       make(chan error, 1),
	})
	o.tokens = append(o.tokens, token)
}

// finalize derives the slices the existing contender helpers consume.
func (o *issue872Oracle) finalize(t *testing.T) {
	t.Helper()

	n := len(o.participants)
	o.acquired = make([]chan struct{}, n)
	o.releaseSig = make([]chan struct{}, n)
	o.done = make([]chan struct{}, n)
	o.errs = make([]chan error, n)
	o.completed = make([]bool, n)
	for i, p := range o.participants {
		o.acquired[i] = p.acquired
		o.releaseSig[i] = p.releaseSig
		o.done[i] = p.done
		o.errs[i] = p.errs
	}
}

// start runs one participant's acquire subprocess, then its release subprocess once
// the oracle signals it.
func (o *issue872Oracle) start(t *testing.T, idx int) {
	t.Helper()

	p := o.participants[idx]
	go func() {
		out, err := exec.CommandContext(o.ctx, "bash", "-c", p.acquireCmd).CombinedOutput()
		if err != nil {
			p.errs <- fmt.Errorf("acquire failed: %w (out: %s)", err, strings.TrimSpace(string(out)))
			return
		}
		p.acquired <- struct{}{}
		<-p.releaseSig
		relOut, relErr := exec.CommandContext(o.ctx, "bash", "-c", p.releaseCmd).CombinedOutput()
		if relErr != nil {
			p.errs <- fmt.Errorf("release failed: %w (out: %s)", relErr, strings.TrimSpace(string(relOut)))
		}
		p.done <- struct{}{}
	}()
}

// events parses the journal. A missing journal is an empty journal; a journal that
// cannot be read surfaces through the diagnostics of whichever wait expires.
func (o *issue872Oracle) events() []issue872JournalEvent {
	raw, err := os.ReadFile(o.journalPath)
	if err != nil {
		return nil
	}

	var events []issue872JournalEvent
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 4)
		if len(parts) < 4 {
			continue
		}
		events = append(events, issue872JournalEvent{
			kind:  parts[0],
			token: parts[2],
			owner: strings.TrimPrefix(parts[3], "owner="),
		})
	}
	return events
}

func (o *issue872Oracle) countByKind(kind string) map[string]int {
	counts := make(map[string]int, len(o.tokens))
	for _, ev := range o.events() {
		if ev.kind == kind {
			counts[ev.token]++
		}
	}
	return counts
}

// journalText returns the raw journal. A missing journal is reported as such rather
// than as an empty timeline.
func (o *issue872Oracle) journalText() string {
	raw, err := os.ReadFile(o.journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "<no journal written yet>"
		}
		return fmt.Sprintf("<unreadable: %v>", err)
	}
	return strings.TrimSpace(string(raw))
}

// diagnostics reports the journal and the current owner file. The owner reading is
// explicitly a sample taken now, not at event time, and each journal line carries the
// sample that was taken at that event.
func (o *issue872Oracle) diagnostics() string {
	journal := o.journalText()

	owner := "absent"
	switch raw, err := os.ReadFile(filepath.Join(o.lockPath, "owner")); {
	case err == nil:
		owner = strings.TrimSpace(string(raw))
	case !os.IsNotExist(err):
		owner = fmt.Sprintf("<unreadable: %v>", err)
	}

	return fmt.Sprintf("lock journal (%s):\n%s\nowner file sampled now, not at event time: %q",
		o.journalPath, journal, owner)
}

// await polls cond until it holds, failing with the full journal on a participant
// error or on expiry. Every wait in this file goes through it, so no readiness wait
// can silently pass.
func (o *issue872Oracle) await(what string, cond func() bool) {
	o.t.Helper()

	deadline := time.Now().Add(issue872AwaitBound)
	for {
		if cond() {
			return
		}
		for i, errs := range o.errs {
			select {
			case err := <-errs:
				o.t.Fatalf("waiting for %s: participant %q reported an error: %v\n%s",
					what, o.tokens[i], err, o.diagnostics())
			default:
			}
		}
		if time.Now().After(deadline) {
			o.t.Fatalf("timed out after %v waiting for %s\n%s", issue872AwaitBound, what, o.diagnostics())
		}
		time.Sleep(issue872PollInterval)
	}
}

// assertNoParticipantError surfaces a release failure that the legacy contender
// helper cannot report.
func (o *issue872Oracle) assertNoParticipantError() {
	o.t.Helper()

	for i, errs := range o.errs {
		select {
		case err := <-errs:
			o.t.Fatalf("participant %q reported an error: %v\n%s", o.tokens[i], err, o.diagnostics())
		default:
		}
	}
}

// assertNoConcurrentAcquisition fails when any participant other than the current
// holder reached the point where the lock was its own. It is called from inside the
// attempt wait as well, so a broken acquisition is reported as an exclusion violation
// even when it cuts the attempt count short.
func (o *issue872Oracle) assertNoConcurrentAcquisition(winnerIdx int, heldBy string) {
	o.t.Helper()

	for _, ev := range o.events() {
		if ev.kind != issue872EventAcquire {
			continue
		}
		idx := issue872IndexOf(o.tokens, ev.token)
		if idx < 0 || idx == winnerIdx || o.completed[idx] {
			continue
		}
		o.t.Fatalf("MUTUAL EXCLUSION BROKEN: participant %q completed a real acquisition (owner sampled at that instant: %q) while %q held the exclusive resource\n%s",
			ev.token, ev.owner, heldBy, o.diagnostics())
	}
}

// allRetried reports whether every participant except skipIdx has logged at least
// want passes of the given kind.
func (o *issue872Oracle) allRetried(kind string, skipIdx, want int) bool {
	o.t.Helper()

	counts := o.countByKind(kind)
	for i, token := range o.tokens {
		if i == skipIdx || o.completed[i] {
			continue
		}
		if counts[token] < want {
			return false
		}
	}
	return true
}

// awaitNextHolder waits for and returns the index of the next participant whose
// acquisition is recorded in the journal. The journal, not a channel event, decides
// who holds the lock.
func (o *issue872Oracle) awaitNextHolder() int {
	o.t.Helper()

	holderIdx := -1
	o.await("the next participant to acquire the lock", func() bool {
		for _, ev := range o.events() {
			if ev.kind != issue872EventAcquire {
				continue
			}
			if idx := issue872IndexOf(o.tokens, ev.token); idx >= 0 && !o.completed[idx] {
				holderIdx = idx
				return true
			}
		}
		return false
	})
	return holderIdx
}

// awaitHolderParked waits for the holder's own acquire shell to reach its parking point,
// which means the ownership record is written and will not change until this test acts.
func (o *issue872Oracle) awaitHolderParked(holderIdx int) {
	o.t.Helper()

	o.await(fmt.Sprintf("the acquire shell of %q to park after acquiring", o.tokens[holderIdx]), func() bool {
		_, err := os.Stat(o.participants[holderIdx].parkPath)
		return err == nil
	})
}

// awaitOthersAttempting waits until every participant that is neither the holder nor
// already completed has logged further real lock-contention retries than it had when
// the wait started, so earlier rounds cannot satisfy the evidence floor. A concurrent
// acquisition is reported here as an exclusion violation even when it cuts a
// contender's attempt count short.
func (o *issue872Oracle) awaitOthersAttempting(holderIdx int) {
	o.t.Helper()

	before := o.countByKind(issue872EventLockTry)
	o.await(fmt.Sprintf("the remaining participants to attempt acquisition while %q holds the lock", o.tokens[holderIdx]),
		func() bool {
			o.assertNoConcurrentAcquisition(holderIdx, o.tokens[holderIdx])
			counts := o.countByKind(issue872EventLockTry)
			for i, token := range o.tokens {
				if i == holderIdx || o.completed[i] {
					continue
				}
				if counts[token] < before[token]+issue872RequiredAttempts {
					return false
				}
			}
			return true
		})
}

// releaseHolder unblocks the parked shell, confirms that the delayed Go notification
// comes from the participant the journal named, and then drives the real release.
func (o *issue872Oracle) releaseHolder(holderIdx int) {
	o.t.Helper()

	// Only now is the holder's Go notification released, so a channel event can never
	// stand in for continuous ownership.
	if err := os.WriteFile(o.participants[holderIdx].resumePath, []byte("ok"), 0644); err != nil {
		o.t.Fatalf("failed to release the parked acquire shell for %q: %v", o.tokens[holderIdx], err)
	}
	if notified := awaitNextContenderAcquisition(o.t, len(o.tokens), o.completed, o.acquired, o.errs); notified != holderIdx {
		o.t.Fatalf("delayed notification mismatch: the journal shows %q acquired but the channel event came from %q\n%s",
			o.tokens[holderIdx], o.tokens[notified], o.diagnostics())
	}

	releaseAndAwaitContenderDone(o.t, holderIdx, o.releaseSig, o.done)
	o.completed[holderIdx] = true
	o.assertNoParticipantError()
}

// acquireRound drives one serialized round: elect the holder from the journal, confirm
// its parked shell owns the lock, require real attempts from everyone else, assert
// exclusion, and only then release.
func (o *issue872Oracle) acquireRound(t *testing.T, step int) {
	t.Helper()

	holderIdx := o.awaitNextHolder()
	if step == 0 && holderIdx != 0 {
		t.Fatalf("expected the stale reclaimer to win the first round, got %q\n%s", o.tokens[holderIdx], o.diagnostics())
	}

	o.awaitHolderParked(holderIdx)
	assertLockOwnerEquals(t, o.lockPath, o.tokens[holderIdx], fmt.Sprintf("winner at step %d", step+1))

	o.awaitOthersAttempting(holderIdx)

	// Exclusion from protocol state, then the retained non-blocking channel cross-check
	// (the same fact; it can only fire if the journal injection were broken).
	o.assertNoConcurrentAcquisition(holderIdx, o.tokens[holderIdx])
	assertNoOtherContenderAcquired(t, holderIdx, len(o.tokens), o.completed, o.acquired)

	o.releaseHolder(holderIdx)
}

// assertJournalSerialized checks the whole timeline: at most one holder at a time, each
// acquisition owned the record it exited on, and nothing is left held.
func (o *issue872Oracle) assertJournalSerialized(t *testing.T) {
	t.Helper()

	holder := ""
	for _, ev := range o.events() {
		switch ev.kind {
		case issue872EventAcquire:
			if !strings.Contains(ev.owner, ev.token) {
				t.Fatalf("acquire by %q sampled owner file %q at acquisition time: it exited on a lock it did not own\n%s",
					ev.token, ev.owner, o.diagnostics())
			}
			if holder != "" {
				t.Fatalf("overlapping ownership in the journal: %q acquired while %q had not released\n%s",
					ev.token, holder, o.diagnostics())
			}
			holder = ev.token
		case issue872EventRelease:
			if holder == ev.token {
				holder = ""
			}
		}
	}
	if holder != "" {
		t.Fatalf("journal ends with %q still holding the lock\n%s", holder, o.diagnostics())
	}
}

func (o *issue872Oracle) assertEventTotals(t *testing.T, want int) {
	t.Helper()

	acquired, released := 0, 0
	for _, ev := range o.events() {
		switch ev.kind {
		case issue872EventAcquire:
			acquired++
		case issue872EventRelease:
			released++
		}
	}
	if acquired != want || released != want {
		t.Fatalf("expected %d acquisitions and %d releases in the journal, observed %d and %d\n%s",
			want, want, acquired, released, o.diagnostics())
	}
}

func issue872IndexOf(tokens []string, token string) int {
	for i, tok := range tokens {
		if tok == token {
			return i
		}
	}
	return -1
}

// TestRemoteLock_StaleReclaimerPausedInGate_AllContendersWaitOnGate verifies that a
// stale reclaimer holding the gate fences every contender, and that the three subsequent
// acquisitions are strictly serialized with no overlap.
//
// Every exclusion decision in this test comes from the lock protocol's own journal, and
// every holder is parked by its own subprocess while the assertions run.
func TestRemoteLock_StaleReclaimerPausedInGate_AllContendersWaitOnGate(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available on this environment")
	}

	resName := fmt.Sprintf("gate_multi_wait_%d", time.Now().UnixNano())
	o := newIssue872Oracle(t, resName)

	// 1. An abandoned lock older than the 60 s reclaim window, inside this test's own
	//    scratch root rather than the shared production lock root.
	staleToken := "stale-owner-multi-101"
	setupAbandonedStaleLock(t, o.lockPath, staleToken, 120*time.Second)

	// 2. Participant 0 is the stale reclaimer and parks inside the gate critical
	//    section; participants 1..3 are plain contenders.
	const numContenders = 3
	reclaimerToken := "reclaimer-holding-gate"
	o.addParticipant(t, reclaimerToken, true)
	for i := 0; i < numContenders; i++ {
		o.addParticipant(t, fmt.Sprintf("multi-contender-%d", i+1), false)
	}
	o.finalize(t)

	o.start(t, 0)
	waitForBarrierFile(t, o.gatePark, issue872AwaitBound)
	if _, err := os.Stat(o.gatePath); err != nil {
		t.Fatalf("gate directory must exist while the reclaimer is inside the critical section: %v", err)
	}
	assertLockOwnerEquals(t, o.gatePath, reclaimerToken, "gate held by reclaimer")

	for i := 1; i <= numContenders; i++ {
		o.start(t, i)
	}

	// 3. Every contender must demonstrably retry against the held gate. This replaces a
	//    fixed sleep with counted protocol passes, and a broken acquisition is reported
	//    here as an exclusion violation.
	o.await("every contender to retry against the held gate", func() bool {
		o.assertNoConcurrentAcquisition(-1, reclaimerToken)
		return o.allRetried(issue872EventGateWait, 0, issue872RequiredAttempts)
	})

	// The gate hold must not have disturbed the stale lock or its owner record.
	assertLockOwnerEquals(t, o.lockPath, staleToken, "stale lock preserved while contenders wait on gate")
	assertLockOwnerEquals(t, o.gatePath, reclaimerToken, "gate still held by reclaimer")

	// 4. Release the gate: the reclaimer completes reclamation and becomes the holder.
	if err := os.WriteFile(o.gateResume, []byte("ok"), 0644); err != nil {
		t.Fatalf("failed to resume the reclaimer gate barrier: %v", err)
	}

	// 5. Four serialized rounds: the reclaimer, then each contender in the order the
	//    protocol itself serializes them.
	for step := 0; step < len(o.tokens); step++ {
		o.acquireRound(t, step)
	}

	// 6. Whole-timeline invariants.
	o.assertJournalSerialized(t)
	o.assertEventTotals(t, len(o.tokens))
	t.Logf("lock protocol journal (owner= is the owner file sampled inside the subprocess at that event):\n%s", o.journalText())

	if _, err := os.Stat(o.lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after the last release: %v", err)
	}
	if _, err := os.Stat(o.gatePath); !os.IsNotExist(err) {
		t.Fatalf("gate directory still exists after the last release: %v", err)
	}
}
