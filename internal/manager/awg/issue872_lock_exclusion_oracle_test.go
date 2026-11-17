package awg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
)

// This file is the stale-lock exclusion oracle. Its exclusion evidence comes from the
// lock protocol itself rather than from a Go channel notification:
//
//   - every acquire subprocess appends counted retry lines and one acquisition line to
//     a single journal, so the ownership sample comes from the real shell;
//   - the holder is parked by its own acquire shell immediately after it writes the
//     ownership record, so the exclusion assertions run while the lock is provably held
//     instead of during a fixed sleep;
//   - every other participant must demonstrate a counted number of real acquisition
//     attempts against that held lock before the exclusion assertion is accepted;
//   - the holder's Go notification is only released afterwards, so a channel event can
//     never stand in for continuous ownership.
//
// Release is observed as a lifecycle, not as a single instant. A release subprocess
// records when it begins releasing (while it still owns the lock) and when the removal
// call returned. The real removal therefore falls somewhere inside that interval, and a
// successor acquisition observed inside it is reported as unresolved rather than as
// either legal or overlapping. Only an acquisition observed before the predecessor's
// release began is an overlap, because at that point the predecessor had not started
// removing anything. Journal order alone cannot resolve the interval; that limit is
// stated rather than assumed away.
//
// The production lock source is not modified. The generated acquire and release commands
// are preserved byte for byte apart from the lock root, which is redirected into this
// test's own scratch directory; that restriction is checked structurally rather than
// asserted in prose.

const (
	// issue872EventGateWait records one real retry pass while another token held the gate.
	issue872EventGateWait = "GATEWAIT"
	// issue872EventLockTry records one real retry pass while another token held the lock.
	issue872EventLockTry = "LOCKTRY"
	// issue872EventAcquire records that a token's acquire subprocess reached the point
	// where the lock is its own. The owner field is what the owner file said at that
	// instant, which is a sample, not a continuous claim.
	issue872EventAcquire = "ACQ"
	// issue872EventReleaseBegin records that a token's release subprocess entered its
	// removal branch. The lock is still present at this point.
	issue872EventReleaseBegin = "RELBEGIN"
	// issue872EventReleaseDone records that the removal call for this token returned.
	issue872EventReleaseDone = "RELDONE"

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

	// issue872JoinBound bounds the wait for participant goroutines and their
	// subprocesses to exit after cancellation.
	issue872JoinBound = 10 * time.Second

	// issue872PollInterval is the readiness poll interval for journal observations.
	issue872PollInterval = 5 * time.Millisecond

	// issue872GateRetryAnchor is the tail of the gate-contended branch of the generated
	// acquire command. It must occur exactly once or the injection is refused.
	issue872GateRetryAnchor = "sleep 0.05 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; continue;"
	// issue872LockRetryAnchor is the tail of the lock-contended branch.
	issue872LockRetryAnchor = "sleep 0.05 2>/dev/null || sleep 0.1 2>/dev/null || sleep 1; done"
	// issue872ReleaseBeginAnchor is the release command's removal branch entry.
	issue872ReleaseBeginAnchor = "; then rm -rf "
	// issue872ReleaseDoneAnchor is the statement that ends the removal branch.
	issue872ReleaseDoneAnchor = "2>/dev/null; fi"
)

// issue872JournalEvent is one parsed journal line: a counted attempt or one observation
// of the acquire/release lifecycle made inside a real subprocess.
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

	// releaseDoneDelay, when set, is inserted between the real removal call and its
	// release-complete observation. It exists so a control can force the logging lag
	// that the single-marker oracle mistook for an overlap.
	releaseDoneDelay time.Duration

	ctx        context.Context
	cancel     context.CancelFunc
	cancelOnce sync.Once

	wg      sync.WaitGroup
	live    atomic.Int32
	pids    []atomic.Int64
	started []bool

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

	o := &issue872Oracle{
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

	// Registered after t.TempDir so it runs before the scratch directory is removed.
	t.Cleanup(func() {
		if err := o.joinParticipants(); err != nil {
			t.Errorf("lock oracle cleanup: %v", err)
		}
	})

	return o
}

// joinParticipants cancels the oracle and waits for every participant goroutine and its
// live subprocess to exit. It reports a failure to join instead of treating a leaked
// goroutine as harmless because its process will eventually exit on its own.
func (o *issue872Oracle) joinParticipants() error {
	o.cancelOnce.Do(o.cancel)

	joined := make(chan struct{})
	go func() {
		o.wg.Wait()
		close(joined)
	}()

	select {
	case <-joined:
	case <-time.After(issue872JoinBound):
		return fmt.Errorf("%d participant goroutine(s) still running %v after cancellation", o.live.Load(), issue872JoinBound)
	}

	return o.assertNoLeftoverProcesses()
}

// assertNoLeftoverProcesses proves by identity that no subprocess of this oracle is still
// running. Identity comes from the unique scratch path this test owns, which appears in
// the command line of every shell it starts, rather than from a process id that could
// have been reused after the child was reaped.
func (o *issue872Oracle) assertNoLeftoverProcesses() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// No procfs to inspect; the join above still proves the goroutines exited.
		return nil
	}

	var leftovers []string
	for _, entry := range entries {
		if _, convErr := strconv.Atoi(entry.Name()); convErr != nil {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if readErr != nil {
			continue
		}
		if strings.Contains(string(raw), o.scratch) {
			leftovers = append(leftovers, fmt.Sprintf("pid %s: %s", entry.Name(), strings.ReplaceAll(string(raw), "\x00", " ")))
		}
	}
	if len(leftovers) > 0 {
		return fmt.Errorf("subprocesses of this oracle are still running after join: %s", strings.Join(leftovers, "; "))
	}
	return nil
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

// instrumentRelease brackets the real removal call with a release-begin and a
// release-complete observation, so the removal instant is confined to a known interval
// instead of being inferred from a marker that trails the whole release.
func (o *issue872Oracle) instrumentRelease(t *testing.T, cmd, token string) string {
	t.Helper()

	if got := strings.Count(cmd, issue872ReleaseBeginAnchor); got != 1 {
		t.Fatalf("expected exactly 1 release-start anchor in the generated release command, found %d:\n%s", got, cmd)
	}
	begin := issue872JournalRecord(issue872EventReleaseBegin, token, o.journalPath, o.lockPath)
	cmd = strings.Replace(cmd, issue872ReleaseBeginAnchor, "; then "+begin+"; rm -rf ", 1)

	if got := strings.Count(cmd, issue872ReleaseDoneAnchor); got != 1 {
		t.Fatalf("expected exactly 1 release-complete anchor in the generated release command, found %d:\n%s", got, cmd)
	}
	lag := ""
	if o.releaseDoneDelay > 0 {
		lag = fmt.Sprintf("sleep %.3f; ", o.releaseDoneDelay.Seconds())
	}
	done := issue872JournalRecord(issue872EventReleaseDone, token, o.journalPath, o.lockPath)
	return strings.Replace(cmd, issue872ReleaseDoneAnchor, "2>/dev/null; "+lag+done+"; fi", 1)
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

	releaseCmd := o.instrumentRelease(t, o.redirectLockRoot(t, remoteLockReleaseCmd(o.resName, token)), token)

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
	o.pids = make([]atomic.Int64, n)
	o.started = make([]bool, n)
	for i, p := range o.participants {
		o.acquired[i] = p.acquired
		o.releaseSig[i] = p.releaseSig
		o.done[i] = p.done
		o.errs[i] = p.errs
	}
}

// start runs one participant's acquire subprocess, then its release subprocess once the
// oracle signals it. Both waits observe cancellation, and the goroutine is tracked so
// the fixture can join it before cleanup.
func (o *issue872Oracle) start(t *testing.T, idx int) {
	t.Helper()

	if o.started[idx] {
		t.Fatalf("participant %q was already started", o.tokens[idx])
	}
	o.started[idx] = true

	p := o.participants[idx]
	o.wg.Add(1)
	o.live.Add(1)
	go func() {
		defer o.wg.Done()
		defer o.live.Add(-1)
		if err := o.runParticipant(idx, p); err != nil {
			select {
			case p.errs <- err:
			default:
			}
		}
	}()
}

// runParticipant drives one participant's lifecycle and returns the first failure. It is
// the only place that waits on the participant's own signals, and every wait can be
// abandoned on cancellation so the goroutine cannot outlive the fixture.
func (o *issue872Oracle) runParticipant(idx int, p issue872Participant) error {
	out, err := o.runShell(idx, p, p.acquireCmd, "acquire")
	if err != nil {
		return err
	}
	_ = out

	select {
	case p.acquired <- struct{}{}:
	case <-o.ctx.Done():
		return fmt.Errorf("cancelled after acquiring: %w", o.ctx.Err())
	}

	select {
	case <-p.releaseSig:
	case <-o.ctx.Done():
		return fmt.Errorf("cancelled before release: %w", o.ctx.Err())
	}

	if _, err := o.runShell(idx, p, p.releaseCmd, "release"); err != nil {
		select {
		case p.errs <- err:
		default:
		}
	}

	select {
	case p.done <- struct{}{}:
	case <-o.ctx.Done():
		return fmt.Errorf("cancelled before completion: %w", o.ctx.Err())
	}
	return nil
}

// runShell executes one generated shell command for a participant, recording its
// process id before it runs so the fixture can prove that exact process exited.
func (o *issue872Oracle) runShell(idx int, p issue872Participant, command, phase string) (string, error) {
	cmd := exec.CommandContext(o.ctx, "bash", "-c", command)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("%s start failed: %w", phase, err)
	}
	o.pids[idx].Store(int64(cmd.Process.Pid))

	if err := cmd.Wait(); err != nil {
		return buf.String(), fmt.Errorf("%s failed: %w (out: %s)", phase, err, strings.TrimSpace(buf.String()))
	}
	return buf.String(), nil
}

// issue872ParseJournalLine parses one journal line. Anything that does not have the
// exact shape this oracle relies on is an error: silently dropping a line would let the
// exclusion evidence be weaker than it claims.
func issue872ParseJournalLine(line string) (issue872JournalEvent, error) {
	parts := strings.SplitN(line, " ", 4)
	if len(parts) != 4 {
		return issue872JournalEvent{}, fmt.Errorf("expected 4 fields, got %d in %q", len(parts), line)
	}
	if parts[0] == "" || parts[2] == "" {
		return issue872JournalEvent{}, fmt.Errorf("missing event kind or token in %q", line)
	}
	if !strings.HasPrefix(parts[3], "owner=") {
		return issue872JournalEvent{}, fmt.Errorf("missing owner observation in %q", line)
	}
	return issue872JournalEvent{
		kind:  parts[0],
		token: parts[2],
		owner: strings.TrimPrefix(parts[3], "owner="),
	}, nil
}

// issue872ParseJournal parses a whole journal. It also returns an unterminated trailing
// fragment separately, because a live journal may be read between writes while a final
// read must not silently lose a truncated tail.
func issue872ParseJournal(raw string) ([]issue872JournalEvent, string, error) {
	if raw == "" {
		return nil, "", nil
	}

	lines := strings.Split(raw, "\n")
	tail := ""
	if last := len(lines) - 1; lines[last] == "" {
		// The journal ends with a newline, which is its completed shape.
		lines = lines[:last]
	} else {
		// The final line has not been terminated yet, so it is an in-progress write.
		tail = lines[last]
		lines = lines[:last]
	}

	events := make([]issue872JournalEvent, 0, len(lines))
	for i, line := range lines {
		if line == "" {
			return nil, tail, fmt.Errorf("line %d is empty", i+1)
		}
		ev, err := issue872ParseJournalLine(line)
		if err != nil {
			return nil, tail, fmt.Errorf("line %d: %w", i+1, err)
		}
		events = append(events, ev)
	}
	return events, tail, nil
}

// issue872OwnerToken returns the token field of an owner-file sample.
func issue872OwnerToken(sample string) string {
	fields := strings.Fields(sample)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// issue872AcqClass is how one acquisition relates to its predecessor's release.
type issue872AcqClass string

const (
	// issue872AcqFirst is the first acquisition in the journal.
	issue872AcqFirst issue872AcqClass = "first"
	// issue872AcqReleased follows a predecessor whose removal call had already returned.
	issue872AcqReleased issue872AcqClass = "predecessor-released"
	// issue872AcqInFlight falls inside the predecessor's release interval, so the
	// journal cannot say whether the removal call had already taken effect. It is
	// reported as unresolved, never as legal and never as overlap.
	issue872AcqInFlight issue872AcqClass = "release-in-flight"
	// issue872AcqOverlap precedes the predecessor's release entirely.
	issue872AcqOverlap issue872AcqClass = "overlap"
)

// issue872Acquisition is one classified acquisition.
type issue872Acquisition struct {
	token    string
	owner    string
	previous string
	class    issue872AcqClass
}

// issue872Classification is the whole-journal verdict.
type issue872Classification struct {
	acquisitions []issue872Acquisition
	inFlight     int
	outstanding  string
}

// issue872ClassifyJournal classifies every acquisition against the release lifecycle of
// its predecessor. It rejects journal data whose shape it cannot interpret, because the
// exclusion verdict depends on that data.
//
// Release state is tracked per token, not globally: a successor can take the lock while a
// predecessor's removal call is still in flight, and the predecessor's release-complete
// record then legitimately arrives afterwards.
func issue872ClassifyJournal(events []issue872JournalEvent) (issue872Classification, error) {
	var out issue872Classification

	acquired := map[string]bool{}
	begun := map[string]bool{}
	latest := ""
	everAcquired := false

	for i, ev := range events {
		switch ev.kind {
		case issue872EventGateWait, issue872EventLockTry:
			continue

		case issue872EventAcquire:
			if issue872OwnerToken(ev.owner) != ev.token {
				return out, fmt.Errorf("line %d: acquisition by %q sampled owner %q at that instant", i+1, ev.token, ev.owner)
			}
			if acquired[ev.token] {
				return out, fmt.Errorf("line %d: %q acquired again while an earlier acquisition of its own is outstanding", i+1, ev.token)
			}

			var class issue872AcqClass
			switch {
			case latest == "" && !everAcquired:
				class = issue872AcqFirst
			case latest == "":
				class = issue872AcqReleased
			case begun[latest]:
				class = issue872AcqInFlight
				out.inFlight++
			default:
				class = issue872AcqOverlap
			}

			out.acquisitions = append(out.acquisitions, issue872Acquisition{
				token:    ev.token,
				owner:    ev.owner,
				previous: latest,
				class:    class,
			})
			acquired[ev.token] = true
			begun[ev.token] = false
			latest = ev.token
			everAcquired = true

		case issue872EventReleaseBegin:
			if !acquired[ev.token] {
				return out, fmt.Errorf("line %d: release began for %q without an outstanding acquisition", i+1, ev.token)
			}
			if issue872OwnerToken(ev.owner) != ev.token {
				return out, fmt.Errorf("line %d: release began for %q but the owner file named %q", i+1, ev.token, ev.owner)
			}
			begun[ev.token] = true

		case issue872EventReleaseDone:
			if !acquired[ev.token] || !begun[ev.token] {
				return out, fmt.Errorf("line %d: release completed for %q without a matching release-begin", i+1, ev.token)
			}
			acquired[ev.token] = false
			begun[ev.token] = false
			if latest == ev.token {
				latest = ""
			}

		default:
			return out, fmt.Errorf("line %d: unknown journal event kind %q", i+1, ev.kind)
		}
	}

	out.outstanding = latest
	return out, nil
}

// issue872LegacyOverlapRule reproduces the superseded single-marker rule: an acquisition
// observed before the previous holder's final release record was reported as overlap.
// It exists only to show what the earlier oracle would have concluded about the same
// journal, and it is the rule that turned a delayed release record into a false positive.
func issue872LegacyOverlapRule(events []issue872JournalEvent) (successor, predecessor string, flagged bool) {
	heldBy := ""
	for _, ev := range events {
		switch ev.kind {
		case issue872EventAcquire:
			if heldBy != "" {
				return ev.token, heldBy, true
			}
			heldBy = ev.token
		case issue872EventReleaseDone:
			if heldBy == ev.token {
				heldBy = ""
			}
		}
	}
	return "", "", false
}

// readJournal returns the parsed journal without failing the test, so diagnostics can
// report malformed data instead of dying while trying to describe it.
func (o *issue872Oracle) readJournal() ([]issue872JournalEvent, string, error) {
	raw, err := os.ReadFile(o.journalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	return issue872ParseJournal(string(raw))
}

// events returns the parsed journal, failing the test when the evidence is unusable.
func (o *issue872Oracle) events() []issue872JournalEvent {
	o.t.Helper()

	events, tail, err := o.readJournal()
	if err != nil {
		o.t.Fatalf("lock journal is not usable as exclusion evidence: %v\n%s", err, o.diagnostics())
	}
	if tail != "" {
		o.t.Fatalf("lock journal ends with an unterminated fragment %q\n%s", tail, o.diagnostics())
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

// contentionSummary reports what each participant was actually observed doing, plus the
// artefacts a contention failure turns on. It reads state directly and never fails.
func (o *issue872Oracle) contentionSummary() string {
	var b strings.Builder
	events, tail, err := o.readJournal()
	if err != nil {
		fmt.Fprintf(&b, "journal unusable: %v\n", err)
	}
	if tail != "" {
		fmt.Fprintf(&b, "journal has an unterminated trailing fragment: %q\n", tail)
	}

	counts := map[string]map[string]int{}
	for _, ev := range events {
		if counts[ev.token] == nil {
			counts[ev.token] = map[string]int{}
		}
		counts[ev.token][ev.kind]++
	}
	kinds := []string{issue872EventAcquire, issue872EventReleaseBegin, issue872EventReleaseDone, issue872EventLockTry, issue872EventGateWait}
	for _, token := range o.tokens {
		fmt.Fprintf(&b, "  participant %q:", token)
		for _, kind := range kinds {
			fmt.Fprintf(&b, " %s=%d", kind, counts[token][kind])
		}
		b.WriteString("\n")
	}

	if class, classErr := issue872ClassifyJournal(events); classErr == nil {
		fmt.Fprintf(&b, "  classification: acquisitions=%d release-in-flight=%d outstanding=%q\n",
			len(class.acquisitions), class.inFlight, class.outstanding)
	} else {
		fmt.Fprintf(&b, "  classification: unusable (%v)\n", classErr)
	}
	if successor, predecessor, flagged := issue872LegacyOverlapRule(events); flagged {
		fmt.Fprintf(&b, "  superseded single-marker rule would have reported overlap: %q after %q\n", successor, predecessor)
	}

	for _, probe := range []struct{ label, path string }{
		{"lock dir", o.lockPath},
		{"gate dir", o.gatePath},
		{"lock owner file", filepath.Join(o.lockPath, "owner")},
	} {
		info, statErr := os.Stat(probe.path)
		switch {
		case statErr == nil:
			fmt.Fprintf(&b, "  %s: present mtime=%s\n", probe.label, info.ModTime().UTC().Format(time.RFC3339Nano))
		case os.IsNotExist(statErr):
			fmt.Fprintf(&b, "  %s: absent\n", probe.label)
		default:
			fmt.Fprintf(&b, "  %s: stat failed: %v\n", probe.label, statErr)
		}
	}
	fmt.Fprintf(&b, "  wall clock now: %s (unix %d)\n", time.Now().UTC().Format(time.RFC3339Nano), time.Now().Unix())

	return b.String()
}

// diagnostics reports the journal, the per-participant contention summary and the
// current owner file. The owner reading here is explicitly a sample taken now, not at
// event time, and each journal line carries the sample that was taken at that event.
func (o *issue872Oracle) diagnostics() string {
	owner := "absent"
	switch raw, err := os.ReadFile(filepath.Join(o.lockPath, "owner")); {
	case err == nil:
		owner = strings.TrimSpace(string(raw))
	case !os.IsNotExist(err):
		owner = fmt.Sprintf("<unreadable: %v>", err)
	}

	return fmt.Sprintf("lock journal (%s):\n%s\ncontention summary:\n%sowner file sampled now, not at event time: %q",
		o.journalPath, o.journalText(), o.contentionSummary(), owner)
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

// assertNoParticipantError surfaces a release failure that the legacy contender helper
// cannot report.
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

// signalAndAwaitRelease asks one participant to release and waits, with a bound, for its
// release subprocess to finish. Cancellation abandons the wait instead of blocking it.
func (o *issue872Oracle) signalAndAwaitRelease(t *testing.T, idx int) {
	t.Helper()

	p := o.participants[idx]
	select {
	case p.releaseSig <- struct{}{}:
	case <-o.ctx.Done():
		t.Fatalf("oracle cancelled before releasing %q: %v", p.token, o.ctx.Err())
	}

	select {
	case <-p.done:
	case <-time.After(issue872AwaitBound):
		t.Fatalf("timed out after %v waiting for %q to release the lock\n%s", issue872AwaitBound, p.token, o.diagnostics())
	case <-o.ctx.Done():
		t.Fatalf("oracle cancelled while waiting for %q to release: %v", p.token, o.ctx.Err())
	}
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

	o.signalAndAwaitRelease(o.t, holderIdx)
	o.completed[holderIdx] = true
	o.assertNoParticipantError()
}

// acquireRound drives one serialized round: elect the holder from the journal, confirm
// its parked shell owns the lock, require real attempts from everyone else, assert
// exclusion, and only then release.
func (o *issue872Oracle) acquireRound(t *testing.T, step, requireFirstHolder int) {
	t.Helper()

	holderIdx := o.awaitNextHolder()
	if step == 0 && requireFirstHolder >= 0 && holderIdx != requireFirstHolder {
		t.Fatalf("expected %q to win the first round, got %q\n%s",
			o.tokens[requireFirstHolder], o.tokens[holderIdx], o.diagnostics())
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

// assertReleaseOrdering classifies the whole timeline. An acquisition that precedes its
// predecessor's release-begin is an overlap and fails. An acquisition inside the
// predecessor's release interval is unresolved by journal order, so it is counted and
// reported rather than being claimed as exclusion.
func (o *issue872Oracle) assertReleaseOrdering(t *testing.T) {
	t.Helper()

	events := o.events()
	class, err := issue872ClassifyJournal(events)
	if err != nil {
		t.Fatalf("lock journal is not usable as exclusion evidence: %v\n%s", err, o.diagnostics())
	}

	for _, acq := range class.acquisitions {
		if acq.class != issue872AcqOverlap {
			continue
		}
		t.Fatalf("MUTUAL EXCLUSION BROKEN: %q acquired while %q held the lock and had not begun releasing (owner sampled at that instant: %q)\n%s",
			acq.token, acq.previous, acq.owner, o.diagnostics())
	}

	if class.outstanding != "" {
		t.Fatalf("lock journal ends with %q still holding the lock\n%s", class.outstanding, o.diagnostics())
	}

	for _, acq := range class.acquisitions {
		t.Logf("acquisition class: %q after %q -> %s (owner sampled at that instant: %q)",
			acq.token, acq.previous, acq.class, acq.owner)
	}
	if class.inFlight > 0 {
		t.Logf("unresolved: %d acquisition(s) fall inside a predecessor's release interval, so the journal cannot say whether the removal call had already taken effect; they are reported, not counted as exclusion proof", class.inFlight)
	}
}

func (o *issue872Oracle) assertEventTotals(t *testing.T, want int) {
	t.Helper()

	acquired, begun, completedReleases := 0, 0, 0
	for _, ev := range o.events() {
		switch ev.kind {
		case issue872EventAcquire:
			acquired++
		case issue872EventReleaseBegin:
			begun++
		case issue872EventReleaseDone:
			completedReleases++
		}
	}
	if acquired != want || begun != want || completedReleases != want {
		t.Fatalf("expected %d acquisitions, %d release-begin and %d release-complete observations, observed %d, %d and %d\n%s",
			want, want, want, acquired, begun, completedReleases, o.diagnostics())
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
		o.acquireRound(t, step, 0)
	}

	// 6. Whole-timeline invariants.
	o.assertReleaseOrdering(t)
	o.assertEventTotals(t, len(o.tokens))
	t.Logf("lock protocol journal (owner= is the owner file sampled inside the subprocess at that event):\n%s", o.journalText())

	if _, err := os.Stat(o.lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock directory still exists after the last release: %v", err)
	}
	if _, err := os.Stat(o.gatePath); !os.IsNotExist(err) {
		t.Fatalf("gate directory still exists after the last release: %v", err)
	}
}
