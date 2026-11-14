package gigahostsetup

// Restart-safe execution of an approved Gigahost setup.
//
// The tracker in this package stops at ready_for_setup: it settles the provider
// side plus the credential and host-trust gates, and writes nothing else. This
// file owns what comes next - protocol installation, backend enablement and
// healthy admission - because those steps have remote side effects that must
// survive a crash without being repeated.
//
// Two boundaries are hard here:
//
//  1. One attempt owns one row. Claiming is a compare-and-set that increments a
//     generation token, and every later journal write presents that token. A
//     revoked approval or a superseded attempt therefore cannot issue another
//     remote command, so administrative cancellation reaches the install and not
//     merely the provider poll that precedes it.
//  2. A step whose effect is unproven is never re-issued. The journal records the
//     phase in flight before the effect and the last proven phase after it. A
//     restart that finds a phase in flight asks the runner to VERIFY that effect;
//     when verification cannot prove it, the attempt pauses and waits for an
//     operator instead of replaying a command whose outcome nobody knows.
//
// Exactly-once delivery to a remote host is not assumed and not claimed. The
// guarantee offered is: at most one attempt acts at a time, a completed effect is
// never repeated, and an unknown effect stops the job for a human.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// InstallStore is the persistence the installer needs. It is satisfied by
// *database.DB and narrowed here so the installer cannot issue its own SQL.
type InstallStore interface {
	ListDueGigahostSetupInstalls(ctx context.Context, now time.Time, limit int) ([]models.GigahostSetupIntent, error)
	ClaimGigahostSetupInstall(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error)
	TakeOverGigahostSetupInstall(ctx context.Context, orderID string, expectGeneration int64) (*models.GigahostSetupIntent, bool, error)
	UpdateGigahostSetupInstall(ctx context.Context, intent *models.GigahostSetupIntent, expectedGeneration int64) (bool, error)
	GetGigahostSetupIntent(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error)
}

// InstallRunner performs the actual steps for one claimed attempt.
//
// It receives the claimed intent and the attempt's journal, and records all
// progress through the journal. A nil return means the runner wrote a terminal
// outcome itself; any returned error is a non-terminal diagnosis the installer
// records as a pause. The runner must stop issuing effects as soon as a journal
// call reports that it no longer owns the attempt.
type InstallRunner interface {
	RunInstall(ctx context.Context, intent models.GigahostSetupIntent, journal *InstallJournal) error
}

// Installer defaults. The interval is short because the queue is normally empty
// and a row here means an administrator already approved the work.
const (
	DefaultInstallInterval = 15 * time.Second
	DefaultInstallBatch    = 5
)

// ErrInstallNotOwned reports that this attempt must stop: the approval was
// revoked, or another attempt took the row over.
var ErrInstallNotOwned = errors.New("this install attempt no longer owns the setup intent")

// InstallOptions configure an Installer. Every field has a safe default.
type InstallOptions struct {
	// Now is the clock; the zero value means time.Now.
	Now      func() time.Time
	Interval time.Duration
	Batch    int
}

// Installer drives approved intents through installation.
type Installer struct {
	store  InstallStore
	runner InstallRunner
	now    func() time.Time
	nudge  chan struct{}

	interval time.Duration
	batch    int

	running     atomic.Bool
	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	stopped     chan struct{}
}

// NewInstaller builds an Installer over the store and runner.
func NewInstaller(store InstallStore, runner InstallRunner, opts InstallOptions) *Installer {
	i := &Installer{
		store:    store,
		runner:   runner,
		now:      opts.Now,
		nudge:    make(chan struct{}, 1),
		interval: opts.Interval,
		batch:    opts.Batch,
	}
	if i.now == nil {
		i.now = func() time.Time { return time.Now().UTC() }
	}
	if i.interval <= 0 {
		i.interval = DefaultInstallInterval
	}
	if i.batch <= 0 {
		i.batch = DefaultInstallBatch
	}
	return i
}

// Name identifies the worker to the supervisor.
func (i *Installer) Name() string { return "gigahost-setup-installer" }

// Start runs the install loop until the context ends.
//
// It is a supervised BackgroundService like the tracker, so the panel's own
// startup and shutdown own it: closing a browser changes nothing and a restart
// resumes from the persisted journal.
func (i *Installer) Start(ctx context.Context) error {
	if !i.running.CompareAndSwap(false, true) {
		return errors.New("gigahost setup installer is already running")
	}
	subCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	i.lifecycleMu.Lock()
	i.cancel = cancel
	i.stopped = stopped
	i.lifecycleMu.Unlock()

	defer func() {
		cancel()
		i.lifecycleMu.Lock()
		i.cancel = nil
		i.stopped = nil
		i.lifecycleMu.Unlock()
		i.running.Store(false)
		close(stopped)
	}()

	slog.Info("Gigahost setup installer started", "interval", i.interval.String())
	for {
		if err := i.RunOnce(subCtx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("Gigahost setup installer pass failed", "err", err)
		}
		if !i.waitNext(subCtx) {
			slog.Info("Gigahost setup installer stopped cleanly")
			return nil
		}
	}
}

// Nudge asks a running installer to run a pass now. It never blocks: the
// interval sweep covers a dropped hint.
func (i *Installer) Nudge() {
	select {
	case i.nudge <- struct{}{}:
	default:
	}
}

func (i *Installer) waitNext(ctx context.Context) bool {
	timer := time.NewTimer(i.interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-i.nudge:
		return true
	case <-timer.C:
		return true
	}
}

// Stop asks a running installer to finish and joins it, or returns the caller's
// deadline error.
func (i *Installer) Stop(ctx context.Context) error {
	i.lifecycleMu.Lock()
	cancel := i.cancel
	stopped := i.stopped
	i.lifecycleMu.Unlock()
	if cancel == nil || stopped == nil {
		return nil
	}
	cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopped:
		return nil
	}
}

// RunOnce performs one install pass over the rows that are due.
func (i *Installer) RunOnce(ctx context.Context) error {
	if i.store == nil {
		return errors.New("gigahost setup installer has no store")
	}
	if i.runner == nil {
		return errors.New("gigahost setup installer has no runner")
	}
	due, err := i.store.ListDueGigahostSetupInstalls(ctx, i.now(), i.batch)
	if err != nil {
		return fmt.Errorf("failed to list due setup installs: %w", err)
	}
	var passErr error
	for k := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := i.runOne(ctx, &due[k]); err != nil {
			passErr = err
		}
	}
	return passErr
}

// runOne claims (or takes over) one intent and runs the install attempt.
func (i *Installer) runOne(ctx context.Context, candidate *models.GigahostSetupIntent) error {
	claimed, gen, ok, err := i.claim(ctx, candidate)
	if err != nil || !ok {
		return err
	}
	journal := newInstallJournal(i.store, claimed, gen)
	if err := i.runner.RunInstall(ctx, *claimed, journal); err != nil {
		journal.Pause(ctx, journal.Step(), err)
	}
	return nil
}

// claim takes ownership of one attempt, incrementing its generation.
//
// A row found at the handoff point is claimed outright. A row found still
// installing is a leftover attempt whose owner died; it is taken over with a new
// generation, which both invalidates any zombie writer and preserves the phase
// journal the new attempt needs in order to verify rather than replay.
//
// Only one actor may do this per pass. The claim is a compare-and-set in the
// database, so a competing panel process loses it and sees ok=false, and its
// attempt performs no remote command at all.
func (i *Installer) claim(
	ctx context.Context, candidate *models.GigahostSetupIntent,
) (*models.GigahostSetupIntent, int64, bool, error) {
	if candidate == nil {
		return nil, 0, false, nil
	}
	if candidate.IsInstalling() {
		return i.takeOver(ctx, candidate)
	}
	claimed, ok, err := i.store.ClaimGigahostSetupInstall(ctx, candidate.OrderID)
	if err != nil || !ok || claimed == nil {
		return nil, 0, false, err
	}
	return claimed, claimed.InstallGeneration, true, nil
}

// takeOver re-owns a leftover claim from an attempt whose process died, keeping the
// phase journal that tells the new attempt what to verify.
func (i *Installer) takeOver(
	ctx context.Context, candidate *models.GigahostSetupIntent,
) (*models.GigahostSetupIntent, int64, bool, error) {
	taken, ok, err := i.store.TakeOverGigahostSetupInstall(ctx, candidate.OrderID, candidate.InstallGeneration)
	if err != nil || !ok || taken == nil {
		return nil, 0, false, err
	}
	slog.Info("Gigahost setup install taken over",
		"order_id", taken.OrderID, "generation", taken.InstallGeneration,
		"phase_in_flight", taken.InstallPhase, "phase_done", taken.InstallPhaseDone)
	return taken, taken.InstallGeneration, true, nil
}

// SettleAuthority reports whether this attempt still owns the row at the moment
// the caller is about to issue a remote command.
func (j *InstallJournal) SettleAuthority(ctx context.Context) (bool, error) {
	current, found, err := j.store.GetGigahostSetupIntent(ctx, j.orderID)
	if err != nil || !found || current == nil {
		return false, err
	}
	if current.State != models.SetupStateInstalling {
		return false, nil
	}
	return current.InstallGeneration == j.generation, nil
}

// InstallJournal is one attempt's only writer.
//
// Every method is a fenced compare-and-set against (installing, generation). A
// refusal means this attempt is no longer the owner and must issue no further
// remote command.
type InstallJournal struct {
	store      InstallStore
	orderID    string
	generation int64

	mu     sync.Mutex
	intent models.GigahostSetupIntent
}

func newInstallJournal(store InstallStore, intent *models.GigahostSetupIntent, generation int64) *InstallJournal {
	j := &InstallJournal{store: store, generation: generation}
	if intent != nil {
		j.orderID = intent.OrderID
		j.intent = *intent
	}
	return j
}

// Intent returns the attempt's current snapshot.
func (j *InstallJournal) Intent() models.GigahostSetupIntent {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.intent
}

// Generation returns the fencing token this attempt must present.
func (j *InstallJournal) Generation() int64 { return j.generation }

// Step returns the step most recently recorded, for a pause diagnosis.
func (j *InstallJournal) Step() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.intent.Step == "" {
		return "install"
	}
	return j.intent.Step
}

// ResumePhase returns the phase that was in flight when the previous attempt
// stopped and the last phase whose effect is proven complete.
func (j *InstallJournal) ResumePhase() (inFlight, done string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.intent.InstallPhase, j.intent.InstallPhaseDone
}

// BeginPhase records that a side-effecting step is starting, BEFORE the effect.
//
// It returns false when this attempt no longer owns the row, which is the signal
// to stop without performing the step.
func (j *InstallJournal) BeginPhase(ctx context.Context, phase, step string) (bool, error) {
	return j.write(ctx, phase, j.done(), 0, step, models.SetupStateInstalling, "")
}

// CompletePhase records that a step's effect is proven complete.
func (j *InstallJournal) CompletePhase(ctx context.Context, phase, step string, serverID int64) (bool, error) {
	return j.write(ctx, "", phase, serverID, step, models.SetupStateInstalling, "")
}

// Admit records the terminal success of the job.
//
// It is only reachable after the runner itself verified healthy admission; the
// installer does not infer it from the absence of errors.
func (j *InstallJournal) Admit(ctx context.Context, step string, serverID int64) error {
	ok, err := j.write(ctx, "", models.SetupPhaseEnabled, serverID, step, models.SetupStateReady, "")
	if err != nil {
		return err
	}
	if !ok {
		return ErrInstallNotOwned
	}
	return nil
}

// Pause records a non-terminal stop with a bounded diagnosis.
//
// Pausing is deliberately not "failed": the order, the VPS and any partially
// installed software are kept, and an administrator decides what happens next.
func (j *InstallJournal) Pause(ctx context.Context, step string, cause error) {
	reason := "install stopped without a proven outcome"
	if cause != nil {
		reason = summarize(cause.Error())
	}
	// A revoked or superseded row must not be rewritten into a pause: the write
	// is fenced, so this call reports false and the stored revocation stands.
	if _, err := j.write(ctx, j.inFlight(), j.done(), 0, step, models.SetupStateInstallPaused, reason); err != nil {
		slog.Warn("failed to record setup install pause", "order_id", j.orderID, "err", err)
	}
}

func (j *InstallJournal) inFlight() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.intent.InstallPhase
}

func (j *InstallJournal) done() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.intent.InstallPhaseDone
}

// write applies a journal update under the attempt's fencing token.
func (j *InstallJournal) write(
	ctx context.Context, phase, phaseDone string, serverID int64, step, state, lastError string,
) (bool, error) {
	j.mu.Lock()
	next := j.intent
	j.mu.Unlock()

	next.InstallPhase = phase
	next.InstallPhaseDone = phaseDone
	if serverID > 0 {
		next.NexusServerID = serverID
	}
	next.Step = step
	next.State = state
	next.LastError = lastError
	if state != models.SetupStateInstalling {
		next.NextAttemptAt = time.Time{}
	}

	changed, err := j.store.UpdateGigahostSetupInstall(ctx, &next, j.generation)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, ErrInstallNotOwned
	}
	j.mu.Lock()
	j.intent = next
	j.mu.Unlock()
	return true, nil
}

// summarize bounds a diagnosis so it stays a single readable line.
func summarize(msg string) string {
	const limit = 240
	fields := make([]byte, 0, len(msg))
	space := false
	for k := 0; k < len(msg); k++ {
		if c := msg[k]; c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			if !space && len(fields) > 0 {
				fields = append(fields, ' ')
				space = true
			}
			continue
		}
		space = false
		fields = append(fields, msg[k])
	}
	out := string(fields)
	if len(out) > limit {
		out = out[:limit] + "..."
	}
	return out
}
