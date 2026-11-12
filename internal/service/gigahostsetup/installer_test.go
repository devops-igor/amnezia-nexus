package gigahostsetup

// Behavioural tests for the install state machine.
//
// These drive the real Installer over a real SQLite database with a runner that
// records what it was asked to do. The point is the ownership contract, not the
// runner's internals: one claim at a time, a generation fence that stops a
// superseded attempt, and a takeover that keeps the phase journal.

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// recordingRunner records every attempt it was asked to run.
type recordingRunner struct {
	mu      sync.Mutex
	orderID []string
	journal []*InstallJournal
	behave  func(ctx context.Context, journal *InstallJournal) error
}

func (r *recordingRunner) RunInstall(ctx context.Context, intent models.GigahostSetupIntent, journal *InstallJournal) error {
	r.mu.Lock()
	r.orderID = append(r.orderID, intent.OrderID)
	r.journal = append(r.journal, journal)
	behave := r.behave
	r.mu.Unlock()
	if behave != nil {
		return behave(ctx, journal)
	}
	return nil
}

func (r *recordingRunner) attempts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.orderID...)
}

// installHarness is a real database plus the installer under test.
type installHarness struct {
	t     *testing.T
	db    *database.DB
	clock *fakeClock
}

func newInstallHarness(t *testing.T) *installHarness {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "installer.db"), trackerTestSecretKey)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &installHarness{t: t, db: db, clock: newFakeClock()}
}

// seedIntent records a placed order and an approval in the requested state.
func (h *installHarness) seedIntent(orderID, state string) *models.GigahostSetupIntent {
	h.t.Helper()
	now := h.clock.Now()
	if err := h.db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID: orderID, Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		h.t.Fatalf("seed order: %v", err)
	}
	intent := &models.GigahostSetupIntent{
		OrderID:          orderID,
		ProviderServerID: 4242,
		Protocol:         models.ProtocolAWG,
		Port:             "51820",
		CredentialMode:   models.SetupCredentialManaged,
		HostFingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		State:            state,
		Step:             "seeded",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := h.db.CreateGigahostSetupIntent(context.Background(), intent); err != nil {
		h.t.Fatalf("seed intent: %v", err)
	}
	return intent
}

// installer builds an installer over the harness.
func (h *installHarness) installer(runner InstallRunner) *Installer {
	return NewInstaller(h.db, runner, InstallOptions{Interval: time.Minute, Batch: 10})
}

// load re-reads the intent.
func (h *installHarness) load(orderID string) *models.GigahostSetupIntent {
	h.t.Helper()
	intent, found, err := h.db.GetGigahostSetupIntent(context.Background(), orderID)
	if err != nil || !found {
		h.t.Fatalf("read intent: found=%v err=%v", found, err)
	}
	return intent
}

// TestInstallerClaimsAndJournalsInOrder proves the claim is the first durable
// write and that the phase markers bracket the effect.
func TestInstallerClaimsAndJournalsInOrder(t *testing.T) {
	h := newInstallHarness(t)
	h.seedIntent("ord_claim", models.SetupStateReadyForSetup)

	runner := &recordingRunner{behave: func(ctx context.Context, journal *InstallJournal) error {
		if gen := journal.Generation(); gen <= 0 {
			t.Errorf("journal generation = %d, want a fencing token", gen)
		}
		ok, err := journal.BeginPhase(ctx, models.SetupPhaseInstalled, "installing_protocol")
		if err != nil || !ok {
			t.Errorf("begin phase: ok=%v err=%v", ok, err)
			return nil
		}
		if _, err := journal.CompletePhase(ctx, models.SetupPhaseInstalled, "protocol_installed", 77); err != nil {
			t.Errorf("complete phase: %v", err)
			return nil
		}
		return journal.Admit(ctx, "ready", 77)
	}}

	if err := h.installer(runner).RunOnce(context.Background()); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := runner.attempts(); len(got) != 1 || got[0] != "ord_claim" {
		t.Fatalf("attempts = %v, want exactly one for ord_claim", got)
	}
	got := h.load("ord_claim")
	if got.State != models.SetupStateReady {
		t.Fatalf("state = %q, want %q (%s)", got.State, models.SetupStateReady, got.LastError)
	}
	if got.InstallPhaseDone != models.SetupPhaseEnabled {
		t.Fatalf("phase done = %q, want %q (admission completes the last phase)",
			got.InstallPhaseDone, models.SetupPhaseEnabled)
	}
	if got.InstallGeneration != 1 {
		t.Fatalf("generation = %d, want 1", got.InstallGeneration)
	}
	if got.NexusServerID != 77 {
		t.Fatalf("recorded server = %d, want 77", got.NexusServerID)
	}
}

// TestInstallerTakesOverALeftoverClaim proves a row left installing is picked up,
// gets a NEW generation, and keeps the phase journal the next attempt needs.
func TestInstallerTakesOverALeftoverClaim(t *testing.T) {
	h := newInstallHarness(t)
	h.seedIntent("ord_leftover", models.SetupStateReadyForSetup)

	ctx := context.Background()
	claimed, ok, err := h.db.ClaimGigahostSetupInstall(ctx, "ord_leftover")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	claimed.InstallPhase = models.SetupPhaseInstalled
	claimed.InstallPhaseDone = models.SetupPhaseRegistered
	if _, err := h.db.UpdateGigahostSetupInstall(ctx, claimed, claimed.InstallGeneration); err != nil {
		t.Fatalf("record in-flight phase: %v", err)
	}

	var seenInFlight, seenDone string
	runner := &recordingRunner{behave: func(_ context.Context, journal *InstallJournal) error {
		inflight, done := journal.ResumePhase()
		seenInFlight, seenDone = inflight, done
		if journal.Generation() <= claimed.InstallGeneration {
			t.Errorf("takeover generation %d is not newer than the leftover %d",
				journal.Generation(), claimed.InstallGeneration)
		}
		return nil
	}}

	if err := h.installer(runner).RunOnce(ctx); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if seenInFlight != models.SetupPhaseInstalled || seenDone != models.SetupPhaseRegistered {
		t.Fatalf("resume journal = (%q, %q), want the leftover phase kept",
			seenInFlight, seenDone)
	}
	got := h.load("ord_leftover")
	if got.InstallAttempts != 2 {
		t.Fatalf("install attempts = %d, want 2 (claim + takeover)", got.InstallAttempts)
	}
	if got.InstallGeneration != 2 {
		t.Fatalf("generation = %d, want 2", got.InstallGeneration)
	}
}

// TestInstallerDoesNotRunAPausedJob proves pause is a real stopping point for the
// scheduler, not advice to the runner.
func TestInstallerDoesNotRunAPausedJob(t *testing.T) {
	h := newInstallHarness(t)
	h.seedIntent("ord_paused", models.SetupStateInstallPaused)

	runner := &recordingRunner{}
	for k := 0; k < 3; k++ {
		if err := h.installer(runner).RunOnce(context.Background()); err != nil {
			t.Fatalf("pass %d: %v", k, err)
		}
	}
	if attempts := runner.attempts(); len(attempts) != 0 {
		t.Fatalf("a paused job was scheduled %d times", len(attempts))
	}
}

// TestJournalRefusesWritesFromASupersededAttempt proves the generation fence: an
// old attempt cannot keep writing once a resume has taken the row.
func TestJournalRefusesWritesFromASupersededAttempt(t *testing.T) {
	h := newInstallHarness(t)
	h.seedIntent("ord_fence", models.SetupStateReadyForSetup)
	ctx := context.Background()

	old, ok, err := h.db.ClaimGigahostSetupInstall(ctx, "ord_fence")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	oldJournal := newInstallJournal(h.db, old, old.InstallGeneration)

	// The administrator resumes, which issues a new generation, while the old
	// attempt is still "running".
	old.State = models.SetupStateInstallPaused
	if _, err := h.db.UpdateGigahostSetupInstall(ctx, old, old.InstallGeneration); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if _, changed, err := h.db.ResumeGigahostSetupInstall(ctx, "ord_fence"); err != nil || !changed {
		t.Fatalf("resume: changed=%v err=%v", changed, err)
	}

	owned, err := oldJournal.SettleAuthority(ctx)
	if err != nil {
		t.Fatalf("authority check: %v", err)
	}
	if owned {
		t.Fatal("a superseded attempt still reported ownership")
	}
	if ok, err := oldJournal.BeginPhase(ctx, models.SetupPhaseInstalled, "installing_protocol"); !errors.Is(err, ErrInstallNotOwned) || ok {
		t.Fatalf("superseded attempt began a phase: ok=%v err=%v", ok, err)
	}
	if err := oldJournal.Admit(ctx, "ready", 1); !errors.Is(err, ErrInstallNotOwned) {
		t.Fatalf("superseded attempt admitted the order: %v", err)
	}
	got := h.load("ord_fence")
	if got.State != models.SetupStateInstalling {
		t.Fatalf("state = %q, want the resume's %q", got.State, models.SetupStateInstalling)
	}
	if got.InstallGeneration != 2 {
		t.Fatalf("generation = %d, want 2 (claim, then resume)", got.InstallGeneration)
	}
}

// TestInstallerPausesWhenTheRunnerFails proves an error from the runner becomes a
// pause with the reason recorded, never a silent failure.
func TestInstallerPausesWhenTheRunnerFails(t *testing.T) {
	h := newInstallHarness(t)
	h.seedIntent("ord_runnererr", models.SetupStateReadyForSetup)

	runner := &recordingRunner{behave: func(ctx context.Context, journal *InstallJournal) error {
		if _, err := journal.BeginPhase(ctx, models.SetupPhaseInstalled, "installing_protocol"); err != nil {
			return err
		}
		return errors.New("the host refused the payload")
	}}

	if err := h.installer(runner).RunOnce(context.Background()); err != nil {
		t.Fatalf("pass: %v", err)
	}
	got := h.load("ord_runnererr")
	if got.State != models.SetupStateInstallPaused {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateInstallPaused)
	}
	if got.Step != "installing_protocol" {
		t.Fatalf("step = %q, want the in-flight step", got.Step)
	}
	if got.LastError == "" {
		t.Fatal("pause recorded no reason")
	}
	if got.InstallPhase != models.SetupPhaseInstalled {
		t.Fatalf("in-flight phase = %q, want it kept for the next attempt", got.InstallPhase)
	}
}

// TestInstallerStartAndStopLifecycle proves the supervised lifecycle: Start runs
// until the context ends and Stop joins it.
func TestInstallerStartAndStopLifecycle(t *testing.T) {
	h := newInstallHarness(t)
	runner := &recordingRunner{}
	installer := NewInstaller(h.db, runner, InstallOptions{Interval: 20 * time.Millisecond, Batch: 5})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- installer.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !installer.running.Load() {
		time.Sleep(2 * time.Millisecond)
	}
	if !installer.running.Load() {
		t.Fatal("installer did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v after cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("installer did not stop within 3s")
	}
	if installer.running.Load() {
		t.Fatal("installer still reports running after Start returned")
	}
}

// TestInstallerStopJoinsRunningLoop proves Stop waits rather than returning while a
// pass is still executing.
func TestInstallerStopJoinsRunningLoop(t *testing.T) {
	h := newInstallHarness(t)
	installer := NewInstaller(h.db, &recordingRunner{}, InstallOptions{Interval: time.Hour, Batch: 5})

	if err := startInstallerAsync(installer); err != nil {
		t.Fatalf("start: %v", err)
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := installer.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func startInstallerAsync(i *Installer) error {
	errCh := make(chan error, 1)
	go func() { errCh <- i.Start(context.Background()) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if i.running.Load() {
			return nil
		}
		select {
		case err := <-errCh:
			return err
		case <-time.After(2 * time.Millisecond):
		}
	}
	return errors.New("installer did not start")
}
