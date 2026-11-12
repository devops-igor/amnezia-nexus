package handlers

// The exact post-promotion, pre-terminal-journal window: the last moment authority can
// change after the promotion effect has already committed.
//
// Where the window is, from source:
//
//	installEnableStep -> enableDeployBackend -> qualify -> pre-commit policy gate (ok)
//	                  -> PromoteQualifiedTunnel   (commits status=active AND releases the
//	                                               durable enrollment marker atomically)
//	                  -> journal.CompletePhase(enabled)   <-- the barrier is here
//	finishInstall     -> journal.Admit("ready")
//
// CompletePhase writes through InstallStore.UpdateGigahostSetupInstall, which a
// test-owned decorator can observe. That decorator needs no production seam, no new hook
// and no runtime mode, and it still fires on corrected code because CompletePhase is still
// called there - so the proof does not depend on the code the correction removed.
//
// Everything asserted about the interval is measured inside that barrier; the meaning for
// the final state is asserted after finalization.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// statefulPolicy is an automation policy whose answer is a real, latched state transition
// that it reads back on every call.
//
// This replaces the earlier fixture, whose "withdrawal" was a field nothing consulted:
// that Enabled() recomputed its answer from pool state and never read the flag, so
// setting the flag changed nothing and no transition was ever exercised.
type statefulPolicy struct {
	mu      sync.Mutex
	enabled bool
	queries int
}

func newStatefulPolicy(enabled bool) *statefulPolicy {
	return &statefulPolicy{enabled: enabled}
}

func (p *statefulPolicy) Enabled(context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.queries++
	return p.enabled, nil
}

// setDisabled performs the administrator's withdrawal.
func (p *statefulPolicy) setDisabled() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = false
}

// answer reports the current answer, which is what the test asserts after the flip.
func (p *statefulPolicy) answer() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled
}

func (p *statefulPolicy) queryCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.queries
}

// intervalStore forwards to the real store and fires beforeComplete exactly once, on the
// journalled completion of the enablement phase.
//
// It follows admitInterruptStore (gigahost_setup_r14_withdrawal_test.go), which already
// established UpdateGigahostSetupInstall as the right observation point for this interval.
type intervalStore struct {
	*database.DB
	beforeComplete func(*models.GigahostSetupIntent)
}

func (s *intervalStore) UpdateGigahostSetupInstall(
	ctx context.Context, intent *models.GigahostSetupIntent, gen int64,
) (bool, error) {
	if intent.State == models.SetupStateInstalling &&
		intent.InstallPhaseDone == models.SetupPhaseEnabled && s.beforeComplete != nil {
		fn := s.beforeComplete
		s.beforeComplete = nil
		fn(intent)
	}
	return s.DB.UpdateGigahostSetupInstall(ctx, intent, gen)
}

// intervalObservation records what was true while the job sat between a committed
// promotion and its terminal journal write.
type intervalObservation struct {
	reached      bool
	selectable   bool
	state        string
	step         string
	phaseDone    string
	policyAnswer bool
}

// installPassToBarrier drives one real install attempt over the observing store.
//
// onEnter runs inside the interval, after the observation is taken and before the journal
// write that lets finalization proceed.
func installPassToBarrier(
	env *installEnv, providerServerID int64, onEnter func(),
) (intervalObservation, error) {
	obs := intervalObservation{}
	store := &intervalStore{
		DB: env.db,
		beforeComplete: func(intent *models.GigahostSetupIntent) {
			obs.reached = true
			obs.state = intent.State
			obs.step = intent.Step
			obs.phaseDone = intent.InstallPhaseDone
			if server := env.registeredServer(providerServerID); server != nil {
				obs.selectable = authenticPoolContains(env.t, env, server.ID)
			}
			if onEnter != nil {
				onEnter()
			}
		},
	}
	installer := gigahostsetup.NewInstaller(store, env.h.NewSetupInstallRunner(),
		gigahostsetup.InstallOptions{Interval: time.Second})
	return obs, installer.RunOnce(context.Background())
}

// TestAutomaticJobPolicyWithdrawnInsidePostPromotionWindow is the decisive regression.
//
// Inside the barrier that fires after the promotion commit and before journal.Admit:
// record that the target is selectable, record that the reloaded job is still nonterminal,
// withdraw the policy, and confirm the policy's own answer changed. Only then is
// finalization released.
func TestAutomaticJobPolicyWithdrawnInsidePostPromotionWindow(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_window_inside", 9411)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(env.orderID, models.SetupStateReadyForSetup)

	policy := newStatefulPolicy(true)
	env.h.SetGigahostSetupAutomationPolicyForTest(policy)

	obs, err := installPassToBarrier(env.installEnv, env.providerServerID, func() { policy.setDisabled() })
	if err != nil {
		t.Fatalf("install pass: %v", err)
	}

	// The interval was genuinely entered; without this the rest would prove nothing.
	if !obs.reached {
		t.Fatal("the barrier never fired, so the promotion-to-admission interval was not " +
			"reached and this test says nothing about it")
	}
	if !obs.selectable {
		t.Fatal("precondition: the target was not selectable at the barrier, so the promotion " +
			"had not committed when the policy was withdrawn")
	}
	if obs.state != models.SetupStateInstalling {
		t.Fatalf("at the barrier the job was %q, want the nonterminal %q so the terminal "+
			"journal had not been written yet", obs.state, models.SetupStateInstalling)
	}
	obs.policyAnswer = policy.answer()
	if obs.policyAnswer {
		t.Fatal("the policy still answers enabled after the withdrawal, so no transition was " +
			"exercised")
	}
	if policy.queryCount() == 0 {
		t.Fatal("the policy was never consulted, so the gate did not run")
	}

	// Finalization has completed. Accepted semantic: a committed promotion is a completed
	// authorized admission, so the row says ready beside a selectable target.
	final := env.intent(env.orderID)
	server := env.registeredServer(env.providerServerID)
	if server == nil {
		t.Fatal("no panel server was registered, so admission was never reached")
	}
	selectable := authenticPoolContains(t, env.installEnv, server.ID)

	if final.State == models.SetupStateInstallPaused && selectable {
		t.Fatalf("the job is recorded %q while its backend is selectable: durable state and "+
			"pool membership disagree (step %q, last error %q)",
			final.State, final.Step, final.LastError)
	}
	if !selectable {
		t.Fatalf("the target stopped being selectable after a committed promotion (state %q "+
			"step %q last error %q)", final.State, final.Step, final.LastError)
	}
	if final.State != models.SetupStateReady {
		t.Fatalf("a selectable target behind a completed promotion was recorded as %q "+
			"(step %q, last error %q), want %q",
			final.State, final.Step, final.LastError, models.SetupStateReady)
	}

	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1", enables)
	}
	if final.HostFingerprint != env.presented {
		t.Fatalf("the pin was revoked: %q", final.HostFingerprint)
	}
}

// TestAutomaticJobPolicyWithdrawnInsideWindowLeavesUnrelatedBackendHealthy proves the
// in-window withdrawal is scoped to its own job.
func TestAutomaticJobPolicyWithdrawnInsideWindowLeavesUnrelatedBackendHealthy(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_window_scoped", 9412)
	ctx := context.Background()

	neighbourID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "window-neighbour", Host: "198.51.100.212", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 9512,
			models.ProtocolAWG: map[string]any{
				"installed": true, "port": "51822",
				"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
			},
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register unrelated server: %v", err)
	}
	if err := env.h.enableDeployBackend(ctx, &models.Server{ID: neighbourID, Host: "198.51.100.212",
		Protocols: map[string]any{models.ProtocolAWG: map[string]any{
			"installed": true, "port": "51822",
			"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
		}}}, models.ProtocolAWG); err != nil {
		t.Fatalf("admit the unrelated backend: %v", err)
	}
	if !authenticPoolContains(t, env.installEnv, neighbourID) {
		t.Fatal("precondition: the unrelated backend is not selectable")
	}
	before, err := env.h.vpnSvc.GetTunnel(neighbourID)
	if err != nil || before == nil {
		t.Fatalf("read unrelated tunnel: %v", err)
	}
	versionBefore := before.StateVersion

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	policy := newStatefulPolicy(true)
	env.h.SetGigahostSetupAutomationPolicyForTest(policy)

	obs, err := installPassToBarrier(env.installEnv, env.providerServerID, func() { policy.setDisabled() })
	if err != nil {
		t.Fatalf("install pass: %v", err)
	}
	if !obs.reached || !obs.selectable {
		t.Fatal("the promotion-to-admission interval was not entered with a selectable target")
	}

	if !authenticPoolContains(t, env.installEnv, neighbourID) {
		t.Fatal("an in-window policy withdrawal removed an unrelated healthy backend from the " +
			"production pool")
	}
	after, err := env.h.vpnSvc.GetTunnel(neighbourID)
	if err != nil || after == nil {
		t.Fatalf("re-read unrelated tunnel: %v", err)
	}
	if !after.Enabled || after.Status != before.Status {
		t.Fatalf("the unrelated backend changed: enabled %v->%v status %q->%q",
			before.Enabled, after.Enabled, before.Status, after.Status)
	}
	if after.StateVersion != versionBefore {
		t.Fatalf("the unrelated backend's state version advanced %d->%d",
			versionBefore, after.StateVersion)
	}
}

// TestAutomaticJobRepeatPassAfterInWindowWithdrawalDoesNotReinstall proves a repeat pass
// over a completed job does not replay the install or enablement.
func TestAutomaticJobRepeatPassAfterInWindowWithdrawalDoesNotReinstall(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_window_repeat", 9413)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	policy := newStatefulPolicy(true)
	env.h.SetGigahostSetupAutomationPolicyForTest(policy)

	obs, err := installPassToBarrier(env.installEnv, env.providerServerID, func() { policy.setDisabled() })
	if err != nil {
		t.Fatalf("install pass: %v", err)
	}
	if !obs.reached || !obs.selectable {
		t.Fatal("the promotion-to-admission interval was not entered with a selectable target")
	}
	server := env.registeredServer(env.providerServerID)
	if server == nil || !authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatal("precondition: the target was not admitted")
	}
	installsBefore := env.counters.totalInstalls()

	if err := env.h.NewGigahostSetupInstaller().RunOnce(ctx); err != nil {
		t.Fatalf("repeat install pass: %v", err)
	}

	if got := env.counters.totalInstalls(); got != installsBefore {
		t.Fatalf("a repeat pass reinstalled a completed protocol: %d -> %d", installsBefore, got)
	}
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if enables != 1 {
		t.Fatalf("backend enablements = %d, want exactly 1", enables)
	}
	if !authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatal("a repeat pass removed a healthy admitted backend from the pool")
	}
	if got := env.intent(env.orderID); got.State != models.SetupStateReady {
		t.Fatalf("a repeat pass changed the terminal state to %q", got.State)
	}
}

// TestAutomaticJobRefusesBeforePromotionWhenPolicyIsAlreadyOff is the companion control:
// the same withdrawal, but before promotion, must still refuse and leave the target
// unselectable - so the in-window result cannot be misread as the gate being removed.
func TestAutomaticJobRefusesBeforePromotionWhenPolicyIsAlreadyOff(t *testing.T) {
	env := newAutomaticJobEnv(t, "ord_window_before", 9414)
	ctx := context.Background()

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	policy := newStatefulPolicy(false)
	env.h.SetGigahostSetupAutomationPolicyForTest(policy)

	obs, err := installPassToBarrier(env.installEnv, env.providerServerID, nil)
	if err != nil {
		t.Fatalf("install pass: %v", err)
	}
	// The barrier must NOT be reached: enablement never completes, so the promotion never
	// commits and there is no interval to observe.
	if obs.reached {
		t.Fatal("a job refused before promotion still reached the completed-enablement " +
			"journal write, so the pre-promotion gate did not stop it")
	}

	final := env.intent(env.orderID)
	if final.State == models.SetupStateReady {
		t.Fatal("a job whose policy was withdrawn before promotion was recorded ready")
	}
	if server := env.registeredServer(env.providerServerID); server != nil &&
		authenticPoolContains(t, env.installEnv, server.ID) {
		t.Fatal("a target refused before promotion is still selectable")
	}
}
