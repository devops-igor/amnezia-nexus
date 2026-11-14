package handlers

// Recovery of an automatic job whose admission completed but whose terminal journal
// write never happened.
//
// The interruption is produced at the real store boundary, not by seeding an admitted
// row: one real install attempt runs through the real runner, journal, VPN enablement,
// qualification and promotion transaction, and is stopped by a panic at the exact
// journal write. A fresh production installer then takes the unfinished row over, as it
// would after a process restart.
//
// The two post-promotion boundaries are the enabled-phase completion write and the
// terminal admission write. Each is recovered under an enabled, a disabled and an
// unreadable policy. The negatives cover every way admission can be unproven -
// interrupted before enablement, enablement in flight with no backend, a backend still
// in enrollment quarantine, a backend withdrawn after promotion and an ownership record
// that names another server - and require the ordinary policy refusal with no new
// authentication, installation or enablement.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// errRecoveryStop is the controlled interruption. It is a panic, not an error, so the
// attempt stops exactly where a dying process would: no pause and no cleanup is written.
var errRecoveryStop = errors.New("controlled interruption at a setup journal write")

// recoveryStopStore forwards every journal write to the real store and acts once, at
// the first write the matcher selects.
//
// By default it panics before that write reaches the database. afterWrite lets the
// write land first. onMatch replaces the panic with another action, such as an
// administrator's cancellation arriving at that moment.
type recoveryStopStore struct {
	*database.DB
	match      func(*models.GigahostSetupIntent) bool
	afterWrite bool
	onMatch    func()
}

func (s *recoveryStopStore) UpdateGigahostSetupInstall(
	ctx context.Context, intent *models.GigahostSetupIntent, gen int64,
) (bool, error) {
	if s.match == nil || !s.match(intent) {
		return s.DB.UpdateGigahostSetupInstall(ctx, intent, gen)
	}
	s.match = nil
	if s.onMatch != nil {
		s.onMatch()
		return s.DB.UpdateGigahostSetupInstall(ctx, intent, gen)
	}
	if !s.afterWrite {
		panic(errRecoveryStop)
	}
	changed, err := s.DB.UpdateGigahostSetupInstall(ctx, intent, gen)
	if err != nil || !changed {
		return changed, err
	}
	panic(errRecoveryStop)
}

// The journal writes an interruption can be placed at.
func atEnablementStart(i *models.GigahostSetupIntent) bool {
	return i.State == models.SetupStateInstalling && i.InstallPhase == models.SetupPhaseEnabled
}

func atEnabledPhaseCompletion(i *models.GigahostSetupIntent) bool {
	return i.State == models.SetupStateInstalling && i.InstallPhaseDone == models.SetupPhaseEnabled
}

func atTerminalAdmission(i *models.GigahostSetupIntent) bool {
	return i.State == models.SetupStateReady
}

// newRecoveryJob builds an automatic job at the install handoff under an enabled policy.
func newRecoveryJob(t *testing.T, orderID string, providerServerID int64) *automaticJobEnv {
	t.Helper()
	env := newAutomaticJobEnv(t, orderID, providerServerID)
	if err := env.h.NewGigahostSetupTracker().RunOnce(context.Background()); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)
	return env
}

// runInterrupted performs one real install attempt over store and requires that it was
// stopped by the controlled interruption.
func runInterrupted(t *testing.T, env *installEnv, store gigahostsetup.InstallStore) {
	t.Helper()
	stopped := false
	func() {
		defer func() {
			if p := recover(); p != nil {
				if p != errRecoveryStop {
					panic(p)
				}
				stopped = true
			}
		}()
		installer := gigahostsetup.NewInstaller(store, env.h.NewSetupInstallRunner(),
			gigahostsetup.InstallOptions{Interval: time.Second})
		if err := installer.RunOnce(context.Background()); err != nil {
			t.Fatalf("interrupted install pass: %v", err)
		}
	}()
	if !stopped {
		t.Fatal("the interruption boundary was never reached, so this case proves nothing")
	}
}

// interruptAt stops the first attempt at the selected journal write.
func interruptAt(t *testing.T, env *installEnv, match func(*models.GigahostSetupIntent) bool, afterWrite bool) {
	t.Helper()
	runInterrupted(t, env, &recoveryStopStore{DB: env.db, match: match, afterWrite: afterWrite})
}

// interruptDuringQualification stops the first attempt after the backend was enrolled
// and before qualification could promote it, so the durable quarantine is still set.
func interruptDuringQualification(t *testing.T, env *installEnv) {
	t.Helper()
	env.h.vpnSvc.SetEnableBackendPostAddTunnelHookForTest(func() { panic(errRecoveryStop) })
	defer env.h.vpnSvc.SetEnableBackendPostAddTunnelHookForTest(nil)
	runInterrupted(t, env, env.db)
}

// admitUnrelatedBackend registers and admits a backend no setup job owns.
func admitUnrelatedBackend(t *testing.T, env *installEnv, providerServerID int64, host string) int64 {
	t.Helper()
	ctx := context.Background()
	awg := map[string]any{
		"installed": true, "port": "51822",
		"public_key": "x9aB1234567890abcdef1234567890abcdef1234567=",
	}
	id, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "recovery-neighbour", Host: host, SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": providerServerID, models.ProtocolAWG: awg,
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register unrelated server: %v", err)
	}
	if err := env.h.enableDeployBackend(ctx, &models.Server{ID: id, Host: host,
		Protocols: map[string]any{models.ProtocolAWG: awg}}, models.ProtocolAWG); err != nil {
		t.Fatalf("admit unrelated backend: %v", err)
	}
	if !authenticPoolContains(t, env, id) {
		t.Fatal("precondition: the unrelated backend is not selectable")
	}
	return id
}

// recoveryEffects is every effect a recovery must not repeat or newly perform.
type recoveryEffects struct {
	installs, enables  int
	auths, sessions    int32
	generation         int64
	pin                string
	neighbourVersion   int64
	neighbourSelected  bool
	neighbourEnabled   bool
	neighbourStatus    string
	neighbourServerID  int64
	hasNeighbourRecord bool
}

func captureRecoveryEffects(t *testing.T, env *automaticJobEnv, neighbourID int64) recoveryEffects {
	t.Helper()
	row := env.intent(env.orderID)
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	got := recoveryEffects{
		installs: env.counters.totalInstalls(), enables: enables,
		auths: env.peer.auths.Load(), sessions: env.peer.sessions.Load(),
		generation: row.InstallGeneration, pin: row.HostFingerprint,
	}
	if neighbourID > 0 {
		tun, err := env.h.vpnSvc.GetTunnel(neighbourID)
		if err != nil || tun == nil {
			t.Fatalf("read unrelated tunnel: %v", err)
		}
		got.hasNeighbourRecord = true
		got.neighbourServerID = neighbourID
		got.neighbourVersion = tun.StateVersion
		got.neighbourEnabled = tun.Enabled
		got.neighbourStatus = tun.Status
		got.neighbourSelected = authenticPoolContains(t, env.installEnv, neighbourID)
	}
	return got
}

// requireNoNewEffects compares the effects after recovery with those before it.
func requireNoNewEffects(t *testing.T, before, after recoveryEffects) {
	t.Helper()
	if after.generation <= before.generation {
		t.Fatalf("no takeover happened: generation %d -> %d", before.generation, after.generation)
	}
	if after.installs != before.installs || after.enables != before.enables {
		t.Fatalf("recovery repeated a completed effect: installs %d->%d enables %d->%d",
			before.installs, after.installs, before.enables, after.enables)
	}
	if after.auths != before.auths || after.sessions != before.sessions {
		t.Fatalf("recovery performed new SSH work: authentications %d->%d sessions %d->%d",
			before.auths, after.auths, before.sessions, after.sessions)
	}
	if after.pin != before.pin || after.pin == "" {
		t.Fatalf("recovery changed the pin: %q -> %q", before.pin, after.pin)
	}
	if before.hasNeighbourRecord && (after.neighbourVersion != before.neighbourVersion ||
		after.neighbourEnabled != before.neighbourEnabled || after.neighbourStatus != before.neighbourStatus ||
		after.neighbourSelected != before.neighbourSelected) {
		t.Fatalf("recovery disturbed an unrelated backend: %+v -> %+v", before, after)
	}
}

// recoverWithFreshInstaller runs the production installer once, as a restarted panel would.
func recoverWithFreshInstaller(t *testing.T, env *installEnv) {
	t.Helper()
	if err := env.h.NewGigahostSetupInstaller().RunOnce(context.Background()); err != nil {
		t.Fatalf("recovery install pass: %v", err)
	}
}

// storedBackend reloads the job's backend from the database, independently of the pool.
func storedBackend(t *testing.T, env *installEnv, serverID int64) *models.BackendTunnel {
	t.Helper()
	stored, err := env.db.GetBackendTunnelByServerID(context.Background(), serverID)
	if err != nil {
		t.Fatalf("reload stored backend: %v", err)
	}
	return stored
}

var recoveryPolicies = []struct {
	name string
	set  func(*stubAutomationPolicy)
}{
	{"policy_on", func(*stubAutomationPolicy) {}},
	{"policy_off", func(p *stubAutomationPolicy) { p.setEnabled(false) }},
	{"policy_unreadable", func(p *stubAutomationPolicy) { p.setError(errPolicySourceUnavailable) }},
}

// TestAutomaticRecoveryFinalizesAnInterruptedCompletedAdmission is the regression for a
// takeover that paused a job whose backend was already admitted.
//
// A real promotion commits, the attempt dies before the terminal journal, and a fresh
// installer takes the row over. Whatever the current policy says, the recovered row must
// record the admission that actually happened - ready beside a selectable backend - and
// recovery must perform no new SSH, install or enablement and leave the pin and an
// unrelated backend untouched.
func TestAutomaticRecoveryFinalizesAnInterruptedCompletedAdmission(t *testing.T) {
	boundaries := []struct {
		name  string
		match func(*models.GigahostSetupIntent) bool
	}{
		{"before_enabled_journal", atEnabledPhaseCompletion},
		{"before_terminal_journal", atTerminalAdmission},
	}
	for _, boundary := range boundaries {
		for _, policy := range recoveryPolicies {
			t.Run(boundary.name+"/"+policy.name, func(t *testing.T) {
				env := newRecoveryJob(t, "ord_recovery_completed", 9621)
				neighbourID := admitUnrelatedBackend(t, env.installEnv, 9622, "198.51.100.222")
				interruptAt(t, env.installEnv, boundary.match, false)

				unfinished := env.requireState(env.orderID, models.SetupStateInstalling)
				server := env.registeredServer(env.providerServerID)
				if server == nil || !authenticPoolContains(t, env.installEnv, server.ID) ||
					authenticDurableQuarantine(t, env.installEnv, server.ID) {
					t.Fatal("precondition: the interrupted attempt did not leave a promoted backend")
				}
				before := captureRecoveryEffects(t, env, neighbourID)
				policy.set(env.policy)

				recoverWithFreshInstaller(t, env.installEnv)

				final := env.intent(env.orderID)
				after := captureRecoveryEffects(t, env, neighbourID)
				selectable := authenticPoolContains(t, env.installEnv, server.ID)
				quarantined := authenticDurableQuarantine(t, env.installEnv, server.ID)
				stored := storedBackend(t, env.installEnv, server.ID)
				t.Logf("recovery: journal %q/%q -> state=%s step=%s selectable=%v quarantine=%v "+
					"stored_enabled=%v stored_status=%s generation=%d->%d",
					unfinished.InstallPhase, unfinished.InstallPhaseDone, final.State, final.Step,
					selectable, quarantined, stored != nil && stored.Enabled, storedStatus(stored),
					before.generation, after.generation)

				if final.State == models.SetupStateInstallPaused && selectable {
					t.Fatalf("recovery recorded %q (step %q) beside a selectable backend", final.State, final.Step)
				}
				if final.State != models.SetupStateReady || final.Step != "ready" || final.LastError != "" {
					t.Fatalf("completed admission not finalized: state=%q step=%q last_error=%q",
						final.State, final.Step, final.LastError)
				}
				if final.InstallPhaseDone != models.SetupPhaseEnabled || final.NexusServerID != server.ID {
					t.Fatalf("terminal journal phase=%q server=%d, want %q/%d",
						final.InstallPhaseDone, final.NexusServerID, models.SetupPhaseEnabled, server.ID)
				}
				if !selectable || quarantined || stored == nil || !stored.Enabled {
					t.Fatalf("the admitted backend changed: selectable=%v quarantine=%v stored=%+v",
						selectable, quarantined, stored)
				}
				requireNoNewEffects(t, before, after)
			})
		}
	}
}

func storedStatus(tun *models.BackendTunnel) string {
	if tun == nil {
		return "<absent>"
	}
	return tun.Status
}

// TestAutomaticRecoveryRefusesWhenAdmissionIsNotProven keeps the policy authoritative for
// work that was not admitted.
//
// Each case leaves an unfinished row whose admission the durable records do not prove.
// Under a disabled or unreadable policy recovery must be the ordinary refusal: paused
// with the policy step, no SSH authentication, install or enablement, and - where the
// job's own backend is not admitted - nothing selectable.
func TestAutomaticRecoveryRefusesWhenAdmissionIsNotProven(t *testing.T) {
	cases := []struct {
		name string
		// interrupt produces the unproven state.
		interrupt func(t *testing.T, env *automaticJobEnv, neighbourID int64)
	}{
		{
			name: "interrupted_before_enablement",
			interrupt: func(t *testing.T, env *automaticJobEnv, _ int64) {
				interruptAt(t, env.installEnv, atEnablementStart, false)
			},
		},
		{
			name: "enablement_in_flight_without_backend",
			interrupt: func(t *testing.T, env *automaticJobEnv, _ int64) {
				interruptAt(t, env.installEnv, atEnablementStart, true)
			},
		},
		{
			name: "backend_still_in_enrollment_quarantine",
			interrupt: func(t *testing.T, env *automaticJobEnv, _ int64) {
				interruptDuringQualification(t, env.installEnv)
				server := env.registeredServer(env.providerServerID)
				if server == nil || !authenticDurableQuarantine(t, env.installEnv, server.ID) {
					t.Fatal("precondition: the enrolled backend is not durably quarantined")
				}
			},
		},
		{
			name: "backend_withdrawn_after_promotion",
			interrupt: func(t *testing.T, env *automaticJobEnv, _ int64) {
				interruptAt(t, env.installEnv, atEnabledPhaseCompletion, false)
				server := env.registeredServer(env.providerServerID)
				if err := env.h.vpnSvc.DisableBackend(context.Background(), server.ID); err != nil {
					t.Fatalf("withdraw the backend: %v", err)
				}
			},
		},
		{
			// The journal reached enablement but no own backend exists, and the
			// ownership record names the unrelated admitted backend. Its admission must
			// not be claimed as this job's.
			name: "ownership_record_names_another_server",
			interrupt: func(t *testing.T, env *automaticJobEnv, neighbourID int64) {
				interruptAt(t, env.installEnv, atEnablementStart, true)
				row := env.intent(env.orderID)
				row.NexusServerID = neighbourID
				if ok, err := env.db.UpdateGigahostSetupInstall(context.Background(), row,
					row.InstallGeneration); err != nil || !ok {
					t.Fatalf("rewrite ownership record: ok=%v err=%v", ok, err)
				}
			},
		},
	}
	for _, tc := range cases {
		for _, policy := range recoveryPolicies[1:] {
			t.Run(tc.name+"/"+policy.name, func(t *testing.T) {
				env := newRecoveryJob(t, "ord_recovery_unproven", 9631)
				neighbourID := admitUnrelatedBackend(t, env.installEnv, 9632, "198.51.100.232")
				tc.interrupt(t, env, neighbourID)
				env.requireState(env.orderID, models.SetupStateInstalling)
				before := captureRecoveryEffects(t, env, neighbourID)
				policy.set(env.policy)

				recoverWithFreshInstaller(t, env.installEnv)

				final := env.requireDisabledStop(t)
				after := captureRecoveryEffects(t, env, neighbourID)
				if final.State != models.SetupStateInstallPaused {
					t.Fatalf("state = %q, want %q", final.State, models.SetupStateInstallPaused)
				}
				requireNoNewEffects(t, before, after)
				selectable := false
				if server := env.registeredServer(env.providerServerID); server != nil {
					selectable = authenticPoolContains(t, env.installEnv, server.ID)
				}
				t.Logf("refusal: state=%s step=%s own_selectable=%v", final.State, final.Step, selectable)
				if selectable {
					t.Fatalf("recovery left %q (step %q) beside a selectable backend", final.State, final.Step)
				}
			})
		}
	}
}

// TestAutomaticRecoveryNeverRevivesACanceledAdmission keeps explicit cancellation the
// one operation that withdraws an admitted backend, before and during recovery.
func TestAutomaticRecoveryNeverRevivesACanceledAdmission(t *testing.T) {
	t.Run("canceled_after_interruption", func(t *testing.T) {
		env := newRecoveryJob(t, "ord_recovery_cancel_after", 9641)
		interruptAt(t, env.installEnv, atEnabledPhaseCompletion, false)
		server := env.registeredServer(env.providerServerID)
		env.policy.setEnabled(false)
		if _, changed, err := env.h.CancelGigahostSetup(context.Background(), env.orderID); err != nil || !changed {
			t.Fatalf("cancel: changed=%v err=%v", changed, err)
		}
		recoverWithFreshInstaller(t, env.installEnv)
		env.requireState(env.orderID, models.SetupStateCanceled)
		assertWithdrawn(t, env.installEnv, server.ID, "cancel after interruption")
	})
	t.Run("canceled_during_recovery", func(t *testing.T) {
		env := newRecoveryJob(t, "ord_recovery_cancel_during", 9642)
		interruptAt(t, env.installEnv, atEnabledPhaseCompletion, false)
		server := env.registeredServer(env.providerServerID)
		env.policy.setEnabled(false)
		reached := false
		store := &recoveryStopStore{DB: env.db, match: atTerminalAdmission, onMatch: func() {
			reached = true
			if _, changed, err := env.h.CancelGigahostSetup(context.Background(), env.orderID); err != nil || !changed {
				t.Errorf("cancel during recovery: changed=%v err=%v", changed, err)
			}
		}}
		installer := gigahostsetup.NewInstaller(store, env.h.NewSetupInstallRunner(),
			gigahostsetup.InstallOptions{Interval: time.Second})
		if err := installer.RunOnce(context.Background()); err != nil {
			t.Fatalf("recovery install pass: %v", err)
		}
		if !reached {
			t.Fatal("recovery never reached its terminal admission write")
		}
		env.requireState(env.orderID, models.SetupStateCanceled)
		assertWithdrawn(t, env.installEnv, server.ID, "cancel during recovery")
	})
}

// TestAutomaticRecoveryProofIsIndependentOfStartupHealthReset separates the durable proof
// of a completed promotion from the backend's current runtime health.
//
// Panel startup rewrites every enabled backend's stored status to connecting until the
// prober has fresh evidence. That reset leaves administrative enablement and the released
// enrollment quarantine alone, so the prober can return the backend to the pool. A
// recovery that treated status as the proof would pause an admitted job after every
// restart; the proof must be the durable admission record.
func TestAutomaticRecoveryProofIsIndependentOfStartupHealthReset(t *testing.T) {
	env := newRecoveryJob(t, "ord_recovery_startup", 9651)
	interruptAt(t, env.installEnv, atEnabledPhaseCompletion, false)
	server := env.registeredServer(env.providerServerID)
	ctx := context.Background()
	if err := env.db.ResetEnabledBackendTunnelHealthForStartup(ctx); err != nil {
		t.Fatalf("startup health reset: %v", err)
	}
	if stored := storedBackend(t, env.installEnv, server.ID); stored == nil ||
		stored.Status != models.TunnelStatusConnecting {
		t.Fatalf("precondition: stored status after the startup reset = %q", storedStatus(stored))
	}
	before := captureRecoveryEffects(t, env, 0)
	env.policy.setEnabled(false)

	recoverWithFreshInstaller(t, env.installEnv)

	final := env.intent(env.orderID)
	if final.State != models.SetupStateReady {
		t.Fatalf("state = %q (step %q, last error %q), want %q",
			final.State, final.Step, final.LastError, models.SetupStateReady)
	}
	stored := storedBackend(t, env.installEnv, server.ID)
	if stored == nil || !stored.Enabled || authenticDurableQuarantine(t, env.installEnv, server.ID) {
		t.Fatalf("recovery changed the durable admission: %+v", stored)
	}
	requireNoNewEffects(t, before, captureRecoveryEffects(t, env, 0))
}
