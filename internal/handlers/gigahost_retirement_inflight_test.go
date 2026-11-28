package handlers

// Retirement stops a saved installer that is already in flight.
//
// A saved approval reaches ready_for_setup, the installer reads the order as live, claims
// the row and begins work. The administrator's inventory refresh then records a complete,
// own-account omission, which is the panel's own statement that the deployment is gone. There
// is no registered server at that point, so no server-row mark can protect the path, and the
// order ledger change reaches nothing that holds the approval.
//
// The attempt must stop before the next effect. It does, because every effect-bearing phase
// is authorized by a fenced journal write and that write asks the order's own ending inside
// the database critical section. The test therefore interleaves the retirement between the
// claim and a later phase - inside the real protocol manager's Install call, which is the
// effect immediately after registration - rather than asserting a flag or racing a
// background loop.
//
// The control is the identical interleaving with a live order: registration, install and
// enablement all happen, so the correction stops retired work rather than saved installs.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// TestRetirementDuringAnInstallStopsTheRemainingPhases is the in-flight regression.
//
// The retirement is committed by the real list read while the install attempt is waiting on
// SSH verification - after the claim, after the precheck, and before any effect-bearing
// phase has been authorized. Registration, protocol installation and backend enablement must
// all be refused from that point, and the row must say why it stopped.
func TestRetirementDuringAnInstallStopsTheRemainingPhases(t *testing.T) {
	cases := []struct {
		name   string
		retire bool
	}{
		{name: "live-control", retire: false},
		{name: "retired-mid-install", retire: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			ctx := context.Background()
			const orderID = "ord_install_midflight"
			const providerServerID = int64(7404)
			const ip = "198.51.100.44"

			env.seedOrder(orderID, providerServerID, ip)
			env.seedManagedCredential(orderID)
			if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
				t.Fatalf("record the ready ledger row: %v", err)
			}
			if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
				t.Fatalf("record the order's account: %v", err)
			}

			// The tracker settles the approval at the handoff point. The approval already
			// carries a confirmed identity, so no first-contact challenge is needed and the
			// only SSH dial in this test is the install attempt's own verification.
			provider := existenceProvider(t,
				[]gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, Status: gigahost.StatusReady}}, nil, nil)
			provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
				return &gigahost.DeployStatusResponse{OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady}, nil
			}
			env.h.SetGigahostClient(provider)
			env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
			if err := env.tracker(nil).RunOnce(ctx); err != nil {
				t.Fatalf("tracker pass: %v", err)
			}
			env.requireState(orderID, models.SetupStateReadyForSetup)

			// The retirement lands while the attempt waits on SSH verification. The dialer
			// hook is the seam the repository already replaces, so this is the real
			// production runner reaching its real network boundary, not a simulated window.
			previousDialer := env.h.sshDialerHook
			if previousDialer == nil {
				t.Fatal("the install fixture must wire an SSH dialer")
			}
			reached := false
			env.h.SetSSHDialerForTest(func(callCtx context.Context, cfg ssh.Config) (ssh.SSHClient, error) {
				if !reached {
					reached = true
					if tc.retire {
						// The provider inventory now omits the order entirely, and the real
						// list read records that as the panel's existence observation.
						env.h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
					}
					_ = gigahostOrderStatusRead(t, env.h, "")
					if stored := storedOrder(t, env.h, orderID); stored.Retired() != tc.retire {
						t.Errorf("fixture retirement = %v, want %v", stored.Retired(), tc.retire)
					}
				}
				return previousDialer(callCtx, cfg)
			})

			if err := env.installer().RunOnce(ctx); err != nil {
				t.Fatalf("install pass: %v", err)
			}
			if !reached {
				t.Fatal("the fixture never reached SSH verification, so this case proves nothing")
			}
			installs := env.counters.totalInstalls()
			env.counters.mu.Lock()
			enables := env.counters.enables
			env.counters.mu.Unlock()
			registered := env.registeredServer(providerServerID) != nil
			job := env.intent(orderID)

			if tc.retire {
				// The surrender is the recorded outcome: the job is closed, and it says
				// which fact closed it instead of looking paused and resumable.
				if job.State != models.SetupStateCanceled {
					t.Fatalf("state = %q, want %q (step %q, last error %q)",
						job.State, models.SetupStateCanceled, job.Step, job.LastError)
				}
				if job.Step != database.SetupStepOrderEnded {
					t.Errorf("step = %q, want %q so the surrender is diagnosable", job.Step, database.SetupStepOrderEnded)
				}
				if job.LastError == "" {
					t.Error("the closed job records no reason")
				}
				// No effect-bearing phase was authorized: not even the registration that
				// follows SSH verification, which is the first journalled effect.
				if registered {
					t.Error("a retired order registered a panel server")
				}
				if installs != 0 {
					t.Errorf("a retired order completed a protocol installation: installs=%d", installs)
				}
				if enables != 0 {
					t.Errorf("a retired order reached backend enablement: enables=%d", enables)
				}
				if job.InstallPhaseDone != "" {
					t.Errorf("proven phase = %q, want none: the retirement preceded every phase", job.InstallPhaseDone)
				}
				// A closed job is not resumable: the order has no deployment left.
				if _, changed, err := env.h.ResumeGigahostSetup(ctx, orderID); err != nil || changed {
					t.Errorf("a closed job was resumable: changed=%v err=%v", changed, err)
				}
				return
			}

			// The control: with the order still live, the same pass completes normally.
			if job.State != models.SetupStateReady {
				t.Fatalf("live control state = %q, want %q (step %q, last error %q)",
					job.State, models.SetupStateReady, job.Step, job.LastError)
			}
			if installs != 1 {
				t.Errorf("live control protocol installs = %d, want 1", installs)
			}
			if enables != 1 {
				t.Errorf("live control backend enablements = %d, want 1", enables)
			}
			if !registered {
				t.Error("live control did not register a panel server")
			}
		})
	}
}

// TestRetirementBetweenClaimAndFirstPhaseStopsBeforeRegistration proves the fence holds for
// the earliest window: the order ends after the claim but before any effect-bearing phase
// begins, so not even the registration is authorized.
//
// This is the direction a check made only at claim time cannot cover. The claim succeeded
// while the order was live, and the retirement lands in the gap between that claim and the
// first journaled phase.
func TestRetirementBetweenClaimAndFirstPhaseStopsBeforeRegistration(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	const orderID = "ord_install_preclaim"
	const providerServerID = int64(7405)
	const ip = "198.51.100.45"

	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
		t.Fatalf("record the ready ledger row: %v", err)
	}
	if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	provider := existenceProvider(t,
		[]gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, Status: gigahost.StatusReady}}, nil, nil)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady}, nil
	}
	env.h.SetGigahostClient(provider)
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	// The claim succeeds while the order is live: this is the attempt that now owns the row.
	claimed, ok, err := env.db.ClaimGigahostSetupInstall(ctx, orderID)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if claimed.InstallGeneration <= 0 {
		t.Fatalf("claim generation = %d, want a fencing token", claimed.InstallGeneration)
	}

	// The order ends now, between the claim and the first phase.
	env.h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	_ = gigahostOrderStatusRead(t, env.h, "")
	if !storedOrder(t, env.h, orderID).Retired() {
		t.Fatal("the fixture did not retire the order through its inventory read")
	}

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	job := env.intent(orderID)
	if job.State != models.SetupStateCanceled || job.Step != database.SetupStepOrderEnded {
		t.Fatalf("state = %q step = %q, want %q/%q (last error %q)",
			job.State, job.Step, models.SetupStateCanceled, database.SetupStepOrderEnded, job.LastError)
	}
	installs := env.counters.totalInstalls()
	env.counters.mu.Lock()
	dials := env.counters.sshDials
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if installs != 0 || enables != 0 {
		t.Errorf("an order that ended before the first phase still produced effects: installs=%d enables=%d", installs, enables)
	}
	// The takeover re-claims before the precheck, so the SSH dial is bounded by the fenced
	// write that precedes registration; the assertion that matters is that no server row and
	// no install exist.
	if env.registeredServer(providerServerID) != nil {
		t.Error("an order that ended before the first phase still registered a panel server")
	}
	if dials != 0 {
		t.Errorf("an order that ended before the first phase dialled the host: %d dials", dials)
	}
}

// TestInstallerSurrendersAHandoffJobForAnEndedOrder proves the prompt settlement: a job found
// at the handoff point for an already-ended order is closed rather than silently skipped, so
// it stops being listed as work waiting to be picked up.
//
// Without the durable transition the row stays at ready_for_setup with no explanation, and
// the saved-jobs view keeps presenting a job nobody will ever run.
func TestInstallerSurrendersAHandoffJobForAnEndedOrder(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	const orderID = "ord_install_handoff"
	const providerServerID = int64(7406)
	const ip = "198.51.100.46"

	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	if err := env.h.updateDeployOrderStatus(ctx, orderID, gigahost.StatusReady, "", "", providerServerID, 0, ip); err != nil {
		t.Fatalf("record the ready ledger row: %v", err)
	}
	if err := env.db.SetGigahostOrderProviderAccount(ctx, orderID, existenceAccount); err != nil {
		t.Fatalf("record the order's account: %v", err)
	}
	provider := existenceProvider(t,
		[]gigahost.ServerInfo{{ID: providerServerID, OrderID: orderID, Status: gigahost.StatusReady}}, nil, nil)
	provider.getDeployStatusFn = func(context.Context, string) (*gigahost.DeployStatusResponse, error) {
		return &gigahost.DeployStatusResponse{OrderID: orderID, ServerID: providerServerID, AssignedIP: ip, Status: gigahost.StatusReady}, nil
	}
	env.h.SetGigahostClient(provider)
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	env.requireState(orderID, models.SetupStateReadyForSetup)

	// The order ends while the job sits at the handoff point, before any install pass.
	env.h.SetGigahostClient(existenceProvider(t, nil, nil, nil))
	_ = gigahostOrderStatusRead(t, env.h, "")
	if !storedOrder(t, env.h, orderID).Retired() {
		t.Fatal("the fixture did not retire the order through its inventory read")
	}
	// The approval's own row cannot show this: it carries neither the absence observation nor
	// the onboarding journal, which is why the installer has to ask the ledger.
	if job := env.intent(orderID); job.State != models.SetupStateReadyForSetup {
		t.Fatalf("fixture premise: the approval must still be at the handoff point, got %q", job.State)
	}

	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}

	job := env.intent(orderID)
	if job.State != models.SetupStateCanceled || job.Step != database.SetupStepOrderEnded {
		t.Fatalf("state = %q step = %q, want %q/%q (last error %q)",
			job.State, job.Step, models.SetupStateCanceled, database.SetupStepOrderEnded, job.LastError)
	}
	installs := env.counters.totalInstalls()
	env.counters.mu.Lock()
	enables := env.counters.enables
	env.counters.mu.Unlock()
	if installs != 0 || enables != 0 {
		t.Errorf("a handoff job for an ended order produced effects: installs=%d enables=%d", installs, enables)
	}
	if env.registeredServer(providerServerID) != nil {
		t.Error("a handoff job for an ended order registered a panel server")
	}
	// A second pass finds nothing to do and does not rewrite the closed row.
	closed := *job
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("second install pass: %v", err)
	}
	if again := env.intent(orderID); again.State != closed.State || !again.UpdatedAt.Equal(closed.UpdatedAt) {
		t.Errorf("a later pass rewrote the closed job: %+v -> %+v", closed, *again)
	}
}

// TestRotationSurrenderUsesTheRevocationVocabulary keeps the new endpoint honest about what
// it shares with revocation. The surrender must not invent a second set of cancellable
// states: a completed install is preserved by both, and the difference is only the reason
// and the step.
func TestRotationSurrenderUsesTheRevocationVocabulary(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	const orderID = "ord_install_completed"
	const providerServerID = int64(7407)
	const ip = "198.51.100.47"

	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, providerServerID, ip)
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	env.trackerAndInstall()
	completed := env.requireState(orderID, models.SetupStateReady)

	// The order ends after the install completed.
	if err := env.db.SetGigahostOrderAbsence(ctx, orderID, timeNowUTC(), existenceAccount); err != nil {
		t.Fatalf("record the absence: %v", err)
	}
	ended, err := env.db.SurrenderGigahostSetupForEndedOrder(ctx, orderID)
	if err != nil {
		t.Fatalf("surrender: %v", err)
	}
	if !ended {
		t.Fatal("the surrender did not see the recorded ending")
	}
	// A completed install is not rewritten: removing an admitted backend goes through the
	// existing backend disable path, exactly as it does after a revocation.
	after := env.intent(orderID)
	if after.State != completed.State || after.InstallPhaseDone != completed.InstallPhaseDone {
		t.Errorf("a completed install was rewritten: %+v -> %+v", completed, *after)
	}
	// A second call is idempotent.
	again, err := env.db.SurrenderGigahostSetupForEndedOrder(ctx, orderID)
	if err != nil || !again {
		t.Fatalf("repeated surrender: ended=%v err=%v", again, err)
	}
	if final := env.intent(orderID); final.State != completed.State {
		t.Errorf("the repeated surrender changed the row: %q", final.State)
	}
}

// TestSurrenderIsANoOpForALiveOrder is the negative control for the store method itself: an
// order with no recorded ending leaves the approval exactly as it was.
func TestSurrenderIsANoOpForALiveOrder(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()
	const orderID = "ord_install_live"
	const providerServerID = int64(7408)
	const ip = "198.51.100.48"

	env.seedOrder(orderID, providerServerID, ip)
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, providerServerID, ip)
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	before := env.intent(orderID)

	ended, err := env.db.SurrenderGigahostSetupForEndedOrder(ctx, orderID)
	if err != nil {
		t.Fatalf("surrender: %v", err)
	}
	if ended {
		t.Fatal("an order with no recorded ending was reported as ended")
	}
	if after := env.intent(orderID); after.State != before.State || after.Step != before.Step {
		t.Errorf("a live order's job was changed: %+v -> %+v", before, *after)
	}
	// And the pass still installs it: the control is what proves the refusal is about the
	// order's life rather than about the endpoint existing.
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	if got := env.intent(orderID); got.State == models.SetupStateCanceled {
		t.Fatalf("a live job was closed: %+v", got)
	}
}

// timeNowUTC is the observation instant these fixtures record, matching the write the
// provider inventory performs.
func timeNowUTC() time.Time { return time.Now().UTC() }
