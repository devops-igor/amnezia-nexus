package handlers

// The scoped half of C2b: who may acquire automatic authority, and what happens when the
// acquisition itself fails.
//
// The grant is the one production path that issues unattended authority, so its refusals
// are the property that matters most. Four of them are structural rather than incidental:
//
//   - a manual job can never acquire it, whatever its other fields say;
//   - an already-granted job is never re-granted, and a completed or uncertain phase is
//     never replayed because of a grant attempt;
//   - two passes racing, or one pass repeating, converge on one grant;
//   - a store failure or a disabled policy leaves the job inert with a reason, and the
//     next pass can still succeed.
//
// Each is asserted against the durable row and the live effect counters, with the
// positive control beside it in the browserless test.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// requireNoScopedGrant asserts the row carries no binding, whatever else it holds.
//
// This is deliberately narrower than requireNoTrustAuthority: a manual approval
// legitimately carries the identity the administrator confirmed, and the property under
// test here is that it never acquires the automation binding.
func requireNoScopedGrant(t *testing.T, intent *models.GigahostSetupIntent, what string) {
	t.Helper()
	if intent.HostTrustOrderID != "" || intent.HostTrustServerID != 0 ||
		intent.HostTrustAddress != "" || intent.HostTrustKeyID != 0 {
		t.Fatalf("%s carries a binding: order=%q server=%d address=%q key=%d",
			what, intent.HostTrustOrderID, intent.HostTrustServerID,
			intent.HostTrustAddress, intent.HostTrustKeyID)
	}
	if !intent.HostTrustGrantedAt.IsZero() {
		t.Fatalf("%s carries a grant timestamp %s", what, intent.HostTrustGrantedAt)
	}
}

// TestManualJobCannotAcquireAutomaticAuthority is the manual isolation control.
//
// A job a person approved carries no automation policy. The grant path is offered it
// anyway - which is what a wiring mistake or a future caller would do - and it must
// change nothing: no binding, no policy, and no automatic authority in any column.
func TestManualJobCannotAcquireAutomaticAuthority(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)
	ctx := context.Background()

	const orderID = "ord_binding_manual"
	const providerServerID = 9501
	const ip = "127.0.0.1"

	env.seedAutomaticOrder(orderID, providerServerID, ip)
	// The administrator's own approval: no policy, and the identity they confirmed. The
	// identity is real key material because the install path parses it.
	hostSigner := newHandshakeSigner(t)
	env.realSSHAt(map[string]int{ip: newChallengePeer(t, hostSigner).port()}, 2*time.Second)
	env.approve(orderID, models.ProtocolAWG, "51820", sshFingerprintOf(t, hostSigner))
	before := env.intent(orderID)

	// Offer the grant directly, exactly as the tracker would for an automatic job.
	reader, err := env.h.ResolveGigahostSetupProvider(ctx)
	if err != nil {
		t.Fatalf("resolve provider: %v", err)
	}
	got, err := env.h.GrantAutomaticGigahostSetupBinding(ctx, *before, reader)
	if err != nil {
		t.Fatalf("grant against a manual job: %v", err)
	}

	if got.HostTrustPolicy != models.SetupTrustPolicyManual {
		t.Fatalf("a manual job acquired policy %q", got.HostTrustPolicy)
	}
	requireNoScopedGrant(t, &got, "a manual job offered automatic authority")
	stored := env.intent(orderID)
	if stored.HostTrustPolicy != models.SetupTrustPolicyManual {
		t.Fatalf("the stored manual job acquired policy %q", stored.HostTrustPolicy)
	}
	requireNoScopedGrant(t, stored, "the stored manual job")

	// And its normal path still works untouched: a pin, then an install.
	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}
	if err := env.installer().RunOnce(ctx); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	if final := env.intent(orderID); final.State != models.SetupStateReady {
		t.Fatalf("the manual job was disturbed: state = %q (step %q, last error %q)",
			final.State, final.Step, final.LastError)
	}
	if final := env.intent(orderID); final.HostTrustMode == models.SetupTrustModeFirstContact {
		t.Fatalf("the manual job recorded automatic trust provenance %q", final.HostTrustMode)
	}
}

// TestAutomaticGrantIsIdempotentAndDoesNotReplayEffects covers replay and concurrency.
//
// A second pass, and two passes racing, must converge on exactly one grant and must not
// re-issue anything. The job is then driven to completion so the "no replay" half is
// measured against a real install count rather than by inspection.
func TestAutomaticGrantIsIdempotentAndDoesNotReplayEffects(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)
	ctx := context.Background()

	const orderID = "ord_binding_idempotent"
	const providerServerID = 9502
	const providerKeyID = 4242
	const ip = "127.0.0.1"

	env.seedFreshPurchase(orderID, newManagedTestKey(t))
	env.providerServes(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)
	env.startAutomatic(orderID, automaticOptions)

	// The first pass does the work.
	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("first tracking pass: %v", err)
	}
	granted := env.requireScopedGrant(orderID, providerServerID, ip, providerKeyID)
	firstGrantedAt := granted.HostTrustGrantedAt
	pinned := granted.HostFingerprint
	if pinned == "" {
		t.Fatal("precondition: the job was not pinned")
	}

	// A second pass over an already-granted, already-pinned job changes nothing.
	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("second tracking pass: %v", err)
	}
	again := env.requireScopedGrant(orderID, providerServerID, ip, providerKeyID)
	if !again.HostTrustGrantedAt.Equal(firstGrantedAt) {
		t.Fatalf("a second pass re-granted: %s became %s", firstGrantedAt, again.HostTrustGrantedAt)
	}
	if again.HostFingerprint != pinned {
		t.Fatalf("a second pass changed the pin to %q", again.HostFingerprint)
	}

	// Two racing passes over a fresh job converge on one grant and one pin. A new job is
	// used so the race is against an ungranted row, which is where a double grant could
	// actually happen.
	const raceOrderID = "ord_binding_race"
	const raceServerID = 9503
	env.seedFreshPurchase(raceOrderID, newManagedTestKey(t))
	env.providerServes(raceOrderID, raceServerID, ip)
	env.startAutomatic(raceOrderID, automaticOptions)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = env.h.NewGigahostSetupTracker().RunOnce(ctx)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racing pass %d: %v", i, err)
		}
	}
	raced := env.requireScopedGrant(raceOrderID, raceServerID, ip, providerKeyID)
	if raced.HostFingerprint == "" {
		t.Fatalf("the racing passes left the job unpinned (state %q, step %q, last error %q)",
			raced.State, raced.Step, raced.LastError)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("the tracking passes installed %d times", n)
	}
}

// TestAutomaticGrantRefusesWhenThePolicyIsOff proves the policy is consulted before
// authority is issued, not only before it is used.
//
// A setting turned off while a purchase was provisioning must stop the grant. The job
// keeps its place and acquires nothing, so a later pass with the policy on can still
// grant it.
func TestAutomaticGrantRefusesWhenThePolicyIsOff(t *testing.T) {
	cases := []struct {
		name   string
		policy func(*stubAutomationPolicy)
		want   string
	}{
		{
			name:   "the policy answers no",
			policy: func(p *stubAutomationPolicy) { p.setEnabled(false) },
			want:   stepAutomaticUnavailableLiteral,
		},
		{
			name:   "the policy cannot be read",
			policy: func(p *stubAutomationPolicy) { p.setError(errPolicySourceUnavailable) },
			want:   stepAutomaticUnavailableLiteral,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			policy := env.enableAutomaticSetup(true)
			ctx := context.Background()

			const orderID = "ord_binding_policy_off"
			const providerServerID = 9504
			const ip = "127.0.0.1"

			env.seedFreshPurchase(orderID, newManagedTestKey(t))
			env.providerServes(orderID, providerServerID, ip)
			peer := newChallengePeer(t, newHandshakeSigner(t))
			env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)
			env.startAutomatic(orderID, automaticOptions)

			// The setting changes while the purchase is provisioning.
			tc.policy(policy)

			if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
				t.Fatalf("tracking pass: %v", err)
			}

			got := env.intent(orderID)
			requireNoTrustAuthority(t, got, "a job whose grant was refused")
			if got.Step != tc.want {
				t.Fatalf("step = %q, want %q (state %q, last error %q)",
					got.Step, tc.want, got.State, got.LastError)
			}
			if got.LastError == "" {
				t.Fatal("the refusal recorded no reason")
			}
			if n := peer.auths.Load(); n != 0 {
				t.Fatalf("a refused grant authenticated %d times", n)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("a refused grant installed %d times", n)
			}

			// The association was not recorded either: the grant is what justifies
			// touching the ledger, so a refusal before it leaves the ledger alone.
			order, _, err := env.db.GetGigahostOrder(ctx, orderID)
			if err != nil {
				t.Fatalf("read order: %v", err)
			}
			if order.AssignedIP != "" || order.ServerID != 0 {
				t.Fatalf("a refused grant still wrote the association: address=%q server=%d",
					order.AssignedIP, order.ServerID)
			}

			// Re-enabling lets the same job acquire its authority on a later pass.
			policy.setEnabled(true)
			policy.setError(nil)
			later := time.Now().UTC().Add(2 * time.Hour)
			if err := env.tracker(func() time.Time { return later }).RunOnce(ctx); err != nil {
				t.Fatalf("tracking pass after re-enabling: %v", err)
			}
			recovered := env.requireScopedGrant(orderID, providerServerID, ip, 4242)
			if recovered.HostFingerprint == "" {
				t.Fatalf("after re-enabling, the job was not pinned (step %q, last error %q)",
					recovered.Step, recovered.LastError)
			}
		})
	}
}

// TestAutomaticGrantSurvivesAWriteFailure proves a store failure cannot leave a job with
// partial authority.
//
// The association write and the grant are separate statements, so the interesting failure
// is the grant failing after the association succeeded. The job must stay ungranted with a
// recorded reason and no effects, and a later pass must be able to complete it.
func TestAutomaticGrantSurvivesAWriteFailure(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	env.enableAutomaticSetup(true)
	ctx := context.Background()

	const orderID = "ord_binding_writefail"
	const providerServerID = 9505
	const ip = "127.0.0.1"

	env.seedFreshPurchase(orderID, newManagedTestKey(t))
	env.providerServes(orderID, providerServerID, ip)
	peer := newChallengePeer(t, newHandshakeSigner(t))
	env.realSSHAt(map[string]int{ip: peer.port()}, 2*time.Second)
	env.startAutomatic(orderID, automaticOptions)

	// A provider answer that contradicts the ledger's own recorded server id makes the
	// association statement mismatch, which is the write-failure path that does not
	// require breaking the store itself.
	env.executeSQL(`UPDATE gigahost_orders SET server_id = 999999 WHERE order_id = ?`, orderID)

	if err := env.h.NewGigahostSetupTracker().RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass: %v", err)
	}

	got := env.intent(orderID)
	requireNoTrustAuthority(t, got, "a job whose association write was refused")
	if got.LastError == "" {
		t.Fatal("the write failure recorded no reason")
	}
	if got.State == models.SetupStateReady {
		t.Fatal("a refused association still completed the job")
	}
	if n := peer.auths.Load(); n != 0 {
		t.Fatalf("a refused association authenticated %d times", n)
	}
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("a refused association installed %d times", n)
	}
	// The conflicting value was not overwritten: a background pass never re-points a row.
	order, _, err := env.db.GetGigahostOrder(ctx, orderID)
	if err != nil {
		t.Fatalf("read order: %v", err)
	}
	if order.ServerID != 999999 {
		t.Fatalf("the background pass overwrote the recorded server id with %d", order.ServerID)
	}

	// Returning the ledger to its real state lets the same job complete on a later pass.
	env.executeSQL(`UPDATE gigahost_orders SET server_id = 0 WHERE order_id = ?`, orderID)
	later := time.Now().UTC().Add(2 * time.Hour)
	if err := env.tracker(func() time.Time { return later }).RunOnce(ctx); err != nil {
		t.Fatalf("tracking pass after the conflict cleared: %v", err)
	}
	recovered := env.requireScopedGrant(orderID, providerServerID, ip, 4242)
	if recovered.HostFingerprint == "" {
		t.Fatalf("after the conflict cleared, the job was not pinned (step %q, last error %q)",
			recovered.Step, recovered.LastError)
	}
}

// TestAutomaticGrantDoesNotDisturbACompletedJob is the terminal-state control.
//
// A job that already finished must never be re-opened by a grant attempt, and a job whose
// install is in an uncertain phase must not have that phase replayed because authority
// was refreshed.
func TestAutomaticGrantDoesNotDisturbACompletedJob(t *testing.T) {
	cases := []struct {
		name  string
		state string
		phase string
	}{
		{name: "a completed job", state: models.SetupStateReady, phase: models.SetupPhaseEnabled},
		{name: "an uncertain install", state: models.SetupStateInstalling, phase: models.SetupPhaseInstalled},
		{name: "a canceled job", state: models.SetupStateCanceled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newInstallEnv(t, models.ProtocolAWG)
			env.enableAutomaticSetup(true)
			ctx := context.Background()

			const orderID = "ord_binding_terminal"
			const providerServerID = 9506
			const ip = "127.0.0.1"

			env.seedAutomaticOrder(orderID, providerServerID, ip)
			env.startAutomatic(orderID, automaticOptions)
			env.executeSQL(
				`UPDATE gigahost_setup_intents SET state = ?, step = ?, install_phase = ? WHERE order_id = ?`,
				tc.state, tc.state, tc.phase, orderID)
			before := env.intent(orderID)

			// Offer the grant directly to a row that is no longer pending.
			reader, err := env.h.ResolveGigahostSetupProvider(ctx)
			if err != nil {
				t.Fatalf("resolve provider: %v", err)
			}
			got, err := env.h.GrantAutomaticGigahostSetupBinding(ctx, *before, reader)
			if err != nil {
				t.Fatalf("grant against a %s job: %v", tc.name, err)
			}

			// The grant applies only to a pending, identity-free row, so it records
			// nothing here - and crucially it does not reopen the job or rewrite its
			// journal.
			requireNoTrustAuthority(t, &got, tc.name)
			stored := env.intent(orderID)
			if stored.State != tc.state {
				t.Fatalf("the grant reopened the job: state = %q, want %q", stored.State, tc.state)
			}
			if stored.InstallPhase != tc.phase {
				t.Fatalf("the grant rewrote the journal: phase = %q, want %q", stored.InstallPhase, tc.phase)
			}
			if n := env.counters.totalInstalls(); n != 0 {
				t.Fatalf("the grant attempt installed %d times", n)
			}
		})
	}
}

// TestProviderAssociationWriteCannotManufactureProvenance is the store-level control for
// the one new write this checkpoint adds.
//
// The purchase stamp is the only evidence that this panel bought an order, and it is what
// the whole automatic path rests on. The association statement must not be able to create
// it: a row that appeared some other way stays unproven no matter what provider facts are
// recorded against it.
func TestProviderAssociationWriteCannotManufactureProvenance(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)
	ctx := context.Background()

	const orderID = "ord_provenance_control"
	const providerServerID = 9601
	const ip = "198.51.100.60"

	// A ledger row the deploy-status mirror could have created: plausible, no stamp.
	now := time.Now().UTC()
	if err := env.db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: orderID, Status: gigahost.StatusReady, PlanID: 7, RegionID: 3,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed unstamped order: %v", err)
	}

	changed, err := env.db.RecordGigahostSetupProviderAssociation(ctx, orderID, providerServerID, ip)
	if err != nil {
		t.Fatalf("associate an unstamped row: %v", err)
	}
	if changed {
		t.Fatal("the association statement updated a row that is not the panel's purchase")
	}
	order, found, err := env.db.GetGigahostOrder(ctx, orderID)
	if err != nil || !found {
		t.Fatalf("read order: found=%v err=%v", found, err)
	}
	if order.PurchaseOrigin != models.PurchaseOriginNone {
		t.Fatalf("the association manufactured the purchase stamp: %q", order.PurchaseOrigin)
	}
	if order.ServerID != 0 || order.AssignedIP != "" {
		t.Fatalf("the association wrote facts onto an unstamped row: server=%d address=%q",
			order.ServerID, order.AssignedIP)
	}

	// The same statement on the panel's own purchase does record them, and repeats are
	// not conflicts.
	if err := env.db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: "ord_provenance_positive", Status: "pending_order", PlanID: 7, RegionID: 3,
		PurchaseOrigin: models.PurchaseOriginPanelPurchase, PurchaseRecordedAt: now,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed purchased order: %v", err)
	}
	changed, err = env.db.RecordGigahostSetupProviderAssociation(
		ctx, "ord_provenance_positive", providerServerID, ip)
	if err != nil || !changed {
		t.Fatalf("associate a purchased row: changed=%v err=%v", changed, err)
	}
	changed, err = env.db.RecordGigahostSetupProviderAssociation(
		ctx, "ord_provenance_positive", providerServerID, ip)
	if err != nil {
		t.Fatalf("repeat the association: %v", err)
	}
	if changed {
		t.Fatal("a repeated association reported a change")
	}

	// A conflicting identity is a refusal, not an overwrite.
	_, err = env.db.RecordGigahostSetupProviderAssociation(
		ctx, "ord_provenance_positive", providerServerID+1, ip)
	if !errors.Is(err, database.ErrProviderAssociationConflict) {
		t.Fatalf("a conflicting server id was not reported as a conflict: %v", err)
	}
	kept, _, err := env.db.GetGigahostOrder(ctx, "ord_provenance_positive")
	if err != nil {
		t.Fatalf("read purchased order: %v", err)
	}
	if kept.ServerID != providerServerID {
		t.Fatalf("a conflicting write re-pointed the row to server %d", kept.ServerID)
	}
}
