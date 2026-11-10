package handlers

// Cancellation-side withdrawal of an unfinished owned enrollment (F14).
//
// The audited obligation is one safety outcome: when an administrator
// successfully cancels a setup approval, the backend that approval admitted must
// stop being selectable. The guard inside the promotion transaction already covers
// a revocation that commits before admission. These controls cover the opposite
// orderings the audit demonstrated, and assert the end state rather than an error
// string: durable intent, the tunnel's real enabled flag and status, and whether
// the durable enrollment quarantine survived.
//
// The subjects are production code throughout - real SQLite, the real install
// runner/journal, the real VPN enrollment and promotion path, the real HTTP
// endpoints. Only the provider, the SSH peer, the protocol manager and the
// external traffic outcome are fixtures, as in the rest of this suite.
//
// Two controls are deliberately about truthfulness rather than withdrawal: an
// absent backend must not be reported as a failure, and a withdrawal that genuinely
// failed must not be reported as a completed cancellation.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// admitInterruptStore observes the existing InstallStore boundary so a control can
// fire at one exact point in the lifecycle. It does not fake admission, SQL, journal
// results or cancellation: the real store receives every write.
type admitInterruptStore struct {
	*database.DB
	beforeComplete func(*models.GigahostSetupIntent)
}

// UpdateGigahostSetupInstall forwards to the real store, firing the observer
// immediately before the completed-enablement journal commit.
func (s *admitInterruptStore) UpdateGigahostSetupInstall(
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

// admitUnfinished runs one real install attempt over the observing store.
func admitUnfinished(t *testing.T, env *installEnv, orderID string, interrupt func()) bool {
	t.Helper()
	reached := false
	store := &admitInterruptStore{DB: env.db, beforeComplete: func(*models.GigahostSetupIntent) {
		reached = true
		if interrupt != nil {
			interrupt()
		}
	}}
	installer := gigahostsetup.NewInstaller(store, env.h.NewSetupInstallRunner(),
		gigahostsetup.InstallOptions{Interval: time.Second})
	if err := installer.RunOnce(context.Background()); err != nil {
		t.Fatalf("install pass: %v", err)
	}
	return reached
}

// TestSetupCancelAfterPromotionWithdrawsOwnedBackend is the auditor's first F14
// ordering, driven through the real DELETE endpoint.
//
// A real promotion commits, then the administrator's cancellation succeeds before
// the next journal commit. Asserted end state: canceled intent, owned backend
// disabled, not selectable, durable quarantine retained, and later worker passes do
// not revive it.
func TestSetupCancelAfterPromotionWithdrawsOwnedBackend(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	ctx := context.Background()

	const orderID = "ord_r14_cancel_postpromote"
	env.seedOrder(orderID, 9201, "198.51.100.201")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9201, "198.51.100.201")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}

	var cancelCode int
	var cancelBody map[string]any
	reached := admitUnfinished(t, env, orderID, func() {
		// The DELETE arrives after promotion committed and before the journal
		// records the finished phase.
		router := setupActionTestRouter(t, env.h)
		cancelCode, cancelBody = doJSON(t, router, http.MethodDelete,
			"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	})
	if !reached {
		t.Fatal("the post-promotion boundary was never reached: this control proves nothing")
	}
	if cancelCode != http.StatusOK || cancelBody["changed"] != true {
		t.Fatalf("cancel = %d %v, want a successful 200 changed", cancelCode, cancelBody)
	}

	got := env.requireState(orderID, models.SetupStateCanceled)
	server := env.registeredServer(9201)
	if server == nil {
		t.Fatal("registration precondition missing: no server row for the approved provider server")
	}
	assertWithdrawn(t, env, server.ID, "cancel after promotion")

	// A fresh worker pass must not revive the canceled job's backend.
	env.trackerAndInstall()
	env.trackerAndInstall()
	env.requireState(orderID, models.SetupStateCanceled)
	assertWithdrawn(t, env, server.ID, "after later worker passes")
	if !got.RevokedAt.IsZero() == false {
		t.Fatal("the canceled intent records no revocation time")
	}
}

// TestSetupCancelInterruptedFinalizationWithdraws is the stronger, non-timing
// control: the process stops before the final journal commit, and an administrator
// revokes the still-unfinished saved job much later, with no concurrent actor.
func TestSetupCancelInterruptedFinalizationWithdraws(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	ctx := context.Background()

	const orderID = "ord_r14_cancel_interrupted"
	env.seedOrder(orderID, 9202, "198.51.100.202")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9202, "198.51.100.202")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}

	stop := errors.New("controlled interruption before completed-phase journal commit")
	interrupted := false
	func() {
		defer func() {
			if p := recover(); p != nil {
				if p != stop {
					panic(p)
				}
				interrupted = true
			}
		}()
		admitUnfinished(t, env, orderID, func() { panic(stop) })
	}()
	if !interrupted {
		t.Fatal("the interruption boundary was never reached")
	}

	unfinished := env.requireState(orderID, models.SetupStateInstalling)
	if unfinished.InstallPhase != models.SetupPhaseEnabled ||
		unfinished.InstallPhaseDone != models.SetupPhaseInstalled {
		t.Fatalf("wrong durable interruption journal: %+v", unfinished)
	}
	server := env.registeredServer(9202)
	if server == nil {
		t.Fatal("registration precondition missing")
	}
	// Precondition: the interruption really did leave an admitted backend.
	if !enabledAndSelectable(t, env, server.ID) {
		t.Fatal("precondition: the interrupted run did not leave an admitted backend")
	}

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK || body["changed"] != true {
		t.Fatalf("revoke the interrupted job = %d %v, want 200 changed", code, body)
	}

	env.trackerAndInstall()
	env.trackerAndInstall()
	env.requireState(orderID, models.SetupStateCanceled)
	assertWithdrawn(t, env, server.ID, "cancel of an interrupted finalization")
}

// TestSetupCancelBeforePromotionStillRefused proves the retained ordering: a
// revocation that commits before admission is refused by the promotion transaction,
// and the backend is not admitted in the first place.
func TestSetupCancelBeforePromotionStillRefused(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)

	const orderID = "ord_r14_cancel_before"
	env.seedOrder(orderID, 9203, "198.51.100.203")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9203, "198.51.100.203")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)

	var reached atomic.Bool
	env.h.vpnSvc.SetProxyTrafficProbeFuncForTest(func(context.Context, *models.BackendTunnel) (int64, error) {
		reached.Store(true)
		if _, changed, err := env.h.CancelGigahostSetup(context.Background(), orderID); err != nil || !changed {
			t.Errorf("revocation during qualification: changed=%v err=%v", changed, err)
			return 0, err
		}
		return 5, nil
	})

	env.trackerAndInstall()
	if !reached.Load() {
		t.Fatal("the qualification callback was never reached")
	}
	env.requireState(orderID, models.SetupStateCanceled)
	server := env.registeredServer(9203)
	if server == nil {
		t.Fatal("registration precondition missing")
	}
	assertWithdrawn(t, env, server.ID, "cancel before promotion")
	if n := env.counters.totalInstalls(); n != 1 {
		t.Fatalf("protocol installs = %d, want 1 (the install precedes enablement)", n)
	}
}

// TestSetupCancelRepeatRetriesAWithdrawalFailure proves the truthful-failure half.
//
// The disable write genuinely fails, so the cancellation must answer 500 rather
// than a successful revocation, leave the durable quarantine set, and repeating the
// same DELETE must retry the withdrawal and then succeed.
func TestSetupCancelRepeatRetriesAWithdrawalFailure(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	ctx := context.Background()

	const orderID = "ord_r14_cancel_retry"
	env.seedOrder(orderID, 9204, "198.51.100.204")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9204, "198.51.100.204")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	if !admitUnfinished(t, env, orderID, nil) {
		t.Fatal("the post-promotion boundary was never reached")
	}
	env.executeSQL(`UPDATE gigahost_setup_intents SET state = ? WHERE order_id = ?`,
		models.SetupStateInstalling, orderID)
	server := env.registeredServer(9204)
	if server == nil {
		t.Fatal("registration precondition missing")
	}

	// Make the real disable write fail.
	injected := errors.New("injected disable failure")
	env.h.vpnSvc.SetTunnelEnabledHookForTest(func(context.Context, int64, bool, string) error {
		return injected
	})

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusInternalServerError {
		t.Fatalf("cancel with a failing withdrawal = %d %v, want 500", code, body)
	}
	if body["status"] == "ok" {
		t.Fatalf("a failed withdrawal was reported as a completed cancellation: %v", body)
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "was not withdrawn") {
		t.Fatalf("failure detail = %q, want it to name the withdrawal", body["detail"])
	}
	// The intent really is canceled, and the backend is at least quarantined.
	if got := env.intent(orderID); got.State != models.SetupStateCanceled {
		t.Fatalf("state = %q, want the revocation recorded", got.State)
	}
	if !durableQuarantine(t, env, server.ID) {
		t.Error("a failed withdrawal did not leave the durable quarantine set")
	}

	// The operator's retry: clearing the fault and repeating the same DELETE
	// completes the withdrawal.
	env.h.vpnSvc.SetTunnelEnabledHookForTest(nil)
	code, body = doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("repeated cancel = %d %v, want 200", code, body)
	}
	assertWithdrawn(t, env, server.ID, "after a repeated cancellation")
}

// TestSetupCancelWithoutAdmissionDoesNotFail proves the narrow scope: a job revoked
// before it ever enabled a backend owns no admission, so the cancellation is a plain
// success and no backend is touched.
func TestSetupCancelWithoutAdmissionDoesNotFail(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)

	const orderID = "ord_r14_cancel_early"
	env.seedOrder(orderID, 9205, "198.51.100.205")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9205, "198.51.100.205")
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	env.requireState(orderID, models.SetupStatePending)

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK || body["changed"] != true {
		t.Fatalf("cancel of an unadmitted job = %d %v, want 200 changed", code, body)
	}
	env.requireState(orderID, models.SetupStateCanceled)
	if n := env.counters.totalInstalls(); n != 0 {
		t.Fatalf("a pre-install cancellation installed %d times, want 0", n)
	}
}

// TestSetupCancelLeavesUnrelatedBackendAdmitted proves the withdrawal is scoped to
// the job's own server: a different admitted backend is untouched.
func TestSetupCancelLeavesUnrelatedBackendAdmitted(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)
	ctx := context.Background()

	// An unrelated, already admitted backend.
	neighbourID, err := env.db.CreateServerWithFingerprint(ctx, &models.Server{
		Name: "r14-unrelated", Host: "198.51.100.210", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"provider": "gigahost", "provider_server_id": 9299,
			models.ProtocolVLESS: map[string]any{"installed": true, "port": "443"},
		},
	}, installFixtureFingerprint)
	if err != nil {
		t.Fatalf("register unrelated server: %v", err)
	}
	if err := env.h.enableDeployBackend(ctx, &models.Server{ID: neighbourID, Host: "198.51.100.210",
		Protocols: map[string]any{models.ProtocolVLESS: map[string]any{
			"installed": true, "port": "443",
			"public_key": "x9aBVLESS1234567890abcdef1234567890abcdef12=",
		}}}, models.ProtocolVLESS); err != nil {
		t.Fatalf("admit the unrelated backend: %v", err)
	}
	before, err := env.h.vpnSvc.GetTunnel(neighbourID)
	if err != nil || before == nil || !before.Enabled {
		t.Fatalf("precondition: unrelated backend not admitted: %+v err=%v", before, err)
	}
	versionBefore := before.StateVersion

	// A second order that promotes and is then canceled.
	const orderID = "ord_r14_cancel_scoped"
	env.seedOrder(orderID, 9206, "198.51.100.206")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9206, "198.51.100.206")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	if err := env.tracker(nil).RunOnce(ctx); err != nil {
		t.Fatalf("tracker pass: %v", err)
	}
	admitUnfinished(t, env, orderID, nil)

	router := setupActionTestRouter(t, env.h)
	if code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil); code != http.StatusOK {
		t.Fatalf("cancel = %d %v", code, body)
	}

	after, err := env.h.vpnSvc.GetTunnel(neighbourID)
	if err != nil || after == nil {
		t.Fatalf("re-read unrelated backend: %v", err)
	}
	if !after.Enabled || after.Status != before.Status {
		t.Errorf("the unrelated backend changed: enabled %v->%v status %q->%q",
			before.Enabled, after.Enabled, before.Status, after.Status)
	}
	if after.StateVersion != versionBefore {
		t.Errorf("the unrelated backend's state version advanced %d->%d", versionBefore, after.StateVersion)
	}
	if durableQuarantine(t, env, neighbourID) {
		t.Error("the withdrawal quarantined an unrelated backend")
	}
}

// enabledAndSelectable reports whether the backend would be chosen for client
// traffic, using the same predicate the load balancer uses.
func enabledAndSelectable(t *testing.T, env *installEnv, serverID int64) bool {
	t.Helper()
	tun, err := env.h.vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil {
		return false
	}
	return tun.Enabled && (tun.Status == models.TunnelStatusActive || tun.Status == models.TunnelStatusDegraded)
}

// TestSetupCancelWithdrawsViaProviderLookupWhenIntentLacksServerID covers the
// ownership fallback. A job that registered its server but whose intent column was
// never written must still have its backend withdrawn, and a job whose server is
// gone must not withdraw somebody else's.
func TestSetupCancelWithdrawsViaProviderLookupWhenIntentLacksServerID(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolVLESS)
	validVLESSClientFixture(t, env)

	const orderID = "ord_r14_cancel_fallback"
	env.seedOrder(orderID, 9207, "198.51.100.207")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9207, "198.51.100.207")
	env.approve(orderID, models.ProtocolVLESS, "443", installFixtureFingerprint)
	env.runTrackerPassFor(orderID)
	admitUnfinished(t, env, orderID, nil)
	env.executeSQL(`UPDATE gigahost_setup_intents SET state = ?, nexus_server_id = 0 WHERE order_id = ?`,
		models.SetupStateInstalling, orderID)

	server := env.registeredServer(9207)
	if server == nil {
		t.Fatal("registration precondition missing")
	}
	if !enabledAndSelectable(t, env, server.ID) {
		t.Fatal("precondition: the promotion did not admit the backend")
	}

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK {
		t.Fatalf("cancel = %d %v, want 200", code, body)
	}
	assertWithdrawn(t, env, server.ID, "cancel resolved by provider lookup")
}

// TestSetupCancelWithEnablementButNoServerDoesNotFail proves the other side of the
// ownership rule: a job that recorded enablement but which no server claims has no
// identity to withdraw, so the cancellation is a plain success rather than an error
// or a guess at somebody else's backend.
func TestSetupCancelWithEnablementButNoServerDoesNotFail(t *testing.T) {
	env := newInstallEnv(t, models.ProtocolAWG)

	const orderID = "ord_r14_cancel_orphan"
	env.seedOrder(orderID, 9208, "198.51.100.208")
	env.seedManagedCredential(orderID)
	env.providerServes(orderID, 9208, "198.51.100.208")
	env.approve(orderID, models.ProtocolAWG, "51820", installFixtureFingerprint)
	// Enablement recorded, but the server was never registered and the intent
	// carries no server id: the job owns no admission this panel can identify.
	env.executeSQL(`UPDATE gigahost_setup_intents SET install_phase = ?, nexus_server_id = 0 WHERE order_id = ?`,
		models.SetupPhaseEnabled, orderID)

	router := setupActionTestRouter(t, env.h)
	code, body := doJSON(t, router, http.MethodDelete,
		"/api/admin/hosting/gigahost/orders/"+orderID+"/setup-approval", nil)
	if code != http.StatusOK || body["changed"] != true {
		t.Fatalf("cancel of an unidentifiable job = %d %v, want 200 changed", code, body)
	}
	env.requireState(orderID, models.SetupStateCanceled)
}

// runTrackerPassFor runs one tracker pass for environments that hold a single
// pending approval.
func (e *installEnv) runTrackerPassFor(orderID string) {
	e.t.Helper()
	if err := e.tracker(nil).RunOnce(context.Background()); err != nil {
		e.t.Fatalf("tracker pass: %v", err)
	}
	if got := e.intent(orderID); got.State != models.SetupStateReadyForSetup {
		e.t.Fatalf("state after tracking = %q (step %q, error %q), want %q",
			got.State, got.Step, got.LastError, models.SetupStateReadyForSetup)
	}
}

// assertWithdrawn asserts the end state a completed cancellation must leave.
//
// Selection is decided by the load balancer's own predicate, so that is what is
// asserted rather than a status string: this repository's administrative disable
// clears the enabled flag and leaves the recorded status alone. The durable row must
// agree with the runtime view, and the durable enrollment quarantine must be set, so
// startup quarantine cannot re-admit the backend after a restart either.
func assertWithdrawn(t *testing.T, env *installEnv, serverID int64, when string) {
	t.Helper()
	tun, err := env.h.vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil {
		t.Fatalf("%s: tunnel: %+v err=%v", when, tun, err)
	}
	quarantined := durableQuarantine(t, env, serverID)
	t.Logf("%s: enabled=%v status=%s quarantine=%v", when, tun.Enabled, tun.Status, quarantined)
	if tun.Enabled {
		t.Errorf("%s: the canceled job's backend is still enabled", when)
	}
	// The real consumer: the load balancer must not offer this backend.
	if selected := loadbalancer.FilterHealthy([]*models.BackendTunnel{tun}, 0); len(selected) != 0 {
		t.Errorf("%s: the load balancer still selects the canceled job's backend", when)
	}
	if !quarantined {
		t.Errorf("%s: the canceled job's durable enrollment quarantine was released", when)
	}
	// The persisted row must agree with the runtime view.
	stored, err := env.db.GetBackendTunnel(context.Background(), tun.ID)
	if err != nil || stored == nil {
		t.Fatalf("%s: stored tunnel: %v", when, err)
	}
	if stored.Enabled {
		t.Errorf("%s: the stored tunnel row is still enabled", when)
	}
	if selected := loadbalancer.FilterHealthy([]*models.BackendTunnel{stored}, 0); len(selected) != 0 {
		t.Errorf("%s: the persisted state still selects the canceled job's backend", when)
	}
}
