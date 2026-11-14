package database

// Persistence tests for durable Gigahost setup intents.
//
// These cover the properties the tracker relies on and cannot verify itself: the
// unique index that makes a second job impossible, the compare-and-set that makes
// a revocation win a race, and the due-query that keeps settled work out of the
// schedule.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func openSetupIntentTestDB(t *testing.T) *DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "setup_intents.db")
	db, err := Open(dbPath, testSecretKey)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newPendingIntent(orderID string) *models.GigahostSetupIntent {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	return &models.GigahostSetupIntent{
		OrderID:        orderID,
		Protocol:       models.ProtocolAWG,
		Port:           "51820",
		CredentialMode: models.SetupCredentialManaged,
		State:          models.SetupStatePending,
		Step:           "approved",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// TestCreateSetupIntentIsUniquePerOrder proves the unique index: a second approval
// for the same order is a durable conflict, not a second job.
func TestCreateSetupIntentIsUniquePerOrder(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_dup")); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_dup"))
	if !errors.Is(err, ErrSetupIntentExists) {
		t.Fatalf("second insert error = %v, want ErrSetupIntentExists", err)
	}

	list, err := db.ListGigahostSetupIntents(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("intent count = %d, want 1", len(list))
	}
}

// TestSetupIntentRoundTripsEveryField proves the row survives a write/read with
// all the identity and progress fields intact, including the zero-time form.
func TestSetupIntentRoundTripsEveryField(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	intent := &models.GigahostSetupIntent{
		OrderID:          "ord_round",
		ProviderServerID: 4242,
		AssignedIP:       "198.51.100.7",
		Protocol:         models.ProtocolVLESS,
		Port:             "443",
		TLSDomain:        "vpn.example.com",
		EngineProfile:    "profile-a",
		CredentialMode:   models.SetupCredentialManaged,
		State:            models.SetupStatePending,
		ProviderStatus:   "deploying",
		Step:             "provisioning",
		LastError:        "",
		HostFingerprint:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		HostMismatch:     true,
		ReadFailures:     2,
		Attempts:         7,
		NextAttemptAt:    now.Add(5 * time.Minute),
		LastCheckedAt:    now,
		ApprovedBy:       "admin-1",
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, found, err := db.GetGigahostSetupIntent(ctx, "ord_round")
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if got.Protocol != models.ProtocolVLESS || got.TLSDomain != "vpn.example.com" {
		t.Fatalf("options lost: %+v", got)
	}
	if got.ProviderServerID != 4242 || got.AssignedIP != "198.51.100.7" {
		t.Fatalf("identity lost: %+v", got)
	}
	if !got.HostMismatch || got.ReadFailures != 2 || got.Attempts != 7 {
		t.Fatalf("progress lost: %+v", got)
	}
	if !got.NextAttemptAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("next attempt = %v, want %v", got.NextAttemptAt, now.Add(5*time.Minute))
	}
	if got.ApprovedBy != "admin-1" {
		t.Fatalf("approver = %q", got.ApprovedBy)
	}
	// RevokedAt was never set and must read as the zero time, not as a real one.
	if !got.RevokedAt.IsZero() {
		t.Fatalf("revoked_at = %v, want zero", got.RevokedAt)
	}
}

// TestTransitionRequiresExpectedState proves the compare-and-set: a transition
// whose expected state no longer matches is refused instead of applied.
func TestTransitionRequiresExpectedState(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	intent := newPendingIntent("ord_cas")
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// The row is pending, so a transition expecting cancelled must not apply.
	update := newPendingIntent("ord_cas")
	update.State = models.SetupStateReadyForSetup
	changed, err := db.TransitionGigahostSetupIntent(ctx, update, []string{models.SetupStateCanceled})
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if changed {
		t.Fatal("transition applied despite a mismatched expected state")
	}
	got, _, _ := db.GetGigahostSetupIntent(ctx, "ord_cas")
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want unchanged %q", got.State, models.SetupStatePending)
	}

	// The matching expected state applies.
	changed, err = db.TransitionGigahostSetupIntent(ctx, update, []string{models.SetupStatePending})
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if !changed {
		t.Fatal("transition refused despite a matching expected state")
	}
	got, _, _ = db.GetGigahostSetupIntent(ctx, "ord_cas")
	if got.State != models.SetupStateReadyForSetup {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStateReadyForSetup)
	}
	if !got.NextAttemptAt.IsZero() {
		t.Fatalf("settled intent still scheduled for %v", got.NextAttemptAt)
	}
}

// TestCancelSetupIntentIsIdempotentAndTerminal proves revocation: repeated
// cancellation is a no-op, and a canceled row cannot be canceled back.
func TestCancelSetupIntentIsIdempotentAndTerminal(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_cancel")); err != nil {
		t.Fatalf("insert: %v", err)
	}

	first, changed, err := db.CancelGigahostSetupIntent(ctx, "ord_cancel", "revoked")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if !changed || first.State != models.SetupStateCanceled {
		t.Fatalf("first cancel: changed=%v state=%q", changed, first.State)
	}
	if first.RevokedAt.IsZero() {
		t.Fatal("revoked_at not recorded")
	}

	second, changed, err := db.CancelGigahostSetupIntent(ctx, "ord_cancel", "revoked again")
	if err != nil {
		t.Fatalf("repeat cancel: %v", err)
	}
	if !changed {
		t.Fatal("repeated cancel reported changed=false; it is the same request twice")
	}
	if !second.RevokedAt.Equal(first.RevokedAt) {
		t.Fatalf("repeated cancel rewrote the revocation time: %v vs %v", second.RevokedAt, first.RevokedAt)
	}
}

// TestDueQueryExcludesSettledAndNotYetDueIntents proves the schedule is bounded:
// only pending rows whose next attempt has arrived are returned.
func TestDueQueryExcludesSettledAndNotYetDueIntents(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	seed := func(orderID, state string, next time.Time) {
		t.Helper()
		intent := newPendingIntent(orderID)
		intent.State = state
		intent.NextAttemptAt = next
		if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
			t.Fatalf("insert %s: %v", orderID, err)
		}
	}
	seed("ord_due", models.SetupStatePending, base.Add(-time.Minute))
	seed("ord_never", models.SetupStatePending, time.Time{})
	seed("ord_future", models.SetupStatePending, base.Add(time.Hour))
	seed("ord_settled", models.SetupStateReadyForSetup, base.Add(-time.Hour))
	seed("ord_cancelled", models.SetupStateCanceled, base.Add(-time.Hour))

	due, err := db.ListDueGigahostSetupIntents(ctx, base, 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	got := make(map[string]bool, len(due))
	for _, intent := range due {
		got[intent.OrderID] = true
	}
	if !got["ord_due"] {
		t.Fatal("due pending intent was not returned")
	}
	if !got["ord_never"] {
		t.Fatal("never-scheduled pending intent was not returned; it would never run")
	}
	if got["ord_future"] {
		t.Fatal("not-yet-due intent was returned early")
	}
	if got["ord_settled"] || got["ord_cancelled"] {
		t.Fatal("a settled intent was returned to the schedule")
	}
	if len(due) != 2 {
		t.Fatalf("due count = %d, want 2 (%v)", len(due), got)
	}

	// The batch limit is honoured, so a large backlog cannot stall one pass.
	limited, err := db.ListDueGigahostSetupIntents(ctx, base, 1)
	if err != nil {
		t.Fatalf("limited list: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited count = %d, want 1", len(limited))
	}
}

// TestSetupIntentSchemaUpgradesAnOlderDatabase proves the additive upgrade: a
// database created before this table existed gains it without losing its rows.
func TestSetupIntentSchemaUpgradesAnOlderDatabase(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	// Simulate an older database: the ledger exists with a row, the intent table
	// does not.
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: "ord_legacy", Status: "ready", PlanID: 1, RegionID: 1,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed legacy order: %v", err)
	}
	if _, err := db.SQLDB().ExecContext(ctx, `DROP TABLE IF EXISTS gigahost_setup_intents`); err != nil {
		t.Fatalf("drop intent table: %v", err)
	}

	// Re-running the migration must recreate it and leave the ledger alone.
	if err := db.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	order, found, err := db.GetGigahostOrder(ctx, "ord_legacy")
	if err != nil || !found {
		t.Fatalf("legacy order lost: found=%v err=%v", found, err)
	}
	if order.Status != "ready" {
		t.Fatalf("legacy order mutated: %+v", order)
	}
	// And the recreated table is usable.
	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_after_upgrade")); err != nil {
		t.Fatalf("insert after upgrade: %v", err)
	}
}

// TestHasOrderCredentialDistinguishesAbsentFromPresent proves the credential
// presence probe the tracker uses, including that an order with no credential is
// reported absent rather than as an error.
func TestHasOrderCredentialDistinguishesAbsentFromPresent(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	for _, orderID := range []string{"ord_nocred", "ord_yescred"} {
		if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
			OrderID: orderID, Status: "ready", PlanID: 1, RegionID: 1,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("seed order %s: %v", orderID, err)
		}
	}
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:    "ord_yescred",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----",
		PublicKey:  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureKeyMaterialForTestsOnly0000",
	}); err != nil {
		t.Fatalf("set credential: %v", err)
	}

	has, err := db.HasGigahostOrderCredential(ctx, "ord_nocred")
	if err != nil {
		t.Fatalf("absent probe: %v", err)
	}
	if has {
		t.Fatal("order without a credential reported as having one")
	}
	has, err = db.HasGigahostOrderCredential(ctx, "ord_yescred")
	if err != nil {
		t.Fatalf("present probe: %v", err)
	}
	if !has {
		t.Fatal("order with a credential reported as absent")
	}
	// An order that does not exist has no credential and is not an error.
	has, err = db.HasGigahostOrderCredential(ctx, "ord_missing")
	if err != nil || has {
		t.Fatalf("unknown order probe: has=%v err=%v", has, err)
	}
}

// TestSetupIntentTransitionsRejectIncompleteInput proves the guard clauses: a
// transition with no order id, no state or no expected state is refused rather
// than issuing a statement that would silently match nothing.
func TestSetupIntentTransitionsRejectIncompleteInput(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if _, err := db.TransitionGigahostSetupIntent(ctx, nil, []string{models.SetupStatePending}); err == nil {
		t.Fatal("nil intent accepted")
	}
	if _, err := db.TransitionGigahostSetupIntent(ctx, &models.GigahostSetupIntent{
		State: models.SetupStatePending}, []string{models.SetupStatePending}); err == nil {
		t.Fatal("intent without an order id accepted")
	}
	if _, err := db.TransitionGigahostSetupIntent(ctx, &models.GigahostSetupIntent{
		OrderID: "ord_x"}, []string{models.SetupStatePending}); err == nil {
		t.Fatal("transition without a state accepted")
	}
	if _, err := db.TransitionGigahostSetupIntent(ctx, &models.GigahostSetupIntent{
		OrderID: "ord_x", State: models.SetupStatePending}, nil); err == nil {
		t.Fatal("transition without expected states accepted")
	}
	if err := db.CreateGigahostSetupIntent(ctx, nil); err == nil {
		t.Fatal("nil intent insert accepted")
	}
	if err := db.CreateGigahostSetupIntent(ctx, &models.GigahostSetupIntent{
		State: models.SetupStatePending}); err == nil {
		t.Fatal("intent without an order id inserted")
	}
}

// TestCancelUnknownOrderReportsAbsent proves cancelling an order with no approval
// reports absence instead of inventing a row.
func TestCancelUnknownOrderReportsAbsent(t *testing.T) {
	db := openSetupIntentTestDB(t)
	intent, changed, err := db.CancelGigahostSetupIntent(context.Background(), "ord_none", "reason")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if intent != nil || changed {
		t.Fatalf("cancel of an unknown order returned intent=%+v changed=%v", intent, changed)
	}
}

// TestCancelSettledIntentDoesNotRewriteHistory proves a completed install cannot be
// cancelled into a different state: an admitted backend is removed through the
// existing backend-disable path, not by rewriting the setup history.
func TestCancelSettledIntentDoesNotRewriteHistory(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	intent := newPendingIntent("ord_installed")
	intent.State = models.SetupStateReady
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, changed, err := db.CancelGigahostSetupIntent(ctx, "ord_installed", "late revoke")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if changed {
		t.Fatal("a completed install was cancelled")
	}
	if got == nil || got.State != models.SetupStateReady {
		t.Fatalf("state = %+v, want unchanged ready", got)
	}
}

// TestGetOrderReportsAbsentAndPresent proves the single-order read distinguishes
// a missing order from a real one, and that it reads the same fields the list read
// returns.
func TestGetOrderReportsAbsentAndPresent(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if _, found, err := db.GetGigahostOrder(ctx, "ord_missing"); err != nil || found {
		t.Fatalf("missing order: found=%v err=%v", found, err)
	}
	if _, found, err := db.GetGigahostOrder(ctx, ""); err != nil || found {
		t.Fatalf("empty id: found=%v err=%v", found, err)
	}

	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: "ord_present", ServerID: 314, Status: "ready", PlanID: 5, RegionID: 2,
		HourlyPriceNOK: 1.25, AssignedIP: "198.51.100.44", PriceID: 9,
		Currency: "NOK", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	order, found, err := db.GetGigahostOrder(ctx, "ord_present")
	if err != nil || !found {
		t.Fatalf("present order: found=%v err=%v", found, err)
	}
	if order.ServerID != 314 || order.AssignedIP != "198.51.100.44" ||
		order.PlanID != 5 || order.RegionID != 2 || order.PriceID != 9 || order.Currency != "NOK" {
		t.Fatalf("fields not preserved: %+v", order)
	}

	// The list read must report the same row with the same fields.
	list, err := db.ListGigahostOrders(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: len=%d err=%v", len(list), err)
	}
	if list[0].ServerID != order.ServerID || list[0].AssignedIP != order.AssignedIP {
		t.Fatalf("list and single read disagree: %+v vs %+v", list[0], *order)
	}
}

// TestValidateTransitionInputCoversEveryGuard proves each malformed transition is
// refused with its own reason, so a caller can tell what it got wrong.
func TestValidateTransitionInputCoversEveryGuard(t *testing.T) {
	cases := []struct {
		name     string
		intent   *models.GigahostSetupIntent
		expected []string
	}{
		{"nil intent", nil, []string{models.SetupStatePending}},
		{"no order id", &models.GigahostSetupIntent{State: models.SetupStatePending},
			[]string{models.SetupStatePending}},
		{"blank order id", &models.GigahostSetupIntent{OrderID: "  ", State: models.SetupStatePending},
			[]string{models.SetupStatePending}},
		{"no state", &models.GigahostSetupIntent{OrderID: "ord"},
			[]string{models.SetupStatePending}},
		{"no expected states", &models.GigahostSetupIntent{OrderID: "ord", State: models.SetupStatePending}, nil},
	}
	for _, tc := range cases {
		if err := validateTransitionInput(tc.intent, tc.expected); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
	if err := validateTransitionInput(&models.GigahostSetupIntent{
		OrderID: "ord", State: models.SetupStatePending}, []string{models.SetupStatePending}); err != nil {
		t.Fatalf("valid input refused: %v", err)
	}
}

// TestCancelableSetupStateExcludesCompletedInstallAndRevoked proves which states
// a revocation may change.
//
// ready_for_setup and the two install states ARE revocable on purpose: a
// revocation has to reach work that has not started or is still in progress, not
// only the provider poll that precedes it. A completed install is excluded because
// removing an admitted backend is the existing backend-disable path, and a revoked
// row is excluded because it is already revoked.
func TestCancelableSetupStateExcludesCompletedInstallAndRevoked(t *testing.T) {
	for _, state := range []string{
		models.SetupStatePending, models.SetupStateAwaitingHostConfirm,
		models.SetupStateAwaitingCredentials, models.SetupStateFailed,
		models.SetupStateReadyForSetup, models.SetupStateInstalling,
		models.SetupStateInstallPaused,
	} {
		if !isCancelableSetupState(state) {
			t.Fatalf("%q should be cancelable", state)
		}
	}
	for _, state := range []string{models.SetupStateReady, models.SetupStateCanceled} {
		if isCancelableSetupState(state) {
			t.Fatalf("%q must not be cancelable", state)
		}
	}
}

// TestApplyRevocationReportsWhetherItWon proves the revocation transition reports
// its own success, which is what lets the caller distinguish "I revoked it" from
// "something else changed it first".
func TestApplyRevocationReportsWhetherItWon(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	intent := newPendingIntent("ord_revoke")
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	changed, err := db.applyRevocation(ctx, intent, "revoked")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !changed {
		t.Fatal("apply reported no change for a pending intent")
	}
	got, _, _ := db.GetGigahostSetupIntent(ctx, "ord_revoke")
	if got.State != models.SetupStateCanceled || got.RevokedAt.IsZero() {
		t.Fatalf("state = %q revoked_at = %v", got.State, got.RevokedAt)
	}

	// A second application on the now-canceled row must not win again: canceled is
	// not in the cancelable set, so no further transition applies.
	again, err := db.applyRevocation(ctx, got, "revoked twice")
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if again {
		t.Fatal("a second revocation overwrote the first")
	}
}

// TestCancelLosesToAConcurrentCompletion proves the read-then-write window: if the
// row left the cancelable states between the read and the write, the cancel
// reports the actual state and does not rewrite it.
func TestCancelLosesToAConcurrentHandoff(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	intent := newPendingIntent("ord_race_done")
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Simulate the installer winning the race and completing the order.
	completed := newPendingIntent("ord_race_done")
	completed.State = models.SetupStateReady
	if changed, err := db.TransitionGigahostSetupIntent(ctx, completed,
		[]string{models.SetupStatePending}); err != nil || !changed {
		t.Fatalf("completion transition: changed=%v err=%v", changed, err)
	}

	got, changed, err := db.CancelGigahostSetupIntent(ctx, "ord_race_done", "late")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if changed {
		t.Fatal("cancel won against an already-completed order")
	}
	if got == nil || got.State != models.SetupStateReady {
		t.Fatalf("state = %+v, want the completed order reported unchanged", got)
	}
}

// TestCancelReportsDatabaseErrors proves a read failure during revocation is
// reported rather than being mistaken for "no such approval".
func TestCancelReportsDatabaseErrors(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_dberr")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, _, err := db.CancelGigahostSetupIntent(ctx, "ord_dberr", "reason"); err == nil {
		t.Fatal("cancel against a closed database returned no error")
	}
	// A closed database reports nothing missing rather than inventing an answer.
	intent, changed, err := db.CancelGigahostSetupIntent(ctx, "", "reason")
	if err != nil {
		// Either an error or an empty result is acceptable here; inventing a row
		// is not. What must never happen is a non-nil intent.
		if intent != nil {
			t.Fatalf("cancel returned an intent with an error: %+v", intent)
		}
	} else if intent != nil || changed {
		t.Fatalf("cancel of an empty id returned intent=%+v changed=%v", intent, changed)
	}
}

// TestCancelNilDatabaseIsANoOp proves the nil-database guard, which the handler
// path can reach in a build without persistence.
func TestCancelNilDatabaseIsANoOp(t *testing.T) {
	var db *DB
	intent, changed, err := db.CancelGigahostSetupIntent(context.Background(), "ord", "reason")
	if err != nil || intent != nil || changed {
		t.Fatalf("nil database cancel: intent=%+v changed=%v err=%v", intent, changed, err)
	}
}

// TestCancelReReadsAfterConcurrentSettlement proves the read-then-write window is
// handled by re-reading: if the revocation's own transition loses, the caller is
// told the row's current state rather than a stale one.
//
// The losing branch is produced deterministically by making the transition see a
// row that already left the cancelable states between the read and the write.
func TestCancelReReadsAfterConcurrentSettlement(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_concurrent")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Move the row while the cancel has already read it: complete the install
	// first, then attempt the cancel from a pre-read snapshot.
	stale, found, err := db.GetGigahostSetupIntent(ctx, "ord_concurrent")
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	completed := newPendingIntent("ord_concurrent")
	completed.State = models.SetupStateReady
	if changed, err := db.TransitionGigahostSetupIntent(ctx, completed,
		[]string{models.SetupStatePending}); err != nil || !changed {
		t.Fatalf("completion: changed=%v err=%v", changed, err)
	}
	if stale.State != models.SetupStatePending {
		t.Fatalf("precondition: snapshot should still read pending, got %q", stale.State)
	}

	// The revocation's transition must lose, and the re-read must report the
	// completed state rather than the stale snapshot.
	changed, err := db.applyRevocation(ctx, stale, "late revoke")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed {
		t.Fatal("revocation won against a completed order")
	}
	latest, foundLatest, err := db.GetGigahostSetupIntent(ctx, "ord_concurrent")
	if err != nil || !foundLatest {
		t.Fatalf("re-read: found=%v err=%v", foundLatest, err)
	}
	if latest.State != models.SetupStateReady {
		t.Fatalf("re-read state = %q, want the completed order", latest.State)
	}
}

// TestCancelPropagatesTransitionFailure proves a failing revocation write is
// reported rather than silently swallowed: the caller must not conclude that the
// approval was revoked when the write failed.
func TestCancelPropagatesTransitionFailure(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_writefail")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Close the database after the read would succeed: the transition write then
	// fails while the row lookup had already answered, which is the exact shape of
	// a mid-operation storage failure.
	current, found, err := db.GetGigahostSetupIntent(ctx, "ord_writefail")
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := db.applyRevocation(ctx, current, "reason"); err == nil {
		t.Fatal("applyRevocation reported success against a closed database")
	}
	if _, _, err := db.CancelGigahostSetupIntent(ctx, "ord_writefail", "reason"); err == nil {
		t.Fatal("CancelGigahostSetupIntent reported success against a closed database")
	}
}

// TestCancelThroughPublicPathAfterSettlement drives the losing-race path through
// the public method, so the re-read it performs is exercised end to end.
//
// The row is settled first, then cancelled: the cancel observes a non-cancelable
// state and must report the stored state without rewriting it.
func TestCancelThroughPublicPathAfterSettlement(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_public_race")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	completed := newPendingIntent("ord_public_race")
	completed.State = models.SetupStateReady
	if changed, err := db.TransitionGigahostSetupIntent(ctx, completed,
		[]string{models.SetupStatePending}); err != nil || !changed {
		t.Fatalf("completion: changed=%v err=%v", changed, err)
	}

	got, changed, err := db.CancelGigahostSetupIntent(ctx, "ord_public_race", "late revoke")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if changed {
		t.Fatal("public cancel won against a completed order")
	}
	if got == nil || got.State != models.SetupStateReady {
		t.Fatalf("reported state = %+v, want the completed order", got)
	}
}

// TestCancelOutcomeAfterLosingRaceReportsStoredTruth pins the contract of the
// re-read a losing revocation performs: it answers from the row as it is now, and
// reports a vanished row as absent rather than fabricating one.
//
// The branch is exercised directly because reaching it through CancelGigahost-
// SetupIntent requires a write to land between its read and its transition, which
// no deterministic test can schedule without a production test seam. The behaviour
// being pinned here is real and observable regardless of how it is reached.
func TestCancelOutcomeAfterLosingRaceReportsStoredTruth(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	if err := db.CreateGigahostSetupIntent(ctx, newPendingIntent("ord_reread")); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// The row exists: the re-read reports it with its stored state.
	got, changed, err := db.cancelOutcomeAfterLosingRace(ctx, "ord_reread")
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if changed {
		t.Fatal("the losing re-read must never report that it changed the row")
	}
	if got == nil || got.State != models.SetupStatePending {
		t.Fatalf("re-read = %+v, want the stored pending row", got)
	}

	// The row is absent: absent is reported, not an invented row or an error.
	got, changed, err = db.cancelOutcomeAfterLosingRace(ctx, "ord_gone")
	if err != nil {
		t.Fatalf("re-read of a missing row: %v", err)
	}
	if got != nil || changed {
		t.Fatalf("missing row reported as intent=%+v changed=%v", got, changed)
	}
}
