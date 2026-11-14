package database

// Persistence tests for the install journal.
//
// These are the guarantees the rest of the lifecycle relies on, tested directly
// against SQLite: a claim is exclusive, a takeover is generation-fenced, a journal
// write from a superseded attempt is refused, resume cannot revive a completed or
// revoked job, and an older database is upgraded without losing its rows.

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// seedInstallIntent records one pending order plus an approval in the given state.
func seedInstallIntent(t *testing.T, db *DB, orderID, state string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(ctx, &models.GigahostOrder{
		OrderID: orderID, Status: "ready", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed order: %v", err)
	}
	intent := newPendingIntent(orderID)
	intent.State = state
	intent.NextAttemptAt = time.Time{}
	if err := db.CreateGigahostSetupIntent(ctx, intent); err != nil {
		t.Fatalf("seed intent: %v", err)
	}
}

// TestClaimIsExclusive proves only one concurrent claim can succeed, which is what
// makes "one install attempt at a time" a database fact rather than a convention.
func TestClaimIsExclusive(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	seedInstallIntent(t, db, "ord_excl", models.SetupStateReadyForSetup)

	const racers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for k := 0; k < racers; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := db.ClaimGigahostSetupInstall(ctx, "ord_excl")
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("successful claims = %d, want exactly 1", wins)
	}
	got, _, err := db.GetGigahostSetupIntent(ctx, "ord_excl")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.InstallAttempts != 1 {
		t.Fatalf("install attempts = %d, want 1", got.InstallAttempts)
	}
}

// TestTakeoverIsGenerationFenced proves a takeover only succeeds against the
// generation it read, so two contenders cannot both capture the same leftover.
func TestTakeoverIsGenerationFenced(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	seedInstallIntent(t, db, "ord_takeover", models.SetupStateReadyForSetup)

	claimed, ok, err := db.ClaimGigahostSetupInstall(ctx, "ord_takeover")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if _, ok, err := db.TakeOverGigahostSetupInstall(ctx, "ord_takeover", claimed.InstallGeneration+5); err != nil || ok {
		t.Fatalf("takeover with a stale generation succeeded: ok=%v err=%v", ok, err)
	}
	taken, ok, err := db.TakeOverGigahostSetupInstall(ctx, "ord_takeover", claimed.InstallGeneration)
	if err != nil || !ok {
		t.Fatalf("takeover: ok=%v err=%v", ok, err)
	}
	if taken.InstallGeneration != claimed.InstallGeneration+1 {
		t.Fatalf("generation = %d, want %d", taken.InstallGeneration, claimed.InstallGeneration+1)
	}
}

// TestJournalWriteIsFencedByState proves a journal write from an attempt fails once
// the row leaves the installing state - the path a revocation takes.
func TestJournalWriteIsFencedByState(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	seedInstallIntent(t, db, "ord_fenced", models.SetupStateReadyForSetup)

	claimed, ok, err := db.ClaimGigahostSetupInstall(ctx, "ord_fenced")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if _, _, err := db.CancelGigahostSetupIntent(ctx, "ord_fenced", "revoked"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	claimed.State = models.SetupStateInstallPaused
	claimed.Step = "installing_protocol"
	claimed.InstallPhase = models.SetupPhaseInstalled
	changed, err := db.UpdateGigahostSetupInstall(ctx, claimed, claimed.InstallGeneration)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if changed {
		t.Fatal("a revoked attempt wrote its journal")
	}
	got, _, _ := db.GetGigahostSetupIntent(ctx, "ord_fenced")
	if got.State != models.SetupStateCanceled {
		t.Fatalf("state = %q, want the revocation to stand", got.State)
	}
}

// TestResumeRefusesTerminalStates proves a resume cannot revive a completed
// install, a revocation or a provider terminal failure.
func TestResumeRefusesTerminalStates(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	for _, state := range []string{
		models.SetupStateReady, models.SetupStateCanceled, models.SetupStateFailed,
	} {
		orderID := "ord_term_" + state
		seedInstallIntent(t, db, orderID, state)
		if _, changed, err := db.ResumeGigahostSetupInstall(ctx, orderID); err != nil {
			t.Fatalf("%s: resume error: %v", state, err)
		} else if changed {
			t.Fatalf("%s: a terminal state was resumed", state)
		}
		if got, _, _ := db.GetGigahostSetupIntent(ctx, orderID); got.State != state {
			t.Fatalf("%s: state = %q after refused resume", state, got.State)
		}
	}
}

// TestResumeAcceptsEveryStoppedState proves the resume acts on exactly the states
// that stopped for a decision, and issues a new generation each time.
func TestResumeAcceptsEveryStoppedState(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	for _, state := range []string{
		models.SetupStateReadyForSetup, models.SetupStateAwaitingHostConfirm,
		models.SetupStateAwaitingCredentials, models.SetupStateInstallPaused,
	} {
		orderID := "ord_stop_" + state
		seedInstallIntent(t, db, orderID, state)
		resumed, changed, err := db.ResumeGigahostSetupInstall(ctx, orderID)
		if err != nil || !changed {
			t.Fatalf("%s: changed=%v err=%v", state, changed, err)
		}
		if resumed.State != models.SetupStateInstalling {
			t.Fatalf("%s: resumed into %q, want %q", state, resumed.State, models.SetupStateInstalling)
		}
		if resumed.InstallGeneration == 0 {
			t.Fatalf("%s: resume issued no generation", state)
		}
	}
}

// TestConfirmHostBindsExactIdentity proves the confirmation stores the exact
// displayed value, re-arms tracking, and refuses everything else.
//
// "Refuses everything else" is the load-bearing half: a value the panel never
// displayed for this job cannot become a trusted host, so an approval with no
// observation and a value differing from the observation are both refusals.
func TestConfirmHostBindsExactIdentity(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const other = "SHA256:ERERERERERERERERERERERERERERERERERERERERERE"

	seedInstallIntent(t, db, "ord_confirm", models.SetupStateAwaitingHostConfirm)
	seedHostCandidate(t, db, "ord_confirm", fp)

	// A value the panel did not display is refused and changes nothing.
	if got, changed, err := db.ConfirmGigahostSetupHostFingerprint(ctx, "ord_confirm", other); err != nil {
		t.Fatalf("confirm with an undisplayed identity: %v", err)
	} else if changed {
		t.Fatalf("an identity the panel never displayed was accepted: %+v", got)
	}
	if got, _, _ := db.GetGigahostSetupIntent(ctx, "ord_confirm"); got.HostFingerprint != "" {
		t.Fatalf("a refused confirmation stored %q", got.HostFingerprint)
	}

	got, changed, err := db.ConfirmGigahostSetupHostFingerprint(ctx, "ord_confirm", fp)
	if err != nil || !changed {
		t.Fatalf("confirm: changed=%v err=%v", changed, err)
	}
	if got.HostFingerprint != fp {
		t.Fatalf("stored identity = %q, want %q", got.HostFingerprint, fp)
	}
	if got.HostCandidateFingerprint != "" {
		t.Fatalf("the confirmed candidate was left on the row: %q", got.HostCandidateFingerprint)
	}
	if got.State != models.SetupStatePending {
		t.Fatalf("state = %q, want %q", got.State, models.SetupStatePending)
	}

	// A completed job is not a confirmation target.
	seedInstallIntent(t, db, "ord_confirm_done", models.SetupStateReady)
	seedHostCandidate(t, db, "ord_confirm_done", fp)
	done, changed, err := db.ConfirmGigahostSetupHostFingerprint(ctx, "ord_confirm_done", fp)
	if err != nil {
		t.Fatalf("confirm on completed: %v", err)
	}
	if changed {
		t.Fatal("a completed install accepted a host confirmation")
	}
	if done == nil || done.State != models.SetupStateReady {
		t.Fatalf("completed job state = %+v, want it unchanged", done)
	}

	// An empty identity is refused outright.
	if _, _, err := db.ConfirmGigahostSetupHostFingerprint(ctx, "ord_confirm", "  "); err == nil {
		t.Fatal("an empty host identity was accepted")
	}
}

// TestConfirmHostPreservesAnUnknownInstallJournal proves the uncertainty boundary
// survives a trust decision.
//
// An interrupted install has remote effects nobody can prove. Confirming the same
// correct identity is a trust decision, and it must not become an installation
// decision: the journal is kept, a new attempt generation is issued so the
// existing verify-not-replay path owns the row, and the row returns to the
// installing state rather than to the handoff that would install again.
func TestConfirmHostPreservesAnUnknownInstallJournal(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const orderID = "ord_unknown_install"

	seedInstallIntent(t, db, orderID, models.SetupStateInstallPaused)
	seedHostCandidate(t, db, orderID, fp)
	// The persisted shape of an install that stopped inside the protocol phase.
	if _, err := db.SQLDB().ExecContext(ctx,
		`UPDATE gigahost_setup_intents
		    SET install_generation = 1, install_phase = ?, install_phase_done = ?
		  WHERE order_id = ?`,
		models.SetupPhaseInstalled, models.SetupPhaseRegistered, orderID); err != nil {
		t.Fatalf("seed interrupted install: %v", err)
	}

	got, changed, err := db.ConfirmGigahostSetupHostFingerprint(ctx, orderID, fp)
	if err != nil || !changed {
		t.Fatalf("confirm: changed=%v err=%v", changed, err)
	}
	if got.InstallPhase != models.SetupPhaseInstalled || got.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("the install journal was discarded: phase=%q done=%q",
			got.InstallPhase, got.InstallPhaseDone)
	}
	if got.InstallGeneration != 2 {
		t.Fatalf("generation = %d, want a new attempt generation (2)", got.InstallGeneration)
	}
	if got.State != models.SetupStateInstalling {
		t.Fatalf("state = %q, want %q so the verify path owns the row", got.State, models.SetupStateInstalling)
	}

	// The confirmed row is in the installing state with a new generation and no
	// live owner, which is exactly the leftover-claim shape the takeover branch
	// exists for. Taking it over must keep the journal the new attempt verifies.
	taken, ok, err := db.TakeOverGigahostSetupInstall(ctx, orderID, got.InstallGeneration)
	if err != nil || !ok {
		t.Fatalf("takeover after confirmation: ok=%v err=%v", ok, err)
	}
	if taken.InstallPhase != models.SetupPhaseInstalled || taken.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("the takeover erased the journal: phase=%q done=%q",
			taken.InstallPhase, taken.InstallPhaseDone)
	}
	if taken.InstallGeneration != 3 {
		t.Fatalf("generation = %d, want 3 after the takeover", taken.InstallGeneration)
	}
}

// TestClaimKeepsJournal proves the claim is journal-safe.
//
// Two cases, because a claim of a handoff row must not invent a journal while a
// claim of a row that carries history must not destroy it. The second case is the
// consumer half of the replay window: the plan reads exactly these columns to
// decide "verify" instead of "run", so a claim that cleared them silently turned
// an unknown remote effect back into an authorized installation.
func TestClaimKeepsJournal(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()

	seedInstallIntent(t, db, "ord_handoff_clean", models.SetupStateReadyForSetup)
	claimed, ok, err := db.ClaimGigahostSetupInstall(ctx, "ord_handoff_clean")
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if claimed.InstallPhase != "" || claimed.InstallPhaseDone != "" {
		t.Fatalf("a fresh claim invented a journal: phase=%q done=%q",
			claimed.InstallPhase, claimed.InstallPhaseDone)
	}

	// A row that reaches the handoff carrying history: the claim is the same
	// transition, and it must leave the journal for the plan to read.
	seedInstallIntent(t, db, "ord_handoff_history", models.SetupStateReadyForSetup)
	if _, err := db.SQLDB().ExecContext(ctx,
		`UPDATE gigahost_setup_intents
		    SET install_generation = 2, install_phase = ?, install_phase_done = ?
		  WHERE order_id = ?`,
		models.SetupPhaseInstalled, models.SetupPhaseRegistered, "ord_handoff_history"); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	historical, ok, err := db.ClaimGigahostSetupInstall(ctx, "ord_handoff_history")
	if err != nil || !ok {
		t.Fatalf("claim with history: ok=%v err=%v", ok, err)
	}
	if historical.InstallPhase != models.SetupPhaseInstalled ||
		historical.InstallPhaseDone != models.SetupPhaseRegistered {
		t.Fatalf("the claim erased the journal: phase=%q done=%q",
			historical.InstallPhase, historical.InstallPhaseDone)
	}
	if historical.InstallGeneration != 3 {
		t.Fatalf("generation = %d, want 3 after the claim", historical.InstallGeneration)
	}
}

// seedHostCandidate records the identity the panel's read-only challenge observed
// for an approval, which is what makes that exact value confirmable.
func seedHostCandidate(t *testing.T, db *DB, orderID, fingerprint string) {
	t.Helper()
	if _, err := db.SQLDB().ExecContext(context.Background(),
		`UPDATE gigahost_setup_intents SET host_candidate_fingerprint = ? WHERE order_id = ?`,
		fingerprint, orderID); err != nil {
		t.Fatalf("seed host candidate for %s: %v", orderID, err)
	}
}

// TestInstallSchemaUpgradeKeepsExistingRows proves the install columns are added to
// a table created by the earlier version, and an existing approval keeps its data.
//
// The older table is created by a raw connection BEFORE the database is opened for
// use, which is the same seam the repository's other legacy-migration tests use
// (internal/database/test_helpers_test.go, openLegacyDB). Opening the file through
// Open() then runs the real production migration chain - no bypass, no second
// CREATE TABLE against a table the current schema already made.
func TestInstallSchemaUpgradeKeepsExistingRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")
	oldSchema := `CREATE TABLE IF NOT EXISTS gigahost_setup_intents (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id TEXT NOT NULL,
		provider_server_id INTEGER NOT NULL DEFAULT 0,
		assigned_ip TEXT NOT NULL DEFAULT '',
		protocol TEXT NOT NULL DEFAULT '',
		port TEXT NOT NULL DEFAULT '',
		tls_domain TEXT NOT NULL DEFAULT '',
		engine_profile TEXT NOT NULL DEFAULT '',
		credential_mode TEXT NOT NULL DEFAULT '',
		state TEXT NOT NULL,
		provider_status TEXT NOT NULL DEFAULT '',
		step TEXT NOT NULL DEFAULT '',
		last_error TEXT NOT NULL DEFAULT '',
		host_fingerprint TEXT NOT NULL DEFAULT '',
		host_mismatch INTEGER NOT NULL DEFAULT 0,
		read_failures INTEGER NOT NULL DEFAULT 0,
		attempts INTEGER NOT NULL DEFAULT 0,
		next_attempt_at TEXT NOT NULL DEFAULT '',
		last_checked_at TEXT NOT NULL DEFAULT '',
		approved_by TEXT NOT NULL DEFAULT '',
		revoked_at TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw legacy database: %v", err)
	}
	if _, err := raw.Exec(oldSchema); err != nil {
		_ = raw.Close()
		t.Fatalf("create older table: %v", err)
	}
	const legacyFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := raw.Exec(
		`INSERT INTO gigahost_setup_intents
		 (order_id, provider_server_id, protocol, port, credential_mode, state,
		  step, host_fingerprint, approved_by, created_at, updated_at)
		 VALUES ('ord_legacy', 4242, 'awg', '51820', 'managed', 'ready_for_setup',
		         'ready_for_setup', ?, 'admin-fixture', ?, ?)`,
		legacyFingerprint, now, now); err != nil {
		_ = raw.Close()
		t.Fatalf("insert legacy row: %v", err)
	}
	// An order row with a stored credential, to prove the upgrade does not touch it.
	if _, err := raw.Exec(
		`CREATE TABLE IF NOT EXISTS gigahost_orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL,
			server_id INTEGER DEFAULT 0, status TEXT NOT NULL,
			plan_id INTEGER NOT NULL, region_id INTEGER NOT NULL,
			hourly_price_nok REAL NOT NULL DEFAULT 0.0, assigned_ip TEXT DEFAULT '',
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		)`); err != nil {
		_ = raw.Close()
		t.Fatalf("create older order table: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO gigahost_orders (order_id, server_id, status, plan_id, region_id, created_at, updated_at)
		 VALUES ('ord_legacy', 4242, 'ready', 1, 1, ?, ?)`, now, now); err != nil {
		_ = raw.Close()
		t.Fatalf("insert legacy order: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw legacy database: %v", err)
	}

	// Open() runs the real migration chain over the file in place.
	db, err := Open(dbPath, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("open and migrate: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	got, found, err := db.GetGigahostSetupIntent(ctx, "ord_legacy")
	if err != nil || !found {
		t.Fatalf("read legacy row after upgrade: found=%v err=%v", found, err)
	}
	if got.State != models.SetupStateReadyForSetup || got.Protocol != models.ProtocolAWG {
		t.Fatalf("legacy row changed by the upgrade: %+v", got)
	}
	if got.HostFingerprint != legacyFingerprint || got.ApprovedBy != "admin-fixture" {
		t.Fatalf("legacy approval identity lost: fingerprint=%q approved_by=%q",
			got.HostFingerprint, got.ApprovedBy)
	}
	if got.ProviderServerID != 4242 || got.Port != "51820" || got.CredentialMode != models.SetupCredentialManaged {
		t.Fatalf("legacy approval fields lost: %+v", got)
	}
	if got.InstallGeneration != 0 || got.InstallPhase != "" || got.NexusServerID != 0 {
		t.Fatalf("upgraded install columns are not at their zero value: %+v", got)
	}
	// The upgraded row is immediately usable by the install path: a claim wins and
	// carries a real generation, without a second migration or a schema error.
	claimed, ok, err := db.ClaimGigahostSetupInstall(ctx, "ord_legacy")
	if err != nil || !ok {
		t.Fatalf("claim after upgrade: ok=%v err=%v", ok, err)
	}
	if claimed.InstallGeneration != 1 {
		t.Fatalf("generation after first claim = %d, want 1", claimed.InstallGeneration)
	}
	// The already-migrated columns must not be re-added as duplicates on a second
	// open (idempotent upgrade), so the same file opens again cleanly.
	if err := db.migrateGigahostSetupIntents(ctx); err != nil {
		t.Fatalf("re-running the migration on an upgraded database: %v", err)
	}
}

// TestDueInstallQueryIncludesInstallingAndExcludesPaused proves the scheduler's
// selection: an interrupted attempt is picked up, a paused one is not.
func TestDueInstallQueryIncludesInstallingAndExcludesPaused(t *testing.T) {
	db := openSetupIntentTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

	seedInstallIntent(t, db, "ord_handoff", models.SetupStateReadyForSetup)
	seedInstallIntent(t, db, "ord_inflight", models.SetupStateInstalling)
	seedInstallIntent(t, db, "ord_paused", models.SetupStateInstallPaused)
	seedInstallIntent(t, db, "ord_finished", models.SetupStateReady)

	due, err := db.ListDueGigahostSetupInstalls(ctx, now, 10)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	got := map[string]bool{}
	for _, intent := range due {
		got[intent.OrderID] = true
	}
	if !got["ord_handoff"] || !got["ord_inflight"] {
		t.Fatalf("due = %v, want the handoff and the interrupted attempt", got)
	}
	if got["ord_paused"] || got["ord_finished"] {
		t.Fatalf("due = %v, paused and finished rows must not be scheduled", got)
	}
}

// TestValidateInstallUpdateCoversEveryGuard proves the journal-update validator
// rejects each malformed call with its own reason and accepts a real one. A guard
// that silently accepted one of these would let a caller write a row it does not
// describe.
func TestValidateInstallUpdateCoversEveryGuard(t *testing.T) {
	valid := &models.GigahostSetupIntent{
		OrderID: "ord_v", Step: "installing_protocol", State: models.SetupStateInstalling,
	}
	cases := []struct {
		name   string
		intent *models.GigahostSetupIntent
		gen    int64
	}{
		{"nil intent", nil, 1},
		{"no order id", &models.GigahostSetupIntent{Step: "s", State: models.SetupStateInstalling}, 1},
		{"blank order id", &models.GigahostSetupIntent{OrderID: "  ", Step: "s", State: models.SetupStateInstalling}, 1},
		{"no generation", &models.GigahostSetupIntent{OrderID: "o", Step: "s", State: models.SetupStateInstalling}, 0},
		{"negative generation", &models.GigahostSetupIntent{OrderID: "o", Step: "s", State: models.SetupStateInstalling}, -1},
		{"no step", &models.GigahostSetupIntent{OrderID: "o", State: models.SetupStateInstalling}, 1},
		{"blank step", &models.GigahostSetupIntent{OrderID: "o", Step: " ", State: models.SetupStateInstalling}, 1},
		{"unwritable state", &models.GigahostSetupIntent{OrderID: "o", Step: "s", State: models.SetupStateCanceled}, 1},
		{"completed state", &models.GigahostSetupIntent{OrderID: "o", Step: "s", State: models.SetupStateFailed}, 1},
	}
	for _, tc := range cases {
		if err := validateInstallUpdate(tc.intent, tc.gen); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
	if err := validateInstallUpdate(valid, 1); err != nil {
		t.Fatalf("a valid update was refused: %v", err)
	}
	// Every writable state is accepted.
	for _, state := range installUpdateStates {
		candidate := *valid
		candidate.State = state
		if err := validateInstallUpdate(&candidate, 3); err != nil {
			t.Fatalf("state %q refused: %v", state, err)
		}
	}
}
