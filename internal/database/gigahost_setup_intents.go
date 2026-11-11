package database

// Persistence for durable Gigahost setup intents.
//
// An intent is the administrator's explicit approval to set up one already
// placed order, plus the progress of the provider provisioning that must finish
// before setup can run. It exists because provisioning takes far longer than a
// browser session: a background worker owns the progress, so closing the tab
// must not lose the work, and restating the approval must not create a second
// job.
//
// The row never stores credentials. It stores the reference kind (managed or
// manual) and, when the approval carries one, the SSH host fingerprint the
// administrator actually confirmed. Key material stays in the order credential
// already encrypted by the existing boundary.
//
// Only this package issues SQL for the table (module ownership rules).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// gigahostSetupIntentsSchema is the current table definition. It is created when
// missing and upgraded column by column for databases created by earlier
// versions, matching the ledger's idempotent upgrade convention.
var gigahostSetupIntentsSchema = `CREATE TABLE IF NOT EXISTS gigahost_setup_intents (
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
	host_candidate_fingerprint TEXT NOT NULL DEFAULT '',
	host_trust_policy TEXT NOT NULL DEFAULT '',
	host_trust_mode TEXT NOT NULL DEFAULT '',
	host_trust_order_id TEXT NOT NULL DEFAULT '',
	host_trust_server_id INTEGER NOT NULL DEFAULT 0,
	host_trust_address TEXT NOT NULL DEFAULT '',
	host_trust_key_id INTEGER NOT NULL DEFAULT 0,
	host_trust_granted_at TEXT NOT NULL DEFAULT '',
	read_failures INTEGER NOT NULL DEFAULT 0,
	attempts INTEGER NOT NULL DEFAULT 0,
	install_generation INTEGER NOT NULL DEFAULT 0,
	install_phase TEXT NOT NULL DEFAULT '',
	install_phase_done TEXT NOT NULL DEFAULT '',
	install_attempts INTEGER NOT NULL DEFAULT 0,
	nexus_server_id INTEGER NOT NULL DEFAULT 0,
	next_attempt_at TEXT NOT NULL DEFAULT '',
	last_checked_at TEXT NOT NULL DEFAULT '',
	approved_by TEXT NOT NULL DEFAULT '',
	revoked_at TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`

// gigahostSetupIntentColumnUpgrades adds the install-journal columns to a table
// created by an earlier version. SQLite refuses a NOT NULL column without a
// default, so every entry carries one and an existing row reads as "no install
// has started".
var gigahostSetupIntentColumnUpgrades = []struct {
	name string
	ddl  string
}{
	{"host_candidate_fingerprint", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_candidate_fingerprint TEXT NOT NULL DEFAULT ''`},
	{"install_generation", `ALTER TABLE gigahost_setup_intents ADD COLUMN install_generation INTEGER NOT NULL DEFAULT 0`},
	{"install_phase", `ALTER TABLE gigahost_setup_intents ADD COLUMN install_phase TEXT NOT NULL DEFAULT ''`},
	{"install_phase_done", `ALTER TABLE gigahost_setup_intents ADD COLUMN install_phase_done TEXT NOT NULL DEFAULT ''`},
	{"install_attempts", `ALTER TABLE gigahost_setup_intents ADD COLUMN install_attempts INTEGER NOT NULL DEFAULT 0`},
	{"nexus_server_id", `ALTER TABLE gigahost_setup_intents ADD COLUMN nexus_server_id INTEGER NOT NULL DEFAULT 0`},
	{"host_trust_policy", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_policy TEXT NOT NULL DEFAULT ''`},
	{"host_trust_mode", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_mode TEXT NOT NULL DEFAULT ''`},
	{"host_trust_order_id", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_order_id TEXT NOT NULL DEFAULT ''`},
	{"host_trust_server_id", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_server_id INTEGER NOT NULL DEFAULT 0`},
	{"host_trust_address", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_address TEXT NOT NULL DEFAULT ''`},
	{"host_trust_key_id", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_key_id INTEGER NOT NULL DEFAULT 0`},
	{"host_trust_granted_at", `ALTER TABLE gigahost_setup_intents ADD COLUMN host_trust_granted_at TEXT NOT NULL DEFAULT ''`},
}

// gigahostSetupIntentIndexes are created after the table and column upgrades.
//
// The unique index is the durable guard against a second job for one order: two
// concurrent approvals cannot both become a row, and the loser gets a
// constraint error rather than a silently duplicated tracker.
var gigahostSetupIntentIndexes = []string{
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_gigahost_setup_intents_order
		ON gigahost_setup_intents(order_id)`,
	`CREATE INDEX IF NOT EXISTS idx_gigahost_setup_intents_due
		ON gigahost_setup_intents(state, next_attempt_at)`,
}

// EnsureGigahostSetupIntentsSchema creates or upgrades the intent table. It is
// safe to call on every request and from a migration.
func (d *DB) EnsureGigahostSetupIntentsSchema(ctx context.Context) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.ensureGigahostSetupIntentsSchemaLocked(ctx)
}

func (d *DB) ensureGigahostSetupIntentsSchemaLocked(ctx context.Context) error {
	if _, err := d.sqlDB.ExecContext(ctx, gigahostSetupIntentsSchema); err != nil {
		return fmt.Errorf("failed to init gigahost_setup_intents schema: %w", err)
	}
	for _, col := range gigahostSetupIntentColumnUpgrades {
		// A duplicate column means the upgrade already ran; any other error is
		// real and must not be swallowed.
		if _, err := d.sqlDB.ExecContext(ctx, col.ddl); err != nil && !isDuplicateColumnError(err) {
			return fmt.Errorf("failed to add gigahost_setup_intents column %s: %w", col.name, err)
		}
	}
	for _, q := range gigahostSetupIntentIndexes {
		if _, err := d.sqlDB.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed to create gigahost_setup_intents index: %w", err)
		}
	}
	return nil
}

// migrateGigahostSetupIntents upgrades an existing database at startup. It runs
// from runMigrationsLocked, which already holds writeMu.
func (d *DB) migrateGigahostSetupIntents(ctx context.Context) error {
	return d.ensureGigahostSetupIntentsSchemaLocked(ctx)
}

// ErrSetupIntentExists reports that an intent already exists for the order.
// Callers treat it as "an approval is already recorded", never as a new job.
var ErrSetupIntentExists = errors.New("a setup intent already exists for this order")

// setupIntentColumns is the canonical column order for every SELECT and INSERT.
const setupIntentColumns = `id, order_id, provider_server_id, assigned_ip,
	protocol, port, tls_domain, engine_profile, credential_mode,
	state, provider_status, step, last_error,
	host_fingerprint, host_mismatch, host_candidate_fingerprint, host_trust_policy, host_trust_mode,
	host_trust_order_id, host_trust_server_id, host_trust_address, host_trust_key_id, host_trust_granted_at,
	read_failures, attempts,
	install_generation, install_phase, install_phase_done, install_attempts,
	nexus_server_id,
	next_attempt_at, last_checked_at, approved_by, revoked_at,
	created_at, updated_at`

// scanSetupIntent scans one row in setupIntentColumns order.
func scanSetupIntent(scanner interface {
	Scan(dest ...any) error
}) (*models.GigahostSetupIntent, error) {
	var i models.GigahostSetupIntent
	var hostMismatch int
	var nextAttempt, lastChecked, revokedAt, createdAt, updatedAt, trustGrantedAt string
	if err := scanner.Scan(
		&i.ID, &i.OrderID, &i.ProviderServerID, &i.AssignedIP,
		&i.Protocol, &i.Port, &i.TLSDomain, &i.EngineProfile, &i.CredentialMode,
		&i.State, &i.ProviderStatus, &i.Step, &i.LastError,
		&i.HostFingerprint, &hostMismatch, &i.HostCandidateFingerprint,
		&i.HostTrustPolicy, &i.HostTrustMode,
		&i.HostTrustOrderID, &i.HostTrustServerID, &i.HostTrustAddress, &i.HostTrustKeyID, &trustGrantedAt,
		&i.ReadFailures, &i.Attempts,
		&i.InstallGeneration, &i.InstallPhase, &i.InstallPhaseDone, &i.InstallAttempts,
		&i.NexusServerID,
		&nextAttempt, &lastChecked, &i.ApprovedBy, &revokedAt,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	i.HostMismatch = hostMismatch != 0
	i.HostTrustGrantedAt = parseSetupTimestamp(trustGrantedAt)
	i.NextAttemptAt = parseSetupTimestamp(nextAttempt)
	i.LastCheckedAt = parseSetupTimestamp(lastChecked)
	i.RevokedAt = parseSetupTimestamp(revokedAt)
	i.CreatedAt = parseSetupTimestamp(createdAt)
	i.UpdatedAt = parseSetupTimestamp(updatedAt)
	return &i, nil
}

// parseSetupTimestamp reads a stored RFC3339 timestamp; an empty or unparseable
// value is the zero time, which reads as "not recorded".
func parseSetupTimestamp(s string) time.Time {
	if strings.TrimSpace(s) == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// formatSetupTimestamp writes a timestamp, mapping the zero time to "" so it is
// distinct from a real instant.
func formatSetupTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// CreateGigahostSetupIntent records a new approval. It returns
// ErrSetupIntentExists when the order already has one, which is the durable
// answer to a repeated or concurrent approval.
func (d *DB) CreateGigahostSetupIntent(ctx context.Context, intent *models.GigahostSetupIntent) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	if err := validateSetupIntent(intent); err != nil {
		return err
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return err
	}

	now := time.Now().UTC()
	if intent.CreatedAt.IsZero() {
		intent.CreatedAt = now
	}
	intent.UpdatedAt = now

	q := `INSERT INTO gigahost_setup_intents (` + setupIntentColumns + `)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		nil, intent.OrderID, intent.ProviderServerID, intent.AssignedIP,
		intent.Protocol, intent.Port, intent.TLSDomain, intent.EngineProfile, intent.CredentialMode,
		intent.State, intent.ProviderStatus, intent.Step, intent.LastError,
		intent.HostFingerprint, boolToInt(intent.HostMismatch), intent.HostCandidateFingerprint,
		intent.HostTrustPolicy, intent.HostTrustMode,
		intent.HostTrustOrderID, intent.HostTrustServerID, intent.HostTrustAddress,
		intent.HostTrustKeyID, formatSetupTimestamp(intent.HostTrustGrantedAt),
		intent.ReadFailures, intent.Attempts,
		intent.InstallGeneration, intent.InstallPhase, intent.InstallPhaseDone, intent.InstallAttempts,
		intent.NexusServerID,
		formatSetupTimestamp(intent.NextAttemptAt), formatSetupTimestamp(intent.LastCheckedAt),
		intent.ApprovedBy, formatSetupTimestamp(intent.RevokedAt),
		formatSetupTimestamp(intent.CreatedAt), formatSetupTimestamp(intent.UpdatedAt),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return ErrSetupIntentExists
		}
		return fmt.Errorf("failed to insert gigahost setup intent: %w", err)
	}
	if id, idErr := res.LastInsertId(); idErr == nil {
		intent.ID = id
	}
	return nil
}

// validateSetupIntent rejects an intent that could not describe a real job.
func validateSetupIntent(intent *models.GigahostSetupIntent) error {
	if intent == nil {
		return errors.New("setup intent is required")
	}
	if strings.TrimSpace(intent.OrderID) == "" {
		return errors.New("setup intent requires an order id")
	}
	if strings.TrimSpace(intent.State) == "" {
		return errors.New("setup intent requires a state")
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetGigahostSetupIntent returns the intent for an order, or found=false.
func (d *DB) GetGigahostSetupIntent(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	row := d.sqlDB.QueryRowContext(ctx,
		`SELECT `+setupIntentColumns+` FROM gigahost_setup_intents WHERE order_id = ?`, orderID)
	intent, err := scanSetupIntent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read gigahost setup intent: %w", err)
	}
	return intent, true, nil
}

// ListGigahostSetupIntents returns every intent, newest first, for the status
// API and the administrator's view.
func (d *DB) ListGigahostSetupIntents(ctx context.Context) ([]models.GigahostSetupIntent, error) {
	if d == nil || d.sqlDB == nil {
		return []models.GigahostSetupIntent{}, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := d.sqlDB.QueryContext(ctx,
		`SELECT `+setupIntentColumns+` FROM gigahost_setup_intents ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to list gigahost setup intents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	list := []models.GigahostSetupIntent{}
	for rows.Next() {
		intent, scanErr := scanSetupIntent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		list = append(list, *intent)
	}
	return list, rows.Err()
}

// ListDueGigahostSetupIntents returns pending intents whose next attempt is due
// at or before now, oldest due first, bounded by limit.
//
// Only pending intents are returned: every other state is settled, and a settled
// row must not produce further provider reads.
func (d *DB) ListDueGigahostSetupIntents(ctx context.Context, now time.Time, limit int) ([]models.GigahostSetupIntent, error) {
	if d == nil || d.sqlDB == nil {
		return []models.GigahostSetupIntent{}, nil
	}
	if limit <= 0 {
		return []models.GigahostSetupIntent{}, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, err
	}
	// next_attempt_at is stored as RFC3339Nano text, whose fixed-width UTC form
	// sorts lexicographically in time order, so the comparison is a plain string
	// bound. An empty value (never scheduled) is due immediately.
	q := `SELECT ` + setupIntentColumns + `
	      FROM gigahost_setup_intents
	      WHERE state = ?
	        AND (next_attempt_at = '' OR next_attempt_at <= ?)
	      ORDER BY next_attempt_at, id
	      LIMIT ?`
	rows, err := d.sqlDB.QueryContext(ctx, q,
		models.SetupStatePending, formatSetupTimestamp(now), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list due gigahost setup intents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	list := []models.GigahostSetupIntent{}
	for rows.Next() {
		intent, scanErr := scanSetupIntent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		list = append(list, *intent)
	}
	return list, rows.Err()
}

// TransitionGigahostSetupIntent writes a state transition only if the row is
// still in one of the expected states.
//
// This is a compare-and-set, not a blind update: a tracker commit that raced an
// administrator's cancellation loses and reports changed=false, so a revoked
// approval can never be resurrected by a provider read that was already in
// flight. It returns the stored row after the attempt when found.
func (d *DB) TransitionGigahostSetupIntent(
	ctx context.Context,
	intent *models.GigahostSetupIntent,
	expectedStates []string,
) (bool, error) {
	if d == nil || d.sqlDB == nil {
		return false, nil
	}
	if err := validateTransitionInput(intent, expectedStates); err != nil {
		return false, err
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return false, err
	}

	q, args := buildTransitionStatement(intent, expectedStates)
	intent.UpdatedAt = time.Now().UTC()

	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q, args...)
	if err != nil {
		return false, fmt.Errorf("failed to transition gigahost setup intent: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to confirm gigahost setup intent transition: %w", err)
	}
	return affected > 0, nil
}

// validateTransitionInput rejects a transition that cannot describe a real row
// version, so a malformed call fails loudly instead of matching nothing.
func validateTransitionInput(intent *models.GigahostSetupIntent, expectedStates []string) error {
	switch {
	case intent == nil || strings.TrimSpace(intent.OrderID) == "":
		return errors.New("setup intent transition requires an order id")
	case strings.TrimSpace(intent.State) == "":
		return errors.New("setup intent transition requires a state")
	case len(expectedStates) == 0:
		return errors.New("setup intent transition requires at least one expected state")
	}
	return nil
}

// buildTransitionStatement renders the compare-and-set statement and its bound
// arguments for one intent version.
//
// The only interpolated text is a run of "?" bind markers counted from the
// expected-state list. Every value, including the states themselves, is a bound
// parameter, so no caller data reaches the statement text.
func buildTransitionStatement(
	intent *models.GigahostSetupIntent, expectedStates []string,
) (string, []any) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(expectedStates)), ",")
	q := `UPDATE gigahost_setup_intents
	      SET provider_server_id = CASE WHEN ? > 0 THEN ? ELSE provider_server_id END,
	          assigned_ip = CASE WHEN ? != '' THEN ? ELSE assigned_ip END,
	          provider_status = CASE WHEN ? != '' THEN ? ELSE provider_status END,
	          step = ?,
	          last_error = ?,
	          host_fingerprint = CASE WHEN ? != '' AND host_fingerprint = '' THEN ? ELSE host_fingerprint END,
	          host_trust_mode = CASE WHEN host_trust_mode = '' AND ? != '' THEN ? ELSE host_trust_mode END,
	          host_trust_order_id = CASE WHEN host_trust_order_id = '' AND ? != '' THEN ? ELSE host_trust_order_id END,
	          host_trust_server_id = CASE WHEN host_trust_server_id = 0 AND ? > 0 THEN ? ELSE host_trust_server_id END,
	          host_trust_address = CASE WHEN host_trust_address = '' AND ? != '' THEN ? ELSE host_trust_address END,
	          host_trust_key_id = CASE WHEN host_trust_key_id = 0 AND ? > 0 THEN ? ELSE host_trust_key_id END,
	          host_mismatch = ?,
	          host_candidate_fingerprint = ?,
	          read_failures = ?,
	          attempts = ?,
	          install_generation = ?,
	          install_phase = ?,
	          install_phase_done = ?,
	          install_attempts = ?,
	          nexus_server_id = CASE WHEN ? > 0 THEN ? ELSE nexus_server_id END,
	          next_attempt_at = ?,
	          last_checked_at = ?,
	          revoked_at = CASE WHEN ? != '' THEN ? ELSE revoked_at END,
	          state = ?,
	          updated_at = ?
	      WHERE order_id = ? AND state IN (` + placeholders + `)` // #nosec G202 -- placeholder count only; all values are bound arguments

	intent.UpdatedAt = time.Now().UTC()
	args := []any{
		intent.ProviderServerID, intent.ProviderServerID,
		intent.AssignedIP, intent.AssignedIP,
		intent.ProviderStatus, intent.ProviderStatus,
		intent.Step,
		intent.LastError,
		intent.HostFingerprint, intent.HostFingerprint,
		intent.HostTrustMode, intent.HostTrustMode,
		intent.HostTrustOrderID, intent.HostTrustOrderID,
		intent.HostTrustServerID, intent.HostTrustServerID,
		intent.HostTrustAddress, intent.HostTrustAddress,
		intent.HostTrustKeyID, intent.HostTrustKeyID,
		boolToInt(intent.HostMismatch),
		intent.HostCandidateFingerprint,
		intent.ReadFailures,
		intent.Attempts,
		intent.InstallGeneration,
		intent.InstallPhase,
		intent.InstallPhaseDone,
		intent.InstallAttempts,
		intent.NexusServerID, intent.NexusServerID,
		formatSetupTimestamp(intent.NextAttemptAt),
		formatSetupTimestamp(intent.LastCheckedAt),
		formatSetupTimestamp(intent.RevokedAt), formatSetupTimestamp(intent.RevokedAt),
		intent.State,
		formatSetupTimestamp(intent.UpdatedAt),
		intent.OrderID,
	}
	for _, s := range expectedStates {
		args = append(args, s)
	}
	return q, args
}

// CancelGigahostSetupIntent revokes the approval for an order.
//
// Canceling an intent that is already canceled succeeds without change, so a
// repeated request is idempotent. Canceling a settled intent that is not
// cancellable (ready_for_setup already handed off) reports changed=false and the
// caller explains the actual state instead of silently rewriting history.
func (d *DB) CancelGigahostSetupIntent(ctx context.Context, orderID, reason string) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil {
		return nil, false, nil
	}
	current, found, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil || !found {
		return nil, false, err
	}
	switch {
	case current.State == models.SetupStateCanceled:
		// Already revoked: the same request twice, not a second effect.
		return current, true, nil
	case !isCancelableSetupState(current.State):
		// The intent already left the states a revocation may change (it was
		// handed off). Report the actual state instead of rewriting history.
		return current, false, nil
	}

	changed, err := d.applyRevocation(ctx, current, reason)
	if err != nil {
		return nil, false, err
	}
	if changed {
		return current, true, nil
	}
	// The row moved between the read and the write, so answer with what it is now.
	return d.cancelOutcomeAfterLosingRace(ctx, orderID)
}

// cancelOutcomeAfterLosingRace reports the row's current state when this
// revocation lost, so the caller answers from the stored truth rather than from a
// stale snapshot.
func (d *DB) cancelOutcomeAfterLosingRace(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error) {
	latest, foundLatest, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil || !foundLatest {
		return nil, false, err
	}
	return latest, false, nil
}

// applyRevocation writes the revoked state over the states a revocation may
// change. It reports whether this call was the one that performed the transition.
func (d *DB) applyRevocation(
	ctx context.Context, current *models.GigahostSetupIntent, reason string,
) (bool, error) {
	current.State = models.SetupStateCanceled
	current.RevokedAt = time.Now().UTC()
	current.Step = models.SetupStateCanceled
	current.LastError = strings.TrimSpace(reason)
	current.NextAttemptAt = time.Time{}
	return d.TransitionGigahostSetupIntent(ctx, current, cancelableSetupStates)
}

// ListDueGigahostSetupInstalls returns the intents an install pass may act on:
// rows at the install handoff point, and rows still marked installing because a
// previous attempt never wrote a terminal outcome.
//
// install_paused is deliberately absent. A paused install stopped without a
// proven result, so failing again on its own would replay an unknown remote
// effect; only an explicit administrator resume puts it back in this set.
func (d *DB) ListDueGigahostSetupInstalls(ctx context.Context, now time.Time, limit int) ([]models.GigahostSetupIntent, error) {
	if d == nil || d.sqlDB == nil {
		return []models.GigahostSetupIntent{}, nil
	}
	if limit <= 0 {
		return []models.GigahostSetupIntent{}, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, err
	}
	q := `SELECT ` + setupIntentColumns + `
	      FROM gigahost_setup_intents
	      WHERE state IN (?, ?)
	        AND (next_attempt_at = '' OR next_attempt_at <= ?)
	      ORDER BY next_attempt_at, id
	      LIMIT ?`
	rows, err := d.sqlDB.QueryContext(ctx, q,
		models.SetupStateReadyForSetup, models.SetupStateInstalling,
		formatSetupTimestamp(now), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list due gigahost setup installs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	list := []models.GigahostSetupIntent{}
	for rows.Next() {
		intent, scanErr := scanSetupIntent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		list = append(list, *intent)
	}
	return list, rows.Err()
}

// ClaimGigahostSetupInstall takes exclusive ownership of one install attempt.
//
// The claim is a single statement whose WHERE clause names the handoff state, so
// exactly one caller can win: RowsAffected is the arbiter, not a value this
// process read earlier. The generation is incremented in the same statement, so
// the returned row carries the fencing token the attempt must present for every
// later journal write.
//
// The claim deliberately does NOT clear the phase journal. A row can reach this
// claim carrying history - a trust confirmation over an interrupted install
// returns it here - and the plan needs that history to verify an unknown remote
// effect instead of re-running it. Clearing it here was the second half of the
// replay window: the in-flight phase vanished, every phase looked unfinished, and
// the plan selected the install action again.
func (d *DB) ClaimGigahostSetupInstall(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	q := `UPDATE gigahost_setup_intents
	      SET state = ?,
	          install_generation = install_generation + 1,
	          install_attempts = install_attempts + 1,
	          step = 'install_claimed',
	          last_error = '',
	          next_attempt_at = '',
	          updated_at = ?
	      WHERE order_id = ? AND state = ?`
	d.writeMu.Lock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		models.SetupStateInstalling, now, orderID, models.SetupStateReadyForSetup)
	d.writeMu.Unlock()
	if err != nil {
		return nil, false, fmt.Errorf("failed to claim gigahost setup install: %w", err)
	}
	// RowsAffected is the arbiter: a competing claim that matched no row lost, and
	// must not be told it owns an attempt it never started.
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("failed to confirm gigahost setup claim: %w", err)
	}
	if affected == 0 {
		return nil, false, nil
	}
	return d.rereadSetupIntent(ctx, orderID)
}

// TakeOverGigahostSetupInstall re-owns an install attempt that a previous pass
// left in the installing state, and issues a new fencing token for it.
//
// The expected generation is part of the WHERE clause, so a takeover cannot
// silently capture a row some other writer already advanced. Taking over does
// NOT clear the phase journal: the audit of what was in flight is exactly what
// the next attempt needs in order to verify instead of replay.
func (d *DB) TakeOverGigahostSetupInstall(
	ctx context.Context, orderID string, expectGeneration int64,
) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	q := `UPDATE gigahost_setup_intents
	      SET install_generation = install_generation + 1,
	          install_attempts = install_attempts + 1,
	          step = 'install_taken_over',
	          next_attempt_at = '',
	          updated_at = ?
	      WHERE order_id = ? AND state = ? AND install_generation = ?`
	d.writeMu.Lock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		now, orderID, models.SetupStateInstalling, expectGeneration)
	d.writeMu.Unlock()
	if err != nil {
		return nil, false, fmt.Errorf("failed to take over gigahost setup install: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("failed to confirm gigahost setup takeover: %w", err)
	}
	if affected == 0 {
		return nil, false, nil
	}
	return d.rereadSetupIntent(ctx, orderID)
}

// UpdateGigahostSetupInstall is the only writer of an in-flight install attempt,
// and it is fenced by both the installing state and the attempt's generation.
//
// changed=false means this attempt no longer owns the row - the administrator
// revoked the approval or a newer attempt took over. The caller must then issue
// no further remote command: that refusal is the guarantee that a cancellation
// reaches the install, not just the provider poll.
func (d *DB) UpdateGigahostSetupInstall(
	ctx context.Context, intent *models.GigahostSetupIntent, expectedGeneration int64,
) (bool, error) {
	if d == nil || d.sqlDB == nil {
		return false, nil
	}
	if err := validateInstallUpdate(intent, expectedGeneration); err != nil {
		return false, err
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return false, err
	}
	intent.UpdatedAt = time.Now().UTC()
	q := `UPDATE gigahost_setup_intents
	      SET state = ?,
	          step = ?,
	          last_error = ?,
	          install_phase = ?,
	          install_phase_done = ?,
	          nexus_server_id = CASE WHEN ? > 0 THEN ? ELSE nexus_server_id END,
	          next_attempt_at = ?,
	          updated_at = ?
	      WHERE order_id = ? AND state = ? AND install_generation = ?`
	d.writeMu.Lock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		intent.State, intent.Step, intent.LastError,
		intent.InstallPhase, intent.InstallPhaseDone,
		intent.NexusServerID, intent.NexusServerID,
		formatSetupTimestamp(intent.NextAttemptAt),
		formatSetupTimestamp(intent.UpdatedAt),
		intent.OrderID, models.SetupStateInstalling, expectedGeneration)
	d.writeMu.Unlock()
	if err != nil {
		return false, fmt.Errorf("failed to update gigahost setup install: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to confirm gigahost setup install update: %w", err)
	}
	return affected > 0, nil
}

// installUpdateStates are the states an in-flight attempt may write. A completed
// install, a revocation and a provider terminal failure are not reachable from
// here: each of those has its own writer, so no attempt can fake one.
var installUpdateStates = []string{
	models.SetupStateInstalling,
	models.SetupStateInstallPaused,
	models.SetupStateReady,
}

// validateInstallUpdate rejects a journal update that could not describe a real
// attempt, so a malformed call fails loudly instead of matching nothing.
func validateInstallUpdate(intent *models.GigahostSetupIntent, expectedGeneration int64) error {
	switch {
	case intent == nil || strings.TrimSpace(intent.OrderID) == "":
		return errors.New("gigahost setup install update requires an order id")
	case expectedGeneration <= 0:
		return errors.New("gigahost setup install update requires the attempt generation")
	case strings.TrimSpace(intent.Step) == "":
		return errors.New("gigahost setup install update requires a step")
	}
	for _, s := range installUpdateStates {
		if intent.State == s {
			return nil
		}
	}
	return fmt.Errorf("gigahost setup install cannot write state %q", intent.State)
}

// rereadSetupIntent returns the stored row after a claim or takeover.
func (d *DB) rereadSetupIntent(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error) {
	return d.GetGigahostSetupIntent(ctx, orderID)
}

// ResumeGigahostSetupInstall claims an intent that an operator has explicitly
// resumed: a trust pause, a credential pause, or a paused install attempt.
//
// The expected-state list is the guard. A completed install, a revocation and a
// provider terminal failure are absent, so a resume cannot pass those states, and
// the generation increments in the same statement so any attempt that was already
// running is fenced out by the resume.
func (d *DB) ResumeGigahostSetupInstall(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(resumableSetupStates)), ",")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	q := `UPDATE gigahost_setup_intents
	      SET state = ?,
	          install_generation = install_generation + 1,
	          install_attempts = install_attempts + 1,
	          step = 'install_resumed',
	          last_error = '',
	          next_attempt_at = '',
	          updated_at = ?
	      WHERE order_id = ? AND state IN (` + placeholders + `)` // #nosec G202 -- placeholder count only; all values are bound arguments
	args := []any{models.SetupStateInstalling, now, orderID}
	for _, s := range resumableSetupStates {
		args = append(args, s)
	}
	d.writeMu.Lock()
	res, err := d.sqlDB.ExecContext(ctx, q, args...)
	d.writeMu.Unlock()
	if err != nil {
		return nil, false, fmt.Errorf("failed to resume gigahost setup install: %w", err)
	}
	return d.resumeOutcome(ctx, orderID, res)
}

// resumeOutcome reports what a resume attempt actually achieved.
//
// changed=false means the row was not in a resumable state; the stored row is
// returned so the caller explains the real state instead of claiming a resume.
func (d *DB) resumeOutcome(
	ctx context.Context, orderID string, res sql.Result,
) (*models.GigahostSetupIntent, bool, error) {
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("failed to confirm gigahost setup resume: %w", err)
	}
	current, found, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil || !found {
		return nil, false, err
	}
	return current, affected > 0, nil
}

// resumableSetupStates are the states an explicit administrator resume may act
// on. They are exactly the states that stopped and asked for a decision: a trust
// pause, a credential pause, a paused attempt, and the untouched handoff.
var resumableSetupStates = []string{
	models.SetupStateReadyForSetup,
	models.SetupStateAwaitingHostConfirm,
	models.SetupStateAwaitingCredentials,
	models.SetupStateInstallPaused,
}

// ReArmGigahostSetupDiscovery makes a job whose first-contact discovery could not
// reach the address due for an immediate tracking attempt.
//
// It is a narrow compare-and-set: the row must still be pending and still recorded
// under the discovery step, so it cannot re-arm ordinary provider polling, a trust
// pause, an install attempt or a terminal row. It writes no trust decision and no
// journal, because the row has neither yet - the only thing it changes is the
// schedule, which is what a retry needs.
//
// The step is cleared along with the schedule so the tracker re-evaluates the job
// from the beginning instead of claiming a stale diagnosis. changed=false means the
// row left this state (a revocation, or a pass that already retried it), and the
// caller explains the real state.
func (d *DB) ReArmGigahostSetupDiscovery(ctx context.Context, orderID string) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	q := `UPDATE gigahost_setup_intents
	      SET step = ?,
	          last_error = '',
	          next_attempt_at = '',
	          updated_at = ?
	      WHERE order_id = ? AND state = ? AND step = ?`
	res, err := d.execWrite(ctx, q,
		"discovery_rearmed", formatSetupTimestamp(time.Now().UTC()), orderID,
		models.SetupStatePending, setupStepHostUnreachable)
	if err != nil {
		return nil, false, fmt.Errorf("failed to re-arm gigahost setup discovery: %w", err)
	}
	// Reporting the outcome is the same question a resume asks: did this statement
	// win, and what is stored now. resumeOutcome answers exactly that.
	return d.resumeOutcome(ctx, orderID, res)
}

// setupStepHostUnreachable is the recorded step of a discovery that could not
// obtain an identity. It is duplicated here rather than imported from the tracking
// package because this package owns the durable vocabulary of its own table.
const setupStepHostUnreachable = "host_identity_unreachable"

// hasInstallHistory reports whether any install attempt ever touched this row.
//
// It is the boundary between a pre-install trust pause and a job whose remote
// effects are partly unknown. Either evidence is sufficient: a generation means
// an attempt was claimed, and a journal phase names a step that was in flight.
func hasInstallHistory(intent *models.GigahostSetupIntent) bool {
	if intent == nil {
		return false
	}
	return intent.InstallGeneration > 0 ||
		strings.TrimSpace(intent.InstallPhase) != "" ||
		strings.TrimSpace(intent.InstallPhaseDone) != ""
}

// isConfirmableSetupState reports whether a host confirmation may act on this
// state. Only a job that stopped for identity, or one whose install paused, is
// waiting for that decision; a provider poll, a running attempt, a completed job
// and a revocation are all absent.
func isConfirmableSetupState(state string) bool {
	return state == models.SetupStateAwaitingHostConfirm || state == models.SetupStateInstallPaused
}

// execWrite runs a statement under the database write lock, so every statement
// that mutates this table is serialized with the rest of the ledger's writers.
func (d *DB) execWrite(ctx context.Context, query string, args ...any) (sql.Result, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.sqlDB.ExecContext(ctx, query, args...)
}

// cancelableSetupStates are the states a revocation may change. A completed
// install is deliberately absent: it is finished, and removing an admitted
// backend goes through the existing backend disable path. The install states are
// present because revocation must reach an install that is still in progress,
// not only the provider poll that precedes it.
var cancelableSetupStates = []string{
	models.SetupStatePending,
	models.SetupStateAwaitingHostConfirm,
	models.SetupStateAwaitingCredentials,
	models.SetupStateReadyForSetup,
	models.SetupStateInstalling,
	models.SetupStateInstallPaused,
	models.SetupStateFailed,
}

// isCancelableSetupState reports whether a revocation applies to this state.
func isCancelableSetupState(state string) bool {
	for _, s := range cancelableSetupStates {
		if state == s {
			return true
		}
	}
	return false
}
