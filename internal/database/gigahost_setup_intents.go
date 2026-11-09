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
	read_failures INTEGER NOT NULL DEFAULT 0,
	attempts INTEGER NOT NULL DEFAULT 0,
	next_attempt_at TEXT NOT NULL DEFAULT '',
	last_checked_at TEXT NOT NULL DEFAULT '',
	approved_by TEXT NOT NULL DEFAULT '',
	revoked_at TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
)`

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
	host_fingerprint, host_mismatch, read_failures, attempts,
	next_attempt_at, last_checked_at, approved_by, revoked_at,
	created_at, updated_at`

// scanSetupIntent scans one row in setupIntentColumns order.
func scanSetupIntent(scanner interface {
	Scan(dest ...any) error
}) (*models.GigahostSetupIntent, error) {
	var i models.GigahostSetupIntent
	var hostMismatch int
	var nextAttempt, lastChecked, revokedAt, createdAt, updatedAt string
	if err := scanner.Scan(
		&i.ID, &i.OrderID, &i.ProviderServerID, &i.AssignedIP,
		&i.Protocol, &i.Port, &i.TLSDomain, &i.EngineProfile, &i.CredentialMode,
		&i.State, &i.ProviderStatus, &i.Step, &i.LastError,
		&i.HostFingerprint, &hostMismatch, &i.ReadFailures, &i.Attempts,
		&nextAttempt, &lastChecked, &i.ApprovedBy, &revokedAt,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}
	i.HostMismatch = hostMismatch != 0
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
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		nil, intent.OrderID, intent.ProviderServerID, intent.AssignedIP,
		intent.Protocol, intent.Port, intent.TLSDomain, intent.EngineProfile, intent.CredentialMode,
		intent.State, intent.ProviderStatus, intent.Step, intent.LastError,
		intent.HostFingerprint, boolToInt(intent.HostMismatch), intent.ReadFailures, intent.Attempts,
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
	          host_fingerprint = CASE WHEN ? != '' THEN ? ELSE host_fingerprint END,
	          host_mismatch = ?,
	          read_failures = ?,
	          attempts = ?,
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
		boolToInt(intent.HostMismatch),
		intent.ReadFailures,
		intent.Attempts,
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

// cancelableSetupStates are the states a revocation may change. A handoff that
// already happened is deliberately absent: it is settled, not revocable.
var cancelableSetupStates = []string{
	models.SetupStatePending,
	models.SetupStateAwaitingHostConfirm,
	models.SetupStateAwaitingCredentials,
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
