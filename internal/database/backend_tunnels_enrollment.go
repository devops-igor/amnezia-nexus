package database

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

const pendingEnrollmentKeyPrefix = "backend_pending_enrollment:"

// boundEnrollmentPrefix marks a durable quarantine that belongs to one backend
// tunnel row ("tunnel:<id>"). The legacy value '1' is an unbound mark with no
// recorded owner. The prefix keeps a bound value distinct from the legacy mark.
const boundEnrollmentPrefix = "tunnel:"

func pendingEnrollmentKey(serverID int64) string {
	return fmt.Sprintf("%s%d", pendingEnrollmentKeyPrefix, serverID)
}

func boundEnrollmentValue(tunnelID int64) string {
	return boundEnrollmentPrefix + strconv.FormatInt(tunnelID, 10)
}

// recordBoundEnrollment records, inside tx, that serverID is quarantined on behalf
// of the backend tunnel row tunnelID. It replaces any earlier mark for the server:
// after this commit the enrolled row is the only generation it can belong to.
func recordBoundEnrollment(ctx context.Context, tx *sql.Tx, serverID, tunnelID int64) error {
	const query = `INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	if _, err := tx.ExecContext(ctx, query, pendingEnrollmentKey(serverID), boundEnrollmentValue(tunnelID)); err != nil {
		return fmt.Errorf("failed to record pending enrollment for server %d: %w", serverID, err)
	}
	return nil
}

// CreateBackendTunnelWithEnrollment inserts a backend tunnel row and its durable
// enrollment quarantine in ONE transaction.
//
// A deploy-created backend is unqualified, and the quarantine is what keeps it out
// of selection. Committing the row first and the quarantine second left a window
// in which a failure (or a process exit) persisted an enabled row with no
// quarantine, which the next startup loaded and a handshake-only probe admitted.
// Either both facts commit or neither does, so there is nothing to compensate.
func (d *DB) CreateBackendTunnelWithEnrollment(ctx context.Context, t *models.BackendTunnel) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	args, err := d.prepareBackendTunnelInsert(t)
	if err != nil {
		return 0, err
	}
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin backend enrollment transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	res, err := tx.ExecContext(ctx, insertBackendTunnelSQL, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to insert backend tunnel: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := recordBoundEnrollment(ctx, tx, t.ServerID, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit backend enrollment for server %d: %w", t.ServerID, err)
	}
	t.ID = id
	return id, nil
}

// releaseOwnedEnrollment deletes, inside tx, serverID's enrollment mark when it is
// unbound or bound to tunnelID. A mark bound to any other row belongs to a
// different generation (a replacement) and is left in place.
func releaseOwnedEnrollment(ctx context.Context, tx *sql.Tx, serverID, tunnelID int64) error {
	if _, err := tx.ExecContext(ctx, releaseOwnedEnrollmentSQL,
		pendingEnrollmentKey(serverID), boundEnrollmentPrefix+"%", boundEnrollmentValue(tunnelID)); err != nil {
		return fmt.Errorf("failed to release pending enrollment for server %d: %w", serverID, err)
	}
	return nil
}

const releaseOwnedEnrollmentSQL = `DELETE FROM settings
	WHERE key = ? AND (value IS NULL OR value NOT LIKE ? OR value = ?)`

// SetBackendPendingEnrollment records or clears an UNBOUND (server-keyed) durable
// enrollment mark.
//
// A mark bound to a tunnel row is written with that row by a deploy add or
// re-enrollment, and only that row's qualification or removal releases it. A
// server-keyed caller cannot tell which generation it is acting for, so recording
// never downgrades a bound mark and clearing never deletes one: a late release for
// a retired backend cannot unquarantine the replacement that now owns the server.
func (d *DB) SetBackendPendingEnrollment(ctx context.Context, serverID int64, pending bool) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	key := pendingEnrollmentKey(serverID)
	args := []any{key, boundEnrollmentPrefix + "%", boundEnrollmentPrefix, pendingEnrollmentKeyPrefix}
	if pending {
		const query = `INSERT INTO settings (key, value) VALUES (?, '1')
			ON CONFLICT(key) DO UPDATE SET value = '1'
			WHERE (settings.value IS NULL OR settings.value NOT LIKE ? OR NOT EXISTS (
				SELECT 1 FROM backend_tunnels b
				WHERE ? || b.id = settings.value AND ? || b.server_id = settings.key))`
		if _, err := d.sqlDB.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("failed to record pending enrollment for server %d: %w", serverID, err)
		}
		return nil
	}
	// Only unbound marks and marks whose owning row no longer exists may be
	// cleared by a server-keyed caller, matching the upsert guard above.
	const query = `DELETE FROM settings WHERE key = ?
		AND (settings.value IS NULL OR settings.value NOT LIKE ? OR NOT EXISTS (
			SELECT 1 FROM backend_tunnels b
			WHERE ? || b.id = settings.value AND ? || b.server_id = settings.key))`
	if _, err := d.sqlDB.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to delete pending enrollment for server %d: %w", serverID, err)
	}
	return nil
}

// effectiveEnrollmentsSQL selects the marks that quarantine something: unbound
// marks, and bound marks whose row still exists for that server. A bound mark left
// behind by a row-only delete belongs to a generation that no longer exists, so
// it must not quarantine (or be inherited by) the server's next backend.
const effectiveEnrollmentsSQL = `SELECT s.key, s.value FROM settings s
	WHERE s.key LIKE ? AND (s.value IS NULL OR s.value NOT LIKE ? OR EXISTS (
		SELECT 1 FROM backend_tunnels b
		WHERE ? || b.id = s.value AND ? || b.server_id = s.key))`

// GetBackendPendingEnrollmentOwners returns every effective durable enrollment
// quarantine with the backend tunnel row that owns it. Owner 0 is an unbound mark
// (the legacy value, or a server-keyed caller mark).
func (d *DB) GetBackendPendingEnrollmentOwners(ctx context.Context) (map[int64]int64, error) {
	owners := make(map[int64]int64)
	if d == nil || d.sqlDB == nil {
		return owners, nil
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.sqlDB.QueryContext(ctx, effectiveEnrollmentsSQL,
		pendingEnrollmentKeyPrefix+"%", boundEnrollmentPrefix+"%", boundEnrollmentPrefix, pendingEnrollmentKeyPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending enrollment owners: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var value sql.NullString
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		sid, err := strconv.ParseInt(strings.TrimPrefix(key, pendingEnrollmentKeyPrefix), 10, 64)
		if err != nil {
			continue
		}
		owners[sid] = parseEnrollmentOwner(value.String)
	}
	return owners, rows.Err()
}

// parseEnrollmentOwner returns the row a mark value is bound to, or 0 for an
// unbound or unparseable mark (which still quarantines: unknown is not released).
func parseEnrollmentOwner(value string) int64 {
	if !strings.HasPrefix(value, boundEnrollmentPrefix) {
		return 0
	}
	owner, err := strconv.ParseInt(strings.TrimPrefix(value, boundEnrollmentPrefix), 10, 64)
	if err != nil || owner < 0 {
		return 0
	}
	return owner
}

// GetBackendPendingEnrollments retrieves all server IDs currently under an
// effective durable enrollment quarantine.
func (d *DB) GetBackendPendingEnrollments(ctx context.Context) (map[int64]bool, error) {
	owners, err := d.GetBackendPendingEnrollmentOwners(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending enrollments: %w", err)
	}
	pending := make(map[int64]bool, len(owners))
	for sid := range owners {
		pending[sid] = true
	}
	return pending, nil
}

// ResetBackendTunnelForEnrollment atomically refreshes identity and invalidates
// runtime health, including for disabled rows. It preserves administrative intent.
// The version predicate fences concurrent health/admin writers; a mismatch or
// missing row is not a successful enrollment. Generic updates must not gain access
// to health fields.
//
// A re-enrolled identity is unqualified, so its durable enrollment quarantine,
// bound to this row, commits in the same transaction: either the new identity is
// persisted quarantined or nothing changes.
func (d *DB) ResetBackendTunnelForEnrollment(ctx context.Context, id, expectedVersion int64, updates map[string]any) (bool, error) {
	clauses := []string{"status = ?", "disable_reason = ?", "latency_ms = 0", "last_health_check = NULL", "state_version = state_version + 1"}
	values := []any{models.TunnelStatusConnecting, models.DisableReasonNone}
	for col, raw := range updates {
		switch col {
		case "endpoint", "public_key", "private_key", "probe_private_key", "protocol", "protocol_params":
		default:
			return false, fmt.Errorf("invalid enrollment identity column: %s", col)
		}
		value, err := d.prepareBackendTunnelUpdateValue(col, raw)
		if err != nil {
			return false, err
		}
		clauses = append(clauses, col+" = ?")
		values = append(values, value)
	}
	values = append(values, id, expectedVersion)
	// #nosec G201 -- Column names are restricted to the identity allowlist above.
	query := fmt.Sprintf("UPDATE backend_tunnels SET %s WHERE id = ? AND state_version = ?", strings.Join(clauses, ", "))
	return d.commitEnrollmentReset(ctx, id, query, values)
}

// commitEnrollmentReset applies the version-fenced reset and binds the row's
// durable enrollment quarantine in one transaction. A refused CAS (stale version
// or missing row) commits nothing and reports false.
func (d *DB) commitEnrollmentReset(ctx context.Context, id int64, query string, values []any) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin backend enrollment reset: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	result, err := tx.ExecContext(ctx, query, values...)
	if err != nil {
		return false, fmt.Errorf("failed to reset backend tunnel enrollment: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to inspect backend tunnel enrollment: %w", err)
	}
	if rows != 1 {
		return false, nil
	}
	var serverID int64
	if err := tx.QueryRowContext(ctx, "SELECT server_id FROM backend_tunnels WHERE id = ?", id).Scan(&serverID); err != nil {
		return false, fmt.Errorf("failed to read re-enrolled backend tunnel %d: %w", id, err)
	}
	if err := recordBoundEnrollment(ctx, tx, serverID, id); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit backend enrollment reset %d: %w", id, err)
	}
	return true, nil
}
