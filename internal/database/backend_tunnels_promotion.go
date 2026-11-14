package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// promoteAndRelease applies the qualification CAS and removes the durable
// enrollment marker inside tx. It reports whether the CAS landed; a refused CAS
// leaves the marker untouched so the backend stays safely ineligible.
func promoteAndRelease(
	ctx context.Context,
	tx *sql.Tx,
	id int64,
	expectedStatus, expectedReason string,
	expectedVersion int64,
	newStatus, newReason string,
	latencyMS int64,
	serverID int64,
) (bool, error) {
	// F14: admission authority is decided inside the transaction, not before the
	// network work and not after the commit. A revoked setup approval must not be
	// able to promote its backend, and because revocation and this transaction
	// both serialize on the database write mutex, a revocation that committed
	// before this point is visible here.
	revoked, err := setupApprovalRevoked(ctx, tx, serverID)
	if err != nil {
		return false, err
	}
	if revoked {
		return false, ErrSetupApprovalRevoked
	}

	const casQuery = `UPDATE backend_tunnels SET status = ?, disable_reason = ?, latency_ms = ?, last_health_check = ?, state_version = state_version + 1
		WHERE id = ? AND enabled = 1 AND status = ? AND disable_reason = ? AND state_version = ?`
	nowStr := time.Now().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, casQuery, newStatus, newReason, latencyMS, nowStr, id, expectedStatus, expectedReason, expectedVersion)
	if err != nil {
		return false, fmt.Errorf("failed to execute promotion update on backend tunnel %d: %w", id, err)
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to inspect rows affected on promotion update %d: %w", id, err)
	}
	if rowsAffected == 0 {
		return false, nil
	}
	if err := releaseOwnedEnrollment(ctx, tx, serverID, id); err != nil {
		return false, err
	}
	return true, nil
}

// PromoteTunnelAndClearEnrollment commits a qualified backend's runtime health
// and releases its durable enrollment quarantine in ONE transaction.
//
// Finding F10: promotion and quarantine release used to be two independent
// statements. A process exit between them left a genuinely qualified backend
// marked pending with an active status, which startup then reset to
// connecting — permanently unselectable, with no path back. Because the
// quarantine marker IS the durable "not yet qualified" fact, releasing it must
// be part of the same commit as the qualification verdict.
//
// The status predicates mirror CompareAndSwapTunnelStatus exactly; the caller
// passes the expected current status/reason/version it observed.
func (d *DB) PromoteTunnelAndClearEnrollment(
	ctx context.Context,
	id int64,
	expectedStatus, expectedReason string,
	expectedVersion int64,
	newStatus, newReason string,
	latencyMS int64,
	serverID int64,
) (bool, error) {
	if d == nil || d.sqlDB == nil {
		return false, nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin backend promotion transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	swapped, err := promoteAndRelease(ctx, tx, id, expectedStatus, expectedReason, expectedVersion, newStatus, newReason, latencyMS, serverID)
	if err != nil || !swapped {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit backend promotion for server %d: %w", serverID, err)
	}
	return true, nil
}
