package database

// Ending a saved setup job because the order it installs for has ended.
//
// An order's life can end while an administrator-approved setup job for it is still work
// in progress: a complete provider inventory read stops listing the deployment, or the
// provider reports the order canceled or failed before any panel work began. That fact is
// written on the ORDER ledger, so it reaches nothing that holds the approval.
//
// Retirement therefore cannot be only an admission check. An attempt that is already
// running holds a generation token and keeps writing its journal, and every journal write
// is the authorization for the next effect - so a deployment the panel presents as DELETED
// could still register a server, install a protocol and reach backend enablement.
//
// The surrender below is the mechanism the panel already uses for canceling in-flight
// work, pointed at a second reason. The row leaves the states work may continue from, so
// the attempt's next fenced journal write is refused and the runner stops; nothing
// downstream needs a new signal, because "no longer owns the row" is already handled
// everywhere. The phase journal is deliberately left untouched, so what the attempt had
// proven before the order ended stays recorded.
//
// It runs in two places, and the one that decides is the second:
//
//   - SurrenderGigahostSetupForEndedOrder is the prompt settlement, called by a worker that
//     has just found the order ended. It keeps a job that never started from being
//     examined on every later pass.
//   - UpdateGigahostSetupInstall is the single writer of an in-flight attempt, and it asks
//     the same question inside the database write mutex, immediately before its own update.
//     A retirement that committed at any point before that write is therefore visible to
//     it, so no worker has to remember to call anything for the stop to happen.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// SetupStepOrderEnded is the recorded step of a saved setup job the panel closed because
// the order it belongs to ended. It is the durable evidence that the panel gave up on the
// work, rather than a pause an operator is expected to resume.
//
// It is this package's own vocabulary: the step is written onto this table by the statement
// below, so the constant lives beside it rather than being imported from a consumer.
const SetupStepOrderEnded = "order_ended"

// setupEndedReason is the diagnosis recorded with a surrendered job. It states only what
// the panel actually knows - the order ended - and never guesses which ending it was: the
// ledger distinguishes a provider absence from a cancellation, and inventing one of them
// here would be a second, weaker authority.
const setupEndedReason = "the order ended, so this setup job was closed without further work"

// SurrenderGigahostSetupForEndedOrder closes a saved setup job whose order the panel has
// recorded as over, and reports whether the order has ended.
//
// It is the same durable transition a revocation performs - the row leaves every state work
// may continue from - and it is deliberately not a second implementation of it: the
// expected-state list is the revocation's own, so a completed job (`ready`) is preserved and
// a repeated call is idempotent. It differs in the reason it records and in the step, so an
// operator reading the row sees that the panel closed the work because the order ended.
//
// A completed install is not rolled back. Removing an admitted backend goes through the
// existing backend disable path, exactly as it does after a revocation.
func (d *DB) SurrenderGigahostSetupForEndedOrder(ctx context.Context, orderID string) (bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return false, nil
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return false, err
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return false, err
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.surrenderSetupForEndedOrderLocked(ctx, orderID, 0)
}

// surrenderSetupForEndedOrderLocked closes the approval for an order that has ended and
// reports whether it has. The caller holds the database write mutex.
//
// expectGeneration > 0 fences the surrender to one install attempt: a generation that no
// longer owns the row is answered with "not ended for this caller", and the newer owner
// reaches its own decision on its own next write. 0 is the unfenced form the prompt
// settlement uses.
//
// A read failure is returned rather than reported as "not ended": the caller is about to
// issue effect-bearing work for this order, and "could not ask" must not authorize it.
func (d *DB) surrenderSetupForEndedOrderLocked(
	ctx context.Context, orderID string, expectGeneration int64,
) (bool, error) {
	ended, err := d.gigahostOrderEndedLocked(ctx, orderID)
	if err != nil || !ended {
		return false, err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cancelableSetupStates)), ",")
	// #nosec G202 -- the only interpolated text is a run of bind markers counted from a
	// package-level list; every value, including the states, is a bound argument.
	q := `UPDATE gigahost_setup_intents
	      SET state = ?,
	          step = ?,
	          last_error = ?,
	          next_attempt_at = '',
	          updated_at = ?
	      WHERE order_id = ?
	        AND state IN (` + placeholders + `)
	        AND (? = 0 OR install_generation = ?)`
	args := []any{
		models.SetupStateCanceled, SetupStepOrderEnded, setupEndedReason,
		time.Now().UTC().Format(time.RFC3339Nano),
		orderID,
	}
	for _, s := range cancelableSetupStates {
		args = append(args, s)
	}
	args = append(args, expectGeneration, expectGeneration)

	res, err := d.sqlDB.ExecContext(ctx, q, args...)
	if err != nil {
		return true, fmt.Errorf("failed to close the setup job for ended order %q: %w", orderID, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return true, fmt.Errorf("failed to confirm closing the setup job for ended order %q: %w", orderID, err)
	}
	if affected > 0 {
		slog.Info("Gigahost setup job closed: the order has ended",
			"order_id", orderID, "generation", expectGeneration, "step", SetupStepOrderEnded)
	}
	return true, nil
}

// gigahostOrderEndedLocked reports whether the panel's own records say this order's life
// has ended. The caller holds the database write mutex.
//
// It reads the canonical ledger row and applies models.GigahostOrder.Retired - the one
// predicate every other consumer of an order's life uses - so the decision here cannot
// drift from the decision the grid, the history view and the saved-jobs list present. It
// does not call the locking readers: taking the mutex twice deadlocks, and this read has to
// happen inside the same critical section as the write it guards.
//
// A missing row answers "not ended". The ledger has no observation about an order it does
// not hold, and a deployment the panel never recorded must keep the pre-existing behavior.
// A database that has never created the ledger table answers the same way and for the same
// reason - it holds no order at all - which is the reading this package's own list read
// already applies to that table. Every other failure is returned.
func (d *DB) gigahostOrderEndedLocked(ctx context.Context, orderID string) (bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return false, nil
	}
	row := d.sqlDB.QueryRowContext(ctx,
		`SELECT `+gigahostOrderSelectColumns+`
		   FROM gigahost_orders WHERE order_id = ? ORDER BY id DESC LIMIT 1`, orderID)
	order, err := scanGigahostOrder(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || containsFold(err.Error(), "no such table") {
			return false, nil
		}
		return false, fmt.Errorf("failed to read whether order %q has ended: %w", orderID, err)
	}
	return order.Retired(), nil
}
