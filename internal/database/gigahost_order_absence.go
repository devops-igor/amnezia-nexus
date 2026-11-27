package database

// The order-level existence record.
//
// The panel records provider absence on the server row a deployment registered
// (servers.provider_absent_at). That column can only exist for an order that
// registered a panel server, so an order the provider no longer lists and that
// never became a server had nowhere to record its absence - and kept being
// refreshed and offered for setup forever. These two writers keep the same fact
// on the ledger row itself.
//
// Both are addressed by the provider order id, which is the ledger's identity for
// an order, and both refuse an update that matched no row: an observation about an
// order the ledger does not hold is a caller defect, not a silent no-op.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SetGigahostOrderProviderAccount records the provider account an order was
// observed under.
//
// The association is what makes absence decidable: one account's inventory answer
// says nothing about another account's orders, so an order whose account is
// unknown is never judged. It is written only from a provider answer that named
// this order or the server it registered, never inferred from whichever
// credential happens to be configured.
func (d *DB) SetGigahostOrderProviderAccount(ctx context.Context, orderID, accountID string) error {
	orderID = strings.TrimSpace(orderID)
	accountID = strings.TrimSpace(accountID)
	if d == nil || d.sqlDB == nil || orderID == "" || accountID == "" {
		return nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return err
	}
	q := `UPDATE gigahost_orders
	      SET provider_account_id = ?, updated_at = ?
	      WHERE order_id = ? AND provider_account_id != ?`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q, accountID, time.Now().UTC().Format(time.RFC3339), orderID, accountID)
	if err != nil {
		return fmt.Errorf("failed to record the provider account of order %q: %w", orderID, err)
	}
	if _, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to confirm the provider account write for order %q: %w", orderID, err)
	}
	return nil
}

// SetGigahostOrderAbsence records one order's existence observation: absentAt is
// the instant the successful listing that omitted the order was requested, and a
// zero time clears the observation.
//
// Clearing is written together with the observation, so a row can never carry an
// absence stamp that belongs to a different account than the one currently
// recorded.
func (d *DB) SetGigahostOrderAbsence(ctx context.Context, orderID string, absentAt time.Time, accountID string) error {
	orderID = strings.TrimSpace(orderID)
	if d == nil || d.sqlDB == nil || orderID == "" {
		return nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return err
	}
	stamp := ""
	if !absentAt.IsZero() {
		stamp = absentAt.UTC().Format(time.RFC3339)
	}
	if stamp == "" {
		accountID = ""
	}
	q := `UPDATE gigahost_orders
	      SET provider_absent_at = ?, provider_absent_account_id = ?, updated_at = ?
	      WHERE order_id = ?
	        AND (provider_absent_at != ? OR provider_absent_account_id != ?)`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		stamp, strings.TrimSpace(accountID), time.Now().UTC().Format(time.RFC3339),
		orderID, stamp, strings.TrimSpace(accountID),
	)
	if err != nil {
		return fmt.Errorf("failed to record the existence state of order %q: %w", orderID, err)
	}
	if _, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to confirm the existence state write for order %q: %w", orderID, err)
	}
	return nil
}
