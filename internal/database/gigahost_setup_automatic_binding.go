package database

// Recording the provider's final association on the order ledger, from a background
// pass rather than a browser.
//
// A purchase is committed before the provider is asked to sell anything, so the ledger
// row exists with the order id and no address. The address and the provider server id
// arrive later, in the provider's own answer. Until now only an HTTP path that polls
// the orders list ever wrote them, which meant a job whose owner never opened that page
// could never prove the resource it was configuring.
//
// This statement closes that gap without becoming a second provenance writer. The
// purchase stamp is in the predicate, not the SET list: a row can only be updated if it
// is already the panel's own purchase, so a row that appeared some other way can never
// acquire the stamp from here, and no caller can claim provenance by passing it as a
// value.
//
// The identity columns are also first-writer-wins. An existing different server id or
// address is a conflict, not an update: a row that already describes a resource must not
// be silently re-pointed by a later provider answer, because that would let the job's
// authority drift onto a different host while its grant still names the old one.
//
// Only this package issues SQL for the table (module ownership rules).

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrProviderAssociationConflict reports that the ledger row already records a
// different provider identity than the one being recorded.
//
// It is distinct from a plain "did not match" because the two mean opposite things to
// an operator: one says this row is not the panel's purchase (nothing to fix here), the
// other says the resource moved or two answers disagree (something is genuinely wrong
// with this order).
var ErrProviderAssociationConflict = fmt.Errorf("the order ledger already records a different provider identity")

// RecordGigahostSetupProviderAssociation writes the provider's own answer about which
// server and address belong to one already purchased order.
//
// It returns changed=false when the row is not the panel's purchase, or when it already
// records exactly these facts (a repeated pass is not an error). A row whose recorded
// identity disagrees is reported as ErrProviderAssociationConflict rather than being
// overwritten.
//
// The write is deliberately limited to identity. Order status is a progress view that
// other paths maintain, and rewriting it here would make a background association report
// as the authority on provisioning state.
func (d *DB) RecordGigahostSetupProviderAssociation(
	ctx context.Context, orderID string, providerServerID int64, address string,
) (bool, error) {
	orderID = strings.TrimSpace(orderID)
	address = strings.TrimSpace(address)
	if d == nil || d.sqlDB == nil || !isRecordableAssociation(orderID, providerServerID, address) {
		return false, nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return false, err
	}
	res, err := d.writeProviderAssociation(ctx, orderID, providerServerID, address)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to confirm the provider association for order %s: %w", orderID, err)
	}
	if affected > 0 {
		return true, nil
	}
	return d.explainProviderAssociationMiss(ctx, orderID, providerServerID, address)
}

// isRecordableAssociation reports whether the three values describe an association at all.
//
// A partial answer is not a weaker association, it is no association: an order id with no
// server, a server with no address, or a negative id cannot be recorded, and none of them
// is an error worth reporting to a caller that will simply try again next pass.
func isRecordableAssociation(orderID string, providerServerID int64, address string) bool {
	return orderID != "" && providerServerID > 0 && address != ""
}

// writeProviderAssociation applies the guarded update and returns its raw result.
//
// The stamp is required, not written. `(server_id = 0 OR server_id = ?)` and the matching
// address clause make an existing different identity a non-match instead of an overwrite,
// and the final pair makes a row that already carries both facts a non-match too - so a
// repeated pass reports "nothing to do" rather than claiming a change it did not make.
// SQLite counts a matched UPDATE as affected even when the values are identical, so
// relying on RowsAffected alone would report every repeat as a write.
func (d *DB) writeProviderAssociation(
	ctx context.Context, orderID string, providerServerID int64, address string,
) (sql.Result, error) {
	q := `UPDATE gigahost_orders
	         SET server_id = ?, assigned_ip = ?, updated_at = ?
	       WHERE order_id = ?
	         AND purchase_origin = ?
	         AND (server_id = 0 OR server_id = ?)
	         AND (assigned_ip = '' OR assigned_ip = ?)
	         AND (server_id = 0 OR assigned_ip = '')`
	res, err := d.execWrite(ctx, q,
		providerServerID, address, time.Now().UTC().Format(time.RFC3339),
		orderID, models.PurchaseOriginPanelPurchase,
		providerServerID, address)
	if err != nil {
		return nil, fmt.Errorf("failed to record the provider association for order %s: %w", orderID, err)
	}
	return res, nil
}

// explainProviderAssociationMiss says why the association statement matched no row.
//
// "This is not the panel's purchase" and "this order already names a different resource"
// are different answers and only one of them is a fault, so the refusal is explained
// from the stored row rather than left as a silent no-op. A read error here is reported
// as an error: an unreadable row is not evidence of either.
func (d *DB) explainProviderAssociationMiss(
	ctx context.Context, orderID string, providerServerID int64, address string,
) (bool, error) {
	order, found, err := d.GetGigahostOrder(ctx, orderID)
	if err != nil {
		return false, err
	}
	if !found || order == nil {
		return false, nil
	}
	if order.PurchaseOrigin != models.PurchaseOriginPanelPurchase {
		// Not this panel's purchase. Not a fault of the record; simply not ours to
		// describe.
		return false, nil
	}
	return false, associationConflictReason(order, providerServerID, address)
}

// associationConflictReason names the first recorded fact that disagrees with the
// provider's answer, or nil when the row already carries exactly these facts.
func associationConflictReason(
	order *models.GigahostOrder, providerServerID int64, address string,
) error {
	if order.ServerID != 0 && order.ServerID != providerServerID {
		return fmt.Errorf("%w: order %s records server %d, the provider reports %d",
			ErrProviderAssociationConflict, order.OrderID, order.ServerID, providerServerID)
	}
	if recorded := strings.TrimSpace(order.AssignedIP); recorded != "" && recorded != address {
		return fmt.Errorf("%w: order %s records address %s, the provider reports %s",
			ErrProviderAssociationConflict, order.OrderID, recorded, address)
	}
	// The row already carries exactly these facts: a repeated pass, not a conflict.
	return nil
}
