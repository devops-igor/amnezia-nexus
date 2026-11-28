package handlers

// Refusal of immediate setup for an order whose life the panel has recorded as over.
//
// Two routes reach the same preamble: POST /deploy and POST /orders/{order_id}/setup.
// Both exist because the administrator may be looking at either surface when they start a
// deployment, so both are one entry, and a guard that lived in one of them would leave the
// other reachable.
//
// The order can end while the dialog is open. A provider inventory refresh records a
// complete, own-account omission on the order ledger, and the dialog the administrator is
// already looking at still submits. Removing the button would not have refused that
// request: the form was rendered before the ending was recorded. So the refusal belongs in
// the preamble, before any provider detail read, before SSH is dialed and before anything
// is registered.
//
// The provider's detail answer is deliberately not consulted. It can still report the order
// ready while the inventory omits it, and that inconsistent pair is exactly the state this
// order-absence record exists to represent; the inventory is the panel's own existence
// observation, so it outranks a stale detail. A deployment the ledger does not hold keeps
// the pre-existing behavior: no row is no observation, and a first-time deployment may
// legitimately have none.

import (
	"context"
	"errors"
	"fmt"
)

// ErrOrderEnded reports that the order a request names has ended, so no setup work may be
// issued for it. It is a refusal, not a failure: the deployment the request described no
// longer exists at the provider, and the panel has recorded that.
var ErrOrderEnded = errors.New("the order has ended; its deployment no longer exists")

// orderEndedCode is the closed-set code the refusal answers with, so a caller can
// distinguish "this order is over" from every other conflict on the route.
const orderEndedCode = "order_ended"

// refuseEndedOrder answers whether this order's life has ended, and returns the refusal to
// report when it has.
//
// The question is asked of the order ledger through the store's IsGigahostOrderRetired,
// which applies models.GigahostOrder.Retired - the one predicate the grid, the history view
// and the saved-jobs list present from. No second copy of the rule exists here, so the
// refusal cannot disagree with the DELETED badge the operator is looking at.
//
// A read failure is returned as an error rather than as consent: the caller is about to do
// remote work, and "could not ask whether this order still exists" must not authorize it.
func (h *Handlers) refuseEndedOrder(ctx context.Context, orderID string) error {
	if h == nil || h.db == nil {
		return nil
	}
	retired, err := h.db.IsGigahostOrderRetired(ctx, orderID)
	if err != nil {
		return fmt.Errorf("failed to read whether order %s has ended: %w", orderID, err)
	}
	if !retired {
		return nil
	}
	return fmt.Errorf("%w: order %s", ErrOrderEnded, orderID)
}
