package database

// Admission authority for the order a backend is being admitted for.
//
// setup_admission_authority.go answers "was the setup approval revoked?". That question is
// asked at the right place - inside the promotion transaction - but it is not the only
// durable fact that can withdraw permission to admit a backend. An order's life can also end
// while its backend is being qualified: a complete provider inventory omission retires the
// order, and the approval's own row is closed by the surrender writer. When the surrender has
// already committed, the revoked-approval guard catches it. When it has not - the qualification
// returns first, or no saved job owns the backend at all because this is an immediate setup -
// the promotion still had authority it no longer holds.
//
// The order question therefore belongs in that same transaction, for the same reason: the
// retirement is committed on the ORDER ledger, promotion runs under the database write mutex,
// and every retirement writer takes that mutex too, so a guard evaluated inside the promotion
// transaction is serialized against retirement rather than racing it.
//
// The contract stays as narrow as its sibling: only a backend that the panel's own records
// attribute to a gigahost order is judged. Every backend outside the gigahost onboarding
// workflow - and every server whose order the panel never recorded - is unaffected, which is
// what keeps the ordinary backend lifecycle, provisioning and revival paths untouched.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrOrderEndedBeforeAdmission reports that the order a backend is being admitted for has
// ended, so the backend may not be promoted into the pool.
var ErrOrderEndedBeforeAdmission = fmt.Errorf("%w: backend admission refused", ErrOrderEnded)

// attributeOrderAdmission answers which gigahost order, if any, owns this backend - and
// whether that order has ended. The caller owns the transaction.
//
// Attribution runs in both directions and both are needed. A saved setup job records the order
// on its own row beside the server it registered, which covers a job whose intent is still live.
// The order ledger's nexus_server_id covers the rest: an immediate setup that never had a setup
// row, and a job that promotion reached after its approval was already closed. Neither is
// inferred from an address or a provider id - the panel's own two records are the provenance.
//
// owned is false for a backend neither record claims, and the caller must then leave it alone:
// this is an onboarding fence, not a general backend policy.
func attributeOrderAdmission(ctx context.Context, tx *sql.Tx, serverID int64) (orderID string, owned, ended bool, err error) {
	if tx == nil || serverID <= 0 {
		return "", false, false, nil
	}
	intentOrderID, found, err := orderForServerIntent(ctx, tx, serverID)
	if err != nil {
		return "", false, false, err
	}
	if !found {
		intentOrderID, found, err = orderForRegisteredServer(ctx, tx, serverID)
		if err != nil || !found {
			return "", false, false, err
		}
	}
	ended, err = gigahostOrderEndedFrom(ctx, tx, intentOrderID)
	if err != nil {
		return "", false, false, err
	}
	return intentOrderID, true, ended, nil
}

// orderAdmissionRefused answers whether the order that owns this backend has ended, so the
// promotion must be refused. The caller owns the transaction and has already established that
// the setup approval, if any, is live.
//
// A backend no panel record attributes to an order is answered "not ended", which is the
// narrow contract this file documents: the ordinary backend paths are not judged here.
func orderAdmissionRefused(ctx context.Context, tx *sql.Tx, serverID int64) (bool, error) {
	_, _, ended, err := attributeOrderAdmission(ctx, tx, serverID)
	if err != nil {
		return false, err
	}
	return ended, nil
}

// orderForServerIntent returns the order of the setup job that registered this server.
//
// One row can own a backend: nexus_server_id is written by the journal, and an approval never
// moves to a different server, so "any row" is "the row". The query deliberately does not
// filter on state - a canceled row is exactly the fact that must survive to be read here.
func orderForServerIntent(ctx context.Context, tx *sql.Tx, serverID int64) (string, bool, error) {
	var orderID string
	err := tx.QueryRowContext(ctx,
		`SELECT order_id FROM gigahost_setup_intents
		  WHERE nexus_server_id = ? ORDER BY id DESC LIMIT 1`, serverID).Scan(&orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to resolve the setup order for server %d: %w", serverID, err)
	}
	return orderID, true, nil
}

// orderForRegisteredServer returns the order the ledger records for this server.
//
// A ledger that has never been created holds no order, which is the same "no observation"
// answer every other reader of that table in this package applies. That state is an
// un-migrated deployment, not a statement about this backend, so it leaves the promotion
// untouched rather than refusing work for an order nobody could name.
func orderForRegisteredServer(ctx context.Context, tx *sql.Tx, serverID int64) (string, bool, error) {
	var orderID string
	err := tx.QueryRowContext(ctx,
		`SELECT order_id FROM gigahost_orders
		  WHERE nexus_server_id = ? ORDER BY id DESC LIMIT 1`, serverID).Scan(&orderID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || containsFold(err.Error(), "no such table") {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to resolve the order registered for server %d: %w", serverID, err)
	}
	return orderID, true, nil
}
