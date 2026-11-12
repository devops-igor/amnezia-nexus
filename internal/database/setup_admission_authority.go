package database

// Admission authority for backend promotion.
//
// A durable setup approval can be revoked while its enablement is in flight. The
// revocation commits to the intent row; the enablement is a multi-second network
// operation that ends in PromoteTunnelAndClearEnrollment. A point-in-time check
// before that operation cannot cover the window, and a fenced journal write after
// it is too late - a refused write does not undo an admission.
//
// The one place that can decide both facts at once is the promotion transaction
// itself: CancelGigahostSetupIntent writes under DB.writeMu and promotion runs its
// transaction under the same mutex, so a guard evaluated inside that transaction is
// serialized against revocation. This file supplies that guard.
//
// The contract is deliberately narrow: it answers "is the setup approval that owns
// this backend revoked?". It is not a general admission policy, and a backend with
// no live setup approval - every backend outside the saved-setup workflow - is
// unaffected.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrSetupApprovalRevoked reports that the setup approval which owns a backend was
// revoked before the backend could be admitted. It is a refusal, not a failure:
// the enrollment stays quarantined and the caller reports the real cause.
var ErrSetupApprovalRevoked = errors.New("setup approval was revoked before backend admission")

// setupApprovalRevoked reports whether a revoked setup approval owns serverID.
//
// The read runs through the caller's transaction, so the answer is the same
// snapshot the promotion commits against. Only a live approval can own a backend:
// the query deliberately excludes the canceled state, so a revoked approval that
// owns the backend is not returned and the promotion is refused. A backend whose
// approval was never revoked (or that has no approval at all) returns false.
func setupApprovalRevoked(ctx context.Context, tx *sql.Tx, serverID int64) (bool, error) {
	if tx == nil || serverID <= 0 {
		return false, nil
	}
	// One row can own a backend: nexus_server_id is set by the journal, and the
	// approval never moves to a different server, so "any row" is "the row".
	var state string
	err := tx.QueryRowContext(ctx,
		`SELECT state FROM gigahost_setup_intents
		  WHERE nexus_server_id = ? ORDER BY id DESC LIMIT 1`, serverID).Scan(&state)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to resolve the setup approval for server %d: %w", serverID, err)
	}
	return state == "canceled", nil
}
