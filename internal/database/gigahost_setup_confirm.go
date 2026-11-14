package database

// The administrator's host-identity confirmation for a setup intent.
//
// A confirmation is the manual half of host trust: it records the exact identity the
// panel displayed for one job, and it never decides an installation. It lives in its own
// file because it is one cohesive decision with its own durability rules - the displayed
// candidate is the only acceptable value, install history is never discarded, and an
// identity the panel pinned itself is not replaceable here.
//
// Only this package issues SQL for the table (module ownership rules).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ConfirmGigahostSetupHostFingerprint records the identity the administrator
// confirmed for an order.
//
// Two guarantees are enforced here rather than in the caller, because the HTTP
// endpoint and any future caller must obey the same rules:
//
//  1. The confirmed value must be an identity this job actually displayed: the
//     candidate observed on the panel's own first-contact challenge, or the
//     identity already recorded for this approval. Nothing else is confirmable,
//     so an arbitrary value from a client can never become a trusted host.
//  2. An interrupted install keeps its journal. When the row already carries
//     install history the confirmation issues a new attempt generation in the
//     same statement, so the job goes back to the installing state and the
//     existing verify-not-replay path owns it. A trust decision therefore can
//     neither erase an unknown remote effect nor authorize a second install.
//
// A row with no install history is a genuine pre-install trust pause: it returns
// to pending so the tracker re-reads the provider and reaches the handoff.
//
// changed=false means the row was not in a state this confirmation applies to,
// or the value was not one this job displayed; the returned row is then the stored
// truth, so the caller explains the real state instead of claiming a confirmation
// happened. A nil row means no approval exists for the order.
func (d *DB) ConfirmGigahostSetupHostFingerprint(
	ctx context.Context, orderID, fingerprint string,
) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil, false, errors.New("a confirmed host fingerprint is required")
	}
	current, applies, err := d.confirmableHostIntent(ctx, orderID, fingerprint)
	if err != nil || current == nil {
		return nil, false, err
	}
	if !applies {
		return current, false, nil
	}
	return d.applyHostConfirmation(ctx, orderID, fingerprint, hasInstallHistory(current))
}

// confirmableHostIntent loads the row and decides whether this exact confirmation
// applies to it.
//
// Two independent refusals live here because both are "this confirmation is not
// about this job": the row is not in a state that stopped for identity, or the
// value is not an identity the panel displayed for it. A not-found row returns
// (nil, false, nil) so the caller can answer 404 rather than inventing a refusal.
func (d *DB) confirmableHostIntent(
	ctx context.Context, orderID, fingerprint string,
) (*models.GigahostSetupIntent, bool, error) {
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	current, found, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil || !found {
		return nil, false, err
	}
	if !isConfirmableSetupState(current.State) || !isDisplayedHostIdentity(current, fingerprint) {
		return current, false, nil
	}
	// An identity the panel pinned on its own first contact is not an
	// administrator decision, so an administrator confirmation is not the way to
	// replace it. Replacement is an explicit revocation followed by a fresh
	// approval; refusing here means no ordinary writer can silently rewrite a pin
	// that the install path is already enforcing.
	if current.HostTrustMode == models.SetupTrustModeFirstContact {
		return current, false, nil
	}
	return current, true, nil
}

// isDisplayedHostIdentity reports whether this exact value is an identity the
// panel displayed for this approval: the first-contact candidate, or the identity
// the approval already carries. Nothing else is confirmable.
func isDisplayedHostIdentity(intent *models.GigahostSetupIntent, fingerprint string) bool {
	if intent == nil {
		return false
	}
	if observed := strings.TrimSpace(intent.HostCandidateFingerprint); observed != "" && observed == fingerprint {
		return true
	}
	return strings.TrimSpace(intent.HostFingerprint) == fingerprint
}

// applyHostConfirmation writes the confirmed identity and decides what the job
// continues as, without ever discarding install history.
//
// The journal columns are set explicitly: `withHistory` returns the row to the
// installing state with a fresh generation and the journal kept, so a resumed
// attempt verifies the interrupted phase instead of replaying it. Without
// history the row returns to pending and the tracker re-reads the provider.
func (d *DB) applyHostConfirmation(
	ctx context.Context, orderID, fingerprint string, withHistory bool,
) (*models.GigahostSetupIntent, bool, error) {
	now := time.Now().UTC()
	state := models.SetupStatePending
	step := "host_confirmed"
	if withHistory {
		state = models.SetupStateInstalling
		step = "install_resumed"
	}
	q := `UPDATE gigahost_setup_intents
	      SET host_fingerprint = ?,
	          host_mismatch = 0,
	          host_candidate_fingerprint = '',
	          host_trust_mode = ?,
	          state = ?,
	          step = ?,
	          last_error = '',
	          install_generation = CASE WHEN ? THEN install_generation + 1 ELSE install_generation END,
	          install_attempts = CASE WHEN ? THEN install_attempts + 1 ELSE install_attempts END,
	          next_attempt_at = '',
	          updated_at = ?
	      WHERE order_id = ? AND state IN (?, ?)
	        AND (host_trust_mode != ? OR host_fingerprint = ?)` // #nosec G202 -- "?"-only statement text; every value is bound
	res, err := d.execWrite(ctx, q, fingerprint, models.SetupTrustModeConfirmed, state, step,
		withHistory, withHistory,
		formatSetupTimestamp(now), orderID,
		models.SetupStateAwaitingHostConfirm, models.SetupStateInstallPaused,
		models.SetupTrustModeFirstContact, fingerprint)
	if err != nil {
		return nil, false, fmt.Errorf("failed to confirm gigahost setup host identity: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return nil, false, fmt.Errorf("failed to confirm gigahost setup host identity write: %w", err)
	}
	current, found, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil || !found {
		return nil, false, err
	}
	return current, affected > 0, nil
}
