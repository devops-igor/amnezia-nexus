package database

// Persistence for automatic first-contact host trust on a setup intent.
//
// The setup intent is the only durable place a host identity can be recorded
// before a server row exists: known_hosts is keyed by server id and constrained by
// a foreign key, so it cannot hold a pre-registration pin. The intent's
// host_fingerprint is also exactly what the install path already consumes as its
// expected identity, which is why pinning here is enforcement rather than a second
// record.
//
// Two properties make this safe to call from a background pass:
//
//  1. The pin is one statement whose WHERE clause carries the whole authority: the
//     row must still be pending, must still carry the automation policy, must
//     still have no identity, and must not have been revoked. Nothing is decided
//     from a value read earlier, so a concurrent cancellation, a policy
//     withdrawal or a competing pin makes this statement match no row.
//  2. The result is reported as an outcome, not a boolean. "A different identity
//     is already pinned" and "this row is no longer pinnable" are different
//     answers, and a caller that could not distinguish them would either retry
//     forever or trust a host on a refusal.
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

// ErrFirstContactNotEligible reports a pin refused because the durable row no
// longer carries the authority for it.
var ErrFirstContactNotEligible = errors.New("this setup intent is not eligible for automatic host trust")

// PinGigahostSetupFirstContact records the host identity the panel observed on its
// own first-contact challenge, under the automation policy the row already
// carries.
//
// The caller must have established eligibility already (policy, real order, managed
// credential, positive provider association, no competing registered server). This
// statement re-proves the durable half of that decision, because the caller's
// answer came from a read that may be stale by the time it is committed.
//
// It never overwrites an existing identity, and it never records anything when the
// row has left the state that authorizes it. A row whose identity was already
// confirmed or pinned by a person is reported as changed/not-eligible, never
// silently replaced.
func (d *DB) PinGigahostSetupFirstContact(
	ctx context.Context, orderID, fingerprint string,
) (string, error) {
	if d == nil || d.sqlDB == nil {
		return models.FirstContactNotEligible, nil
	}
	orderID = strings.TrimSpace(orderID)
	fingerprint = strings.TrimSpace(fingerprint)
	if orderID == "" {
		return "", errors.New("a setup intent order id is required")
	}
	if err := models.ValidateHostFingerprint(fingerprint); err != nil {
		return "", err
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return "", err
	}

	q := `UPDATE gigahost_setup_intents
	      SET host_fingerprint = ?,
	          host_trust_mode = ?,
	          host_candidate_fingerprint = '',
	          updated_at = ?
	      WHERE order_id = ?
	        AND state = ?
	        AND host_trust_policy = ?
	        AND host_fingerprint = ''`
	res, err := d.execWrite(ctx, q,
		fingerprint, models.SetupTrustModeFirstContact,
		formatSetupTimestamp(time.Now().UTC()),
		orderID, models.SetupStatePending, models.SetupTrustPolicyFirstContact)
	if err != nil {
		return "", fmt.Errorf("failed to pin the first-contact host identity: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("failed to confirm the first-contact host pin: %w", err)
	}
	if affected > 0 {
		return models.FirstContactPinned, nil
	}
	return d.firstContactPinOutcome(ctx, orderID, fingerprint)
}

// firstContactPinOutcome explains a pin that matched no row by reading what is
// actually stored now.
//
// A read error here is reported as an error, never as "not eligible": an
// unreadable row is not evidence that the pin was refused.
func (d *DB) firstContactPinOutcome(
	ctx context.Context, orderID, fingerprint string,
) (string, error) {
	current, found, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil {
		return "", err
	}
	if !found || current == nil {
		return models.FirstContactNotEligible, nil
	}
	switch {
	case strings.TrimSpace(current.HostFingerprint) == fingerprint:
		// The identity this call wanted is the one stored. Whether this call or
		// an earlier one wrote it, the answer to "is this host trusted" is yes.
		return models.FirstContactAlreadyPinnedSame, nil
	case strings.TrimSpace(current.HostFingerprint) != "":
		return models.FirstContactIdentityChanged, nil
	default:
		return models.FirstContactNotEligible, nil
	}
}

// SetGigahostSetupHostTrustPolicy records the authority a setup intent carries for
// its host identity, and is the only writer of it.
//
// It exists for the internal caller that owns the automation decision: a
// controller that has already decided this order is its own managed resource
// records the policy here, before any tracking pass runs. It is deliberately not
// reachable from an HTTP payload, so approving, resuming or confirming a job can
// never grant a job more authority than it already has.
//
// The write only applies to a row that is still pending and still carries no
// identity. A row that already has a trusted host, or one that has been revoked or
// handed off, is reported as changed=false: authority is granted before trust is
// decided, never after.
func (d *DB) SetGigahostSetupHostTrustPolicy(
	ctx context.Context, orderID, policy string,
) (*models.GigahostSetupIntent, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := validateHostTrustPolicy(policy); err != nil {
		return nil, false, err
	}
	if err := d.EnsureGigahostSetupIntentsSchema(ctx); err != nil {
		return nil, false, err
	}
	changed, err := d.writeHostTrustPolicy(ctx, orderID, policy)
	if err != nil {
		return nil, false, err
	}
	current, found, err := d.GetGigahostSetupIntent(ctx, orderID)
	if err != nil || !found {
		return nil, false, err
	}
	return current, changed, nil
}

// writeHostTrustPolicy performs the one statement that grants or withdraws authority.
//
// The WHERE clause carries the whole eligibility rule: the row must still be pending, must
// still have no identity, and must not already carry the requested policy. That is what
// makes a repeat request a no-op and a request after trust was decided a refusal.
func (d *DB) writeHostTrustPolicy(ctx context.Context, orderID, policy string) (bool, error) {
	q := `UPDATE gigahost_setup_intents
	      SET host_trust_policy = ?,
	          updated_at = ?
	      WHERE order_id = ?
	        AND state = ?
	        AND host_fingerprint = ''
	        AND host_trust_policy != ?`
	res, err := d.execWrite(ctx, q,
		policy, formatSetupTimestamp(time.Now().UTC()), orderID,
		models.SetupStatePending, policy)
	if err != nil {
		return false, fmt.Errorf("failed to record the setup host trust policy: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to confirm the setup host trust policy write: %w", err)
	}
	return affected > 0, nil
}

// validateHostTrustPolicy accepts only the policies this panel understands. An
// unknown value is refused rather than stored: it would be durable state nothing
// enforces, which reads as authority in the database and is not.
func validateHostTrustPolicy(policy string) error {
	switch policy {
	case models.SetupTrustPolicyManual, models.SetupTrustPolicyFirstContact:
		return nil
	default:
		return fmt.Errorf("unsupported setup host trust policy %q", policy)
	}
}
