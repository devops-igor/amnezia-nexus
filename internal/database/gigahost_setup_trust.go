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
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrFirstContactNotEligible reports a pin refused because the durable row no
// longer carries the authority for it.
var ErrFirstContactNotEligible = errors.New("this setup intent is not eligible for automatic host trust")

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
