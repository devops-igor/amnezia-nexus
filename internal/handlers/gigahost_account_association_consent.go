package handlers

// The consent a preview issues, on top of the durable authority the database holds.
//
// There is ONE authority per administrator, and it lives in the database rather than
// in this process: issuing a preview replaces the previous row in a single statement,
// so two Settings tabs cannot both hold a confirmable screen. The authority records
// the account that answered, the rows the preview showed as unlisted, the provider
// configuration version that produced it, and an expiry.
//
// Nothing here decides whether a binding may be written. That decision is made by the
// statement that writes the row, which requires this authority to still be current -
// see BindServerProviderAccountUnderAuthority.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

// gigahostAssociationPreviewTTL is how long a preview's consent stays usable. It must
// not outlive a plausible reading of that screen; an expired authority is refused
// rather than re-interpreted.
const gigahostAssociationPreviewTTL = 15 * time.Minute

// gigahostAssociationConfig identifies the effective provider configuration a plan
// was produced from.
//
// epoch is the durable version of the gigahost settings, moved in the same transaction
// as a settings write; generation advances when the provider client is replaced; scope
// is the one-way digest of the credential that answered. All three are required, since
// an injected client and a stored key move different parts of this identity.
type gigahostAssociationConfig struct {
	epoch      int64
	generation uint64
	scope      string
}

// gigahostAssociationConfigOf names the configuration one resolution acts under.
func gigahostAssociationConfigOf(resolution gigahostClientResolution, epoch int64) gigahostAssociationConfig {
	return gigahostAssociationConfig{
		epoch:      epoch,
		generation: resolution.generation,
		scope:      catalogScopeKey(resolution.credential),
	}
}

// gigahostAssociationConsentStatus is how a presented token was answered.
type gigahostAssociationConsentStatus int

const (
	// gigahostAssociationConsentCurrent: this administrator's live authority.
	gigahostAssociationConsentCurrent gigahostAssociationConsentStatus = iota
	// gigahostAssociationConsentSuperseded: an authority a newer preview replaced.
	gigahostAssociationConsentSuperseded
	// gigahostAssociationConsentUnknown: nothing this administrator holds, or an
	// expired authority.
	gigahostAssociationConsentUnknown
)

// issueGigahostAssociationPreview mints the token a confirmation must present, and
// makes it the administrator's only authority.
//
// Every earlier authority for the same administrator is replaced by the same
// statement, whether or not the new plan has anything to write: the screen the
// administrator is looking at now is the only one their next answer can be about.
func (h *Handlers) issueGigahostAssociationPreview(
	ctx context.Context, admin string, plan gigahostAccountPlan, config gigahostAssociationConfig,
) (string, error) {
	if plan.account == "" || len(plan.attributed)+len(plan.unlisted) == 0 {
		// Nothing to write: the new screen withdraws the previous authority and offers
		// no replacement, so an earlier token can no longer be presented.
		if _, err := h.db.ClearGigahostAssociationAuthority(ctx, admin); err != nil {
			return "", err
		}
		return "", nil
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	unlisted := make([]int64, 0, len(plan.unlisted))
	for _, binding := range plan.unlisted {
		unlisted = append(unlisted, binding.serverID)
	}
	authority := database.GigahostAssociationAuthority{
		Admin:            admin,
		Token:            token,
		Account:          plan.account,
		ConfigEpoch:      config.epoch,
		ConfigGeneration: config.generation,
		ConfigScope:      config.scope,
		Unlisted:         unlisted,
		ExpiresAt:        time.Now().Add(gigahostAssociationPreviewTTL),
	}
	if err := h.db.StoreGigahostAssociationAuthority(ctx, authority); err != nil {
		return "", err
	}
	return token, nil
}

// gigahostAssociationConsent answers what a presented token stands for.
//
// Only the administrator's current, unexpired authority is a consent. A token the
// administrator has superseded is REFUSED, and anything else is unknown.
func (h *Handlers) gigahostAssociationConsent(
	ctx context.Context, admin, token string,
) (database.GigahostAssociationAuthority, gigahostAssociationConsentStatus, error) {
	authority, found, err := h.db.LoadGigahostAssociationAuthority(ctx, admin, token, time.Now())
	if err != nil {
		return database.GigahostAssociationAuthority{}, gigahostAssociationConsentUnknown, err
	}
	if found {
		return authority, gigahostAssociationConsentCurrent, nil
	}
	current, held, err := h.db.GigahostAssociationAuthorityToken(ctx, admin)
	if err != nil {
		return database.GigahostAssociationAuthority{}, gigahostAssociationConsentUnknown, err
	}
	if held && current != "" && current != token {
		return database.GigahostAssociationAuthority{}, gigahostAssociationConsentSuperseded, nil
	}
	return database.GigahostAssociationAuthority{}, gigahostAssociationConsentUnknown, nil
}

// gigahostAssociationHoldsAuthority reports whether this authority, as presented, is
// still current under the configuration in force. It explains a refused binding; it
// never authorizes one.
func (h *Handlers) gigahostAssociationHoldsAuthority(
	ctx context.Context, authority database.GigahostAssociationAuthority,
) (bool, error) {
	return h.db.CurrentGigahostAssociationAuthority(ctx, authority, h.catalogCache().currentGeneration(), time.Now())
}

// forgetGigahostAssociationPreview withdraws a consent that can no longer be honored.
func (h *Handlers) forgetGigahostAssociationPreview(ctx context.Context, admin string) error {
	_, err := h.db.ClearGigahostAssociationAuthority(ctx, admin)
	return err
}
