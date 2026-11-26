package handlers

// The consent a preview issues, and the record a confirmation is checked against.
//
// The counts a preview shows belong to one account and one set of unlisted rows, so
// the confirmation the administrator gives is bound to exactly those. The record is
// per-process: a restart makes every outstanding consent stale, which is the safe
// direction, and an expired consent is refused rather than re-interpreted.

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// gigahostAssociationPreviewTTL is how long a preview's consent stays usable. The
// consent is bound to the account and the unlisted rows the administrator was shown,
// so it must not outlive a plausible reading of that screen; an expired preview is
// refused rather than re-interpreted.
const gigahostAssociationPreviewTTL = 15 * time.Minute

// gigahostAssociationPreviewRecord is what one preview promised. The confirmation the
// administrator gives is bound to exactly this: the account that answered, and the
// rows the preview showed as unlisted. The counts alone are not consent, because the
// account behind them can change between the two requests.
type gigahostAssociationPreviewRecord struct {
	account  string
	unlisted map[int64]struct{}
	expires  time.Time
}

// recordGigahostAssociationPreview mints the token a confirmation must present, and
// stores the account and unlisted rows it stands for.
//
// A plan with nothing to write mints no token: there is no consent to give, and an
// empty token would let a request confirm a preview that never offered anything.
func (h *Handlers) recordGigahostAssociationPreview(plan gigahostAccountPlan) (string, error) {
	if plan.account == "" || len(plan.attributed)+len(plan.unlisted) == 0 {
		return "", nil
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	unlisted := make(map[int64]struct{}, len(plan.unlisted))
	for _, binding := range plan.unlisted {
		unlisted[binding.serverID] = struct{}{}
	}

	now := time.Now()
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	if h.associationPreviews == nil {
		h.associationPreviews = make(map[string]gigahostAssociationPreviewRecord)
	}
	for stale, record := range h.associationPreviews {
		if now.After(record.expires) {
			delete(h.associationPreviews, stale)
		}
	}
	h.associationPreviews[token] = gigahostAssociationPreviewRecord{
		account:  plan.account,
		unlisted: unlisted,
		expires:  now.Add(gigahostAssociationPreviewTTL),
	}
	return token, nil
}

// gigahostAssociationPreviewRecordFor returns the consent a token stands for. An
// expired token is refused as if it had never existed: the administrator's screen is
// stale, and a stale screen is not consent.
func (h *Handlers) gigahostAssociationPreviewRecordFor(token string) (gigahostAssociationPreviewRecord, bool) {
	if token == "" {
		return gigahostAssociationPreviewRecord{}, false
	}
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	record, ok := h.associationPreviews[token]
	if !ok {
		return gigahostAssociationPreviewRecord{}, false
	}
	if time.Now().After(record.expires) {
		delete(h.associationPreviews, token)
		return gigahostAssociationPreviewRecord{}, false
	}
	return record, true
}

// forgetGigahostAssociationPreview drops a consent that can no longer be honored,
// so the same token cannot be presented again after the account behind it changed.
func (h *Handlers) forgetGigahostAssociationPreview(token string) {
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	delete(h.associationPreviews, token)
}
