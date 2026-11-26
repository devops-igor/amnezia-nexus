package handlers

// The consent a preview issues, and the record a confirmation is checked against.
//
// There is ONE authority per administrator: issuing a preview retires whatever the
// same administrator held before. Two Settings tabs therefore cannot both hold a
// confirmable screen; the older one is refused when it is presented, rather than
// being applied to a batch the administrator has since replaced.
//
// The record is also bound to the effective provider configuration that produced it
// (client generation and credential scope). A confirmation that predates a change of
// that configuration is refused, so a write-once association cannot be recorded
// against an account the administrator is no longer configured with.
//
// The store is per-process: a restart makes every outstanding consent stale, which is
// the safe direction, and an expired consent is refused rather than re-interpreted.

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// gigahostAssociationPreviewTTL is how long a preview's consent stays usable. It must
// not outlive a plausible reading of that screen; an expired preview is refused rather
// than re-interpreted.
const gigahostAssociationPreviewTTL = 15 * time.Minute

// gigahostAssociationRetiredLimit bounds the tombstones kept per administrator. They
// exist only so a superseded token is answered with an explicit refusal instead of
// being indistinguishable from an invented one; a token older than this bound is
// refused as unknown, which is the same outcome for the caller.
const gigahostAssociationRetiredLimit = 8

// gigahostAssociationConfig identifies the effective provider configuration a plan
// was produced from.
//
// generation advances whenever the provider client is replaced, and scope is the
// one-way digest of the credential that answered. Both are needed: a settings change
// that swaps the key builds a new client without replacing the injected one, so the
// scope moves while the generation may not, and a replacement of the injected client
// moves the generation while the credential stays empty.
type gigahostAssociationConfig struct {
	generation uint64
	scope      string
}

// gigahostAssociationConfigOf names the configuration one resolution acts under.
func gigahostAssociationConfigOf(resolution gigahostClientResolution) gigahostAssociationConfig {
	return gigahostAssociationConfig{
		generation: resolution.generation,
		scope:      catalogScopeKey(resolution.credential),
	}
}

// gigahostAssociationPreviewRecord is what one preview promised: the account that
// answered, the configuration it was asked under, and the rows it showed as unlisted.
type gigahostAssociationPreviewRecord struct {
	account  string
	config   gigahostAssociationConfig
	unlisted map[int64]struct{}
	expires  time.Time
}

// gigahostAssociationAuthority is the single consent one administrator may hold.
type gigahostAssociationAuthority struct {
	// token is the consent currently offered; empty means the last preview offered
	// nothing to confirm.
	token string
	// record is what that token stands for.
	record gigahostAssociationPreviewRecord
	// retired holds the tokens this administrator has superseded, newest last.
	retired []string
}

// gigahostAssociationConsentStatus is how a presented token was answered.
type gigahostAssociationConsentStatus int

const (
	// gigahostAssociationConsentCurrent: this administrator's live consent.
	gigahostAssociationConsentCurrent gigahostAssociationConsentStatus = iota
	// gigahostAssociationConsentSuperseded: a consent a newer preview retired.
	gigahostAssociationConsentSuperseded
	// gigahostAssociationConsentUnknown: nothing this administrator ever held, or an
	// expired one.
	gigahostAssociationConsentUnknown
)

// issueGigahostAssociationPreview mints the token a confirmation must present, and
// makes it the administrator's only authority.
//
// Every earlier consent for the same administrator is retired here, whether or not the
// new plan has anything to write: the screen the administrator is looking at now is the
// only one their next answer can be about.
func (h *Handlers) issueGigahostAssociationPreview(
	admin string, plan gigahostAccountPlan, config gigahostAssociationConfig,
) (string, error) {
	now := time.Now()
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	if h.associationAuthorities == nil {
		h.associationAuthorities = make(map[string]gigahostAssociationAuthority)
	}
	previous := h.associationAuthorities[admin]
	retired := append([]string{}, previous.retired...)
	if previous.token != "" {
		retired = append(retired, previous.token)
	}
	if len(retired) > gigahostAssociationRetiredLimit {
		retired = retired[len(retired)-gigahostAssociationRetiredLimit:]
	}

	if plan.account == "" || len(plan.attributed)+len(plan.unlisted) == 0 {
		// Nothing to write: the new screen withdraws the previous consent and offers
		// no replacement, so an earlier token can no longer be presented.
		h.associationAuthorities[admin] = gigahostAssociationAuthority{retired: retired}
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
	h.associationAuthorities[admin] = gigahostAssociationAuthority{
		token: token,
		record: gigahostAssociationPreviewRecord{
			account:  plan.account,
			config:   config,
			unlisted: unlisted,
			expires:  now.Add(gigahostAssociationPreviewTTL),
		},
		retired: retired,
	}
	return token, nil
}

// gigahostAssociationConsent answers what a presented token stands for.
//
// Only the administrator's current token is a consent. A token this administrator has
// superseded is REFUSED (never silently accepted and never applied to the current
// plan), and anything else is unknown.
func (h *Handlers) gigahostAssociationConsent(
	admin, token string,
) (gigahostAssociationPreviewRecord, gigahostAssociationConsentStatus) {
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	authority, ok := h.associationAuthorities[admin]
	if !ok {
		return gigahostAssociationPreviewRecord{}, gigahostAssociationConsentUnknown
	}
	if token != "" && token == authority.token {
		if time.Now().After(authority.record.expires) {
			h.forgetLocked(admin, authority)
			return gigahostAssociationPreviewRecord{}, gigahostAssociationConsentUnknown
		}
		return authority.record, gigahostAssociationConsentCurrent
	}
	for _, retired := range authority.retired {
		if retired == token {
			return gigahostAssociationPreviewRecord{}, gigahostAssociationConsentSuperseded
		}
	}
	return gigahostAssociationPreviewRecord{}, gigahostAssociationConsentUnknown
}

// gigahostAssociationHoldsAuthority reports whether this token is still the
// administrator's live consent. The commit path asks again immediately before it
// writes, so a preview that arrived while the confirmation was deciding cannot be
// overtaken by the older answer.
func (h *Handlers) gigahostAssociationHoldsAuthority(admin, token string) bool {
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	authority, ok := h.associationAuthorities[admin]
	return ok && token != "" && token == authority.token && !time.Now().After(authority.record.expires)
}

// forgetGigahostAssociationPreview withdraws a consent that can no longer be honored,
// keeping its token as a tombstone so a replay is refused explicitly.
func (h *Handlers) forgetGigahostAssociationPreview(admin, token string) {
	h.associationMu.Lock()
	defer h.associationMu.Unlock()
	authority, ok := h.associationAuthorities[admin]
	if !ok {
		return
	}
	h.forgetLocked(admin, authority)
}

// forgetLocked withdraws the administrator's authority. The caller holds associationMu.
func (h *Handlers) forgetLocked(admin string, authority gigahostAssociationAuthority) {
	retired := append([]string{}, authority.retired...)
	if authority.token != "" {
		retired = append(retired, authority.token)
	}
	if len(retired) > gigahostAssociationRetiredLimit {
		retired = retired[len(retired)-gigahostAssociationRetiredLimit:]
	}
	h.associationAuthorities[admin] = gigahostAssociationAuthority{retired: retired}
}
