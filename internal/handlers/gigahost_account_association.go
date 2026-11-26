package handlers

// The one-time association of existing provider-provisioned server rows with the
// account that owns them.
//
// A server row the panel registered before it recorded the hosting account carries
// an empty provider_account_id. Empty means unknown, and an unknown association is
// never treated as a match: every inventory read skips such a row (see
// decideGigahostRow), so the provider's view of it is never recorded - including for
// a server the provider has already deleted, which is the case the issue exists for.
//
// This file adds one deliberate, administrator-initiated action that states that
// association once, for exactly those rows, using the two answers the provider
// already gives:
//
//   - the configured account's inventory listing names the servers that account
//     holds, and every entry in it belongs to that account;
//   - a per-server read names the account the provider says owns that server.
//
// A row either answer names is associated with the account it names. A row the
// provider refuses to show, answers about without naming an account, or cannot be
// asked about stays unknown: nothing here guesses an account for a row the provider
// speaks against or says nothing about.
//
// The one remaining case is a row the provider answers "no such server" for. The
// provider has no such server, so there is no account to read off it, and the panel
// cannot tell a deleted server from one another account owns - the provider's answer
// is identical. That row is therefore associated only when the administrator asks
// for it explicitly, and the preview states the consequence first: the next
// inventory read of this account does not list the server, so the row is recorded
// absent. That is the deliberate decision this action exists for, and it is the only
// place where a row's account is stated by the administrator rather than by the
// provider.
//
// Nothing here decides existence. It writes one column, only onto a row that records
// no account, and never a status, a health verdict, a credential or an absence
// observation.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// gigahostAssociationTimeout bounds the whole association pass, not one provider
// call: the reads exist to state an association the administrator asked for, and a
// provider that stops answering must end the pass with the rows it had decided
// rather than hold the request open.
const gigahostAssociationTimeout = 60 * time.Second

// gigahostAssociationReason says why a row was left without an association. The
// tokens are returned to the administrator, so they are part of this file's
// contract with the settings surface.
type gigahostAssociationReason string

const (
	// gigahostAssociationRefused: the provider refused to show the server. A refusal
	// says the key may not see it, which is not an answer about who owns it.
	gigahostAssociationRefused gigahostAssociationReason = "provider_refused"
	// gigahostAssociationUnanswered: the read failed for any other reason - a
	// timeout, a network error, a malformed answer. Nothing was learnt.
	gigahostAssociationUnanswered gigahostAssociationReason = "provider_unanswered"
	// gigahostAssociationUnnamed: the provider answered with the server but did not
	// name the account it belongs to.
	gigahostAssociationUnnamed gigahostAssociationReason = "provider_unnamed"
	// gigahostAssociationWriteFailed: the row's association could not be stored.
	gigahostAssociationWriteFailed gigahostAssociationReason = "write_failed"
	// gigahostAssociationNotConfirmed: the row is one the account no longer lists,
	// and the administrator did not authorize that consequence for this preview. It
	// still records no account, so reconciliation still skips it.
	gigahostAssociationNotConfirmed gigahostAssociationReason = "unlisted_not_confirmed"
)

// undecidedCount is the number of candidate rows this pass left unknown.
func (p gigahostAccountPlan) undecidedCount() int {
	total := 0
	for _, n := range p.undecided {
		total += n
	}
	return total
}

// reasonPayload renders an unknown-row tally as a stable, sorted list, so a response
// is comparable across runs and a test can assert the exact reasons.
func reasonPayload(reasons map[gigahostAssociationReason]int) []map[string]any {
	names := make([]string, 0, len(reasons))
	for reason := range reasons {
		names = append(names, string(reason))
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		out = append(out, map[string]any{
			"reason": name,
			"count":  reasons[gigahostAssociationReason(name)],
		})
	}
	return out
}

// previewPayload is what the administrator is shown before confirming. Every count
// is the count the action will apply, because both come from the same plan.
//
// previewID is the token the confirmation must present. It stands for the account
// that answered and the unlisted rows below, so a confirmation cannot be carried to
// a different account or to a preview that never showed those rows.
func (p gigahostAccountPlan) previewPayload(previewID string) map[string]any {
	return map[string]any{
		"preview_id":    previewID,
		"candidates":    p.candidates,
		"already_bound": p.alreadyBound,
		"attributable":  len(p.attributed),
		"unlisted":      len(p.unlisted),
		"unattributed":  p.undecidedCount(),
		"reasons":       reasonPayload(p.undecided),
	}
}

// GigahostAccountAssociationPreviewHandler reports what the one-time association
// would do, without writing anything.
//
// It reads the provider, so it is the step that shows the administrator how many
// rows can be associated before any of them is changed.
func (h *Handlers) GigahostAccountAssociationPreviewHandler(w http.ResponseWriter, r *http.Request) {
	if !h.gigahostAssociationAdmin(w, r) {
		return
	}
	plan, config, err := h.planGigahostAccountAssociation(r.Context(), r)
	if err != nil {
		h.JSONError(w, http.StatusServiceUnavailable, "gigahost_association_unavailable", err.Error())
		return
	}
	previewID, err := h.issueGigahostAssociationPreview(h.gigahostAssociationAdminID(r), plan, config)
	if err != nil {
		h.JSONError(w, http.StatusInternalServerError, "gigahost_association_unavailable",
			"the preview could not be recorded, so nothing may be confirmed from it")
		return
	}
	h.JSON(w, http.StatusOK, plan.previewPayload(previewID))
}

// gigahostAssociationAdminID names the administrator whose authority a preview
// creates. One administrator holds one consent at a time, so a second tab's preview
// retires the first tab's rather than leaving two confirmable screens alive.
func (h *Handlers) gigahostAssociationAdminID(r *http.Request) string {
	sess := middleware.GetSession(r.Context())
	if sess == nil || strings.TrimSpace(sess.UserID) == "" {
		return "administrator"
	}
	return sess.UserID
}

// gigahostAssociationConfirmation is the administrator's answer to the preview.
//
// PreviewID names the preview this answer was given for. It is required: the counts
// the administrator saw belong to one account and one set of unlisted rows, and a
// confirmation that does not name them could be applied to whichever account the
// configured key happens to belong to by the time it arrives.
//
// IncludeUnlisted is the authorisation for the rows the provider says it does not
// have. It is a named field rather than an inference from the request, so a client
// that does not send it can never associate one of those rows by accident.
type gigahostAssociationConfirmation struct {
	PreviewID       string `json:"preview_id"`
	IncludeUnlisted bool   `json:"include_unlisted"`
}

// gigahostAssociationApplication is what one application of the plan wrote.
type gigahostAssociationApplication struct {
	associated     int
	unlisted       int
	boundElsewhere int
	reasons        map[gigahostAssociationReason]int
}

// gigahostAssociationRefusal says why the commit path wrote nothing.
type gigahostAssociationRefusal int

const (
	// gigahostAssociationCommitted: the bindings were applied.
	gigahostAssociationCommitted gigahostAssociationRefusal = iota
	// gigahostAssociationLostAuthority: a newer preview retired this consent while
	// the confirmation was deciding.
	gigahostAssociationLostAuthority
	// gigahostAssociationConfigMoved: the effective provider configuration changed
	// after the preview this confirmation answers.
	gigahostAssociationConfigMoved
	// gigahostAssociationCommitUnavailable: the configuration could not be re-read,
	// so the fence could not be established.
	gigahostAssociationCommitUnavailable
)

// applyGigahostAssociation writes every binding, one conditional row update each.
//
// Before the first write it establishes two facts from live state rather than from
// the request's own earlier reads:
//
//   - this consent is still the administrator's live authority, so a newer preview
//     that arrived while this one was deciding cannot be overtaken by the older
//     answer;
//   - the effective provider configuration is the one the preview was produced from,
//     re-resolved here, so a confirmation that predates a key change never writes.
//
// One row's failure does not stop the rest: the association is per-row and
// idempotent, and the count reports what happened. A row another writer bound first
// is counted as already bound rather than as a change of this run, which is what
// makes a repeated run report "nothing further associated".
func (h *Handlers) applyGigahostAssociation(
	ctx context.Context,
	r *http.Request,
	admin, token string,
	expected gigahostAssociationConfig,
	bindings []gigahostAccountBinding,
	reasons map[gigahostAssociationReason]int,
) (gigahostAssociationApplication, gigahostAssociationRefusal) {
	application := gigahostAssociationApplication{reasons: reasons}
	if len(bindings) == 0 {
		// Nothing to write: a repeated confirmation or an account whose rows all
		// record themselves. There is no write to fence, and requiring a resolvable
		// key to answer "nothing further" would turn a true all-clear into an error.
		return application, gigahostAssociationCommitted
	}
	if !h.gigahostAssociationHoldsAuthority(admin, token) {
		return application, gigahostAssociationLostAuthority
	}
	live, err := h.resolveGigahostClient(ctx, r)
	if err != nil {
		return application, gigahostAssociationCommitUnavailable
	}
	if gigahostAssociationConfigOf(live) != expected {
		return application, gigahostAssociationConfigMoved
	}
	for _, binding := range bindings {
		written, err := h.db.BindServerProviderAccount(ctx, binding.serverID, binding.accountID)
		if err != nil {
			slog.Warn("Provider account association could not record a server",
				"server_id", binding.serverID, "error", err)
			application.reasons[gigahostAssociationWriteFailed]++
			continue
		}
		if !written {
			application.boundElsewhere++
			continue
		}
		application.associated++
		if binding.unlisted {
			application.unlisted++
		}
	}
	return application, gigahostAssociationCommitted
}

// GigahostAccountAssociationHandler applies the plan the preview showed.
//
// It writes one column and only onto rows that record no account. It sets no
// absence mark, changes no status and touches no credential: the ordinary
// reconciliation decides existence on its next pass, exactly as it does for a row
// registered with its account.
func (h *Handlers) GigahostAccountAssociationHandler(w http.ResponseWriter, r *http.Request) {
	if !h.gigahostAssociationAdmin(w, r) {
		return
	}

	confirmation := gigahostAssociationConfirmation{}
	if r.Body != nil {
		// An absent or empty body means "no confirmation", which is what a client
		// that only wants the provider-named rows sends. Anything unreadable is
		// refused, so a malformed confirmation can never be read as consent.
		if err := h.DecodeJSON(r, &confirmation); err != nil && !errors.Is(err, io.EOF) {
			h.JSONError(w, http.StatusBadRequest, "invalid_body", err.Error())
			return
		}
	}

	ctx := r.Context()
	admin := h.gigahostAssociationAdminID(r)

	// The consent must name the preview it was given for, before anything is read
	// from the provider: a request without one has no account and no unlisted scope
	// to be bound to.
	if strings.TrimSpace(confirmation.PreviewID) == "" {
		h.JSONError(w, http.StatusConflict, "gigahost_association_preview_required",
			"check again before associating: the confirmation must name the preview it was given for, and nothing was changed")
		return
	}
	consent, status := h.gigahostAssociationConsent(admin, confirmation.PreviewID)
	switch status {
	case gigahostAssociationConsentSuperseded:
		// A newer check replaced the screen this answer came from. It is refused
		// outright: the batch the administrator is looking at now is a different one.
		h.JSONError(w, http.StatusConflict, "gigahost_association_preview_superseded",
			"a newer check has replaced that one; confirm from the check you are looking at, and nothing was changed")
		return
	case gigahostAssociationConsentCurrent:
	default:
		h.JSONError(w, http.StatusConflict, "gigahost_association_preview_stale",
			"that check is no longer available; check again and confirm from the fresh counts, and nothing was changed")
		return
	}

	plan, config, err := h.planGigahostAccountAssociation(ctx, r)
	if err != nil {
		h.JSONError(w, http.StatusServiceUnavailable, "gigahost_association_unavailable", err.Error())
		return
	}

	// The account that answers now must be the account the administrator previewed.
	// Otherwise the consent shown for one account would be applied to another: the
	// remainder of the request would be a write the administrator never approved.
	//
	// An empty plan account means the pass had no candidate rows to ask the provider
	// about, so this request can only be a no-op (a repeated confirmation, or an
	// account whose every row already records itself). There is no account behind it
	// to mismatch, and there is nothing it could write.
	if plan.account != "" && plan.account != consent.account {
		h.forgetGigahostAssociationPreview(admin, confirmation.PreviewID)
		h.JSONError(w, http.StatusConflict, "gigahost_association_account_changed",
			"the configured account changed since that check; check again and confirm under the account you reviewed, and nothing was changed")
		return
	}

	// Every row that still needs an answer is counted, including the ones this
	// confirmation excludes: a row left unknown is still skipped by reconciliation,
	// so a result that wrote nothing must not look like an all-clear.
	var unlisted []gigahostAccountBinding
	excluded := 0
	for _, binding := range plan.unlisted {
		_, previewed := consent.unlisted[binding.serverID]
		if confirmation.IncludeUnlisted && previewed {
			unlisted = append(unlisted, binding)
			continue
		}
		excluded++
	}
	if confirmation.IncludeUnlisted && len(consent.unlisted) == 0 {
		h.JSONError(w, http.StatusConflict, "gigahost_association_preview_stale",
			"that check did not offer any servers the account no longer lists; check again before confirming, and nothing was changed")
		return
	}

	bindings := append(append([]gigahostAccountBinding{}, plan.attributed...), unlisted...)

	// The configuration that produced the preview must still be the one in effect.
	// The commit path re-establishes this against live state; refusing here keeps the
	// request from doing any further work for a screen that is already obsolete.
	// Only a request with something to write is fenced: a no-op repeat has nothing to
	// record and must still be able to report that.
	if len(bindings) > 0 && config != consent.config {
		h.forgetGigahostAssociationPreview(admin, confirmation.PreviewID)
		h.JSONError(w, http.StatusConflict, "gigahost_association_configuration_changed",
			"the provider configuration changed since that check; check again under the current key, and nothing was changed")
		return
	}

	reasons := make(map[gigahostAssociationReason]int, len(plan.undecided)+1)
	for reason, count := range plan.undecided {
		reasons[reason] = count
	}
	if excluded > 0 {
		reasons[gigahostAssociationNotConfirmed] += excluded
	}

	applied, refusal := h.applyGigahostAssociation(ctx, r, admin, confirmation.PreviewID, consent.config, bindings, reasons)
	switch refusal {
	case gigahostAssociationLostAuthority:
		h.JSONError(w, http.StatusConflict, "gigahost_association_preview_superseded",
			"a newer check replaced that one while it was being confirmed; confirm from the check you are looking at, and nothing was changed")
		return
	case gigahostAssociationConfigMoved:
		h.forgetGigahostAssociationPreview(admin, confirmation.PreviewID)
		h.JSONError(w, http.StatusConflict, "gigahost_association_configuration_changed",
			"the provider configuration changed while that confirmation was being applied; check again under the current key, and nothing was changed")
		return
	case gigahostAssociationCommitUnavailable:
		h.JSONError(w, http.StatusServiceUnavailable, "gigahost_association_unavailable",
			"the provider configuration could not be re-read, so nothing was changed")
		return
	}

	unattributed := 0
	for _, count := range applied.reasons {
		unattributed += count
	}

	slog.Info("Provider account association recorded",
		"associated", applied.associated,
		"unlisted", applied.unlisted,
		"already_bound", plan.alreadyBound+applied.boundElsewhere,
		"unattributed", unattributed,
		"write_failures", applied.reasons[gigahostAssociationWriteFailed])

	h.JSON(w, http.StatusOK, map[string]any{
		"associated":    applied.associated,
		"unlisted":      applied.unlisted,
		"already_bound": plan.alreadyBound + applied.boundElsewhere,
		"unattributed":  unattributed,
		"reasons":       reasonPayload(applied.reasons),
	})
}

// gigahostAssociationAdmin answers the request itself when the caller is not an
// administrator, and reports whether the caller may continue.
//
// The route is already admin-only; this is the same check at the handler, so the
// action cannot be reached by a request that arrived through another route or a
// future registration that forgot the middleware.
func (h *Handlers) gigahostAssociationAdmin(w http.ResponseWriter, r *http.Request) bool {
	sess := middleware.GetSession(r.Context())
	if sess == nil || sess.Role != models.RoleAdmin {
		h.JSONError(w, http.StatusForbidden, "forbidden", "Admin privileges required")
		return false
	}
	return true
}
