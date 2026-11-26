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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
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
)

// gigahostDetailOutcome is what one per-server read established.
type gigahostDetailOutcome int

const (
	// gigahostDetailNamed: the provider answered with the server.
	gigahostDetailNamed gigahostDetailOutcome = iota
	// gigahostDetailMissing: the provider answered that it has no such server.
	gigahostDetailMissing
	// gigahostDetailRefused: the key may not see the server.
	gigahostDetailRefused
	// gigahostDetailUnanswered: anything else - a failure, a timeout, an answer
	// that could not be read.
	gigahostDetailUnanswered
)

// gigahostDetailOutcomeFor classifies one per-server read.
//
// The two failure kinds are kept apart on purpose: the provider documents "not
// found" as the resource being gone and an authorization refusal as the key not
// being allowed to see it, and only the first is an answer about the server at all.
func gigahostDetailOutcomeFor(server *gigahost.ServerInfo, err error) (gigahostDetailOutcome, string) {
	switch {
	case err == nil && server != nil:
		if account := strings.TrimSpace(server.CustID.String()); account != "" {
			return gigahostDetailNamed, account
		}
		return gigahostDetailNamed, ""
	case err == nil:
		return gigahostDetailUnanswered, ""
	case errors.Is(err, gigahost.ErrNotFound):
		return gigahostDetailMissing, ""
	case errors.Is(err, gigahost.ErrUnauthorized):
		return gigahostDetailRefused, ""
	default:
		return gigahostDetailUnanswered, ""
	}
}

// gigahostAccountBinding is one row to associate, with the account to record.
type gigahostAccountBinding struct {
	serverID  int64
	accountID string
	// unlisted marks a row the provider says it does not have, so the caller can
	// count the rows whose association the next inventory read will mark absent.
	unlisted bool
}

// gigahostAccountPlan is what one association pass decided, before anything is
// written. The preview endpoint returns it and the action endpoint applies it, so
// what the administrator is shown and what the action does cannot drift.
type gigahostAccountPlan struct {
	// candidates are the provider-provisioned rows that record no account.
	candidates int
	// alreadyBound are the provider-provisioned rows that already record one.
	alreadyBound int
	// attributed are the rows the provider named an account for.
	attributed []gigahostAccountBinding
	// unlisted are the rows the provider says it does not have.
	unlisted []gigahostAccountBinding
	// undecided counts the rows left unknown, by reason.
	undecided map[gigahostAssociationReason]int
}

// decideGigahostAssociation classifies one row against one provider answer.
//
// The listing wins over the per-server read because it is the authoritative
// enumeration of the account: an entry in it is the provider stating that this
// account holds that server.
func decideGigahostAssociation(
	row providerBackedServer,
	listed map[int64]struct{},
	answerAccount string,
	outcome gigahostDetailOutcome,
	namedAccount string,
) gigahostAccountBinding {
	if _, ok := listed[row.providerServerID]; ok {
		return gigahostAccountBinding{serverID: row.serverID, accountID: answerAccount}
	}
	switch outcome {
	case gigahostDetailNamed:
		if namedAccount == "" {
			// The answer states that the server exists and names no account, so
			// there is nothing to associate it with.
			return gigahostAccountBinding{serverID: row.serverID}
		}
		return gigahostAccountBinding{serverID: row.serverID, accountID: namedAccount}
	case gigahostDetailMissing:
		// The provider has no such server. There is no account to read off it, so
		// the association can only come from the administrator's confirmation.
		return gigahostAccountBinding{serverID: row.serverID, accountID: answerAccount, unlisted: true}
	default:
		return gigahostAccountBinding{serverID: row.serverID}
	}
}

// gigahostAssociationReasonFor names why an undecided row stayed unknown, so the
// administrator can read a reason rather than a bare count.
func gigahostAssociationReasonFor(outcome gigahostDetailOutcome) gigahostAssociationReason {
	switch outcome {
	case gigahostDetailRefused:
		return gigahostAssociationRefused
	case gigahostDetailNamed:
		return gigahostAssociationUnnamed
	default:
		return gigahostAssociationUnanswered
	}
}

// planGigahostAccountAssociation reads the provider and decides, per row, which
// account to record. It writes nothing.
//
// Every provider read that fails refuses the whole pass, so a partial answer can
// never associate a row: the administrator is told the pass did not run rather than
// being shown a count derived from an incomplete read.
func (h *Handlers) planGigahostAccountAssociation(ctx context.Context, r *http.Request) (gigahostAccountPlan, error) {
	plan := gigahostAccountPlan{undecided: make(map[gigahostAssociationReason]int)}
	if h == nil || h.db == nil {
		return plan, errors.New("database not available")
	}

	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		return plan, fmt.Errorf("failed to read servers for the provider account association: %w", err)
	}

	var rows []providerBackedServer
	for _, s := range servers {
		providerServerID, ok := providerBackedServerID(s.Protocols)
		if !ok {
			continue
		}
		row := providerBackedServer{
			serverID:         s.ID,
			providerServerID: providerServerID,
			accountID:        strings.TrimSpace(s.ProviderAccountID),
			absentAt:         s.ProviderAbsentAt,
		}
		if row.accountID != "" {
			plan.alreadyBound++
			continue
		}
		rows = append(rows, row)
	}
	plan.candidates = len(rows)
	if plan.candidates == 0 {
		// Every provider-provisioned row already records its account, so there is
		// nothing to ask the provider and nothing to associate.
		return plan, nil
	}

	client, err := h.getGigahostClient(ctx, r)
	if err != nil {
		return plan, fmt.Errorf("gigahost account association skipped; no server row changed: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, gigahostAssociationTimeout)
	defer cancel()

	account, err := client.GetAccount(callCtx)
	if err != nil {
		return plan, fmt.Errorf("gigahost account identity unavailable; no server row changed: %w", err)
	}
	answerAccount := gigahostAccountIdentity(account)
	if answerAccount == "" {
		return plan, errors.New(
			"gigahost GET /account answered without a usable account identifier; no server row changed")
	}

	inventory, err := client.GetServers(callCtx)
	if err != nil {
		return plan, fmt.Errorf("gigahost inventory read failed; no server row changed: %w", err)
	}
	listed, err := gigahostIdentifiedServerIDs(inventory)
	if err != nil {
		return plan, err
	}

	for _, row := range rows {
		outcome, namedAccount := gigahostDetailUnanswered, ""
		if _, isListed := listed[row.providerServerID]; !isListed {
			// The listing already answers for a listed row, and its answer is the
			// authoritative one; asking a second time could only contradict it.
			outcome, namedAccount = gigahostDetailOutcomeFor(client.GetServer(callCtx, row.providerServerID))
		}
		binding := decideGigahostAssociation(row, listed, answerAccount, outcome, namedAccount)
		switch {
		case binding.unlisted:
			plan.unlisted = append(plan.unlisted, binding)
		case binding.accountID != "":
			plan.attributed = append(plan.attributed, binding)
		default:
			plan.undecided[gigahostAssociationReasonFor(outcome)]++
		}
	}
	return plan, nil
}

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
func (p gigahostAccountPlan) previewPayload() map[string]any {
	return map[string]any{
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
	plan, err := h.planGigahostAccountAssociation(r.Context(), r)
	if err != nil {
		h.JSONError(w, http.StatusServiceUnavailable, "gigahost_association_unavailable", err.Error())
		return
	}
	h.JSON(w, http.StatusOK, plan.previewPayload())
}

// gigahostAssociationConfirmation is the administrator's answer to the preview.
//
// IncludeUnlisted is the authorisation for the rows the provider says it does not
// have. It is a named field rather than an inference from the request, so a client
// that does not send it can never associate one of those rows by accident.
type gigahostAssociationConfirmation struct {
	IncludeUnlisted bool `json:"include_unlisted"`
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
	plan, err := h.planGigahostAccountAssociation(ctx, r)
	if err != nil {
		h.JSONError(w, http.StatusServiceUnavailable, "gigahost_association_unavailable", err.Error())
		return
	}

	bindings := plan.attributed
	if confirmation.IncludeUnlisted {
		bindings = append(append([]gigahostAccountBinding{}, plan.attributed...), plan.unlisted...)
	}

	reasons := make(map[gigahostAssociationReason]int, len(plan.undecided))
	for reason, count := range plan.undecided {
		reasons[reason] = count
	}

	associated, unlisted, boundElsewhere, failed := 0, 0, 0, 0
	for _, binding := range bindings {
		written, err := h.db.BindServerProviderAccount(ctx, binding.serverID, binding.accountID)
		if err != nil {
			// One row's failure does not stop the rest: the association is
			// per-row and idempotent, and the count reports what happened.
			slog.Warn("Provider account association could not record a server",
				"server_id", binding.serverID, "error", err)
			reasons[gigahostAssociationWriteFailed]++
			failed++
			continue
		}
		if !written {
			// The row recorded an account between the plan and this write, or
			// another run of this action bound it first. Either way this run did
			// not change it.
			boundElsewhere++
			continue
		}
		associated++
		if binding.unlisted {
			unlisted++
		}
	}

	unattributed := 0
	for _, count := range reasons {
		unattributed += count
	}

	slog.Info("Provider account association recorded",
		"associated", associated,
		"unlisted", unlisted,
		"already_bound", plan.alreadyBound+boundElsewhere,
		"unattributed", unattributed,
		"write_failures", failed)

	h.JSON(w, http.StatusOK, map[string]any{
		"associated":    associated,
		"unlisted":      unlisted,
		"already_bound": plan.alreadyBound + boundElsewhere,
		"unattributed":  unattributed,
		"reasons":       reasonPayload(reasons),
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
