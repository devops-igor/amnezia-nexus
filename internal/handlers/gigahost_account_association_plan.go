package handlers

// What the association pass decides, before anything is written.
//
// The pass reads the two answers the provider gives - the identity of the account
// that answered, and the servers that account lists - and classifies every
// provider-provisioned row that records no account. It writes nothing; the handler
// returns the plan, and the action endpoint applies the part the administrator
// confirmed.
//
// The listing wins over the per-server read because it is the authoritative
// enumeration of the account: an entry in it is the provider stating that this
// account holds that server.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
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
	// account is the identifier the provider said it answered as. The confirmation
	// is bound to it: a plan built under a different account must never apply a
	// consent given for this one.
	account string
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

// gigahostAssociationCandidates splits the server rows into the ones the provider
// can judge and the ones that already record their account.
func gigahostAssociationCandidates(servers []models.Server) ([]providerBackedServer, int) {
	var rows []providerBackedServer
	alreadyBound := 0
	for _, s := range servers {
		providerServerID, ok := providerBackedServerID(s.Protocols)
		if !ok {
			continue
		}
		account := strings.TrimSpace(s.ProviderAccountID)
		if account != "" {
			alreadyBound++
			continue
		}
		rows = append(rows, providerBackedServer{
			serverID:         s.ID,
			providerServerID: providerServerID,
			accountID:        account,
			absentAt:         s.ProviderAbsentAt,
		})
	}
	return rows, alreadyBound
}

// gigahostAssociationAnswer reads the two answers the association is decided from:
// the identity of the account that answered, and the servers that account lists.
//
// Both are required together. An answer that cannot be attributed to an account
// proves nothing about any row, and a listing that could not be read cannot say which
// rows the account holds, so either failure refuses the pass rather than associating
// from a partial read.
func gigahostAssociationAnswer(ctx context.Context, client gigahost.Client) (map[int64]struct{}, string, error) {
	account, err := client.GetAccount(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("gigahost account identity unavailable; no server row changed: %w", err)
	}
	answerAccount := gigahostAccountIdentity(account)
	if answerAccount == "" {
		return nil, "", errors.New(
			"gigahost GET /account answered without a usable account identifier; no server row changed")
	}
	inventory, err := client.GetServers(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("gigahost inventory read failed; no server row changed: %w", err)
	}
	listed, err := gigahostIdentifiedServerIDs(inventory)
	if err != nil {
		return nil, "", err
	}
	return listed, answerAccount, nil
}

// gigahostAssociationBindings classifies every candidate row against one answer.
//
// The per-server read is made only for a row the listing does not contain: the
// listing already answered for the rest, and a second answer could only contradict
// the enumeration this pass is decided from.
func gigahostAssociationBindings(
	ctx context.Context,
	client gigahost.Client,
	rows []providerBackedServer,
	listed map[int64]struct{},
	answerAccount string,
) (attributed, unlisted []gigahostAccountBinding, undecided map[gigahostAssociationReason]int) {
	undecided = make(map[gigahostAssociationReason]int)
	for _, row := range rows {
		outcome, namedAccount := gigahostDetailUnanswered, ""
		if _, isListed := listed[row.providerServerID]; !isListed {
			outcome, namedAccount = gigahostDetailOutcomeFor(client.GetServer(ctx, row.providerServerID))
		}
		binding := decideGigahostAssociation(row, listed, answerAccount, outcome, namedAccount)
		switch {
		case binding.unlisted:
			unlisted = append(unlisted, binding)
		case binding.accountID != "":
			attributed = append(attributed, binding)
		default:
			undecided[gigahostAssociationReasonFor(outcome)]++
		}
	}
	return attributed, unlisted, undecided
}

// planGigahostAccountAssociation reads the provider and decides, per row, which
// account to record. It writes nothing.
//
// It returns the provider configuration the plan was produced from, so a preview can
// bind its consent to it and a confirmation can refuse a screen that predates a
// change of that configuration. Every provider read that fails refuses the whole pass,
// so a partial answer can never associate a row.
func (h *Handlers) planGigahostAccountAssociation(ctx context.Context, r *http.Request) (gigahostAccountPlan, gigahostAssociationConfig, error) {
	plan := gigahostAccountPlan{undecided: make(map[gigahostAssociationReason]int)}
	if h == nil || h.db == nil {
		return plan, gigahostAssociationConfig{}, errors.New("database not available")
	}

	servers, err := h.db.GetAllServers(ctx)
	if err != nil {
		return plan, gigahostAssociationConfig{}, fmt.Errorf("failed to read servers for the provider account association: %w", err)
	}
	rows, alreadyBound := gigahostAssociationCandidates(servers)
	plan.candidates, plan.alreadyBound = len(rows), alreadyBound
	if len(rows) == 0 {
		// Every provider-provisioned row already records its account, so there is
		// nothing to ask the provider and nothing to associate. The configuration is
		// still resolved, because the preview must be bound to the one in effect.
		resolution, err := h.resolveGigahostClient(ctx, r)
		if err != nil {
			return plan, gigahostAssociationConfig{}, nil
		}
		return plan, gigahostAssociationConfigOf(resolution), nil
	}

	resolution, err := h.resolveGigahostClient(ctx, r)
	if err != nil {
		return plan, gigahostAssociationConfig{}, fmt.Errorf("gigahost account association skipped; no server row changed: %w", err)
	}
	client := resolution.client

	callCtx, cancel := context.WithTimeout(ctx, gigahostAssociationTimeout)
	defer cancel()

	listed, answerAccount, err := gigahostAssociationAnswer(callCtx, client)
	if err != nil {
		return plan, gigahostAssociationConfig{}, err
	}
	plan.account = answerAccount
	plan.attributed, plan.unlisted, plan.undecided = gigahostAssociationBindings(callCtx, client, rows, listed, answerAccount)
	return plan, gigahostAssociationConfigOf(resolution), nil
}
