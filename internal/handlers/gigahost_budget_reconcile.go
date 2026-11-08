package handlers

// Automatic, restart-safe reconciliation of the Gigahost reservation ledger.
//
// The monthly budget counts a reservation until it is provably over, and an
// unknown financial outcome must stay counted. This file is the only place that
// decides a reservation is over, and it can only do so from evidence:
//
//   - the provider's own terminal status for the matching server, or
//   - the provider reporting that it does not own a real provider order id
//     (the provider issues those ids, so "no such order" is authoritative), or
//   - an operator's explicit, recorded no-charge confirmation for a record that
//     carries no provider identity at all.
//
// A local synthetic id (intent_/unknown_) is never evidence: the provider never
// issued it, so a not-found answer for it proves nothing. A communication
// failure is explicitly not evidence of absence.
//
// Two properties the procedure must have, and which the tests pin:
//
//   - Restart-safe: the only durable state it consults is the ledger and the
//     provider's live answer. Nothing is remembered in memory between runs.
//   - Idempotent: releases write released_at plus an audit row and keep the
//     original status, so running twice writes once and reports the second run
//     as already released instead of rewriting history.

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// maxBudgetReconcileLookups bounds the provider reads one order attempt may
// spend on reconciliation. It mirrors the pre-existing orders-list limit so a
// large legacy ledger cannot turn every purchase attempt into a provider
// hammering loop.
const maxBudgetReconcileLookups = 10

// releaseReasons recorded in the audit trail.
const (
	releaseReasonProviderOrderNotFound = "provider_order_not_found"
	releaseReasonProviderTerminal      = "provider_terminal_status"
	releaseReasonOperatorConfirmed     = "operator_confirmed_no_charge"
)

// budgetReconciliation is the outcome of one reconciliation pass.
type budgetReconciliation struct {
	// released lists the record ids this pass moved to released.
	released []int64
	// unresolved lists the record ids that stay counted because the outcome
	// could not be established.
	unresolved []gigahostbudget.Reservation
}

// gatherLedgerEvidence observes the provider for each ledger row that still
// counts, using only authoritative identities, and returns the observation per
// record id. Provider calls are bounded and each failure is recorded as an
// unknown outcome rather than being treated as absence.
func (h *Handlers) gatherLedgerEvidence(
	ctx context.Context, client gigahost.Client, servers []gigahost.ServerInfo, orders []GigahostOrderRecord,
) map[int64]gigahostbudget.Evidence {
	evidence := make(map[int64]gigahostbudget.Evidence, len(orders))
	sharedServers := budgetServers(servers)
	lookups := 0

	for _, o := range orders {
		if o.ReleasedAt != "" || gigahostbudget.IsTerminalStatus(o.Status) {
			continue
		}
		ev := gigahostbudget.Evidence{}
		inventoryTerminal := false
		for _, s := range sharedServers {
			if !gigahostbudget.EntryMatchesServer(budgetEntries([]GigahostOrderRecord{o})[0], s) {
				continue
			}
			// A matching provider server is evidence about this reservation
			// even when the local row is an unresolved attempt: the money is
			// committed and the provider told us its state.
			ev.ServerFound = true
			if s.Status != "" {
				ev.ServerStatus = s.Status
				inventoryTerminal = gigahostbudget.IsTerminalStatus(s.Status)
			}
			break
		}

		// Only a real provider order id may be queried. A synthetic local id
		// names nothing at the provider, so asking about it can only produce a
		// meaningless answer.
		if o.OrderID != "" && !gigahostbudget.IsSyntheticOrderID(o.OrderID) && lookups < maxBudgetReconcileLookups {
			lookups++
			resp, err := client.GetDeployStatus(ctx, o.OrderID)
			switch {
			case err == nil && resp != nil && resp.Status != "":
				ev.OrderQueried = true
				// The live inventory row for a matching server is the more
				// specific statement: a terminal inventory status must not be
				// overridden by an order-level non-terminal answer, or a
				// canceled server would look alive again.
				if !inventoryTerminal {
					ev.ServerFound = true
					ev.ServerStatus = resp.Status
				}
			case err == nil:
				// The provider answered about an id it issued but described no
				// live order: the pre-existing behavior treated that as an
				// ended order, and the id being the provider's own makes the
				// answer conclusive.
				ev.OrderQueried = true
				ev.OrderEnded = true
			case errors.Is(err, gigahost.ErrNotFound):
				ev.OrderQueried = true
				ev.OrderNotFound = true
			default:
				ev.OrderQueried = true
				ev.OrderQueryFailed = true
			}
		}
		evidence[o.ID] = ev
	}
	return evidence
}

// reconcileLedgerReservations runs one automatic reconciliation pass and writes
// the durable result: provider status updates, and release markers only for
// reservations the shared classification proves are over.
func (h *Handlers) reconcileLedgerReservations(
	ctx context.Context, client gigahost.Client, servers []gigahost.ServerInfo, orders []GigahostOrderRecord,
) budgetReconciliation {
	var out budgetReconciliation
	evidence := h.gatherLedgerEvidence(ctx, client, servers, orders)

	for i := range orders {
		order := &orders[i]
		if order.ReleasedAt != "" {
			continue
		}
		ev, observed := evidence[order.ID]
		if !observed || gigahostbudget.IsTerminalStatus(order.Status) {
			continue
		}
		verdict := gigahostbudget.Classify(budgetEntries([]GigahostOrderRecord{*order})[0], ev)

		// Keep the pre-existing status reconciliation, but only for statuses
		// that genuinely end the binding. A provider "failed" status ends the
		// deployment without proving no charge was incurred, so writing it onto
		// the row would silently release the reservation; that case keeps the
		// local status and is reported as unresolved instead.
		newStatus := ""
		switch {
		case ev.ServerFound && gigahostbudget.IsReleaseConclusiveStatus(ev.ServerStatus):
			newStatus = ev.ServerStatus
		case (ev.OrderEnded || ev.OrderNotFound) && !ev.ServerFound:
			// The provider owns this order id and has no live order for it: the
			// pre-existing behavior recorded that as canceled.
			newStatus = statusCancelled
		}
		if newStatus != "" && newStatus != order.Status {
			order.Status = newStatus
			if err := h.updateGigahostOrder(ctx, order); err != nil {
				slog.Warn("gigahost reconciliation: failed to record provider status",
					"record_id", order.ID, "error", err)
			}
		}

		if !verdict.Releasable {
			if verdict.State == gigahostbudget.StateUnresolved {
				out.unresolved = append(out.unresolved, gigahostbudget.Reservation{
					Source:      "ledger",
					RecordID:    order.ID,
					Identity:    order.OrderID,
					Status:      order.Status,
					State:       verdict.State,
					Reason:      verdict.Reason,
					Explanation: verdict.Explanation,
				})
			}
			continue
		}

		reason := releaseReasonFor(verdict)
		if reason == "" {
			continue
		}
		detail := verdict.Explanation
		if err := h.db.ReleaseGigahostOrder(ctx, order.ID, reason, detail); err != nil {
			if errors.Is(err, databaseErrAlreadyReleased) {
				continue
			}
			// A failed release must never be reported as released: the
			// reservation stays counted and the failure is visible.
			slog.Warn("gigahost reconciliation: failed to release reservation",
				"record_id", order.ID, "error", err)
			out.unresolved = append(out.unresolved, gigahostbudget.Reservation{
				Source:      "ledger",
				RecordID:    order.ID,
				Identity:    order.OrderID,
				Status:      order.Status,
				State:       gigahostbudget.StateUnresolved,
				Reason:      "release_write_failed",
				Explanation: "the release could not be recorded; the reservation stays counted",
			})
			continue
		}
		out.released = append(out.released, order.ID)
	}
	return out
}

// releaseReasonFor maps a releasable verdict to the audit reason.
func releaseReasonFor(v gigahostbudget.Verdict) string {
	switch {
	case v.Reason == "provider_order_not_found":
		return releaseReasonProviderOrderNotFound
	case strings.HasPrefix(v.Reason, "provider_"):
		return releaseReasonProviderTerminal
	case v.Reason == "operator_confirmed_no_charge":
		return releaseReasonOperatorConfirmed
	default:
		return ""
	}
}

// databaseErrAlreadyReleased is the sentinel the database package returns when a
// release is repeated, so a second reconciliation run is a no-op instead of an
// error an operator could mistake for data loss.
var databaseErrAlreadyReleased = database.ErrGigahostOrderAlreadyReleased
