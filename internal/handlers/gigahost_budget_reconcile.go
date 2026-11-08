package handlers

// Automatic, restart-safe reconciliation of the Gigahost reservation ledger.
//
// The monthly budget counts a reservation until the provider states no further
// charge accrues, and an unknown financial outcome must stay counted. This file
// is the only place that decides a reservation is over.
//
// It can distinguish exactly two evidences, described in the provider contract:
// https://gigahost.no/en/api-dokumentasjon
//
//   - the provider reporting a matching server as terminated or deleted, which
//     ends the recurring pay-as-you-go commitment, or
//   - the provider reporting the order as a waitlist reservation, which the
//     contract states is not billed while it waits.
//
// Everything else keeps the reservation. In particular this file must NOT treat
// as proof of non-billability:
//
//   - a server reported as canceled, which is a PENDING cancellation: the server keeps
//     running and is billed until termination_date,
//   - `stopped` / `expired` / `refunded`, which the documentation gives no
//     billing meaning,
//   - an omission from GET /deploy/status, which the contract states also omits
//     canceled orders and orders whose server was deleted, and silently ignores
//     orders that are not yours,
//   - a local synthetic id, which names nothing at the provider.
//
// Two properties the procedure must have, and which the tests pin:
//
//   - Restart-safe: the only durable state it consults is the ledger and the
//     provider's live answer. Nothing is remembered in memory between runs.
//   - Idempotent and freshness-safe: a release re-reads the row and verifies the
//     observed identity is still the stored one before writing, so a stale
//     observation can never release a record that changed underneath it. The
//     release writes released_at plus an audit row and keeps the original status,
//     so running twice writes once.

import (
	"context"
	"errors"
	"log/slog"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostbudget"
)

// maxBudgetReconcileLookups bounds the provider reads one order attempt may
// spend on reconciliation. It mirrors the pre-existing orders-list limit so a
// large legacy ledger cannot turn every purchase attempt into a provider
// hammering loop.
const maxBudgetReconcileLookups = 10

// budgetReconciliation is the outcome of one reconciliation pass.
type budgetReconciliation struct {
	// released lists the record ids this pass moved to released.
	released []int64
	// unresolved lists the reservations that stay counted because the outcome
	// could not be established.
	unresolved []gigahostbudget.Reservation
	// stale lists the records whose evidence no longer matched the stored row,
	// so the release was correctly refused.
	stale []int64
}

// ledgerObservation is one provider observation plus the identity it was made
// against. The identity is kept so the release can verify the record has not
// changed since it was observed.
type ledgerObservation struct {
	evidence gigahostbudget.Evidence
	// orderID and serverID are the identity values the observation is about.
	orderID  string
	serverID int64
}

// gatherLedgerEvidence observes the provider for each ledger row that still
// counts, using only authoritative identities. Provider calls are bounded and
// each failure is recorded as an unknown outcome rather than being treated as
// absence.
func (h *Handlers) gatherLedgerEvidence(
	ctx context.Context, client gigahost.Client, servers []gigahost.ServerInfo, orders []GigahostOrderRecord,
) map[int64]ledgerObservation {
	out := make(map[int64]ledgerObservation, len(orders))
	sharedServers := budgetServers(servers)
	lookups := 0

	for _, o := range orders {
		if o.ReleasedAt != "" || gigahostbudget.IsLocallyTerminal(o.Status) {
			continue
		}
		obs := ledgerObservation{orderID: o.OrderID, serverID: o.ServerID}
		entry := budgetEntries([]GigahostOrderRecord{o})[0]

		// A matching inventory row describes the resource itself, and is the
		// most specific statement available.
		for _, s := range sharedServers {
			if !gigahostbudget.EntryMatchesServer(entry, s) {
				continue
			}
			obs.evidence.ServerFound = true
			obs.evidence.ServerStatus = s.Status
			break
		}

		// Only a real provider order id may be queried: a synthetic local id
		// names nothing at the provider.
		queryable := o.OrderID != "" && !gigahostbudget.IsSyntheticOrderID(o.OrderID)
		if queryable && lookups < maxBudgetReconcileLookups {
			lookups++
			resp, err := client.GetDeployStatus(ctx, o.OrderID)
			switch {
			case err == nil && resp != nil && resp.Status != "":
				obs.evidence.ProviderOrderFound = true
				obs.evidence.ProviderOrderStatus = resp.Status
			case err == nil:
				// The provider listed the order with no status. That is not a
				// statement about billing, so nothing is concluded from it.
			case errors.Is(err, gigahost.ErrNotFound):
				// Recorded as an observation, and deliberately never treated as
				// evidence: the contract states this endpoint omits canceled
				// orders and orders whose server was deleted (E1), so omission
				// cannot prove a charge does not exist.
				obs.evidence.OrderOmittedFromDeployStatus = true
			default:
				obs.evidence.OrderQueryFailed = true
			}
		}
		out[o.ID] = obs
	}
	return out
}

// reconcileLedgerReservations runs one automatic reconciliation pass and writes
// the durable result: release markers only for reservations the shared
// classification proves carry no further charge.
func (h *Handlers) reconcileLedgerReservations(
	ctx context.Context, client gigahost.Client, servers []gigahost.ServerInfo, orders []GigahostOrderRecord,
) budgetReconciliation {
	var out budgetReconciliation
	observed := h.gatherLedgerEvidence(ctx, client, servers, orders)

	for i := range orders {
		order := &orders[i]
		if order.ReleasedAt != "" || gigahostbudget.IsLocallyTerminal(order.Status) {
			continue
		}
		obs, seen := observed[order.ID]
		if !seen {
			continue
		}
		verdict := gigahostbudget.Classify(budgetEntries([]GigahostOrderRecord{*order})[0], obs.evidence)

		if !verdict.Releasable {
			if verdict.State == gigahostbudget.StateUnresolved {
				out.unresolved = append(out.unresolved, unresolvedReservation(order, verdict))
			}
			continue
		}

		// Freshness: the observation was made against an identity, and the
		// release must not apply if the record has since changed to a different
		// commitment. The check is passed into the release transaction, which
		// re-reads the row under the write lock, because a check outside the
		// transaction can be invalidated between the check and the write.
		err := h.db.ReleaseGigahostOrderIfCurrent(ctx, order.ID,
			database.ReleaseExpectation{OrderID: obs.orderID, ServerID: obs.serverID},
			verdict.Reason, verdict.Explanation)
		switch {
		case err == nil:
			out.released = append(out.released, order.ID)
		case errors.Is(err, database.ErrGigahostOrderAlreadyReleased):
			// Another pass or another worker released it; nothing to do.
		case errors.Is(err, database.ErrGigahostOrderChanged):
			out.stale = append(out.stale, order.ID)
			out.unresolved = append(out.unresolved, gigahostbudget.Reservation{
				Source:      "ledger",
				RecordID:    order.ID,
				Identity:    order.OrderID,
				Status:      order.Status,
				State:       gigahostbudget.StateUnresolved,
				Reason:      "release_evidence_stale",
				Explanation: "the record changed since it was observed, so the evidence was not applied",
			})
		default:
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
		}
	}
	return out
}

// unresolvedReservation describes a counted reservation for reporting.
func unresolvedReservation(order *GigahostOrderRecord, verdict gigahostbudget.Verdict) gigahostbudget.Reservation {
	return gigahostbudget.Reservation{
		Source:      "ledger",
		RecordID:    order.ID,
		Identity:    order.OrderID,
		Status:      order.Status,
		State:       verdict.State,
		Reason:      verdict.Reason,
		Explanation: verdict.Explanation,
	}
}
