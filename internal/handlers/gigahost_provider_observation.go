package handlers

import (
	"context"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// The Gigahost order list answers with the panel's own rows whether or not the
// provider could be reached: the rows are the panel's copy of the last answer, and
// that is deliberate, so an outage does not blank the page. What the rows cannot say
// is whether they are a fresh provider answer or an old copy. The observations below
// are the additive, read-only answer to that question for one list response, so a
// consumer can label ledger-only or unreachable data instead of presenting it as a
// confirmed provider state.
//
// This file only reads. It performs the same provider calls the list always performed
// and records what they answered; it decides nothing about provisioning and writes no
// state of its own beyond the row refresh the handler already did.

// Provider observation outcomes for one order in one list response.
const (
	// gigahostObservationConfirmed: the provider answered for this order in this
	// response, so Status is the provider's own spelling.
	gigahostObservationConfirmed = "confirmed"
	// gigahostObservationUnconfirmed: a provider read returned no usable status. An
	// answer that says nothing is not evidence of anything.
	gigahostObservationUnconfirmed = "unconfirmed"
	// gigahostObservationUnavailable: the provider read failed for this order.
	gigahostObservationUnavailable = "unavailable"
	// gigahostObservationNotChecked: no provider read was attempted, because the
	// recorded state is terminal and re-reading it would not change the outcome.
	gigahostObservationNotChecked = "not_checked"
)

// GigahostProviderObservation states what one list response can prove about the
// provider for one order. It is additive metadata: the order rows keep their existing
// shape and meaning, so a consumer that ignores this key sees the previous response.
type GigahostProviderObservation struct {
	Outcome string `json:"outcome"`
	// Status is the provider's own status spelling, present only when Outcome is
	// confirmed. It is never the onboarding journal vocabulary.
	Status string `json:"status,omitempty"`
	// Error is what the provider reported when it failed, so a consumer can show the
	// reason rather than only the fact.
	Error string `json:"error,omitempty"`
}

// settled reports whether a provider read was attempted at all. Only an attempted and
// failed read makes displayed state stale; a terminal order that is deliberately not
// re-read is not a read failure.
func (o GigahostProviderObservation) settled() bool {
	return o.Outcome != ""
}

// gigahostProviderServerStatus returns the provider's own status for an order from an
// already-fetched server inventory. A match without a status is not an answer, so it is
// reported as absent rather than as a confirmation.
func gigahostProviderServerStatus(servers []gigahost.ServerInfo, orderID string) (string, bool) {
	if orderID == "" {
		return "", false
	}
	for _, s := range servers {
		if s.OrderID != "" && s.OrderID == orderID {
			if s.Status == "" {
				return "", false
			}
			return s.Status, true
		}
	}
	return "", false
}

// isRefreshableOrderID reports an order id the provider can be asked about. A ledger
// placeholder never resolved into a provider order, so asking about it would invent a
// read that cannot answer.
func isRefreshableOrderID(orderID string) bool {
	return orderID != "" &&
		!strings.HasPrefix(orderID, "unknown_") &&
		!strings.HasPrefix(orderID, "intent_")
}

// gigahostOrderObservations performs the list's provider reads and records what each
// one actually answered, per order. The rows are modified in place exactly as before;
// the returned map is the only new fact.
func (h *Handlers) gigahostOrderObservations(
	ctx context.Context, client gigahost.Client, orders []GigahostOrderRecord,
) map[string]GigahostProviderObservation {
	// Every order starts at "no read was attempted", which is the truth for a terminal
	// row and the base each successful read below overwrites.
	observations := make(map[string]GigahostProviderObservation, len(orders))
	for i := range orders {
		observations[orders[i].OrderID] = GigahostProviderObservation{Outcome: gigahostObservationNotChecked}
	}

	servers, serversErr := client.GetServers(ctx)
	if serversErr != nil {
		// An inventory that could not be read answers for nobody. Every non-terminal
		// order it would have covered is reported unavailable, which is the one thing
		// the failure does establish.
		for i := range orders {
			if !isTerminalStatus(orders[i].Status) {
				observations[orders[i].OrderID] = GigahostProviderObservation{
					Outcome: gigahostObservationUnavailable,
					Error:   serversErr.Error(),
				}
			}
		}
	}

	deployQueries := 0
	const maxDeployQueries = 10
	for i := range orders {
		if isTerminalStatus(orders[i].Status) {
			continue
		}
		updated := false
		if len(servers) > 0 && h.refreshOrderFromServers(servers, &orders[i]) {
			updated = true
		}
		// An inventory entry naming this order with a status is a provider answer,
		// whether or not it changed the row.
		if status, ok := gigahostProviderServerStatus(servers, orders[i].OrderID); ok {
			observations[orders[i].OrderID] = GigahostProviderObservation{
				Outcome: gigahostObservationConfirmed,
				Status:  status,
			}
		}
		if (isPendingOrInFlight(orders[i].Status) || !updated) && deployQueries < maxDeployQueries {
			if isRefreshableOrderID(orders[i].OrderID) {
				deployQueries++
				rowUpdated, obs := h.refreshOrderFromDeployStatus(ctx, client, &orders[i])
				if rowUpdated {
					updated = true
				}
				// The order detail is the more specific read, so it outranks the
				// inventory answer for the same order.
				if obs.settled() {
					observations[orders[i].OrderID] = obs
				}
			}
		}
		if updated {
			_ = h.updateGigahostOrder(ctx, &orders[i])
		}
	}
	return observations
}
