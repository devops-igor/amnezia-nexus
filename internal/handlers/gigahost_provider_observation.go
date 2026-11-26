package handlers

import (
	"context"
	"errors"
	"net/http"
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

// gigahostObservationClientUnavailable is the diagnostic reported when the provider
// client could not be resolved for a list request.
//
// It is a fixed string on purpose. The resolution error can come from API-key
// validation, which reports the offending character of a rejected key; echoing that
// error into a response body would publish a fragment of configured material. The
// operator needs to know the provider was unreachable, not which byte was wrong.
const gigahostObservationClientUnavailable = "gigahost provider client unavailable"

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

// confirmed reports whether this observation states a provider-confirmed status.
//
// It answers both precedence questions this file asks, because they are the same
// question: a confirmation is the only thing a less specific read may not displace, and
// it is the only thing a later read that failed may not invalidate.
func (o GigahostProviderObservation) confirmed() bool {
	return o.Outcome == gigahostObservationConfirmed
}

// authoritativeTerminal reports whether this observation is a provider answer that ends the
// order's life - as opposed to a confirmed status that merely reports progress.
//
// It exists for one case: when the inventory read failed, the read as a whole is "the provider
// was not fully reachable", so an ordinary confirmation must not clear the stale state. An
// explicit terminal answer about the order itself is different in kind - the provider has told
// us how the deployment ended - and suppressing it would lose real information. Only the
// provider's own terminal spelling qualifies; `ready` and `deploying` are progress, not ends.
func (o GigahostProviderObservation) authoritativeTerminal() bool {
	if o.Outcome != gigahostObservationConfirmed {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(o.Status), statusCancelled)
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

// gigahostProviderServerLive reports whether the inventory lists a live server for this
// order, i.e. a match whose provider status is not a terminal one.
//
// It answers a narrower question than gigahostProviderServerStatus on purpose. A row may
// legitimately be terminal in the panel while the provider still lists it, so "the
// inventory mentions this order" alone is not enough to argue against a cancellation -
// only a match that the provider itself reports as live is.
func gigahostProviderServerLive(servers []gigahost.ServerInfo, orderID string) bool {
	status, ok := gigahostProviderServerStatus(servers, orderID)
	if !ok {
		return false
	}
	return !isTerminalStatus(status)
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
	inventoryKnown := serversErr == nil
	if !inventoryKnown {
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
			if observation, spoke := h.repairDeletedOrderFromInventory(ctx, servers, inventoryKnown, &orders[i]); spoke {
				observations[orders[i].OrderID] = observation
			}
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
				rowUpdated, obs := h.refreshOrderFromDeployStatus(ctx, client, &orders[i], servers, inventoryKnown)
				if rowUpdated {
					updated = true
				}
				// The order detail is the more specific read, so a confirmed answer from
				// it outranks the inventory answer for the same order. A failed or silent
				// detail read does not: the inventory already established a real provider
				// status for this order, and overwriting it with "unavailable" would mark
				// a confirmed order stale and refuse to advance its confirmed check time.
				//
				// The exception is when the inventory itself could not be read: then the
				// provenance of this whole read is "the provider was not fully reachable",
				// and a confirmation from the detail alone must not erase that, because the
				// view has to stay visibly stale and keep its last confirmed time.
				if inventoryKnown && (obs.confirmed() || !observations[orders[i].OrderID].confirmed()) {
					observations[orders[i].OrderID] = obs
				} else if !inventoryKnown && obs.authoritativeTerminal() {
					// An explicit terminal status is a real provider answer about the order
					// itself, so it still applies even while the inventory read failed.
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

// gigahostListObservations answers, per order, what the list request could prove about the
// provider. Every order starts at "no read was attempted", which is the truth for a terminal
// row; a resolution failure or the real reads then overwrite that where they can say more.
//
// It lives here rather than in the handler so the handler stays a handler and the accounting
// rules stay in one file. A failure to resolve the provider client is reported as
// unavailable for every non-terminal order, because the provider was not "not asked" - it
// could not be reached - and leaving it at not_checked would let a stale ledger row display
// with no warning. Terminal rows keep not_checked, since re-reading them changes nothing.
func (h *Handlers) gigahostListObservations(
	ctx context.Context, r *http.Request, orders []GigahostOrderRecord,
) map[string]GigahostProviderObservation {
	observations := make(map[string]GigahostProviderObservation, len(orders))
	for i := range orders {
		observations[orders[i].OrderID] = GigahostProviderObservation{Outcome: gigahostObservationNotChecked}
	}

	client, clientErr := h.getGigahostClient(ctx, r)
	if clientErr != nil {
		for i := range orders {
			if isTerminalStatus(orders[i].Status) {
				continue
			}
			observations[orders[i].OrderID] = GigahostProviderObservation{
				Outcome: gigahostObservationUnavailable,
				Error:   gigahostObservationClientUnavailable,
			}
		}
		return observations
	}
	if len(orders) == 0 {
		return observations
	}
	return h.gigahostOrderObservations(ctx, client, orders)
}

// isDeletedStatus reports the one terminal vocabulary that claims the *server* is gone,
// as opposed to an order that ended while its VPS could still be running.
//
// The distinction decides whether a later affirmative inventory listing may repair a
// recorded ending: a deletion recorded by the provider is the panel's copy of an
// observation about the server, and a server the provider now lists is a correction of
// that observation. A cancellation or a failure is the order's outcome, which an
// inventory read cannot decide and must not overwrite.
func isDeletedStatus(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == "deleted" || s == "terminated"
}

// repairDeletedOrderFromInventory applies this response's inventory to a terminal row
// whose recorded ending is a deletion.
//
// A terminal row is not asked about again through the order detail: the order has ended,
// and re-reading an ended order changes nothing. The inventory read is different in kind -
// this response already made it for every order - and an entry that names this order as
// live is an affirmative answer about the same deployed server.
//
// Only a recorded DELETION is repaired this way, because it is the one terminal value that
// claims the server is gone: the panel's copy of that observation is what a live listing
// corrects. A cancellation or a failure is the order's own outcome, which an inventory read
// cannot decide and must not overwrite. Without the deletion case the row kept its value
// forever, because the next list read skipped it as terminal before consulting the
// inventory again, while the server itself had already returned to the grid. An inventory
// that failed, or that does not mention this order, changes nothing, so an unknown read is
// never rendered as presence.
//
// It reports the observation and whether the inventory spoke about this row at all.
func (h *Handlers) repairDeletedOrderFromInventory(
	ctx context.Context, servers []gigahost.ServerInfo, inventoryKnown bool, order *GigahostOrderRecord,
) (GigahostProviderObservation, bool) {
	if !isDeletedStatus(order.Status) || !inventoryKnown || !gigahostProviderServerLive(servers, order.OrderID) {
		return GigahostProviderObservation{}, false
	}
	updated := h.refreshOrderFromServers(servers, order)
	observation := GigahostProviderObservation{Outcome: gigahostObservationNotChecked}
	if status, ok := gigahostProviderServerStatus(servers, order.OrderID); ok {
		observation = GigahostProviderObservation{Outcome: gigahostObservationConfirmed, Status: status}
	}
	if updated {
		_ = h.updateGigahostOrder(ctx, order)
	}
	return observation, true
}

func (h *Handlers) refreshOrderFromServers(servers []gigahost.ServerInfo, order *GigahostOrderRecord) bool {
	for _, s := range servers {
		if s.OrderID != "" && s.OrderID == order.OrderID {
			updated := false
			if s.Status != "" && s.Status != order.Status && !strings.EqualFold(s.Status, "active") {
				if isTerminalStatus(s.Status) || !isPendingOrInFlight(order.Status) {
					order.Status = s.Status
					updated = true
				}
			}
			if s.ID > 0 && order.ServerID != s.ID {
				order.ServerID = s.ID
				updated = true
			}
			if ip := s.GetIP(); ip != "" && ip != order.AssignedIP {
				order.AssignedIP = ip
				updated = true
			}
			return updated
		}
	}
	return false
}

// refreshOrderFromDeployStatus refreshes one order from the provider's order detail
// and reports both whether the row changed and what the provider actually answered.
//
// The two are different questions: a provider that repeats the status already on the
// row changed nothing, yet it is still the freshest confirmation the panel has. Only
// the returned observation may be presented as a provider read.
//
// live is the inventory already read for this request, and inventoryKnown says whether that
// read succeeded. Together they decide one thing - whether a "no such order" answer may be
// trusted as a cancellation. An inventory that could not be read is not evidence that the
// order is gone, so it must not be allowed to stand in for absence.
func (h *Handlers) refreshOrderFromDeployStatus(ctx context.Context, client gigahost.Client, order *GigahostOrderRecord, live []gigahost.ServerInfo, inventoryKnown bool) (bool, GigahostProviderObservation) {
	if strings.HasPrefix(order.OrderID, "unknown_") || strings.HasPrefix(order.OrderID, "intent_") || order.OrderID == "" {
		return false, GigahostProviderObservation{Outcome: gigahostObservationNotChecked}
	}
	statusResp, deployErr := client.GetDeployStatus(ctx, order.OrderID)
	if deployErr == nil {
		updated := false
		if statusResp != nil && statusResp.Status != "" && statusResp.Status != order.Status {
			order.Status = statusResp.Status
			updated = true
		}
		/* An answer that carries no status is not a cancellation.
		 *
		 * The provider's decoder accepts an empty body (`{}`, or an empty
		 * data.servers[] envelope) into a zero response with no error, so "the provider
		 * answered and there is no such deployment" is indistinguishable here from "the
		 * provider answered with nothing useful". Treating the absent status as a
		 * cancellation therefore turned a live, inventory-confirmed ready row into a
		 * durable terminal one: the row was persisted with the terminal value, and the
		 * next list read skipped it as terminal, so continued positive inventory could
		 * never repair it.
		 *
		 * Genuine termination still reaches this row by a non-empty provider status (above)
		 * or by ErrNotFound (below), so nothing is lost by not inventing a terminal state
		 * from silence. This branch used to claim the opposite; it was wrong. */
		if statusResp != nil {
			if ip := statusResp.GetIP(); ip != "" && ip != order.AssignedIP {
				order.AssignedIP = ip
				updated = true
			}
			if statusResp.ServerID > 0 && order.ServerID != statusResp.ServerID {
				order.ServerID = statusResp.ServerID
				updated = true
			}
		}
		observation := GigahostProviderObservation{Outcome: gigahostObservationUnconfirmed}
		if statusResp != nil {
			if status := strings.TrimSpace(statusResp.Status); status != "" {
				observation = GigahostProviderObservation{Outcome: gigahostObservationConfirmed, Status: status}
			}
			observation.Error = statusResp.Error
		}
		return updated, observation
	}
	if errors.Is(deployErr, gigahost.ErrNotFound) && (order.Status == gigahost.StatusReady || strings.ToLower(order.Status) == "active") {
		/* "No such order" only means cancellation when the inventory could corroborate it.
		 *
		 * The inventory read is what distinguishes "the provider no longer has this order"
		 * from "I could not find out": it either names the order (live, or with the
		 * provider's own terminal status), or it answered and named nobody. When the
		 * inventory read FAILED, none of those is true, and the terminal value would be
		 * sticky here - the next list read skips a terminal row before consulting the
		 * inventory again, so an ordinary 503 would strand a live order in the terminal state
		 * forever. Report the gap instead and leave the row live, so the next read can
		 * repair it. */
		if !inventoryKnown {
			return false, GigahostProviderObservation{
				Outcome: gigahostObservationUnavailable,
				Error:   "provider inventory could not be read, so a missing deployment record is not evidence of cancellation",
			}
		}
		// Only a cancellation nothing contradicts: live inventory for this order means the
		// missing detail record is a partial read failure, and the terminal value would be
		// sticky, so later reads would skip the row and inventory could never repair it.
		if gigahostProviderServerLive(live, order.OrderID) {
			return false, GigahostProviderObservation{
				Outcome: gigahostObservationUnconfirmed,
				Error:   "provider has no detail record for this order while inventory still lists it",
			}
		}
		order.Status = statusCancelled
		return true, GigahostProviderObservation{Outcome: gigahostObservationConfirmed, Status: statusCancelled}
	}
	return false, GigahostProviderObservation{Outcome: gigahostObservationUnavailable, Error: deployErr.Error()}
}
