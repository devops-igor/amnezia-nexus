package handlers

// The durable existence record, read back for the order list.
//
// The panel records the provider's own server inventory on the server row this order
// registered (servers.provider_absent_at), and that column is the one fact the
// inventory pass writes when it concludes a server is gone. The order list already
// says what the provider answered about each order, but it said nothing about the
// panel's own record, so the Recent Deployments view had to learn it from the
// per-order deploy read - a second request that can fail. A failing detail read then
// returned a deletion to the ordinary treatment: the row lost its DELETED stage,
// regained the contact actions that stage suppresses, and an older deleted row fell
// out of the list's five-row window because its stage no longer read as deleted.
//
// This file answers that question inside the list response instead, from exactly the
// column the reconciliation writes. It reads; it decides nothing about absence and
// performs no provider call.

import (
	"context"
	"strings"
)

// gigahostOrderAbsenceMarks reports, per order id, whether the panel's durable record
// marks the server this order registered as gone.
//
// Only orders the record marks appear in the result. A missing key and a false value
// are the same answer - the ordinary treatment - because absence is a positive
// observation: a failed read of the column, an order that registered no panel server
// and a server nobody marked absent all mean "not absent", never a guess.
func (h *Handlers) gigahostOrderAbsenceMarks(ctx context.Context, orders []GigahostOrderRecord) map[string]bool {
	marks := make(map[string]bool, len(orders))
	absent, err := h.providerAbsentServerIDs(ctx)
	if err != nil {
		// An unanswered read is not an absence observation.
		return marks
	}
	for i := range orders {
		if h.gigahostOrderRegisteredAbsent(ctx, &orders[i], absent) {
			marks[orders[i].OrderID] = true
		}
	}
	return marks
}

// providerAbsentServerIDs reads the recorded existence marks as a set of panel server
// ids. A panel with no database answers with no marks, which is the same answer as a
// panel that has recorded none.
func (h *Handlers) providerAbsentServerIDs(ctx context.Context) (map[int64]struct{}, error) {
	if h == nil || h.db == nil {
		return nil, nil
	}
	ids, err := h.db.ListProviderAbsentServerIDs(ctx)
	if err != nil {
		return nil, err
	}
	absent := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		absent[id] = struct{}{}
	}
	return absent, nil
}

// gigahostOrderRegisteredAbsent reports whether the server this order registered is in
// the recorded set. The registered server is resolved through the same helper the
// deploy read uses, so the list and the detail cannot disagree about which row an order
// registered. An order with no order id and no registered server answers "not absent".
func (h *Handlers) gigahostOrderRegisteredAbsent(
	ctx context.Context, order *GigahostOrderRecord, absent map[int64]struct{},
) bool {
	if order == nil || strings.TrimSpace(order.OrderID) == "" || len(absent) == 0 {
		return false
	}
	serverID := h.registeredServerIDForOrder(ctx, order.OrderID, order.NexusServerID)
	if serverID <= 0 {
		return false
	}
	_, gone := absent[serverID]
	return gone
}
