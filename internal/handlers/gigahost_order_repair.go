package handlers

import (
	"context"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// inventoryServerForOrder never attributes an address to an order. Explicit order
// identity wins; a previously recorded numeric identity also works when order_id
// is absent, but cannot override an explicitly different order.
func inventoryServerForOrder(servers []gigahost.ServerInfo, order *GigahostOrderRecord) (gigahost.ServerInfo, bool) {
	for _, server := range servers {
		if order.OrderID != "" && server.OrderID == order.OrderID {
			return server, true
		}
	}
	for _, server := range servers {
		if server.OrderID == "" && order.ServerID > 0 && server.ID == order.ServerID {
			return server, true
		}
	}
	return gigahost.ServerInfo{}, false
}

func inventoryListsOrderLive(servers []gigahost.ServerInfo, order *GigahostOrderRecord) bool {
	server, found := inventoryServerForOrder(servers, order)
	return found && isGigahostReady(server.Status)
}

// detailPostdatesRepair requires evidence time, not the arrival time of a repeat
// request. Missing/invalid timestamps or conflicting identities cannot undo repair.
func detailPostdatesRepair(order *GigahostOrderRecord, detail *gigahost.DeployStatusResponse) bool {
	if detail.OrderID != order.OrderID {
		return false
	}
	if detail.ServerID > 0 && order.ServerID > 0 && detail.ServerID != order.ServerID {
		return false
	}
	updated, err := time.Parse(time.RFC3339Nano, detail.UpdatedAt)
	return err == nil && updated.After(*order.LiveRepairedAt) && !updated.After(time.Now().UTC())
}

// rememberContradictedDetail advances the durable evidence only for a newly
// contradicted deletion; repeating old detail must not invent a later repair.
func rememberContradictedDetail(order *GigahostOrderRecord, detail *gigahost.DeployStatusResponse) {
	if order.LiveRepairedAt == nil || detailPostdatesRepair(order, detail) {
		now := time.Now().UTC()
		order.LiveRepairedAt = &now
	}
}

// persistOrderObservation refuses an old reader at the write boundary. A failed
// commit must not present its speculative state as durable; reload, never retry
// an observation against a replacement repair fact.
func (h *Handlers) persistOrderObservation(ctx context.Context, order *GigahostOrderRecord, observedRepair *time.Time) error {
	if h.db == nil {
		return nil
	}
	if err := h.db.UpdateGigahostOrderObservation(ctx, order, observedRepair); err != nil {
		if stored, found, readErr := h.db.GetGigahostOrder(ctx, order.OrderID); readErr == nil && found {
			*order = *stored
		}
		return err
	}
	return nil
}
