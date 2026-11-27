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

// detailIdentifiesOrder reports whether this detail answer is about this order. An
// explicit different order id, or a different positive server id, is somebody else's
// answer and cannot decide anything here.
func detailIdentifiesOrder(order *GigahostOrderRecord, detail *gigahost.DeployStatusResponse) bool {
	if detail.OrderID != order.OrderID {
		return false
	}
	return detail.ServerID == 0 || order.ServerID == 0 || detail.ServerID == order.ServerID
}

// detailEvidenceTime returns the provider's own evidence time for this answer. A missing
// or unreadable timestamp is not evidence at any instant.
func detailEvidenceTime(detail *gigahost.DeployStatusResponse) (time.Time, bool) {
	updated, err := time.Parse(time.RFC3339Nano, detail.UpdatedAt)
	return updated, err == nil
}

// detailPostdatesRepair requires evidence time, not the arrival time of a repeat
// request. Missing/invalid timestamps or conflicting identities cannot undo repair.
func detailPostdatesRepair(order *GigahostOrderRecord, detail *gigahost.DeployStatusResponse) bool {
	if !detailIdentifiesOrder(order, detail) {
		return false
	}
	updated, ok := detailEvidenceTime(detail)
	return ok && updated.After(*order.LiveRepairedAt) && !updated.After(time.Now().UTC())
}

// rememberContradictedDetail records the affirmative inventory observation that
// contradicted a deletion, stamped with the instant that observation was requested.
//
// The stamp is the evidence a later deletion has to beat, so it must be the observation's
// own temporal boundary and never the moment this detail answer was processed. Processing
// time claims more than the listing can: the provider can remove the server while the
// request that took the listing is in flight, so a deletion with evidence after the
// listing but before this code ran would be judged older than the "observation" that
// contradicts it. Every later complete omission would then defer that real ending, and
// the row would stay Ready with its setup actions offered for good.
//
// A detail whose evidence postdates the observation is therefore not contradicted by it:
// the stored repair is left exactly where it is so the ending stays recordable. A detail
// at or before the observation is one that listing already answered, so the observation
// becomes the durable repair.
func rememberContradictedDetail(order *GigahostOrderRecord, detail *gigahost.DeployStatusResponse, observedAt time.Time) {
	if updated, ok := detailEvidenceTime(detail); ok && detailIdentifiesOrder(order, detail) && updated.After(observedAt) {
		return
	}
	if order.LiveRepairedAt == nil || detailPostdatesRepair(order, detail) {
		repair := observedAt.UTC()
		order.LiveRepairedAt = &repair
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
