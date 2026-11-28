package handlers

// Refusal of immediate setup for an order whose life the panel has recorded as over.
//
// Two routes reach the same preamble: POST /deploy and POST /orders/{order_id}/setup.
// Both exist because the administrator may be looking at either surface when they start a
// deployment, so both are one entry, and a guard that lived in one of them would leave the
// other reachable.
//
// The order can end while the dialog is open. A provider inventory refresh records a
// complete, own-account omission on the order ledger, and the dialog the administrator is
// already looking at still submits. Removing the button would not have refused that
// request: the form was rendered before the ending was recorded. So the refusal belongs in
// the preamble, before any provider detail read, before SSH is dialed and before anything
// is registered.
//
// The preamble answer is necessary and not sufficient. It is a snapshot: the order can end
// while SSH verification is still waiting on the network, and then registration, protocol
// installation, backend enablement and the ready report would all happen after the panel
// recorded the deployment as gone. Each of those is therefore fenced again at the boundary
// that commits it - refuseRetiredOrderBeforeEffect, below - so the entry refusal keeps the
// common case cheap and the later fences close the window the entry cannot see.
//
// The provider's detail answer is deliberately not consulted. It can still report the order
// ready while the inventory omits it, and that inconsistent pair is exactly the state this
// order-absence record exists to represent; the inventory is the panel's own existence
// observation, so it outranks a stale detail. A deployment the ledger does not hold keeps
// the pre-existing behavior: no row is no observation, and a first-time deployment may
// legitimately have none.

import (
	"context"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

// ErrOrderEnded reports that the order a request names has ended, so no setup work may be
// issued for it. It is a refusal, not a failure: the deployment the request described no
// longer exists at the provider, and the panel has recorded that.
//
// It is the database layer's own refusal, re-exported rather than redeclared: a fence at the
// registration or admission boundary and the entry guard must answer the operator with one
// error, or the HTTP surface would have to grow a second case for the same fact.
var ErrOrderEnded = database.ErrOrderEnded

// orderEndedCode is the closed-set code the refusal answers with, so a caller can
// distinguish "this order is over" from every other conflict on the route.
const orderEndedCode = "order_ended"

// retiredOrderReportStep is the step recorded on the ledger when an immediate setup stops
// because the order ended mid-flight. It names the fact rather than the phase, because the
// phase is what did NOT happen: nothing was installed, enabled or registered.
const retiredOrderReportStep = "order_ended"

// retirementRecheckTimeout bounds the retirement read taken at an effect boundary. It is a
// durable-state question with no network work behind it, and the surrounding step already
// has its own budget, so this only stops a wedged store from hanging the attempt.
const retirementRecheckTimeout = 15 * time.Second

// refuseEndedOrder answers whether this order's life has ended, and returns the refusal to
// report when it has.
//
// The question is asked of the order ledger through the store's IsGigahostOrderRetired,
// which applies models.GigahostOrder.Retired - the one predicate the grid, the history view
// and the saved-jobs list present from. No second copy of the rule exists here, so the
// refusal cannot disagree with the DELETED badge the operator is looking at.
//
// A read failure is returned as an error rather than as consent: the caller is about to do
// remote work, and "could not ask whether this order still exists" must not authorize it.
func (h *Handlers) refuseEndedOrder(ctx context.Context, orderID string) error {
	if h == nil || h.db == nil {
		return nil
	}
	retired, err := h.db.IsGigahostOrderRetired(ctx, orderID)
	if err != nil {
		return fmt.Errorf("failed to read whether order %s has ended: %w", orderID, err)
	}
	if !retired {
		return nil
	}
	return fmt.Errorf("%w: order %s", ErrOrderEnded, orderID)
}

// retirementQuestion asks whether this order has ended, keeping "the panel recorded an ending"
// and "the question could not be answered" as separate answers.
//
// The distinction is the whole point of having two answers. Collapsing a failed read into
// "not ended" is how a caller ends up reporting success for a deployment whose fate it never
// established, and collapsing it into "ended" invents a retirement the panel never recorded.
// Each caller decides its own safe direction from the three outcomes.
func (h *Handlers) retirementQuestion(ctx context.Context, orderID string) (ended, known bool) {
	if h == nil || h.db == nil {
		// No store holds an order at all, which is the pre-existing behavior for a
		// deployment the panel never recorded.
		return false, true
	}
	retired, err := h.db.IsGigahostOrderRetired(ctx, orderID)
	if err != nil {
		return false, false
	}
	return retired, true
}

// refuseRetiredOrderBeforeEffect is the mid-flight form of the entry refusal: it asks the
// same durable question at the boundary that is about to commit an effect, and returns the
// refusal plus the status to report when the order has ended since the request began.
//
// It exists because beginGigahostDeploy's answer is taken once, before any provider read or
// SSH dial, and every step after it can wait on the network for seconds to minutes. A
// retirement committed in that wait is durable state the entry snapshot cannot see, so the
// order question is asked again from the ledger - never from the record loaded at entry -
// immediately before each effect.
//
// The refusal reuses failDeployStatus, so the ledger records why the deployment stopped and
// the endpoint answers the same 409/order_ended a request that arrived late would get. An
// attempt that stopped this way performed no further effect, so reporting the failure here
// describes what actually happened.
func (h *Handlers) refuseRetiredOrderBeforeEffect(
	ctx context.Context,
	req GigahostDeployRequest,
	providerServerID, nexusServerID int64,
	assignedIP, step string,
) (*GigahostDeployStatus, error) {
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), retirementRecheckTimeout)
	defer cancel()
	ended, known := h.retirementQuestion(checkCtx, req.OrderID)
	if ended {
		return h.failDeployStatus(ctx, req.OrderID, retiredOrderReportStep, fmt.Errorf("%w: order %s", ErrOrderEnded, req.OrderID),
			providerServerID, nexusServerID, assignedIP, "", "")
	}
	if !known {
		// "Could not ask" is not permission either. It is reported as a failure rather than
		// as a recorded ending, because the panel has not recorded one.
		return h.failDeployStatus(ctx, req.OrderID, step,
			fmt.Errorf("failed to read whether order %s has ended", req.OrderID),
			providerServerID, nexusServerID, assignedIP, "", "")
	}
	return nil, nil
}
