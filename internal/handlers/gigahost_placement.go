package handlers

// Explicit datacenter placement for manual hourly Gigahost orders.
//
// The provider documents two placement shapes for POST /deploy/servers, and this
// file owns the decision for the second one:
//
//   - provider-chosen: you pass region_id and "we place the server in any
//     datacenter in that region" (validatePlanRegion still owns that check);
//   - pinned: you pass dc_id and "the datacenter must be one of the product's
//     dc_ids". If the pinned datacenter is sold out while others have capacity
//     the provider FAILS the request rather than going to the waitlist, and for a
//     built-to-order dedicated server dc_id is IGNORED and the server is placed
//     anywhere in the region.
//
// Those two documented behaviors are why this validator exists and refuses
// before the purchase instead of relying on the provider:
//
//   - a silently ignored dc_id is a silent replacement location, which the
//     accepted contract forbids, so an explicit choice on a built-to-order plan
//     is refused here rather than bought somewhere else;
//   - a sold-out pinned datacenter is refused here so the operator learns why
//     before any money-moving request, with no fallback to region-only.
//
// Every branch is a pre-purchase refusal: the caller (validateOrderAgainstCatalog)
// runs inside orderEligibilityAdmission, ahead of the durable intent and ahead of
// any provider order call, and handleCatalogCheckError answers it as a 400.

import (
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// validatePlanPlacement enforces the documented explicit-placement contract for
// a request that pinned a datacenter. A request without dc_id is provider-chosen
// placement and is untouched here, so region-only ordering keeps its existing
// semantics exactly.
//
// The datacenter must be listed by this plan, resolvable to a documented region
// the plan serves, matching the requested region, explicitly in stock, and the
// plan must be orderable in a way the provider honors dc_id for. Each failure
// names its own reason, because "unknown datacenter", "not offered here",
// "sold out" and "cannot be pinned" need different operator action.
func validatePlanPlacement(plan *gigahost.HourlyPlan, req OrderServerPayload) error {
	if req.DCID <= 0 {
		return nil
	}

	dc, ok := placementDatacenter(plan, req.DCID)
	if !ok {
		return fmt.Errorf("invalid_plan: datacenter %d is not offered for plan %d", req.DCID, req.PID)
	}
	if dc.RegionID <= 0 {
		// dc_ids listed an id with no datacenter record: its region relationship
		// is unproven, so it can never be used as a placement.
		return fmt.Errorf("invalid_plan: datacenter %d has no documented region for plan %d", req.DCID, req.PID)
	}
	if !planServesRegion(plan, dc.RegionID) {
		return fmt.Errorf("invalid_plan: datacenter %d is in region %d, which plan %d does not serve",
			req.DCID, dc.RegionID, req.PID)
	}
	if req.RegionID != dc.RegionID {
		return fmt.Errorf("invalid_plan: datacenter %d is in region %d, not the requested region %d",
			req.DCID, dc.RegionID, req.RegionID)
	}
	if plan.BuiltToOrder {
		// Documented: "For a dedicated server that is built to order, dc_id is
		// ignored and the server is placed within the region." Ordering anyway
		// would place the server somewhere the operator did not choose.
		return fmt.Errorf("invalid_plan: plan %d is built to order and cannot be pinned to datacenter %d",
			req.PID, req.DCID)
	}
	if dc.InStock == nil {
		return fmt.Errorf("invalid_plan: stock for datacenter %d is not reported for plan %d, so it cannot be selected",
			req.DCID, req.PID)
	}
	if !dc.Stocked() {
		return fmt.Errorf("invalid_plan: datacenter %d is out of stock for plan %d", req.DCID, req.PID)
	}
	return nil
}

// placementDatacenter returns the plan's own record of a datacenter.
func placementDatacenter(plan *gigahost.HourlyPlan, dcID int) (gigahost.Datacenter, bool) {
	for _, dc := range plan.Datacenters {
		if dc.ID == dcID {
			return dc, true
		}
	}
	return gigahost.Datacenter{}, false
}

// planServesRegion reports whether the plan documents availability in a region.
// A plan that carries no region list has no proven availability anywhere, which
// validatePlanRegion already refuses for the requested region; here it also means
// no datacenter's region can be confirmed.
func planServesRegion(plan *gigahost.HourlyPlan, regionID int) bool {
	for _, r := range plan.Regions {
		if r.ID == regionID && r.Available {
			return true
		}
	}
	return false
}
