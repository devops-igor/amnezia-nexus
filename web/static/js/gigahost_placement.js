/* Datacenter placement choices for a Gigahost order.
 *
 * The provider documents two placement shapes for POST /deploy/servers:
 * region_id alone means "place the server in any datacenter in that region",
 * and dc_id alone pins it to one datacenter, with the region taken from the
 * datacenter. This module owns the second choice and keeps the first one intact.
 *
 * Three rules shape everything here, and each of them exists because the
 * provider's own catalog can say something it cannot act on:
 *
 *  1. A datacenter is selectable only on positive evidence: a positive id the
 *     plan lists, that resolves to a datacenter record in the region the operator
 *     chose, whose stock is explicitly true. Anything less is shown, explained
 *     and refused, never pre-selected.
 *  2. "Unknown" is not "sold out" and neither is "available". The catalog omits a
 *     dc_stock entry when it has no fact; an absent fact cannot justify pinning a
 *     paid purchase to one location, so unknown datacenters stay disabled while a
 *     whole region with unknown stock stays orderable through region-only
 *     placement.
 *  3. A pin never degrades silently. If the plan or region changes, or the pinned
 *     datacenter disappears or loses its stock, the choice is cleared and the
 *     operator must choose again. Falling back to region-managed placement would
 *     place a server somewhere they did not pick.
 *
 * This module renders choices and reports state. It does not post the order: the
 * page owns the request, and reads the pin from placementPayloadField below.
 */

/* placementRegionManagedValue is the value of the region-managed choice. It is
 * deliberately not a number: every real datacenter id is a positive integer, so
 * one string sentinel keeps "let the provider choose" from ever colliding with a
 * provider id, including id 0 or a malformed id. */
const placementRegionManagedValue = 'region';

/* placementChoices builds the placement options for one plan and region.
 *
 * The returned object is plain data so it can be asserted without a DOM and
 * rendered without re-deriving anything:
 *
 *   managed   the region-managed option, always first and always offered
 *   options   the plan's datacenters in the plan's own order, each with its own
 *             eligibility and the reason it is or is not selectable
 *   note      why no explicit datacenter can be chosen, when the reason is about
 *             the plan or the region as a whole rather than one datacenter
 */
function placementChoices(plan, regionId) {
    const managed = {value: placementRegionManagedValue, managed: true, label: _('deploy_vps_placement_region')};
    if (!plan) return {managed, options: [], note: _('deploy_vps_no_plans')};

    const region = placementRegion(plan, regionId);
    if (!region) {
        return {managed, options: [], note: _('deploy_vps_placement_region_required')};
    }
    const datacenters = plan.datacenters || [];
    if (datacenters.length === 0) {
        // The provider published no datacenter for this plan at all. That is a
        // real answer - region-managed placement is the only documented choice -
        // and not a failure, so it gets its own message rather than looking like
        // a missing catalog.
        return {managed, options: [], note: _('deploy_vps_placement_none')};
    }

    const options = datacenters.map((dc, index) => placementOption(plan, region, dc, index));
    let note = '';
    if (options.every(o => !o.selectable)) {
        // Distinguish "this plan can never be pinned" from "nothing happens to be
        // in stock": the first is a documented unsupported choice, the second may
        // change on the next catalog read.
        note = plan.built_to_order
            ? _('deploy_vps_placement_built_to_order')
            : _('deploy_vps_placement_none_in_stock');
    }
    return {managed, options, note};
}

/* placementRegion finds the plan's own record for the chosen region.
 *
 * A region the plan does not list is not a region this plan may deploy in, so no
 * datacenter in it can be pinned either. Availability is checked on the same
 * documented fact the order path checks: region_ids membership.
 */
function placementRegion(plan, regionId) {
    const wanted = Number(regionId);
    if (!Number.isInteger(wanted) || wanted <= 0) return null;
    const regions = plan.regions || [];
    for (const r of regions) {
        if (Number(r.id) === wanted && r.available) return r;
    }
    return null;
}

/* placementOption classifies one datacenter of the plan.
 *
 * index is the entry's position in the plan's list, and it is what an unreadable
 * id is labelled with. Such a choice must never carry the empty value: to a
 * selector, '' means "no choice made", which would let a malformed entry be
 * ordered as region-managed placement - a silent location change behind a
 * datacenter label. A distinct non-numeric value keeps it explicit and therefore
 * refusable.
 *
 * The order of the checks is the explanation order: an identity problem is
 * reported before a stock problem, because an operator who picked the wrong
 * datacenter should not be told it is sold out.
 */
function placementOption(plan, region, dc, index) {
    const id = Number(dc && dc.id);
    const base = {
        value: String(id),
        managed: false,
        id: Number.isInteger(id) && id > 0 ? id : null,
        name: (dc && dc.name) || '',
        location: (dc && dc.location) || '',
        country: (dc && dc.country) || '',
        selectable: false,
        reason: ''
    };

    if (!base.id) {
        // An id the catalog could not read as a positive integer identifies
        // nothing. It is listed so the provider's own entry is visible, and it
        // carries an explicit non-numeric value so it can never be sent as a
        // guessed target nor mistaken for an unmade choice.
        base.value = 'invalid-' + index;
        base.reason = _('deploy_vps_placement_invalid_id');
        return base;
    }
    if (plan.built_to_order) {
        // Documented: for a built-to-order dedicated server dc_id is ignored and the
        // server is placed within the region. Offering the pin would promise a
        // location the provider will not honour.
        base.reason = _('deploy_vps_placement_built_to_order');
        return base;
    }
    if (Number(dc.region_id) !== Number(region.id)) {
        base.reason = _('deploy_vps_placement_wrong_region');
        return base;
    }
    if (dc.in_stock === null || dc.in_stock === undefined) {
        base.reason = _('deploy_vps_placement_stock_unknown');
        return base;
    }
    if (dc.in_stock !== true) {
        base.reason = _('deploy_vps_placement_out_of_stock');
        return base;
    }
    base.selectable = true;
    return base;
}

/* placementLabel is the text shown for one choice.
 *
 * The region-managed choice is labelled as the distinct placement it is, and a
 * datacenter's label carries its location so two datacenters in one region remain
 * distinguishable to the operator.
 */
function placementLabel(choice) {
    if (!choice) return '';
    if (choice.managed) return choice.label;
    const parts = [choice.name || String(choice.id)];
    if (choice.location) parts.push(choice.location);
    else if (choice.country) parts.push(choice.country);
    let label = parts.join(' - ');
    if (choice.reason) label += ' (' + choice.reason + ')';
    return label;
}

/* placementSelection decides what the placement selector may hold.
 *
 * previous is the value the selector carried before this rebuild. It survives
 * only when it still names a selectable datacenter of the new plan and region;
 * every other case - nothing chosen yet, a plan or region change, a vanished
 * datacenter, lost stock, an unknown or malformed id - resolves to the
 * region-managed choice and reports why, so the caller can tell the operator that
 * the pin was dropped instead of letting a location change under them.
 */
function placementSelection(choices, previous) {
    if (!choices) return {value: placementRegionManagedValue, cleared: false, reason: ''};
    const wanted = previous === undefined || previous === null ? '' : String(previous);
    if (wanted === '' || wanted === placementRegionManagedValue) {
        return {value: placementRegionManagedValue, cleared: false, reason: ''};
    }
    for (const option of choices.options) {
        if (option.selectable && option.value === wanted) {
            return {value: wanted, cleared: false, reason: ''};
        }
    }
    // The previous choice is no longer valid. Say which way it went, because
    // "sold out" and "no longer offered" need different operator responses, and
    // neither may be swallowed by a silent move to region-managed placement.
    let reason = _('deploy_vps_placement_choice_cleared');
    for (const option of choices.options) {
        if (option.value === wanted) { reason = option.reason; break; }
    }
    return {value: placementRegionManagedValue, cleared: true, reason};
}

/* placementPayloadField returns the placement half of an order payload.
 *
 * A valid explicit choice returns {dc_id} and no region_id: the provider takes the
 * region from the datacenter, and the documented shape for a pinned order omits it.
 * Region-managed placement returns {region_id} and no dc_id, which is exactly the
 * payload this page sent before datacenter placement existed.
 *
 * A choice that cannot be sent returns null rather than a guess. That includes an
 * id that is absent, unparseable or not selectable right now: the caller must stop
 * the order, not place it somewhere else.
 */
function placementPayloadField(choices, value, regionId) {
    const region = Number(regionId);
    if (!Number.isInteger(region) || region <= 0) return null;
    if (value === undefined || value === null || value === '' || String(value) === placementRegionManagedValue) {
        return {region_id: region};
    }
    if (!choices) return null;
    const wanted = String(value);
    for (const option of choices.options) {
        if (option.value === wanted && option.selectable) {
            return {dc_id: option.id};
        }
    }
    return null;
}

/* placementIsExplicit reports whether a selector value names a datacenter pin
 * rather than region-managed placement. It says nothing about validity: an
 * unselectable pin is still explicit, which is what a caller needs to know in
 * order to refuse it. */
function placementIsExplicit(value) {
    return value !== undefined && value !== null && value !== '' && String(value) !== placementRegionManagedValue;
}
