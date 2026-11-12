package web

// Datacenter placement module: behavioural JSDOM test (#739 B1).
//
// This file executes the SHIPPED module web/static/js/gigahost_placement.js as
// a static asset (read through StaticFS, not extracted from a template), so the
// assertions describe the file the browser will load. The fixtures are the
// committed provider DTO shape: a plan carries regions[] and
// datacenters[]{id,name,region_id,location,country,in_stock}, where in_stock is
// true, false, or null for unknown, plus built_to_order.
//
// The controls are deliberately paired. For every "a valid pin is offered" claim
// there is a neighbouring case that must refuse: an unknown stock is not a sold
// out stock, a built-to-order plan cannot be pinned at all, a stale pin must not
// survive a plan or region change, and a malformed id must never reach a payload.
//
// Scope note, stated so this test is not overread: it proves the module's own
// choices, clearing rules and payload contract. It does NOT prove that
// settings.html is wired to them - that page is owned by other in-flight work and
// its integration is the next checkpoint.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// placementTestFixtures is the JSDOM-side fixture set: the committed DTO shape
// with multiple regions and multiple datacenters per region.
const placementTestFixtures = `
// planNorth: two regions. Region 1 holds DC1 (in stock), DC2 (sold out) and DC4
// (stock unknown - the provider sent no dc_stock entry). Region 2 holds DC3,
// which is in stock but in a different region, so pinning it while region 1 is
// chosen must be refused.
const planNorth = {
  product_id: 101, price_id: 555, name: 'Cloud 2', type: 'vm',
  built_to_order: false, in_stock: true,
  currency: 'NOK', hourly_rate_nok: 0.14375, monthly_ceiling_nok: 90,
  regions: [
    {id: 1, name: 'Norway', country: 'NO', available: true, in_stock: true},
    {id: 2, name: 'Sweden', country: 'SE', available: true, in_stock: true}
  ],
  datacenters: [
    {id: 1, name: 'DC1', region_id: 1, location: 'Sandefjord', country: 'NO', in_stock: true},
    {id: 2, name: 'DC2', region_id: 1, location: 'Oslo', country: 'NO', in_stock: false},
    {id: 4, name: 'DC4', region_id: 1, location: 'Bergen', country: 'NO', in_stock: null},
    {id: 3, name: 'DC3', region_id: 2, location: 'Stockholm', country: 'SE', in_stock: true}
  ]
};

// planBuilt: the same regions and datacenters, but built to order. The provider
// documents that dc_id is ignored for these, so nothing may be pinned.
const planBuilt = {
  product_id: 120, price_id: 560, name: 'Dedicated 64', type: 'dedicated',
  built_to_order: true, in_stock: false,
  currency: 'NOK', hourly_rate_nok: 0.9, monthly_ceiling_nok: 560,
  regions: [{id: 1, name: 'Norway', country: 'NO', available: true, in_stock: true}],
  datacenters: [
    {id: 1, name: 'DC1', region_id: 1, location: 'Sandefjord', country: 'NO', in_stock: true},
    {id: 2, name: 'DC2', region_id: 1, location: 'Oslo', country: 'NO', in_stock: false}
  ]
};

// planNoDC: the provider published no datacenter at all.
const planNoDC = {
  product_id: 102, price_id: 556, name: 'Cloud 1', type: 'vm',
  built_to_order: false, in_stock: true,
  currency: 'NOK', hourly_rate_nok: 0.0719, monthly_ceiling_nok: 45,
  regions: [{id: 1, name: 'Norway', country: 'NO', available: true, in_stock: true}],
  datacenters: []
};

// planTampered: a dc_ids entry the catalog could not read as a positive integer,
// plus one that is zero. Neither may ever become a selectable target.
const planTampered = {
  product_id: 103, price_id: 557, name: 'Cloud 2', type: 'vm',
  built_to_order: false, in_stock: true,
  currency: 'NOK', hourly_rate_nok: 0.1, monthly_ceiling_nok: 70,
  regions: [{id: 1, name: 'Norway', country: 'NO', available: true, in_stock: true}],
  datacenters: [
    {id: 1, name: 'DC1', region_id: 1, location: 'Sandefjord', country: 'NO', in_stock: true},
    {id: 0, name: 'DC0', region_id: 1, location: 'Nowhere', country: 'NO', in_stock: true},
    {id: null, name: 'DC?', region_id: 1, location: '', country: 'NO', in_stock: true}
  ]
};
`

func TestGigahostPlacementModuleDOM(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)

	source, err := StaticFS.ReadFile("static/js/gigahost_placement.js")
	if err != nil {
		t.Fatalf("read placement module: %v", err)
	}
	if len(strings.TrimSpace(string(source))) == 0 {
		t.Fatal("placement module is empty")
	}

	encodedModule, err := json.Marshal(string(source))
	if err != nil {
		t.Fatalf("encode module: %v", err)
	}

	script := jsdomBootstrapSnippet + placementTestFixtures + fmt.Sprintf(`
// The module reads translations through the page's _() helper. The harness
// resolves every key to itself, so an assertion can name the exact key a branch
// chose instead of depending on English wording.
const dom = new JSDOM('<div id="deployPlacementHost"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.eval(%s);

// The module declares its region-managed sentinel as a top-level const, which
// eval keeps in the eval scope rather than on window. Ask the module itself for the
// value, which also pins that the managed choice and the sentinel are consistent.
const MANAGED = w.placementChoices(planNorth, 1).managed.value;
assert.equal(typeof MANAGED, 'string');
assert.notEqual(MANAGED, '', 'the managed sentinel must be a non-empty string');
const values = choices => choices.options.map(o => o.value);
const selectableValues = choices => choices.options.filter(o => o.selectable).map(o => o.value);
const byValue = (choices, v) => choices.options.find(o => o.value === v);

// equals compares a value the module produced (a jsdom-realm object or array)
// against a harness literal by structure, not by prototype identity. The module's
// values are created inside the jsdom eval realm, so deepStrictEqual would reject
// an identical structure for its prototype alone.
const equals = (actual, expected, message) =>
  assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected, message);

// ---------------------------------------------------------------- positive ---
// A region-managed choice is always available and is always first, so the
// documented default cannot be lost by a datacenter change.
const north1 = w.placementChoices(planNorth, 1);
assert.equal(north1.managed.value, MANAGED);
assert.equal(north1.managed.managed, true);
assert.equal(north1.note, '', 'a plan with an in-stock datacenter needs no plan-level note');

// Region 1 offers exactly DC1 and DC3-shaped refusals: DC1 alone is selectable.
equals(values(north1), ['1', '2', '4', '3'],
  'every plan datacenter is listed, in the plan order');
equals(selectableValues(north1), ['1'],
  'only the in-stock datacenter of the chosen region is selectable');

// Each refusal carries its own reason, so the operator can act on it.
assert.equal(byValue(north1, '2').reason, 'deploy_vps_placement_out_of_stock');
assert.equal(byValue(north1, '4').reason, 'deploy_vps_placement_stock_unknown');
assert.equal(byValue(north1, '3').reason, 'deploy_vps_placement_wrong_region');
assert.equal(byValue(north1, '1').reason, '', 'a selectable datacenter has no refusal reason');

// Unknown stock is not sold out: those are different facts and different messages.
assert.notEqual(byValue(north1, '4').reason, byValue(north1, '2').reason,
  'unknown stock must not be reported as sold out');

// A datacenter pin is a distinct placement from the region-managed one, and its
// label carries the location so two datacenters stay distinguishable.
assert.equal(w.placementLabel(north1.managed), 'deploy_vps_placement_region');
assert.match(w.placementLabel(byValue(north1, '1')), /DC1/);
assert.match(w.placementLabel(byValue(north1, '1')), /Sandefjord/);
assert.match(w.placementLabel(byValue(north1, '2')), /deploy_vps_placement_out_of_stock/,
  'a refused datacenter label states why it is refused');

// In region 2 the eligible pin is DC3, and DC1 is refused for the region reason.
const north2 = w.placementChoices(planNorth, 2);
equals(selectableValues(north2), ['3']);
assert.equal(byValue(north2, '3').reason, '');
assert.equal(byValue(north2, '1').reason, 'deploy_vps_placement_wrong_region');

// ---------------------------------------------------------------- refusals ---
// Built to order: nothing may be pinned, and the note says why.
const built = w.placementChoices(planBuilt, 1);
equals(selectableValues(built), [],
  'a built-to-order plan exposes no pinnable datacenter');
assert.equal(built.note, 'deploy_vps_placement_built_to_order');
for (const o of built.options) {
  assert.equal(o.reason, 'deploy_vps_placement_built_to_order');
}
assert.equal(built.managed.value, MANAGED,
  'region-managed placement remains the documented choice for built-to-order plans');

// No datacenter published at all.
const noDC = w.placementChoices(planNoDC, 1);
equals(noDC.options, []);
assert.equal(noDC.note, 'deploy_vps_placement_none');
assert.equal(noDC.managed.value, MANAGED);

// A region the plan does not serve cannot host a pin either.
const badRegion = w.placementChoices(planNorth, 99);
equals(badRegion.options, []);
assert.equal(badRegion.note, 'deploy_vps_placement_region_required');
assert.equal(w.placementChoices(planNorth, 0).note, 'deploy_vps_placement_region_required');
assert.equal(w.placementChoices(planNorth, 'x').note, 'deploy_vps_placement_region_required');
assert.equal(w.placementChoices(null, 1).note, 'deploy_vps_no_plans');

// Malformed identifiers are listed but never selectable, and carry no id that
// could be sent.
const tampered = w.placementChoices(planTampered, 1);
equals(selectableValues(tampered), ['1']);
for (const o of tampered.options) {
  if (o.value === '1') continue;
  assert.equal(o.selectable, false);
  assert.equal(o.reason, 'deploy_vps_placement_invalid_id');
  assert.equal(o.id, null, 'an unreadable id must not be reported as a number');
  // It must not collapse to the empty value either: '' means "nothing chosen",
  // which would let a malformed entry be ordered as region-managed placement.
  assert.notEqual(o.value, '', 'an unreadable id must not look like an unmade choice');
  assert.notEqual(o.value, MANAGED, 'an unreadable id must not look like managed placement');
  assert.equal(Number.isNaN(Number(o.value)), true, 'its value must not parse as an id');
}

// --------------------------------------------------- selection persistence ---
// A valid pin survives a rebuild.
equals(w.placementSelection(north1, '1'),
  {value: '1', cleared: false, reason: ''});

// Region-managed survives too, and is the default when nothing was chosen.
assert.equal(w.placementSelection(north1, MANAGED).value,
  MANAGED);
assert.equal(w.placementSelection(north1, undefined).value, MANAGED);
assert.equal(w.placementSelection(north1, null).value, MANAGED);

// A plan change that no longer offers the pinned datacenter clears it, and the
// operator is told - it must not become region-managed silently.
const planOther = JSON.parse(JSON.stringify(planNorth));
planOther.product_id = 999; planOther.datacenters = [planNorth.datacenters[2]]; // only DC4
const clearedByPlan = w.placementSelection(w.placementChoices(planOther, 1), '1');
assert.equal(clearedByPlan.value, MANAGED);
assert.equal(clearedByPlan.cleared, true, 'a vanishing datacenter must clear the pin');
assert.equal(clearedByPlan.reason, 'deploy_vps_placement_choice_cleared');

// A region change clears a pin from the other region.
const clearedByRegion = w.placementSelection(north2, '1');
assert.equal(clearedByRegion.cleared, true);
assert.equal(clearedByRegion.reason, 'deploy_vps_placement_wrong_region');

// Stock loss clears the pin and says exactly that, rather than "no longer offered".
const planStockLost = JSON.parse(JSON.stringify(planNorth));
planStockLost.datacenters[0].in_stock = false;
const clearedByStock = w.placementSelection(w.placementChoices(planStockLost, 1), '1');
assert.equal(clearedByStock.cleared, true);
assert.equal(clearedByStock.reason, 'deploy_vps_placement_out_of_stock');

// Stock becoming unknown also clears it: unknown is not permission to keep a pin.
const planStockUnknown = JSON.parse(JSON.stringify(planNorth));
planStockUnknown.datacenters[0].in_stock = null;
const clearedByUnknown = w.placementSelection(w.placementChoices(planStockUnknown, 1), '1');
assert.equal(clearedByUnknown.cleared, true);
assert.equal(clearedByUnknown.reason, 'deploy_vps_placement_stock_unknown');

// -------------------------------------------------------------- payloads ----
// Region-managed placement keeps the legacy payload exactly: region_id, no dc_id.
equals(w.placementPayloadField(north1, MANAGED, 1),
  {region_id: 1});
equals(w.placementPayloadField(north1, undefined, 1), {region_id: 1});
equals(w.placementPayloadField(north1, '', 1), {region_id: 1});

// An explicit pin sends dc_id and no region_id, which is the documented shape.
const pinned = w.placementPayloadField(north1, '1', 1);
equals(pinned, {dc_id: 1});
assert.equal(Object.prototype.hasOwnProperty.call(pinned, 'region_id'), false,
  'a pinned payload must not also carry region_id');

// Nothing unselectable may produce a payload: no guess, no silent downgrade.
assert.equal(w.placementPayloadField(north1, '2', 1), null, 'a sold-out pin must refuse');
assert.equal(w.placementPayloadField(north1, '4', 1), null, 'an unknown-stock pin must refuse');
assert.equal(w.placementPayloadField(north1, '3', 1), null, 'a wrong-region pin must refuse');
assert.equal(w.placementPayloadField(north1, '99', 1), null, 'an unknown id must refuse');
assert.equal(w.placementPayloadField(north1, '1', 0), null, 'no region means no payload');
assert.equal(w.placementPayloadField(north1, '1', NaN), null);
assert.equal(w.placementPayloadField(null, '1', 1), null);

// Tampered ids never reach a payload, even when the selector claims one.
for (const o of tampered.options) {
  if (o.selectable) continue;
  assert.equal(w.placementPayloadField(tampered, o.value, 1), null,
    'a non-selectable option must never produce a payload');
}
// A tampered value the operator somehow submits is refused, not downgraded.
assert.equal(w.placementPayloadField(tampered, 'invalid-1', 1), null,
  'a malformed id must refuse rather than fall back to region-managed placement');

// Built-to-order: managed placement only, and the pin refuses.
equals(w.placementPayloadField(built, MANAGED, 1), {region_id: 1});
assert.equal(w.placementPayloadField(built, '1', 1), null);

// --------------------------------------------------- explicit-vs-managed -----
assert.equal(w.placementIsExplicit('1'), true);
assert.equal(w.placementIsExplicit(1), true);
assert.equal(w.placementIsExplicit(MANAGED), false);
assert.equal(w.placementIsExplicit(''), false);
assert.equal(w.placementIsExplicit(undefined), false);
assert.equal(w.placementIsExplicit(null), false);

// The whole payload the page will assemble: pid/price_id/os_id preserved, and the
// placement half merged in, for both shapes.
function assemble(choices, value, regionId, osId) {
  const field = w.placementPayloadField(choices, value, regionId);
  if (!field) return null;
  return Object.assign({pid: planNorth.product_id, price_id: planNorth.price_id}, field, {os_id: osId});
}
equals(assemble(north1, MANAGED, 1, 12),
  {pid: 101, price_id: 555, region_id: 1, os_id: 12});
equals(assemble(north1, '1', 1, 12),
  {pid: 101, price_id: 555, dc_id: 1, os_id: 12});
assert.equal(assemble(north1, '2', 1, 12), null);

console.log('GIGAHOST_PLACEMENT_OK');dom.window.close();
`, string(encodedModule))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_PLACEMENT_OK") {
		t.Fatalf("placement module contract failed: %v\n%s", err, out)
	}
}

// TestGigahostPlacementLocaleKeysExist proves the module's five locales exist and
// agree on the same key set, so no locale falls back to a bare key in the UI.
//
// This is a pure-Go check over the shipped JSON: it needs no Node, and it fails if
// a locale is missing a placement key or carries an empty value.
func TestGigahostPlacementLocaleKeysExist(t *testing.T) {
	keys := []string{
		"deploy_vps_placement_label",
		"deploy_vps_placement_region",
		"deploy_vps_placement_region_required",
		"deploy_vps_placement_none",
		"deploy_vps_placement_none_in_stock",
		"deploy_vps_placement_built_to_order",
		"deploy_vps_placement_invalid_id",
		"deploy_vps_placement_wrong_region",
		"deploy_vps_placement_stock_unknown",
		"deploy_vps_placement_out_of_stock",
		"deploy_vps_placement_choice_cleared",
	}
	locales := []string{"en", "fa", "fr", "ru", "zh"}

	for _, locale := range locales {
		raw, readErr := TranslationsFS.ReadFile("translations/" + locale + ".json")
		if readErr != nil {
			t.Fatalf("read locale %s: %v", locale, readErr)
		}
		var dict map[string]string
		if err := json.Unmarshal(raw, &dict); err != nil {
			t.Fatalf("decode locale %s: %v", locale, err)
		}
		for _, key := range keys {
			value, ok := dict[key]
			if !ok {
				t.Errorf("locale %s is missing %s", locale, key)
				continue
			}
			if strings.TrimSpace(value) == "" {
				t.Errorf("locale %s has an empty %s", locale, key)
			}
		}
	}
}
