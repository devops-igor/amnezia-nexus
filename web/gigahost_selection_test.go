package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestGigahostDeploySelectionContract proves the portal only offers provider
// facts and never a guessed default. It extracts the real selection helpers from
// templates/settings.html and runs them in JSDOM, so the assertions describe the
// shipped code rather than a copy of it.
//
// The behaviours under test are the ones the order path depends on:
//   - the image and region selectors are built from the plan the provider
//     returned, not from a hardcoded list or a fallback region id;
//   - a plan change drops a selection the new plan does not support and keeps one
//     it does;
//   - with nothing selectable the order button stays disabled, so no purchase can
//     be posted from an empty selector.
func TestGigahostDeploySelectionContract(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)
	source, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	functions := []string{
		"function appendDeployOption",
		"function deployPlanAt",
		"function deployPlanLabel",
		"function updateDeploySelections",
		"function updateDeployButtonState",
		// updateDeploySelections now rebuilds the placement selector, so the
		// placement helpers it calls must be extracted with it: the harness runs the
		// page's real functions, and a partial extraction would fail on a missing
		// reference rather than on a behaviour.
		"function deployPlacementChoices",
		"function rebuildDeployPlacement",
		"function showDeployPlacementHint",
		"function deployPlacementNeedsChoice",
	}
	var extracted strings.Builder
	for _, fn := range functions {
		code, extractErr := extractJSFunction(string(source), fn)
		if extractErr != nil {
			t.Fatalf("extractJSFunction %s failed: %v", fn, extractErr)
		}
		extracted.WriteString(code + "\n")
	}
	encodedFunctions, _ := json.Marshal(extracted.String())
	// The page loads the placement module before its own script, and
	// updateDeploySelections delegates to it, so the harness loads it the same way
	// rather than stubbing the decisions the page really makes.
	placementModule, err := StaticFS.ReadFile("static/js/gigahost_placement.js")
	if err != nil {
		t.Fatalf("read placement module: %v", err)
	}
	encodedPlacement, _ := json.Marshal(string(placementModule))
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<select id="deployPlanSelect"></select><select id="deployRegionSelect"></select><select id="deployPlacementSelect"></select><p id="deployPlacementHint"></p><select id="deployOSSelect"></select><button id="btnDeployVPS"></button>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;

// The template declares these as module-scope bindings; in the harness they are
// window properties, which is what the extracted helpers resolve against.
w.cachedPlans = [];
w.deployPlanSelect = w.document.getElementById('deployPlanSelect');
w.deployRegionSelect = w.document.getElementById('deployRegionSelect');
w.deployPlacementSelect = w.document.getElementById('deployPlacementSelect');
w.deployPlacementHint = w.document.getElementById('deployPlacementHint');
w.deployOSSelect = w.document.getElementById('deployOSSelect');
w.btnDeployVPS = w.document.getElementById('btnDeployVPS');
w.eval(%s);   // the shipped placement module, as the page loads it
// The page declares its placement-intent owner as a module-scope const, which a
// function extractor cannot lift. Create the same instance the page creates, after
// the module defines the constructor and before the helpers use it.
// Resolve the constructor through the window object: the module was evaluated in
// the window's script scope, so the bare name is visible to the extracted helpers but
// not to this harness line.
w.deploymentPlacementIntent = new w.placementIntent();
w.eval(%s);   // the extracted page helpers

function setPlans(plans) {
  w.cachedPlans.length = 0;
  plans.forEach(p => w.cachedPlans.push(p));
}

// A documented plan: region 1 with stock, one general image and no dedicated-only
// image, so the narrowing is observable between plans.
const planA = {
  product_id: 101, price_id: 555, name: 'Cloud 2', type: 'vm',
  cpu_cores: 2, ram_mb: 4096, disk_gb: 80,
  currency: 'NOK', hourly_rate_nok: 0.14375, monthly_ceiling_nok: 90,
  regions: [{id: 1, name: 'Norway', country: 'NO', available: true, in_stock: true}],
  os_options: [
    {os_id: 12, os_name: 'Debian 12'},
    {os_id: 72, os_name: 'Ubuntu 24.04'}
  ]
};
// A second plan: different region, and only one of the two images.
const planB = {
  product_id: 102, price_id: 556, name: 'Cloud 4', type: 'vm',
  cpu_cores: 4, ram_mb: 8192, disk_gb: 160,
  currency: 'NOK', hourly_rate_nok: 0.2875, monthly_ceiling_nok: 180,
  regions: [{id: 2, name: 'Sweden', country: 'SE', available: true, in_stock: true}],
  os_options: [{os_id: 72, os_name: 'Ubuntu 24.04'}]
};
// A plan with no capacity and no installable image: nothing may be orderable.
const planEmpty = {
  product_id: 103, price_id: 557, name: 'Sold out', type: 'vm',
  currency: 'NOK', hourly_rate_nok: 0.1, monthly_ceiling_nok: 70,
  regions: [{id: 1, name: 'Norway', country: 'NO', available: true, in_stock: false}],
  os_options: []
};

const planSel = w.deployPlanSelect;
const regionSel = w.deployRegionSelect;
const osSel = w.deployOSSelect;
const btn = w.btnDeployVPS;

setPlans([planA, planB]);
planSel.innerHTML = '<option value="0">a</option><option value="1">b</option>';
planSel.value = '0';
w.updateDeploySelections(null);

// Positive: both selectors carry exactly the plan's provider values.
assert.deepStrictEqual(
  Array.from(osSel.options).map(o => o.value), ['12', '72'],
  'image selector must list the plan os_options');
assert.deepStrictEqual(
  Array.from(regionSel.options).map(o => o.value), ['1'],
  'region selector must list only the plan regions');
assert.equal(btn.disabled, false, 'a valid selection must enable ordering');
assert.match(w.deployPlanLabel(w.cachedPlans[0]), /0\.14375 NOK\/hr/,
  'plan label must show the authoritative hourly rate and currency');
assert.match(w.deployPlanLabel(w.cachedPlans[0]), /max 90 NOK\/mo/,
  'plan label must show the provider monthly ceiling');

// Plan change: os 12 is not offered by plan B, so the selection must move to a
// supported image, and region 1 must be replaced by region 2.
planSel.value = '1';
w.updateDeploySelections({region: regionSel.value, os: osSel.value});
assert.deepStrictEqual(
  Array.from(osSel.options).map(o => o.value), ['72'],
  'plan change must rebuild images from the new plan');
assert.equal(osSel.value, '72', 'an unsupported image must not stay selected');
assert.deepStrictEqual(
  Array.from(regionSel.options).map(o => o.value), ['2'],
  'plan change must rebuild regions from the new plan');
assert.equal(regionSel.value, '2', 'an unsupported region must not stay selected');

// A selection the new plan still supports survives the change.
planSel.value = '0';
w.updateDeploySelections({region: regionSel.value, os: osSel.value});
assert.equal(osSel.value, '72', 'a still-supported image must be preserved');
assert.equal(regionSel.value, '1', 'region must follow the plan');

// Negative: nothing selectable means nothing orderable, and no option carries an
// id that could be posted as a guess.
setPlans([planEmpty]);
planSel.innerHTML = '<option value="0">a</option>';
planSel.value = '0';
w.updateDeploySelections(null);
assert.equal(osSel.value, '', 'no image means an empty selection');
assert.equal(regionSel.value, '', 'no stocked region means an empty selection');
assert.equal(osSel.options[0].value, '', 'the placeholder must carry no id');
assert.equal(btn.disabled, true, 'an empty selection must not be orderable');

// Negative: with no plans at all the button stays disabled too.
setPlans([]);
w.updateDeployButtonState();
assert.equal(btn.disabled, true, 'no plans must not be orderable');

console.log('GIGAHOST_SELECTION_OK');dom.window.close();
`, string(encodedPlacement), string(encodedFunctions))
	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_SELECTION_OK") {
		t.Fatalf("deploy selection contract failed: %v\n%s", err, out)
	}
}
