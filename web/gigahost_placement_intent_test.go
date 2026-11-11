package web

// Regression: an invalidated datacenter pin must stay invalidated until the
// operator deliberately chooses again, across every automatic rebuild and recovery.
//
// The defect it pins: after a pin was dropped, a SECOND automatic event (another
// region change, a repeated refresh, or a catalog recovery) released the block,
// because the rebuild saw the value it had written itself and treated it as a choice.
// Each of the three histories then posted one provider-managed order nobody asked for.
//
// This file asserts the corrected contract on the ACTUAL shipped page script and the
// ACTUAL shipped placement module, through real DOM change events. For every history
// it asserts BOTH halves the review asks for:
//
//   1. the order button stays disabled, and
//   2. calling the page's own handleDeployVPS directly posts nothing -
//
// because a disabled button alone is a UI hint, not a guard.
//
// It then asserts that a deliberate choice (a valid pin, or an explicit choice of
// provider-managed placement) releases the block and posts exactly once with the
// right shape, and that a cold first-time managed order still works. Those positives
// are what keep the fix from "solving" the defect by breaking legitimate ordering.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGigahostPlacementIntentStaysBlockedUntilDeliberateChoice(t *testing.T) {
	node := requireJSDOM(t)

	template, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	pageJS, err := lastInlineScript(string(template))
	if err != nil {
		t.Fatalf("extract the page script: %v", err)
	}
	moduleJS, err := StaticFS.ReadFile("static/js/gigahost_placement.js")
	if err != nil {
		t.Fatalf("read placement module: %v", err)
	}
	// The page must actually use the module's intent owner, not a local flag: a
	// local latch is what allowed the rule to drift in the first place.
	if !strings.Contains(pageJS, "placementIntent") {
		t.Fatal("the page does not use the module's placement intent owner")
	}

	pageEncoded, _ := json.Marshal(pageJS)
	moduleEncoded, _ := json.Marshal(string(moduleJS))
	idsEncoded, _ := json.Marshal(pageElementIDs(pageJS))

	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<!doctype html><html><body></body></html>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;

for (const id of %s) {
  const el = w.document.createElement('input');
  el.id = id;
  w.document.body.appendChild(el);
}
function mk(tag, id) {
  const old = w.document.getElementById(id);
  if (old) old.remove();
  const el = w.document.createElement(tag);
  el.id = id;
  w.document.body.appendChild(el);
}
for (const [tag, id] of [['select','deployPlanSelect'],['select','deployRegionSelect'],
                         ['select','deployPlacementSelect'],['p','deployPlacementHint'],
                         ['select','deployOSSelect'],['button','btnDeployVPS'],
                         ['button','btnRefreshCatalog'],['div','deployVPSSpinner'],
                         ['div','deployCatalogLoading']]) { mk(tag, id); }

const posts = [];
let catalogResponse = null;
w.API = {
  get: async url => {
    if (url.indexOf('/catalog') !== -1) {
      if (catalogResponse instanceof Error) throw catalogResponse;
      return catalogResponse;
    }
    return {orders:[], setup_intents:[]};
  },
  post: async (url, body) => { posts.push({url, body}); return {message:'ok'}; },
  delete: async () => ({status:'ok'}),
};
w.UI = {toast: () => {}};
w.confirm = () => true;
w.startGigahostOrderStatusRefresh = () => {};
w.loadRecentOrders = () => {};
w.loadSetupIntents = () => {};
w.saveSettings = () => {};
w.checkUpstreamStatus = () => {};
w.setupIntentsInFlight = new Set();

w.eval(%s);
w.eval(%s);

const planSel = w.document.getElementById('deployPlanSelect');
const regionSel = w.document.getElementById('deployRegionSelect');
const placeSel = w.document.getElementById('deployPlacementSelect');
const osSel = w.document.getElementById('deployOSSelect');
const btn = w.document.getElementById('btnDeployVPS');
const hint = w.document.getElementById('deployPlacementHint');
const fire = el => el.dispatchEvent(new w.Event('change', {bubbles:true}));
const orderPosts = () => posts.filter(p => p.url.indexOf('/order') !== -1);

function makePlan(overrides) {
  const base = {
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
    ],
    os_options: [{os_id: 12, os_name: 'Debian 12'}]
  };
  return Object.assign(base, overrides || {});
}
const planNoDC = makePlan({product_id: 102, price_id: 556, name: 'Cloud 1', datacenters: []});
const planBuilt = makePlan({product_id: 120, price_id: 560, name: 'Dedicated', built_to_order: true, in_stock: false});

async function loadCatalog(plans) {
  catalogResponse = {plans};
  await w.loadGigahostCatalog();
  await new Promise(r => setTimeout(r, 0));
}
// A valid pin in region 1, established the way an operator would.
async function pinnedState() {
  await loadCatalog([makePlan(), planNoDC, planBuilt]);
  regionSel.value = '1'; fire(regionSel);
  placeSel.value = '1'; fire(placeSel);
  assert.equal(btn.disabled, false, 'precondition: a valid pin must be orderable');
  assert.equal(placeSel.value, '1', 'precondition: the pin must be selected');
}
// Attempt an order without touching the placement selector.
async function orderedWithoutChoice() {
  const before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  return orderPosts().length - before;
}

(async () => {
  // ---- history 1: pin -> incompatible region -> another region event --------
  await pinnedState();
  regionSel.value = '2'; fire(regionSel);
  assert.equal(btn.disabled, true, 'history 1: the first incompatible region must block');
  assert.equal(await orderedWithoutChoice(), 0, 'history 1: the first refusal must post nothing');
  regionSel.value = '1'; fire(regionSel);
  assert.equal(btn.disabled, true, 'a second region event must NOT release the block');
  assert.equal(await orderedWithoutChoice(), 0, 'zero POSTs after the second region event');

  // ---- history 2: pin -> stock loss -> the same refresh again ---------------
  await pinnedState();
  const lost = makePlan(); lost.datacenters[0].in_stock = false;
  await loadCatalog([lost, planNoDC, planBuilt]);
  assert.equal(btn.disabled, true, 'history 2: a stock-loss refresh must block');
  assert.equal(await orderedWithoutChoice(), 0, 'history 2: the first refusal must post nothing');
  await loadCatalog([lost, planNoDC, planBuilt]);
  assert.equal(btn.disabled, true, 'a repeated refresh must NOT release the block');
  assert.equal(await orderedWithoutChoice(), 0, 'zero POSTs after the repeated refresh');

  // ---- history 3: pin -> failed catalog -> recovery -------------------------
  await pinnedState();
  catalogResponse = new Error('controlled outage');
  await w.loadGigahostCatalog();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(btn.disabled, true, 'history 3: a failed catalog must block');
  assert.equal(await orderedWithoutChoice(), 0, 'history 3: a failed catalog must post nothing');
  await loadCatalog([makePlan(), planNoDC, planBuilt]);
  assert.equal(btn.disabled, true, 'a catalog recovery must NOT release the block');
  assert.equal(await orderedWithoutChoice(), 0, 'zero POSTs after catalog recovery');

  // ---- adjacent realistic sequence: region change then plan change ----------
  await pinnedState();
  regionSel.value = '2'; fire(regionSel);
  planSel.value = '1'; fire(planSel);
  assert.equal(btn.disabled, true, 'an adjacent plan change must not release the block');
  assert.equal(await orderedWithoutChoice(), 0, 'the adjacent sequence must post nothing');

  // ---- positive: a deliberate valid pin releases it and posts exactly once --
  planSel.value = '0'; fire(planSel);
  regionSel.value = '1'; fire(regionSel);
  assert.equal(btn.disabled, true, 'still blocked before the deliberate choice');
  placeSel.value = '1'; fire(placeSel);
  assert.equal(btn.disabled, false, 'a deliberate valid pin must release the block');
  let before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length - before, 1, 'the deliberate pin must post exactly once');
  const pinBody = JSON.parse(JSON.stringify(orderPosts().at(-1).body));
  assert.deepStrictEqual(pinBody,
    {pid:101, price_id:555, region_id:1, os_id:12, hourly_price_nok:0.14375, dc_id:1},
    'the deliberate pin must carry dc_id beside region_id');

  // ---- positive: an explicit managed choice is a deliberate choice ----------
  regionSel.value = '2'; fire(regionSel);
  assert.equal(btn.disabled, true, 'a region change re-blocks');
  const managedValue = placeSel.options[0].value;
  placeSel.value = managedValue; fire(placeSel);
  assert.equal(btn.disabled, false, 'an explicit managed choice is deliberate and must unblock');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length - before, 1, 'the deliberate managed choice must post once');
  const manBody = JSON.parse(JSON.stringify(orderPosts().at(-1).body));
  assert.equal(manBody.region_id, 2, 'it must carry the region the operator is looking at');
  assert.equal(Object.prototype.hasOwnProperty.call(manBody, 'dc_id'), false,
    'managed placement carries no dc_id');

  // ---- positive: a refused option cannot release a block ---------------------
  // Re-establish a real block first: a pin, then an event that invalidates it.
  // (After a deliberate managed choice nothing was dropped, so a later region change
  // has nothing to block - that is correct, not a gap.)
  await pinnedState();
  regionSel.value = '2'; fire(regionSel);
  assert.equal(btn.disabled, true, 'a pin invalidated by a region change must block');
  placeSel.value = '2'; fire(placeSel);   // sold out: still listed, but not selectable
  assert.equal(btn.disabled, true, 'a refused datacenter must not release the block');
  assert.equal(await orderedWithoutChoice(), 0, 'a refused datacenter must post nothing');

  // ---- positive: cold first-time managed ordering still works --------------
  await loadCatalog([makePlan(), planNoDC, planBuilt]);
  placeSel.value = placeSel.options[0].value; fire(placeSel);
  assert.equal(btn.disabled, false, 'a cold initial managed selection must be orderable');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length - before, 1, 'cold managed ordering must still work');

  console.log('GIGAHOST_PLACEMENT_INTENT_OK');dom.window.close();
})().catch(e => {console.error('INTENT_TEST_FAILED: ' + (e && e.stack || e)); process.exit(1);});
`, string(idsEncoded), string(moduleEncoded), string(pageEncoded))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_PLACEMENT_INTENT_OK") {
		t.Fatalf("placement intent regression failed: %v\n%s", err, out)
	}
}
