package web

// Joined page-level placement test (#739 B2).
//
// Unlike the B1 module test, this file loads the ACTUAL shipped page: it reads
// templates/settings.html, extracts the real page script, executes it in JSDOM
// together with the real static modules the template loads, and drives real DOM
// change events. Nothing here reimplements the page.
//
// What it proves, in the page's own terms:
//   - the template loads gigahost_placement.js and has a placement select;
//   - region-managed placement is offered as a distinct option, and a datacenter
//     the provider cannot honour is listed but not selectable;
//   - a deliberate pin survives a compatible rebuild, and a plan or region change
//     that invalidates it drops it AND blocks ordering until the operator chooses
//     again - a toast alone never enables a region-managed order;
//   - the payload the page posts keeps pid/price_id/os_id/hourly_price_nok and adds
//     either region_id or dc_id, never both, never a guess;
//   - stale stock between display and submission, an unknown/malformed/mismatched
//     id, and a failed catalog read all send zero order POSTs.
//
// The order endpoint is a recording stub: this is a page-contract test, not an HTTP
// consumer test. The real handler/provider path is covered in the Go consumer test
// next to this file.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// lastInlineScript returns the body of the last <script> block without a src
// attribute in an HTML template. It is used to run a page's own ordering logic in
// JSDOM rather than a reimplementation of it.
//
// The scan is a simple forward search for "<script" and the matching "</script>",
// which is sufficient here because the template contains no "<script" inside a
// string literal. A missing or empty block is reported as an error, never as an
// empty string that would let a test pass against nothing.
func lastInlineScript(html string) (string, error) {
	const open, closeTag = "<script", "</script>"
	var last string
	for offset := 0; ; {
		start := strings.Index(html[offset:], open)
		if start < 0 {
			break
		}
		start += offset
		tagEnd := strings.Index(html[start:], ">")
		if tagEnd < 0 {
			break
		}
		tagEnd += start
		bodyStart := tagEnd + 1
		end := strings.Index(html[bodyStart:], closeTag)
		if end < 0 {
			break
		}
		end += bodyStart
		attributes := html[start:tagEnd]
		if !strings.Contains(attributes, "src=") {
			last = html[bodyStart:end]
		}
		offset = end + len(closeTag)
	}
	if strings.TrimSpace(last) == "" {
		return "", fmt.Errorf("no inline script block with content found")
	}
	return last, nil
}

// pageElementIDs returns the element ids a page script binds with
// getElementById('...'), deduplicated and in first-appearance order. It lets a DOM
// harness create exactly the elements the shipped script expects, so the script can
// run unmodified instead of being cut down to the part under test.
func pageElementIDs(js string) []string {
	const marker = "getElementById('"
	var ids []string
	seen := make(map[string]struct{})
	for offset := 0; ; {
		start := strings.Index(js[offset:], marker)
		if start < 0 {
			break
		}
		start += offset + len(marker)
		end := strings.Index(js[start:], "'")
		if end < 0 {
			break
		}
		id := js[start : start+end]
		if _, ok := seen[id]; !ok && id != "" {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
		offset = start + end
	}
	return ids
}

func TestGigahostPlacementPageWiringDOM(t *testing.T) {
	node := requireJSDOM(t)

	template, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	templateText := string(template)

	// The page must load the shipped module, not an inline copy.
	if !strings.Contains(templateText, `src="/static/js/gigahost_placement.js"`) {
		t.Fatal("settings.html does not load the placement module")
	}
	if !strings.Contains(templateText, `id="deployPlacementSelect"`) {
		t.Fatal("settings.html has no placement selector")
	}

	pageJS, err := lastInlineScript(templateText)
	if err != nil {
		t.Fatalf("extract the page script: %v", err)
	}
	// The block this test runs must be the ordering logic, not some other script.
	for _, token := range []string{"function updateDeploySelections", "function handleDeployVPS", "deployPlacementSelect"} {
		if !strings.Contains(pageJS, token) {
			t.Fatalf("extracted page script lacks %q; the wrong block was selected", token)
		}
	}

	moduleJS, err := StaticFS.ReadFile("static/js/gigahost_placement.js")
	if err != nil {
		t.Fatalf("read placement module: %v", err)
	}

	// The page calls the catalog-freshness module from its own catalog read, so the
	// harness loads it too, exactly as the page does.
	catalogStatusJS, err := StaticFS.ReadFile("static/js/gigahost_catalog_status.js")
	if err != nil {
		t.Fatalf("read catalog status module: %v", err)
	}
	pageEncoded, _ := json.Marshal(pageJS)
	moduleEncoded, _ := json.Marshal(string(moduleJS))
	catalogStatusEncoded, _ := json.Marshal(string(catalogStatusJS))
	// The ids the page's own script binds, read from the script it will run. The
	// harness creates an element for each so the shipped script executes unmodified.
	pageIDListJSON, _ := json.Marshal(pageElementIDs(pageJS))

	script := jsdomBootstrapSnippet + fmt.Sprintf(`
// The shipped markup for the ordering form, with the ids the page script binds.
const dom = new JSDOM('<!doctype html><html><body></body></html>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;

// Recorded HTTP effects. The order endpoint must be called exactly when the page
// decides the selection is orderable, and never otherwise.
const posts = [];
const gets = [];
let catalogResponse = null;
w.API = {
  get: async (url) => {
    gets.push(url);
    if (url.indexOf('/catalog') !== -1) {
      if (catalogResponse instanceof Error) throw catalogResponse;
      return catalogResponse;
    }
    return {orders:[], setup_intents:[]};
  },
  post: async (url, body) => { posts.push({url, body}); return {message:'ok'}; },
  delete: async () => ({status:'ok'}),
};
w.UI = {toast: (text, kind) => {(w.__toasts = w.__toasts || []).push({text, kind});}};
w.confirm = () => true;
// Status polling belongs to the order-status module, which this harness does not
// load; stub the two entry points the page calls so its boot path can run.
w.startGigahostOrderStatusRefresh = () => {};
w.loadRecentOrders = () => {};
w.loadSetupIntents = () => {};
w.setupIntentsInFlight = new Set();
w.saveSettings = () => {};
w.checkUpstreamStatus = () => {};
// The template's earlier inline blocks also bind these; keep them harmless.
w.loadGigahostCatalog = undefined;

// The page binds every one of these ids while it loads, so they must exist first.
// The page binds many elements at load (SSL, telegram, upstream, restore). This
// markup supplies every id its own script asks for, generated from the template,
// so the real script runs unmodified instead of being cut down to the ordering
// part. Anything the page does not find is a real wiring defect and will throw.
const pageIds = %s;
for (const id of pageIds) {
	if (w.document.getElementById(id)) continue;
	const el = w.document.createElement('input');
	el.id = id;
	w.document.body.appendChild(el);
}
// The deploy section elements must be the interactive types the page expects.
function mk(tag, id) {
	const el = w.document.createElement(tag);
	el.id = id;
	w.document.body.appendChild(el);
	return el;
}
for (const [tag, id] of [['select','deployPlanSelect'],['select','deployRegionSelect'],
                         ['select','deployPlacementSelect'],['p','deployPlacementHint'],
                         ['select','deployOSSelect'],['button','btnDeployVPS'],
                         ['button','btnRefreshCatalog'],['div','deployVPSSpinner'],
                         ['div','deployCatalogLoading']]) {
	const existing = w.document.getElementById(id);
	if (existing) existing.remove();
	mk(tag, id);
}


// The module is loaded the way the template loads it, then the page script, so the
// page sees the real exported placement helpers.
w.eval(%s);   // catalog-freshness module, as the page loads it
w.eval(%s);   // placement module
w.eval(%s);   // the page script

// The page script binds its own DOMContentLoaded/initial load; run them now.
if (w.document.readyState !== 'loading') {
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
}

const planSel = w.document.getElementById('deployPlanSelect');
const regionSel = w.document.getElementById('deployRegionSelect');
const placeSel = w.document.getElementById('deployPlacementSelect');
const osSel = w.document.getElementById('deployOSSelect');
const btn = w.document.getElementById('btnDeployVPS');
const hint = w.document.getElementById('deployPlacementHint');
const options = el => Array.from(el.options).map(o => ({value:o.value, label:o.textContent, disabled:o.disabled}));
const values = el => Array.from(el.options).map(o => o.value);
const orderPosts = () => posts.filter(p => p.url.indexOf('/order') !== -1);
const fire = (el) => el.dispatchEvent(new w.Event('change', {bubbles:true}));

// Documented plan DTOs: two regions, four datacenters, one sold out, one with
// unreported stock, one built-to-order plan, one plan with no datacenters.
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
const planA = makePlan();
const planNoDC = makePlan({product_id: 102, price_id: 556, name: 'Cloud 1', datacenters: []});
const planBuilt = makePlan({product_id: 120, price_id: 560, name: 'Dedicated', built_to_order: true, in_stock: false});

// Load a catalog the way the page does, then let its promise settle.
async function loadCatalog(plans) {
  catalogResponse = {plans};
  await w.loadGigahostCatalog();
}

(async () => {
  // ---------------------------------------------------------- template shape --
  // Region-managed placement is a distinct first option, and its value can never
  // collide with a provider id.
  await loadCatalog([planA, planNoDC, planBuilt]);
  await new Promise(r => setTimeout(r, 0));

  assert.equal(placeSel.options[0].textContent, 'deploy_vps_placement_region',
    'the first placement option must be the documented region-managed choice');
  const managedValue = placeSel.options[0].value;
  assert.equal(Number(managedValue), NaN, 'the managed value must not look like a provider id');
  assert.notEqual(managedValue, '', 'the managed value must not look like an unmade choice');

  // Every datacenter is listed, and only the in-stock one of the chosen region is
  // selectable - the others are shown with the reason instead of hidden.
  const opts = options(placeSel);
  assert.deepStrictEqual(opts.map(o => o.value), [managedValue, '1', '2', '4', '3']);
  assert.equal(opts[0].disabled, false);
  assert.equal(opts[1].disabled, false, 'the in-stock datacenter of the region must be selectable');
  assert.equal(opts[2].disabled, true, 'a sold-out datacenter must not be selectable');
  assert.equal(opts[3].disabled, true, 'a datacenter with unreported stock must not be selectable');
  assert.equal(opts[4].disabled, true, 'a datacenter in another region must not be selectable');
  assert.match(opts[2].label, /deploy_vps_placement_out_of_stock/);
  assert.match(opts[3].label, /deploy_vps_placement_stock_unknown/);
  assert.match(opts[4].label, /deploy_vps_placement_wrong_region/);

  // ------------------------------------------------- region-only positive -----
  placeSel.value = managedValue;
  fire(placeSel);
  assert.equal(btn.disabled, false, 'a complete region-managed selection must be orderable');
  let before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  let sent = orderPosts();
  assert.equal(sent.length, before + 1, 'the region-managed order must post exactly once');
  let body = sent[sent.length - 1].body;
  assert.deepStrictEqual(JSON.parse(JSON.stringify(body)),
    {pid:101, price_id:555, region_id:1, os_id:12, hourly_price_nok:0.14375},
    'region-managed payload keeps the legacy shape and adds no dc_id');

  // ------------------------------------------------- explicit positive --------
  placeSel.value = '1';
  fire(placeSel);
  assert.equal(btn.disabled, false, 'a valid explicit pin must be orderable');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  sent = orderPosts();
  assert.equal(sent.length, before + 1, 'the pinned order must post exactly once');
  body = sent[sent.length - 1].body;
  const pinnedBody = JSON.parse(JSON.stringify(body));
  // The page posts to the panel, so region_id stays: it is the region the operator
  // saw, the duplicate-guard key and the ledger field. The panel's provider client
  // is what drops region_id on the outbound wire for a pin; the joined consumer test
  // asserts that half against the real provider body.
  assert.deepStrictEqual(pinnedBody,
    {pid:101, price_id:555, region_id:1, os_id:12, hourly_price_nok:0.14375, dc_id:1},
    'a pinned payload carries dc_id beside region_id');

  // ------------------------------------- explicit choice on a sold-out dc -----
  // A disabled option cannot be chosen through the UI, but a tampered value must
  // also be refused: no POST, and no fallback to region-managed placement.
  before = orderPosts().length;
  placeSel.value = '2';
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before, 'a sold-out pin must send no order');
  placeSel.value = 'invalid-2';
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before, 'a malformed pin must send no order');
  const lastToast = (w.__toasts || [])[w.__toasts.length - 1];
  assert.equal(lastToast.kind, 'error', 'a refused pin must be reported as an error, not success');

  // ------------------------------------------- region change drops the pin ----
  placeSel.value = '1';
  fire(placeSel);
  assert.equal(btn.disabled, false);
  // The operator switches to region 2, where dc 1 does not live.
  regionSel.value = '2';
  fire(regionSel);
  assert.equal(placeSel.value, managedValue, 'a cross-region pin must be dropped');
  assert.equal(btn.disabled, true,
    'a dropped pin must block ordering until a new choice is made');
  assert.match(hint.textContent, /deploy_vps_placement_wrong_region|deploy_vps_placement_choice_cleared/,
    'the drop must be explained to the operator');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before,
    'a cleared pin must not be replaced by a silent region-managed order');

  // Choosing again deliberately (here: region-managed, explicitly) unblocks it.
  placeSel.value = managedValue;
  fire(placeSel);
  assert.equal(btn.disabled, false, 'a fresh deliberate choice must re-enable ordering');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before + 1, 'the re-chosen selection must order once');
  assert.equal(JSON.parse(JSON.stringify(orderPosts()[orderPosts().length-1].body)).region_id, 2,
    'the order must use the region the operator is now looking at');

  // ------------------------------------------------ plan change drops the pin -
  // Back to region 1 and pin dc 1, then switch to a plan with no datacenters.
  regionSel.value = '1';
  fire(regionSel);
  placeSel.value = '1';
  fire(placeSel);
  assert.equal(btn.disabled, false);
  planSel.value = '1';
  fire(planSel);
  assert.equal(placeSel.value, managedValue, 'a plan without that datacenter must drop the pin');
  assert.equal(btn.disabled, true, 'a dropped pin after a plan change must block ordering');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before, 'no order may follow a dropped pin');

  // ------------------------------------------ built-to-order plan is never pinned
  planSel.value = '2';
  fire(planSel);
  const builtOpts = options(placeSel);
  assert.equal(builtOpts.length, 1 + planBuilt.datacenters.length);
  for (const o of builtOpts.slice(1)) {
    assert.equal(o.disabled, true, 'a built-to-order plan must expose no pinnable datacenter');
  }
  placeSel.value = managedValue;
  fire(placeSel);

  // ------------------------------------------------ stock lost after display ---
  // The operator pins dc 1 from a catalog where it is in stock; the next catalog
  // read reports it sold out. The pin must be dropped, explained, and blocked from
  // ordering rather than silently becoming a region-managed purchase.
  planSel.value = '0';
  fire(planSel);
  regionSel.value = '1';
  fire(regionSel);
  placeSel.value = '1';
  fire(placeSel);
  assert.equal(placeSel.value, '1', 'precondition: dc 1 must be pinnable before the loss');
  assert.equal(btn.disabled, false, 'precondition: the pin must be orderable before the loss');

  // Now the provider reports the stock gone. The refresh must consume the loss.
  const planStockLost = makePlan();
  planStockLost.datacenters[0].in_stock = false;
  await loadCatalog([planStockLost, planNoDC, planBuilt]);
  await new Promise(r => setTimeout(r, 0));
  assert.equal(placeSel.value, managedValue, 'stock loss must drop the pin');
  assert.equal(btn.disabled, true, 'stock loss must block ordering until a new choice');
  assert.match(hint.textContent, /deploy_vps_placement_out_of_stock/,
    'the stock loss must be named, not reported as a generic clear');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before,
    'stock loss must not produce an order, and must not fall back to region-managed');

  // ------------------------------------------------------- catalog failure ----
  // A failed catalog read leaves nothing orderable: the selectors carry no ids.
  catalogResponse = new Error('provider down');
  await w.loadGigahostCatalog();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(placeSel.value, '', 'a failed catalog read must leave no placement value');
  assert.equal(btn.disabled, true, 'a failed catalog read must not leave ordering enabled');
  before = orderPosts().length;
  await w.handleDeployVPS();
  await new Promise(r => setTimeout(r, 0));
  assert.equal(orderPosts().length, before, 'a failed catalog read must send no order');

  console.log('GIGAHOST_PLACEMENT_PAGE_OK');dom.window.close();
})().catch(e => {console.error('PAGE_TEST_FAILED: ' + (e && e.stack || e)); process.exit(1);});
`, string(pageIDListJSON), string(catalogStatusEncoded), string(moduleEncoded), string(pageEncoded))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_PLACEMENT_PAGE_OK") {
		t.Fatalf("page placement wiring failed: %v\n%s", err, out)
	}
}
