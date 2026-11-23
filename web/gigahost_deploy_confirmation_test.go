package web

// Regression: Deploy VPS is a paid action and must not place an order before the
// operator confirms the plan, region, image and cost. The defect it pins: with a
// local catalog the button posted /api/admin/hosting/gigahost/order immediately,
// with no confirmation and no statement of what was being bought.
//
// These cases run the ACTUAL shipped page script against a deferred UI.confirm, so
// they can hold the answer open and observe the page while the operator decides.
// Cancelling must send nothing and leave every selection and the button untouched;
// confirming must send exactly the payload the page built, once.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// deployConfirmationTranslations reads the shipped English strings this flow
// renders. The expectations below are built from them, so a locale edit that drops
// a placeholder fails here instead of silently producing a sentence with holes.
func deployConfirmationTranslations(t *testing.T) map[string]string {
	t.Helper()
	raw, err := TranslationsFS.ReadFile("translations/en.json")
	if err != nil {
		t.Fatalf("read en.json: %v", err)
	}
	var dict map[string]string
	if err := json.Unmarshal(raw, &dict); err != nil {
		t.Fatalf("decode en.json: %v", err)
	}
	keys := []string{
		"deploy_vps_confirm_title", "deploy_vps_confirm_body", "deploy_vps_cost_hourly",
		"deploy_vps_cost_ceiling", "deploy_vps_cost_unknown", "deploy_vps_btn",
	}
	for _, key := range keys {
		if strings.TrimSpace(dict[key]) == "" {
			t.Fatalf("en.json is missing %q", key)
		}
	}
	for _, key := range []string{"deploy_vps_confirm_body", "deploy_vps_cost_hourly", "deploy_vps_cost_ceiling"} {
		if !strings.Contains(dict[key], "{") {
			t.Fatalf("%q carries no placeholder: %q", key, dict[key])
		}
	}
	return dict
}

func TestGigahostDeployVPSConfirmsBeforeOrdering(t *testing.T) {
	node := requireJSDOM(t)

	pageJS := settingsPageScript(t)
	moduleJS, err := StaticFS.ReadFile("static/js/gigahost_placement.js")
	if err != nil {
		t.Fatalf("read placement module: %v", err)
	}
	catalogStatusJS, err := StaticFS.ReadFile("static/js/gigahost_catalog_status.js")
	if err != nil {
		t.Fatalf("read catalog status module: %v", err)
	}
	dict := deployConfirmationTranslations(t)

	// The two summaries the page must produce, in the shipped wording. The facts are
	// the ones the payload carries and the selectors show; the price half is the
	// provider's own quote, not a figure the page invents.
	hourly := strings.NewReplacer("{rate}", strconv.FormatFloat(0.14375, 'f', -1, 64), "{currency}", "NOK").
		Replace(dict["deploy_vps_cost_hourly"])
	ceiling := strings.NewReplacer("{ceiling}", "90", "{currency}", "NOK").
		Replace(dict["deploy_vps_cost_ceiling"])
	quotedMessage := strings.NewReplacer(
		"{plan}", "Cloud 2", "{region}", "Norway (NO)", "{os}", "Debian 12",
		"{cost}", hourly+", "+ceiling,
	).Replace(dict["deploy_vps_confirm_body"])
	unquotedMessage := strings.NewReplacer(
		"{plan}", "Unpriced 1", "{region}", "Norway (NO)", "{os}", "Debian 12",
		"{cost}", dict["deploy_vps_cost_unknown"],
	).Replace(dict["deploy_vps_confirm_body"])

	pageEncoded, _ := json.Marshal(pageJS)
	moduleEncoded, _ := json.Marshal(string(moduleJS))
	catalogStatusEncoded, _ := json.Marshal(string(catalogStatusJS))
	idsEncoded, _ := json.Marshal(pageElementIDs(pageJS))
	dictEncoded, _ := json.Marshal(dict)
	quotedEncoded, _ := json.Marshal(quotedMessage)
	unquotedEncoded, _ := json.Marshal(unquotedMessage)

	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<!doctype html><html><body></body></html>', {runScripts:'outside-only'});
const w = dom.window;
const DICT = %s;
w._ = key => (Object.prototype.hasOwnProperty.call(DICT, key) ? DICT[key] : key);

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
                         ['div','deployCatalogLoading'],['div','deployCatalogStale'],
                         ['div','recentOrdersContainer'],['div','setupIntentsContainer']]) { mk(tag, id); }

const posts = [];
let catalogResponse = {plans: []};
// A deferred answer: the operator has been shown the summary and has not decided.
const asked = [];
let decide = null;
w.UI = {
  toast: () => {},
  confirm: options => {
    asked.push(options);
    return new Promise(resolve => { decide = resolve; });
  },
};
w.API = {
  get: async url => (url.indexOf('/catalog') !== -1) ? catalogResponse : {orders:[], setup_intents:[]},
  post: async (url, body) => { posts.push({url, body}); return {message:'ok'}; },
  delete: async () => ({status:'ok'}),
};
w.confirm = () => true;
w.startGigahostOrderStatusRefresh = () => {};
w.loadRecentOrders = () => {};
w.loadSetupIntents = () => {};
w.saveSettings = () => {};
w.checkUpstreamStatus = () => {};
w.setupIntentsInFlight = new Set();

w.eval(%s);
w.eval(%s);
w.eval(%s);

const planSel = w.document.getElementById('deployPlanSelect');
const regionSel = w.document.getElementById('deployRegionSelect');
const placeSel = w.document.getElementById('deployPlacementSelect');
const osSel = w.document.getElementById('deployOSSelect');
const btn = w.document.getElementById('btnDeployVPS');
const spinner = w.document.getElementById('deployVPSSpinner');
// Mirrors the shipped markup, whose spinner starts hidden.
spinner.className = 'spinner spinner-sm hidden';
const fire = el => el.dispatchEvent(new w.Event('change', {bubbles:true}));
const orderPosts = () => posts.filter(p => p.url.indexOf('/order') !== -1);
const tick = () => new Promise(r => setTimeout(r, 0));

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
      {id: 3, name: 'DC3', region_id: 2, location: 'Stockholm', country: 'SE', in_stock: true}
    ],
    os_options: [{os_id: 12, os_name: 'Debian 12'}]
  };
  return Object.assign(base, overrides || {});
}

const quoted = makePlan();
// A provider catalog entry with no price facts in it at all.
const unpriced = makePlan({
  product_id: 130, price_id: 570, name: 'Unpriced 1',
  hourly_rate_nok: 0, monthly_ceiling_nok: 0, datacenters: []
});

async function loadCatalog(plans) {
  catalogResponse = {plans};
  await w.loadGigahostCatalog();
  await tick();
}

// ready places the page in an orderable state the way an operator would: a plan, a
// region, an image, and a deliberate datacenter choice.
async function ready() {
  await loadCatalog([quoted, unpriced]);
  planSel.value = '0'; fire(planSel);
  regionSel.value = '1'; fire(regionSel);
  placeSel.value = '1'; fire(placeSel);
  osSel.value = '12'; fire(osSel);
  assert.equal(btn.disabled, false, 'precondition: this selection must be orderable');
}

(async () => {
  await ready();

  // ---- cancelling sends nothing and leaves the form untouched -----------------
  const cancelled = w.handleDeployVPS();
  await tick();
  assert.equal(asked.length, 1, 'pressing Deploy VPS must ask for confirmation before ordering');
  assert.equal(orderPosts().length, 0, 'nothing may be sent while the operator is deciding');
  assert.equal(btn.disabled, false, 'the button is not disabled while the confirmation is open');
  const title = asked[0].title;
  const message = asked[0].message;
  assert.equal(title, DICT.deploy_vps_confirm_title, 'the confirmation must carry its own title');
  assert.equal(asked[0].confirmText, DICT.deploy_vps_btn, 'the confirming control names the action');
  assert.equal(asked[0].confirmVariant, 'primary', 'a purchase is confirmed as a primary action, not a danger');
  assert.equal(message, %s, 'the confirmation must name plan, region, image and the provider quote');
  decide(false);
  await cancelled;
  await tick();
  assert.equal(orderPosts().length, 0, 'cancelling must send no order');
  assert.equal(btn.disabled, false, 'cancelling must leave the button usable');
  assert.equal(spinner.classList.contains('hidden'), true, 'cancelling must not start the spinner');
  assert.equal(planSel.value, '0', 'cancelling must keep the plan');
  assert.equal(regionSel.value, '1', 'cancelling must keep the region');
  assert.equal(osSel.value, '12', 'cancelling must keep the operating system');
  assert.equal(placeSel.value, '1', 'cancelling must keep the datacenter choice');
  assert.equal(asked.length, 1, 'cancelling must not re-open the confirmation');

  // ---- confirming sends exactly the order that was described -----------------
  const confirmed = w.handleDeployVPS();
  await tick();
  assert.equal(asked.length, 2, 'a second press must ask again rather than remember');
  assert.equal(asked[1].message, message, 'the repeated summary must describe the same order');
  assert.equal(orderPosts().length, 0, 'the order must not leave the page before the answer');
  decide(true);
  await confirmed;
  await tick();
  assert.equal(orderPosts().length, 1, 'confirming must place the order exactly once');
  const body = JSON.parse(JSON.stringify(orderPosts()[0].body));
  assert.deepStrictEqual(body,
    {pid:101, price_id:555, region_id:1, os_id:12, hourly_price_nok:0.14375, dc_id:1},
    'the confirmed order must carry the selection the summary described');
  assert.equal(btn.disabled, false, 'the button must be usable again after the order settles');

  // ---- two rapid presses cannot become two orders ---------------------------
  // The form is left alone while the dialog is open, so the pending confirmation
  // itself is the guard, not a disabled button.
  const firstPress = w.handleDeployVPS();
  await tick();
  const secondPress = w.handleDeployVPS();
  await tick();
  assert.equal(asked.length, 3, 'the second press must not open a second confirmation');
  assert.equal(orderPosts().length, 1, 'the second press must send nothing while undecided');
  decide(true);
  await Promise.all([firstPress, secondPress]);
  await tick();
  assert.equal(orderPosts().length, 2, 'confirming once must place exactly one more order');
  assert.equal(asked.length, 3, 'the answered confirmation must not re-open by itself');

  // ---- a catalog entry the provider did not price says so --------------------
  planSel.value = '1'; fire(planSel);
  regionSel.value = '1'; fire(regionSel);
  placeSel.value = placeSel.options[0].value; fire(placeSel);
  osSel.value = '12'; fire(osSel);
  assert.equal(btn.disabled, false, 'precondition: the unpriced plan is still orderable');
  const unpricedRun = w.handleDeployVPS();
  await tick();
  assert.equal(asked.length, 4, 'the unpriced plan must still be confirmed');
  assert.equal(asked[3].message, %s,
    'a plan with no quoted price must say so instead of showing a made-up figure');
  decide(false);
  await unpricedRun;
  await tick();
  assert.equal(orderPosts().length, 2, 'the unpriced run was cancelled, so it must add no order');

  console.log('GIGAHOST_DEPLOY_CONFIRMATION_OK');dom.window.close();
})().catch(e => {console.error('CONFIRMATION_TEST_FAILED: ' + (e && e.stack || e)); process.exit(1);});
`,
		string(dictEncoded), string(idsEncoded), string(catalogStatusEncoded), string(moduleEncoded),
		string(pageEncoded), string(quotedEncoded), string(unquotedEncoded))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_DEPLOY_CONFIRMATION_OK") {
		t.Fatalf("deploy confirmation regression failed: %v\n%s", err, out)
	}
}
