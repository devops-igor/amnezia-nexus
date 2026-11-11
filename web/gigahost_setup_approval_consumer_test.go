package web

// Behavioural DOM test for portal-initiated saved setup approvals.
//
// The contract under test is the one the panel actually serves, read from
// internal/handlers/gigahost_setup.go and internal/router/router.go:
//
//	POST /api/admin/hosting/gigahost/orders/{id}/setup-approval
//	     body {"protocol":"awg|vless|naive","use_order_credential":true,
//	           "tls_domain":"..."}            -> 202 {created:true, setup:{...}}
//	     a repeat                          -> 200 {created:false, setup:{...}}
//
// The module is executed as shipped, in JSDOM, and the recent-orders renderer is
// extracted from templates/settings.html - the same renderer the page runs - so
// the assertions describe the buttons an administrator actually clicks rather
// than a copy of them.
//
// The negative half is the important one. A durable approval is a decision the
// panel performs later, so a cancelled prompt, an unsupported protocol or a
// declined confirmation must post nothing at all: there is no fallback protocol
// here, unlike the immediate setup path, because a default would record work
// nobody asked for. Payloads must also carry no credential material.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGigahostSetupApprovalInitiationConsumerDOM(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)

	module, err := StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read setup intents module: %v", err)
	}
	templates, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	templateStr := string(templates)
	// The saved action must be offered from the shipped renderer, and the renderer
	// itself must be the shipped module: an inline copy could diverge from it. The
	// offer is not conditioned on the provider having assigned an address, because
	// the provisioning interval before an address exists is what a saved job covers.
	if !strings.Contains(templateStr, `src="/static/js/gigahost_setup_intents.js"`) {
		t.Fatal("settings.html does not load the module that defines the action")
	}
	if !strings.Contains(templateStr, `src="/static/js/gigahost_order_status.js"`) {
		t.Fatal("settings.html does not load the module that renders the recent orders")
	}
	consumer, err := StaticFS.ReadFile("static/js/gigahost_order_status.js")
	if err != nil {
		t.Fatalf("read the recent-orders renderer: %v", err)
	}
	if !strings.Contains(string(consumer), "appendSetupApprovalAction(right, order.order_id)") {
		t.Fatal("the shipped renderer does not offer the saved setup approval action")
	}

	encodedModule, _ := json.Marshal(string(module))
	encodedConsumer, _ := json.Marshal(string(consumer))
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="recentOrdersContainer"></div><div id="setupIntentsContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};

const calls = [];
let orders = [];
let intents = [];
let approveResponse = {status:'ok', created:true, setup:{order_id:'ord-101', protocol:'vless', state:'pending'}};
let approveError = null;
let releaseInFlight = null;
const holdNextPost = () => new Promise(res => { releaseInFlight = res; });
let hold = false;
w.API = {
  get: async url => {
    calls.push({method:'GET', url});
    if (url === '/api/admin/hosting/gigahost/orders') return {orders: orders};
    if (url.indexOf('/status') !== -1) return {status:'ok', deploy:{status:'deploying'}};
    if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents: intents};
    if (url === '/api/vpn/backends') return {backends: []};
    return {};
  },
  post: async (url, body) => {
    calls.push({method:'POST', url, body});
    if (hold) await holdNextPost();
    if (approveError) throw approveError;
    return approveResponse;
  },
  delete: async url => { calls.push({method:'DELETE', url}); return {status:'ok'}; },
};
const byMethod = m => calls.filter(c => c.method === m);
const postsTo = suffix => byMethod('POST').filter(c => c.url.slice(-suffix.length) === suffix);
const flush = async () => { for (let i = 0; i < 4; i++) await new Promise(r => setTimeout(r, 0)); };
// The status cell is a button as well, so the action assertions select every button
// except that disclosure control: the actions are the rest of them.
const rowButtons = () => Array.from(w.document.querySelectorAll('#recentOrdersContainer button:not(.gigahost-order-status-toggle)')).map(b => b.textContent);
const container = w.document.getElementById('recentOrdersContainer');
const intentsContainer = w.document.getElementById('setupIntentsContainer');
const approveBtn = () => Array.from(w.document.querySelectorAll('#recentOrdersContainer button:not(.gigahost-order-status-toggle)'))
  .find(b => b.textContent === 'setup_intents_approve');

w.eval(%s);
w.eval(%s);

(async()=>{
 // 1. An order with an address offers both paths, and the saved one is labelled
 //    as the durable choice rather than the immediate setup.
 orders = [{order_id:'ord-101', status:'deploying', assigned_ip:'198.51.100.10'}];
 await w.loadRecentOrders();
 assert.deepEqual(rowButtons(), ['deploy_setup_btn','setup_intents_approve'],
   'a deployable order must offer the immediate and the saved path, got ' + JSON.stringify(rowButtons()));

 // 2. The chosen order and options are posted as the durable approval, and the
 //    panel's own answer is what reports the saved job.
 calls.length = 0; toasts.length = 0;
 w.prompt = q => q === 'deploy_protocol_prompt' ? 'vless' : 'vpn.example.com';
 w.confirm = () => true;
 intents = [{order_id:'ord-101', protocol:'vless', port:'443', state:'pending', step:'approved'}];
 approveBtn().click();
 await flush();
 assert.equal(byMethod('POST').length, 1, 'exactly one approval must be posted');
 const post = byMethod('POST')[0];
 assert.equal(post.url, '/api/admin/hosting/gigahost/orders/ord-101/setup-approval');
 assert.deepEqual(post.body, {protocol:'vless', use_order_credential:true, tls_domain:'vpn.example.com'});
 assert.equal(postsTo('/setup').length, 0, 'the saved path must not post the synchronous setup request');
 assert.ok(byMethod('GET').some(c => c.url === '/api/admin/hosting/gigahost/setup-intents'),
   'the saved job must be refreshed into view after approval');
 assert.match(intentsContainer.textContent, /ord-101/, 'the saved job must be visible');
 assert.match(intentsContainer.textContent, /setup_state_pending/);
 assert.ok(toasts.some(t => t.text === 'setup_intents_saved' && t.kind === 'success'));
 // No credential material may ever be part of an approval payload.
 const bodyText = JSON.stringify(post.body);
 ['ssh_password','ssh_key','password','private_key'].forEach(field => {
   assert.equal(bodyText.indexOf(field), -1, 'approval payload leaked ' + field + ': ' + bodyText);
 });

 // 3. NEGATIVE: a cancelled protocol prompt is an answer - nothing is posted.
 calls.length = 0; toasts.length = 0;
 w.prompt = () => null;
 await w.approveSetupIntent('ord-101');
 assert.equal(byMethod('POST').length, 0, 'a cancelled prompt must post nothing');
 assert.equal(postsTo('/setup').length, 0);
 assert.equal(toasts.length, 0, 'a cancelled choice must not report an outcome');

 // 4. NEGATIVE: cancelling the domain prompt aborts a protocol that needs one.
 calls.length = 0; toasts.length = 0;
 w.prompt = q => q === 'deploy_protocol_prompt' ? 'naive' : null;
 await w.approveSetupIntent('ord-101');
 assert.equal(byMethod('POST').length, 0, 'a cancelled domain prompt must post nothing');

 // 5. NEGATIVE: an unsupported protocol is refused in the browser, so nothing is
 //    posted and the panel is not asked to refuse it.
 calls.length = 0; toasts.length = 0;
 w.prompt = () => 'wireguard-ng';
 await w.approveSetupIntent('ord-101');
 assert.equal(byMethod('POST').length, 0, 'an unsupported protocol must post nothing');
 assert.ok(toasts.some(t => t.kind === 'error'), 'an unsupported protocol must be reported');

 // 6. NEGATIVE: a declined confirmation is not an approval.
 calls.length = 0; toasts.length = 0;
 w.prompt = q => q === 'deploy_protocol_prompt' ? 'awg' : '';
 w.confirm = () => false;
 await w.approveSetupIntent('ord-101');
 assert.equal(byMethod('POST').length, 0, 'a declined confirmation must post nothing');
 w.confirm = () => true;

 // 7. awg needs no domain, so no second prompt is asked and no tls_domain is sent.
 calls.length = 0; toasts.length = 0;
 let prompted = [];
 w.prompt = q => { prompted.push(q); return 'AWG'; };
 await w.approveSetupIntent('ord-101');
 assert.deepEqual(prompted, ['deploy_protocol_prompt'], 'awg must not ask for a TLS domain');
 assert.deepEqual(byMethod('POST')[0].body, {protocol:'awg', use_order_credential:true});

 // 8. A repeated approval (200, created:false) is reported as already saved, not
 //    as a second job and not as an error.
 calls.length = 0; toasts.length = 0;
 approveResponse = {status:'ok', created:false, setup:{order_id:'ord-101', protocol:'awg', state:'pending'}};
 w.prompt = q => q === 'deploy_protocol_prompt' ? 'awg' : '';
 await w.approveSetupIntent('ord-101');
 assert.equal(byMethod('POST').length, 1);
 assert.ok(toasts.some(t => t.text === 'setup_intents_already_saved' && t.kind === 'info'),
   'a repeated approval must be reported as already saved, got ' + JSON.stringify(toasts));
 assert.equal(toasts.some(t => t.kind === 'error'), false);
 approveResponse = {status:'ok', created:true, setup:{order_id:'ord-101', protocol:'awg', state:'pending'}};

 // 9. NEGATIVE: a refused approval surfaces the panel's error and claims nothing.
 calls.length = 0; toasts.length = 0;
 const refusal = new Error('order ord-101 is not recorded');
 refusal.status = 400;
 approveError = refusal;
 await w.approveSetupIntent('ord-101');
 approveError = null;
 assert.equal(toasts.some(t => t.text === 'setup_intents_saved'), false,
   'a refused approval must not report a saved job');
 assert.ok(toasts.some(t => t.kind === 'error'));

 // 10. DUPLICATE-CLICK CONTROL: a second click while the first request is open
 //     must not issue a second approval.
 calls.length = 0; toasts.length = 0;
 hold = true;
 w.prompt = q => q === 'deploy_protocol_prompt' ? 'awg' : '';
 const first = w.approveSetupIntent('ord-101');
 const second = w.approveSetupIntent('ord-101');
 await flush();
 assert.equal(byMethod('POST').length, 1, 'a second click issued another approval');
 if (releaseInFlight) releaseInFlight();
 hold = false;
 await Promise.all([first, second]);
 assert.equal(byMethod('POST').length, 1, 'the in-flight guard let a second approval through');

 // 11. THE DEFECT ORACLE: a real pending order the provider has not addressed yet
 //     still offers the saved action, and only that. This is the state the saved
 //     path exists for: the administrator approves now and closes the browser while
 //     provisioning continues.
 orders = [{order_id:'ord-noip', status:'pending'}];
 await w.loadRecentOrders();
 assert.deepEqual(rowButtons(), ['setup_intents_approve'],
   'a pending order with no address must offer the saved action and no immediate setup, got ' + JSON.stringify(rowButtons()));

 // 12. That approval posts exactly one existing approval request - the same route
 //     and body as an addressed order - and the saved job is shown afterwards.
 calls.length = 0; toasts.length = 0; intents.length = 0;
 w.prompt = q => q === 'deploy_protocol_prompt' ? 'vless' : 'vpn.example.com';
 w.confirm = () => true;
 const savedJob = {order_id:'ord-noip', protocol:'vless', port:'443', state:'pending', step:'approved'};
 approveResponse = {status:'ok', created:true, setup: savedJob};
 intents = [savedJob];
 approveBtn().click();
 await flush();
 assert.equal(byMethod('POST').length, 1, 'the pre-address approval must post exactly once, got ' + JSON.stringify(byMethod('POST')));
 assert.equal(byMethod('POST')[0].url, '/api/admin/hosting/gigahost/orders/ord-noip/setup-approval');
 assert.deepEqual(byMethod('POST')[0].body, {protocol:'vless', use_order_credential:true, tls_domain:'vpn.example.com'});
 assert.equal(postsTo('/setup').length, 0, 'the saved path must not post the synchronous setup request');
 assert.match(intentsContainer.textContent, /ord-noip/, 'the saved job for a pre-address order must be visible');
 assert.match(intentsContainer.textContent, /setup_state_pending/);
 assert.ok(toasts.some(t => t.text === 'setup_intents_saved' && t.kind === 'success'));

 // 13. NEGATIVE: the same pre-address order with a cancelled prompt posts nothing.
 calls.length = 0; toasts.length = 0;
 w.prompt = () => null;
 approveBtn().click();
 await flush();
 assert.equal(byMethod('POST').length, 0, 'a cancelled choice on a pre-address order must post nothing');
 assert.equal(postsTo('/setup').length, 0);

 // 14. NEGATIVE: a ledger placeholder id has no confirmed provider order behind it,
 //     so it offers no saved action even though the endpoint would refuse it too.
 approveResponse = {status:'ok', created:true, setup:{order_id:'ord-101', protocol:'awg', state:'pending'}};
 orders = [{order_id:'intent_1700000000000', status:'pending'}];
 await w.loadRecentOrders();
 assert.deepEqual(rowButtons(), [], 'a placeholder order must offer no setup action, got ' + JSON.stringify(rowButtons()));

 console.log('SETUP_APPROVAL_INITIATION_DOM_OK');dom.window.close();
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedModule), string(encodedConsumer))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "SETUP_APPROVAL_INITIATION_DOM_OK") {
		t.Fatalf("DOM consumer failed: %v\n%s", err, out)
	}
}
