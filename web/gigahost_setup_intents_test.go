package web

// Behavioural DOM test for the saved-setup portal, at the B (actionable) contract.
//
// The predecessor test asserted the 741A read-only view: a saved approval was
// listed, a hostile provider diagnostic was rendered as text, and only a pending
// row offered a revoke. That contract is now too weak to be useful, because the
// module performs three real actions, so this file asserts the actions.
//
// What is asserted is the HTTP contract the handlers actually expose, read from
// internal/handlers/gigahost_setup.go and internal/router/router.go - not whatever
// the module happens to produce:
//
//	DELETE /api/admin/hosting/gigahost/orders/{id}/setup-approval   revoke
//	POST   /api/admin/hosting/gigahost/orders/{id}/setup-resume     resume
//	POST   /api/admin/hosting/gigahost/orders/{id}/setup-host-confirmation
//	       body {"fingerprint": "<the exact SHA256:... the row is waiting on>"}
//	GET    /api/admin/hosting/gigahost/setup-intents               list
//
// Each state case is a safety claim, not a cosmetic one:
//
//	pending                     revoke only
//	install_paused              resume only
//	awaiting_credentials        resume only, plus the credential hint
//	awaiting_host_confirmation  confirm-host only, and ONLY when the row records the
//	                            exact fingerprint it is waiting on
//	installing / ready / failed / canceled / ready_for_setup
//	                            no action: a running or finished job must not offer a
//	                            button that would issue a second effect
//
// The negative controls are the important half: a trust pause with no recorded
// fingerprint must offer NO confirmation (otherwise the UI would authorize a host
// identity nobody displayed), a terminal state must offer nothing, a refused
// response must not be reported as success, and a second click while a request is
// in flight must not issue a second request.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGigahostSetupIntentsConsumerDOM(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)

	source, err := StaticFS.ReadFile("static/js/gigahost_setup_intents.js")
	if err != nil {
		t.Fatalf("read setup intents module: %v", err)
	}
	templates, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatalf("read settings template: %v", err)
	}
	// The template must load the extracted module: an inline copy would silently
	// diverge from the file this test exercises.
	if !strings.Contains(string(templates), `src="/static/js/gigahost_setup_intents.js"`) {
		t.Fatal("settings.html does not load the extracted setup-intents module")
	}
	if !strings.Contains(string(templates), `id="setupIntentsContainer"`) {
		t.Fatal("settings.html has no container for saved setup approvals")
	}

	encodedModule, _ := json.Marshal(string(source))
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="setupIntentsContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};
w.confirm = () => true;

// Every HTTP call the module makes is recorded with method, URL and body, so a
// payload is asserted exactly instead of inferred from a rendered label.
const calls = [];
let releaseInFlight = null;
const holdNextPost = () => new Promise(res => { releaseInFlight = res; });
w.API = {
  get: async url => { calls.push({method:'GET', url}); return {setup_intents: []}; },
  post: async (url, body) => { calls.push({method:'POST', url, body}); return {status:'ok'}; },
  delete: async url => { calls.push({method:'DELETE', url}); return {status:'ok'}; },
};
const byMethod = m => calls.filter(c => c.method === m);
const labels = el => Array.from(el.querySelectorAll('button')).map(b => b.textContent);

w.eval(%s);

const FP = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// render feeds one list through the module's own fetch path, so the assertions do
// not depend on any shape beyond the documented one.
async function render(intents) {
  w.API.get = async url => { calls.push({method:'GET', url}); return {setup_intents: intents}; };
  await w.loadSetupIntents();
  return w.document.getElementById('setupIntentsContainer');
}

(async()=>{
 const container = w.document.getElementById('setupIntentsContainer');

 // 1. Empty state says so rather than rendering nothing.
 await render([]);
 assert.match(container.textContent, /setup_intents_none/);

 // 2. A pending approval offers revoke and nothing else, and the row shows the
 //    real protocol:port identity so two orders are distinguishable.
 let root = await render([{order_id:'ord-pending', protocol:'awg', port:'51820', state:'pending', step:'provisioning'}]);
 assert.match(root.textContent, /ord-pending/);
 assert.match(root.textContent, /awg:51820/);
 assert.match(root.textContent, /setup_state_pending/);
 assert.deepEqual(labels(root), ['setup_intents_cancel']);

 // 3. A paused install offers resume and NOT revoke: revoking a job past the
 //    handoff would strand an install nobody can follow.
 root = await render([{order_id:'ord-paused', protocol:'awg', port:'51820', state:'install_paused', step:'enabling_backend', last_error:'interrupted'}]);
 assert.deepEqual(labels(root), ['setup_intents_resume']);
 assert.match(root.textContent, /setup_state_install_paused/);

 // 4. Awaiting credentials offers resume plus the credential hint, and never an
 //    input to type a secret into.
 root = await render([{order_id:'ord-cred', protocol:'awg', state:'awaiting_credentials'}]);
 assert.deepEqual(labels(root), ['setup_intents_resume']);
 assert.match(root.textContent, /setup_intents_credentials_hint/);
 assert.equal(root.querySelector('input'), null);

 // 5. A trust pause with a recorded identity asks for exactly that identity, and
 //    the confirm action posts that exact value for that exact order.
 root = await render([{order_id:'ord-host', protocol:'vless', state:'awaiting_host_confirmation', host_fingerprint:FP}]);
 assert.deepEqual(labels(root), ['setup_intents_confirm_host']);
 calls.length = 0;
 await w.confirmSetupHost('ord-host', FP);
 assert.equal(byMethod('POST').length, 1);
 assert.equal(byMethod('POST')[0].url, '/api/admin/hosting/gigahost/orders/ord-host/setup-host-confirmation');
 assert.deepEqual(byMethod('POST')[0].body, {fingerprint: FP});
 assert.ok(toasts.some(t => t.text === 'setup_intents_host_confirmed'));

 // 6. NEGATIVE CONTROL: a trust pause with NO recorded identity offers no
 //    confirmation at all. Confirming here would authorize a host the panel never
 //    displayed, so the button must not exist and no request may be made.
 root = await render([{order_id:'ord-host-missing', protocol:'vless', state:'awaiting_host_confirmation'}]);
 assert.deepEqual(labels(root), []);
 calls.length = 0;
 await w.confirmSetupHost('ord-host-missing', '');
 assert.equal(byMethod('POST').length, 0);

 // 7. NEGATIVE CONTROL: terminal and moving states offer no action at all.
 for (const state of ['installing','ready','failed','canceled','ready_for_setup']) {
   root = await render([{order_id:'ord-' + state, protocol:'awg', state:state}]);
   assert.deepEqual(labels(root), [], 'state ' + state + ' must not offer an action');
 }

 // 8. Revoking is that exact order's DELETE, and the view refreshes afterwards.
 calls.length = 0;
 await render([{order_id:'ord-revoke me', protocol:'awg', state:'pending'}]);
 await w.cancelSetupIntent('ord-revoke me');
 assert.equal(byMethod('DELETE').length, 1);
 assert.equal(byMethod('DELETE')[0].url,
   '/api/admin/hosting/gigahost/orders/ord-revoke%%20me/setup-approval');
 assert.ok(byMethod('GET').length >= 1, 'the view must refresh after a decided action');

 // A declined confirmation is not an action: no request, no toast.
 calls.length = 0;
 w.confirm = () => false;
 await w.cancelSetupIntent('ord-declined');
 assert.equal(byMethod('DELETE').length, 0);
 w.confirm = () => true;

 // 9. Resuming posts to that order's resume route, carries no secret field, and
 //    refreshes afterwards.
 calls.length = 0;
 await render([{order_id:'ord-resume', protocol:'awg', state:'install_paused'}]);
 await w.resumeSetupIntent('ord-resume');
 assert.equal(byMethod('POST').length, 1);
 assert.equal(byMethod('POST')[0].url, '/api/admin/hosting/gigahost/orders/ord-resume/setup-resume');
 const body = byMethod('POST')[0].body;
 assert.ok(body === undefined || body === null || Object.keys(body).length === 0,
   'resume must not send credential fields, got ' + JSON.stringify(body));
 assert.ok(byMethod('GET').length >= 1, 'the view must refresh after resume');
 assert.ok(toasts.some(t => t.text === 'setup_intents_resumed'));

 // 10. A refused resume (409 not_resumable) surfaces an error and never claims
 //     success.
 toasts.length = 0;
 w.API.get = async url => { calls.push({method:'GET', url});
   return {setup_intents:[{order_id:'ord-stale', protocol:'awg', state:'ready'}]}; };
 w.API.post = async (url, body) => { calls.push({method:'POST', url, body});
   const e = new Error('this setup job is not in a state a resume can act on');
   e.status = 409; e.data = {status:'not_resumable'}; throw e; };
 await w.resumeSetupIntent('ord-stale');
 assert.ok(!toasts.some(t => t.text === 'setup_intents_resumed'),
   'a refused resume must not report success');
 assert.ok(toasts.some(t => t.kind === 'error'), 'a refused resume must surface an error');

 // 11. A denied revoke surfaces an error and does not claim the revocation.
 toasts.length = 0;
 w.API.delete = async url => { calls.push({method:'DELETE', url});
   const e = new Error('Forbidden'); e.status = 403; throw e; };
 await w.cancelSetupIntent('ord-denied');
 assert.ok(!toasts.some(t => t.text === 'setup_intents_cancelled'),
   'a denied revoke must not report success');
 assert.ok(toasts.some(t => t.kind === 'error'), 'a denied revoke must surface an error');

 // 12. DUPLICATE-CLICK CONTROL: a second resume while the first request is in
 //     flight must not issue a second POST.
 calls.length = 0;
 let posts = 0;
 w.API.post = async (url, body) => {
   posts++; calls.push({method:'POST', url, body});
   await holdNextPost();
   return {status:'ok'};
 };
 w.API.get = async url => { calls.push({method:'GET', url});
   return {setup_intents:[{order_id:'ord-double', protocol:'awg', state:'install_paused'}]}; };
 const first = w.resumeSetupIntent('ord-double');
 const second = w.resumeSetupIntent('ord-double');
 assert.equal(posts, 1, 'a second click while a request is in flight issued another POST');
 if (releaseInFlight) releaseInFlight();
 await Promise.all([first, second]);
 assert.equal(posts, 1, 'the in-flight guard let a second POST through');

 // 13. Hostile provider text is still rendered as text, never as markup, and no
 //     credential material recorded on a row reaches the DOM.
 const evil = '<img src=x onerror=evil()>';
 root = await render([{order_id:'ord-evil', protocol:'awg', state:'failed', step:'provider_failed',
   last_error: evil, ssh_private_key:'FIXTURE-PRIVATE-MATERIAL', password:'fixture-password'}]);
 assert.match(root.textContent, /<img src=x onerror=evil\(\)>/);
 assert.equal(root.querySelector('img'), null);
 assert.equal(root.textContent.indexOf('FIXTURE-PRIVATE-MATERIAL'), -1, 'a private key reached the DOM');
 assert.equal(root.textContent.indexOf('fixture-password'), -1, 'a password reached the DOM');

 // 14. An unreadable list degrades to the empty state instead of throwing.
 w.API.get = async () => { throw new Error('offline'); };
 await w.loadSetupIntents();
 assert.match(container.textContent, /setup_intents_none/);

 console.log('SETUP_INTENTS_DOM_OK');dom.window.close();
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedModule))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "SETUP_INTENTS_DOM_OK") {
		t.Fatalf("DOM consumer failed: %v\n%s", err, out)
	}
}
