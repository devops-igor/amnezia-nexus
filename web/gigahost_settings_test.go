package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestGigahostSettingsConsumerDOM runs the shipped recent-orders renderer against
// the shipped setup module, so the assertions describe the request and reading
// paths an administrator actually gets.
//
// The status cell moved into its own module, so the fixture evaluates that module
// instead of extracting an inline function: an inline copy could silently diverge
// from the asset the page loads.
func TestGigahostSettingsConsumerDOM(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)
	statusModule, err := StaticFS.ReadFile("static/js/gigahost_order_status.js")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := StaticFS.ReadFile("static/js/gigahost_setup.js")
	if err != nil {
		t.Fatal(err)
	}
	encodedStatus, _ := json.Marshal(string(statusModule))
	encodedSetup, _ := json.Marshal(string(setup))
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};
w.appendSetupApprovalAction = () => {};
w.eval(%s);
let failed = true;
w.API = {get:async url => {
  if (url === '/api/admin/hosting/gigahost/orders') return {orders:[{order_id:'order-1',status:'ready',assigned_ip:'198.51.100.10'}]};
  if (url === '/api/admin/hosting/gigahost/setup-intents') return {setup_intents:[]};
  if (url === '/api/vpn/backends') return {backends:[]};
  if (url.endsWith('/status')) return {status:'ok',deploy:failed
    ? {status:'failed',step:'installing_protocol',error:'<img src=x onerror=evil()>',server_id:42}
    : {status:'ready',step:'ready',server_id:42}};
  throw new Error('unexpected GET ' + url);
}};
// A provider diagnostic is untrusted input: it belongs in the details as text.
const stage = root => { const el = root.querySelector('.gigahost-order-status'); return el && el.getAttribute('data-stage'); };
const actions = root => Array.from(root.querySelectorAll('button:not(.gigahost-order-status-toggle)')).map(b => b.textContent);
(async()=>{
 await w.loadRecentOrders();
 let root = w.document.getElementById('recentOrdersContainer');
 assert.match(root.textContent,/installing_protocol/);
 assert.ok(root.textContent.indexOf('<img src=x onerror=evil()>') !== -1, 'the diagnostic must be shown as text');
 assert.equal(root.querySelector('img'),null);
 assert.equal(stage(root),'failed');
 assert.deepEqual(actions(root),['deploy_retry_btn']);
 failed=false;
 await w.loadRecentOrders();
 assert.equal(stage(root),'ready');
 assert.deepEqual(actions(root),[]);
 w.eval(%s);
 w.loadRecentOrders=()=>{};
 w.prompt = key => key==='deploy_protocol_prompt' ? 'awg' : 'fixture-only';
 let allow=false, calls=[], confirmations=[];
 const fp='SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
 w.confirm=text=>{confirmations.push(text);return allow;};
 w.API.post=async(url,payload)=>{
   calls.push(JSON.parse(JSON.stringify(payload)));
   if(!payload.expected_fingerprint) {const err=new Error('challenge');err.status=409;err.data={status:'host_key_confirmation_required',host:'198.51.100.10',fingerprint:fp};throw err;}
   assert.equal(payload.expected_fingerprint,fp);
   return {status:'ok',deploy:{status:'ready',server_id:42}};
 };
 await w.triggerGigahostSetup('order-1');
 assert.equal(calls.length,1);
 assert.equal(calls[0].confirm_host_key,undefined);
 assert.match(confirmations[0],new RegExp('198.51.100.10'));
 assert.ok(confirmations[0].includes(fp));
 allow=true;calls=[];toasts.length=0;
 await w.triggerGigahostSetup('order-1');
 assert.equal(calls.length,2);
 assert.equal(calls[1].expected_fingerprint,fp);
 assert.equal(toasts.at(-1).kind,'success');
 // The managed-credential path is the default: the first request carries the
 // opt-in and no password at all.
 assert.equal(calls[0].use_order_credential,true);
 assert.equal(calls[0].ssh_password,undefined);
 calls=[];toasts.length=0;
 w.API.post=async()=>{throw new Error('qualification refused');};
 await w.triggerGigahostSetup('order-1');
 assert.equal(toasts.at(-1).kind,'error');
 assert.equal(toasts.some(t=>t.kind==='success'),false);
 // credential_missing pause: the operator is asked for a password and that
 // password is what the retry sends, without the stored-credential opt-in.
 calls=[];toasts.length=0;
 let prompted=[];
 w.prompt = key => {prompted.push(key);return key==='deploy_protocol_prompt' ? 'naive' : 'fixture-password';};
 w.API.post=async(url,payload)=>{
   calls.push(JSON.parse(JSON.stringify(payload)));
   if(payload.use_order_credential){const err=new Error('pause');err.status=409;err.data={status:'failed',code:'credential_missing'};throw err;}
   return {status:'ok',deploy:{status:'ready',server_id:42}};
 };
 await w.triggerGigahostSetup('order-2');
 assert.ok(prompted.includes('deploy_ssh_password_prompt'));
 assert.equal(calls.length,2);
 assert.equal(calls[0].use_order_credential,true);
 assert.equal(calls[1].use_order_credential,undefined);
 assert.equal(calls[1].ssh_password,'fixture-password');
 assert.equal(toasts.at(-1).kind,'success');
 // A declined host-identity confirmation reports nothing and does not claim success.
 calls=[];toasts.length=0;allow=false;
 w.prompt = key => key==='deploy_protocol_prompt' ? 'awg' : 'fixture-only';
 w.API.post=async(url,payload)=>{
   calls.push(JSON.parse(JSON.stringify(payload)));
   const err=new Error('challenge');err.status=409;err.data={status:'host_key_confirmation_required',host:'198.51.100.10',fingerprint:fp};throw err;
 };
 await w.triggerGigahostSetup('order-3');
 assert.equal(calls.length,1);
 assert.equal(toasts.some(t=>t.kind==='error'),false);
 assert.equal(toasts.some(t=>t.kind==='success'),false);
 console.log('GIGAHOST_DOM_OK');dom.window.close();
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedStatus), string(encodedSetup))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_DOM_OK") {
		t.Fatalf("DOM consumer failed: %v\n%s", err, out)
	}
}
