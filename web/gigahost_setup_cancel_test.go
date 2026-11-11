package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestGigahostSetupCancellationSendsNoSetup covers the immediate setup prompt
// boundary: cancelling a prompt is an answer that authorizes nothing. The script
// is the deployed static asset, executed in a Node VM with mocked prompts, an API
// spy and a toast recorder, so the assertions observe the real request/telemetry
// effects of the shipped code rather than a re-implementation.
func TestGigahostSetupCancellationSendsNoSetup(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)
	setup, err := StaticFS.ReadFile("static/js/gigahost_setup.js")
	if err != nil {
		t.Fatal(err)
	}
	encodedSetup, _ := json.Marshal(string(setup))
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};
let posts = [];
let reloads = 0;
w.loadRecentOrders = () => { reloads++; };
const ok = {status:'ok',deploy:{status:'ready',server_id:42}};
w.API = {post:async(url,payload)=>{posts.push({url,payload:JSON.parse(JSON.stringify(payload))});return ok;}};
w.eval(%s);

// A cancellation must not appear as progress or as success: those are the two
// signals the owner saw while the backend was being set up without permission.
const announced = () => toasts.filter(t=>t.kind==='info'||t.kind==='success');
const reset = () => { posts=[]; toasts.length=0; };

(async()=>{
 // Cancelling the protocol prompt is an explicit refusal, not a default answer.
 reset();
 w.prompt = () => null;
 await w.triggerGigahostSetup('order-cancel-protocol');
 assert.deepEqual(posts, [], 'cancelled protocol prompt must not send a setup request');
 assert.deepEqual(announced(), [], 'cancelled protocol prompt must not announce progress');
 assert.equal(reloads, 0, 'a refused setup must not claim the order list changed');

 // Accepting the offered default (blank input, OK) is not the same answer as
 // cancelling, and must still authorize the pre-existing AWG setup.
 reset();
 w.prompt = key => key === 'deploy_protocol_prompt' ? '' : 'ignored';
 await w.triggerGigahostSetup('order-default-protocol');
 assert.equal(posts.length, 1, 'a blank accepted default must still submit once');
 assert.equal(posts[0].payload.protocol, 'awg');
 assert.equal(posts[0].payload.tls_domain, '');
 assert.equal(posts[0].payload.use_order_credential, true);
 assert.equal(toasts.at(-1).kind, 'success');

 // Cancelling the TLS domain prompt must not fall back to an empty domain: the
 // owner saw a Naive setup POST with an empty domain and a progress toast.
 reset();
 w.prompt = key => key === 'deploy_protocol_prompt' ? 'naive' : null;
 await w.triggerGigahostSetup('order-cancel-domain');
 assert.deepEqual(posts, [], 'cancelled domain prompt must not send a setup request');
 assert.deepEqual(announced(), [], 'cancelled domain prompt must not announce progress');

 // The same holds for the optional vless domain: a cancelled answer is a refusal.
 reset();
 w.prompt = key => key === 'deploy_protocol_prompt' ? 'vless' : null;
 await w.triggerGigahostSetup('order-cancel-vless-domain');
 assert.deepEqual(posts, [], 'cancelled vless domain prompt must not send a setup request');

 // A legitimate typed domain still submits it unchanged.
 reset();
 w.prompt = key => key === 'deploy_protocol_prompt' ? 'naive' : 'vpn.example.test';
 await w.triggerGigahostSetup('order-submit-domain');
 assert.equal(posts.length, 1);
 assert.equal(posts[0].payload.protocol, 'naive');
 assert.equal(posts[0].payload.tls_domain, 'vpn.example.test');
 assert.equal(toasts.at(-1).kind, 'success');

 // A declined host-identity challenge allows the challenge request itself and
 // sends no follow-up POST, and never claims success.
 reset();
 const fp = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
 w.prompt = key => key === 'deploy_protocol_prompt' ? 'awg' : '';
 w.confirm = () => false;
 w.API.post = async(url,payload)=>{
   posts.push({url,payload:JSON.parse(JSON.stringify(payload))});
   const err = new Error('challenge');
   err.status = 409;
   err.data = {status:'host_key_confirmation_required',host:'198.51.100.10',fingerprint:fp};
   throw err;
 };
 await w.triggerGigahostSetup('order-declined-fingerprint');
 assert.equal(posts.length, 1, 'the initial challenge request is allowed, no follow-up POST follows');
 assert.equal(posts[0].payload.expected_fingerprint, undefined);
 assert.equal(toasts.some(t=>t.kind==='success'), false);

 // A declined password prompt at the credential pause sends the single
 // stored-credential request that caused the pause and nothing more.
 reset();
 w.prompt = key => key === 'deploy_protocol_prompt' ? 'awg' : null;
 w.API.post = async(url,payload)=>{
   posts.push({url,payload:JSON.parse(JSON.stringify(payload))});
   const err = new Error('pause');
   err.status = 409;
   err.data = {status:'failed',code:'credential_missing'};
   throw err;
 };
 await w.triggerGigahostSetup('order-declined-password');
 assert.equal(posts.length, 1, 'a declined password prompt must not authorize a retry');
 assert.equal(posts[0].payload.use_order_credential, true);
 assert.equal(toasts.some(t=>t.kind==='success'), false);
 assert.equal(toasts.some(t=>t.kind==='error'), false);
 console.log('GIGAHOST_SETUP_CANCEL_OK');dom.window.close();
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedSetup))
	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_SETUP_CANCEL_OK") {
		t.Fatalf("setup cancellation consumer failed: %v\n%s", err, out)
	}
}
