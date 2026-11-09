package web

// Behavioural DOM test for the saved-setup-approval panel.
//
// This drives the real extracted module in a jsdom document with a stubbed API,
// which is the same harness the existing Gigahost settings test uses. What it
// proves is the two things a browser-independent view must get right: every saved
// approval is visible with its real state, and untrusted provider text becomes
// text rather than markup.

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
	// The template must actually load the extracted module: an inline copy would
	// silently diverge from the file this test exercises.
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
const deletes = [];
w.eval(%s);

(async()=>{
 const container = w.document.getElementById('setupIntentsContainer');

 // Empty state says so rather than rendering nothing.
 w.API = {get:async()=>({setup_intents:[]})};
 await w.loadSetupIntents();
 assert.match(container.textContent,/setup_intents_none/);

 // A saved approval from a closed browser is visible with its real state, and a
 // hostile provider diagnostic is rendered as text, never as markup.
 const evil = '<img src=x onerror=evil()>';
 w.API = {get:async()=>({setup_intents:[
   {order_id:'ord-1',protocol:'vless',port:'443',state:'ready_for_setup',step:'ready_for_setup'},
   {order_id:'ord-2',protocol:'awg',port:'51820',state:'failed',step:'provider_failed',last_error:evil}
 ]})};
 await w.loadSetupIntents();
 assert.match(container.textContent,/ord-1/);
 assert.match(container.textContent,/vless:443/);
 assert.match(container.textContent,/setup_state_ready_for_setup/);
 assert.match(container.textContent,/ord-2/);
 assert.match(container.textContent,/provider_failed/);
 assert.match(container.textContent,/<img src=x onerror=evil\(\)>/);
 assert.equal(container.querySelector('img'),null);

 // Only a pending approval offers a revoke control; a settled one does not.
 const buttons = Array.from(container.querySelectorAll('button'));
 assert.equal(buttons.length,0);

 w.API = {get:async()=>({setup_intents:[{order_id:'ord-3',protocol:'awg',port:'51820',state:'pending'}]})};
 await w.loadSetupIntents();
 const revoke = Array.from(container.querySelectorAll('button'));
 assert.equal(revoke.length,1);
 assert.equal(revoke[0].textContent,'setup_intents_cancel');

 // Revoking calls the cancel endpoint for that exact order and refreshes.
 w.API = {
   get:async()=>({setup_intents:[{order_id:'ord-3',protocol:'awg',state:'cancelled'}]}),
   delete:async url => { deletes.push(url); return {status:'ok'}; }
 };
 await w.cancelSetupIntent('ord-3');
 assert.equal(deletes.length,1);
 assert.equal(deletes[0],'/api/admin/hosting/gigahost/orders/ord-3/setup-approval');
 assert.ok(toasts.some(t=>t.text==='setup_intents_cancelled'));

 // A refused confirmation is not a revocation and produces no request.
 deletes.length = 0;
 w.confirm = () => false;
 await w.cancelSetupIntent('ord-4');
 assert.equal(deletes.length,0);

 // An unreadable API degrades to the empty state instead of throwing.
 w.API = {get:async()=>{throw new Error('offline');}};
 await w.loadSetupIntents();
 assert.match(container.textContent,/setup_intents_none/);

 console.log('SETUP_INTENTS_DOM_OK');dom.window.close();
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedModule))

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "SETUP_INTENTS_DOM_OK") {
		t.Fatalf("DOM consumer failed: %v\n%s", err, out)
	}
}
