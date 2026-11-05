package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestGigahostSettingsConsumerDOM(t *testing.T) {
	node := requireNode(t)
	requireJSDOM(t)
	source, err := TemplatesFS.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := extractJSFunction(string(source), "async function loadRecentOrders")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := StaticFS.ReadFile("static/js/gigahost_setup.js")
	if err != nil {
		t.Fatal(err)
	}
	encodedConsumer, _ := json.Marshal(consumer)
	encodedSetup, _ := json.Marshal(string(setup))
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="recentOrdersContainer"></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => key;
w.scheduleRecentOrdersPolling = () => {};
const toasts = [];
w.UI = {toast:(text,kind)=>toasts.push({text,kind})};
w.eval(%s);
let failed = true;
w.API = {get:async url => url.endsWith('/status') ? {status:'ok',deploy:failed ? {status:'failed',step:'installing_protocol',error:'<img src=x onerror=evil()>',server_id:42} : {status:'ready',step:'ready',server_id:42}} : {orders:[{order_id:'order-1',status:'ready',assigned_ip:'198.51.100.10'}]}};
(async()=>{
 await w.loadRecentOrders();
 let root = w.document.getElementById('recentOrdersContainer');
 assert.match(root.textContent,/installing_protocol/);
 assert.match(root.textContent,/<img src=x onerror=evil\(\)>/);
 assert.equal(root.querySelector('img'),null);
 assert.equal(root.querySelector('.badge').textContent,'failed');
 assert.equal(root.querySelector('button').textContent,'deploy_retry_btn');
 failed=false;
 await w.loadRecentOrders();
 assert.equal(root.querySelector('.badge').textContent,'ready');
 assert.equal(root.querySelector('button'),null);
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
 calls=[];toasts.length=0;
 w.API.post=async()=>{throw new Error('qualification refused');};
 await w.triggerGigahostSetup('order-1');
 assert.equal(toasts.at(-1).kind,'error');
 assert.equal(toasts.some(t=>t.kind==='success'),false);
 console.log('GIGAHOST_DOM_OK');dom.window.close();
})().catch(err=>{console.error(err);process.exit(1)});
`, string(encodedConsumer), string(encodedSetup))
	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "GIGAHOST_DOM_OK") {
		t.Fatalf("DOM consumer failed: %v\n%s", err, out)
	}
}
