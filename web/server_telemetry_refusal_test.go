package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func requireTelemetryRefusalJSDOM(t *testing.T) string {
	t.Helper()
	node, err := findNodeBinary()
	if err != nil {
		t.Fatalf("telemetry refusal guard requires Node and jsdom: %v", err)
	}
	out, err := execNodeScript(node, jsdomBootstrapSnippet+`console.log("JSDOM_READY");`)
	if err != nil || !strings.Contains(string(out), "JSDOM_READY") {
		t.Fatalf("telemetry refusal guard requires jsdom: %v\n%s", err, out)
	}
	return node
}

func TestServerTelemetry_NotMeasuredCheckAndReachability(t *testing.T) {
	module, err := StaticFS.ReadFile("static/js/server_telemetry.js")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(string(module))
	if err != nil {
		t.Fatal(err)
	}
	node := requireTelemetryRefusalJSDOM(t)
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<button id="checkBtn"></button><span id="checkBtnText"></span><span id="checkSpinner" class="hidden"></span><span id="checkIcon"></span><div id="serverStatus" class="hidden"></div><div id="statusBadges"></div><div id="reachabilityOverallBadge"></div><div id="mimicryHealthBadges">old</div><div id="awg-mimicry-health">old</div><div id="reachabilityLastChecked">old</div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = k => k;
w.SERVER_ID = 7;
let toasts = [], calls = [], payload;
w.UI = {toast: (...args) => toasts.push(args), escapeHtml: x => String(x)};
w.API = {post: async url => { calls.push(url); return payload; }, get: async url => { calls.push(url); return payload; }};
w.eval(%s);
(async () => {
  for (const path of ['cold', 'warm']) {
    payload = {status:'provider_absent', not_measured:true, provider_absent:true};
    calls = []; toasts = [];
    await w.checkServer();
    assert.match(w.document.getElementById('statusBadges').textContent, /gigahost_status_not_checked/, path);
    assert.doesNotMatch(w.document.getElementById('statusBadges').textContent, /ssh_ok|docker_ok|docker_not_installed/);
    assert.deepStrictEqual(toasts, [], 'refusal is not a successful check');
    assert.strictEqual(calls.length, 1, 'no follow-up probe or connection load');
    assert.strictEqual(w.document.getElementById('checkBtn').disabled, false);
    assert(w.document.getElementById('checkSpinner').classList.contains('hidden'));
    await w.updateReachability();
    assert.match(w.document.getElementById('reachabilityOverallBadge').textContent, /gigahost_status_not_checked/);
    assert.doesNotMatch(w.document.getElementById('reachabilityOverallBadge').textContent, /unreachable|ms/);
    for (const id of ['mimicryHealthBadges', 'awg-mimicry-health', 'reachabilityLastChecked']) assert.strictEqual(w.document.getElementById(id).textContent, '');
  }
  payload = {connection:'ok', docker_installed:true};
  await w.checkServer();
  assert.match(w.document.getElementById('statusBadges').textContent, /ssh_ok/);
  assert.match(w.document.getElementById('statusBadges').textContent, /docker_ok/);
  assert(toasts.some(x => x[0] === 'check_done' && x[1] === 'success'));
  payload = {reachable:true, latency_ms:12};
  await w.updateReachability();
  assert.match(w.document.getElementById('reachabilityOverallBadge').textContent, /12ms/);
  payload = {reachable:false};
  await w.updateReachability();
  assert.match(w.document.getElementById('reachabilityOverallBadge').textContent, /unreachable/);
  console.log('PASS');
})().catch(err => { console.error(err); process.exit(1); });
`, encoded)
	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("telemetry refusal: %v\n%s", err, out)
	}
}
