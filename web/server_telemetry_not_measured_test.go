package web

// What the server page renders when the stats poll comes back "not measured".
//
// The backend refuses the SSH session for a server the provider's inventory no
// longer lists and answers with a not-measured body. The page must show that,
// instead of leaving the previous sample on screen or painting zeros that read as
// a healthy (or a dead) host. One continuous JSDOM lifecycle drives the shipped
// module through both answers, so the branch is asserted on the rendered DOM.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestServerTelemetry_NotMeasuredStatsRenderAsNotChecked(t *testing.T) {
	module, err := StaticFS.ReadFile("static/js/server_telemetry.js")
	if err != nil {
		t.Fatalf("read the telemetry module: %v", err)
	}
	encoded, _ := json.Marshal(string(module))

	node := requireJSDOM(t)
	script := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<div id="serverStats"><span class="stat-pill">CPU: 41%%</span></div>', {runScripts:'outside-only'});
const w = dom.window;
w._ = key => (key === 'gigahost_status_not_checked' ? 'Not checked yet' : key);
w.UI = {formatBytes: bytes => String(bytes)};
w.SERVER_ID = 7;
let nextPayload = null;
w.API = {post: async () => nextPayload};

w.eval(%s);

(async () => {
  const el = w.document.getElementById('serverStats');

  // 1. A not-measured answer: no fabricated sample, the existing not-checked label.
  nextPayload = {status: 'provider_absent', not_measured: true, provider_absent: true};
  await w.loadServerStats();
  const notMeasured = el.textContent;
  if (!/Not checked yet/.test(notMeasured)) {
    console.error('FAIL: the not-measured answer did not render the not-checked label: ' + notMeasured);
    process.exit(1);
  }
  if (/CPU:|RAM:|Disk:|%%/.test(notMeasured)) {
    console.error('FAIL: the not-measured answer still rendered a sample: ' + notMeasured);
    process.exit(1);
  }

  // 2. A real answer still renders the pills, so the branch is a branch and not a
  //    disabled renderer.
  nextPayload = {cpu: 12, ram_used: 2048, ram_total: 4096, ram_percent: 50, disk_used: 10, disk_total: 40, disk_percent: 25, net_rx: 1024, net_tx: 2048};
  await w.loadServerStats();
  const measured = el.textContent;
  if (!/CPU: 12/.test(measured) || !/RAM: 50/.test(measured)) {
    console.error('FAIL: a measured answer did not render its pills: ' + measured);
    process.exit(1);
  }
  console.log('PASS');
})();
`, encoded)

	out, err := execNodeScript(node, script)
	if err != nil || !strings.Contains(string(out), "PASS") {
		t.Fatalf("server telemetry render: %v\n%s", err, string(out))
	}
}
