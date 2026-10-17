package web

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestServerTemplateAndActionsJSDOM(t *testing.T) {
	nodePath := requireJSDOM(t)

	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	serverBytes, err := fs.ReadFile(templatesFS, "server.html")
	if err != nil {
		t.Fatalf("failed to read server.html: %v", err)
	}
	serverHTML := string(serverBytes)

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}
	actionsBytes, err := fs.ReadFile(staticFS, "js/server_actions.js")
	if err != nil {
		t.Fatalf("failed to read js/server_actions.js: %v", err)
	}
	actionsJS := string(actionsBytes)

	// 1. Assert server.html contains <script src="/static/js/server_actions.js"></script> before the inline <script> block.
	const scriptTag = `<script src="/static/js/server_actions.js"></script>`
	scriptIdx := strings.Index(serverHTML, scriptTag)
	if scriptIdx == -1 {
		t.Fatalf("server.html missing required script tag: %q", scriptTag)
	}
	inlineScriptRelIdx := strings.Index(serverHTML[scriptIdx:], "<script>")
	if inlineScriptRelIdx == -1 {
		t.Fatalf("server.html must include inline <script> block after %q", scriptTag)
	}

	// Extract all onclick function calls to assert they resolve on window.
	onclickRegex := regexp.MustCompile(`onclick="([^"]+)"`)
	matches := onclickRegex.FindAllStringSubmatch(serverHTML, -1)
	fnNameRegex := regexp.MustCompile(`^([a-zA-Z0-9_$]+)\s*\(`)
	fnNamesSet := make(map[string]struct{})
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		expr := strings.TrimSpace(match[1])
		if sub := fnNameRegex.FindStringSubmatch(expr); len(sub) >= 2 {
			name := sub[1]
			if name != "closeModal" && !strings.HasPrefix(name, "UI.") {
				fnNamesSet[name] = struct{}{}
			}
		}
	}
	var expectedFunctions []string
	for fn := range fnNamesSet {
		expectedFunctions = append(expectedFunctions, fn)
	}

	serverHTMLJSON, err := json.Marshal(serverHTML)
	if err != nil {
		t.Fatalf("json.Marshal serverHTML failed: %v", err)
	}
	actionsJSJSON, err := json.Marshal(actionsJS)
	if err != nil {
		t.Fatalf("json.Marshal actionsJS failed: %v", err)
	}
	expectedFunctionsJSON, err := json.Marshal(expectedFunctions)
	if err != nil {
		t.Fatalf("json.Marshal expectedFunctions failed: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(jsdomBootstrapSnippet)
	sb.WriteString("\nconst serverHtmlRaw = " + string(serverHTMLJSON) + ";\n")
	sb.WriteString("const serverActionsJs = " + string(actionsJSJSON) + ";\n")
	sb.WriteString("const expectedFunctions = " + string(expectedFunctionsJSON) + ";\n")
	sb.WriteString(`
const scriptTag = '<script src="/static/js/server_actions.js"></script>';
assert(serverHtmlRaw.includes(scriptTag), 'serverHtmlRaw must contain server_actions.js script tag');

// Render template with realistic substitutions
let rendered = serverHtmlRaw;
const subs = {
    '{{ .server_id }}': '42',
    '{{ .server.ID }}': '42',
    '{{ .server.Name }}': 'srv-alpha',
    '{{ .server.Host }}': '203.0.113.5',
    '{{ .server.SSHUser }}': 'root',
    '{{ .server.SSHPort }}': '22',
    '{{ .reachability.LatencyMs }}': '33',
    '{{ $u.ID }}': '7',
    '{{ $u.Username }}': 'alice',
    '{{ $u.Role }}': 'user',
};
for (const [k, v] of Object.entries(subs)) {
    rendered = rendered.split(k).join(v);
}
rendered = rendered.replace(/\{\{\s*_\s+"([^"]+)"\s*\}\}/g, 'T:$1');
rendered = rendered.replace(/\{\{slice_str[^}]*\}\}/g, '12:00:00');
// Remove any remaining Go control tags
rendered = rendered.replace(/\{\{[^}]*\}\}/g, '');

assert(!rendered.includes('{{'), 'all template directives must be resolved');
assert(rendered.includes(scriptTag), 'scriptTag must remain intact before script replacement');

// Replace script tag with inlined server_actions.js
rendered = rendered.replace(scriptTag, '<script>\n' + serverActionsJs + '\n</script>');

const docHtml = '<!DOCTYPE html><html><head></head><body>' + rendered + '</body></html>';

const virtualConsole = new (require('jsdom').VirtualConsole)();
virtualConsole.on('jsdomError', (err) => {
    if (!err.message.includes('navigation')) {
        console.error('jsdomError:', err.message);
        process.exit(1);
    }
});

let confirmOptions = null;
let lastToast = null;
let apiCalls = [];

const dom = new JSDOM(docHtml, {
    virtualConsole,
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://nexus.invalid/servers/42',
    beforeParse(w) {
        w._ = (k) => 'T:' + k;
        w.UI = {
            toast: (msg, type) => { lastToast = { msg, type }; },
            confirm: async (opts) => { confirmOptions = opts; return true; },
            copy: async () => true,
            downloadFile: () => {},
            escapeHtml: (s) => (s == null ? '' : String(s)),
            formatBytes: (n) => String(n) + 'B',
        };
        w.API = {
            get: async (url, opts) => { apiCalls.push({ method: 'GET', url, opts }); return {}; },
            post: async (url, body, opts) => { apiCalls.push({ method: 'POST', url, body, opts }); return {}; },
        };
        w.openModal = () => {};
        w.closeModal = () => {};
        w.Telemetry = { poll: () => {} };
        w.NexusTable = class { constructor() {} refresh() {} };
        w.QRCode = function() {};
        w.QRCode.CorrectLevel = { L: 'L' };
    }
});

const w = dom.window;
const d = w.document;

(async () => {
    // 3. Assert all functions referenced by inline onclick handlers in server.html resolve on window
    assert(expectedFunctions.length > 0, 'expectedFunctions must not be empty');
    for (const fn of expectedFunctions) {
        assert.strictEqual(typeof w[fn], 'function', 'Function ' + fn + ' must be defined on window');
    }

    // 4. Drive flows:
    // Flow 4.1: removeServer verifying confirmText: 'Remove' (Finding H1)
    confirmOptions = null;
    apiCalls = [];
    await w.removeServer();
    assert(confirmOptions !== null, 'removeServer must invoke UI.confirm');
    assert.strictEqual(confirmOptions.confirmText, 'Remove', 'removeServer confirmText must be "Remove"');
    assert.strictEqual(confirmOptions.confirmVariant, 'danger', 'removeServer confirmVariant must be "danger"');
    assert(apiCalls.some(c => c.method === 'POST' && c.url === '/api/servers/42/delete'), 'removeServer must post to /api/servers/42/delete');

    // Flow 4.2: rebootServer and clearServer confirm texts
    confirmOptions = null;
    await w.rebootServer();
    assert.strictEqual(confirmOptions.confirmText, 'Reboot', 'rebootServer confirmText must be "Reboot"');

    confirmOptions = null;
    await w.clearServer();
    assert.strictEqual(confirmOptions.confirmText, 'Clear Server Data', 'clearServer confirmText must be "Clear Server Data"');

    // Flow 4.3: isValidHost matrix
    const hostMatrix = [
        { host: '192.168.1.1', expected: true },
        { host: '10.0.0.1', expected: true },
        { host: '203.0.113.195', expected: true },
        { host: 'example.com', expected: true },
        { host: 'vpn.example.org', expected: true },
        { host: 'sub-domain.nexus.net', expected: true },
        { host: '::1', expected: true },
        { host: '2001:db8::1', expected: true },
        { host: '[2001:db8::1]', expected: true },
        { host: 'fe80::1%eth0', expected: true },
        { host: '256.1.1.1', expected: false },
        { host: '1.2.3', expected: false },
        { host: '999.999.999.999', expected: false },
        { host: '-bad.com', expected: false },
        { host: 'a b', expected: false },
        { host: 'http://example.com', expected: false },
        { host: 'ftp://host', expected: false },
        { host: 'x'.repeat(254), expected: false },
        { host: '', expected: false },
        { host: null, expected: false },
        { host: undefined, expected: false },
    ];
    for (const testCase of hostMatrix) {
        assert.strictEqual(w.isValidHost(testCase.host), testCase.expected, 'isValidHost(' + JSON.stringify(testCase.host) + ') should be ' + testCase.expected);
    }

    // Flow 4.4: editHost flow
    w.openEditHostModal(42, '203.0.113.5');
    const hostInput = d.getElementById('editHostInput');
    assert(hostInput !== null, 'editHostInput must exist in DOM');
    assert.strictEqual(hostInput.value, '203.0.113.5', 'editHostInput should have initial value');

    apiCalls = [];
    hostInput.value = 'http://invalid';
    await w.submitEditHost();
    assert.strictEqual(apiCalls.length, 0, 'submitEditHost with invalid host must not post');

    hostInput.value = 'vpn.newhost.net';
    await w.submitEditHost();
    assert(apiCalls.some(c => c.url === '/api/servers/42/host' && c.body && c.body.host === 'vpn.newhost.net'), 'submitEditHost with valid host must post updated host');

    // Flow 4.5: switchCategory
    w.switchCategory('services');
    assert(!d.getElementById('services-grid').classList.contains('hidden'), 'services-grid must be visible');
    assert(d.getElementById('protocols-grid').classList.contains('hidden'), 'protocols-grid must be hidden');
    assert(d.getElementById('tab-services').classList.contains('active'), 'tab-services must be active');

    w.switchCategory('protocols');
    assert(!d.getElementById('protocols-grid').classList.contains('hidden'), 'protocols-grid must be visible');
    assert(d.getElementById('services-grid').classList.contains('hidden'), 'services-grid must be hidden');

    // Flow 4.6: getProtoTitle
    assert.strictEqual(w.getProtoTitle('awg'), 'AmneziaWG');
    assert.strictEqual(w.getProtoTitle('telemt'), 'MTProxyL');
    assert.strictEqual(w.getProtoTitle('dns'), 'AmneziaDNS');
    assert.strictEqual(w.getProtoTitle('other'), 'other');

    console.log('JSDOM_TEST_SUCCESS');
    process.exit(0);
})();
`)

	testScript := sb.String()
	out, err := execNodeScript(nodePath, testScript)
	if err != nil {
		t.Fatalf("JSDOM execution failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "JSDOM_TEST_SUCCESS") {
		t.Fatalf("JSDOM test did not report success. Output:\n%s", string(out))
	}
}
