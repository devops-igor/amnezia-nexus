package web

import (
	"bytes"
	"encoding/json"
	"html/template"
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

	telemetryBytes, err := fs.ReadFile(staticFS, "js/server_telemetry.js")
	if err != nil {
		t.Fatalf("failed to read js/server_telemetry.js: %v", err)
	}
	telemetryJS := string(telemetryBytes)

	// 1. Assert server.html contains <script src="/static/js/server_actions.js..."> and <script src="/static/js/server_telemetry.js..."> before the inline <script> block.
	const scriptTagPrefix = `<script src="/static/js/server_actions.js`
	const telemetryScriptTagPrefix = `<script src="/static/js/server_telemetry.js`
	scriptIdx := strings.Index(serverHTML, scriptTagPrefix)
	if scriptIdx == -1 {
		t.Fatalf("server.html missing required script tag: %q", scriptTagPrefix)
	}
	telemetryScriptIdx := strings.Index(serverHTML, telemetryScriptTagPrefix)
	if telemetryScriptIdx == -1 {
		t.Fatalf("server.html missing required script tag: %q", telemetryScriptTagPrefix)
	}
	if telemetryScriptIdx < scriptIdx {
		t.Fatalf("server_telemetry.js must be loaded after server_actions.js")
	}
	inlineScriptRelIdx := strings.Index(serverHTML[telemetryScriptIdx:], "<script>")
	if inlineScriptRelIdx == -1 {
		t.Fatalf("server.html must include inline <script> block after %q", telemetryScriptTagPrefix)
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
	telemetryJSJSON, err := json.Marshal(telemetryJS)
	if err != nil {
		t.Fatalf("json.Marshal telemetryJS failed: %v", err)
	}
	expectedFunctionsJSON, err := json.Marshal(expectedFunctions)
	if err != nil {
		t.Fatalf("json.Marshal expectedFunctions failed: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(jsdomBootstrapSnippet)
	sb.WriteString("\nconst serverHtmlRaw = " + string(serverHTMLJSON) + ";\n")
	sb.WriteString("const serverActionsJs = " + string(actionsJSJSON) + ";\n")
	sb.WriteString("const serverTelemetryJs = " + string(telemetryJSJSON) + ";\n")
	sb.WriteString("const expectedFunctions = " + string(expectedFunctionsJSON) + ";\n")
	sb.WriteString(`
const scriptTagPrefix = '<script src="/static/js/server_actions.js';
const telemetryScriptTagPrefix = '<script src="/static/js/server_telemetry.js';
assert(serverHtmlRaw.includes(scriptTagPrefix), 'serverHtmlRaw must contain server_actions.js script tag');
assert(serverHtmlRaw.includes(telemetryScriptTagPrefix), 'serverHtmlRaw must contain server_telemetry.js script tag');

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
assert(rendered.includes(scriptTagPrefix), 'scriptTagPrefix must remain intact before script replacement');
assert(rendered.includes(telemetryScriptTagPrefix), 'telemetryScriptTagPrefix must remain intact before script replacement');

// Replace script tags with inlined server_actions.js and server_telemetry.js
rendered = rendered.replace(/<script src="\/static\/js\/server_actions\.js[^"]*"><\/script>/, '<script>\n' + serverActionsJs + '\n</script>');
rendered = rendered.replace(/<script src="\/static\/js\/server_telemetry\.js[^"]*"><\/script>/, '<script>\n' + serverTelemetryJs + '\n</script>');

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
const failUrls = new Set();
const telemetryRegistrations = [];
const telemetryStops = [];
const activeIntervals = new Set();

const dom = new JSDOM(docHtml, {
    virtualConsole,
    runScripts: 'dangerously',
    pretendToBeVisual: true,
    url: 'https://nexus.invalid/servers/42',
    beforeParse(w) {
        const origSetInterval = w.setInterval;
        const origClearInterval = w.clearInterval;
        w.setInterval = function(...args) {
            const id = origSetInterval.apply(this, args);
            activeIntervals.add(id);
            return id;
        };
        w.clearInterval = function(id) {
            activeIntervals.delete(id);
            return origClearInterval.apply(this, arguments);
        };
        w._ = (k) => 'T:' + k;
        w.UI = {
            toast: (msg, type) => { lastToast = { msg, type }; },
            confirm: async (opts) => { confirmOptions = opts; return true; },
            copy: async () => true,
            downloadFile: () => {},
            downloadQRCode: () => {},
            escapeHtml: (s) => (s == null ? '' : String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')),
            formatBytes: (n) => String(n) + 'B',
        };
        w.API = {
            get: async (url, opts) => {
                apiCalls.push({ method: 'GET', url, opts });
                for (const pattern of failUrls) {
                    if (url.includes(pattern)) {
                        throw new Error('API get failed for ' + pattern);
                    }
                }
                if (url.includes('/reachability')) {
                    return { reachable: true, latency_ms: 35, last_checked: '2026-10-17 12:00:00' };
                }
                if (url.includes('/connections')) {
                    return { clients: [{ clientId: 'c1', name: 'Alice', enabled: true }] };
                }
                return {};
            },
            post: async (url, body, opts) => {
                apiCalls.push({ method: 'POST', url, body, opts });
                for (const pattern of failUrls) {
                    if (url.includes(pattern)) {
                        throw new Error('API post failed for ' + pattern);
                    }
                }
                if (url.includes('/stats')) {
                    return { cpu: 15, ram_used: 1024, ram_total: 4096, ram_percent: 25, disk_used: 5000, disk_total: 20000, disk_percent: 25, net_rx: 100, net_tx: 200 };
                }
                if (url.includes('/check')) {
                    return { connection: 'ok', docker_installed: true, protocols: { awg: { container_running: true, port: 55424 } } };
                }
                if (url.includes('/install')) {
                    return { log: ['Installed successfully'] };
                }
                return {};
            },
        };
        w.openModal = () => {};
        w.closeModal = () => {};
        w.Telemetry = {
            poll: (id, fn, interval) => {
                telemetryRegistrations.push({ id, fn, interval });
            },
            stop: (id) => {
                telemetryStops.push(id);
            },
        };
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

    // 3.1 Assert telemetry functions resolve on window
    const expectedTelemetryFunctions = [
        'loadServerStats',
        'updateReachability',
        'checkServer',
        'updateStatusCounts',
        'updateProtocolCard',
        'showConnectionsSection',
        'hideConnectionsSection',
        'selectProtocolForConns',
        'loadConnections',
        'initServerTelemetry',
        'startServerTelemetryPolling',
        'stopServerTelemetryPolling',
    ];
    for (const fn of expectedTelemetryFunctions) {
        assert.strictEqual(typeof w[fn], 'function', 'Telemetry function ' + fn + ' must be defined on window');
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

    // Flow 4.7: server telemetry & reachability execution
    apiCalls = [];
    const statsResult = await w.loadServerStats();
    assert(statsResult && statsResult.cpu === 15, 'loadServerStats must return stats payload');
    assert(apiCalls.some(c => c.method === 'POST' && c.url === '/api/servers/42/stats'), 'loadServerStats must post to /api/servers/42/stats');
    const prevStatsHtml = d.getElementById('serverStats').innerHTML;
    assert(prevStatsHtml.length > 0, 'serverStats must have content after successful stats call');

    // Failed poll: stats error must reject and leave DOM unchanged (Finding H1 & L2)
    failUrls.add('/stats');
    let statsErrorCaught = false;
    const prevStatsDisplay = d.getElementById('serverStats').style.display;
    try {
        await w.loadServerStats();
    } catch (err) {
        statsErrorCaught = true;
    } finally {
        failUrls.delete('/stats');
    }
    assert(statsErrorCaught, 'loadServerStats must reject when API call fails');
    assert.strictEqual(d.getElementById('serverStats').innerHTML, prevStatsHtml, 'serverStats DOM content must remain unchanged on stats error');
    assert.strictEqual(d.getElementById('serverStats').style.display, prevStatsDisplay, 'serverStats display style must remain unchanged on stats error');

    const reachResult = await w.updateReachability();
    assert(reachResult && reachResult.reachable === true, 'updateReachability must return reachability payload');
    assert(apiCalls.some(c => c.method === 'GET' && c.url === '/api/servers/42/reachability'), 'updateReachability must get /api/servers/42/reachability');

    // Failed poll: reachability error must rethrow (Finding H1)
    failUrls.add('/reachability');
    let reachErrorCaught = false;
    try {
        await w.updateReachability();
    } catch (err) {
        reachErrorCaught = true;
    } finally {
        failUrls.delete('/reachability');
    }
    assert(reachErrorCaught, 'updateReachability must rethrow when API call fails');

    // Flow 4.8: connections section toggle & protocol select
    w.showConnectionsSection();
    assert.strictEqual(d.getElementById('connectionsSection').style.display, 'block', 'showConnectionsSection must set display: block');
    w.hideConnectionsSection();
    assert.strictEqual(d.getElementById('connectionsSection').style.display, 'none', 'hideConnectionsSection must set display: none');

    // selectProtocolForConns with missing option does NOT inject option, reveal stale UI, or trigger API call (Finding M1, L1)
    apiCalls = [];
    d.getElementById('connectionsTableBody').innerHTML = '<tr><td>stale-row</td></tr>';
    d.getElementById('connectionsSection').style.display = '';
    d.getElementById('connProtoSelect').value = 'awg';
    w.selectProtocolForConns('nonexistent');
    assert.strictEqual(d.getElementById('connectionsSection').style.display, 'none', 'connectionsSection must be hidden when selecting unavailable protocol');
    assert.strictEqual(d.getElementById('connProtoSelect').value, '', 'connProtoSelect value must be reset to empty');
    assert.strictEqual(apiCalls.filter(c => c.url.includes('/connections')).length, 0, 'selectProtocolForConns with missing option must not trigger API call');
    assert.strictEqual(Array.from(d.getElementById('connProtoSelect').options).some(o => o.value === 'nonexistent'), false, 'selectProtocolForConns must not inject option for missing protocol');

    // Flow 4.9: checkServer execution
    await w.checkServer();
    assert(apiCalls.some(c => c.method === 'POST' && c.url === '/api/servers/42/check'), 'checkServer must post to /api/servers/42/check');
    const badgesSuccessHtml = d.getElementById('statusBadges').innerHTML;
    assert(badgesSuccessHtml.includes('ssh_ok'), 'statusBadges must show ssh_ok badge on success');
    assert(!badgesSuccessHtml.includes('check_error'), 'statusBadges must not show check_error on success');

    // selectProtocolForConns with protocol populated by checkServer triggers loadConnections
    apiCalls = [];
    w.selectProtocolForConns('awg');
    assert(apiCalls.some(c => c.method === 'GET' && c.url.includes('/api/servers/42/connections')), 'selectProtocolForConns must trigger loadConnections');

    // Failed checkServer: check error must render check_error badge and re-enable button (Finding H1)
    failUrls.add('/check');
    await w.checkServer();
    failUrls.delete('/check');
    const badgesErrorHtml = d.getElementById('statusBadges').innerHTML;
    assert(badgesErrorHtml.includes('check_error'), 'statusBadges must show check_error badge on failure');
    assert.strictEqual(d.getElementById('checkBtn').disabled, false, 'checkBtn must be re-enabled after failed check');

    // Flow 4.9b: CheckServer with succeeding /check but failing /reachability must not emit unhandled rejection (#502 Finding 2)
    failUrls.add('/reachability');
    let unhandledRejectionCaught = null;
    const unhandledHandler = (reason) => {
        unhandledRejectionCaught = reason;
    };
    process.on('unhandledRejection', unhandledHandler);
    try {
        const checkResultWithReachError = await w.checkServer();
        await new Promise(r => setTimeout(r, 20));
        assert.strictEqual(unhandledRejectionCaught, null, 'checkServer must safely catch reachability failure without unhandled rejection');
        assert(checkResultWithReachError && checkResultWithReachError.connection === 'ok', 'checkServer must return check result when reachability rejects');
        const badgesWithReachError = d.getElementById('statusBadges').innerHTML;
        assert(badgesWithReachError.includes('ssh_ok'), 'statusBadges must show check results even if reachability rejects');
    } finally {
        process.removeListener('unhandledRejection', unhandledHandler);
        failUrls.delete('/reachability');
    }

    // Flow 4.9c: Out-of-order connection response race protection & date escaping (#502 Findings 1 & 3, H1)
    {
        const protoSelect = d.getElementById('connProtoSelect');
        if (!Array.from(protoSelect.options).some(o => o.value === 'telemt')) {
            const opt = d.createElement('option');
            opt.value = 'telemt';
            opt.textContent = 'MTProxyL';
            protoSelect.appendChild(opt);
        }
        if (!Array.from(protoSelect.options).some(o => o.value === 'awg')) {
            const opt = d.createElement('option');
            opt.value = 'awg';
            opt.textContent = 'AmneziaWG';
            protoSelect.appendChild(opt);
        }

        const origGet = w.API.get;

        // Sub-case 1: Cross-protocol race (awg -> telemt) & creationDate HTML escaping
        {
            let resolveAwg = null;
            let resolveTelemt = null;
            const awgPromise = new Promise(resolve => { resolveAwg = resolve; });
            const telemtPromise = new Promise(resolve => { resolveTelemt = resolve; });

            w.API.get = function(url, ...args) {
                if (url.includes('/connections') && url.includes('protocol=awg')) {
                    return awgPromise;
                }
                if (url.includes('/connections') && url.includes('protocol=telemt')) {
                    return telemtPromise;
                }
                return origGet.apply(this, [url, ...args]);
            };

            try {
                // Request A: awg
                protoSelect.value = 'awg';
                const reqA = w.loadConnections();

                // Request B: telemt (rapid switch)
                protoSelect.value = 'telemt';
                const reqB = w.loadConnections();

                // Request B resolves first
                resolveTelemt({
                    clients: [
                        {
                            clientId: 'telemt-client-1',
                            name: 'Telemt Client',
                            enabled: true,
                            userData: {
                                total_octets: 1024,
                                creationDate: '<malicious-date-tag>',
                            }
                        }
                    ]
                });
                await reqB;

                assert(w.connectionsStore['telemt-client-1'], 'connectionsStore must have telemt client from Request B');
                assert(!w.connectionsStore['awg-client-1'], 'connectionsStore must not have awg client yet');
                let tableHtml = d.getElementById('connectionsTableBody').innerHTML;
                assert(tableHtml.includes('Telemt Client'), 'table must display telemt client from Request B');
                // Verify creationDate HTML escaping (Finding 3)
                assert(tableHtml.includes('&lt;malicious-date-tag&gt;'), 'table must escape creationDate in metaHtml');
                assert(!tableHtml.includes('<malicious-date-tag>'), 'table must not contain unescaped creationDate HTML sink');

                // Request A resolves later (out of order / stale)
                resolveAwg({
                    clients: [
                        {
                            clientId: 'awg-client-1',
                            name: 'AWG Client',
                            enabled: true,
                            userData: {}
                        }
                    ]
                });
                await reqA;

                // Assert table and connectionsStore strictly retain telemt and reject stale awg
                assert(w.connectionsStore['telemt-client-1'], 'connectionsStore must strictly retain telemt client');
                assert(!w.connectionsStore['awg-client-1'], 'connectionsStore must reject stale awg client');
                tableHtml = d.getElementById('connectionsTableBody').innerHTML;
                assert(tableHtml.includes('Telemt Client'), 'table must strictly display telemt client');
                assert(!tableHtml.includes('AWG Client'), 'table must reject stale awg client data');
            } finally {
                w.API.get = origGet;
            }
        }

        // Sub-case 2: Same-protocol out-of-order race (kills mutants R7 & R2)
        {
            protoSelect.value = 'awg';
            let resolveA = null;
            let resolveB = null;
            const promiseA = new Promise(resolve => { resolveA = resolve; });
            const promiseB = new Promise(resolve => { resolveB = resolve; });
            let awgReqCount = 0;

            w.API.get = function(url, ...args) {
                if (url.includes('/connections') && url.includes('protocol=awg')) {
                    awgReqCount++;
                    if (awgReqCount === 1) return promiseA;
                    if (awgReqCount === 2) return promiseB;
                }
                return origGet.apply(this, [url, ...args]);
            };

            try {
                // Request A (awg, older generation)
                const reqA = w.loadConnections();
                // Request B (awg, newer generation)
                const reqB = w.loadConnections();

                // Resolve B first with fresh data
                resolveB({
                    clients: [
                        {
                            clientId: 'awg-fresh',
                            name: 'AWG Fresh',
                            enabled: true,
                            userData: {}
                        }
                    ]
                });
                await reqB;

                assert(w.connectionsStore['awg-fresh'], 'connectionsStore must contain awg-fresh');
                assert.strictEqual(Object.keys(w.connectionsStore).length, 1, 'connectionsStore must have strictly 1 entry');
                let rows = d.getElementById('connectionsTableBody').querySelectorAll('tr');
                assert.strictEqual(rows.length, 1, 'connectionsTableBody must have strictly 1 row after reqB');
                assert(d.getElementById('connectionsTableBody').innerHTML.includes('AWG Fresh'), 'table must display awg-fresh');

                // Resolve A second with stale data
                resolveA({
                    clients: [
                        {
                            clientId: 'awg-stale',
                            name: 'AWG Stale',
                            enabled: true,
                            userData: {}
                        }
                    ]
                });
                await reqA;

                // Assert table strictly contains 1 row (awg-fresh) and connectionsStore contains only awg-fresh
                assert(w.connectionsStore['awg-fresh'], 'connectionsStore must strictly retain awg-fresh');
                assert(!w.connectionsStore['awg-stale'], 'connectionsStore must reject stale awg-stale');
                assert.strictEqual(Object.keys(w.connectionsStore).length, 1, 'connectionsStore must strictly have 1 entry (awg-fresh only)');
                rows = d.getElementById('connectionsTableBody').querySelectorAll('tr');
                assert.strictEqual(rows.length, 1, 'connectionsTableBody must strictly contain 1 row (awg-fresh)');
                const bodyHtml = d.getElementById('connectionsTableBody').innerHTML;
                assert(bodyHtml.includes('AWG Fresh'), 'table must retain awg-fresh');
                assert(!bodyHtml.includes('AWG Stale'), 'table must reject stale awg-stale');
            } finally {
                w.API.get = origGet;
            }
        }

        // Sub-case 3: Superseded rejection does not emit error toast (kills mutant R6)
        {
            lastToast = null;
            let rejectA = null;
            let resolveB = null;
            const promiseA = new Promise((_, reject) => { rejectA = reject; });
            const promiseB = new Promise(resolve => { resolveB = resolve; });

            w.API.get = function(url, ...args) {
                if (url.includes('/connections') && url.includes('protocol=awg')) {
                    return promiseA;
                }
                if (url.includes('/connections') && url.includes('protocol=telemt')) {
                    return promiseB;
                }
                return origGet.apply(this, [url, ...args]);
            };

            try {
                // Start request A ('awg')
                protoSelect.value = 'awg';
                const reqA = w.loadConnections();

                // Start request B ('telemt')
                protoSelect.value = 'telemt';
                const reqB = w.loadConnections();

                // Resolve B
                resolveB({
                    clients: [
                        {
                            clientId: 'telemt-fresh',
                            name: 'Telemt Fresh',
                            enabled: true,
                            userData: {}
                        }
                    ]
                });
                await reqB;

                // Reject request A
                rejectA(new Error('superseded network error'));
                await reqA;

                // Assert that lastToast is NOT loading_connections_error
                assert(!lastToast || !lastToast.msg || !lastToast.msg.includes('loading_connections_error'),
                    'superseded rejection must not display loading_connections_error toast');
                assert.strictEqual(lastToast, null, 'superseded rejection must not trigger any toast');
            } finally {
                w.API.get = origGet;
            }
        }

        // Sub-case 4: Invalidate in-flight requests when selecting unavailable protocol (Finding H1 / #502 Cycle 6)
        {
            w.connectionsStore = {};
            d.getElementById('connectionsTableBody').innerHTML = '';
            d.getElementById('connectionsTableContainer').style.display = 'none';

            let resolveA = null;
            const promiseA = new Promise(resolve => { resolveA = resolve; });

            w.API.get = function(url, ...args) {
                if (url.includes('/connections') && url.includes('protocol=awg')) {
                    return promiseA;
                }
                return origGet.apply(this, [url, ...args]);
            };

            try {
                // 1. Start an in-flight connection request for 'awg'
                protoSelect.value = 'awg';
                const reqA = w.loadConnections();

                // 2. Call selectProtocolForConns('nonexistent')
                w.selectProtocolForConns('nonexistent');

                // 3. Resolve the pending 'awg' connection request with [{id: 'stale-awg'}]
                const stalePayload = [
                    {
                        clientId: 'stale-awg',
                        id: 'stale-awg',
                        name: 'Stale AWG',
                        enabled: true,
                        userData: {}
                    }
                ];
                stalePayload.clients = stalePayload;
                resolveA(stalePayload);
                await reqA;

                // 4. Assert that #connectionsTableBody rows remain empty ([]),
                //    window.connectionsStore remains empty ({}),
                //    and #connectionsSection.style.display === 'none'.
                const rows = d.getElementById('connectionsTableBody').querySelectorAll('tr');
                assert.strictEqual(rows.length, 0, 'connectionsTableBody rows must remain empty');
                assert.deepStrictEqual(w.connectionsStore, {}, 'window.connectionsStore must remain empty');
                assert.strictEqual(d.getElementById('connectionsSection').style.display, 'none', 'connectionsSection.style.display must remain none');
                assert.strictEqual(d.getElementById('connectionsTableContainer').style.display, 'none', 'connectionsTableContainer must remain hidden');
            } finally {
                w.API.get = origGet;
            }
        }
    }

    // Flow 4.10: installProtocol rejection verifies progressInterval is cleared (Finding H1 / #478, Finding 4)
    w.openInstallModal('awg');
    failUrls.add('/install');
    let installAttempted = false;
    let liveIntervalsDuringInstall = 0;
    const origPostForInstall = w.API.post;
    w.API.post = async function(url, ...args) {
        if (url.includes('/install')) {
            installAttempted = true;
            liveIntervalsDuringInstall = activeIntervals.size;
        }
        return origPostForInstall.apply(this, [url, ...args]);
    };
    try {
        await w.installProtocol();
    } finally {
        w.API.post = origPostForInstall;
        failUrls.delete('/install');
    }
    assert(installAttempted, 'installProtocol must attempt /install API call');
    assert(liveIntervalsDuringInstall > 0, 'installProtocol must start a progress timer before awaiting install API call');
    assert.strictEqual(activeIntervals.size, 0, 'installProtocol rejection must leave 0 live intervals');

    // Flow 4.11: polling lifecycle functions & exact Telemetry.poll registrations (Finding H1 & M2)
    telemetryRegistrations.length = 0;
    telemetryStops.length = 0;
    w.startServerTelemetryPolling();

    const statsPoll = telemetryRegistrations.find(r => r.id === 'server-stats-42');
    assert(statsPoll, 'Telemetry.poll must be registered for server-stats-42');
    assert.strictEqual(statsPoll.fn, w.loadServerStats, 'server-stats poll handler must be loadServerStats');
    assert.strictEqual(statsPoll.interval, 30000, 'server-stats poll interval must be 30000');

    const reachPoll = telemetryRegistrations.find(r => r.id === 'server-reachability-42');
    assert(reachPoll, 'Telemetry.poll must be registered for server-reachability-42');
    assert.strictEqual(reachPoll.fn, w.updateReachability, 'server-reachability poll handler must be updateReachability');
    assert.strictEqual(reachPoll.interval, 30000, 'server-reachability poll interval must be 30000');

    w.stopServerTelemetryPolling();
    assert(telemetryStops.includes('server-stats-42'), 'stopServerTelemetryPolling must stop server-stats-42');
    assert(telemetryStops.includes('server-reachability-42'), 'stopServerTelemetryPolling must stop server-reachability-42');

    // Idempotent initServerTelemetry guard & boot check assertion (Finding M2, L2)
    telemetryRegistrations.length = 0;
    apiCalls = [];
    w.initServerTelemetry();
    assert.strictEqual(telemetryRegistrations.length, 2, 'initServerTelemetry must register stats and reachability once');
    const checkCallsAfterFirstInit = apiCalls.filter(c => c.method === 'POST' && c.url.includes('/api/servers/42/check')).length;
    assert.strictEqual(checkCallsAfterFirstInit, 1, 'initServerTelemetry must trigger checkServer exactly once on initial call');

    w.initServerTelemetry();
    assert.strictEqual(telemetryRegistrations.length, 2, 'second initServerTelemetry call must be a no-op');
    const checkCallsAfterSecondInit = apiCalls.filter(c => c.method === 'POST' && c.url.includes('/api/servers/42/check')).length;
    assert.strictEqual(checkCallsAfterSecondInit, 1, 'second initServerTelemetry must not trigger checkServer again');
    w.stopServerTelemetryPolling();

    // Flow 4.12: Server actions glue cleanup & modal functions
    // 4.12.1: Rename server flow
    w.openRenameServerModal(42, 'srv-alpha');
    const renameInput = d.getElementById('renameServerInput');
    assert(renameInput !== null, 'renameServerInput must exist in DOM');
    assert.strictEqual(renameInput.value, 'srv-alpha', 'renameServerInput must initialize with server name');

    apiCalls = [];
    renameInput.value = '';
    await w.submitRenameServer();
    assert.strictEqual(apiCalls.filter(c => c.url && c.url.includes('/rename')).length, 0, 'empty server name must not call API');

    renameInput.value = 'srv-renamed-beta';
    await w.submitRenameServer();
    assert(apiCalls.some(c => c.method === 'POST' && c.url === '/api/servers/42/rename' && c.body && c.body.name === 'srv-renamed-beta'), 'submitRenameServer must post new name');
    assert.strictEqual(d.getElementById('serverNameTitle').textContent, 'srv-renamed-beta', 'serverNameTitle must update with new name');

    // 4.12.1a: Enter keydown event handling on renameServerInput
    w.openRenameServerModal(42, 'srv-renamed-beta');
    apiCalls = [];
    const renameNonEnter = new w.KeyboardEvent('keydown', { key: 'a', cancelable: true, bubbles: true });
    renameInput.dispatchEvent(renameNonEnter);
    assert.strictEqual(renameNonEnter.defaultPrevented, false, 'non-Enter keydown on renameServerInput must not prevent default');
    assert.strictEqual(apiCalls.filter(c => c.url && c.url.includes('/rename')).length, 0, 'non-Enter keydown must not submit rename');

    renameInput.value = 'srv-enter-renamed';
    const renameEnter = new w.KeyboardEvent('keydown', { key: 'Enter', cancelable: true, bubbles: true });
    renameInput.dispatchEvent(renameEnter);
    assert.strictEqual(renameEnter.defaultPrevented, true, 'Enter keydown on renameServerInput must prevent default');
    await new Promise(r => setTimeout(r, 20));
    assert(apiCalls.some(c => c.method === 'POST' && c.url === '/api/servers/42/rename' && c.body && c.body.name === 'srv-enter-renamed'), 'Enter keydown on renameServerInput must submit rename');

    // 4.12.1b: Edit host flow & Enter keydown handling
    w.openEditHostModal(42, '203.0.113.55');
    const editHostInput = d.getElementById('editHostInput');
    assert(editHostInput !== null, 'editHostInput must exist in DOM');
    assert.strictEqual(editHostInput.value, 'vpn.newhost.net', 'editHostInput must initialize with current server host');

    apiCalls = [];
    const editHostNonEnter = new w.KeyboardEvent('keydown', { key: 'Escape', cancelable: true, bubbles: true });
    editHostInput.dispatchEvent(editHostNonEnter);
    assert.strictEqual(editHostNonEnter.defaultPrevented, false, 'non-Enter keydown on editHostInput must not prevent default');
    assert.strictEqual(apiCalls.filter(c => c.url && c.url.includes('/host')).length, 0, 'non-Enter keydown must not submit host update');

    editHostInput.value = '198.51.100.42';
    const editHostEnter = new w.KeyboardEvent('keydown', { key: 'Enter', cancelable: true, bubbles: true });
    editHostInput.dispatchEvent(editHostEnter);
    assert.strictEqual(editHostEnter.defaultPrevented, true, 'Enter keydown on editHostInput must prevent default');
    await new Promise(r => setTimeout(r, 20));
    assert(apiCalls.some(c => c.method === 'POST' && c.url === '/api/servers/42/host' && c.body && c.body.host === '198.51.100.42'), 'Enter keydown on editHostInput must submit new host');
    assert.strictEqual(d.getElementById('serverHostDisplay').textContent, '198.51.100.42', 'serverHostDisplay must update with new host');

    // 4.12.2: Server config copy and download helpers
    let copiedText = null;
    let copiedBtn = null;
    let downloadedFile = null;
    w.UI.copy = async (text, btn) => { copiedText = text; copiedBtn = btn; return true; };
    w.UI.downloadFile = (text, filename) => { downloadedFile = { text, filename }; };

    const mockCopyBtn = d.createElement('button');
    d.getElementById('serverConfigText').value = '[Interface]\nPrivateKey = mockKey';
    w.copyServerConfig(mockCopyBtn);
    assert.strictEqual(copiedText, '[Interface]\nPrivateKey = mockKey', 'copyServerConfig must copy text');
    assert.strictEqual(copiedBtn, mockCopyBtn, 'copyServerConfig must pass button element to UI.copy');
    w.downloadServerConfig();
    assert.deepStrictEqual(downloadedFile, { text: '[Interface]\nPrivateKey = mockKey', filename: 'server.conf' }, 'downloadServerConfig must download text with default filename');

    await w.showServerConfig('awg');
    w.downloadServerConfig();
    assert.strictEqual(downloadedFile.filename, 'server_awg.conf', 'downloadServerConfig must use protocol filename');

    // 4.12.3: finishProtocolInstall helper
    let modalClosed = null;
    let reloadCalled = 0;
    w.closeModal = (id) => { modalClosed = id; };
    w.reloadPage = () => { reloadCalled++; };
    w.finishProtocolInstall();
    assert.strictEqual(modalClosed, 'installModal', 'finishProtocolInstall must close installModal');
    assert.strictEqual(reloadCalled, 1, 'finishProtocolInstall must trigger reload helper');

    // 4.12.4: installTelemtTls change listener toggle
    const telemtTlsCheckbox = d.getElementById('installTelemtTls');
    const telemtDomainGroup = d.getElementById('telemtDomainGroup');
    assert(telemtTlsCheckbox !== null, 'installTelemtTls checkbox must exist in DOM');
    assert(telemtDomainGroup !== null, 'telemtDomainGroup container must exist in DOM');

    telemtTlsCheckbox.checked = false;
    telemtTlsCheckbox.dispatchEvent(new w.Event('change'));
    assert.strictEqual(telemtDomainGroup.style.display, 'none', 'unchecking installTelemtTls must hide telemtDomainGroup');

    telemtTlsCheckbox.checked = true;
    telemtTlsCheckbox.dispatchEvent(new w.Event('change'));
    assert.strictEqual(telemtDomainGroup.style.display, 'block', 'checking installTelemtTls must show telemtDomainGroup');

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

func TestServerTemplateGoRenderingFailClosed(t *testing.T) {
	templatesFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}

	funcMap := template.FuncMap{
		"_": func(k string) string { return k },
		"t": func(k string) string { return k },
		"safe_js": func(v any) template.JS {
			switch val := v.(type) {
			case string:
				return template.JS(val)
			case template.JS:
				return val
			default:
				b, _ := json.Marshal(v)
				return template.JS(b)
			}
		},
		"slice_str": func(s string, start, end int) string {
			if start >= len(s) {
				return ""
			}
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
		"has_role": func(u any, roles ...string) bool { return true },
		"upper":    strings.ToUpper,
		"slice": func(s string, start, end int) string {
			if start >= len(s) {
				return ""
			}
			if end > len(s) {
				end = len(s)
			}
			return s[start:end]
		},
	}

	tmpl, err := template.New("base.html").Funcs(funcMap).ParseFS(templatesFS, "base.html", "server.html")
	if err != nil {
		t.Fatalf("failed to parse base.html and server.html: %v", err)
	}

	data := map[string]any{
		"lang":              "en",
		"active_page":       "servers",
		"csrf_token":        "mock-csrf-token-12345",
		"translations_json": "{}",
		"server_id":         42,
		"server": map[string]any{
			"ID":      42,
			"Name":    "alpha-server-test",
			"Host":    "203.0.113.55",
			"SSHPort": 22,
			"SSHUser": "root",
		},
		"users": []map[string]any{
			{"ID": 1, "Username": "alice", "Role": "user"},
		},
		"site_settings": map[string]any{"Title": "Amnezia Nexus"},
		"current_user":  map[string]any{"Username": "admin", "Role": "admin"},
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "base.html", data); err != nil {
		t.Fatalf("failed to execute server.html template: %v", err)
	}

	rendered := buf.String()

	// 1. Assert script loading sequence and bootstrap
	const expectedActionsScript = `<script src="/static/js/server_actions.js`
	const expectedTelemetryScript = `<script src="/static/js/server_telemetry.js`
	actionsIdx := strings.Index(rendered, expectedActionsScript)
	if actionsIdx == -1 {
		t.Errorf("rendered server.html missing script tag %q", expectedActionsScript)
	}
	telemetryIdx := strings.Index(rendered, expectedTelemetryScript)
	if telemetryIdx == -1 {
		t.Errorf("rendered server.html missing script tag %q", expectedTelemetryScript)
	}
	if telemetryIdx < actionsIdx {
		t.Errorf("server_telemetry.js must be loaded after server_actions.js")
	}

	serverIDPattern := `const SERVER_ID\s*=\s*42\s*;`
	matched, err := regexp.MatchString(serverIDPattern, rendered)
	if err != nil || !matched {
		t.Errorf("rendered server.html missing expected bootstrap pattern %q", serverIDPattern)
	}
	if !strings.Contains(rendered, "initServerTelemetry();") {
		t.Errorf("rendered server.html missing initServerTelemetry() in bootstrap")
	}

	// 2. Assert server name, host, CSRF injection, and default status
	if !strings.Contains(rendered, "alpha-server-test") {
		t.Errorf("rendered server.html missing server.Name 'alpha-server-test'")
	}
	if !strings.Contains(rendered, "203.0.113.55") {
		t.Errorf("rendered server.html missing server.Host '203.0.113.55'")
	}
	if !strings.Contains(rendered, `content="mock-csrf-token-12345"`) {
		t.Errorf("rendered server.html missing CSRF token in meta tag")
	}
	if !strings.Contains(rendered, "pending") {
		t.Errorf("rendered server.html missing default pending status badge")
	}
}
