package web

import (
	"strings"
	"testing"
)

func TestVPNRenderBackendRowFleet(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');

    w.UI = {
        escapeHtml: (s) => String(s == null ? '' : s)
    };

    w.vpnCachedServers = [
        { id: 101, name: 'Alpha Gateway' },
        { id: 102, name: 'Beta Relay' },
        { id: 103, name: 'Gamma Standby' }
    ];

    // 1. Active backend with good latency
    const activeBackend = {
        server_id: 101,
        endpoint: '203.0.113.10:51820',
        enabled: true,
        status: 'active',
        latency_ms: 28,
        active_connections: 42
    };
    const rowActive = w.vpnRenderBackendRow(activeBackend);
    assert.strictEqual(rowActive.getAttribute('data-status'), 'active', 'row data-status must be active');
    assert(rowActive.innerHTML.includes('Alpha Gateway'), 'server name must appear in row');
    assert(rowActive.innerHTML.includes('#101'), 'server ID must appear in row');
    assert(rowActive.innerHTML.includes('203.0.113.10:51820'), 'endpoint must appear in row');

    const activeBadge = rowActive.querySelector('td:nth-child(3) .badge');
    assert(activeBadge, 'status badge must exist');
    assert(activeBadge.className.includes('badge-success'), 'active badge class must be badge-success');
    assert(activeBadge.textContent.includes('Active'), 'active badge text must be Active');

    const latencyPill = rowActive.querySelector('.latency-pill');
    assert(latencyPill, 'latency pill must exist');
    assert(latencyPill.className.includes('latency-good'), 'latency <= 50ms must use latency-good class');
    assert(latencyPill.textContent.includes('28 ms'), 'latency text must include 28 ms');

    const connsCell = rowActive.querySelector('td:nth-child(5)');
    assert(connsCell.textContent.includes('42'), 'active connections must appear in cell');

    const toggleBtn = rowActive.querySelector('button[aria-label="Disable"]');
    assert(toggleBtn, 'active backend must offer Disable action toggle');
    assert(toggleBtn.innerHTML.includes('href="#icon-pause"'), 'active toggle must use icon-pause');

    const delBtn = rowActive.querySelector('button[aria-label="Delete"]');
    assert(delBtn, 'delete button must exist');
    assert(delBtn.innerHTML.includes('href="#icon-trash"'), 'delete button must use icon-trash');

    // 2. Degraded backend with poor latency (> 150ms)
    const degradedBackend = {
        server_id: 102,
        endpoint: '203.0.113.20:51820',
        enabled: true,
        status: 'degraded',
        latency_ms: 185,
        active_connections: 5
    };
    const rowDegraded = w.vpnRenderBackendRow(degradedBackend);
    assert.strictEqual(rowDegraded.getAttribute('data-status'), 'degraded', 'row data-status must be degraded');

    const degradedBadge = rowDegraded.querySelector('td:nth-child(3) .badge');
    assert(degradedBadge.className.includes('badge-warn'), 'degraded badge must use badge-warn class');

    const degradedLatency = rowDegraded.querySelector('.latency-pill');
    assert(degradedLatency.className.includes('latency-poor'), 'latency > 150ms must use latency-poor class');
    assert(degradedLatency.textContent.includes('185 ms'), 'latency must render 185 ms');

    // 3. Disabled backend with fair latency (50-150ms)
    const disabledBackend = {
        server_id: 103,
        endpoint: '203.0.113.30:51820',
        enabled: false,
        status: 'active',
        latency_ms: 75,
        active_connections: 0
    };
    const rowDisabled = w.vpnRenderBackendRow(disabledBackend);
    assert.strictEqual(rowDisabled.getAttribute('data-status'), 'disabled', 'disabled backend row must have data-status="disabled"');

    const disabledBadge = rowDisabled.querySelector('td:nth-child(3) .badge');
    assert(disabledBadge.className.includes('badge-danger'), 'disabled backend status badge must be badge-danger');
    assert.strictEqual(disabledBadge.title, 'Active', 'disabled backend title attribute must preserve underlying status');

    const disabledToggleBtn = rowDisabled.querySelector('button[aria-label="Enable"]');
    assert(disabledToggleBtn, 'disabled backend must offer Enable action toggle');
    assert(disabledToggleBtn.className.includes('btn-success-hover'), 'disabled toggle must have btn-success-hover');
    assert(disabledToggleBtn.innerHTML.includes('href="#icon-play"'), 'disabled toggle must use icon-play');

    const disabledLatency = rowDisabled.querySelector('.latency-pill');
    assert(disabledLatency.className.includes('latency-fair'), 'latency between 50 and 150 ms must use latency-fair');
    assert(disabledLatency.textContent.includes('75 ms'), 'latency must render 75 ms');

    // 4. Fallback server ID and missing latency
    const fallbackBackend = {
        server_id: 999,
        endpoint: '',
        enabled: true,
        status: 'unknown',
        latency_ms: null,
        active_connections: 0
    };
    const rowFallback = w.vpnRenderBackendRow(fallbackBackend);
    assert(rowFallback.innerHTML.includes('Server #999'), 'unmatched server ID must render Server #999 fallback');
    assert(rowFallback.querySelector('td:nth-child(2)').textContent.includes('-'), 'empty endpoint renders dash');
    assert(rowFallback.querySelector('td:nth-child(4)').textContent.includes('-'), 'null latency renders dash');

    console.log('PASS_RENDER_BACKEND_ROW');
})();
`,
	})

	out, err := execNodeScript(nodePath, testScript)
	if err != nil {
		t.Fatalf("TestVPNRenderBackendRowFleet failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "PASS_RENDER_BACKEND_ROW") {
		t.Fatalf("expected output to contain PASS_RENDER_BACKEND_ROW, got:\n%s", string(out))
	}
}

func TestVPNBackendToggleAndDeleteInteractions(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let apiCalls = [];
    let uiToasts = [];
    let uiConfirms = [];
    let loadDataCount = 0;
    let confirmResult = true;

    w.API = {
        post: async (endpoint) => {
            apiCalls.push({ method: 'POST', endpoint: endpoint });
            return { ok: true };
        }
    };

    w.UI = {
        toast: (msg, variant) => {
            uiToasts.push({ msg, variant });
        },
        confirm: async (opts) => {
            uiConfirms.push(opts);
            return confirmResult;
        }
    };

    w.vpnLoadData = async () => {
        loadDataCount++;
    };

    // 1. Toggle backend 'disable' when user cancels confirmation
    confirmResult = false;
    await w.vpnToggleBackend(101, 'disable');
    assert.strictEqual(uiConfirms.length, 1, 'UI.confirm must be called on disable');
    assert.strictEqual(uiConfirms[0].confirmVariant, 'warning', 'confirmVariant must be warning on disable');
    assert.strictEqual(apiCalls.length, 0, 'API.post must not be called when user cancels disable');
    assert.strictEqual(loadDataCount, 0, 'vpnLoadData must not be called when cancelled');

    // 2. Toggle backend 'disable' when user confirms
    confirmResult = true;
    await w.vpnToggleBackend(101, 'disable');
    assert.strictEqual(uiConfirms.length, 2, 'second UI.confirm recorded');
    assert.strictEqual(apiCalls.length, 1, 'API.post must be called on confirmed disable');
    assert.strictEqual(apiCalls[0].endpoint, '/api/vpn/backends/101/disable');
    assert.strictEqual(loadDataCount, 1, 'vpnLoadData must be called after successful disable');
    assert(uiToasts.some(t => t.variant === 'success'), 'success toast emitted on disable');

    // 3. Toggle backend 'enable' does NOT require UI.confirm
    apiCalls = [];
    loadDataCount = 0;
    uiToasts = [];
    await w.vpnToggleBackend(102, 'enable');
    assert.strictEqual(uiConfirms.length, 2, 'enable action must not trigger confirmation');
    assert.strictEqual(apiCalls.length, 1, 'API.post must be called directly on enable');
    assert.strictEqual(apiCalls[0].endpoint, '/api/vpn/backends/102/enable');
    assert.strictEqual(loadDataCount, 1, 'vpnLoadData must be called after successful enable');

    // 4. Delete backend when user cancels confirmation
    apiCalls = [];
    loadDataCount = 0;
    confirmResult = false;
    await w.vpnDeleteBackend(103);
    assert.strictEqual(uiConfirms.length, 3, 'UI.confirm must be called on delete');
    assert.strictEqual(uiConfirms[2].confirmVariant, 'danger', 'delete confirmVariant must be danger');
    assert.strictEqual(apiCalls.length, 0, 'API.post must not be called when delete is cancelled');

    // 5. Delete backend when user confirms
    confirmResult = true;
    await w.vpnDeleteBackend(103);
    assert.strictEqual(uiConfirms.length, 4, 'delete confirm recorded');
    assert.strictEqual(apiCalls.length, 1, 'API.post must be called on confirmed delete');
    assert.strictEqual(apiCalls[0].endpoint, '/api/vpn/backends/103/delete', 'delete must POST to /api/vpn/backends/{id}/delete');
    assert.strictEqual(loadDataCount, 1, 'vpnLoadData must be called after successful delete');
    assert(uiToasts.some(t => t.variant === 'success'), 'success toast emitted on delete');

    console.log('PASS_TOGGLE_AND_DELETE');
})().catch(e => {
    console.error(e);
    process.exit(1);
});
`,
	})

	out, err := execNodeScript(nodePath, testScript)
	if err != nil {
		t.Fatalf("TestVPNBackendToggleAndDeleteInteractions failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "PASS_TOGGLE_AND_DELETE") {
		t.Fatalf("expected output to contain PASS_TOGGLE_AND_DELETE, got:\n%s", string(out))
	}
}

func TestVPNBackendModalInteractionsAndQuickCheck(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');

    let apiRequests = [];
    let loadDataCount = 0;
    let openedModals = [];
    let closedModals = [];

    w.openModal = (id) => { openedModals.push(id); };
    w.closeModal = (id) => { closedModals.push(id); };
    w.UI = {
        toast: (msg, variant) => {},
        confirm: async () => true,
        escapeHtml: (s) => String(s == null ? '' : s)
    };
    w.vpnLoadData = async () => { loadDataCount++; };

    w.API = {
        get: async (endpoint) => {
            apiRequests.push({ method: 'GET', endpoint });
            if (endpoint === '/api/servers') {
                return [
                    { id: 1, name: 'Server One', host: '198.51.100.1', protocols: { awg: { installed: true, port: 51820 } } },
                    { id: 2, name: 'Server Two', host: '198.51.100.2', protocols: {} }
                ];
            }
            return [];
        },
        post: async (endpoint, body) => {
            apiRequests.push({ method: 'POST', endpoint, body });
            if (endpoint.includes('/check')) {
                return {
                    protocols: {
                        awg: { container_running: true, installed: true, port: 51820 }
                    }
                };
            }
            return { ok: true };
        },
        request: async (endpoint, opts) => {
            apiRequests.push({ method: opts.method, endpoint, body: opts.body });
            return { ok: true };
        }
    };

    // 1. Open Add Backend Modal: populates servers and annotates existing backends
    w.vpnCurrentBackends = [{ id: 1, server_id: 1 }];
    await w.vpnOpenAddBackendModal();
    assert(openedModals.includes('addBackendModal'), 'addBackendModal must be opened');
    assert(apiRequests.some(r => r.endpoint === '/api/servers'), 'GET /api/servers must be invoked');

    const select = w.document.getElementById('vpnServerSelect');
    assert.strictEqual(select.options.length, 3, 'select must have default + 2 server options');
    assert(select.options[1].textContent.includes('Server One'), 'option 1 must show Server One');
    assert(select.options[1].textContent.includes('[AWG]'), 'server with awg protocol must have [AWG] tag');
    assert(select.options[1].textContent.includes('Active'), 'existing backend server must have active tag');
    assert(!select.options[1].disabled, 'existing backend server must NOT be disabled');

    // 2. Select Server 2 (initially no AWG protocols)
    select.value = '2';
    w.vpnOnServerSelected();
    const details = w.document.getElementById('vpnServerDetails');
    assert.strictEqual(details.style.display, 'block', 'server details must be displayed on selection');
    const badge = w.document.getElementById('vpnServerDetailAwgBadge');
    assert(badge.className.includes('badge-warn'), 'missing AWG must display warning badge');
    const checkRow = w.document.getElementById('vpnServerDetailCheckRow');
    assert.strictEqual(checkRow.style.display, 'flex', 'check row must be visible when AWG absent');

    // 3. Trigger quick check on Server 2
    await w.vpnTriggerQuickCheck();
    assert(apiRequests.some(r => r.endpoint === '/api/servers/2/check'), 'POST /api/servers/2/check must be called');
    assert(badge.className.includes('badge-success'), 'badge must upgrade to badge-success after quick check');
    assert(badge.textContent.includes('AmneziaWG'), 'badge text must indicate AmneziaWG');
    assert.strictEqual(checkRow.style.display, 'none', 'check row must hide after successful AWG check');

    // 4. Submit Add Backend for Server 2
    await w.vpnSubmitAddBackend();
    assert(apiRequests.some(r => r.endpoint === '/api/vpn/backends/2/enable'), 'POST /api/vpn/backends/2/enable must be called');
    assert(closedModals.includes('addBackendModal'), 'modal must be closed after submit');
    assert.strictEqual(loadDataCount, 1, 'vpnLoadData must be called after backend enabled');

    // 5. Submit Edit Endpoint
    w.vpnConfiguredPublicEndpoint = 'vpn.old.domain:51820';
    w.vpnOpenEditEndpointModal();
    assert(openedModals.includes('editEndpointModal'), 'editEndpointModal opened');
    const input = w.document.getElementById('vpnPublicEndpointInput');
    assert.strictEqual(input.value, 'vpn.old.domain:51820', 'endpoint input populated from vpnConfiguredPublicEndpoint');

    input.value = 'vpn.new.domain:51820';
    await w.vpnSubmitEditEndpoint();
    assert(apiRequests.some(r => r.endpoint === '/api/vpn/config' && r.method === 'PUT' && r.body.public_endpoint === 'vpn.new.domain:51820'),
        'PUT /api/vpn/config must be called with public_endpoint');
    assert(closedModals.includes('editEndpointModal'), 'editEndpointModal closed');
    assert.strictEqual(loadDataCount, 2, 'vpnLoadData called after endpoint update');

    console.log('PASS_MODAL_INTERACTIONS');
})().catch(e => {
    console.error(e);
    process.exit(1);
});
`,
	})

	out, err := execNodeScript(nodePath, testScript)
	if err != nil {
		t.Fatalf("TestVPNBackendModalInteractionsAndQuickCheck failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "PASS_MODAL_INTERACTIONS") {
		t.Fatalf("expected output to contain PASS_MODAL_INTERACTIONS, got:\n%s", string(out))
	}
}
