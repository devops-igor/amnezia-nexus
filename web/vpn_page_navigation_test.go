package web

// Fragment landings and dialog focus restoration on the three VPN documents.
//
// These are the navigation guarantees the split had to keep, each asserted through
// the real landing function of the document that owns the target:
//
//	diagnostics  its own disclosure id opens the disclosure and lands on its title;
//	             a conditional target that is not rendered (the stale banner) lands
//	             on the heading that owns it instead of leaving focus on the body
//	overview     a fragment naming anything inside the endpoint dialog lands on the
//	             control that opens it, with the configuration revealed, and never
//	             opens the dialog
//	backends     the Inspect request belongs to the arrival that carried it: a failed
//	             first read does not let a later ordinary visit replay it, and the
//	             retry in the same arrival still focuses the row; a dismiss after a
//	             refresh that replaced the opener restores focus to the owner's
//	             permanent control

import (
	"strings"
	"testing"
)

// TestVPNPageDiagnosticsAnchorsLandVisibly covers the disclosure's own id and the
// conditional stale banner.
func TestVPNPageDiagnosticsAnchorsLandVisibly(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');
    const panel = w.document.getElementById('vpn-diagnostics');
    const entry = w.document.getElementById('vpn-advanced-entry');
    const title = w.document.getElementById('vpn-diagnostics-title');

    // 1. The disclosure's own id opens it; focus lands on its title, which is
    //    inside the panel and therefore invisible while the panel is closed.
    assert.strictEqual(panel.hidden, true, 'the disclosure starts closed');
    w.history.replaceState(null, '', '/vpn/diagnostics#vpn-diagnostics');
    const landed = w.vpnApplyDiagnosticsAnchor();
    assert.strictEqual(landed, 'vpn-diagnostics', 'the id resolved');
    assert.strictEqual(panel.hidden, false, 'landing on the disclosure opens it');
    assert.strictEqual(entry.getAttribute('aria-expanded'), 'true', 'the entry reports the panel open');
    assert.strictEqual(w.document.activeElement, title, 'focus lands on the panel title');

    // 2. A conditional target that is not rendered lands on the heading that owns it,
    //    not on the document body.
    assert.strictEqual(w.document.getElementById('vpnSessionsStaleBanner'), null,
        'the stale banner is absent when no read has failed');
    w.history.replaceState(null, '', '/vpn/diagnostics#vpnSessionsStaleBanner');
    w.document.activeElement.blur();
    const fallbackLanded = w.vpnApplyDiagnosticsAnchor();
    assert.strictEqual(fallbackLanded, 'vpnSessionsStaleBanner', 'the id was still recognised');
    const heading = w.document.getElementById('vpn-troubleshooting-title');
    assert.strictEqual(w.document.activeElement, heading,
        'focus falls back to the heading that owns the conditional target');

    console.log('PASS_DIAGNOSTICS_ANCHORS');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DIAGNOSTICS_ANCHORS") {
		t.Fatalf("expected PASS_DIAGNOSTICS_ANCHORS, got:\n%s", out)
	}
}

// TestVPNPageOverviewModalAnchorLandsOnItsOpener proves a fragment never opens the
// endpoint dialog and never focuses inside it.
func TestVPNPageOverviewModalAnchorLandsOnItsOpener(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');
    const config = w.document.getElementById('vpn-configuration');
    const opener = w.document.getElementById('vpn-edit-endpoint-btn');
    const modal = w.document.getElementById('editEndpointModal');

    assert.ok(config, '#vpn-configuration must exist');
    if (config) config.open = false;

    for (const id of ['vpnPublicEndpointInput', 'editEndpointForm', 'editEndpointModal']) {
        config.open = false;
        w.history.replaceState(null, '', '/vpn#' + id);
        const landed = w.vpnLandOverviewAnchor();
        assert.strictEqual(landed, 'vpn-edit-endpoint-btn', id + ' canonicalises to the control that opens the dialog');
        assert.strictEqual(config.open, true, id + ' reveals the configuration that holds the opener');
        assert.strictEqual(w.document.activeElement, opener, id + ' focuses the opener');
        assert.ok(!(modal.classList && modal.classList.contains('active')), id + ' must not open the dialog');
    }

    console.log('PASS_OVERVIEW_MODAL_ANCHOR');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_MODAL_ANCHOR") {
		t.Fatalf("expected PASS_OVERVIEW_MODAL_ANCHOR, got:\n%s", out)
	}
}

// TestVPNPageBackendsInspectArrivalIsScopedToOneNavigation proves a failed arrival is
// not replayed by a later ordinary visit, and that the retry still lands.
func TestVPNPageBackendsInspectArrivalIsScopedToOneNavigation(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');
    const tbody = w.document.getElementById('vpn-backends-tbody');
    const announcement = w.document.getElementById('vpn-backends-announcement');
    w.NexusTable = function () { this.refresh = () => {}; this.revealRow = () => true; };

    const backends = [
        { tunnel_id: 't-1', server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active' },
        { tunnel_id: 't-2', server_id: 2, endpoint: '198.51.100.2:51820', enabled: true, status: 'active' }
    ];
    const rowCount = () => Array.from(tbody.children).filter(tr => !tr.classList.contains('table-empty-state')).length;

    // The arrival that carries an Inspect request, whose first read fails.
    w.sessionStorage.setItem('vpn.backend-inspect.tunnel', 't-2');
    w.API = { get: async () => { throw new Error('first read refused'); }, post: async () => ({}) };
    await w.vpnLoadBackends();
    assert.ok(tbody.querySelector('tr.table-empty-state'), 'the refused first read is stated');
    assert.strictEqual(announcement.textContent, '', 'a failed arrival announces nothing about a missing entity');

    // A later ordinary visit: the durable slot was consumed at the arrival above, so
    // nothing is replayed even though the entity is now present.
    w.sessionStorage.removeItem('vpn.backend-inspect.tunnel');
    w.API = { get: async () => ({ backends: backends }), post: async () => ({}) };
    await w.vpnLoadBackends();
    assert.strictEqual(rowCount(), 2, 'the inventory rendered');
    assert.notStrictEqual(w.document.activeElement && w.document.activeElement.getAttribute
        ? w.document.activeElement.getAttribute('data-tunnel-id') : null, 't-2',
        'an ordinary visit must not focus the previous Inspect entity');
    assert.strictEqual(announcement.textContent, '', 'an ordinary visit must not announce a missing entity');

    console.log('PASS_INSPECT_SCOPED');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_INSPECT_SCOPED") {
		t.Fatalf("expected PASS_INSPECT_SCOPED, got:\n%s", out)
	}
}

// TestVPNPageBackendsDismissRestoresFocusAfterRefresh proves a dismiss after a
// refresh that replaced the opener still returns focus to a real control.
func TestVPNPageBackendsDismissRestoresFocusAfterRefresh(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(async () => {
    const assert = require('assert');
    const tbody = w.document.getElementById('vpn-backends-tbody');
    const addBtn = w.document.getElementById('vpn-add-backend-btn');
    w.NexusTable = function () { this.refresh = () => {}; };

    // The real modal manager: the behaviour under test is what it does with a saved
    // opener that the refresh has replaced.
    for (const cp of ['static/js/ui.js', 'web/static/js/ui.js']) {
        if (fs.existsSync(cp)) {
            const tag = w.document.createElement('script');
            tag.textContent = fs.readFileSync(cp, 'utf8');
            w.document.body.appendChild(tag);
            break;
        }
    }
    assert.strictEqual(typeof w.openModal, 'function', 'the real modal manager is loaded');

    let backends = [];
    w.API = { get: async () => ({ backends: backends }), post: async () => ({}) };
    await w.vpnLoadBackends();

    // The empty-state CTA opens the dialog; the refresh that follows replaces it.
    const cta = tbody.querySelector('button[data-action="vpn-open-add-backend"]');
    assert.ok(cta, 'the empty state offers the Add control');
    cta.focus();
    w.openModal('addBackendModal');

    backends = [{ tunnel_id: 't-1', server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active' }];
    await w.vpnLoadBackends();
    assert.strictEqual(w.document.contains(cta), false, 'the refresh replaced the control that opened the dialog');

    w.closeModal('addBackendModal');
    assert.strictEqual(w.document.activeElement, addBtn,
        'dismissing after a refresh returns focus to the permanent Add control');

    console.log('PASS_DISMISS_FOCUS');
})().catch(e => { console.error(e); process.exit(1); });
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_DISMISS_FOCUS") {
		t.Fatalf("expected PASS_DISMISS_FOCUS, got:\n%s", out)
	}
}
