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

// TestVPNPageBackendsInspectArrivalIsScopedToOneNavigation proves the Inspect request
// belongs to the arrival that carried it: the failed first read consumes it off tab
// storage and keeps it page-local, the retry in the same arrival still reveals and
// focuses the row, and a fresh document - which is what an ordinary later visit is -
// finds nothing left to replay.
func TestVPNPageBackendsInspectArrivalIsScopedToOneNavigation(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn_backends")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		// The real table engine: a reveal focuses the row's name cell, which only
		// the engine marks as focusable.
		IncludeNexusTable: true,
		ExtraJS: `
(async () => {
    const assert = require('assert');
    const tbody = w.document.getElementById('vpn-backends-tbody');
    const announcement = w.document.getElementById('vpn-backends-announcement');

    // The delivered row shape: the row's tunnel id is the backend's own id.
    const backends = [
        { id: 't-1', server_id: 1, endpoint: '198.51.100.1:51820', enabled: true, status: 'active' },
        { id: 't-2', server_id: 2, endpoint: '198.51.100.2:51820', enabled: true, status: 'active' }
    ];
    const rowCount = () => Array.from(tbody.children).filter(tr => !tr.classList.contains('table-empty-state')).length;

    // 1. The arrival that carries an Inspect request, whose first read fails.
    w.sessionStorage.setItem('vpn.backend-inspect.tunnel', 't-2');
    let mode = 'reject';
    w.API = {
        get: async () => { if (mode === 'reject') throw new Error('first read refused'); return { backends: backends }; },
        post: async () => ({})
    };
    await w.vpnLoadBackends();
    assert.ok(tbody.querySelector('tr.table-empty-state'), 'the refused first read is stated');
    assert.strictEqual(announcement.textContent, '', 'a failed arrival announces nothing about a missing entity');
    assert.strictEqual(w.sessionStorage.getItem('vpn.backend-inspect.tunnel'), null,
        'the arrival took the durable request off tab storage');
    assert.strictEqual(w.eval('vpnPendingInspectTunnelId'), 't-2',
        'the request stays page-local for the retry in this arrival');

    // 2. The retry in the same arrival may still use the request: it is page-local,
    //    not lost with the storage slot. The reveal-and-focus itself is pinned by the
    //    retained reveal oracle (TestVPN955R9BackendReveal), including which cell takes
    //    focus; here the request's survival is what this case owns.
    mode = 'ok';
    await w.vpnLoadBackends();
    assert.strictEqual(rowCount(), 2, 'the inventory rendered on the retry');
    assert.strictEqual(w.eval('vpnPendingInspectTunnelId'), null, 'the request was used once');
    assert.strictEqual(announcement.textContent, '', 'a revealed row announces nothing');

    // 3. An ordinary later visit is a fresh document: nothing page-local survives, and
    //    storage holds nothing to replay.
    w.eval('vpnPendingInspectTunnelId = null');
    w.eval('vpnBackendsAnchorApplied = false');
    w.document.activeElement.blur();
    await w.vpnLoadBackends();
    assert.strictEqual(rowCount(), 2, 'the inventory is still rendered');
    assert.strictEqual(w.document.activeElement, w.document.body,
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

// TestVPNPageOverviewColdSessionsFragmentFocusesANamedHeading covers the design
// re-check's cold case: the Sessions signal value is not focusable, so a fragment
// naming it must land on the overview's own heading - which therefore has to be
// focusable - and focus must not stay on the document body.
func TestVPNPageOverviewColdSessionsFragmentFocusesANamedHeading(t *testing.T) {
	fixture := NewVPNTestFixtureForPage(t, "vpn")
	fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const assert = require('assert');
    const value = w.document.getElementById('vpn-sessions');
    const heading = w.document.querySelector('h1.section-title');
    assert.ok(value, '#vpn-sessions must exist');
    assert.ok(heading, 'the overview has a page heading');

    // The value itself cannot take focus, so the heading is the landing.
    assert.strictEqual(value.getAttribute('tabindex'), null, 'the signal value is not made focusable');
    assert.strictEqual(heading.getAttribute('tabindex'), '-1', 'the page heading is focusable for the landing');
    assert.strictEqual(w.document.activeElement, w.document.body, 'focus starts on the document body');

    w.history.replaceState(null, '', '/vpn#vpn-sessions');
    const landed = w.vpnLandOverviewAnchor();
    assert.strictEqual(landed, 'vpn-sessions', 'the fragment resolved');
    assert.strictEqual(w.document.activeElement, heading,
        'a cold landing on the Sessions signal focuses the overview heading, not the body');

    console.log('PASS_OVERVIEW_COLD_SESSIONS');
})();
`,
	})

	out := fixture.RunJSDOM(testScript)
	if !strings.Contains(out, "PASS_OVERVIEW_COLD_SESSIONS") {
		t.Fatalf("expected PASS_OVERVIEW_COLD_SESSIONS, got:\n%s", out)
	}
}

// TestVPNSessionsCardHeadingCarriesTheLandingMargin covers the measured phone defect:
// a landing on #vpn-forwarder-card focuses the Health heading, so that heading needs
// the shell-chrome scroll margin the other landing targets carry. The delivered bundle
// is asserted, not the module, because the bundle is what the page links.
func TestVPNSessionsCardHeadingCarriesTheLandingMargin(t *testing.T) {
	bundle, err := StaticFS.ReadFile("static/css/style.css")
	if err != nil {
		t.Fatalf("read the delivered bundle: %v", err)
	}
	css := string(bundle)
	rule := css[strings.Index(css, "/* ===== Fragment landing geometry ====="):]
	if end := strings.Index(rule, "}"); end > 0 {
		rule = rule[:end]
	}
	for _, want := range []string{".vpn-health-title", ".vpn-page-title", "#vpn-troubleshooting-title"} {
		if !strings.Contains(rule, want) {
			t.Errorf("the landing margin rule does not cover %s, so a landing on it sits behind the shell bar:\n%s", want, rule)
		}
	}
	if !strings.Contains(rule, "scroll-margin-top") || !strings.Contains(rule, "--shell-chrome-height") {
		t.Errorf("the landing margin rule lost its offset:\n%s", rule)
	}
}
