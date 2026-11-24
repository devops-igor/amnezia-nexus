package web

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

func TestVPNForwarderRoutesTableFormatting(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	vpnStr := fixture.TemplateHTML
	combined := fixture.CombinedSource()
	cssStr := fixture.StyleCSS

	t.Run("TemplateDOMStructure", func(t *testing.T) {
		doc, err := xhtml.Parse(strings.NewReader(vpnStr))
		if err != nil {
			t.Fatalf("failed to parse vpn.html as HTML: %v", err)
		}

		table := findHTMLNodeByID(doc, "vpn-fwd-routes-table")
		if table == nil {
			t.Fatal("table #vpn-fwd-routes-table not found in vpn.html")
		}

		// 1. Parent container of #vpn-fwd-routes-table has class table-container
		parent := table.Parent
		if parent == nil {
			t.Fatal("parent container of #vpn-fwd-routes-table is nil")
		}
		if parent.Data != "div" {
			t.Errorf("parent tag = %q, want div", parent.Data)
		}
		parentClass := getHTMLNodeAttr(parent, "class")
		parentClasses := strings.Fields(parentClass)
		hasTableContainer := false
		for _, c := range parentClasses {
			if c == "table-container" {
				hasTableContainer = true
				break
			}
		}
		if !hasTableContainer {
			t.Errorf("parent container of #vpn-fwd-routes-table missing class table-container, got classes: %q", parentClass)
		}

		// 2. #vpn-fwd-routes-table has class data-table and does not have obsolete class table
		tableClass := getHTMLNodeAttr(table, "class")
		tableClasses := strings.Fields(tableClass)
		hasDataTable := false
		hasTable := false
		for _, c := range tableClasses {
			if c == "data-table" {
				hasDataTable = true
			}
			if c == "table" {
				hasTable = true
			}
		}
		if !hasDataTable {
			t.Errorf("#vpn-fwd-routes-table missing class data-table, got classes: %q", tableClass)
		}
		if hasTable {
			t.Errorf("#vpn-fwd-routes-table has obsolete class table, got classes: %q", tableClass)
		}

		// 3. The 540px minimum width is declared by the scoped stylesheet on the
		// table's named scroll region rather than as an inline style (#955 removes
		// large inline styling from the template).
		if tableStyle := getHTMLNodeAttr(table, "style"); tableStyle != "" {
			t.Errorf("#vpn-fwd-routes-table must not carry an inline style, got %q", tableStyle)
		}
		region := table.Parent
		if region == nil {
			t.Fatal("route table has no parent region")
		}
		if cls := getHTMLNodeAttr(region, "class"); !strings.Contains(cls, "vpn-route-table-region") {
			t.Errorf("route table wrapper class = %q, want the .vpn-route-table-region scroll region", cls)
		}
		if !strings.Contains(cssStr, ".vpn-route-table-region .data-table") ||
			!strings.Contains(cssStr, "min-inline-size: 540px") {
			t.Error("vpn.css must declare the 540px minimum on .vpn-route-table-region .data-table")
		}
		if !strings.Contains(cssStr, ".vpn-route-table-region") || !strings.Contains(cssStr, "overflow: auto") {
			t.Error("vpn.css must make the route region scroll inside itself")
		}

		// 4. Headers: numeric columns are right-aligned and the peer column does not
		// wrap, expressed as classes so RTL logical properties apply.
		thNodes := findHTMLNodesByTag(table, "th")
		if len(thNodes) != 5 {
			t.Fatalf("expected 5 <th> elements in #vpn-fwd-routes-table, found %d", len(thNodes))
		}
		for i := 1; i < len(thNodes); i++ {
			cls := getHTMLNodeAttr(thNodes[i], "class")
			if !strings.Contains(cls, "vpn-numeric") {
				t.Errorf("numeric header %d class = %q, want .vpn-numeric", i, cls)
			}
		}
		if !strings.Contains(cssStr, ".vpn-numeric") || !strings.Contains(cssStr, "text-align: right") {
			t.Error("vpn.css must right-align .vpn-numeric cells")
		}
		// Bind the declaration to the selector. Finding ".vpn-numeric" somewhere and
		// "text-align: right" somewhere else passes a stylesheet that left-aligns the
		// numeric column, so the rule's own body is what gets checked.
		if got, ok := cssDeclaration(cssStr, ".vpn-numeric", "text-align"); !ok || got != "right" {
			t.Errorf(".vpn-numeric text-align = %q (found=%t), want a declaration of right in that rule", got, ok)
		}

		// Counterexample control: the mutation that a substring oracle lets through.
		// Flipping the rule to left while an unrelated `text-align: right` remains
		// elsewhere must be detected, or this oracle proves nothing about alignment.
		mutatedCSS := strings.Replace(cssStr, ".vpn-numeric { text-align: right; }", ".vpn-numeric { text-align: left; }", 1)
		if mutatedCSS == cssStr {
			t.Fatal(".vpn-numeric mutation target missing from the stylesheet")
		}
		if got, ok := cssDeclaration(mutatedCSS, ".vpn-numeric", "text-align"); !ok || got != "left" {
			t.Errorf("the oracle cannot see a left-aligned .vpn-numeric rule: got %q (found=%t)", got, ok)
		}
		if !strings.Contains(mutatedCSS, "text-align: right") {
			t.Fatal("the counterexample must keep an unrelated right-aligned rule, otherwise it does not test selector binding")
		}
	})

	t.Run("RenderedCellFormattingInNode", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Fatal("Node is required for diagnostics verification")
		}

		runnerScript := vpnDiagnosticsHealthScript(t, combined, `
document.reset();

const sampleRoutes = [
    { peer_key: 'peer1', occupancy: 10, capacity: 100, high_water: 20, drops: 0, write_count: 50 },
    { peer_key: 'peer2', occupancy: 90, capacity: 100, high_water: 95, drops: 5, queue_full_drops_recent: 2, write_count: 50 },
    { peer_key: 'peer3', occupancy: 0, capacity: 100, high_water: 10, drops: 0, pressure_note: 'Testing note' },
    { peer_key: 'peer4', occupancy: 0, capacity: 100, high_water: 10, drops: 0, write_count: 10, write_errors: 2, write_errors_recent: 1 },
    { peer_key: 'peer5', occupancy: 0, capacity: 100, high_water: 10, drops: 0, write_count: 10, p95_write_ms: 25.4 }
];

vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    problem_routes: sampleRoutes,
    all_routes: sampleRoutes
});

const tbody = document.getElementById('vpn-fwd-routes-tbody');
assert.strictEqual(tbody.children.length, sampleRoutes.length, 'all sample routes rendered');

for (let i = 0; i < tbody.children.length; i++) {
    const row = tbody.children[i];
    const cells = row.children;
    assert.strictEqual(cells.length, 5, 'row has 5 cells');

    // Peer cell has white-space: nowrap
    assert.strictEqual(cells[0].style.whiteSpace, 'nowrap', 'row ' + i + ' peer cell must have white-space: nowrap');

    // Numeric cells have text-align: right
    assert.strictEqual(cells[1].style.textAlign, 'right', 'row ' + i + ' queue cell must have text-align: right');
    assert.strictEqual(cells[2].style.textAlign, 'right', 'row ' + i + ' peak cell must have text-align: right');
    assert.strictEqual(cells[3].style.textAlign, 'right', 'row ' + i + ' drops cell must have text-align: right');
    assert.strictEqual(cells[4].style.textAlign, 'right', 'row ' + i + ' writes cell must have text-align: right');
}

console.log('TABLE_FORMATTING_PASS');
`)
		out, err := execNodeScript(nodePath, runnerScript)
		if err != nil {
			t.Fatalf("Table formatting DOM tests failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "TABLE_FORMATTING_PASS") {
			t.Fatalf("Table formatting DOM tests did not output TABLE_FORMATTING_PASS\nOutput:\n%s", string(out))
		}
	})

	t.Run("PersianRTLRendering", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Fatal("Node is required for diagnostics verification")
		}

		faDict := vpnDiagnosticsLocale(t, "fa")
		renderedHTML := vpnDiagnosticsRenderedHTML(t, vpnStr, faDict)

		translationsJS := vpnDiagnosticsTranslationsJS(t, "fa")

		// 1. Static assertion on Go template output under Persian locale
		doc, err := xhtml.Parse(strings.NewReader(renderedHTML))
		if err != nil {
			t.Fatalf("failed to parse rendered Persian HTML: %v", err)
		}
		tableNode := findHTMLNodeByID(doc, "vpn-fwd-routes-table")
		if tableNode == nil {
			t.Fatal("table #vpn-fwd-routes-table not found in rendered Persian HTML")
		}
		thNodes := findHTMLNodesByTag(tableNode, "th")
		if len(thNodes) != 5 {
			t.Fatalf("expected 5 <th> elements in Persian table, found %d", len(thNodes))
		}
		expectedHeaders := []struct {
			key       string
			alignment string
			nowrap    bool
		}{
			{"vpn_forwarder_route_peer", "", true},
			{"vpn_forwarder_route_queue", "text-align: right", false},
			{"vpn_forwarder_route_peak", "text-align: right", false},
			{"vpn_forwarder_route_drops", "text-align: right", false},
			{"vpn_forwarder_route_writes", "text-align: right", false},
		}
		for i, exp := range expectedHeaders {
			gotText := getHTMLNodeText(thNodes[i])
			wantText := faDict[exp.key]
			if gotText != wantText {
				t.Errorf("Persian header %d (%s) = %q, want %q", i, exp.key, gotText, wantText)
			}
			// Alignment is expressed by class so logical properties hold in RTL.
			style := getHTMLNodeAttr(thNodes[i], "style")
			if style != "" {
				t.Errorf("Persian header %d must not carry an inline style, style=%q", i, style)
			}
			if exp.alignment != "" {
				if got, ok := cssDeclaration(cssStr, ".vpn-numeric", "text-align"); !ok || got != "right" {
					t.Errorf("Persian header %d: .vpn-numeric text-align = %q (found=%t), want right in that rule", i, got, ok)
				}
			}
			if exp.nowrap && !strings.Contains(cssStr, "white-space: nowrap") {
				t.Errorf("Persian header %d: stylesheet must keep the peer column unwrapped", i)
			}
		}

		// 2. Dynamic RTL rendering with JSDOM
		testScript := jsdomBootstrapSnippet + fmt.Sprintf(`
const dom = new JSDOM('<!DOCTYPE html><html dir="rtl"><head><style>' + %q + '</style></head><body>' + %q + '</body></html>', {
    pretendToBeVisual: true,
    runScripts: 'outside-only'
});
const w = dom.window;
w.eval(%q);
w.eval(%q);
w.eval(%q + "\nwindow.translations = translations;\nwindow._ = _;\n");

assert.strictEqual(w.document.documentElement.getAttribute('dir'), 'rtl', 'document has dir=rtl');

const table = w.document.getElementById('vpn-fwd-routes-table');
assert(table, '#vpn-fwd-routes-table must exist');
const tableComputed = w.getComputedStyle(table);
assert.strictEqual(tableComputed.direction, 'rtl', 'table computed direction must be rtl under dir=rtl root');

const thElements = w.document.querySelectorAll('#vpn-fwd-routes-table thead th');
assert.strictEqual(thElements.length, 5, 'must have 5 th headers');
assert.strictEqual(thElements[0].textContent.trim(), w.translations['vpn_forwarder_route_peer'], 'localized peer header');
assert.strictEqual(thElements[1].textContent.trim(), w.translations['vpn_forwarder_route_queue'], 'localized queue header');
assert.strictEqual(thElements[2].textContent.trim(), w.translations['vpn_forwarder_route_peak'], 'localized peak header');
assert.strictEqual(thElements[3].textContent.trim(), w.translations['vpn_forwarder_route_drops'], 'localized drops header');
assert.strictEqual(thElements[4].textContent.trim(), w.translations['vpn_forwarder_route_writes'], 'localized writes header');

// Header alignment is stylesheet-owned now (logical properties), so assert the
// class contract instead of an inline style.
assert(thElements[1].className.includes('vpn-numeric'), 'queue header uses the numeric class under RTL');
assert(thElements[2].className.includes('vpn-numeric'), 'peak header uses the numeric class under RTL');
assert(thElements[3].className.includes('vpn-numeric'), 'drops header uses the numeric class under RTL');
assert(thElements[4].className.includes('vpn-numeric'), 'writes header uses the numeric class under RTL');

const sampleRoutes = [
    { peer_key: 'fa_peer_1', occupancy: 10, capacity: 100, high_water: 20, drops: 0, write_count: 50 },
    { peer_key: 'fa_peer_2', occupancy: 85, capacity: 100, high_water: 90, drops: 3, queue_full_drops_recent: 1, write_count: 60 },
    { peer_key: 'fa_peer_3', occupancy: 0, capacity: 100, high_water: 10, drops: 0, pressure_note: 'توضیحات' }
];

w.vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    problem_routes: sampleRoutes,
    all_routes: sampleRoutes
});

const tbody = w.document.getElementById('vpn-fwd-routes-tbody');
assert.strictEqual(tbody.children.length, sampleRoutes.length, 'all sample routes rendered under RTL');

for (let i = 0; i < tbody.children.length; i++) {
    const row = tbody.children[i];
    const cells = row.children;
    assert.strictEqual(cells.length, 5, 'row ' + i + ' has 5 cells under RTL');
    assert.strictEqual(cells[0].style.whiteSpace, 'nowrap', 'row ' + i + ' peer cell must have white-space: nowrap under RTL');
    assert.strictEqual(cells[1].style.textAlign, 'right', 'row ' + i + ' queue cell must have text-align: right under RTL');
    assert.strictEqual(cells[2].style.textAlign, 'right', 'row ' + i + ' peak cell must have text-align: right under RTL');
    assert.strictEqual(cells[3].style.textAlign, 'right', 'row ' + i + ' drops cell must have text-align: right under RTL');
    assert.strictEqual(cells[4].style.textAlign, 'right', 'row ' + i + ' writes cell must have text-align: right under RTL');
}

console.log('PERSIAN_RTL_PASS');
`, cssStr, renderedHTML, fixture.HealthProblemsJS, fixture.HealthSummaryJS, translationsJS)

		out := runJSDOMTestScript(t, nodePath, testScript)
		if !strings.Contains(out, "PERSIAN_RTL_PASS") {
			t.Fatalf("Persian RTL test did not output PERSIAN_RTL_PASS\nOutput:\n%s", out)
		}
	})

	t.Run("NarrowViewportLayout", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Fatal("Node is required for diagnostics verification")
		}

		enDict := vpnDiagnosticsLocale(t, "en")
		renderedHTML := vpnDiagnosticsRenderedHTML(t, vpnStr, enDict)

		translationsJS := vpnDiagnosticsTranslationsJS(t, "en")

		testScript := jsdomBootstrapSnippet + fmt.Sprintf(`
const CSS_TEXT = %q;
const dom = new JSDOM('<!DOCTYPE html><html><head><style>' + %q + '</style></head><body>' + %q + '</body></html>', {
    pretendToBeVisual: true,
    runScripts: 'outside-only'
});
const w = dom.window;
w.innerWidth = 375;
w.outerWidth = 375;

w.eval(%q);
w.eval(%q);
w.eval(%q + "\nwindow.translations = translations;\nwindow._ = _;\n");

const table = w.document.getElementById('vpn-fwd-routes-table');
assert(table, '#vpn-fwd-routes-table must exist');
const container = table.closest('.table-container');
assert(container, 'parent .table-container must exist');

// 1. Verify container .table-container has overflow handling (overflow-x: auto)
const containerStyle = w.getComputedStyle(container);
assert.strictEqual(containerStyle.overflowX, 'auto', 'container must have overflow-x: auto');

// 2. The 540px minimum is declared by the scoped stylesheet on the named scroll
// region, not as an inline style; the region scrolls instead of the document.
assert.strictEqual(table.style.minWidth, '', 'table must not carry an inline min-width');
const region = table.closest('.vpn-route-table-region');
assert(region, 'table must sit inside the .vpn-route-table-region scroll region');
assert.strictEqual(region.getAttribute('tabindex'), '0', 'the scroll region is keyboard reachable');
assert.strictEqual(region.getAttribute('role'), 'region', 'the scroll region is a named region');
assert(region.getAttribute('aria-label'), 'the scroll region has an accessible name');
assert(CSS_TEXT.includes('.vpn-route-table-region .data-table'), 'stylesheet declares the route table minimum width');
assert(CSS_TEXT.includes('min-inline-size: 540px'), 'stylesheet minimum width is 540px');
assert(CSS_TEXT.includes('overflow: auto'), 'stylesheet makes the region scroll inside itself');

// 4. Render sample routes and verify table renders without collapsing columns
const sampleRoutes = [
    { peer_key: 'peer_mobile_1', occupancy: 25, capacity: 100, high_water: 50, drops: 0, write_count: 100 },
    { peer_key: 'peer_mobile_2', occupancy: 95, capacity: 100, high_water: 100, drops: 12, queue_full_drops_recent: 3, write_count: 200 }
];

w.vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 100,
    problem_routes: sampleRoutes,
    all_routes: sampleRoutes
});

assert.strictEqual(table.style.display, '', 'table is displayed when routes exist');
const tbody = w.document.getElementById('vpn-fwd-routes-tbody');
assert.strictEqual(tbody.children.length, sampleRoutes.length, 'all sample routes rendered');

for (let i = 0; i < tbody.children.length; i++) {
    const row = tbody.children[i];
    const cells = row.children;
    assert.strictEqual(cells.length, 5, 'row has 5 cells');
    assert.strictEqual(cells[0].style.whiteSpace, 'nowrap', 'peer cell retains white-space nowrap on narrow viewport');
    assert.strictEqual(cells[1].style.textAlign, 'right', 'queue cell text-align right');
    assert.strictEqual(cells[2].style.textAlign, 'right', 'peak cell text-align right');
    assert.strictEqual(cells[3].style.textAlign, 'right', 'drops cell text-align right');
    assert.strictEqual(cells[4].style.textAlign, 'right', 'writes cell text-align right');
}

console.log('NARROW_VIEWPORT_PASS');
`, cssStr, cssStr, renderedHTML, fixture.HealthProblemsJS, fixture.HealthSummaryJS, translationsJS)

		out := runJSDOMTestScript(t, nodePath, testScript)
		if !strings.Contains(out, "NARROW_VIEWPORT_PASS") {
			t.Fatalf("Narrow viewport test did not output NARROW_VIEWPORT_PASS\nOutput:\n%s", out)
		}
	})

	t.Run("CombinedSourceAndTemplateScoping", func(t *testing.T) {
		combined := fixture.CombinedSource()
		for _, fn := range []string{"renderSessions", "vpnRenderSessionRow", "vpnFormatPeerKey"} {
			if _, err := extractJSFunction(combined, "function "+fn); err != nil {
				t.Fatalf("extractJSFunction %s from combined source failed: %v", fn, err)
			}
		}
		if _, err := extractJSFunction(fixture.BackendsJS, "function vpnStatusLabel"); err != nil {
			t.Fatalf("extractJSFunction vpnStatusLabel from BackendsJS failed: %v", err)
		}
		// TemplateHTML must not contain moved functions (scoping strictly limited to source)
		for _, fn := range []string{"renderSessions", "vpnFormatPeerKey", "vpnStatusLabel"} {
			if _, err := extractJSFunction(fixture.TemplateHTML, "function "+fn); err == nil {
				t.Fatalf("expected error extracting %s from TemplateHTML without fallback", fn)
			}
		}
	})
}

func TestVPNSessionsTableSortingAndAccordionPersistence(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	node := fixture.RequireNode()
	tmplStr := fixture.TemplateHTML
	sessionsJS := fixture.SessionsJS

	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatal(err)
	}
	tablesJS, err := fs.ReadFile(staticFS, "js/tables.js")
	if err != nil {
		t.Fatal(err)
	}

	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatal(err)
	}
	enData, err := fs.ReadFile(transFS, "en.json")
	if err != nil {
		t.Fatal(err)
	}

	testScript := fmt.Sprintf(`
const fs = require('fs');
const assert = require('assert');
const path = require('path');

const home = process.env.HOME || process.env.USERPROFILE || '';
const searchPaths = [
    home ? path.join(home, '.hermes', 'hermes-agent', 'node_modules') : '',
    home ? path.join(home, '.cache', 'typescript', '6.0', 'node_modules') : '',
    process.env.NODE_PATH || ''
].filter(Boolean);
searchPaths.forEach(p => {
    if (fs.existsSync(p) && !module.paths.includes(p)) {
        module.paths.push(p);
    }
});

try {
    const globalRoot = require('child_process').execSync('npm root -g').toString().trim();
    if (globalRoot && !module.paths.includes(globalRoot)) {
        module.paths.push(globalRoot);
    }
} catch (_) {}

let JSDOM;
try {
    JSDOM = require('jsdom').JSDOM;
} catch (e) {
    console.log('JSDOM_NOT_AVAILABLE: ' + e.message);
    process.exit(0);
}

const source = %q;
const en = JSON.parse(%q);
const tablesCode = %q;
const sessionsCode = %q;
const healthProblemsCode = %q;
const healthSummaryCode = %q;
const backendsCode = %q;

const dom = new JSDOM(source, { runScripts: 'outside-only', url: 'https://review.invalid' });
const w = dom.window;
// Load the real formatter module so the byte column is asserted against the same
// formatter production ships, not a test-local imitation of it.
let telemetryCode = null;
for (const candidate of ['static/js/telemetry.js', 'web/static/js/telemetry.js']) {
    if (fs.existsSync(candidate)) { telemetryCode = fs.readFileSync(candidate, 'utf8'); break; }
}
if (telemetryCode === null) throw new Error('telemetry.js not found');
w.eval(telemetryCode);
assert.strictEqual(typeof w.Telemetry.formatBytes, 'function', 'the real byte formatter must be loaded');
w.eval(sessionsCode);
w.eval(healthProblemsCode);
w.eval(healthSummaryCode);
w.eval(backendsCode);
w.eval('const translations = ' + JSON.stringify(en) + ';' +
'function _(key) { return translations[key] || key; };' +
'function escapeHtml(s) { const el = document.createElement("div"); el.textContent = String(s == null ? "" : s); return el.innerHTML; };' +
'const UI = { escapeHtml };' +
'var vpnLastStatus = null;\n');

w.eval(tablesCode);

(async function() {
    // 5 sessions covering:
    // - Differing traffic rates (dan 50M > alice 20M > bob 1M > charlie 200k > eve 0)
    // - Packet loss tiers:
    //   Tier 1: active drop rates (alice 4.5 pps > bob 0.8 pps)
    //   Tier 2: recent drops with zero rate (charlie 25 recent drops)
    //   Tier 3: historical lifetime drops with zero recent (dan 10000 drops)
    //   Tier 4: zero drops (eve 0 drops)
    const sessions = [
        { id: 's-dan', username: 'dan', connection_id: 'c-dan', assigned_ip: '10.8.0.4', status: 'connected' },
        { id: 's-alice', username: 'alice', connection_id: 'c-alice', assigned_ip: '10.8.0.2', status: 'connected' },
        { id: 's-bob', username: 'bob', connection_id: 'c-bob', assigned_ip: '10.8.0.3', status: 'connected' },
        { id: 's-charlie', username: 'charlie', connection_id: 'c-charlie', assigned_ip: '10.8.0.5', status: 'connected' },
        { id: 's-eve', username: 'eve', connection_id: 'c-eve', assigned_ip: '10.8.0.6', status: 'connected' }
    ];

    const routes = [
        {
            session_id: 's-dan',
            connection_id: 'c-dan',
            assigned_ip: '10.8.0.4',
            occupancy: 10,
            capacity: 100,
            drops: 10000,
            queue_full_drops_recent: 0,
            queue_full_drop_rate_pps: 0,
            has_pressure: false,
            traffic: { available: true, rx_bps: 25000000, tx_bps: 25000000, rx_bytes: 104857600, tx_bytes: 104857600 } // 50 Mbps, 200 MiB
        },
        {
            session_id: 's-alice',
            connection_id: 'c-alice',
            assigned_ip: '10.8.0.2',
            occupancy: 90,
            capacity: 100,
            drops: 20,
            queue_full_drops_recent: 10,
            queue_full_drop_rate_pps: 4.5,
            has_pressure: true,
            traffic: { available: true, rx_bps: 10000000, tx_bps: 10000000, rx_bytes: 157286400, tx_bytes: 157286400 } // 20 Mbps, 300 MiB
        },
        {
            session_id: 's-bob',
            connection_id: 'c-bob',
            assigned_ip: '10.8.0.3',
            occupancy: 50,
            capacity: 100,
            drops: 5,
            queue_full_drops_recent: 2,
            queue_full_drop_rate_pps: 0.8,
            has_pressure: true,
            traffic: { available: true, rx_bps: 500000, tx_bps: 500000, rx_bytes: 5242880, tx_bytes: 5242880 } // 1 Mbps, 10 MiB
        },
        {
            session_id: 's-charlie',
            connection_id: 'c-charlie',
            assigned_ip: '10.8.0.5',
            occupancy: 30,
            capacity: 100,
            drops: 50,
            queue_full_drops_recent: 25,
            queue_full_drop_rate_pps: 0,
            has_pressure: true,
            traffic: { available: true, rx_bps: 100000, tx_bps: 100000, rx_bytes: 262144000, tx_bytes: 262144000 } // 200 Kbps, 500 MiB
        },
        {
            session_id: 's-eve',
            connection_id: 'c-eve',
            assigned_ip: '10.8.0.6',
            occupancy: 0,
            capacity: 100,
            drops: 0,
            queue_full_drops_recent: 0,
            queue_full_drop_rate_pps: 0,
            has_pressure: false,
            traffic: { available: true, rx_bps: 0, tx_bps: 0, rx_bytes: 0, tx_bytes: 0 } // 0 bps, nothing transferred yet
        }
    ];

    w.vpnLastSessions = { sessions: sessions };
    w.vpnLastStatus = {
        forwarder_available: true,
        all_routes: routes
    };

    w.renderSessions(sessions);

    const tbody = w.document.getElementById('vpn-sessions-tbody');
    function rowOrder() {
        return Array.from(tbody.children)
            .filter(r => r.style.display !== 'none' && !r.classList.contains('table-loading-row') && !r.classList.contains('table-empty-state'))
            .map(r => r.cells[0]?.querySelector('.font-weight-600')?.textContent.trim() || r.cells[0]?.textContent.trim());
    }

    const headers = Array.from(w.document.querySelectorAll('#vpnSessionsTable thead th'));
    assert.strictEqual(headers.length, 5, 'must have 5 headers');

    // Header 2: Live Traffic
    const thTraffic = headers[2];
    assert(thTraffic.textContent.includes('vpn_col_live_traffic'), 'col 2 must be live traffic header');

    // Live Traffic Ascending (1st click)
    thTraffic.click();
    assert.strictEqual(thTraffic.getAttribute('aria-sort'), 'ascending');
    assert.deepStrictEqual(rowOrder(), ['eve', 'charlie', 'bob', 'alice', 'dan'], 'traffic ascending: 0 < 200k < 1M < 20M < 50M');

    // Live Traffic Descending (2nd click)
    thTraffic.click();
    assert.strictEqual(thTraffic.getAttribute('aria-sort'), 'descending');
    assert.deepStrictEqual(rowOrder(), ['dan', 'alice', 'bob', 'charlie', 'eve'], 'traffic descending: 50M > 20M > 1M > 200k > 0');

    // Header 3: Transferred (issue #976 removed the dataplane-drops column from
    // this table; its counters stay in Advanced Diagnostics).
    const thTransferred = headers[3];
    assert(thTransferred.textContent.includes('vpn_col_transferred'), 'col 3 must be the Transferred header');
    assert(!thTransferred.textContent.includes('vpn_col_packet_loss'), 'the dataplane-drops column must not come back');

    // Transferred Ascending (1st click): eve 0 B < bob 10 MiB < dan 200 MiB
    // < alice 300 MiB < charlie 500 MiB. The order is deliberately different from
    // the live-traffic order asserted above, so sorting on the wrong cell (or on
    // the departed drop counters) cannot pass this.
    thTransferred.click();
    assert.strictEqual(thTransferred.getAttribute('aria-sort'), 'ascending');
    assert.deepStrictEqual(rowOrder(), ['eve', 'bob', 'dan', 'alice', 'charlie'], 'transferred ascending: 0 B < 10 MiB < 200 MiB < 300 MiB < 500 MiB');

    // Transferred Descending (2nd click)
    thTransferred.click();
    assert.strictEqual(thTransferred.getAttribute('aria-sort'), 'descending');
    assert.deepStrictEqual(rowOrder(), ['charlie', 'alice', 'dan', 'bob', 'eve'], 'transferred descending: 500 MiB > 300 MiB > 200 MiB > 10 MiB > 0 B');

    // The cell reports both directions summed, in human-readable units, and no
    // row exposes the drop counter that used to occupy this column.
    const transferredByUser = {};
    Array.from(tbody.children).forEach(function (r) {
        const user = r.cells[0] ? r.cells[0].querySelector('.font-weight-600') : null;
        if (user) transferredByUser[user.textContent.trim()] = r.cells[3];
    });
    assert.strictEqual(transferredByUser['dan'].textContent, '200 MB', 'dan: 100 MiB in + 100 MiB out');
    assert.strictEqual(transferredByUser['alice'].textContent, '300 MB', 'alice: 150 MiB in + 150 MiB out');
    assert.strictEqual(transferredByUser['eve'].textContent, '0 B', 'a measured zero renders as 0 B, not a dash');
    Array.from(tbody.children).forEach(function (r) {
        assert(!/drops/i.test(r.textContent), 'no session row may carry the drop counter: ' + r.textContent);
    });

`+vpnSessionsAccordionPersistenceSnippet+`    console.log('PASS');
})().catch(e => {
    console.error(e);
    process.exit(1);
});
`, tmplStr, string(enData), string(tablesJS), string(sessionsJS), fixture.HealthProblemsJS, fixture.HealthSummaryJS, fixture.BackendsJS)

	out, err := execNodeScript(node, testScript)
	if err != nil {
		t.Fatalf("TestVPNSessionsTableSortingAndAccordionPersistence failed: %v\n%s", err, string(out))
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		if os.Getenv("CI") != "" {
			t.Fatalf("jsdom is not available in CI environment: %s", out)
		}
		t.Skip("jsdom is not available in Node environment")
	}
}

// cssCommentPattern matches a CSS comment, which carries no selector text and
// must be removed before a rule's selector list can be compared.
var cssCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)

// cssDeclaration returns the value of one declaration inside the rule whose
// selector list contains selector. It exists so a styling oracle can bind a
// declaration to its selector: checking that ".vpn-numeric" appears somewhere and
// "text-align: right" appears SOMEWHERE ELSE passes a stylesheet that left-aligns
// the numeric column. The last matching rule wins, as it does in the cascade for
// equally specific selectors.
func cssDeclaration(css, selector, property string) (string, bool) {
	// A comment between two rules is not part of the selector that follows it.
	// Left in place it breaks the comparison below, so a documented rule would be
	// invisible to the binding while an undocumented one passed.
	css = cssCommentPattern.ReplaceAllString(css, "")
	value, found := "", false
	declPattern := regexp.MustCompile(`(?m)(?:^|;)\s*` + regexp.QuoteMeta(property) + `\s*:\s*([^;{}]+)`)
	close := -1
	for {
		open := strings.Index(css[close+1:], "{")
		if open < 0 {
			break
		}
		open += close + 1
		end := strings.Index(css[open:], "}")
		if end < 0 {
			break
		}
		end += open
		close = end

		// The selector list is the text since the previous rule's closing brace.
		headStart := strings.LastIndex(css[:open], "}")
		selectors := strings.Split(css[headStart+1:open], ",")
		matches := false
		for _, candidate := range selectors {
			if strings.TrimSpace(candidate) == selector {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if decl := declPattern.FindStringSubmatch(css[open+1 : end]); len(decl) == 2 {
			value, found = strings.TrimSpace(decl[1]), true
		}
	}
	return value, found
}

// requireJSDOMForTransferredGuard fails closed on the dependency this regression
// guard exists to enforce. A guard that inherits the shared fixture's optional
// t.Skip prints the same green "ok" as a passing one, so an environment without
// Node/jsdom cannot silently disable the protection for the sessions table.
func requireJSDOMForTransferredGuard(t *testing.T) string {
	t.Helper()
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatalf("the Transferred-column guard requires a Node binary with jsdom: %v", err)
	}
	out, err := execNodeScript(nodePath, jsdomBootstrapSnippet+`console.log("JSDOM_READY");`)
	if err != nil || !strings.Contains(string(out), "JSDOM_READY") {
		t.Fatalf("the Transferred-column guard requires jsdom: %v\nOutput:\n%s", err, string(out))
	}
	return nodePath
}

// TestVPNSessionsTransferredColumn covers issue #976: the sessions table reports
// the traffic each session has carried instead of the forwarder drop counter.
// The drop counters themselves are unchanged and stay in Advanced Diagnostics.
func TestVPNSessionsTransferredColumn(t *testing.T) {
	fixture := NewVPNTestFixture(t)

	t.Run("HeaderReplacesDataplaneDrops", func(t *testing.T) {
		doc, err := xhtml.Parse(strings.NewReader(fixture.TemplateHTML))
		if err != nil {
			t.Fatalf("failed to parse vpn.html: %v", err)
		}
		table := findHTMLNodeByID(doc, "vpnSessionsTable")
		if table == nil {
			t.Fatal("sessions table #vpnSessionsTable not found in vpn.html")
		}
		thNodes := findHTMLNodesByTag(table, "th")
		if len(thNodes) != 5 {
			t.Fatalf("sessions table headers = %d, want 5", len(thNodes))
		}
		// The third header must be the new key, and the drop column key must not
		// appear anywhere in this table's markup: re-adding it fails here.
		if got := getHTMLNodeText(thNodes[3]); !strings.Contains(got, `vpn_col_transferred`) {
			t.Errorf("sessions header 3 = %q, want the vpn_col_transferred label", got)
		}
		// The transferred header carries its own class, so the no-wrap rule that
		// keeps a locale without a space from splitting the label can be bound to
		// this column instead of every header in the table.
		if cls := getHTMLNodeAttr(thNodes[3], "class"); !strings.Contains(cls, "vpn-transferred-head") {
			t.Errorf("sessions header 3 class = %q, want .vpn-transferred-head", cls)
		}
		for i, th := range thNodes {
			text := getHTMLNodeText(th)
			if strings.Contains(text, "vpn_col_packet_loss") {
				t.Errorf("sessions header %d still renders the dataplane-drops column: %q", i, text)
			}
			if strings.Contains(text, "vpn_dataplane_drops_scope") {
				t.Errorf("sessions header %d still carries the forwarder drop scope note: %q", i, text)
			}
		}
		// Drop figures stay reachable in Advanced Diagnostics: the routing drop
		// readouts and the per-route table that carry them are still present.
		for _, id := range []string{"vpn-routing-drops", "vpn-diag-drops-client", "vpn-diag-drops-return", "vpn-fwd-routes-table"} {
			if findHTMLNodeByID(doc, id) == nil {
				t.Errorf("Advanced Diagnostics drop surface %q is missing", id)
			}
		}
	})

	// The value is one unbreakable, explicitly isolated run and the labels only
	// wrap where the locale offers a break. Both are declarations bound to their
	// own selectors, so a rule renamed or moved elsewhere cannot pass. The sheet
	// read here is the one the page links (vpn.css), not the concatenated
	// artifact; TestStyleCSSConcatenationParity keeps the two identical.
	t.Run("ValueAndLabelsDeclareTheirOwnWrapping", func(t *testing.T) {
		staticFS, err := GetStaticSubFS()
		if err != nil {
			t.Fatal(err)
		}
		vpnCSS, err := fs.ReadFile(staticFS, "css/vpn.css")
		if err != nil {
			t.Fatal(err)
		}
		cssStr := string(vpnCSS)
		expect := []struct{ selector, property, value string }{
			{".vpn-transferred-value", "white-space", "nowrap"},
			{".vpn-transferred-value", "unicode-bidi", "isolate"},
			{".vpn-transferred-value", "direction", "ltr"},
			{".vpn-transferred-missing", "white-space", "nowrap"},
			{".vpn-transferred-head", "white-space", "nowrap"},
		}
		for _, want := range expect {
			got, ok := cssDeclaration(cssStr, want.selector, want.property)
			if !ok || got != want.value {
				t.Errorf("%s %s = %q (found=%t), want %q", want.selector, want.property, got, ok, want.value)
			}
		}

		// Counterexample control: the mutation a substring oracle lets through.
		// Dropping the isolation and letting the value wrap again must be visible
		// through the same selector binding, not absorbed by a nearby rule.
		original := ".vpn-transferred-value {\n    white-space: nowrap;\n    unicode-bidi: isolate;\n    direction: ltr;\n}"
		mutated := ".vpn-transferred-value {\n    white-space: normal;\n    unicode-bidi: normal;\n    direction: ltr;\n}"
		if strings.Count(cssStr, original) != 1 {
			t.Fatalf("the .vpn-transferred-value rule is not present exactly once in the delivered stylesheet")
		}
		mutatedCSS := strings.Replace(cssStr, original, mutated, 1)
		if got, _ := cssDeclaration(mutatedCSS, ".vpn-transferred-value", "unicode-bidi"); got != "normal" {
			t.Errorf("mutation control: unicode-bidi = %q, want the mutated value", got)
		}
		if got, _ := cssDeclaration(mutatedCSS, ".vpn-transferred-value", "white-space"); got != "normal" {
			t.Errorf("mutation control: white-space = %q, want the mutated value", got)
		}
	})

	// The not-measured state owns its colour. The shared muted token and the
	// shared .form-hint style are issue 977's subject, so this delivery must not
	// reach for either: the state label declares --text-secondary itself.
	t.Run("NotMeasuredStateOwnsItsColour", func(t *testing.T) {
		staticFS, err := GetStaticSubFS()
		if err != nil {
			t.Fatal(err)
		}
		vpnCSS, err := fs.ReadFile(staticFS, "css/vpn.css")
		if err != nil {
			t.Fatal(err)
		}
		cssStr := string(vpnCSS)
		got, ok := cssDeclaration(cssStr, ".vpn-transferred-missing", "color")
		if !ok || got != "var(--text-secondary)" {
			t.Errorf(".vpn-transferred-missing color = %q (found=%t), want var(--text-secondary)", got, ok)
		}
		if got, _ := cssDeclaration(cssStr, ".vpn-transferred-missing", "color"); got == "var(--text-muted)" {
			t.Error("the not-measured state must not borrow the shared muted token")
		}

		componentsCSS, err := fs.ReadFile(staticFS, "css/components.css")
		if err != nil {
			t.Fatal(err)
		}
		// Issue 977 tracks the shared hint style; it stays exactly as it is.
		if got, ok := cssDeclaration(string(componentsCSS), ".form-hint", "color"); !ok || got != "var(--text-muted)" {
			t.Errorf(".form-hint color = %q (found=%t); the shared hint style belongs to issue 977 and must not move here", got, ok)
		}
	})

	t.Run("LabelInAllFiveLocales", func(t *testing.T) {
		for _, lang := range requiredLocales {
			dict := fixture.Locale(lang)
			if strings.TrimSpace(dict["vpn_col_transferred"]) == "" {
				t.Errorf("%s missing vpn_col_transferred", lang)
			}
			if dict["vpn_col_transferred"] == dict["vpn_col_packet_loss"] {
				t.Errorf("%s uses the dataplane-drops label for the Transferred column", lang)
			}
		}
		if got := fixture.Locale("en")["vpn_col_transferred"]; got != "Transferred" {
			t.Errorf("en vpn_col_transferred = %q, want %q", got, "Transferred")
		}
	})

	t.Run("RenderedTotalsAndNotMeasured", func(t *testing.T) {
		node := requireJSDOMForTransferredGuard(t)
		enDict := fixture.Locale("en")
		rendered := vpnDiagnosticsRenderedHTML(t, fixture.TemplateHTML, enDict)
		translationsJS := vpnDiagnosticsTranslationsJS(t, "en")

		staticFS, err := GetStaticSubFS()
		if err != nil {
			t.Fatal(err)
		}
		tablesJS, err := fs.ReadFile(staticFS, "js/tables.js")
		if err != nil {
			t.Fatal(err)
		}

		testScript := fmt.Sprintf(`
const fs = require('fs');
const assert = require('assert');
let JSDOM;
try {
    JSDOM = require('jsdom').JSDOM;
} catch (e) {
    console.log('JSDOM_NOT_AVAILABLE: ' + e.message);
    process.exit(2);
}

const source = %q;
const tablesCode = %q;
const sessionsCode = %q;

// The real production formatter, so the assertion is about shipped formatting.
let telemetryCode = null;
for (const candidate of ['static/js/telemetry.js', 'web/static/js/telemetry.js']) {
    if (fs.existsSync(candidate)) { telemetryCode = fs.readFileSync(candidate, 'utf8'); break; }
}
if (telemetryCode === null) { throw new Error('telemetry.js not found'); }

const dom = new JSDOM(source, { runScripts: 'outside-only', url: 'https://review.invalid' });
const w = dom.window;
w.eval(telemetryCode);
w.eval(sessionsCode);
w.eval(%q + "\nwindow.translations = translations;\nwindow._ = _;\n");
w.eval('const UI = { escapeHtml }; var vpnLastStatus = null;');
w.eval(tablesCode);

(async function() {
    const sessions = [
        { id: 's-dave', username: 'dave', server_name: 'eu-1', status: 'connected' },
        { id: 's-erin', username: 'erin', server_name: 'eu-1', status: 'connected' },
        { id: 's-frank', username: 'frank', server_name: 'eu-1', status: 'connected' },
        { id: 's-gina', username: 'gina', server_name: 'eu-1', status: 'connected' },
        { id: 's-hank', username: 'hank', server_name: 'eu-1', status: 'connected' }
    ];
    const routes = [
        // 1 MiB in + 0.5 MiB out, plus the drop counters that used to own this
        // column. The drop values must not reach the row.
        { session_id: 's-dave', traffic: { available: true, rx_bytes: 1048576, tx_bytes: 524288 }, drops: 987654, queue_full_drops_recent: 17, queue_full_drop_rate_pps: 42.5 },
        // Measured, genuinely nothing carried yet.
        { session_id: 's-erin', traffic: { available: false, rx_bytes: 0, tx_bytes: 0 } },
        // Hairline: a route registered but no byte counters in the payload.
        { session_id: 's-gina', traffic: { available: false } },
        // 3 MiB in + 2 MiB out.
        { session_id: 's-hank', traffic: { available: true, rx_bytes: 3145728, tx_bytes: 2097152 } }
        // frank has no route at all -> no forwarder counter to read.
    ];

    w.vpnLastSessions = { sessions: sessions };
    w.vpnLastStatus = { forwarder_available: true, all_routes: routes };
    w.renderSessions(sessions);

    const tbody = w.document.getElementById('vpn-sessions-tbody');
    const headerCells = Array.from(w.document.querySelectorAll('#vpnSessionsTable thead th'));
    assert.strictEqual(headerCells.length, 5, 'the sessions table has 5 columns');
    assert.strictEqual(headerCells[3].textContent.trim(), w.translations['vpn_col_transferred'], 'header 3 is the localized Transferred label');
    headerCells.forEach(function (th, i) {
        assert.notStrictEqual(th.textContent.trim(), w.translations['vpn_col_packet_loss'], 'header ' + i + ' must not be the dataplane-drops column');
    });

    const rowByUser = {};
    Array.from(tbody.children).forEach(function (r) {
        const user = r.cells[0] ? r.cells[0].querySelector('.font-weight-600') : null;
        if (user) rowByUser[user.textContent.trim()] = r;
    });
    assert.deepStrictEqual(Object.keys(rowByUser).sort(), ['dave', 'erin', 'frank', 'gina', 'hank'], 'every session rendered');

    const cell = name => rowByUser[name].cells[3];
    // Both directions summed, in human-readable units from the shared formatter.
    assert.strictEqual(cell('dave').textContent, '1.50 MB', 'dave: 1 MiB + 0.5 MiB is a formatted both-direction total');
    assert.strictEqual(cell('hank').textContent, '5.00 MB', 'hank: 3 MiB + 2 MiB is a formatted both-direction total');
    assert.strictEqual(cell('erin').textContent, '0 B', 'a measured zero is 0 B');
    assert.strictEqual(cell('frank').textContent, w.translations['vpn_diag_not_measured'], 'no route means no counter: not measured');
    assert.strictEqual(cell('gina').textContent, w.translations['vpn_diag_not_measured'], 'no byte counters means not measured');

    assert.strictEqual(cell('dave').getAttribute('data-sort-value'), '1572864', 'the sort value is the raw byte total');
    assert.strictEqual(cell('hank').getAttribute('data-sort-value'), '5242880', 'the sort value is the raw byte total');
    assert.strictEqual(cell('erin').getAttribute('data-sort-value'), '0', 'a measured zero sorts as zero');
    assert.strictEqual(cell('frank').getAttribute('data-sort-value'), '-1', 'unmeasured sorts below a measured zero');
    assert.strictEqual(cell('gina').getAttribute('data-sort-value'), '-1', 'unmeasured sorts below a measured zero');

    assert(cell('dave').className.indexOf('font-mono') !== -1, 'measured totals keep the numeric font');

    // The measured value is one element of its own: the number and its unit are
    // inside a single token, so no line break can fall between them, and the
    // element isolates the run so a right-to-left line cannot reorder it.
    const daveToken = cell('dave').querySelector('[data-transferred-value]');
    assert(daveToken !== null, 'the measured value is its own element');
    assert.strictEqual(cell('dave').children.length, 1, 'the cell holds exactly the value element');
    assert.strictEqual(daveToken.className, 'vpn-transferred-value', 'the value element carries its own class');
    assert.strictEqual(daveToken.textContent, '1.50 MB', 'the value element carries the formatted total');
    assert(cell('hank').querySelector('[data-transferred-value]').textContent === '5.00 MB', 'every measured row uses the token');

    // The not-measured state carries its own class rather than borrowing the
    // shared muted utility that the whole row background makes unreadable.
    assert(cell('frank').className.indexOf('vpn-transferred-missing') !== -1, 'the not-measured state carries its own class');
    assert(cell('frank').className.indexOf('text-muted') === -1, 'the not-measured state does not borrow the shared muted utility');
    assert(cell('frank').children.length === 0, 'the not-measured label stays plain text');

    // The counter that used to live here is gone from every rendered row.
    Array.from(tbody.children).forEach(function (r) {
        assert(!/drops/i.test(r.textContent), 'no session row exposes the drop counter: ' + r.textContent);
        assert(!r.textContent.includes(String(987654)), 'no session row exposes the lifetime drop count');
    });

    // Sorting follows the byte totals, not the departed drop tiers, and the
    // unmeasured rows stay below a measured zero in ascending order.
    const thTransferred = headerCells[3];
    thTransferred.click();
    assert.strictEqual(thTransferred.getAttribute('aria-sort'), 'ascending');
    function rowOrder() {
        return Array.from(tbody.children)
            .filter(r => r.style.display !== 'none' && !r.classList.contains('table-empty-state'))
            .map(r => r.cells[0]?.querySelector('.font-weight-600')?.textContent.trim());
    }
    assert.deepStrictEqual(rowOrder(), ['frank', 'gina', 'erin', 'dave', 'hank'], 'ascending: not measured < 0 B < 1.50 MB < 5.00 MB');

    thTransferred.click();
    assert.strictEqual(thTransferred.getAttribute('aria-sort'), 'descending');
    assert.deepStrictEqual(rowOrder(), ['hank', 'dave', 'erin', 'frank', 'gina'], 'descending: 5.00 MB > 1.50 MB > 0 B > not measured');

    console.log('TRANSFERRED_COLUMN_PASS');
})().catch(function (e) {
    console.error(e && e.stack ? e.stack : e);
    process.exit(1);
});
`, rendered, string(tablesJS), fixture.SessionsJS, translationsJS)

		out, err := execNodeScript(node, testScript)
		if err != nil {
			t.Fatalf("Transferred column DOM assertions failed: %v\nOutput:\n%s", err, string(out))
		}
		if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
			t.Fatalf("the Transferred-column guard requires jsdom: %s", string(out))
		}
		if !strings.Contains(string(out), "TRANSFERRED_COLUMN_PASS") {
			t.Fatalf("Transferred column DOM assertions did not complete\nOutput:\n%s", string(out))
		}
	})
}
