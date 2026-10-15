package web

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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

		// 3. Minimum width rule
		tableStyle := getHTMLNodeAttr(table, "style")
		if !strings.Contains(tableStyle, "min-width: 540px") {
			t.Errorf("#vpn-fwd-routes-table style missing min-width: 540px, got: %q", tableStyle)
		}

		// 4. Headers: Peer has white-space: nowrap, Queue, Peak, Drops, Writes have text-align: right
		thNodes := findHTMLNodesByTag(table, "th")
		if len(thNodes) != 5 {
			t.Fatalf("expected 5 <th> elements in #vpn-fwd-routes-table, found %d", len(thNodes))
		}
		thPeerStyle := getHTMLNodeAttr(thNodes[0], "style")
		if !strings.Contains(thPeerStyle, "white-space: nowrap") {
			t.Errorf("peer header style = %q, want containing 'white-space: nowrap'", thPeerStyle)
		}
		for i, name := range []string{"queue", "peak", "drops", "writes"} {
			thStyle := getHTMLNodeAttr(thNodes[i+1], "style")
			if !strings.Contains(thStyle, "text-align: right") {
				t.Errorf("%s header style = %q, want containing 'text-align: right'", name, thStyle)
			}
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
		cmd := exec.Command(nodePath, "-e", runnerScript)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
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

		translationsJS := vpnDiagnosticsTranslationsJS(t, combined, "fa")

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
			style := getHTMLNodeAttr(thNodes[i], "style")
			if exp.nowrap && !strings.Contains(style, "white-space: nowrap") {
				t.Errorf("Persian header %d missing 'white-space: nowrap', style=%q", i, style)
			}
			if exp.alignment != "" && !strings.Contains(style, exp.alignment) {
				t.Errorf("Persian header %d missing %q, style=%q", i, exp.alignment, style)
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

assert.strictEqual(thElements[0].style.whiteSpace, 'nowrap', 'peer header white-space nowrap under RTL');
assert.strictEqual(thElements[1].style.textAlign, 'right', 'queue header text-align right under RTL');
assert.strictEqual(thElements[2].style.textAlign, 'right', 'peak header text-align right under RTL');
assert.strictEqual(thElements[3].style.textAlign, 'right', 'drops header text-align right under RTL');
assert.strictEqual(thElements[4].style.textAlign, 'right', 'writes header text-align right under RTL');

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

		translationsJS := vpnDiagnosticsTranslationsJS(t, combined, "en")

		testScript := jsdomBootstrapSnippet + fmt.Sprintf(`
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

// 2. Verify #vpn-fwd-routes-table style has min-width: 540px
const tableComputed = w.getComputedStyle(table);
assert.strictEqual(tableComputed.minWidth, '540px', 'table computed min-width must be 540px');
assert.strictEqual(table.style.minWidth, '540px', 'table inline style min-width must be 540px');

// 3. Verify min-width exceeds mobile viewport (~375px), preventing columns from collapsing
const minWidthPx = parseInt(tableComputed.minWidth, 10);
assert.strictEqual(minWidthPx, 540, 'min-width must be 540px');
assert(minWidthPx > w.innerWidth, 'table min-width (' + minWidthPx + 'px) exceeds narrow viewport (' + w.innerWidth + 'px), preserving columns and enabling horizontal scroll');

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
`, cssStr, renderedHTML, fixture.HealthProblemsJS, fixture.HealthSummaryJS, translationsJS)

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
		// Callers needing only template functions remain restricted strictly to fixture.TemplateHTML
		if _, err := extractJSFunction(fixture.TemplateHTML, "function vpnStatusLabel"); err != nil {
			t.Fatalf("extractJSFunction vpnStatusLabel from TemplateHTML failed: %v", err)
		}
		// TemplateHTML must not contain moved functions (scoping strictly limited to source)
		for _, fn := range []string{"renderSessions", "vpnFormatPeerKey"} {
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

function extract(name) {
    const start = source.indexOf('    function ' + name + '(');
    assert(start >= 0, 'function not found: ' + name);
    const rest = source.slice(start + 1);
    const match = /^    (?:async )?function /m.exec(rest);
    return source.slice(start, match ? start + 1 + match.index : source.indexOf('</script>', start));
}

const dom = new JSDOM(source.slice(0, source.indexOf('<script>')), { runScripts: 'outside-only', url: 'https://review.invalid' });
const w = dom.window;
w.eval(sessionsCode);
w.eval(healthProblemsCode);
w.eval(healthSummaryCode);
w.eval('const translations = ' + JSON.stringify(en) + ';' +
'function _(key) { return translations[key] || key; };' +
'function escapeHtml(s) { const el = document.createElement("div"); el.textContent = String(s == null ? "" : s); return el.innerHTML; };' +
'const UI = { escapeHtml };' +
'var vpnLastStatus = null;' +
'var vpnHistoryWindow = "15m";\n' +
[
    'vpnStatusLabel'
].map(extract).join('\n'));

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
            traffic: { available: true, rx_bps: 25000000, tx_bps: 25000000 } // 50 Mbps
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
            traffic: { available: true, rx_bps: 10000000, tx_bps: 10000000 } // 20 Mbps
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
            traffic: { available: true, rx_bps: 500000, tx_bps: 500000 } // 1 Mbps
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
            traffic: { available: true, rx_bps: 100000, tx_bps: 100000 } // 200 Kbps
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
            traffic: { available: true, rx_bps: 0, tx_bps: 0 } // 0 bps
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

    // Header 3: Packet Loss
    const thLoss = headers[3];
    assert(thLoss.textContent.includes('vpn_col_packet_loss'), 'col 3 must be packet loss header');

    // Packet Loss Ascending (1st click)
    thLoss.click();
    assert.strictEqual(thLoss.getAttribute('aria-sort'), 'ascending');
    assert.deepStrictEqual(rowOrder(), ['eve', 'dan', 'charlie', 'bob', 'alice'], 'loss ascending: Tier 4 (0) < Tier 3 (10k drops) < Tier 2 (25 recent) < Tier 1 (0.8 pps) < Tier 1 (4.5 pps)');

    // Packet Loss Descending (2nd click)
    thLoss.click();
    assert.strictEqual(thLoss.getAttribute('aria-sort'), 'descending');
    assert.deepStrictEqual(rowOrder(), ['alice', 'bob', 'charlie', 'dan', 'eve'], 'loss descending: Tier 1 (4.5 pps) > Tier 1 (0.8 pps) > Tier 2 (25 recent) > Tier 3 (10k drops) > Tier 4 (0)');

    // Explicit verification of operational triage guarantees:
    const descOrder = rowOrder();
    const aliceIdx = descOrder.indexOf('alice');
    const bobIdx = descOrder.indexOf('bob');
    const charlieIdx = descOrder.indexOf('charlie');
    const danIdx = descOrder.indexOf('dan');
    const eveIdx = descOrder.indexOf('eve');

    assert(aliceIdx < bobIdx, 'higher active drop rate (4.5 pps) must sort before lower rate (0.8 pps)');
    assert(bobIdx < charlieIdx, 'active rate loss must sort before recent loss with 0 current rate');
    assert(charlieIdx < danIdx, 'recent loss (25 recent drops) must sort before historical drops (10000 drops) despite lower total');
    assert(danIdx < eveIdx, 'historical drops must sort before zero drops');

`+vpnSessionsAccordionPersistenceSnippet+`    console.log('PASS');
})().catch(e => {
    console.error(e);
    process.exit(1);
});
`, tmplStr, string(enData), string(tablesJS), string(sessionsJS), fixture.HealthProblemsJS, fixture.HealthSummaryJS)

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
