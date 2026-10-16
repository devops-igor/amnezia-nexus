package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

func TestVPNDiagnosticsCurrentObservations(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	fixture := NewVPNTestFixture(t)
	source := []byte(fixture.CombinedSource())
	script := vpnDiagnosticsHealthScript(t, string(source), `
const text = id => document.getElementById(id).textContent;
const base = {forwarder_available:true, health_assessment:{status:'HEALTHY'}, rates:{available:true}};
// A recovered data path with historical cumulative drops must be Healthy, not Degraded
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:3,capacity:11,peak:7,drops:13},
 nexus_to_upstream:{occupancy:5,capacity:17,peak:9,drops:19}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Healthy');

// Active queue pressure (>= 80%) degrades VirtualTUN
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:9,capacity:10,peak:9,drops:0},
 nexus_to_upstream:{occupancy:1,capacity:10,peak:1,drops:0}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Degraded');

// Moderate queue pressure (>= 50%, < 80%) marks VirtualTUN as Warning
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:5,capacity:10,peak:5,drops:0},
 nexus_to_upstream:{occupancy:1,capacity:10,peak:1,drops:0}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Warning');

// Active VirtualTUN drop rate (>= 10.0 pps) degrades VirtualTUN
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:1,capacity:10,peak:1,drops:0},
 nexus_to_upstream:{occupancy:1,capacity:10,peak:1,drops:0}},
 drop_categories:{rates_available:true,reason_rates:{client_virtualtun_drops:10.5}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Degraded');

// Active VirtualTUN drop rate (> 0, < 10.0 pps) marks VirtualTUN as Warning
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:1,capacity:10,peak:1,drops:0},
 nexus_to_upstream:{occupancy:1,capacity:10,peak:1,drops:0}},
 drop_categories:{rates_available:true,reason_rates:{return_virtualtun_drops:2.0}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Warning');

// Combined drop rate (client + return) >= 10.0 degrades VirtualTUN
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:1,capacity:10,peak:1,drops:0},
 nexus_to_upstream:{occupancy:1,capacity:10,peak:1,drops:0}},
 drop_categories:{rates_available:true,reason_rates:{client_virtualtun_drops:6.0,return_virtualtun_drops:4.5}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Degraded');

// Zero-capacity unmeasured queues render unavailable
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{capacity:0,occupancy:0},
 nexus_to_upstream:{capacity:0,occupancy:0}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (stopped) • VirtualTUN: Loss rate unavailable');

vpnRenderForwarderHealth({...base,listener_running:true,virtual_tun:{
 upstream_to_nexus:{occupancy:0,capacity:100,peak:0,drops:0},
 nexus_to_upstream:{occupancy:0,capacity:100,peak:0,drops:0}}});
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (active) • VirtualTUN: Healthy');

// Every disjoint reason has current rate and lifetime evidence. The overlapping
// return_injection_tun_drops diagnostic is excluded from the owned reason list.
vpnRenderForwarderHealth({...base,drop_categories:{rates_available:true,
 client_malformed:37,return_queue_full:41,return_injection_tun_drops:999,
 reason_rates:{client_malformed:2.5,return_queue_full:7}}});
let rows=document.getElementById('vpn-diag-drop-reasons').children;
assert.strictEqual(rows.length,2);
assert(rows[0].textContent.includes('7.00 pps (41 cumulative)'));
assert(rows.find(row => row.textContent.includes('2.50 pps (37 cumulative)')));
assert(!rows.some(row => row.textContent.includes('999') || row.textContent.includes('retired')));
vpnRenderForwarderHealth({...base,drop_categories:{rates_available:false,
 client_malformed:37,reason_rates:{client_malformed:99}}});
rows=document.getElementById('vpn-diag-drop-reasons').children;
assert.strictEqual(rows.length,1);
assert(rows[0].textContent.includes('Loss rate unavailable (37 cumulative)'));
assert(rows.every(row => row.style.color === ''));
vpnRenderForwarderHealth({...base,drop_categories:{rates_available:true,
 client_malformed:37,reason_rates:{client_malformed:0}}});
assert(document.getElementById('vpn-diag-drop-reasons').children[0].textContent.includes('0.00 pps (37 cumulative)'));

// Heap bytes use binary MiB. Missing or unknown limit never invents capacity.
for (const available of [undefined,false]) {
 vpnRenderForwarderHealth({...base,runtime_resources:{
  memory_alloc_bytes:2097152,memory_limit_bytes:0,memory_usage_pct:99,memory_limit_available:available}});
 assert.strictEqual(text('vpn-diag-res-mem'),'Heap: 2.0 MiB / Limit unavailable');
}
vpnRenderForwarderHealth({...base,runtime_resources:{
 memory_alloc_bytes:0,memory_limit_bytes:104857600,memory_usage_pct:0,memory_limit_available:true}});
assert.strictEqual(text('vpn-diag-res-mem'),'Heap: 0.0 MiB / 100.0 MiB (0.0%)');

// Cumulative failures do not manufacture current health. No health source means unknown.
vpnRenderForwarderHealth({forwarder_available:true,forwarder_drops_queue_full:99});
assert.strictEqual(text('vpn-fwd-status-text'),'Not reported');
vpnRenderForwarderHealth({...base,forwarder_queue_high_water:73,drop_categories: {rates_available:true,total_drops:99}});
assert.strictEqual(text('vpn-fwd-status-text'),'Healthy');
assert.strictEqual(text('vpn-diag-queue-peak'),'73 (0.0%)');

// Synchronization uses actual/desired peer membership; handshake gauges are separate.
for (const [desired,actual] of [[3,3],[3,1]]) {
 vpnRenderForwarderHealth({...base,upstream_peers_count:99,peer_sync:{
  desired_peers:desired,actual_peers:actual,sync_failures:1,add_failures:1,enqueue_failures:2}});
 assert.strictEqual(text('vpn-kpi-peer-sync'),actual+' / '+desired);
 assert.strictEqual(text('vpn-diag-peers-status'),desired+' / '+actual);
}
vpnRenderForwarderHealth(base);
assert.strictEqual(text('vpn-kpi-peer-sync'),'Unavailable');
vpnRenderForwarderHealth(null);
assert.strictEqual(text('vpn-diag-drop-reasons'),'-');
assert.strictEqual(document.getElementById('vpn-diag-drop-reasons').children.length,0);
`)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("current observations: %v\n%s", err, out)
	}
}

func TestVPNDiagnosticsTemplateDOMOracle(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	fixture := NewVPNTestFixture(t)
	source := []byte(fixture.CombinedSource())
	mutated := strings.Replace(string(source), `id="vpn-diag-throughput"`, `id="vpn-diag-throughput-typo"`, 1)
	script := vpnDiagnosticsHealthScript(t, mutated, `vpnRenderForwarderHealth({forwarder_available:true});`)
	if out, err := execNodeScript(node, script); err == nil ||
		!strings.Contains(string(out), "DOM id missing from actual template: vpn-diag-throughput") {
		t.Fatalf("template ID mutation escaped DOM oracle: %v", err)
	}
}

func TestVPNDiagnosticsPollingContract(t *testing.T) {
	pageSource, err := fs.ReadFile(StaticFS, "static/js/vpn/page.js")
	if err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]int{
		"NexusTelemetry.poll('vpn-status'": 1,
		"API.get('/api/vpn/status')":       1,
	} {
		if got := strings.Count(string(pageSource), token); got != want {
			t.Errorf("%s count=%d, want%d", token, got, want)
		}
	}
	for _, token := range []string{"vpnRenderForwarderHealth(status)", "vpnRenderForwarderHealth(null)"} {
		if !strings.Contains(string(pageSource), token) {
			t.Errorf("polling must handle %s", token)
		}
	}

	tmplSource, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(tmplSource)
	if !strings.Contains(tmplStr, `<script src="/static/js/vpn/page.js"></script>`) {
		t.Errorf("expected rendered templates/vpn.html to contain '<script src=\"/static/js/vpn/page.js\"></script>'")
	}

	inlineScriptRegex := regexp.MustCompile(`(?s)<script(?:\s+type="[^"]*")?>\s*[^<]`)
	if inlineScriptRegex.MatchString(tmplStr) {
		t.Errorf("templates/vpn.html must not contain inline <script> blocks")
	}
}

func TestVPNDashboardSectionOrder(t *testing.T) {
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	vpnData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}

	doc, err := xhtml.Parse(strings.NewReader(string(vpnData)))
	if err != nil {
		t.Fatalf("failed to parse vpn.html: %v", err)
	}

	if err := validateVPNDashboardDOMOrder(doc); err != nil {
		t.Fatalf("vpn.html failed dashboard section order validation: %v", err)
	}

	t.Run("RejectsDecoyComments", func(t *testing.T) {
		// Old pre-fix order with ordered ID strings placed inside an HTML comment before forwarder
		decoyHTML := `
			<div class="stats-grid"></div>
			<!-- id="vpnBackendsTable" id="vpnSessionsTable" id="vpn-forwarder-card" -->
			<div class="card" id="vpn-forwarder-card"></div>
			<div class="card"><table id="vpnBackendsTable"></table></div>
			<div class="card"><table id="vpnSessionsTable"></table></div>
		`
		decoyDoc, err := xhtml.Parse(strings.NewReader(decoyHTML))
		if err != nil {
			t.Fatalf("failed to parse decoy HTML: %v", err)
		}
		if err := validateVPNDashboardDOMOrder(decoyDoc); err == nil {
			t.Fatal("expected validateVPNDashboardDOMOrder to reject decoy comment fixture, but it passed")
		}
	})

	t.Run("RejectsNestedCards", func(t *testing.T) {
		// Sessions card nested inside backends card
		nestedHTML := `
			<div class="stats-grid"></div>
			<div class="card">
				<table id="vpnBackendsTable"></table>
				<div class="card"><table id="vpnSessionsTable"></table></div>
			</div>
			<div class="card" id="vpn-forwarder-card"></div>
		`
		nestedDoc, err := xhtml.Parse(strings.NewReader(nestedHTML))
		if err != nil {
			t.Fatalf("failed to parse nested HTML: %v", err)
		}
		if err := validateVPNDashboardDOMOrder(nestedDoc); err == nil {
			t.Fatal("expected validateVPNDashboardDOMOrder to reject nested card fixture, but it passed")
		}
	})

	t.Run("RejectsSwappedSections", func(t *testing.T) {
		swappedHTML := `
			<div class="stats-grid"></div>
			<div class="card"><table id="vpnSessionsTable"></table></div>
			<div class="card"><table id="vpnBackendsTable"></table></div>
			<div class="card" id="vpn-forwarder-card"></div>
		`
		swappedDoc, err := xhtml.Parse(strings.NewReader(swappedHTML))
		if err != nil {
			t.Fatalf("failed to parse swapped HTML: %v", err)
		}
		if err := validateVPNDashboardDOMOrder(swappedDoc); err == nil {
			t.Fatal("expected validateVPNDashboardDOMOrder to reject swapped sections fixture, but it passed")
		}
	})

	t.Run("RejectsDuplicateIDs", func(t *testing.T) {
		dupHTML := `
			<div class="stats-grid"></div>
			<div class="card"><table id="vpnBackendsTable"></table></div>
			<div class="card"><table id="vpnBackendsTable"></table></div>
			<div class="card"><table id="vpnSessionsTable"></table></div>
			<div class="card" id="vpn-forwarder-card"></div>
		`
		dupDoc, err := xhtml.Parse(strings.NewReader(dupHTML))
		if err != nil {
			t.Fatalf("failed to parse duplicate ID HTML: %v", err)
		}
		if err := validateVPNDashboardDOMOrder(dupDoc); err == nil {
			t.Fatal("expected validateVPNDashboardDOMOrder to reject duplicate ID fixture, but it passed")
		}
	})
}

// TestVPNHistoricalChartsContract verifies that the historical trends panel contains
// the 4 core operational chart containers, their header badge containers, their time
// axis containers, and the floating tooltip element (#459).
func TestVPNHistoricalChartsContract(t *testing.T) {
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	vpnData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	doc, err := xhtml.Parse(strings.NewReader(string(vpnData)))
	if err != nil {
		t.Fatalf("failed to parse vpn.html: %v", err)
	}

	chartIDs := []string{
		"vpn-chart-throughput",
		"vpn-chart-drops",
		"vpn-chart-queue",
		"vpn-chart-latency",
	}
	badgeIDs := []string{
		"vpn-chart-throughput-badges",
		"vpn-chart-drops-badges",
		"vpn-chart-queue-badges",
		"vpn-chart-latency-badges",
	}
	axisIDs := []string{
		"vpn-chart-throughput-axis",
		"vpn-chart-drops-axis",
		"vpn-chart-queue-axis",
		"vpn-chart-latency-axis",
	}

	for _, id := range chartIDs {
		node := findHTMLNodeByID(doc, id)
		if node == nil {
			t.Errorf("expected chart container #%s to exist", id)
		}
	}
	for _, id := range badgeIDs {
		node := findHTMLNodeByID(doc, id)
		if node == nil {
			t.Errorf("expected header badge container #%s to exist", id)
		}
	}
	for _, id := range axisIDs {
		node := findHTMLNodeByID(doc, id)
		if node == nil {
			t.Errorf("expected time axis container #%s to exist", id)
		}
	}

	if tooltipNode := findHTMLNodeByID(doc, "vpn-chart-tooltip"); tooltipNode == nil {
		t.Errorf("expected floating tooltip #vpn-chart-tooltip to exist")
	}
	if selectNode := findHTMLNodeByID(doc, "vpn-history-backend-select"); selectNode == nil {
		t.Errorf("expected backend selector #vpn-history-backend-select to exist")
	}
	if seriesNode := findHTMLNodeByID(doc, "vpn-chart-backend-series"); seriesNode == nil {
		t.Errorf("expected backend series container #vpn-chart-backend-series to exist")
	}

	obsoleteIDs := []string{
		"vpn-chart-directions",
		"vpn-chart-packets",
		"vpn-chart-sessions-routes",
		"vpn-chart-backend-latency",
	}
	for _, id := range obsoleteIDs {
		if node := findHTMLNodeByID(doc, id); node != nil {
			t.Errorf("expected obsolete chart container #%s to be completely removed from DOM", id)
		}
	}

	t.Run("JSRenderContract", func(t *testing.T) {
		fixture := NewVPNTestFixture(t)
		nodePath := fixture.RequireNode()
		script := vpnDOMMock(t, string(vpnData)) + "\n" +
			fixture.TranslationsJS("en") + "\n" +
			fixture.HealthProblemsJS + "\n" +
			fixture.ChartsJS + `
const series = {
    window_15m: [
        { t: 1700000000, rx_bps: 8000000, tx_bps: 8000000, traffic_available: true, q_pct: 25, drop_rate: 2, drop_rates_available: true, drop_reason_rates: { return_queue_full: 2, return_malformed: 0 }, fwd_p95_ms: 12.5, fwd_p95_samples: 1, be_p95_ms: 8, be_latency_samples: 1, backends: [] },
        { t: 1700000060, rx_bps: 16000000, tx_bps: 16000000, traffic_available: true, q_pct: 50, drop_rate: 5, drop_rates_available: true, drop_reason_rates: { return_queue_full: 5, return_malformed: 0 }, fwd_p95_ms: 25.0, fwd_p95_samples: 1, be_p95_ms: 15, be_latency_samples: 1, backends: [] }
    ]
};
vpnRenderHistoryCharts(series);

// Check badges
const tBadges = document.getElementById('vpn-chart-throughput-badges').textContent;
assert(tBadges.includes('Current:') && tBadges.includes('Peak:'), 'throughput badges text: ' + tBadges);
assert(tBadges.includes('MB/s'), 'throughput unit MB/s: ' + tBadges);

const dBadges = document.getElementById('vpn-chart-drops-badges').textContent;
assert(dBadges.includes('Current:') && dBadges.includes('Peak:'), 'drops badges text: ' + dBadges);
assert(dBadges.includes('drops/s'), 'drops unit drops/s: ' + dBadges);

const qBadges = document.getElementById('vpn-chart-queue-badges').textContent;
assert(qBadges.includes('Current:') && qBadges.includes('Peak:'), 'queue badges text: ' + qBadges);
assert(qBadges.includes('%'), 'queue unit %: ' + qBadges);

const lBadges = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadges.includes('Write: 25 ms') && lBadges.includes('Probe: 15 ms') && lBadges.includes('Peak: 25 ms (write)'), 'latency badges text: ' + lBadges);
assert(lBadges.includes('ms'), 'latency unit ms: ' + lBadges);

// Check time axes
const tAxis = document.getElementById('vpn-chart-throughput-axis').innerHTML;
assert(tAxis.includes('<span>') && tAxis.includes('</span>'), 'throughput axis contains timestamp spans');

// Check reasons suppression: return_queue_full has drops, return_malformed has 0
const reasonsEl = document.getElementById('vpn-chart-reasons');
assert(reasonsEl.textContent.includes('return queue full'), 'active reason rendered');
assert(!reasonsEl.textContent.includes('return malformed'), 'zero-drop reason suppressed');

// Check all zero reasons display empty state
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: { return_malformed: 0 }, fwd_p95_ms: 0, fwd_p95_samples: 0, backends: [] }
    ]
});
assert(document.getElementById('vpn-chart-reasons').textContent.includes('No data (15m)'), 'all zero reasons show empty state');

// Check SVG contains crosshair and overlay
const tChart = document.getElementById('vpn-chart-throughput').innerHTML;
assert(tChart.includes('chart-crosshair'), 'sparkline contains crosshair');
assert(tChart.includes('chart-overlay'), 'sparkline contains overlay');

// Check Fix R1: newest sample unavailable -> Current is '—', Peak evaluates past samples
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 8000000, tx_bps: 8000000, traffic_available: true, q_pct: 25, drop_rate: 2, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 12.5, fwd_p95_samples: 1, backends: [] },
        { t: 1700000060, rx_bps: 0, tx_bps: 0, traffic_available: false, q_pct: null, drop_rate: 0, drop_rates_available: false, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, backends: [] }
    ]
});
const tBadgesUnavail = document.getElementById('vpn-chart-throughput-badges').textContent;
assert(tBadgesUnavail.includes('Current: —'), 'throughput unavailable Current: ' + tBadgesUnavail);
assert(tBadgesUnavail.includes('Peak:'), 'throughput preserved Peak: ' + tBadgesUnavail);

const dBadgesUnavail = document.getElementById('vpn-chart-drops-badges').textContent;
assert(dBadgesUnavail.includes('Current: —'), 'drops unavailable Current: ' + dBadgesUnavail);
assert(dBadgesUnavail.includes('Peak: 2 drops/s'), 'drops preserved Peak: ' + dBadgesUnavail);

const lBadgesUnavail = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesUnavail.includes('Current: —'), 'latency unavailable Current: ' + lBadgesUnavail);
assert(lBadgesUnavail.includes('Peak: 12.5 ms'), 'latency preserved Peak: ' + lBadgesUnavail);

// Check Fix R1: valid zero is rendered (not —)
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 1, backends: [] }
    ]
});
const tBadgesZero = document.getElementById('vpn-chart-throughput-badges').textContent;
assert(tBadgesZero.includes('Current: 0.0 MB/s'), 'throughput zero Current: ' + tBadgesZero);
const dBadgesZero = document.getElementById('vpn-chart-drops-badges').textContent;
assert(dBadgesZero.includes('Current: 0 drops/s'), 'drops zero Current: ' + dBadgesZero);
const qBadgesZero = document.getElementById('vpn-chart-queue-badges').textContent;
assert(qBadgesZero.includes('Current: 0%'), 'queue zero Current: ' + qBadgesZero);
const lBadgesZero = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesZero.includes('Current: 0 ms'), 'latency zero Current: ' + lBadgesZero);

// Check Fix R2: tooltip reset at beginning of render
const tipEl = document.getElementById('vpn-chart-tooltip');
tipEl.style.display = 'block';
vpnRenderHistoryCharts({ window_15m: [] });
assert.strictEqual(tipEl.style.display, 'none', 'tooltip hidden at beginning of render');

// Check Fix R5: low positive throughput formatting (<1KB/s formatted as B/s)
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 400, tx_bps: 400, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, backends: [] }
    ]
});
const tBadgesLow = document.getElementById('vpn-chart-throughput-badges').textContent;
assert(tBadgesLow.includes('Current: 100 B/s'), 'throughput sub-KB formatted as B/s: ' + tBadgesLow);

// Rework Round 5: Idle forwarder with backend probe latency: latency chart must be available and interactive
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 15.5, be_latency_samples: 1, backends: [] }
    ]
});
const lChartIdle = document.getElementById('vpn-chart-latency').innerHTML;
assert(!lChartIdle.includes('No data'), 'idle forwarder with probe latency must not show No data');
assert(lChartIdle.includes('<path'), 'idle forwarder with probe latency must render curve');
assert(lChartIdle.includes('chart-overlay'), 'idle forwarder latency chart must include overlay');
const lBadgesIdle = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesIdle.includes('Current: 15.5 ms (probe)'), 'latency idle Current (probe): ' + lBadgesIdle);
assert(lBadgesIdle.includes('Peak: 15.5 ms (probe)'), 'latency idle Peak: ' + lBadgesIdle);

// Rework Round 5: Backend selector and fractional queue formatting
vpnRenderHistoryCharts({
    window_15m: [
        {
            t: 1700000000, rx_bps: 1000, tx_bps: 1000, traffic_available: true, q_pct: 0.4, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 5, fwd_p95_samples: 1, be_p95_ms: 5, be_latency_samples: 1,
            backends: [
                { id: 1, rx_bps: 100, tx_bps: 200, rx_pps: 10, tx_pps: 20, traffic_available: true, probe_latency_ms: 8, probe_available: true },
                { id: 2, rx_bps: 300, tx_bps: 400, rx_pps: 30, tx_pps: 40, traffic_available: true, probe_latency_ms: 12, probe_available: true }
            ]
        }
    ]
});
const bSelect = document.getElementById('vpn-history-backend-select');
assert(bSelect && bSelect.children.length === 2, 'backend selector options count');
assert.strictEqual(bSelect.children[0].value, '1');
assert.strictEqual(bSelect.children[1].value, '2');
const bSeries = document.getElementById('vpn-chart-backend-series');
assert(bSeries.textContent.includes('Backend 1'), 'default renders backend 1 series');
bSelect.value = '2';
bSelect.onchange();
assert(bSeries.textContent.includes('Backend 2'), 'onchange re-renders selected backend 2 series');

const qBadgesFrac = document.getElementById('vpn-chart-queue-badges').textContent;
assert(qBadgesFrac.includes('Current: 0.4%'), 'queue fractional formatting: ' + qBadgesFrac);

// Rework Round 5: Time-proportional X-axis
vpnRenderHistoryCharts({
    window_15m: [
        { t: 100, rx_bps: 100, tx_bps: 100, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 10, fwd_p95_samples: 1, backends: [] },
        { t: 125, rx_bps: 200, tx_bps: 200, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 20, fwd_p95_samples: 1, backends: [] },
        { t: 200, rx_bps: 300, tx_bps: 300, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 30, fwd_p95_samples: 1, backends: [] }
    ]
});
const strokeT = document.getElementById('vpn-chart-throughput').innerHTML.match(/<path d="([^"]+)" fill="none"/);
assert(strokeT && strokeT[1].includes('51.0'), 'time-proportional X mapping: ' + strokeT[1]);

// Rework Round 6: Dual-curve latency rendering, mixed window
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 5, fwd_p95_samples: 1, be_p95_ms: 10, be_latency_samples: 1, backends: [] },
        { t: 1700000060, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 20, be_latency_samples: 1, backends: [] },
        { t: 1700000120, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 30, be_latency_samples: 1, backends: [] }
    ]
});
const lBadgesMixed = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesMixed.includes('Write: —') && lBadgesMixed.includes('Probe: 30 ms'), 'mixed window probe current: ' + lBadgesMixed);
assert(lBadgesMixed.includes('Peak: 30 ms (probe)'), 'mixed window peak: ' + lBadgesMixed);
const lChartMixedHTML = document.getElementById('vpn-chart-latency').innerHTML;
const strokeMatches = lChartMixedHTML.match(/<path [^>]*stroke=/g) || [];
assert.strictEqual(strokeMatches.length, 2, 'latency chart renders two stroke paths for both series');

// Rework Round 8: Mixed window with forward write peak
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 100, fwd_p95_samples: 1, be_p95_ms: 20, be_latency_samples: 1, backends: [] },
        { t: 1700000060, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 30, be_latency_samples: 1, backends: [] }
    ]
});
const lBadgesFwdPeak = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesFwdPeak.includes('Write: —') && lBadgesFwdPeak.includes('Probe: 30 ms'), 'mixed window fwd peak current: ' + lBadgesFwdPeak);
assert(lBadgesFwdPeak.includes('Peak: 100 ms (write)'), 'mixed window fwd peak attributed: ' + lBadgesFwdPeak);

// Rework Round 8: Mixed window with probe peak and forward current
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 2, fwd_p95_samples: 1, be_p95_ms: 80, be_latency_samples: 1, backends: [] },
        { t: 1700000060, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 3, fwd_p95_samples: 1, be_p95_ms: 0, be_latency_samples: 0, backends: [] }
    ]
});
const lBadgesProbePeak = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesProbePeak.includes('Write: 3 ms') && lBadgesProbePeak.includes('Probe: —'), 'mixed window probe peak current: ' + lBadgesProbePeak);
assert(lBadgesProbePeak.includes('Peak: 80 ms (probe)'), 'mixed window probe peak attributed: ' + lBadgesProbePeak);

// Rework Round 8: Non-English localization (Russian)
const origWrite = translations.vpn_chart_write;
const origProbe = translations.vpn_chart_probe;
const origPeak = translations.vpn_chart_peak;
const origWriteSuffix = translations.vpn_diag_write_suffix;
const origProbeSuffix = translations.vpn_diag_probe_suffix;
const origUnitMs = translations.vpn_unit_ms;

translations.vpn_chart_write = 'Запись';
translations.vpn_chart_probe = 'Проба';
translations.vpn_chart_peak = 'Пик';
translations.vpn_diag_write_suffix = ' (запись)';
translations.vpn_diag_probe_suffix = ' (проба)';
translations.vpn_unit_ms = 'мс';

vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 3, fwd_p95_samples: 1, be_p95_ms: 20, be_latency_samples: 1, backends: [] }
    ]
});
const lBadgesRu = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesRu.includes('Запись: 3 мс') && lBadgesRu.includes('Проба: 20 мс') && lBadgesRu.includes('Пик: 20 мс (проба)'), 'ru localized dual badges: ' + lBadgesRu);

translations.vpn_chart_write = origWrite;
translations.vpn_chart_probe = origProbe;
translations.vpn_chart_peak = origPeak;
translations.vpn_diag_write_suffix = origWriteSuffix;
translations.vpn_diag_probe_suffix = origProbeSuffix;
translations.vpn_unit_ms = origUnitMs;

// Neither latency available -> no overlay, empty badge
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 0, be_latency_samples: 0, backends: [] }
    ]
});
const lChartNoneHTML = document.getElementById('vpn-chart-latency').innerHTML;
assert(!lChartNoneHTML.includes('chart-overlay'), 'no overlay when neither latency available');
const lBadgesNone = document.getElementById('vpn-chart-latency-badges').textContent;
assert(lBadgesNone.includes('Current: —') && lBadgesNone.includes('Peak: —'), 'neither latency badges empty: ' + lBadgesNone);

// Check legend dot indicators in dual latency badges
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: true, drop_reason_rates: {}, fwd_p95_ms: 5, fwd_p95_samples: 1, be_p95_ms: 10, be_latency_samples: 1, backends: [] }
    ]
});
const lBadgesDots = document.getElementById('vpn-chart-latency-badges').innerHTML;
assert(lBadgesDots.includes('chart-legend-dot'), 'latency badges include legend dot indicators: ' + lBadgesDots);

// Check drop reason suppression when drop_rates_available is false
vpnRenderHistoryCharts({
    window_15m: [
        { t: 1700000000, rx_bps: 0, tx_bps: 0, traffic_available: true, q_pct: 0, drop_rate: 0, drop_rates_available: false, drop_reason_rates: { return_queue_full: 10 }, fwd_p95_ms: 0, fwd_p95_samples: 0, be_p95_ms: 0, be_latency_samples: 0, backends: [] }
    ]
});
assert(document.getElementById('vpn-chart-reasons').textContent.includes('No data (15m)'), 'drop reason with drop_rates_available false is suppressed');
`
		if out, err := execNodeScript(nodePath, script); err != nil {
			t.Fatalf("historical charts JS render contract failed: %v\n%s", err, out)
		}
	})
}
