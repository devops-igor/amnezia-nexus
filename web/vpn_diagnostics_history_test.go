package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func TestVPNHistoryChartLatencyAvailability(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()
	script := fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + `
const assert = require('assert');
const chart = {innerHTML:''};
const document = {getElementById:id => id === 'vpn-chart-latency' ? chart : null};
` + "\n" + fixture.ChartsJS + `
vpnRenderHistoryCharts({window_15m:[
    {fwd_p95_ms:200,fwd_p95_samples:1},
    {fwd_p95_ms:200,fwd_p95_samples:0},
    {fwd_p95_ms:0,fwd_p95_samples:1}
]});
const stroke = chart.innerHTML.match(/<path d="([^"]+)" fill="none"/);
assert(stroke, 'observed latency must remain visible');
assert.strictEqual((stroke[1].match(/M /g) || []).length, 2, 'missing latency must break the line');
assert(!stroke[1].includes(' L '), 'isolated observations must not connect across the gap');
assert(stroke[1].includes('M 2.0 2.0') && stroke[1].includes('M 198.0 38.0'), 'gaps must preserve observation x positions');
assert.strictEqual((chart.innerHTML.match(/<circle /g) || []).length, 2, 'zero and slow observations must both be visible');
vpnRenderHistoryCharts({window_15m:[{fwd_p95_ms:200,fwd_p95_samples:0}]});
assert(chart.innerHTML.includes('No data'), 'idle history must be unavailable');
assert(!chart.innerHTML.includes('<path'), 'unavailable history must not invent zero/slow curves');
vpnRenderHistoryCharts({window_15m:[{fwd_p95_ms:0,fwd_p95_samples:1}]});
assert(!chart.innerHTML.includes('No data'), 'a measured zero is available');
vpnRenderHistoryCharts({window_15m:[{fwd_p95_ms:20}]});
assert(chart.innerHTML.includes('No data'), 'missing observation count is unavailable');
`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("history renderer: %v\n%s", err, out)
	}
}

func TestVPNCompleteRouteTooltipContract(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()

	// Marshal the production schema: a newly populated field cannot silently
	// disappear between the status payload and the complete tooltip.
	route := vpn.ProblemRouteItem{
		PeerKey: "abcd...wxyz", AssignedIP: "192.0.2.8", BackendID: 38,
		Occupancy: 23, Capacity: 100, HighWater: 47, UtilizationPct: 23, HighWaterPct: 47,
		Drops: 17, P95WriteMS: 18, HasPressure: true, PressureNote: "Recent write errors: 19",
		WriteCount: 101, WriteErrors: 19, WriteStalls: 20, WritesInFlight: 21,
		OldestWriteMS: 22, MaxWriteMS: 24, P95WriteSamples: 25, QueueFullDropsRecent: 26,
		QueueFullDropRatePPS: 2.4,
		WriteErrorsRecent:    27, WriteStallsRecent: 28, SessionAgeSec: 29, LastTrafficAgeSec: 30,
		Traffic: forwarder.TrafficSnapshot{RxBytes: 31, TxBytes: 32, RxPackets: 33, TxPackets: 34,
			RxBytesPerSec: 35, TxBytesPerSec: 36, RxPps: 37, TxPps: 39, Available: true, WindowSec: 40},
	}
	encoded, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	script := "const route = " + string(encoded) + ";\n" + vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + "\n" + fixture.HealthSummaryJS + `
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,problem_routes:[route]});
const renderedRouteCells = document.getElementById('vpn-fwd-routes-tbody').children[0].children;
assert.strictEqual(renderedRouteCells[0].style.whiteSpace, 'nowrap', 'peer cell must have white-space: nowrap');
assert.strictEqual(renderedRouteCells[1].style.textAlign, 'right', 'queue cell must have text-align: right');
assert.strictEqual(renderedRouteCells[2].style.textAlign, 'right', 'peak cell must have text-align: right');
assert.strictEqual(renderedRouteCells[3].style.textAlign, 'right', 'drops cell must have text-align: right');
assert.strictEqual(renderedRouteCells[4].style.textAlign, 'right', 'writes cell must have text-align: right');
const title = document.getElementById('vpn-fwd-routes-tbody').children[0].children[0].title;
const labels = {
 peer_key:_('vpn_forwarder_route_peer'),
 assigned_ip:_('vpn_diag_assigned_address'),
 backend_id:_('vpn_diag_backend'),
 occupancy:_('vpn_forwarder_queue'),
 capacity:_('vpn_diag_queue_capacity'),
 high_water:_('vpn_diag_queue_high_water'),
 utilization_pct:_('vpn_diag_queue_utilization'),
 high_water_pct:_('vpn_diag_high_water_pct'),
 drops:_('vpn_diag_queue_drops_cumulative'),
 p95_write_ms:_('vpn_diag_write_p95_historical'),
 has_pressure:_('vpn_diag_current_pressure'),
 pressure_note:_('vpn_diag_pressure_reason'),
 write_count:_('vpn_diag_writes_admitted'),
 write_errors:_('vpn_diag_write_errors_cumulative'),
 write_stalls:_('vpn_diag_write_stalls_cumulative'),
 writes_in_flight:_('vpn_diag_writes_in_flight'),
 oldest_write_ms:_('vpn_diag_oldest_write'),
 max_write_ms:_('vpn_diag_max_write_historical'),
 p95_write_samples:_('vpn_diag_write_samples'),
 queue_full_drops_recent:_('vpn_diag_recent_queue_drops'),
 queue_full_drop_rate_pps:_('vpn_diag_drop_rate'),
 write_errors_recent:_('vpn_diag_recent_write_errors'),
 write_stalls_recent:_('vpn_diag_recent_write_stalls'),
 session_age_sec:_('vpn_diag_session_age'),
 last_traffic_age_sec:_('vpn_diag_last_traffic_age'),
 traffic:_('vpn_diag_directional_traffic')
};
const trafficLabels = {
 rx_bytes:_('vpn_diag_rx_bytes'),
 tx_bytes:_('vpn_diag_tx_bytes'),
 rx_packets:_('vpn_diag_rx_packets'),
 tx_packets:_('vpn_diag_tx_packets'),
 rx_bytes_per_sec:_('vpn_diag_rx_bytes_rate'),
 tx_bytes_per_sec:_('vpn_diag_tx_bytes_rate'),
 rx_pps:_('vpn_diag_rx_packets_rate'),
 tx_pps:_('vpn_diag_tx_packets_rate'),
 available:_('vpn_diag_available'),
 window_sec:_('vpn_diag_window')
};
assert.deepStrictEqual(Object.keys(route).sort(),Object.keys(labels).sort(),'payload/tooltip field contract drifted');
for (const key of Object.keys(route)) {
 if (key === 'traffic') {
  for (const name of Object.keys(route.traffic)) {
   assert(title.includes(_('vpn_diag_directional_traffic')+' '+trafficLabels[name]+': '+route.traffic[name]), name);
  }
 } else assert(title.includes(labels[key]+': '+route[key]),key);
}
route.traffic.available=false; route.last_traffic_age_sec=-1;route.p95_write_samples=0;
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,problem_routes:[route]});
const unknown = document.getElementById('vpn-fwd-routes-tbody').children[0].children[0].title;
assert(unknown.includes('Directional traffic RX bytes/s: Unavailable'));
assert(unknown.includes('Write p95 (historical ms): Unavailable'));
assert(unknown.includes('Last traffic age (s): Unavailable'));
`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("complete route tooltip: %v\n%s", err, out)
	}
}

func TestVPNCompleteHistoryAllWindowRenderers(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()
	data := fixture.TemplateHTML
	for _, id := range []string{"throughput", "queue", "drops", "latency", "reasons", "backends"} {
		if !strings.Contains(data, `id="vpn-chart-`+id+`"`) {
			t.Fatalf("missing history chart %s", id)
		}
	}
	script := vpnDOMMock(t, data) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + "\n" + fixture.ChartsJS + `
const originalSparkline = vpnGenerateSparklineSVG;
const seen=[];
vpnGenerateSparklineSVG = (values,...args) => {seen.push(values);return originalSparkline(values,...args);};
function entry(id,label) {
 const children=document.getElementById(id).children;
 const index=children.findIndex(e=>e.textContent===label+' ('+vpnHistoryWindow+')');
 assert(index>=0,'missing labelled series '+label+' in '+vpnHistoryWindow);
 return children[index+1].innerHTML;
}
const series={};
for (const [i,w] of ['1m','5m','15m','1h','6h','24h'].entries()) {
 const value=i+1;
 series['window_'+w]=[{
  t:100,rx_bps:999,tx_bps:999,rx_pps:999,tx_pps:999,traffic_available:false,
  q_pct:0,drop_rate:999,drop_rates_available:false,
  drop_reason_rates:{return_queue_full:999,client_backend_device_queue_full:999},
  fwd_p95_ms:999,fwd_p95_samples:0,be_p95_ms:999,be_latency_samples:0,sessions:0,routes:0,backends:[]
 },{
  t:110,rx_bps:value,tx_bps:2*value,rx_pps:3*value,tx_pps:4*value,traffic_available:true,
  q_pct:5*value,drop_rate:6*value,drop_rates_available:true,
  drop_reason_rates:{return_queue_full:2*value,client_backend_device_queue_full:4*value},
  fwd_p95_ms:7*value,fwd_p95_samples:1,be_p95_ms:8*value,be_latency_samples:1,sessions:9*value,routes:10*value,
  backends:[{id:3,rx_bps:11*value,tx_bps:12*value,rx_pps:13*value,tx_pps:14*value,
   traffic_available:true,probe_latency_ms:15*value,probe_available:true,routable:true}]
 },{
  t:120,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0,traffic_available:true,q_pct:0,drop_rate:0,
  drop_rates_available:true,drop_reason_rates:{return_queue_full:0,client_backend_device_queue_full:0},
  fwd_p95_ms:0,fwd_p95_samples:1,be_p95_ms:0,be_latency_samples:0,sessions:0,routes:0,
  backends:[{id:3,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0,traffic_available:true,probe_available:false}]
 }];
}
for (const [i,w] of ['1m','5m','15m','1h','6h','24h'].entries()) {
 vpnHistoryWindow=w;seen.length=0;vpnRenderHistoryCharts(series);
 const v=i+1;
 assert.deepStrictEqual(seen.slice(0,3),[[null,3*v,0],[0,5*v,0],[null,6*v,0]]);
 assert.deepStrictEqual(seen[3],[
  { data: [null,7*v,0], color: 'var(--info, #06b6d4)', fillOpacity: 0.12 },
  { data: [null,8*v,null], color: '#a855f7', fillOpacity: 0.12 }
 ]);
 assert.deepStrictEqual(seen.slice(4),[[null,4*v,0],[null,2*v,0],[null,11*v,0],[null,12*v,0],[null,13*v,0],[null,14*v,0],[null,15*v,null]]);
 for (const [id,label] of [
  ['vpn-chart-reasons','return queue full (drops/s)'],['vpn-chart-reasons','client backend device queue full (drops/s)'],
  ['vpn-chart-backend-series','Backend 3 RX (bps)'],['vpn-chart-backend-series','Backend 3 TX (bps)'],
  ['vpn-chart-backend-series','Backend 3 RX packets/s'],['vpn-chart-backend-series','Backend 3 TX packets/s'],
  ['vpn-chart-backend-series','Backend 3 Probe latency (ms)']
 ]) assert(entry(id,label).includes('<svg'),label);
}
vpnHistoryWindow='15m';
vpnRenderHistoryCharts({window_15m:[]});
assert(document.getElementById('vpn-chart-reasons').textContent.includes('No data (15m)'), 'empty reason window must remain visible');
assert(document.getElementById('vpn-chart-backends').textContent.includes('No data (15m)'), 'empty fleet window must remain visible');
vpnRenderHistoryCharts({window_15m:[series.window_15m[0]]});
assert(document.getElementById('vpn-chart-backends').textContent.includes('No data (15m)'), 'pre-provision fleet context must remain visible');
assert(document.getElementById('vpn-chart-throughput').innerHTML.includes('No data'));
assert(document.getElementById('vpn-chart-drops').innerHTML.includes('No data'));
assert(document.getElementById('vpn-chart-reasons').textContent.includes('No data (15m)'), 'unavailable reasons show empty state rather than ghost sparkline');
// Retired/re-registered backend IDs form gaps, never zero-filled continuity.
vpnRenderHistoryCharts({window_15m:[
 {backends:[{id:3,rx_bps:10,traffic_available:true}]},{backends:[]},
 {backends:[{id:3,rx_bps:0,traffic_available:true}]}
]});
const gap=entry('vpn-chart-backend-series','Backend 3 RX (bps)');
assert.strictEqual((gap.match(/<circle /g)||[]).length,2);
const gapStroke=gap.match(/<path d="([^"]+)" fill="none"/);
assert(gapStroke && !gapStroke[1].includes(' L '),'isolated backend samples must not bridge lifecycle gap');
vpnRenderHistoryCharts({window_15m:[{backends:Array.from({length:129},(_,id)=>({id})),backends_omitted:5}]});
assert.strictEqual(document.getElementById('vpn-history-backend-select').children.length,128,'fleet churn selector must remain bounded');
assert.strictEqual(document.getElementById('vpn-chart-backend-series').children.length,5*2,'only selected backend series are rendered');
assert(document.getElementById('vpn-history-fleet-note').textContent.includes('5 omitted'));
`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("complete history renderers: %v\n%s", err, out)
	}
}

// An unavailable forwarder must erase every rendered history surface. The
// history render path produces two DOM shapes (injected SVG markup in the four
// sparkline containers, appended element children in the renderSeries
// containers), so seeding real stale state and then asserting both shapes are
// empty is what makes this regression meaningful. Starting from empty
// containers would prove nothing.
func TestVPNUnavailableForwarderClearsStaleHistoryState(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()

	for _, id := range []string{
		"vpn-chart-throughput", "vpn-chart-queue", "vpn-chart-latency",
		"vpn-chart-drops", "vpn-chart-reasons", "vpn-chart-backends",
		"vpn-diag-be-traffic", "vpn-history-fleet-note",
	} {
		if !strings.Contains(fixture.TemplateHTML, `id="`+id+`"`) {
			t.Fatalf("missing stale-clearing target %s", id)
		}
	}
	toggleRoutes, err := extractJSFunction(fixture.CombinedSource(), "function vpnToggleShowAllRoutes")
	if err != nil {
		t.Fatal(err)
	}
	script := vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + "\n" + fixture.HealthSummaryJS + "\n" + fixture.ChartsJS + "\n" + toggleRoutes + `
let vpnLastStatus=null;
let vpnShowAllRoutes=false;
// The window-toggle control is a persistent button group with no stale data
// of its own; the mock only needs it to answer a querySelectorAll probe.
document.getElementById('vpn-history-window-toggles').querySelectorAll=()=>[];
const SVG_CHARTS=['vpn-chart-throughput','vpn-chart-queue','vpn-chart-drops','vpn-chart-latency'];
const SERIES_CHARTS=['vpn-chart-reasons','vpn-chart-backends'];
// Seed realistic stale state: measured series render SVG into the sparkline
// containers and label/child pairs into the renderSeries containers.
vpnRenderHistoryCharts({window_15m:[
 {t:100,rx_bps:900,tx_bps:900,rx_pps:90,tx_pps:90,traffic_available:true,q_pct:12,drop_rate:3,
  drop_rates_available:true,drop_reason_rates:{return_queue_full:3},fwd_p95_ms:41,fwd_p95_samples:1,
  be_p95_ms:33,be_latency_samples:1,sessions:4,routes:3,backends_omitted:5,
  backends:[{id:3,rx_bps:900,tx_bps:900,rx_pps:90,tx_pps:90,traffic_available:true,probe_latency_ms:33,probe_available:true}]},
 {t:160,rx_bps:1200,tx_bps:1200,rx_pps:120,tx_pps:120,traffic_available:true,q_pct:18,drop_rate:4,
  drop_rates_available:true,drop_reason_rates:{return_queue_full:4},fwd_p95_ms:52,fwd_p95_samples:1,
  be_p95_ms:44,be_latency_samples:1,sessions:6,routes:5,backends_omitted:5,
  backends:[{id:3,rx_bps:1200,tx_bps:1200,rx_pps:120,tx_pps:120,traffic_available:true,probe_latency_ms:44,probe_available:true}]}
]});
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,
	health_assessment: {status: 'HEALTHY', summary: 'Operational forwarding', conditions: []},
	rates: {available: true, rx_bps: 1000000, tx_bps: 0, rx_pps: 50, tx_pps: 0},
	all_routes: [{peer_key: 'peer12345678', capacity: 100, occupancy: 0, drops: 0, has_pressure: false}],
	problem_routes: [],
	historical_series:{window_15m:[
  {t:100,rx_bps:900,tx_bps:900,traffic_available:true,q_pct:12,drop_rate:3,drop_rates_available:true,
   drop_reason_rates:{return_queue_full:3},fwd_p95_ms:41,fwd_p95_samples:1,be_p95_ms:33,be_latency_samples:1,
   sessions:4,routes:3,backends_omitted:5,
   backends:[{id:3,rx_bps:900,tx_bps:900,traffic_available:true,probe_latency_ms:33,probe_available:true}]},
  {t:160,rx_bps:1200,tx_bps:1200,traffic_available:true,q_pct:18,drop_rate:4,drop_rates_available:true,
   drop_reason_rates:{return_queue_full:4},fwd_p95_ms:52,fwd_p95_samples:1,be_p95_ms:44,be_latency_samples:1,
   sessions:6,routes:5,backends_omitted:5,
   backends:[{id:3,rx_bps:1200,tx_bps:1200,traffic_available:true,probe_latency_ms:44,probe_available:true}]}
 ]},
 backends:{backends:[
 {server_name:'Server 1',enabled:true,health_state:'active',traffic_available:true,
  rx_bytes_per_sec:900,tx_bytes_per_sec:1200,rx_pps:90,tx_pps:120}
 ]}});
// The available poll must cache a real series, otherwise the toggles below
// have nothing to resurrect and the cache-clearing guard would go untested.
assert(vpnLastStatus&&vpnLastStatus.historical_series,'available poll must cache its series');
assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent,_('vpn_forwarder_healthy'),'available poll must render Healthy');
assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent,'1.00 Mbps / 50.0 pps','available poll must render throughput');
for (const id of SVG_CHARTS) {
 assert(document.getElementById(id).innerHTML.includes('<svg'),'seed must render SVG in '+id);
}
for (const id of SERIES_CHARTS) {
 assert(document.getElementById(id).children.length>0,'seed must render series children in '+id);
}
assert(document.getElementById('vpn-diag-be-traffic').children.length>0,'seed must render backend traffic rows');
assert(document.getElementById('vpn-history-fleet-note').textContent.length>0,'seed must render the fleet note');

// The transition under test.
vpnRenderForwarderHealth({forwarder_available:false});
for (const id of SVG_CHARTS) {
 const el=document.getElementById(id);
 assert(!el.innerHTML.includes('<svg'),'stale SVG remains in '+id);
 assert(!el.innerHTML.includes('<path'),'stale curve remains in '+id);
 assert.strictEqual(el.innerHTML,'','sparkline container must be emptied in '+id);
 assert.strictEqual(el.textContent,'','sparkline container text must be emptied in '+id);
}
for (const id of SERIES_CHARTS) {
 const el=document.getElementById(id);
 assert.strictEqual(el.children.length,0,'stale series children remain in '+id);
 assert.strictEqual(el.textContent,'','series container text must be emptied in '+id);
 assert(!el.innerHTML.includes('<svg'),'no placeholder SVG may be injected into '+id);
}
const beTraffic=document.getElementById('vpn-diag-be-traffic');
assert.strictEqual(beTraffic.children.length,0,'backend traffic rows must be cleared');
assert.strictEqual(beTraffic.textContent,'','backend traffic text must be cleared');
const fleetNote=document.getElementById('vpn-history-fleet-note');
assert.strictEqual(fleetNote.textContent,'','fleet omission note must be cleared');
assert.strictEqual(fleetNote.innerHTML,'','fleet omission note markup must be cleared');
// No invented data anywhere in the unavailable state.
for (const id of SVG_CHARTS.concat(SERIES_CHARTS).concat(['vpn-diag-be-traffic','vpn-history-fleet-note'])) {
 const el=document.getElementById(id);
 assert(!el.innerHTML.includes('<path'),'unavailable state must not invent curves in '+id);
 assert(!el.innerHTML.includes('<circle'),'unavailable state must not invent points in '+id);
}
const ALL_KPIS = [
 'vpn-kpi-throughput', 'vpn-kpi-routes-sessions', 'vpn-kpi-queue-pressure',
 'vpn-kpi-packet-loss', 'vpn-kpi-client-engine', 'vpn-kpi-peer-sync',
 'vpn-kpi-backends', 'vpn-kpi-slow-writes'
];
const DETAIL_PANEL_IDS = [
 'vpn-diag-throughput', 'vpn-diag-ewma5m', 'vpn-diag-ewma1h',
 'vpn-diag-queue-occ', 'vpn-diag-queue-peak',
 'vpn-diag-lat-percentiles', 'vpn-diag-lat-max',
 'vpn-diag-drops-client', 'vpn-diag-drops-return', 'vpn-diag-drops-total',
 'vpn-diag-engine-status', 'vpn-diag-peers-status', 'vpn-diag-hs-freshness',
 'vpn-diag-routing-counts', 'vpn-diag-res-cpu', 'vpn-diag-res-mem', 'vpn-diag-res-fd'
];

function assertAllSurfacesCleared(context) {
 assert.strictEqual(document.getElementById('vpn-fwd-status-badge').className, 'badge', context + ': status badge className');
 assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent, _('vpn_forwarder_unavailable'), context + ': status text');
 assert.strictEqual(document.getElementById('vpn-fwd-headline-summary').textContent, _('vpn_forwarder_unavailable'), context + ': headline');
 const problemList = document.getElementById('vpn-fwd-problem-list');
 assert.strictEqual(problemList.textContent, '', context + ': problem list text');
 assert.strictEqual(problemList.style.display, 'none', context + ': problem list display');

 for (const id of ALL_KPIS) {
  assert.strictEqual(document.getElementById(id).textContent, '-', context + ': KPI ' + id);
 }
 for (const id of DETAIL_PANEL_IDS) {
  assert.strictEqual(document.getElementById(id).textContent, '-', context + ': detail elem ' + id);
 }

 const routBadge = document.getElementById('vpn-diag-routing-badge');
 assert.strictEqual(routBadge.className, 'badge', context + ': routing badge className');
 assert.strictEqual(routBadge.textContent, '-', context + ': routing badge text');
 const routAlerts = document.getElementById('vpn-diag-routing-alerts');
 assert.strictEqual(routAlerts.textContent, '', context + ': routing alerts text');
 assert.strictEqual(routAlerts.style.display, 'none', context + ': routing alerts display');

 assert.strictEqual(document.getElementById('vpn-diag-be-traffic').children.length, 0, context + ': backend traffic rows');
 assert.strictEqual(document.getElementById('vpn-history-fleet-note').textContent, '', context + ': fleet note text');
 assert.strictEqual(document.getElementById('vpn-history-fleet-note').innerHTML, '', context + ': fleet note markup');

 for (const id of SVG_CHARTS) {
  const el = document.getElementById(id);
  assert.strictEqual(el.innerHTML, '', context + ': sparkline markup in ' + id);
  assert.strictEqual(el.textContent, '', context + ': sparkline text in ' + id);
 }
 for (const id of SERIES_CHARTS) {
  const el = document.getElementById(id);
  assert.strictEqual(el.children.length, 0, context + ': series children in ' + id);
  assert.strictEqual(el.textContent, '', context + ': series text in ' + id);
 }
}

assertAllSurfacesCleared('immediately after forwarder_available: false');

// The cleared state must be terminal: toggling the route filter or switching
// history windows without a new poll must NOT resurrect stale available diagnostics.
vpnToggleShowAllRoutes(); // Toggle 1: show all routes
assertAllSurfacesCleared('after route toggle 1');

vpnToggleShowAllRoutes(); // Toggle 2: show problem routes only
assertAllSurfacesCleared('after route toggle 2');

for (const w of ['1h', '6h', '24h', '15m']) {
 vpnSetHistoryWindow(w);
 assertAllSurfacesCleared('after switching history window to ' + w);
}

// Deliver a fresh available response and verify live data returns cleanly.
const freshAvailableStatus = {
 forwarder_available: true,
 forwarder_queue_capacity: 200,
 listener_running: true,
 health_assessment: { status: 'HEALTHY', summary: 'Operational forwarding restored', conditions: [] },
 rates: { available: true, rx_bps: 2000000, tx_bps: 0, rx_pps: 100, tx_pps: 0 },
 all_routes: [{ peer_key: 'peer87654321', capacity: 200, occupancy: 5, drops: 0, has_pressure: false }],
 problem_routes: [],
 historical_series: {
  window_15m: [
   { t: 200, rx_bps: 2000, tx_bps: 2000, traffic_available: true, q_pct: 10, drop_rate: 1, drop_rates_available: true,
     drop_reason_rates: { return_queue_full: 1 }, fwd_p95_ms: 30, fwd_p95_samples: 1, be_p95_ms: 25, be_latency_samples: 1,
     sessions: 2, routes: 1, backends_omitted: 0,
     backends: [{ id: 4, rx_bps: 2000, tx_bps: 2000, traffic_available: true, probe_latency_ms: 25, probe_available: true }] }
  ]
 },
 backends: {
  backends: [
   { server_name: 'Server 2', enabled: true, health_state: 'active', traffic_available: true,
     rx_bytes_per_sec: 2000, tx_bytes_per_sec: 2000, rx_pps: 100, tx_pps: 100 }
  ]
 }
};
vpnRenderForwarderHealth(freshAvailableStatus);
assert(vpnLastStatus && vpnLastStatus.historical_series, 'fresh poll must cache status');
assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent, _('vpn_forwarder_healthy'), 'fresh poll restores Healthy');
assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent, '2.00 Mbps / 100.0 pps', 'fresh poll restores throughput');
assert.strictEqual(document.getElementById('vpn-diag-be-traffic').children.length, 1, 'fresh poll restores backend rows');
for (const id of SVG_CHARTS) assert(document.getElementById(id).innerHTML.includes('<svg'), 'fresh poll restores SVG in ' + id);
for (const id of SERIES_CHARTS) assert(document.getElementById(id).children.length > 0, 'fresh poll restores series in ' + id);

// Sequence 2: Polling error response (null status) must also invalidate cache
// and not resurrect on local toggles.
vpnRenderForwarderHealth(null);
assertAllSurfacesCleared('after null polling failure');

vpnToggleShowAllRoutes();
assertAllSurfacesCleared('after null route toggle 1');
vpnToggleShowAllRoutes();
assertAllSurfacesCleared('after null route toggle 2');
vpnSetHistoryWindow('1h');
assertAllSurfacesCleared('after null window 1h');
vpnSetHistoryWindow('15m');
assertAllSurfacesCleared('after null window 15m');

// Recovery from null status when live poll succeeds
vpnRenderForwarderHealth(freshAvailableStatus);
assert.strictEqual(document.getElementById('vpn-fwd-status-text').textContent, _('vpn_forwarder_healthy'), 'recovery after null poll');
assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent, '2.00 Mbps / 100.0 pps', 'recovery throughput after null poll');
assert.strictEqual(document.getElementById('vpn-diag-be-traffic').children.length, 1, 'recovery backend rows after null poll');

`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("unavailable-forwarder history clearing: %v\n%s", err, out)
	}
}

func TestVPNPanelRateAvailability(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireNode()
	script := vpnDOMMock(t, fixture.TemplateHTML) + "\n" + fixture.TranslationsJS("en") + "\n" + fixture.HealthProblemsJS + "\n" + fixture.HealthSummaryJS + `
let vpnLastStatus = null;
let vpnShowAllRoutes = false;

// 1. Both rate flags false: detail panels must show explicit unavailable text, NOT measured zero.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: false, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0, rx_bps_avg_5m: 0, tx_bps_avg_5m: 0, rx_bps_avg_1h: 0, tx_bps_avg_1h: 0 },
	drop_categories: { rates_available: false, client_drop_rate_pps: 0, client_total_drops: 12, return_drop_rate_pps: 0, return_total_drops: 34, total_drop_rate_pps: 0, total_drops: 46 }
});

assert.strictEqual(document.getElementById('vpn-kpi-throughput').textContent, 'Traffic unavailable', 'KPI throughput must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Traffic unavailable', 'detail throughput must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Traffic unavailable', 'detail ewma5m must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Traffic unavailable', 'detail ewma1h must be unavailable');

assert.strictEqual(document.getElementById('vpn-kpi-packet-loss').textContent, 'Loss rate unavailable (46 cumulative)', 'KPI loss must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, 'Loss rate unavailable (12 cumulative)', 'detail client drops must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, 'Loss rate unavailable (34 cumulative)', 'detail return drops must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, 'Loss rate unavailable (46 cumulative)', 'detail total drops must be unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').style.color, '', 'unavailable client drop rate must not be colored danger');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').style.color, '', 'unavailable return drop rate must not be colored danger');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').style.color, '', 'unavailable total drop rate must not be colored danger');

// 2. Independent flags: Traffic unavailable, Loss available (legitimate idle zero loss).
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: false, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0 },
	drop_categories: { rates_available: true, client_drop_rate_pps: 0, client_total_drops: 5, return_drop_rate_pps: 0, return_total_drops: 2, total_drop_rate_pps: 0, total_drops: 7 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, '0.00 pps (5 cumulative)', 'available zero client loss must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, '0.00 pps (2 cumulative)', 'available zero return loss must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, '0.00 pps (7 cumulative)', 'available zero total loss must show measured rate');
assert.strictEqual(document.getElementById('vpn-kpi-packet-loss').textContent, '0.00 pps (7 cumulative)');

// 3. Independent flags: Traffic available (legitimate idle zero), Loss unavailable.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: true, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0, rx_bps_avg_5m: 0, tx_bps_avg_5m: 0, rx_bps_avg_1h: 0, tx_bps_avg_1h: 0 },
	drop_categories: { rates_available: false, client_drop_rate_pps: 0, client_total_drops: 0, return_drop_rate_pps: 0, return_total_drops: 0, total_drop_rate_pps: 0, total_drops: 0 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Rx: 0 bps | Tx: 0 bps', 'available zero traffic must show measured rate');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Rx: 0 bps | Tx: 0 bps');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Rx: 0 bps | Tx: 0 bps');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, 'Loss rate unavailable (0 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, 'Loss rate unavailable (0 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, 'Loss rate unavailable (0 cumulative)');

// 4. Positive measured rates retain formatting and danger highlight.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: true, rx_bps: 1000000, tx_bps: 500000, rx_pps: 100, tx_pps: 50, rx_bps_avg_5m: 800000, tx_bps_avg_5m: 400000, rx_bps_avg_1h: 600000, tx_bps_avg_1h: 300000 },
	drop_categories: { rates_available: true, client_drop_rate_pps: 2.5, client_total_drops: 10, return_drop_rate_pps: 1.0, return_total_drops: 4, total_drop_rate_pps: 3.5, total_drops: 14 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Rx: 1.00 Mbps | Tx: 500.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Rx: 800.00 Kbps | Tx: 400.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Rx: 600.00 Kbps | Tx: 300.00 Kbps');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, '2.50 pps (10 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').style.color, 'var(--danger)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, '1.00 pps (4 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').style.color, 'var(--danger)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, '3.50 pps (14 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').style.color, 'var(--danger)');

// 5. False availability dominates placeholder numeric values in payload.
vpnRenderForwarderHealth({
	forwarder_available: true,
	forwarder_queue_capacity: 100,
	rates: { available: false, rx_bps: 999999, tx_bps: 999999, rx_pps: 999, tx_pps: 999, rx_bps_avg_5m: 999999, tx_bps_avg_5m: 999999, rx_bps_avg_1h: 999999, tx_bps_avg_1h: 999999 },
	drop_categories: { rates_available: false, client_drop_rate_pps: 99.9, client_total_drops: 5, return_drop_rate_pps: 99.9, return_total_drops: 5, total_drop_rate_pps: 199.8, total_drops: 10 }
});
assert.strictEqual(document.getElementById('vpn-diag-throughput').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma5m').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-ewma1h').textContent, 'Traffic unavailable');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').textContent, 'Loss rate unavailable (5 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-return').textContent, 'Loss rate unavailable (5 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-total').textContent, 'Loss rate unavailable (10 cumulative)');
assert.strictEqual(document.getElementById('vpn-diag-drops-client').style.color, '');


`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("panel rate availability: %v\n%s", err, out)
	}
}

func TestVPNHorizonWindowToggles1mAnd5m(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	node := fixture.RequireNode()
	tmplStr := fixture.TemplateHTML

	for _, expectedBtn := range []string{
		`onclick="vpnSetHistoryWindow('1m')"`,
		`onclick="vpnSetHistoryWindow('5m')"`,
		`onclick="vpnSetHistoryWindow('15m')"`,
		`onclick="vpnSetHistoryWindow('1h')"`,
		`onclick="vpnSetHistoryWindow('6h')"`,
		`onclick="vpnSetHistoryWindow('24h')"`,
	} {
		if !strings.Contains(tmplStr, expectedBtn) {
			t.Fatalf("vpn.html missing toggle button %s", expectedBtn)
		}
	}

	assertions := `
const toggles = document.getElementById('vpn-history-window-toggles');
assert(toggles, 'toggles container must exist');
toggles.children = ['1m', '5m', '15m', '1h', '6h', '24h'].map(w => {
    const btn = document.createElement('button');
    btn.textContent = w;
    btn.className = w === '15m' ? 'btn btn-sm btn-primary active' : 'btn btn-sm btn-secondary';
    return btn;
});
toggles.querySelectorAll = (sel) => sel === 'button' ? toggles.children : [];
const buttons = Array.from(toggles.querySelectorAll('button'));
const btn1m = buttons.find(b => b.textContent.trim() === '1m');
const btn5m = buttons.find(b => b.textContent.trim() === '5m');
const btn15m = buttons.find(b => b.textContent.trim() === '15m');

assert(btn1m, '1m button must exist');
assert(btn5m, '5m button must exist');
assert(btn15m, '15m button must exist');

const mockSeries = {
    window_1m: [
        { traffic_available: true, rx_bps: 1000, tx_bps: 2000, q_pct: 10, drop_rates_available: true, drop_rate: 1 },
        { traffic_available: true, rx_bps: 1100, tx_bps: 2200, q_pct: 12, drop_rates_available: true, drop_rate: 0 }
    ],
    window_5m: [
        { traffic_available: true, rx_bps: 5000, tx_bps: 6000, q_pct: 50, drop_rates_available: true, drop_rate: 5 },
        { traffic_available: true, rx_bps: 5500, tx_bps: 6500, q_pct: 55, drop_rates_available: true, drop_rate: 2 }
    ],
    window_15m: [
        { traffic_available: true, rx_bps: 15000, tx_bps: 16000, q_pct: 30, drop_rates_available: true, drop_rate: 0 }
    ]
};

vpnLastStatus = {
    forwarder_available: true,
    historical_series: mockSeries
};

const originalSparkline = vpnGenerateSparklineSVG;
const seen = [];
vpnGenerateSparklineSVG = (values, ...args) => {
    seen.push(values);
    return originalSparkline(values, ...args);
};

// 1. Click 1m horizon button
seen.length = 0;
vpnSetHistoryWindow('1m');
assert(btn1m.className.includes('btn-primary'), '1m button must be primary when active');
assert(btn1m.className.includes('active'), '1m button must have active class');
assert(!btn5m.className.includes('btn-primary'), '5m button must not be primary');
assert(!btn15m.className.includes('btn-primary'), '15m button must not be primary');
assert.strictEqual(vpnHistoryWindow, '1m', 'vpnHistoryWindow must be 1m');
// Verify points loaded from window_1m: throughput is (1000+2000) = 3000, (1100+2200) = 3300
assert.deepStrictEqual(seen[0], [3000, 3300], 'throughput chart must load window_1m points');

// 2. Click 5m horizon button
seen.length = 0;
vpnSetHistoryWindow('5m');
assert(btn5m.className.includes('btn-primary'), '5m button must be primary when active');
assert(btn5m.className.includes('active'), '5m button must have active class');
assert(!btn1m.className.includes('btn-primary'), '1m button must not be primary');
assert(!btn15m.className.includes('btn-primary'), '15m button must not be primary');
assert.strictEqual(vpnHistoryWindow, '5m', 'vpnHistoryWindow must be 5m');
// Verify points loaded from window_5m: throughput is (5000+6000) = 11000, (5500+6500) = 12000
assert.deepStrictEqual(seen[0], [11000, 12000], 'throughput chart must load window_5m points');
`

	script := vpnDOMMock(t, tmplStr) + "\n" + vpnDiagnosticsTranslationsJS(t, "en")
	script += "\n" + fixture.HealthProblemsJS + "\n" + fixture.ChartsJS
	script += "\nlet vpnLastStatus = null;\n" + assertions

	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("1m and 5m horizon window toggles test failed: %v\n%s", err, out)
	}
}

func TestVPNHistoricalChartsHoverPreservedAcrossRerender(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	nodePath := fixture.RequireJSDOM()

	testScript := fixture.BuildJSDOMHarness(JSDOMHarnessOptions{
		ExtraJS: `
(() => {
    const ids = ['throughput', 'queue', 'drops', 'latency'].map(x => 'vpn-chart-' + x);
    for (const id of ids) {
        const el = w.document.getElementById(id);
        assert(el, 'chart container ' + id + ' must exist in DOM');
        el.getBoundingClientRect = () => ({ width: 200, left: 0, top: 0, height: 40 });
    }

    const tooltip = w.document.getElementById('vpn-chart-tooltip');
    assert(tooltip, 'vpn-chart-tooltip must exist in DOM');

    const point = {
        t: 36000,
        traffic_available: true,
        rx_bps: 8000,
        tx_bps: 8000,
        q_pct: 10,
        drop_rates_available: true,
        drop_rate: 2,
        fwd_p95_ms: 5,
        fwd_p95_samples: 1,
        be_p95_ms: 8,
        be_latency_samples: 1
    };

    const initialSeries = {
        window_15m: [point, { ...point, t: 36060 }]
    };

    // 1. Initial render
    w.vpnRenderHistoryCharts(initialSeries);

    // 2. Test hover retention and detached listener cleanup across all 4 charts
    for (const id of ids) {
        const el = w.document.getElementById(id);
        const overlay = el.querySelector('.chart-overlay');
        assert(overlay, 'chart ' + id + ' must have .chart-overlay');

        // Dispatch real mousemove event
        overlay.dispatchEvent(new w.MouseEvent('mousemove', { clientX: 100, clientY: 70 }));

        // Assert window._vpnActiveChartHover coordinates are recorded and tooltip displayed
        assert(w._vpnActiveChartHover, 'window._vpnActiveChartHover must be recorded');
        assert.strictEqual(w._vpnActiveChartHover.chartId, id);
        assert.strictEqual(w._vpnActiveChartHover.clientX, 100);
        assert.strictEqual(w._vpnActiveChartHover.clientY, 70);
        assert.strictEqual(tooltip.style.display, 'block', 'tooltip must be displayed on hover');
        assert.strictEqual(tooltip.style.left, '112px', 'tooltip left position must match hover clientX + 12');
        assert.strictEqual(tooltip.style.top, '35px', 'tooltip top position must match hover clientY - 35');
        assert.strictEqual(el.querySelector('.chart-crosshair').style.display, 'block', 'crosshair must be visible');

        const hoverSnapshot = JSON.stringify(w._vpnActiveChartHover);

        // 3. Rerender with updated series data (simulating a 5s live polling sweep)
        const updatedSeries = {
            window_15m: [point, { ...point, t: 36060 }, { ...point, t: 36065, rx_bps: 9000, tx_bps: 9500 }]
        };
        const oldOverlay = overlay;
        w.vpnRenderHistoryCharts(updatedSeries);

        // Assert hover coordinates and tooltip position are restored
        assert.strictEqual(JSON.stringify(w._vpnActiveChartHover), hoverSnapshot, 'hover coordinates must be restored after rerender');
        assert.strictEqual(tooltip.style.display, 'block', 'tooltip must remain displayed after rerender');
        assert.strictEqual(tooltip.style.left, '112px', 'tooltip left position must remain preserved');
        assert.strictEqual(tooltip.style.top, '35px', 'tooltip top position must remain preserved');
        assert.strictEqual(el.querySelector('.chart-crosshair').style.display, 'block', 'crosshair must remain visible after rerender');

        // 4. Verify detached listeners do not accumulate
        assert.strictEqual(oldOverlay._vpnMouseMove, null, 'detached overlay _vpnMouseMove must be cleaned up');
        assert.strictEqual(oldOverlay._vpnMouseLeave, null, 'detached overlay _vpnMouseLeave must be cleaned up');

        // Old overlay event dispatch must not affect active hover state
        oldOverlay.dispatchEvent(new w.MouseEvent('mouseleave'));
        assert.strictEqual(JSON.stringify(w._vpnActiveChartHover), hoverSnapshot, 'dispatching on detached overlay must not clear hover');
        oldOverlay.dispatchEvent(new w.MouseEvent('mousemove', { clientX: 10, clientY: 10 }));
        assert.strictEqual(JSON.stringify(w._vpnActiveChartHover), hoverSnapshot, 'dispatching on detached overlay must not alter hover');

        // Clear hover via mouseleave on the new overlay before next chart iteration
        el.querySelector('.chart-overlay').dispatchEvent(new w.MouseEvent('mouseleave'));
        assert.strictEqual(w._vpnActiveChartHover, null, 'mouseleave on active overlay must clear hover');
        assert.strictEqual(tooltip.style.display, 'none', 'tooltip must hide after mouseleave');
    }

    // 5. Test vpnDisposeChartInteractions lifecycle
    w.vpnRenderHistoryCharts(initialSeries);
    const throughputOverlay = w.document.querySelector('#vpn-chart-throughput .chart-overlay');
    throughputOverlay.dispatchEvent(new w.MouseEvent('mousemove', { clientX: 120, clientY: 60 }));
    assert(w._vpnActiveChartHover, 'active hover must be set');
    const hoverToPreserve = JSON.stringify(w._vpnActiveChartHover);

    // Verify vpnDisposeChartInteractions(false) preserves hover coordinates
    w.vpnDisposeChartInteractions(false);
    assert.strictEqual(JSON.stringify(w._vpnActiveChartHover), hoverToPreserve, 'vpnDisposeChartInteractions(false) must preserve hover');
    for (const id of ids) {
        assert.strictEqual(w.document.getElementById(id)._vpnCleanup, null, '_vpnCleanup should be null after dispose');
    }

    // Verify vpnDisposeChartInteractions(true) clears window._vpnActiveChartHover and hides tooltip
    w.vpnDisposeChartInteractions(true);
    assert.strictEqual(w._vpnActiveChartHover, null, 'vpnDisposeChartInteractions(true) must clear active hover');
    assert.strictEqual(tooltip.style.display, 'none', 'vpnDisposeChartInteractions(true) must hide tooltip');

    // Repeated call should remain safe and clean
    w.vpnDisposeChartInteractions(true);
    assert.strictEqual(w._vpnActiveChartHover, null);

    console.log('HOVER_LIFECYCLE_TEST_PASS');
})();
`,
	})

	out, err := execNodeScript(nodePath, testScript)
	if err != nil {
		t.Fatalf("hover lifecycle test failed: %v\nOutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "HOVER_LIFECYCLE_TEST_PASS") {
		t.Fatalf("expected HOVER_LIFECYCLE_TEST_PASS, got:\n%s", string(out))
	}
}
