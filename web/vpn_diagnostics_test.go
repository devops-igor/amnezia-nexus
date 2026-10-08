package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

func findNodeBinary() (string, error) {
	if p, err := exec.LookPath("node"); err == nil {
		return p, nil
	}
	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".local", "bin", "node"),
		"/usr/local/bin/node",
		"/usr/bin/node",
		"/bin/node",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("node binary not found in PATH or standard locations")
}

func execNodeScript(nodePath, script string) ([]byte, error) {
	cmd := exec.Command(nodePath)
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

func extractJSFunction(source, funcName string) (string, error) {
	startIdx := strings.Index(source, funcName)
	if startIdx == -1 {
		return "", fmt.Errorf("function %s not found in source", funcName)
	}
	braceStart := strings.Index(source[startIdx:], "{")
	if braceStart == -1 {
		return "", fmt.Errorf("opening brace for %s not found", funcName)
	}
	braceStart += startIdx
	depth := 1
	idx := braceStart + 1
	for idx < len(source) && depth > 0 {
		if source[idx] == '{' {
			depth++
		} else if source[idx] == '}' {
			depth--
		}
		idx++
	}
	if depth != 0 {
		return "", fmt.Errorf("unbalanced braces in function %s", funcName)
	}
	return source[startIdx:idx], nil
}

func TestVPNDiagnosticsHealthAndStructure(t *testing.T) {
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatalf("GetTemplatesSubFS failed: %v", err)
	}
	vpnData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatalf("failed to read vpn.html: %v", err)
	}
	vpnStr := string(vpnData)

	t.Run("RequiredDOMElements", func(t *testing.T) {
		requiredIDs := []string{
			"vpn-fwd-headline-summary",
			"vpn-fwd-problem-list",
			"vpn-fwd-tech-details",
			"vpn-kpi-throughput",
			"vpn-kpi-routes-sessions",
			"vpn-kpi-queue-pressure",
			"vpn-kpi-packet-loss",
			"vpn-kpi-client-engine",
			"vpn-kpi-peer-sync",
			"vpn-kpi-backends",
			"vpn-kpi-slow-writes",
			"vpn-diag-throughput",
			"vpn-diag-packets",
			"vpn-diag-ewma5m",
			"vpn-diag-ewma1h",
			"vpn-diag-queue-occ",
			"vpn-diag-queue-peak",
			"vpn-diag-queue-dur50",
			"vpn-diag-queue-dur80",
			"vpn-diag-queue-drops",
			"vpn-diag-lat-percentiles",
			"vpn-diag-lat-max",
			"vpn-diag-lat-inflight",
			"vpn-diag-lat-stalls",
			"vpn-diag-lat-errors",
			"vpn-diag-drops-client",
			"vpn-diag-drops-return",
			"vpn-diag-drops-total",
			"vpn-diag-vtun-upstream",
			"vpn-diag-vtun-nexus",
			"vpn-diag-engine-status",
			"vpn-diag-peers-status",
			"vpn-diag-sync-failures",
			"vpn-diag-hs-freshness",
			"vpn-diag-routing-badge",
			"vpn-diag-routing-counts",
			"vpn-diag-routing-alerts",
			"vpn-diag-be-counts",
			"vpn-diag-be-latency",
			"vpn-diag-be-skew",
			"vpn-diag-be-drops",
			"vpn-diag-res-cpu",
			"vpn-diag-res-mem",
			"vpn-diag-res-goroutines",
			"vpn-diag-res-gc",
			"vpn-diag-res-fd",
			"vpn-chart-throughput",
			"vpn-chart-queue",
			"vpn-chart-drops",
			"vpn-chart-latency",
			"vpn-routes-toggle-all-btn",
			"vpn-troubleshooting-title",
			"vpn-sessions-count-badge",
			"vpn-sessions-toggle-problems-btn",
			"vpn-sessions-toggle-problems-text",
			"vpnSessionsTable",
			"vpn-sessions-tbody",
			"vpn-sessions-loading",
		}
		for _, id := range requiredIDs {
			if !strings.Contains(vpnStr, fmt.Sprintf(`id="%s"`, id)) {
				t.Errorf("vpn.html missing required element ID %q", id)
			}
		}
	})

	t.Run("TranslationKeysInAllLanguages", func(t *testing.T) {
		transFS, err := GetTranslationsSubFS()
		if err != nil {
			t.Fatalf("GetTranslationsSubFS failed: %v", err)
		}

		requiredKeys := []string{
			"vpn_fwd_panel_traffic",
			"vpn_fwd_panel_queue",
			"vpn_fwd_panel_latency",
			"vpn_fwd_panel_drops",
			"vpn_fwd_panel_vtun",
			"vpn_fwd_panel_peer_sync",
			"vpn_fwd_panel_routing",
			"vpn_fwd_panel_backends",
			"vpn_fwd_panel_runtime",
			"vpn_fwd_panel_history",
			"vpn_fwd_panel_problems",
			"vpn_fwd_upstream_to_nexus",
			"vpn_fwd_nexus_to_upstream",
			"vpn_fwd_show_all",
			"vpn_fwd_show_problems",
			"vpn_fwd_kpi_throughput",
			"vpn_fwd_kpi_routes",
			"vpn_fwd_kpi_pressure",
			"vpn_fwd_kpi_loss",
			"vpn_fwd_kpi_client_engine",
			"vpn_fwd_kpi_peer_sync",
			"vpn_fwd_kpi_backends",
			"vpn_fwd_kpi_slow_writes",
			"vpn_fwd_tech_diagnostics",
			"vpn_fwd_no_active_problems",
			"vpn_fwd_nominal_peers",
			"vpn_fwd_nominal_routes",
			"vpn_fwd_nominal_backends",
			"vpn_fwd_onset",
			"vpn_fwd_active_problems_count",
			"vpn_fwd_affected_users_count",
			"vpn_fwd_affected_configs_count",
			"vpn_fwd_loss_rate_format",
			"vpn_fwd_recent",
			"vpn_col_live_traffic",
			"vpn_col_packet_loss",
			"vpn_col_queue_pressure",
			"vpn_show_all_connections",
			"vpn_show_problems_only",
			"vpn_troubleshooting_title",
			"vpn_drilldown_reservoir",
			"vpn_drilldown_dwell",
			"vpn_drilldown_write_stalls",
			"vpn_drilldown_write_errors",
			"vpn_drilldown_traffic_details",
			"vpn_drilldown_no_telemetry",
			"vpn_forwarder_unroutable",
		}

		languages := []string{"en.json", "ru.json", "fa.json", "fr.json", "zh.json"}
		for _, langFile := range languages {
			data, err := fs.ReadFile(transFS, langFile)
			if err != nil {
				t.Fatalf("failed to read %s: %v", langFile, err)
			}
			var dict map[string]string
			if err := json.Unmarshal(data, &dict); err != nil {
				t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
			}
			for _, k := range requiredKeys {
				val, ok := dict[k]
				if !ok || strings.TrimSpace(val) == "" {
					t.Errorf("%s missing required translation key %q", langFile, k)
				}
				if strings.Contains(val, "\u2014") {
					t.Errorf("%s key %s contains prohibited em dash (\\u2014): %q", langFile, k, val)
				}
			}
		}
	})

	t.Run("ExecutableJSDOMHealthAssessment", func(t *testing.T) {
		nodePath, err := findNodeBinary()
		if err != nil {
			t.Fatal("Node is required for diagnostics verification")
		}

		f1, err := extractJSFunction(vpnStr, "function vpnFormatPeerKey")
		if err != nil {
			t.Fatalf("extract vpnFormatPeerKey failed: %v", err)
		}
		f2, err := extractJSFunction(vpnStr, "function vpnRenderForwarderHealth")
		if err != nil {
			t.Fatalf("extract vpnRenderForwarderHealth failed: %v", err)
		}

		runnerScript := vpnDOMMock(t, vpnStr) + "\n" + vpnDiagnosticsTranslationsJS(t, vpnStr, "en") + "\n" + f1 + "\n" + f2 + `
const mockDoc = document;
// Test 1: HEALTHY state
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'HEALTHY',
        summary: 'All clear and operational'
    },
    rates: {available:true,rx_bps: 1000000, tx_bps: 2000000 },
    routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
    backends: { healthy_count: 2, total_count: 2 }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-success');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-headline-summary').textContent, 'All clear and operational');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').textContent, '2 / 2 healthy');

// Test 2: DEGRADED state with condition
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'DEGRADED',
        summary: 'Elevated queue pressure',
        conditions: [{ severity: 'DEGRADED', message: 'Queue occupancy > 50%' }]
    }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-warn');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Degraded');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-problem-list').children.length, 1);

// Test 3: CRITICAL state
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available: true,
    forwarder_queue_capacity: 1024,
    health_assessment: {
        status: 'CRITICAL',
        summary: 'Packet drops detected',
        conditions: [{ severity: 'CRITICAL', message: 'Queue full drops' }]
    }
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge badge-danger');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Critical');

// Test 4: UNAVAILABLE state
mockDoc.reset();
vpnRenderForwarderHealth(null);
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-badge').className, 'badge');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Not reported');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-throughput').textContent, '-');

// Current route alarms recover while lifetime totals remain visible.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true, forwarder_queue_capacity:100, forwarder_queue_occupancy:0,
    health_assessment:{status:'HEALTHY',summary:'Recovered',conditions:[]},
    problem_routes:[],
    all_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:false}]
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, _('vpn_forwarder_no_route_pressure'));
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, false);
assert.strictEqual(mockDoc.getElementById('vpn-fwd-status-text').textContent, 'Healthy');

// Fresh loss remains a problem after the queue drains.
mockDoc.reset();
vpnRenderForwarderHealth({
    forwarder_available:true, forwarder_queue_capacity:100,
    problem_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:true}],
    all_routes:[{peer_key:'peer',capacity:100,occupancy:0,drops:5,has_pressure:true}]
});
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-summary-status').textContent, 'Pressure Detected');
assert.strictEqual(mockDoc.getElementById('vpn-fwd-routes-details').open, true);

// Recovered KPIs keep lifetime evidence descriptive and show current availability.
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,health_assessment:{status:'HEALTHY',summary:'Recovered'},
 drop_categories: {rates_available:true,total_drops:99,total_drop_rate_pps:0},
 forward_latency:{stalls:7,stalls_recent:0,p95_ms:300,p95_health_ms:0,p95_health_samples:0,oldest_in_flight_ms:0},
 backends:{eligibility_known:true,healthy_count:1,enabled_count:1,disabled_count:2,total_count:3}
});
assert.strictEqual(mockDoc.getElementById('vpn-kpi-packet-loss').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('cumulative'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-slow-writes').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('unavailable'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').style.color,'');
assert(mockDoc.getElementById('vpn-kpi-backends').textContent.includes('1 / 1'));
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 drop_categories: {rates_available:true,total_drops:100,total_drop_rate_pps:2},
 forward_latency:{stalls:8,stalls_recent:1,p95_ms:300,p95_health_ms:150,p95_health_samples:1}
});
assert.strictEqual(mockDoc.getElementById('vpn-kpi-packet-loss').style.color,'var(--danger)');
assert.strictEqual(mockDoc.getElementById('vpn-kpi-slow-writes').style.color,'var(--danger)');
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 forward_latency:{p95_health_ms:0,p95_health_samples:1,stalls_recent:0},
 backends:{eligibility_known:true,healthy_count:0,enabled_count:0,disabled_count:3,total_count:3}
});
assert(mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('0.0ms'));
assert(!mockDoc.getElementById('vpn-kpi-slow-writes').textContent.includes('unavailable'));
assert.strictEqual(mockDoc.getElementById('vpn-kpi-backends').style.color,'var(--danger)');

mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 rates:{available:false,rx_bps:0,tx_bps:0},
 drop_categories:{rates_available:false,total_drops:0,total_drop_rate_pps:0}
});
assert(mockDoc.getElementById('vpn-kpi-throughput').textContent.includes('unavailable'));
assert(mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('unavailable'));
mockDoc.reset();
vpnRenderForwarderHealth({
 forwarder_available:true,forwarder_queue_capacity:100,
 rates:{available:true,rx_bps:0,tx_bps:0},
 drop_categories:{rates_available:true,total_drops:0,total_drop_rate_pps:0}
});
assert(!mockDoc.getElementById('vpn-kpi-throughput').textContent.includes('unavailable'));
assert(!mockDoc.getElementById('vpn-kpi-packet-loss').textContent.includes('unavailable'));

console.log('VPN_HEALTH_PASS');
`

		cmd := exec.Command(nodePath, "-e", runnerScript)
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("VPN health DOM tests failed: %v\nOutput:\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "VPN_HEALTH_PASS") {
			t.Fatalf("VPN health DOM tests did not output VPN_HEALTH_PASS\nOutput:\n%s", string(out))
		}
	})
}

func TestVPNHistoryChartLatencyAvailability(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	templateData, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	sparkline, err := extractJSFunction(string(templateData), "function vpnGenerateSparklineSVG")
	if err != nil {
		t.Fatal(err)
	}
	render, err := extractJSFunction(string(templateData), "function vpnRenderHistoryCharts")
	if err != nil {
		t.Fatal(err)
	}
	script := vpnDiagnosticsTranslationsJS(t, string(templateData), "en") + `const assert = require('assert');
const chart = {innerHTML:''};
const document = {getElementById:id => id === 'vpn-chart-latency' ? chart : null};
` + sparkline + "\n" + render + `
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
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := extractJSFunction(string(data), "function vpnFormatPeerKey")
	if err != nil {
		t.Fatal(err)
	}
	render, err := extractJSFunction(string(data), "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatal(err)
	}
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
	script := "const route = " + string(encoded) + ";\n" + vpnDOMMock(t, string(data)) + "\n" + vpnDiagnosticsTranslationsJS(t, string(data), "en") + "\n" + peer + "\n" + render + `
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,problem_routes:[route]});
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
vpnRenderForwarderHealth({forwarder_available:true,forwarder_queue_capacity:100,backends:{backends:[
 {server_name:'Server 1',enabled:true,health_state:'active',traffic_available:false},
 {server_name:'Server 2',enabled:true,health_state:'active',traffic_available:true,rx_bytes_per_sec:0,tx_bytes_per_sec:0,rx_pps:0,tx_pps:0},
 {server_name:'Server 3',enabled:false,health_state:'active',traffic_available:true,rx_bytes_per_sec:125,tx_bytes_per_sec:250,rx_pps:2,tx_pps:3}
]}});
const rows=document.getElementById('vpn-diag-be-traffic').children;
assert(rows[0].textContent.includes('Traffic unavailable'));
assert(!rows[1].textContent.includes('unavailable') && rows[1].textContent.includes('RX 0'));
assert(rows[2].textContent.includes('Disabled') && rows[2].textContent.includes('1.00 Kbps') && rows[2].textContent.includes('2.00 Kbps'));

`
	if out, err := execNodeScript(nodePath, script); err != nil {
		t.Fatalf("complete route tooltip: %v\n%s", err, out)
	}
}

func vpnDOMMock(t *testing.T, source string) string {
	t.Helper()
	var ids []string
	for _, match := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(source, -1) {
		ids = append(ids, match[1])
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		t.Fatal(err)
	}
	return "const templateIDs = " + string(encoded) + ";\n" + `const assert = require('assert');
class Element {
 constructor() { this.children=[];this._text='';this._html='';this.style={};this.className='';this.title='';this.open=false;this.attributes={};this.parentNode=null; }
 set textContent(s) { this._text=String(s);this._html='';this.children=[]; }
 get textContent() {
   if (this._text) return this._text;
   if (this.children && this.children.length > 0) return this.children.map(c => c.textContent).join('');
   if (this._html) return this._html.replace(/<[^>]*>/g, '');
   return '';
 }
 set innerHTML(s) { this._html=String(s);this._text='';this.children=[]; }
 get innerHTML() {
   if (this._html) return this._html;
   if (this.children && this.children.length > 0) return this.children.map(c => c.innerHTML).join('');
   return '';
 }
 appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
 insertBefore(child, ref) {
   child.parentNode = this;
   const idx = ref ? this.children.indexOf(ref) : -1;
   if (idx >= 0) {
     this.children.splice(idx, 0, child);
   } else {
     this.children.push(child);
   }
   return child;
 }
 remove() {
   if (this.parentNode && Array.isArray(this.parentNode.children)) {
     const idx = this.parentNode.children.indexOf(this);
     if (idx >= 0) this.parentNode.children.splice(idx, 1);
   }
 }
 get nextElementSibling() {
   if (!this.parentNode || !Array.isArray(this.parentNode.children)) return null;
   const idx = this.parentNode.children.indexOf(this);
   if (idx >= 0 && idx + 1 < this.parentNode.children.length) {
     return this.parentNode.children[idx + 1];
   }
   return null;
 }
 get nextSibling() { return this.nextElementSibling; }
 get firstChild() { return this.children && this.children.length > 0 ? this.children[0] : null; }
 get lastChild() { return this.children && this.children.length > 0 ? this.children[this.children.length - 1] : null; }
 get classList() {
   const self = this;
   return {
     add(...classes) {
       const set = new Set((self.className || '').split(/\s+/).filter(Boolean));
       for (const c of classes) set.add(c);
       self.className = Array.from(set).join(' ');
     },
     remove(...classes) {
       const set = new Set((self.className || '').split(/\s+/).filter(Boolean));
       for (const c of classes) set.delete(c);
       self.className = Array.from(set).join(' ');
     },
     contains(c) {
       return (self.className || '').split(/\s+/).filter(Boolean).includes(c);
     },
     toggle(c, force) {
       const set = new Set((self.className || '').split(/\s+/).filter(Boolean));
       const has = set.has(c);
       const want = force !== undefined ? !!force : !has;
       if (want) set.add(c); else set.delete(c);
       self.className = Array.from(set).join(' ');
       return want;
     }
   };
 }
 set id(val) { this._id = String(val); elements.set(String(val), this); }
 get id() { return this._id || this.attributes['id'] || ''; }
 setAttribute(k,v) { this.attributes[k]=String(v); if (k === 'id') { this._id = String(v); elements.set(String(v), this); } }
 getAttribute(k) { return this.attributes[k]; }
 querySelector() { return null; }
 querySelectorAll() { return []; }
}
const elements = new Map();
const dynamicIDs = new Set(['vpnSessionsStaleBanner']);
const document = {
 reset() { elements.clear(); for (const id of templateIDs) elements.set(id,new Element()); },
 getElementById(id) {
   if (elements.has(id)) return elements.get(id);
   if (dynamicIDs.has(id)) return null;
   assert(elements.has(id), 'DOM id missing from actual template: '+id);
   return null;
 },
 createElement() { return new Element(); },
 createTextNode(s) { const el = new Element(); el.textContent = String(s); return el; }
};
document.reset();
`
}

func TestVPNCompleteHistoryAllWindowRenderers(t *testing.T) {
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"directions", "packets", "sessions-routes", "backend-latency", "reasons", "backends"} {
		if !strings.Contains(string(data), `id="vpn-chart-`+id+`"`) {
			t.Fatalf("missing history chart %s", id)
		}
	}
	sparkline, err := extractJSFunction(string(data), "function vpnGenerateSparklineSVG")
	if err != nil {
		t.Fatal(err)
	}
	render, err := extractJSFunction(string(data), "function vpnRenderHistoryCharts")
	if err != nil {
		t.Fatal(err)
	}
	script := vpnDOMMock(t, string(data)) + "\n" + vpnDiagnosticsTranslationsJS(t, string(data), "en") + "\n" + sparkline + "\n" + render + `
let vpnHistoryWindow='15m';
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
 assert.deepStrictEqual(seen.slice(0,4),[[null,3*v,0],[0,5*v,0],[null,6*v,0],[null,7*v,0]]);
 assert.deepStrictEqual(seen.slice(4,11),[[null,v,0],[null,2*v,0],[null,3*v,0],[null,4*v,0],[0,9*v,0],[0,10*v,0],[null,8*v,null]]);
 assert.deepStrictEqual(seen.slice(11),[[null,4*v,0],[null,2*v,0],[null,11*v,0],[null,12*v,0],[null,13*v,0],[null,14*v,0],[null,15*v,null]]);
 for (const [id,label] of [
  ['vpn-chart-directions','RX client to backend (bps)'],['vpn-chart-directions','TX backend to client (bps)'],
  ['vpn-chart-packets','RX packets/s'],['vpn-chart-packets','TX packets/s'],
  ['vpn-chart-sessions-routes','Active sessions'],['vpn-chart-sessions-routes','Active routes'],
  ['vpn-chart-backend-latency','Eligible backend probe p95 (ms)'],
  ['vpn-chart-reasons','return queue full (drops/s)'],['vpn-chart-reasons','client backend device queue full (drops/s)'],
  ['vpn-chart-backends','Backend 3 RX (bps)'],['vpn-chart-backends','Backend 3 TX (bps)'],
  ['vpn-chart-backends','Backend 3 RX packets/s'],['vpn-chart-backends','Backend 3 TX packets/s'],
  ['vpn-chart-backends','Backend 3 Probe latency (ms)']
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
assert(entry('vpn-chart-directions','RX client to backend (bps)').includes('No data'));
assert(entry('vpn-chart-reasons','return queue full (drops/s)').includes('No data'));
// Retired/re-registered backend IDs form gaps, never zero-filled continuity.
vpnRenderHistoryCharts({window_15m:[
 {backends:[{id:3,rx_bps:10,traffic_available:true}]},{backends:[]},
 {backends:[{id:3,rx_bps:0,traffic_available:true}]}
]});
const gap=entry('vpn-chart-backends','Backend 3 RX (bps)');
assert.strictEqual((gap.match(/<circle /g)||[]).length,2);
const gapStroke=gap.match(/<path d="([^"]+)" fill="none"/);
assert(gapStroke && !gapStroke[1].includes(' L '),'isolated backend samples must not bridge lifecycle gap');
vpnRenderHistoryCharts({window_15m:[{backends:Array.from({length:129},(_,id)=>({id})),backends_omitted:5}]});
assert.strictEqual(document.getElementById('vpn-chart-backends').children.length,128*5*2,'fleet churn renderer must remain bounded');
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
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"vpn-chart-throughput", "vpn-chart-packets", "vpn-chart-queue", "vpn-chart-latency",
		"vpn-chart-drops", "vpn-chart-directions", "vpn-chart-reasons",
		"vpn-chart-sessions-routes", "vpn-chart-backends", "vpn-chart-backend-latency",
		"vpn-diag-be-traffic", "vpn-history-fleet-note",
	} {
		if !strings.Contains(string(data), `id="`+id+`"`) {
			t.Fatalf("missing stale-clearing target %s", id)
		}
	}
	formatPeerKey, err := extractJSFunction(string(data), "function vpnFormatPeerKey")
	if err != nil {
		t.Fatal(err)
	}
	sparkline, err := extractJSFunction(string(data), "function vpnGenerateSparklineSVG")
	if err != nil {
		t.Fatal(err)
	}
	history, err := extractJSFunction(string(data), "function vpnRenderHistoryCharts")
	if err != nil {
		t.Fatal(err)
	}
	health, err := extractJSFunction(string(data), "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatal(err)
	}
	setWindow, err := extractJSFunction(string(data), "function vpnSetHistoryWindow")
	if err != nil {
		t.Fatal(err)
	}
	toggleRoutes, err := extractJSFunction(string(data), "function vpnToggleShowAllRoutes")
	if err != nil {
		t.Fatal(err)
	}
	script := vpnDOMMock(t, string(data)) + "\n" + vpnDiagnosticsTranslationsJS(t, string(data), "en") + "\n" + formatPeerKey + "\n" + sparkline + "\n" + history + "\n" + health + "\n" + setWindow + "\n" + toggleRoutes + `
let vpnHistoryWindow='15m';
let vpnLastStatus=null;
let vpnShowAllRoutes=false;
// The window-toggle control is a persistent button group with no stale data
// of its own; the mock only needs it to answer a querySelectorAll probe.
document.getElementById('vpn-history-window-toggles').querySelectorAll=()=>[];
const SVG_CHARTS=['vpn-chart-throughput','vpn-chart-queue','vpn-chart-drops','vpn-chart-latency'];
const SERIES_CHARTS=['vpn-chart-directions','vpn-chart-packets','vpn-chart-sessions-routes',
 'vpn-chart-backend-latency','vpn-chart-reasons','vpn-chart-backends'];
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
 'vpn-diag-throughput', 'vpn-diag-packets', 'vpn-diag-ewma5m', 'vpn-diag-ewma1h',
 'vpn-diag-queue-occ', 'vpn-diag-queue-peak', 'vpn-diag-queue-dur50', 'vpn-diag-queue-dur80',
 'vpn-diag-queue-drops', 'vpn-diag-lat-percentiles', 'vpn-diag-lat-max', 'vpn-diag-lat-inflight',
 'vpn-diag-lat-stalls', 'vpn-diag-lat-errors', 'vpn-diag-drops-client', 'vpn-diag-drops-return',
 'vpn-diag-drops-total', 'vpn-diag-vtun-upstream', 'vpn-diag-vtun-nexus', 'vpn-diag-engine-status',
 'vpn-diag-peers-status', 'vpn-diag-sync-failures', 'vpn-diag-peer-sync-op-failures',
 'vpn-diag-peer-sync-invalid', 'vpn-diag-peer-sync-enqueue', 'vpn-diag-peer-sync-reconcile',
 'vpn-diag-peer-sync-error', 'vpn-diag-peer-sync-restart', 'vpn-diag-hs-freshness',
 'vpn-diag-routing-counts', 'vpn-diag-be-counts', 'vpn-diag-be-latency', 'vpn-diag-be-skew',
 'vpn-diag-be-drops', 'vpn-diag-res-cpu', 'vpn-diag-res-mem', 'vpn-diag-res-goroutines',
 'vpn-diag-res-gc', 'vpn-diag-res-fd'
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

 assert.strictEqual(document.getElementById('vpn-fwd-routes-badge').textContent, '0', context + ': routes badge');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-summary-status').textContent, _('vpn_forwarder_unavailable'), context + ': routes summary');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-tbody').children.length, 0, context + ': route rows');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-table').style.display, 'none', context + ': routes table');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-empty').style.display, 'block', context + ': routes empty div');
 assert.strictEqual(document.getElementById('vpn-fwd-routes-details').open, false, context + ': routes details');

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
   { t: 200, rx_bps: 2000, tx_bps: 2000, traffic_available: true, q_pct: 10, drop_rate: 0, drop_rates_available: true,
     drop_reason_rates: { return_queue_full: 0 }, fwd_p95_ms: 30, fwd_p95_samples: 1, be_p95_ms: 25, be_latency_samples: 1,
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
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	tmplFS, err := GetTemplatesSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(tmplFS, "vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	health, err := extractJSFunction(string(data), "function vpnRenderForwarderHealth")
	if err != nil {
		t.Fatal(err)
	}
	script := vpnDOMMock(t, string(data)) + "\n" + vpnDiagnosticsTranslationsJS(t, string(data), "en") + "\n" + health + `
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
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Traffic unavailable', 'detail packets must be unavailable');
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
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Traffic unavailable');
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
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Rx: 0.0 pps | Tx: 0.0 pps', 'available zero packet rate must show measured rate');
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
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Rx: 100.0 pps | Tx: 50.0 pps');
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
assert.strictEqual(document.getElementById('vpn-diag-packets').textContent, 'Traffic unavailable');
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

func vpnDiagnosticsLocale(t *testing.T, lang string) map[string]string {
	t.Helper()
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(transFS, lang+".json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		t.Fatalf("invalid locale object: %s", lang)
	}
	dict := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		key, ok := keyToken.(string)
		if !ok {
			t.Fatalf("invalid locale key in %s", lang)
		}
		if _, exists := dict[key]; exists {
			t.Fatalf("duplicate locale key %s/%s", lang, key)
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		dict[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	return dict
}

func vpnDiagnosticsTranslationsJS(t *testing.T, source, lang string) string {
	t.Helper()
	encoded, err := json.Marshal(vpnDiagnosticsLocale(t, lang))
	if err != nil {
		t.Fatal(err)
	}
	staticFS, err := GetStaticSubFS()
	if err != nil {
		t.Fatal(err)
	}
	ui, err := fs.ReadFile(staticFS, "js/ui.js")
	if err != nil {
		t.Fatal(err)
	}
	escape, err := extractJSFunction(string(ui), "function escapeHtml")
	if err != nil {
		t.Fatal(err)
	}
	result := "const translations = " + string(encoded) + ";\nconst _ = key => translations[key] || key;\n" + escape + "\n"
	for _, name := range []string{"vpnDiagText", "vpnStatusLabel", "vpnLossReasonLabels"} {
		// The original template has no interpolation helper; baseline repro still
		// executes its real renderer instead of failing only on missing source.
		if !strings.Contains(source, "function "+name+"(") {
			continue
		}
		function, err := extractJSFunction(source, "function "+name)
		if err != nil {
			t.Fatal(err)
		}
		result += function + "\n"
	}
	return result
}

func vpnDiagnosticsRenderedHTML(t *testing.T, source string, dict map[string]string) string {
	t.Helper()
	parsed, err := template.New("vpn.html").Funcs(template.FuncMap{
		"_": func(key string) string {
			if value, ok := dict[key]; ok {
				return value
			}
			return key
		},
	}).Parse(source)
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := parsed.ExecuteTemplate(&rendered, "content", nil); err != nil {
		t.Fatal(err)
	}
	return rendered.String()
}

func vpnDiagnosticsStaticOracle(rendered string, dict map[string]string) error {
	fields := map[string]string{
		"vpn-diag-throughput": "vpn_fwd_kpi_throughput", "vpn-diag-packets": "vpn_diag_packet_rate",
		"vpn-diag-ewma5m": "vpn_diag_avg_5m", "vpn-diag-ewma1h": "vpn_diag_avg_1h",
		"vpn-diag-queue-occ": "vpn_diag_occupancy", "vpn-diag-queue-peak": "vpn_forwarder_peak",
		"vpn-diag-queue-drops": "vpn_diag_queue_drops", "vpn-diag-lat-max": "vpn_diag_max_duration",
		"vpn-diag-lat-inflight": "vpn_diag_in_flight_oldest", "vpn-diag-lat-errors": "vpn_diag_write_errors",
		"vpn-diag-drops-client": "vpn_diag_client_backend", "vpn-diag-drops-return": "vpn_diag_backend_client",
		"vpn-diag-drops-total": "vpn_diag_total_drop_rate", "vpn-diag-engine-status": "vpn_diag_engine",
		"vpn-diag-hs-freshness": "vpn_diag_handshake_freshness", "vpn-diag-routing-counts": "vpn_diag_routing_counts",
		"vpn-diag-be-counts": "vpn_diag_healthy_total", "vpn-diag-be-latency": "vpn_diag_latency_p95",
		"vpn-diag-be-skew": "vpn_diag_load_skew", "vpn-diag-be-drops": "vpn_diag_device_drops",
		"vpn-diag-res-cpu": "vpn_diag_cpu_usage", "vpn-diag-res-mem": "vpn_diag_memory",
		"vpn-diag-res-goroutines": "vpn_diag_goroutines", "vpn-diag-res-gc": "vpn_diag_gc_pause",
		"vpn-diag-res-fd": "vpn_diag_file_descriptors",
	}
	labels := make(map[string]string)
	fieldPattern := regexp.MustCompile(`<div class="flex justify-between"><span class="text-muted">([^<]+)</span><span class="font-mono" id="([^"]+)"`)
	for _, match := range fieldPattern.FindAllStringSubmatch(rendered, -1) {
		labels[match[2]] = html.UnescapeString(match[1])
	}
	for id, key := range fields {
		if labels[id] != dict[key]+":" {
			return fmt.Errorf("static label %s: got %q, want %q", id, labels[id], dict[key]+":")
		}
	}
	for _, threshold := range []string{"50", "80"} {
		if labels["vpn-diag-queue-dur"+threshold] != dict["vpn_diag_duration"]+" > "+threshold+"%:" {
			return fmt.Errorf("duration label %s is not localized", threshold)
		}
	}
	if labels["vpn-diag-lat-stalls"] != dict["vpn_diag_stalls"]+" (≥ 100ms):" {
		return errors.New("stall label is not localized")
	}
	for id, key := range map[string]string{
		"throughput": "vpn_fwd_kpi_throughput", "queue": "vpn_diag_queue_utilization",
		"drops": "vpn_diag_drop_rate", "latency": "vpn_diag_forward_p95",
	} {
		pattern := regexp.MustCompile(`<div style="font-size: 0.75rem; color: var\(--text-muted\);">([^<]+)</div>\s*<div id="vpn-chart-` + id + `"`)
		match := pattern.FindStringSubmatch(rendered)
		expected := dict[key]
		if id == "throughput" {
			expected += " (bps)"
		}
		if len(match) != 2 || html.UnescapeString(match[1]) != expected {
			return fmt.Errorf("static chart %s is not localized", id)
		}
	}
	if !strings.Contains(rendered, "<details><summary>"+html.EscapeString(dict["vpn_diag_loss_backend_history"])+"</summary>") {
		return errors.New("history details heading is not localized")
	}
	return nil
}

func vpnDiagnosticsLocalizationScript(t *testing.T, source, lang string) string {
	t.Helper()
	script := vpnDOMMock(t, source) + "\n" + vpnDiagnosticsTranslationsJS(t, source, lang)
	for _, name := range []string{"vpnFormatPeerKey", "vpnGenerateSparklineSVG", "vpnRenderHistoryCharts", "vpnRenderForwarderHealth", "vpnSetHistoryWindow", "vpnToggleShowAllRoutes"} {
		function, err := extractJSFunction(source, "function "+name)
		if err != nil {
			t.Fatal(err)
		}
		script += "\n" + function
	}
	return script + `
let vpnHistoryWindow='15m', vpnLastStatus=null, vpnShowAllRoutes=false;
document.getElementById('vpn-history-window-toggles').querySelectorAll=()=>[];
const text=id=>document.getElementById(id).textContent;
const E=(key,values={})=>{assert(Object.prototype.hasOwnProperty.call(translations,key),'missing oracle key '+key);return Object.entries(values).reduce((result,[name,value])=>result.split('{'+name+'}').join(String(value)),translations[key]);};
const route={peer_key:'abcd…',assigned_ip:'<client-address>',backend_id:3,occupancy:0,capacity:100,
 high_water:0,drops:0,p95_write_ms:0,p95_write_samples:0,last_traffic_age_sec:-1,pressure_note:'',
 write_count:7,write_errors:2,traffic:{available:false,rx_bytes_per_sec:999,rx_pps:999},future_field:17};
const point={traffic_available:true,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0,sessions:0,routes:0,
 drop_rates_available:true,drop_reason_rates:{return_queue_full:0,future_reason:0},fwd_p95_ms:0,fwd_p95_samples:1,
 be_p95_ms:0,be_latency_samples:1,backends:[{id:3,rx_bps:0,traffic_available:true,probe_latency_ms:0,probe_available:true}],backends_omitted:5};
const fixture={forwarder_available:true,forwarder_queue_capacity:100,listener_running:true,
 health_assessment:{status:'HEALTHY',conditions:[]},rates:{available:false,rx_bps:999,tx_bps:999},
 drop_categories:{rates_available:false,total_drops:12},routing_consistency:{is_consistent:false,ownership_mismatch_drops:4,inconsistency_details:['Server detail']},
 problem_routes:[route],all_routes:[route],
 queue_pressure:{total_seconds_above_50:65,consecutive_above_50_sec:2,total_seconds_above_80:3600,consecutive_above_80_sec:0},
 forward_latency:{p95_health_samples:0,stalls_recent:2,stalls:8,p50_ms:1.5,p95_ms:2.5,p99_ms:3.5,max_ms:7,in_flight:2,oldest_in_flight_ms:9,write_total:10,write_errors:3,write_error_rate_pps:1.25},
 backends:{eligibility_known:true,healthy_count:1,enabled_count:2,total_count:3,disabled_count:1,latency_samples:0,backends:[
 {server_name:'Server < & "quote">',enabled:false,traffic_available:false},
 {server_name:'Server 2',enabled:true,health_state:'active',traffic_available:true},
 {server_name:'Server 3',enabled:true,health_state:'future_state',traffic_available:true}]},
 historical_series:{window_15m:[point]},peer_sync:{desired_peers:1,actual_peers:1,sync_failures:3,sync_failures_recent:2}};
const original=JSON.stringify(fixture);
vpnRenderForwarderHealth(fixture);
assert.strictEqual(text('vpn-kpi-throughput'),E('vpn_diag_traffic_unavailable'),'traffic state');
assert.strictEqual(text('vpn-diag-throughput'),E('vpn_diag_traffic_unavailable'));
assert.strictEqual(text('vpn-kpi-packet-loss'),E('vpn_diag_with_cumulative',{value:E('vpn_diag_loss_unavailable'),count:12}),'unknown loss');
assert.strictEqual(text('vpn-kpi-client-engine'),E('vpn_diag_engine_state',{state:E('vpn_running')}),'engine running');
assert.strictEqual(text('vpn-diag-engine-status'),E('vpn_diag_awg_state',{state:E('vpn_running')}));
assert.strictEqual(text('vpn-diag-routing-badge'),E('vpn_fwd_inconsistent'),'routing state');
assert.strictEqual(text('vpn-diag-routing-alerts'),'Server detail','server detail unchanged');
assert(text('vpn-diag-routing-counts').includes(E('vpn_diag_mismatch_drops',{count:4})));
assert.strictEqual(text('vpn-diag-be-latency'),E('vpn_diag_peer_sync_unavailable'));
assert.strictEqual(text('vpn-kpi-backends'),E('vpn_diag_healthy_count',{healthy:1,enabled:2})+E('vpn_diag_disabled_count',{count:1}));
assert.strictEqual(text('vpn-diag-be-counts'),E('vpn_diag_backend_counts',{healthy:1,enabled:2,total:3,disabled:1}));
const backendRows=document.getElementById('vpn-diag-be-traffic').children;
assert(backendRows[0].textContent.includes(E('disabled')) && backendRows[0].textContent.includes(E('vpn_diag_traffic_unavailable')));
assert(backendRows[0].textContent.includes('Server < & "quote">') && backendRows[0].innerHTML==='','backend name uses text');
assert(backendRows[1].textContent.includes(E('active')));
assert(backendRows[2].textContent.includes('future_state'),'unknown health state unchanged');
assert.strictEqual(text('vpn-kpi-slow-writes'),E('vpn_diag_slow_writes',{count:2,latency:E('vpn_diag_latency_unavailable')}));
assert.strictEqual(document.getElementById('vpn-kpi-slow-writes').title,E('vpn_diag_slow_writes_title',{count:8,latency:'2.5'}));
assert.strictEqual(text('vpn-diag-lat-percentiles'),E('vpn_diag_historical_percentiles',{p50:'1.5',p95:'2.5',p99:'3.5'}),'percentile interpolation');
assert.strictEqual(text('vpn-diag-lat-max'),E('vpn_diag_historical_ms',{value:7}));
assert.strictEqual(text('vpn-diag-lat-inflight'),E('vpn_diag_in_flight',{count:2,oldest:9}));
assert.strictEqual(text('vpn-diag-lat-stalls'),E('vpn_diag_recent_cumulative',{recent:2,count:8}));
assert.strictEqual(text('vpn-diag-lat-errors'),E('vpn_diag_write_error_counts',{rate:'1.25',errors:3,writes:10}));
assert.strictEqual(text('vpn-diag-queue-dur50'),E('vpn_diag_duration_streak',{total:'1m 5s',streak:'2s'}));
assert.strictEqual(text('vpn-diag-queue-dur80'),E('vpn_diag_duration_streak',{total:'1h 0m',streak:'0s'}));
assert.strictEqual(text('vpn-diag-sync-failures'),'3 ('+E('vpn_diag_recent_count',{count:2})+')');
let title=document.getElementById('vpn-fwd-routes-tbody').children[0].children[0].title;
assert(title.includes(E('vpn_diag_assigned_address')+': <client-address>'),'route label');
assert(title.includes(E('vpn_diag_write_p95_historical')+': '+E('vpn_diag_peer_sync_unavailable')));
assert(title.includes(E('vpn_diag_directional_traffic')+' '+E('vpn_diag_rx_bytes_rate')+': '+E('vpn_diag_peer_sync_unavailable')));
assert(title.includes('future field: 17'),'unknown route field unchanged');
assert(title.includes(E('vpn_diag_pressure_reason')+': '+E('vpn_diag_peer_sync_none')));
assert.strictEqual(document.getElementById('vpn-fwd-routes-tbody').children[0].children[4].textContent,E('vpn_diag_route_errors',{writes:7,errors:2}));
function seriesLabel(id,label) {
 return document.getElementById(id).children.some(child=>child.textContent===label+' ('+vpnHistoryWindow+')');
}
assert(seriesLabel('vpn-chart-directions',E('vpn_diag_rx_direction')),'history direction label');
assert(seriesLabel('vpn-chart-reasons',E('vpn_diag_loss_return_queue_full')+' (drops/s)'),'known loss label');
assert(seriesLabel('vpn-chart-reasons','future reason (drops/s)'),'unknown reason unchanged');
assert(seriesLabel('vpn-chart-backends',E('vpn_diag_backend_series',{id:3,label:'RX (bps)'})),'backend history label');
assert.strictEqual(text('vpn-history-fleet-note'),E('vpn_diag_fleet_limit',{count:5}));
assert.strictEqual(JSON.stringify(fixture),original,'renderer must not alter API values');

for (const [status,key,css] of [['HEALTHY','vpn_forwarder_healthy','badge-success'],['DEGRADED','vpn_forwarder_degraded','badge-warn'],['CRITICAL','vpn_forwarder_critical','badge-danger']]) {
 fixture.health_assessment={status,conditions:[{severity:status,message:'Server condition < & >'}]};
 vpnRenderForwarderHealth(fixture);
 assert.strictEqual(text('vpn-fwd-status-text'),E(key),'authoritative severity '+status);
 assert(document.getElementById('vpn-fwd-status-badge').className.includes(css));
 const condition=document.getElementById('vpn-fwd-problem-list').children[0];
 assert.strictEqual(condition.children[0].textContent,E(key),'condition severity '+status);
 assert.strictEqual(condition.children[1].textContent,'Server condition < & >','server condition unchanged');
 assert.strictEqual(fixture.health_assessment.status,status,'wire severity unchanged');
}
fixture.listener_running=false;fixture.routing_consistency.is_consistent=true;
fixture.health_assessment={status:'HEALTHY',conditions:[]};
vpnRenderForwarderHealth(fixture);
assert.strictEqual(text('vpn-kpi-client-engine'),E('vpn_diag_engine_state',{state:E('vpn_stopped')}));
assert.strictEqual(text('vpn-diag-routing-badge'),E('vpn_fwd_consistent'));
assert.strictEqual(text('vpn-fwd-headline-summary'),E('vpn_diag_summary_healthy'),'fallback summary');
fixture.health_assessment.summary='Server summary';vpnRenderForwarderHealth(fixture);
assert.strictEqual(text('vpn-fwd-headline-summary'),'Server summary');

vpnRenderHistoryCharts({window_15m:[]});
assert(document.getElementById('vpn-chart-throughput').innerHTML.includes(escapeHtml(E('no_data'))),'empty sparkline');
assert.strictEqual(text('vpn-chart-reasons'),E('no_data')+' (15m)','empty reason history');
assert.strictEqual(text('vpn-chart-backends'),E('no_data')+' (15m)','empty backend history');
vpnRenderHistoryCharts({window_15m:[{traffic_available:false,drop_rates_available:false,fwd_p95_samples:0}]});
assert(document.getElementById('vpn-chart-throughput').innerHTML.includes(escapeHtml(E('no_data'))));
vpnRenderHistoryCharts(fixture.historical_series);
assert(document.getElementById('vpn-chart-throughput').innerHTML.includes('<path'),'measured zero remains available');

vpnRenderForwarderHealth({forwarder_available:false});
assert.strictEqual(vpnLastStatus,null);
vpnToggleShowAllRoutes();vpnSetHistoryWindow('1h');
assert.strictEqual(text('vpn-fwd-status-text'),E('vpn_forwarder_unavailable'),'unavailable remains localized');
assert.strictEqual(text('vpn-kpi-throughput'),'-','no stale throughput');
assert.strictEqual(document.getElementById('vpn-chart-directions').children.length,0);
fixture.rates={available:true,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0};
fixture.drop_categories={rates_available:true,total_drops:12,total_drop_rate_pps:0};
fixture.problem_routes[0].traffic={available:true,rx_bytes_per_sec:0,rx_pps:0};
fixture.problem_routes[0].p95_write_samples=1;fixture.problem_routes[0].last_traffic_age_sec=0;
fixture.health_assessment={status:'HEALTHY',conditions:[]};
vpnRenderForwarderHealth(fixture);
assert.strictEqual(text('vpn-fwd-status-text'),E('vpn_forwarder_healthy'),'recovered localized healthy');
assert.strictEqual(text('vpn-kpi-throughput'),'0 bps / 0.0 pps','measured zero differs from unknown');
assert.strictEqual(text('vpn-kpi-packet-loss'),E('vpn_diag_with_cumulative',{value:'0.00 pps',count:12}));
title=document.getElementById('vpn-fwd-routes-tbody').children[0].children[0].title;
assert(title.includes(E('vpn_diag_directional_traffic')+' '+E('vpn_diag_rx_bytes_rate')+': 0'));
assert(title.includes(E('vpn_diag_write_p95_historical')+': 0'));

translations.no_data='<img src=x onerror=alert(1)> & "translated"';
const emptySVG=vpnGenerateSparklineSVG([]);
assert(emptySVG.includes('&lt;img') && emptySVG.includes('&amp;') && !emptySVG.includes('<img'),'SVG translation must be escaped');
console.log('LOCALIZATION_PASS');
`
}

func TestVPNDiagnosticsLocalizationDictionaries(t *testing.T) {
	base := vpnDiagnosticsLocale(t, "en")
	placeholders := regexp.MustCompile(`\{[a-z0-9_]+\}`)
	for _, lang := range []string{"en", "fa", "fr", "ru", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dict := vpnDiagnosticsLocale(t, lang)
			if len(dict) != len(base) {
				t.Fatal("locale key count differs")
			}
			for key, expected := range base {
				value, ok := dict[key]
				if !ok || strings.TrimSpace(value) == "" {
					t.Fatalf("missing/empty key %s", key)
				}
				a, b := placeholders.FindAllString(expected, -1), placeholders.FindAllString(value, -1)
				sort.Strings(a)
				sort.Strings(b)
				if strings.Join(a, ",") != strings.Join(b, ",") {
					t.Fatalf("placeholder mismatch for %s", key)
				}
			}
		})
	}
}

func TestVPNDiagnosticsLocalization(t *testing.T) {
	data, err := fs.ReadFile(TemplatesFS, "templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics localization acceptance")
	}
	for _, lang := range []string{"en", "ru", "fa", "fr", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dict := vpnDiagnosticsLocale(t, lang)
			rendered := vpnDiagnosticsRenderedHTML(t, source, dict)
			if err := vpnDiagnosticsStaticOracle(rendered, dict); err != nil {
				t.Fatal(err)
			}
			script := vpnDiagnosticsLocalizationScript(t, source, lang)
			if out, err := execNodeScript(nodePath, script); err != nil {
				t.Fatalf("locale renderer: %v\n%s", err, out)
			}
		})
	}
	t.Run("StaticEscapingAndRTL", func(t *testing.T) {
		dict := vpnDiagnosticsLocale(t, "fa")
		dict["vpn_diag_cpu_usage"] = "<translated & \"quoted\">"
		rendered := vpnDiagnosticsRenderedHTML(t, source, dict)
		if !strings.Contains(rendered, html.EscapeString(dict["vpn_diag_cpu_usage"])) || strings.Contains(rendered, "<translated") {
			t.Fatal("static translation escaped incorrectly")
		}
		base, err := fs.ReadFile(TemplatesFS, "templates/base.html")
		if err != nil {
			t.Fatal(err)
		}
		opening := string(base[:bytes.Index(base, []byte("<head>"))])
		parsed, err := template.New("opening").Parse(opening)
		if err != nil {
			t.Fatal(err)
		}
		for _, lang := range []string{"en", "fa"} {
			var rendered bytes.Buffer
			if err := parsed.Execute(&rendered, map[string]string{"lang": lang}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(rendered.String(), `dir="rtl"`) != (lang == "fa") {
				t.Fatal("RTL locale convention changed")
			}
		}
	})
}

func TestVPNDiagnosticsLocalizationMutations(t *testing.T) {
	data, err := fs.ReadFile(TemplatesFS, "templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	lang := "ru"
	dict := vpnDiagnosticsLocale(t, lang)
	t.Run("HardcodedStaticLabel", func(t *testing.T) {
		before := `{{ _ "vpn_diag_packet_rate" }}`
		if !strings.Contains(source, before) {
			t.Fatal("static mutation target missing")
		}
		mutated := strings.Replace(source, before, "Packet Rate", 1)
		err := vpnDiagnosticsStaticOracle(vpnDiagnosticsRenderedHTML(t, mutated, dict), dict)
		if err == nil || !strings.Contains(err.Error(), "vpn-diag-packets") {
			t.Fatalf("hardcoded static label escaped the rendered oracle: %v", err)
		}
	})
	nodePath, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics localization acceptance")
	}
	for _, mutation := range []struct{ name, before, after, failure string }{
		{"HardcodedTrafficState", "_('vpn_diag_traffic_unavailable')", "'Traffic unavailable'", "traffic state"},
		{"WrongAuthoritativeSeverity", "statusText.textContent = _('vpn_forwarder_degraded');", "statusText.textContent = _('vpn_forwarder_warning');", "authoritative severity DEGRADED"},
		{"HardcodedRouteLabel", "_('vpn_diag_assigned_address')", "'Assigned address'", "route label"},
		{"HardcodedHistoryLabel", "_('vpn_diag_rx_direction')", "'RX client to backend (bps)'", "history direction label"},
		{"BrokenPercentileInterpolation", `/\{([a-z0-9_]+)\}/g`, `/\{([a-z_]+)\}/g`, "percentile interpolation"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if !strings.Contains(source, mutation.before) {
				t.Fatal("renderer mutation target missing")
			}
			mutated := strings.Replace(source, mutation.before, mutation.after, 1)
			out, err := execNodeScript(nodePath, vpnDiagnosticsLocalizationScript(t, mutated, lang))
			if err == nil || !strings.Contains(string(out), mutation.failure) {
				t.Fatalf("mutation escaped its behavioral oracle: %v\n%s", err, out)
			}
		})
	}
}

func vpnDiagnosticsHealthScript(t *testing.T, source, assertions string) string {
	t.Helper()
	return vpnDiagnosticsHealthScriptLocale(t, source, "en", assertions)
}

// vpnDiagnosticsHealthScriptLocale is vpnDiagnosticsHealthScript for an
// explicit locale, so alarm behaviour can be pinned as locale-independent
// rather than only asserted in English.
func vpnDiagnosticsHealthScriptLocale(t *testing.T, source, lang, assertions string) string {
	t.Helper()
	script := vpnDOMMock(t, source) + vpnDiagnosticsTranslationsJS(t, source, lang)
	for _, name := range []string{"vpnFormatPeerKey", "vpnRenderForwarderHealth"} {
		function, err := extractJSFunction(source, "function "+name)
		if err != nil {
			t.Fatal(err)
		}
		script += "\n" + function
	}
	return script + "\nlet vpnLastStatus=null;let vpnShowAllRoutes=false;\n" + assertions
}

// vpnBackendDeviceReasonInventory builds the backend-device reason inventory
// independently of the template, from the serialized Go API schema. Deriving it
// from vpn.DropCategoryBreakdown means a reason the API publishes but the label
// map omits (or the reverse) fails the test instead of silently losing the
// backend KPI alarm for that reason.
func vpnBackendDeviceReasonInventory(t *testing.T) []string {
	t.Helper()
	encoded, err := json.Marshal(vpn.DropCategoryBreakdown{})
	if err != nil {
		t.Fatalf("serializing DropCategoryBreakdown: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("parsing serialized DropCategoryBreakdown: %v", err)
	}
	var reasons []string
	for name := range payload {
		if strings.HasPrefix(name, "client_backend_device_") || strings.HasPrefix(name, "return_backend_device_") || name == "backend_device_unattributed" {
			reasons = append(reasons, name)
		}
	}
	sort.Strings(reasons)
	return reasons
}

// vpnBackendDeviceReasonsBody is the shared renderer oracle. It supplies each
// supported backend-device reason on its own, requires the alarm for it, and
// pins the availability, zero, recovery, unknown and locale contracts around the
// same KPI. It prints RESULT <json> so the caller can compare locales byte for
// byte instead of trusting that one locale happened to be exercised.
func vpnBackendDeviceReasonsBody(t *testing.T) string {
	t.Helper()
	inventory, err := json.Marshal(vpnBackendDeviceReasonInventory(t))
	if err != nil {
		t.Fatal(err)
	}
	return `
const apiReasons = ` + string(inventory) + `;
const deviceReasons = Object.keys(vpnLossReasonLabels()).filter(key =>
	key.indexOf('client_backend_device_') === 0 || key.indexOf('return_backend_device_') === 0 || key === 'backend_device_unattributed');
assert.deepStrictEqual(deviceReasons.slice().sort(), apiReasons,
	'API-to-label backend-device reason inventory drifted');
assert.strictEqual(deviceReasons.length, 7, 'backend-device reason count changed');
assert(deviceReasons.includes('backend_device_unattributed'),
	'backend_device_unattributed must drive the backend KPI alarm');
for (const retired of ['client_backend_device_retired_drops']) {
	assert(!deviceReasons.includes(retired), 'retired-only reason must stay out of the KPI: ' + retired);
}
const kpi = () => document.getElementById('vpn-diag-be-drops');
const alarm = () => kpi().style.color;
const observed = [];
function render(drop_categories, backends) {
	vpnRenderForwarderHealth(Object.assign({
		forwarder_available: true,
		forwarder_queue_capacity: 100,
		health_assessment: {status: 'HEALTHY', conditions: []}
	}, backends ? {backends} : {}, {drop_categories}));
}
// Every supported backend-device reason alarms on its own positive current rate.
for (const reason of apiReasons) {
	render({rates_available: true, reason_rates: {[reason]: 3}}, {total_drops: 17});
	assert.strictEqual(alarm(), 'var(--danger)', reason + ' current backend loss must alarm');
	observed.push(reason + '=' + alarm());
}
// Nonzero lifetime alone is history, not a current alarm.
render({rates_available: true, total_drops: 4242}, {total_drops: 4242});
assert.strictEqual(alarm(), '', 'lifetime backend drops alone must not alarm');
observed.push('lifetime=' + alarm());
// A measured zero rate clears a prior alarm while the loss stays visible.
render({rates_available: true, total_drops: 4242, reason_rates: {backend_device_unattributed: 3}}, {total_drops: 4242});
assert.strictEqual(alarm(), 'var(--danger)', 'fresh current loss must alarm');
observed.push('fresh=' + alarm());
render({rates_available: true, total_drops: 4242, reason_rates: {backend_device_unattributed: 0}}, {total_drops: 4242});
assert.strictEqual(alarm(), '', 'measured zero must clear the alarm');
observed.push('zero=' + alarm());
// Unavailable rates and an unavailable forwarder both suppress the alarm.
render({rates_available: false, total_drops: 4242, reason_rates: {backend_device_unattributed: 9}}, {total_drops: 4242});
assert.strictEqual(alarm(), '', 'unavailable rates must not alarm');
observed.push('unavailable=' + alarm());
render({}, {total_drops: 4242});
assert.strictEqual(alarm(), '', 'missing rates_available must not alarm');
observed.push('missing-flag=' + alarm());
vpnRenderForwarderHealth({forwarder_available: false});
assert.strictEqual(alarm(), '', 'unavailable forwarder must clear the alarm');
observed.push('unavailable-forwarder=' + alarm());
// Unknown, retired-only and overlapping non-device reasons stay out of the sum.
render({rates_available: true, total_drops: 7, reason_rates: {
	client_backend_device_retired_drops: 5, future_reason: 5, return_injection_errors: 5,
	client_backend_queue_full: 5}}, {total_drops: 7});
assert.strictEqual(alarm(), '', 'retired, unknown and injection reasons must not alarm');
observed.push('excluded=' + alarm());
// Fresh recovery after an unavailable poll alarms again on a live reason.
render({rates_available: true, reason_rates: {return_backend_device_shutdown: 1}}, {total_drops: 8});
assert.strictEqual(alarm(), 'var(--danger)', 'recovered poll must alarm on live loss');
observed.push('recovery=' + alarm());
console.log('RESULT ' + JSON.stringify(observed));
`
}

// TestVPNBackendDeviceKPIAlarmCoverage pins the backend-device KPI against the
// canonical reason map for every active locale. The defect under test: a second,
// manually curated KPI subset omitted the unattributed backend-device reason
// (backend_device_unattributed), so the detailed reason table showed the loss
// while the KPI never alarmed.
func TestVPNBackendDeviceKPIAlarmCoverage(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	body := vpnBackendDeviceReasonsBody(t)
	var baseline string
	for i, lang := range []string{"en", "ru", "fa", "fr", "zh"} {
		t.Run(lang, func(t *testing.T) {
			script := vpnDiagnosticsHealthScriptLocale(t, string(source), lang, body)
			out, err := execNodeScript(node, script)
			if err != nil {
				t.Fatalf("backend KPI alarm coverage: %v\n%s", err, out)
			}
			idx := strings.Index(string(out), "RESULT ")
			if idx < 0 {
				t.Fatalf("renderer produced no alarm report:\n%s", out)
			}
			reported := strings.TrimSpace(string(out)[idx+len("RESULT "):])
			if i == 0 {
				baseline = reported
				return
			}
			if reported != baseline {
				t.Fatalf("alarm behaviour differs in %s:\n got %s\nwant %s", lang, reported, baseline)
			}
		})
	}
}

// TestVPNBackendDeviceKPIAlarmMutations proves the acceptance oracle above is
// load-bearing in both directions: the alarm coverage must break when
// backend_device_unattributed is dropped from the KPI subset, and the
// API-to-label inventory must break when it is dropped from the canonical map.
func TestVPNBackendDeviceKPIAlarmMutations(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	body := vpnBackendDeviceReasonsBody(t)
	for _, mutation := range []struct{ name, before, after, failure string }{
		{
			name:    "UnattributedDroppedFromKPISubset",
			before:  "return key.indexOf('client_backend_device_') === 0 || key.indexOf('return_backend_device_') === 0 || key === 'backend_device_unattributed';",
			after:   "return key !== 'backend_device_unattributed' && (key.indexOf('client_backend_device_') === 0 || key.indexOf('return_backend_device_') === 0);",
			failure: "backend_device_unattributed current backend loss must alarm",
		},
		{
			name:    "UnattributedDroppedFromCanonicalMap",
			before:  "backend_device_unattributed: 'vpn_diag_loss_backend_device_unattributed',\n            ",
			after:   "",
			failure: "API-to-label backend-device reason inventory drifted",
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			original := string(source)
			if !strings.Contains(original, mutation.before) {
				t.Fatal("mutation target missing from template")
			}
			mutated := strings.Replace(original, mutation.before, mutation.after, 1)
			script := vpnDiagnosticsHealthScriptLocale(t, mutated, "en", body)
			out, err := execNodeScript(node, script)
			if err == nil || !strings.Contains(string(out), mutation.failure) {
				t.Fatalf("mutation escaped its acceptance oracle: %v\n%s", err, out)
			}
		})
	}
}

// vpnBackendDeviceConditionBody is the shared renderer oracle for the
// unattributed-attribution health condition. It renders the no-stats-device
// fixture (aggregate-only loss with the canonical message_key), requires the
// backend KPI alarm AND the condition row translated from the active locale
// dictionary, and pins both fallbacks: an unresolvable message_key renders the
// serialized message, a condition without one keeps the legacy behaviour. It
// prints RESULT <json> of locale-independent booleans so the caller can prove
// across locales that no locale silently falls back to the wire message.
func vpnBackendDeviceConditionBody(t *testing.T) string {
	t.Helper()
	return `
const CONDITION_KEY = 'vpn_diag_condition_backend_device_unattributed';
assert(Object.prototype.hasOwnProperty.call(translations, CONDITION_KEY) && translations[CONDITION_KEY],
	'locale dictionary must ship ' + CONDITION_KEY);
const observed = [];
function render(conditions) {
	vpnRenderForwarderHealth({
		forwarder_available: true,
		forwarder_queue_capacity: 100,
		health_assessment: {status: 'DEGRADED', conditions},
		drop_categories: {
			rates_available: true,
			total_drops: 9,
			reason_rates: {backend_device_unattributed: 3}
		}
	});
}
const condition = {
	category: 'drops',
	severity: 'DEGRADED',
	message_key: CONDITION_KEY,
	message: 'Backend device drops are active but detailed per-direction attribution is unavailable: 3.0 drops/sec'
};
render([condition]);
observed.push('alarm=' + (document.getElementById('vpn-diag-be-drops').style.color === 'var(--danger)'),
	'no aggregate-only loss must still alarm the backend KPI');
const row = document.getElementById('vpn-fwd-problem-list').children[0];
assert.strictEqual(row.children[0].textContent, _('vpn_forwarder_degraded'), 'condition severity badge');
assert.strictEqual(row.children[1].textContent, _(CONDITION_KEY),
	'condition text must come from the locale dictionary, not the serialized message');
observed.push('severity_from_dict=' + (row.children[0].textContent === _('vpn_forwarder_degraded')),
	'message_from_dict=' + (row.children[1].textContent === _(CONDITION_KEY)));
// An unresolvable message_key falls back to the serialized message.
render([{category: 'drops', severity: 'DEGRADED', message_key: 'vpn_diag_condition_future_key', message: 'Server fallback < & >'}]);
observed.push('fallback=' + (document.getElementById('vpn-fwd-problem-list').children[0].children[1].textContent === 'Server fallback < & >'));
// A condition without message_key keeps the legacy rendering.
render([{category: 'drops', severity: 'DEGRADED', message: 'Legacy server text'}]);
observed.push('legacy=' + (document.getElementById('vpn-fwd-problem-list').children[0].children[1].textContent === 'Legacy server text'));
console.log('RESULT ' + JSON.stringify(observed));
`
}

// TestVPNBackendDeviceUnattributedConditionRendering is the renderer half of
// the R5-refinement acceptance: for every active locale, a no-stats device
// with active loss shows the backend KPI alarm AND the condition row rendered
// from that locale's own dictionary entry via message_key — never the
// serialized English message.
func TestVPNBackendDeviceUnattributedConditionRendering(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	body := vpnBackendDeviceConditionBody(t)
	var baseline string
	for i, lang := range []string{"en", "ru", "fa", "fr", "zh"} {
		t.Run(lang, func(t *testing.T) {
			script := vpnDiagnosticsHealthScriptLocale(t, string(source), lang, body)
			out, err := execNodeScript(node, script)
			if err != nil {
				t.Fatalf("unattributed condition rendering: %v\n%s", err, out)
			}
			idx := strings.Index(string(out), "RESULT ")
			if idx < 0 {
				t.Fatalf("renderer produced no condition report:\n%s", out)
			}
			reported := strings.TrimSpace(string(out)[idx+len("RESULT "):])
			if i == 0 {
				baseline = reported
				return
			}
			if reported != baseline {
				t.Fatalf("condition rendering differs in %s:\n got %s\nwant %s", lang, reported, baseline)
			}
		})
	}
}

func TestVPNDiagnosticsCurrentObservations(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	script := vpnDiagnosticsHealthScript(t, string(source), `
const text = id => document.getElementById(id).textContent;
const base = {forwarder_available:true, health_assessment:{status:'HEALTHY'}, rates:{available:true}};
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:3,capacity:11,peak:7,drops:13},
 nexus_to_upstream:{occupancy:5,capacity:17,peak:9,drops:19}}});
assert.strictEqual(text('vpn-diag-vtun-upstream'),'Occupancy: 3/11 | Peak: 7 | Drops: 13');
assert.strictEqual(text('vpn-diag-vtun-nexus'),'Occupancy: 5/17 | Peak: 9 | Drops: 19');
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:0,capacity:0,peak:0,drops:13},
 nexus_to_upstream:{occupancy:0,capacity:17,peak:9,drops:19}}});
assert.strictEqual(text('vpn-diag-vtun-upstream'),'Queue unavailable | Drops: 13');
assert.strictEqual(text('vpn-diag-vtun-nexus'),'Occupancy: 0/17 | Peak: 9 | Drops: 19');
vpnRenderForwarderHealth({...base,virtual_tun:{upstream_to_nexus:{drops:23}}});
assert.strictEqual(text('vpn-diag-vtun-upstream'),'Queue unavailable | Drops: 23');
vpnRenderForwarderHealth({...base,virtual_tun:{
 upstream_to_nexus:{occupancy:0,capacity:31,peak:0,drops:23}}});
assert.strictEqual(text('vpn-diag-vtun-upstream'),'Occupancy: 0/31 | Peak: 0 | Drops: 23');

// Every disjoint reason has current rate and lifetime evidence. The overlapping
// return_injection_tun_drops diagnostic is excluded from the owned reason list.
vpnRenderForwarderHealth({...base,drop_categories:{rates_available:true,
 client_malformed:37,return_queue_full:41,return_injection_tun_drops:999,
 reason_rates:{client_malformed:2.5,return_queue_full:7}}});
let rows=document.getElementById('vpn-diag-drop-reasons').children;
assert.strictEqual(rows.length,22);
assert(rows[0].textContent.includes('7.00 pps (41 cumulative)'));
assert(rows.find(row => row.textContent.includes('2.50 pps (37 cumulative)')));
assert(!rows.some(row => row.textContent.includes('999') || row.textContent.includes('retired')));
vpnRenderForwarderHealth({...base,drop_categories:{rates_available:false,
 client_malformed:37,reason_rates:{client_malformed:99}}});
rows=document.getElementById('vpn-diag-drop-reasons').children;
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
 assert(text('vpn-diag-sync-failures').startsWith('1 '));
 assert(text('vpn-diag-peer-sync-op-failures').includes('1'));
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
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(source), `id="vpn-diag-vtun-upstream"`, `id="vpn-diag-vtun-typo"`, 1)
	script := vpnDiagnosticsHealthScript(t, mutated, `vpnRenderForwarderHealth({forwarder_available:true});`)
	if out, err := execNodeScript(node, script); err == nil ||
		!strings.Contains(string(out), "DOM id missing from actual template: vpn-diag-vtun-upstream") {
		t.Fatalf("template ID mutation escaped DOM oracle: %v", err)
	}
}

func TestVPNDiagnosticsPollingContract(t *testing.T) {
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]int{
		"NexusTelemetry.poll('vpn-status'": 1,
		"API.get('/api/vpn/status')":       1,
	} {
		if got := strings.Count(string(source), token); got != want {
			t.Errorf("%s count=%d, want%d", token, got, want)
		}
	}
	for _, token := range []string{"vpnRenderForwarderHealth(status)", "vpnRenderForwarderHealth(null)"} {
		if !strings.Contains(string(source), token) {
			t.Errorf("polling must handle %s", token)
		}
	}
}

func TestVPNForwarderHealthDecouplingAndHorizon(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}

	assertions := `
const text = id => document.getElementById(id).textContent;
const el = id => document.getElementById(id);

// 1. Nominal loss with historical drops retains HEALTHY green and unhighlighted KPI
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 0, total_drops: 109 }
});

assert(el('vpn-fwd-status-badge').className.includes('badge-success'), 'top banner must remain HEALTHY green when loss rate is nominal');
assert.strictEqual(text('vpn-fwd-status-text'), 'Healthy');
assert.strictEqual(el('vpn-kpi-packet-loss').style.color, '', 'nominal loss rate must not color packet loss KPI card');
assert.strictEqual(text('vpn-fwd-counters-since'), 'Counters since: 2026-10-07 06:14 UTC', 'counters_since must be formatted');
assert.notStrictEqual(el('vpn-fwd-counters-since').style.display, 'none');
assert.strictEqual(text('vpn-kpi-packet-loss-sub'), 'Current / Live: 0.00 pps | Since Startup / Reset: 109');
assert(el('vpn-kpi-packet-loss').title.includes('Current / Live: 0.00 pps'));
assert(el('vpn-kpi-packet-loss').title.includes('Since Startup / Reset: 109'));

// 2. Positive active drop rate activates danger highlight
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DEGRADED', conditions: [{ severity: 'DEGRADED', message: 'Loss active' }] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 3.5, total_drops: 115 }
});
assert.strictEqual(el('vpn-kpi-packet-loss').style.color, 'var(--danger)', 'active loss rate must highlight KPI card');
assert.strictEqual(text('vpn-kpi-packet-loss-sub'), 'Current / Live: 3.50 pps | Since Startup / Reset: 115');

// 3. Status DOWN displays Down badge
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'DOWN', conditions: [] }
});
assert(el('vpn-fwd-status-badge').className.includes('badge-danger'), 'DOWN status must have danger badge');
assert.strictEqual(text('vpn-fwd-status-text'), 'Down');

// 4. Unavailable forwarder clears counters_since and sublabel
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-fwd-counters-since').style.display, 'none');
assert.strictEqual(el('vpn-kpi-packet-loss-sub').style.display, 'none');
`

	script := vpnDiagnosticsHealthScript(t, string(source), assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("decoupling test failed: %v\n%s", err, out)
	}

	// 5. Test Russian locale translation for horizon labels and counters_since
	ruAssertions := `
const text = id => document.getElementById(id).textContent;
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	counters_since: '2026-10-07T06:14:40Z',
	drop_categories: { rates_available: true, total_drop_rate_pps: 0, total_drops: 109 }
});
assert.strictEqual(text('vpn-fwd-status-text'), 'В норме');
assert.strictEqual(text('vpn-fwd-counters-since'), 'Счетчики с: 2026-10-07 06:14 UTC');
assert.strictEqual(text('vpn-kpi-packet-loss-sub'), 'Текущий / Онлайн: 0.00 pps | С запуска / Сброса: 109');
`
	ruScript := vpnDiagnosticsHealthScriptLocale(t, string(source), "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian decoupling test failed: %v\n%s", err, out)
	}
}

func TestVPNProgressiveDisclosureAndActiveProblems(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

	// 1. Invariant: <details id="vpn-fwd-tech-details"> must be present in template.
	if !strings.Contains(tmplStr, `<details id="vpn-fwd-tech-details"`) {
		t.Fatal("vpn.html missing progressive disclosure container <details id=\"vpn-fwd-tech-details\">")
	}

	assertions := `
const el = id => document.getElementById(id);
const text = id => document.getElementById(id).textContent;

// 1. Nominal / Healthy forwarder:
// - techDetails remains closed (open === false)
// - problem-list renders reassuring green badge with live synced peers, routes, and backends
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	routing_consistency: { is_consistent: true, active_routes_count: 5, active_sessions_count: 5 },
	peer_sync: { actual_peers: 5, desired_peers: 5 },
	backends: { healthy_count: 2, total_count: 2 }
});

assert.strictEqual(el('vpn-fwd-tech-details').open, false, 'tech details must remain closed when healthy');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const greenBadge = el('vpn-fwd-problem-list').children[0];
assert(greenBadge.className.includes('badge-success'), 'nominal summary must have badge-success class');
assert.strictEqual(
	greenBadge.textContent,
	'✓ No active problems detected • 5/5 peers synced • All routes consistent • 2/2 backends healthy',
	'nominal green badge text must show live counts'
);

// 2. Degraded forwarder with active issue:
// - techDetails auto-expands (open === true)
// - problem-list renders styled alert card with severity, message, and component/backend
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		actionable_problems: [{
			severity: 'DEGRADED',
			message: 'Backend -> Client packet drops active',
			category: 'dataplane',
			user_id: 'usr-1',
			username: 'alice',
			connection_name: 'alice-phone',
			assigned_ip: '10.8.0.2',
			backend_id: 3,
			observed_rate: '15 drops'
		}]
	}
});

assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must auto-expand when degraded');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const problemCard = el('vpn-fwd-problem-list').children[0];
assert(problemCard.className.includes('problem-card'), 'problem card must have problem-card class');
assert.strictEqual(problemCard.children[0].textContent, 'Degraded');
assert(problemCard.children[0].className.includes('badge-warn'));
assert.strictEqual(problemCard.children[1].textContent, 'Backend -> Client packet drops active');
assert(problemCard.children[2].textContent.includes('Backend 3'));
assert(problemCard.children[2].textContent.includes('dataplane'));
assert(problemCard.children[2].textContent.includes('User: alice'));
assert(problemCard.children[2].textContent.includes('Config: alice-phone'));
assert(problemCard.children[2].textContent.includes('IP: 10.8.0.2'));
assert(problemCard.children[2].textContent.includes('15 drops'));

// 3. Down forwarder:
// - techDetails auto-expands (open === true)
// - problem-list renders styled alert card with Down severity
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DOWN',
		summary: 'WireGuard forwarder daemon down'
	}
});

assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must auto-expand when down');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'flex');
assert.strictEqual(el('vpn-fwd-problem-list').children.length, 1);
const downCard = el('vpn-fwd-problem-list').children[0];
assert.strictEqual(downCard.children[0].textContent, 'Down');
assert(downCard.children[0].className.includes('badge-danger'));
assert.strictEqual(downCard.children[1].textContent, 'WireGuard forwarder daemon down');

// 4. Critical forwarder with explicit condition:
// - techDetails auto-expands (open === true)
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		conditions: [{
			severity: 'CRITICAL',
			message: 'Queue full drops critical',
			category: 'drops'
		}]
	}
});

assert.strictEqual(el('vpn-fwd-tech-details').open, true, 'tech details must auto-expand when critical');
assert.strictEqual(el('vpn-fwd-problem-list').children[0].children[0].textContent, 'Critical');
assert(el('vpn-fwd-problem-list').children[0].children[0].className.includes('badge-danger'));

// 5. Unavailable forwarder:
// - techDetails closed
// - problem-list hidden and empty
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-fwd-tech-details').open, false, 'tech details must close when unavailable');
assert.strictEqual(el('vpn-fwd-problem-list').style.display, 'none');
assert.strictEqual(el('vpn-fwd-problem-list').textContent, '');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("progressive disclosure & active problems test failed: %v\n%s", err, out)
	}

	// 6. Test Russian locale rendering of nominal badge
	ruAssertions := `
const el = id => document.getElementById(id);
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: { status: 'HEALTHY', conditions: [] },
	rates: { available: true },
	peer_sync: { actual_peers: 12, desired_peers: 12 },
	backends: { healthy_count: 3, total_count: 3 }
});

assert.strictEqual(el('vpn-fwd-tech-details').open, false);
assert.strictEqual(
	el('vpn-fwd-problem-list').children[0].textContent,
	'✓ Активных проблем не обнаружено • 12/12 пиров синхронизировано • Все маршруты согласованы • 3/3 бэкендов в норме'
);
`
	ruScript := vpnDiagnosticsHealthScriptLocale(t, tmplStr, "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian progressive disclosure nominal badge test failed: %v\n%s", err, out)
	}
}

func vpnConnectionTroubleshootingScriptLocale(t *testing.T, source, lang, assertions string) string {
	t.Helper()
	script := vpnDOMMock(t, source) + vpnDiagnosticsTranslationsJS(t, source, lang)
	for _, name := range []string{
		"fmtBps",
		"fmtPps",
		"vpnFormatBytes",
		"vpnFormatPeerKey",
		"vpnFindRouteForSession",
		"vpnRenderSessionRow",
		"vpnCreateSessionDrilldownRow",
		"vpnToggleSessionDrilldown",
		"vpnToggleSessionsProblemFilter",
		"vpnRenderSessionsStaleBanner",
		"vpnFindSessionById",
		"vpnSyncExpandedDrilldowns",
		"vpnWrapSessionsTableRender",
		"renderSessions",
		"vpnRenderForwarderHealth",
	} {
		function, err := extractJSFunction(source, "function "+name)
		if err != nil {
			t.Fatalf("extractJSFunction %s: %v", name, err)
		}
		script += "\n" + function
	}
	return script + `
let vpnLastSessions = null;
let vpnSessionsStale = false;
let vpnSessionsFilterOnlyProblems = false;
let vpnLastStatus = null;
let vpnExpandedSessionIds = new Set();
let vpnSessionsTableInstance = null;
const UI = { escapeHtml: escapeHtml };
` + assertions
}

func TestVPNConnectionTroubleshootingTableAndCorrelation(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

	// Structural invariants in template
	for _, requiredID := range []string{
		"vpnSessionsTable",
		"vpn-troubleshooting-title",
		"vpn-sessions-count-badge",
		"vpn-sessions-toggle-problems-btn",
		"vpn-sessions-toggle-problems-text",
		"vpn-sessions-tbody",
		"vpn-sessions-loading",
	} {
		if !strings.Contains(tmplStr, `id="`+requiredID+`"`) {
			t.Fatalf("vpn.html missing required ID %q", requiredID)
		}
	}

	// 1. English DOM assertions: 8 columns, correlation, telemetry, drilldown, and problem filter
	enAssertions := `
const tbody = document.getElementById('vpn-sessions-tbody');
const countBadge = document.getElementById('vpn-sessions-count-badge');
const filterBtn = document.getElementById('vpn-sessions-toggle-problems-btn');
const filterText = document.getElementById('vpn-sessions-toggle-problems-text');

// Telemetry status payload with 2 routes
vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.2',
            connection_id: '101',
            session_id: 'sess-1',
            occupancy: 12,
            capacity: 100,
            drops: 0,
            queue_full_drops_recent: 0,
            has_pressure: false,
            traffic: {
                available: true,
                rx_bps: 1000000,
                tx_bps: 2000000,
                rx_bytes: 1048576,
                tx_bytes: 2097152,
                rx_packets: 1500,
                tx_packets: 2500
            },
            reservoir: {
                p95_ms: 4.2,
                samples: 100,
                max_ms: 12.5
            },
            high_water: 45,
            write_stalls: 0,
            write_errors: 0,
            writes_in_flight: 1
        },
        {
            assigned_ip: '10.8.0.3',
            connection_id: '102',
            session_id: 'sess-2',
            occupancy: 90,
            capacity: 100,
            drops: 15,
            queue_full_drops_recent: 5,
            queue_full_drop_rate_pps: 2.4,
            has_pressure: true,
            traffic: {
                available: true,
                rx_bps: 500000,
                tx_bps: 100000,
                rx_bytes: 524288,
                tx_bytes: 1048576
            },
            reservoir: {
                p95_ms: 22.8,
                samples: 40,
                max_ms: 85.0
            },
            high_water: 95,
            write_stalls: 3,
            write_errors: 1,
            writes_in_flight: 4
        },
        {
            assigned_ip: '10.8.0.4',
            connection_id: '104',
            session_id: 'sess-4',
            occupancy: 5,
            capacity: 100,
            drops: 10,
            queue_full_drops_recent: 0,
            queue_full_drop_rate_pps: 0,
            has_pressure: false,
            traffic: {
                available: true,
                rx_bps: 100000,
                tx_bps: 200000,
                rx_bytes: 1048576,
                tx_bytes: 2097152,
                rx_packets: 1000,
                tx_packets: 2000
            },
            reservoir: {
                p95_ms: 2.0,
                samples: 20,
                max_ms: 5.0
            },
            high_water: 10,
            write_stalls: 0,
            write_errors: 0,
            writes_in_flight: 0
        }
    ]
};

const sessions = [
    {
        id: 1,
        session_id: 'sess-1',
        connection_id: '101',
        username: 'alice',
        connection_name: 'alice-phone',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.2',
        status: 'connected'
    },
    {
        id: 2,
        session_id: 'sess-2',
        connection_id: '102',
        username: 'bob',
        connection_name: 'bob-laptop',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.3',
        status: 'connected'
    },
    {
        id: 3,
        session_id: 'sess-3',
        connection_id: '103',
        username: 'charlie',
        connection_name: 'charlie-pc',
        server_name: 'Frankfurt-2',
        assigned_ip: '10.8.0.99',
        status: 'connected'
    },
    {
        id: 4,
        session_id: 'sess-4',
        connection_id: '104',
        username: 'dan',
        connection_name: 'dan-phone',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.4',
        status: 'connected'
    }
];

vpnLastSessions = { sessions: sessions };
renderSessions(sessions);

// Assertion 1: Count badge and row count
assert.strictEqual(countBadge.textContent, '4', 'badge count must match session count');
assert.strictEqual(tbody.children.length, 4, 'table must render 4 session rows');

// Row 0 (alice - nominal correlated route):
const row0 = tbody.children[0];
assert.strictEqual(row0.children.length, 8, 'session row must have 8 columns');
assert(row0.children[0].textContent.includes('alice'), 'col 0 must render username');
assert.strictEqual(row0.children[0].style.cursor, 'pointer', 'user cell must have pointer style');
assert(row0.children[0].innerHTML.includes('vpn-expand-icon'), 'user cell must render chevron icon');
assert.strictEqual(row0.children[1].textContent, 'alice-phone', 'col 1 must render config name');
assert.strictEqual(row0.children[2].textContent, 'Frankfurt-1', 'col 2 must render server name');
assert.strictEqual(row0.children[3].textContent, '10.8.0.2', 'col 3 must render assigned IP');
assert(row0.children[4].textContent.includes('1.00 Mbps') && row0.children[4].textContent.includes('2.00 Mbps'), 'col 4 must render live traffic rates');
assert.strictEqual(row0.children[5].textContent, '0', 'col 5 must render 0 drops');
assert.strictEqual(row0.children[6].textContent, '12/100', 'col 6 must render queue occupancy/capacity');
assert(row0.children[7].textContent.includes('Active'), 'col 7 must render Active status badge');
assert(row0.children[7].innerHTML.includes('badge-success'), 'col 7 must render badge-success for connected session');

// Row 1 (bob - degraded correlated route):
const row1 = tbody.children[1];
assert.strictEqual(row1.children.length, 8);
assert(row1.children[0].textContent.includes('bob'));
assert(row1.children[5].innerHTML.includes('text-danger'), 'packet loss must be highlighted with text-danger');
assert(row1.children[5].textContent.includes('2.4 drops/s'), 'loss rate column must render drop rate pps');
assert(row1.children[5].textContent.includes('15'), 'drops count must be 15');
assert(row1.children[6].innerHTML.includes('badge-warn'), 'queue pressure must be styled with badge-warn');
assert.strictEqual(row1.children[6].textContent, '90/100');
assert(row1.children[7].innerHTML.includes('badge-warn'), 'degraded route must reflect degraded status badge');
assert(row1.children[7].textContent.includes('Degraded'), 'status text must show Degraded');

// Row 2 (charlie - active session without route):
const row2 = tbody.children[2];
assert.strictEqual(row2.children.length, 8);
assert(row2.children[0].textContent.includes('charlie'));
assert.strictEqual(row2.children[4].textContent, '-', 'traffic must be dash when route is absent');
assert.strictEqual(row2.children[5].textContent, '-', 'loss must be dash when route is absent');
assert.strictEqual(row2.children[6].textContent, '-', 'pressure must be dash when route is absent');
assert(row2.children[7].textContent.includes('Unroutable'), 'active session without route must reflect unroutable status badge');
assert(row2.children[7].innerHTML.includes('badge-warn'), 'unroutable session must have badge-warn');

// Row 3 (dan - nominal session with historical drops):
const row3 = tbody.children[3];
assert.strictEqual(row3.children.length, 8);
assert(row3.children[0].textContent.includes('dan'));
assert.strictEqual(row3.children[5].textContent, '10', 'historical drops must render count');
assert(!row3.children[5].innerHTML.includes('text-danger'), 'historical drops alone must NOT have text-danger styling');
assert(row3.children[7].textContent.includes('Active'), 'session with only historical drops must remain Active status');
assert(row3.children[7].innerHTML.includes('badge-success'), 'nominal session with historical drops must have badge-success');

// Assertion 2: Expandable drilldown with 4 telemetry cards
vpnToggleSessionDrilldown(sessions[0], tbody.children[0]);
assert(vpnExpandedSessionIds.has('sess-1'), 'session ID must be tracked in expanded set');
assert(tbody.children[0].classList.contains('row-expanded'), 'row must gain row-expanded class');
assert.strictEqual(tbody.children.length, 5, 'tbody must have drilldown row inserted');
const drilldown0 = tbody.children[1];
assert(drilldown0.className.includes('vpn-session-drilldown-row'), 'drilldown row must have correct class');
assert.strictEqual(drilldown0.children[0].colSpan, 8, 'drilldown td must span all 8 columns');

// 4 cards in drilldown:
assert(drilldown0.innerHTML.includes('Latency Reservoirs'), 'drilldown must contain Latency Reservoirs card');
assert(drilldown0.textContent.includes('4.2 ms'), 'drilldown must show p95 reservoir latency');
assert(drilldown0.textContent.includes('100'), 'drilldown must show samples count');
assert(drilldown0.textContent.includes('12.5 ms'), 'drilldown must show max latency');

assert(drilldown0.innerHTML.includes('Queue Dwell & Buffer'), 'drilldown must contain Queue Dwell card');
assert(drilldown0.textContent.includes('12 / 100'), 'drilldown must show queue occupancy');
assert(drilldown0.textContent.includes('45'), 'drilldown must show high water mark');
assert(drilldown0.textContent.includes('Dwell p95: -'), 'drilldown must show dash for unpopulated dwell');

assert(drilldown0.innerHTML.includes('Errors & Stalls'), 'drilldown must contain Errors & Stalls card');
assert(drilldown0.textContent.includes('Stalls: 0'), 'drilldown must show write stalls');
assert(drilldown0.textContent.includes('Errors: 0'), 'drilldown must show write errors');
assert(drilldown0.textContent.includes('In-Flight: 1'), 'drilldown must show writes in-flight');

assert(drilldown0.innerHTML.includes('Traffic Details'), 'drilldown must contain Traffic Details card');
assert(drilldown0.textContent.includes('1 MB') || drilldown0.textContent.includes('1.00 MB') || drilldown0.textContent.includes('1048576'), 'drilldown must show traffic bytes');
assert(drilldown0.textContent.includes('1.00 Mbps'), 'drilldown must show traffic rate');

// Collapse alice's drilldown
vpnToggleSessionDrilldown(sessions[0], tbody.children[0]);
assert(!vpnExpandedSessionIds.has('sess-1'), 'session ID must be removed on collapse');
assert(!tbody.children[0].classList.contains('row-expanded'), 'row-expanded class must be removed');
assert.strictEqual(tbody.children.length, 4, 'drilldown row must be removed from tbody');

// Assertion 3: Expandable drilldown for session without route displays vpn_drilldown_no_telemetry
const charlieRow = tbody.children[2];
vpnToggleSessionDrilldown(sessions[2], charlieRow);
assert.strictEqual(tbody.children.length, 5, 'charlie drilldown row must be inserted');
const charlieDrilldown = tbody.children[3];
assert(charlieDrilldown.textContent.includes('Forwarder route telemetry not available for this session'), 'must display no-telemetry notice');
// Collapse charlie
vpnToggleSessionDrilldown(sessions[2], charlieRow);
assert.strictEqual(tbody.children.length, 4);

// Assertion 4: Problem filter toggle
// Filter ON:
vpnToggleSessionsProblemFilter();
assert.strictEqual(vpnSessionsFilterOnlyProblems, true, 'filter flag must be true');
assert(filterBtn.classList.contains('btn-primary'), 'filter button must gain btn-primary');
assert.strictEqual(filterText.textContent, 'All Connections', 'filter button text must toggle to show all');
assert.strictEqual(tbody.children.length, 2, 'degraded bob and unroutable charlie must remain in problem filter');
assert(tbody.children[0].textContent.includes('bob'), 'bob must be visible in problem filter');
assert(tbody.children[1].textContent.includes('charlie'), 'unroutable charlie must be visible in problem filter');
assert(!Array.from(tbody.children).some(r => r.textContent.includes('alice')), 'Alice must be excluded from problems only filter');
assert(!Array.from(tbody.children).some(r => r.textContent.includes('dan')), 'Dan must be excluded from problems only filter');

// Filter OFF:
vpnToggleSessionsProblemFilter();
assert.strictEqual(vpnSessionsFilterOnlyProblems, false, 'filter flag must be false');
assert(filterBtn.classList.contains('btn-ghost'), 'filter button must gain btn-ghost');
assert.strictEqual(filterText.textContent, 'Problems Only', 'filter button text must toggle to problems only');
assert.strictEqual(tbody.children.length, 4, 'all sessions must return');

// Assertion 5: Forwarder polling sync re-renders session route metrics
vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.2',
            connection_id: '101',
            session_id: 'sess-1',
            occupancy: 95,
            capacity: 100,
            drops: 42,
            queue_full_drops_recent: 12,
            has_pressure: true,
            traffic: { rx_bps: 4000000, tx_bps: 8000000 }
        }
    ]
};
vpnRenderForwarderHealth(vpnLastStatus);
assert.strictEqual(tbody.children.length, 4);
const updatedAlice = tbody.children[0];
assert(updatedAlice.children[4].textContent.includes('4.00 Mbps') && updatedAlice.children[4].textContent.includes('8.00 Mbps'), 'live traffic must be synced with status refresh');
assert(updatedAlice.children[5].innerHTML.includes('text-danger'), 'packet loss alarm must update dynamically');
assert(updatedAlice.children[6].innerHTML.includes('badge-warn'), 'queue pressure must update dynamically');
assert.strictEqual(updatedAlice.children[6].textContent, '95/100');
assert(updatedAlice.children[7].innerHTML.includes('badge-warn'), 'status must update to Degraded dynamically');

// Assertion 6: Correlation priority ordering (session_id > connection_id > assigned_ip)
const routeSessionMatch = { session_id: 'sess-prio', connection_id: 'conn-other', assigned_ip: '10.8.0.200' };
const routeIPMatch = { session_id: 'sess-diff', connection_id: 'conn-diff', assigned_ip: '10.8.0.100' };
vpnLastStatus = { forwarder_available: true, all_routes: [routeIPMatch, routeSessionMatch] };

const sessWithPrio = { session_id: 'sess-prio', connection_id: 'conn-x', assigned_ip: '10.8.0.100' };
assert.strictEqual(vpnFindRouteForSession(sessWithPrio), routeSessionMatch, 'session ID match must take precedence over IP match');

// Connection ID fallback permitted when session ID is absent on one side
const routeConnMatch = { connection_id: 'conn-prio', assigned_ip: '10.8.0.250' };
vpnLastStatus = { forwarder_available: true, all_routes: [routeSessionMatch, routeConnMatch] };
const sessWithConnPrio = { session_id: 'sess-unmatched', connection_id: 'conn-prio', assigned_ip: '10.8.0.200' };
assert.strictEqual(vpnFindRouteForSession(sessWithConnPrio), routeConnMatch, 'connection ID match must take precedence over IP match when session ID absent on route');

// Contradictory session IDs strictly disqualify connection ID fallback
const routeContradictoryConn = { session_id: 'sess-route-diff', connection_id: 'conn-same', assigned_ip: '10.8.0.251' };
vpnLastStatus = { forwarder_available: true, all_routes: [routeContradictoryConn] };
const sessContradictoryConn = { session_id: 'sess-client-diff', connection_id: 'conn-same', assigned_ip: '10.8.0.251' };
assert.strictEqual(vpnFindRouteForSession(sessContradictoryConn), null, 'contradictory session IDs must strictly disqualify connection ID fallback');

// Hardened correlation: Different connection IDs but identical IP do NOT match
const routeDiffConnSameIP = { connection_id: 'conn-route-99', assigned_ip: '10.8.0.150' };
vpnLastStatus = { forwarder_available: true, all_routes: [routeDiffConnSameIP] };
const sessDiffConnSameIP = { connection_id: 'conn-sess-11', assigned_ip: '10.8.0.150' };
assert.strictEqual(vpnFindRouteForSession(sessDiffConnSameIP), null, 'session and route with different connection IDs but identical IP must NOT match');

// Hardened correlation: Different session IDs but identical IP do NOT match
const routeDiffSessSameIP = { session_id: 'sess-route-99', assigned_ip: '10.8.0.151' };
vpnLastStatus = { forwarder_available: true, all_routes: [routeDiffSessSameIP] };
const sessDiffSessSameIP = { session_id: 'sess-sess-11', assigned_ip: '10.8.0.151' };
assert.strictEqual(vpnFindRouteForSession(sessDiffSessSameIP), null, 'session and route with different session IDs but identical IP must NOT match');

// Durable IDs absent on both sides: match on IP fallback
const routeNoDurableSameIP = { assigned_ip: '10.8.0.152' };
vpnLastStatus = { forwarder_available: true, all_routes: [routeNoDurableSameIP] };
const sessNoDurableSameIP = { assigned_ip: '10.8.0.152' };
assert.strictEqual(vpnFindRouteForSession(sessNoDurableSameIP), routeNoDurableSameIP, 'session and route without durable IDs must match on IP fallback');
`

	script := vpnConnectionTroubleshootingScriptLocale(t, tmplStr, "en", enAssertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("English connection troubleshooting table test failed: %v\n%s", err, out)
	}

	// 2. Russian locale assertions: table headers, problem button, drilldown titles, and degraded status
	ruAssertions := `
const tbody = document.getElementById('vpn-sessions-tbody');
const filterBtn = document.getElementById('vpn-sessions-toggle-problems-btn');
const filterText = document.getElementById('vpn-sessions-toggle-problems-text');

vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.10',
            connection_id: '201',
            session_id: 'sess-ru-1',
            occupancy: 88,
            capacity: 100,
            drops: 8,
            queue_full_drops_recent: 2,
            has_pressure: true,
            traffic: { rx_bps: 1000000, tx_bps: 2000000 },
            reservoir: { p95_ms: 15.0, samples: 50, max_ms: 30.0 },
            high_water: 90,
            queue_dwell_p95_ms: 12.0,
            write_stalls: 1,
            write_errors: 0,
            writes_in_flight: 2
        }
    ]
};

const sessions = [
    {
        id: 1,
        session_id: 'sess-ru-1',
        connection_id: '201',
        username: 'иван',
        connection_name: 'иван-офис',
        server_name: 'Москва-1',
        assigned_ip: '10.8.0.10',
        status: 'connected'
    },
    {
        id: 2,
        session_id: 'sess-ru-2',
        connection_id: '202',
        username: 'петр',
        connection_name: 'петр-дом',
        server_name: 'Москва-1',
        assigned_ip: '10.8.0.20',
        status: 'connected'
    }
];

vpnLastSessions = { sessions: sessions };
renderSessions(sessions);

// Russian problem filter button text
vpnToggleSessionsProblemFilter();
assert.strictEqual(filterText.textContent, 'Все подключения', 'toggled filter text in Russian');
vpnToggleSessionsProblemFilter();
assert.strictEqual(filterText.textContent, 'Только с проблемами', 'reverted filter text in Russian');

// Russian degraded status badge
const row0 = tbody.children[0];
assert(row0.children[7].textContent.includes('Деградировано'), 'Russian degraded status label');

// Russian unroutable status badge for session without route
const row1Before = tbody.children[1];
assert(row1Before.children[7].textContent.includes('Немаршрутизируемый'), 'Russian unroutable status label');
assert(row1Before.children[7].innerHTML.includes('badge-warn'));

// Russian drilldown cards titles
vpnToggleSessionDrilldown(sessions[0], row0);
const drilldownRow = tbody.children[1];
assert(drilldownRow.innerHTML.includes('Резервуары задержки'), 'Russian drilldown reservoir card');
assert(drilldownRow.innerHTML.includes('Буфер и задержка в очереди'), 'Russian drilldown dwell card');
assert(drilldownRow.innerHTML.includes('Ошибки и задержки записи'), 'Russian drilldown stalls card');
assert(drilldownRow.innerHTML.includes('Детализация трафика'), 'Russian drilldown traffic card');

// Russian drilldown fallback when no telemetry
const row1 = tbody.children[2];
vpnToggleSessionDrilldown(sessions[1], row1);
const drilldown1 = tbody.children[3];
assert(drilldown1.textContent.includes('Телеметрия маршрута форвардера недоступна для этой сессии'), 'Russian drilldown no-telemetry fallback');
`

	ruScript := vpnConnectionTroubleshootingScriptLocale(t, tmplStr, "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian connection troubleshooting table test failed: %v\n%s", err, out)
	}

	// 3. Rendered template localized headers verification in Russian
	ruDict := vpnDiagnosticsLocale(t, "ru")
	renderedHTML := vpnDiagnosticsRenderedHTML(t, tmplStr, ruDict)
	for _, expectedRussianHeader := range []string{
		"Текущий трафик",
		"Потеря пакетов",
		"Нагрузка на очередь",
		"Диагностика подключений",
		"Только с проблемами",
	} {
		if !strings.Contains(renderedHTML, expectedRussianHeader) {
			t.Fatalf("rendered Russian template missing header %q", expectedRussianHeader)
		}
	}
}

func TestVPNHorizonWindowToggles1mAnd5m(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

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

	script := vpnDOMMock(t, tmplStr) + "\n" + vpnDiagnosticsTranslationsJS(t, tmplStr, "en")
	for _, name := range []string{"vpnGenerateSparklineSVG", "vpnLossReasonLabels", "vpnDiagText", "vpnRenderHistoryCharts", "vpnSetHistoryWindow"} {
		fn, err := extractJSFunction(tmplStr, "function "+name)
		if err != nil {
			t.Fatalf("extractJSFunction %s: %v", name, err)
		}
		script += "\n" + fn
	}
	script += "\nlet vpnHistoryWindow = '15m';\nlet vpnLastStatus = null;\n" + assertions

	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("1m and 5m horizon window toggles test failed: %v\n%s", err, out)
	}
}

func TestVPNSummaryHeaderCountsAndProblemCardOnset(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

	assertions := `
const el = id => document.getElementById(id);

// 1. Degraded forwarder with 2 actionable problems across 1 user and 2 connection configs
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Packet loss observed on active connections',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Buffer pressure on forwarder route',
				category: 'routing',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-1',
				connection_name: 'alice-phone',
				assigned_ip: '10.8.0.2',
				first_observed: '2026-10-07T12:30:00Z'
			},
			{
				severity: 'CRITICAL',
				message: 'Buffer full drops active',
				category: 'dataplane',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-2',
				connection_name: 'alice-laptop',
				assigned_ip: '10.8.0.3',
				first_observed: '2026-10-07T12:35:00Z'
			}
		]
	}
});

// Assert Summary Header Counts
const summaryHeader = el('vpn-fwd-summary-header');
assert(summaryHeader, 'summary header element must exist');
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when problems exist');
assert(summaryHeader.textContent.includes('2 active problems'), 'must show 2 active problems');
assert(summaryHeader.textContent.includes('1 affected users'), 'must show 1 unique affected user');
assert(summaryHeader.textContent.includes('2 client configs'), 'must show 2 unique affected client configs');
assert(summaryHeader.innerHTML.includes('badge-warn'), 'summary header must have badge styling');

// Assert Problem Card Onset Timestamps
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 2, 'must render 2 problem cards');

const card0 = problemList.children[0];
assert(card0.className.includes('problem-card'), 'card 0 must have problem-card class');
assert(card0.textContent.includes('Onset:'), 'card 0 must render onset label');
assert(card0.textContent.includes('2026-10-07 12:30:00 UTC'), 'card 0 must render first_observed timestamp');
assert(card0.textContent.includes('Config: alice-phone'));
assert(card0.textContent.includes('User: alice'));

const card1 = problemList.children[1];
assert(card1.className.includes('problem-card'), 'card 1 must have problem-card class');
assert(card1.textContent.includes('Onset:'), 'card 1 must render onset label');
assert(card1.textContent.includes('2026-10-07 12:35:00 UTC'), 'card 1 must render first_observed timestamp');
assert(card1.textContent.includes('Config: alice-laptop'));
assert(card1.textContent.includes('User: alice'));

// 2. Nominal forwarder (0 problems): summary header must be hidden, nominal green badge rendered
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'HEALTHY',
		conditions: []
	},
	peer_sync: { actual_peers: 5, desired_peers: 5 },
	backends: { healthy_count: 2, total_count: 2 }
});

assert.strictEqual(summaryHeader.style.display, 'none', 'summary header must be hidden when healthy (0 problems)');
assert.strictEqual(problemList.children.length, 1);
const greenBadge = problemList.children[0];
assert(greenBadge.className.includes('badge-success'), 'nominal summary must have badge-success class');
assert(greenBadge.textContent.includes('No active problems detected'), 'nominal green badge text must show when 0 problems');

// 3. Unavailable forwarder: summary header must be hidden
vpnRenderForwarderHealth(null);
assert.strictEqual(summaryHeader.style.display, 'none', 'summary header must be hidden when unavailable');

// 4. Degraded forwarder with generic conditions but empty actionable_problems: summary header must display active problems count from conditions
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Fleet degradation detected',
		conditions: [
			{ severity: 'DEGRADED', message: 'High packet loss on gateway', category: 'dataplane' },
			{ severity: 'WARN', message: 'Queue pressure elevated', category: 'routing' },
			{ severity: 'DEGRADED', message: 'Backend latency elevated', category: 'backends' }
		],
		actionable_problems: []
	}
});

assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when conditions exist during degradation');
assert(summaryHeader.textContent.includes('3 active problems'), 'summary header must show 3 active problems from conditions');
assert(summaryHeader.textContent.includes('0 affected users'), 'affected users count must be 0 in conditions fallback');
assert(summaryHeader.textContent.includes('0 client configs'), 'affected client configs count must be 0 in conditions fallback');
assert(summaryHeader.innerHTML.includes('badge-warn'), 'summary header must retain badge styling');

// 5. Critical forwarder with 1 condition and missing actionable_problems: summary header fallback
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		summary: 'Critical failure',
		conditions: [
			{ severity: 'CRITICAL', message: 'Listener stopped' }
		]
	}
});
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when critical with condition');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must show 1 active problem from condition');
assert(summaryHeader.textContent.includes('0 affected users'), 'affected users count must be 0 in conditions fallback');
assert(summaryHeader.textContent.includes('0 client configs'), 'affected client configs count must be 0 in conditions fallback');

// 6. Warning-only condition with empty actionable_problems: summary header must display active problems count
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'HEALTHY',
		summary: 'Warning condition present',
		conditions: [
			{ severity: 'WARNING', message: 'Cert expiring soon', category: 'cert' }
		],
		actionable_problems: []
	}
});
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed when warning condition exists');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must show 1 active problem from warning condition');
assert(summaryHeader.textContent.includes('0 affected users'), 'affected users count must be 0 in conditions fallback');
assert(summaryHeader.textContent.includes('0 client configs'), 'affected client configs count must be 0 in conditions fallback');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("summary header counts and onset timestamp test failed: %v\n%s", err, out)
	}
}

func TestVPNForwarderCombinedActionableAndGenericConditions(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

	assertions := `
const el = id => document.getElementById(id);

// Critical backend condition occurring simultaneously with a degraded route
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'CRITICAL',
		summary: 'Active VPN session routing or dataplane issues detected',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Return queue full drops (5 recent) for 10.8.0.2',
				category: 'dataplane',
				user_id: 'usr-1',
				username: 'alice',
				connection_id: 'conn-1',
				connection_name: 'alice-phone',
				assigned_ip: '10.8.0.2',
				backend_id: 1,
				observed_rate: '2.5 drops/s',
				first_observed: '2026-10-08T10:00:00Z'
			}
		],
		conditions: [
			{
				severity: 'CRITICAL',
				message: 'No healthy backends available to route traffic',
				category: 'backend'
			}
		]
	}
});

// 1. Assert Summary Header Counts both classes of problems
const summaryHeader = el('vpn-fwd-summary-header');
assert(summaryHeader, 'summary header element must exist');
assert.strictEqual(summaryHeader.style.display, 'block', 'summary header must be displayed');
assert(summaryHeader.textContent.includes('2 active problems'), 'summary header must count both classes: 1 actionable + 1 condition = 2 active problems');
assert(summaryHeader.textContent.includes('1 affected users'), 'summary header must count 1 affected user from actionable problem');
assert(summaryHeader.textContent.includes('1 client configs'), 'summary header must count 1 client config from actionable problem');

// 2. Assert Both Problem Cards are rendered in #vpn-fwd-problem-list
const problemList = el('vpn-fwd-problem-list');
assert.strictEqual(problemList.children.length, 2, 'problem list must render both problem cards');

const card0 = problemList.children[0];
assert(card0.className.includes('problem-card'), 'card 0 must have problem-card class');
assert.strictEqual(card0.children[0].textContent, 'Degraded', 'card 0 severity must be Degraded');
assert.strictEqual(card0.children[1].textContent, 'Return queue full drops (5 recent) for 10.8.0.2');
assert(card0.textContent.includes('User: alice'));
assert(card0.textContent.includes('Config: alice-phone'));
assert(card0.textContent.includes('IP: 10.8.0.2'));
assert(card0.textContent.includes('2.5 drops/s'));

const card1 = problemList.children[1];
assert(card1.className.includes('problem-card'), 'card 1 must have problem-card class');
assert.strictEqual(card1.children[0].textContent, 'Critical', 'card 1 severity must be Critical');
assert.strictEqual(card1.children[1].textContent, 'No healthy backends available to route traffic');
assert(card1.textContent.includes('backend'));

// 3. Deduplication: exact duplicate condition must not be rendered twice
vpnRenderForwarderHealth({
	forwarder_available: true,
	health_assessment: {
		status: 'DEGRADED',
		summary: 'Degraded',
		actionable_problems: [
			{
				severity: 'DEGRADED',
				message: 'Duplicate event message',
				category: 'dataplane'
			}
		],
		conditions: [
			{
				severity: 'DEGRADED',
				message: 'Duplicate event message',
				category: 'dataplane'
			}
		]
	}
});
assert.strictEqual(problemList.children.length, 1, 'duplicate event must not render redundant card');
assert(summaryHeader.textContent.includes('1 active problems'), 'summary header must count 1 active problem when deduplicated');
`

	script := vpnDiagnosticsHealthScript(t, tmplStr, assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("combined actionable and generic conditions test failed: %v\n%s", err, out)
	}
}

func TestVPNTranslationKeyParity(t *testing.T) {
	transFS, err := GetTranslationsSubFS()
	if err != nil {
		t.Fatalf("GetTranslationsSubFS failed: %v", err)
	}

	languages := []string{"en.json", "fa.json", "fr.json", "ru.json", "zh.json"}
	dicts := make(map[string]map[string]string)
	for _, langFile := range languages {
		data, err := fs.ReadFile(transFS, langFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", langFile, err)
		}
		var dict map[string]string
		if err := json.Unmarshal(data, &dict); err != nil {
			t.Fatalf("failed to parse %s as JSON: %v", langFile, err)
		}
		dicts[langFile] = dict
	}

	baseKeys := dicts["en.json"]
	for _, langFile := range languages[1:] {
		curDict := dicts[langFile]
		if len(curDict) != len(baseKeys) {
			t.Errorf("key count mismatch between en.json (%d) and %s (%d)", len(baseKeys), langFile, len(curDict))
		}
		for k, baseVal := range baseKeys {
			val, ok := curDict[k]
			if !ok {
				t.Errorf("%s is missing key %q present in en.json", langFile, k)
			} else if strings.TrimSpace(val) == "" {
				t.Errorf("%s has empty translation for key %q", langFile, k)
			}
			for _, ph := range []string{"%s", "%d"} {
				if strings.Contains(baseVal, ph) && !strings.Contains(val, ph) {
					t.Errorf("%s key %q missing placeholder %q from en.json: %q vs %q", langFile, k, ph, val, baseVal)
				}
			}
		}
		for k := range curDict {
			if _, ok := baseKeys[k]; !ok {
				t.Errorf("%s has extra key %q not present in en.json", langFile, k)
			}
		}
	}

	newKeys := []string{
		"vpn_fwd_onset",
		"vpn_fwd_active_problems_count",
		"vpn_fwd_affected_users_count",
		"vpn_fwd_affected_configs_count",
		"vpn_fwd_loss_rate_format",
		"vpn_fwd_recent",
		"vpn_diag_summary_actionable_issues",
		"vpn_fwd_user_prefix",
		"vpn_fwd_config_prefix",
		"vpn_fwd_ip_prefix",
		"vpn_fwd_backend_prefix",
		"vpn_problem_session_without_route",
		"vpn_problem_route_queue_drops",
		"vpn_problem_write_stall",
		"vpn_problem_write_errors",
		"vpn_problem_route_queue_pressure",
	}
	for _, langFile := range languages {
		for _, k := range newKeys {
			val, ok := dicts[langFile][k]
			if !ok || strings.TrimSpace(val) == "" {
				t.Errorf("%s missing or empty required key %q", langFile, k)
			}
			if strings.Contains(val, "\u2014") {
				t.Errorf("%s new key %q contains prohibited em dash (\\u2014): %q", langFile, k, val)
			}
		}
	}
}

func TestVPNPacketLossCellDecoupledFromQueuePressure(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

	assertions := `
const tbody = document.getElementById('vpn-sessions-tbody');

// Route 1: Dan has historical drops (10) and queue pressure (occupancy 95/100, has_pressure: true),
// but ZERO recent drops and ZERO drop rate pps.
// Loss cell MUST NOT be red (no text-danger). Pressure cell MUST have badge-warn.
// Route 2: Eve has recent drops (5 recent out of 20 total, no pps rate).
// Loss cell MUST be red (text-danger) and use localized "recent" word.
vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.4',
            connection_id: '104',
            session_id: 'sess-dan',
            occupancy: 95,
            capacity: 100,
            drops: 10,
            queue_full_drops_recent: 0,
            queue_full_drop_rate_pps: 0,
            has_pressure: true
        },
        {
            assigned_ip: '10.8.0.5',
            connection_id: '105',
            session_id: 'sess-eve',
            occupancy: 10,
            capacity: 100,
            drops: 20,
            queue_full_drops_recent: 5,
            queue_full_drop_rate_pps: 0,
            has_pressure: false
        }
    ]
};

const sessions = [
    {
        id: 1,
        session_id: 'sess-dan',
        connection_id: '104',
        username: 'dan',
        connection_name: 'dan-phone',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.4',
        status: 'connected'
    },
    {
        id: 2,
        session_id: 'sess-eve',
        connection_id: '105',
        username: 'eve',
        connection_name: 'eve-laptop',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.5',
        status: 'connected'
    }
];

vpnLastSessions = { sessions: sessions };
renderSessions(sessions);

assert.strictEqual(tbody.children.length, 2, 'table must render 2 session rows');

// Row 0: Dan (historical drops + queue pressure)
const rowDan = tbody.children[0];
const lossDan = rowDan.children[5];
const pressureDan = rowDan.children[6];

// Loss cell MUST NOT be colored red
assert.strictEqual(lossDan.textContent, '10', 'Dan loss cell must display historical drops count 10');
assert(!lossDan.innerHTML.includes('text-danger'), 'Dan loss cell must NOT be red when only historical drops + pressure');

// Pressure cell MUST have warning badge
assert(pressureDan.innerHTML.includes('badge-warn'), 'Dan pressure cell must have badge-warn');
assert.strictEqual(pressureDan.textContent, '95/100', 'Dan pressure cell must show 95/100');

// Row 1: Eve (recent drops without pps rate)
const rowEve = tbody.children[1];
const lossEve = rowEve.children[5];

// Loss cell MUST be colored red with localized format
assert(lossEve.innerHTML.includes('text-danger'), 'Eve loss cell must have text-danger styling for recent drops');
assert(lossEve.textContent.includes('5 recent (20)'), 'Eve loss cell must format as "5 recent (20)"');
`

	script := vpnConnectionTroubleshootingScriptLocale(t, tmplStr, "en", assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("packet loss decoupling test (en) failed: %v\n%s", err, out)
	}

	// Also verify Russian translation of fallback format "5 недавних (20)"
	ruAssertions := `
const tbody = document.getElementById('vpn-sessions-tbody');
vpnLastStatus = {
    forwarder_available: true,
    all_routes: [
        {
            assigned_ip: '10.8.0.5',
            connection_id: '105',
            session_id: 'sess-eve',
            occupancy: 10,
            capacity: 100,
            drops: 20,
            queue_full_drops_recent: 5,
            queue_full_drop_rate_pps: 0,
            has_pressure: false
        }
    ]
};
const sessions = [
    {
        id: 1,
        session_id: 'sess-eve',
        connection_id: '105',
        username: 'eve',
        connection_name: 'eve-laptop',
        server_name: 'Frankfurt-1',
        assigned_ip: '10.8.0.5',
        status: 'connected'
    }
];
vpnLastSessions = { sessions: sessions };
renderSessions(sessions);

const lossEve = tbody.children[0].children[5];
assert(lossEve.innerHTML.includes('text-danger'), 'Russian: Eve loss cell must have text-danger');
assert(lossEve.textContent.includes('5 недавних (20)'), 'Russian: Eve loss cell must use localized "недавних"');
`
	ruScript := vpnConnectionTroubleshootingScriptLocale(t, tmplStr, "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("packet loss decoupling test (ru) failed: %v\n%s", err, out)
	}
}

func TestVPNReconnectSessionIDMismatchShowsUnroutable(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

	assertions := `
const tbody = document.getElementById('vpn-sessions-tbody');

// Old route from previous connection
const oldRoute = {
    session_id: 'old-123',
    connection_id: 101,
    drops: 25,
    queue_full_drops_recent: 10,
    has_pressure: true,
    assigned_ip: '10.8.0.101'
};

// New reconnected session
const newSession = {
    id: 1,
    session_id: 'new-456',
    connection_id: 101,
    username: 'alice',
    connection_name: 'alice-phone',
    server_name: 'Frankfurt-1',
    assigned_ip: '10.8.0.101',
    status: 'connected'
};

vpnLastStatus = {
    forwarder_available: true,
    all_routes: [oldRoute]
};
const sessions = [newSession];
vpnLastSessions = { sessions: sessions };

// 1. vpnFindRouteForSession must return null due to contradictory session IDs
assert.strictEqual(vpnFindRouteForSession(newSession), null, 'vpnFindRouteForSession must return null when session IDs contradict');

// 2. Render all sessions
renderSessions(sessions);
assert.strictEqual(tbody.children.length, 1, 'tbody must have 1 session row');
const row = tbody.children[0];

// Assert drops column does NOT inherit the old route's drops (drops: 25)
const dropsCell = row.children[5];
assert.strictEqual(dropsCell.textContent, '-', 'unroutable session must have dash for drops without inheriting old route telemetry');

// Assert status column renders with Unroutable badge
const statusCell = row.children[7];
assert(statusCell.textContent.includes('Unroutable'), 'session without matching route must show Unroutable status badge');
assert(statusCell.innerHTML.includes('badge-warn'), 'unroutable status badge must have badge-warn');

// 3. Switch to "Problems Only" filter
vpnToggleSessionsProblemFilter();
assert.strictEqual(tbody.children.length, 1, 'unroutable session must appear under Problems Only filter');
const probRow = tbody.children[0];
assert(probRow.children[7].textContent.includes('Unroutable'), 'session in Problems Only must show Unroutable status');
`

	script := vpnConnectionTroubleshootingScriptLocale(t, tmplStr, "en", assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("TestVPNReconnectSessionIDMismatchShowsUnroutable failed: %v\n%s", err, out)
	}
}

func TestVPNNexusTableLifecycleDrilldownAndConfigDedup(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal("Node is required for diagnostics verification")
	}
	source, err := TemplatesFS.ReadFile("templates/vpn.html")
	if err != nil {
		t.Fatal(err)
	}
	tmplStr := string(source)

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
// Ensure JSDOM is discoverable
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

function extract(name) {
    const start = source.indexOf('    function ' + name + '(');
    assert(start >= 0, 'function not found: ' + name);
    const rest = source.slice(start + 1);
    const match = /^    (?:async )?function /m.exec(rest);
    return source.slice(start, match ? start + 1 + match.index : source.indexOf('</script>', start));
}

const dom = new JSDOM(source.slice(0, source.indexOf('<script>')), { runScripts: 'outside-only', url: 'https://review.invalid' });
const w = dom.window;
w.eval('const translations = ' + JSON.stringify(en) + ';' +
'function _(key) { return translations[key] || key; };' +
'function escapeHtml(s) { const el = document.createElement("div"); el.textContent = String(s == null ? "" : s); return el.innerHTML; };' +
'const UI = { escapeHtml };' +
'var vpnLastSessions = null, vpnLastStatus = null;' +
'var vpnSessionsStale = false, vpnSessionsFilterOnlyProblems = false;' +
'var vpnExpandedSessionIds = new Set(), vpnSessionsTableInstance = null;' +
'var vpnHistoryWindow = "15m";\n' +
[
    'fmtBps', 'fmtPps', 'vpnStatusLabel', 'vpnFormatBytes', 'vpnFormatPeerKey',
    'vpnFindRouteForSession', 'vpnRenderSessionRow', 'vpnCreateSessionDrilldownRow',
    'vpnToggleSessionDrilldown', 'vpnToggleSessionsProblemFilter', 'vpnRenderSessionsStaleBanner',
    'vpnFindSessionById', 'vpnSyncExpandedDrilldowns', 'vpnWrapSessionsTableRender',
    'renderSessions', 'vpnDiagText', 'vpnLossReasonLabels', 'vpnRenderForwarderHealth'
].map(extract).join('\n'));

w.eval(tablesCode);

(async function() {
    const sessions = [
        {id:'s-z',user_id:'u-z',username:'zulu',connection_id:'c-z',connection_name:'default',assigned_ip:'Client Z',status:'connected'},
        {id:'s-a',user_id:'u-a',username:'alpha',connection_id:'c-a',connection_name:'default',assigned_ip:'Client A',status:'connected'},
        {id:'s-b',user_id:'u-b',username:'bravo',connection_id:'c-b',connection_name:'default',assigned_ip:'Client B',status:'connected'}
    ];
    w.vpnLastSessions = {sessions: sessions};
    w.vpnLastStatus = {
        forwarder_available: true,
        all_routes: sessions.map(s => ({
            session_id: s.id,
            connection_id: s.connection_id,
            assigned_ip: s.assigned_ip,
            occupancy: 0,
            capacity: 100,
            has_pressure: false,
            traffic: { available: true, rx_bps: 0, tx_bps: 0 }
        }))
    };

    w.renderSessions(sessions);
    const tbody = w.document.getElementById('vpn-sessions-tbody');
    function rowOrder() {
        return Array.from(tbody.children).filter(r => r.style.display !== 'none').map(r => r.classList.contains('vpn-session-drilldown-row') ? 'DETAIL' : r.cells[0]?.textContent.trim());
    }

    // 1. Sort ascending
    w.document.querySelector('#vpnSessionsTable thead th').click();
    assert.deepStrictEqual(rowOrder(), ['alpha', 'bravo', 'zulu'], 'table must sort ascending by user');

    // 2. Expand alpha
    const alpha = Array.from(tbody.children).find(r => r.cells[0]?.textContent.trim() === 'alpha');
    assert(alpha, 'alpha row must exist');
    alpha.cells[0].click();
    assert.deepStrictEqual(rowOrder(), ['alpha', 'DETAIL', 'bravo', 'zulu'], 'detail row must follow alpha');
    assert.strictEqual(alpha.nextElementSibling?.classList.contains('vpn-session-drilldown-row'), true, 'detail row must be adjacent to alpha');

    // 3. Polling refresh
    w.renderSessions(sessions);
    assert.deepStrictEqual(rowOrder(), ['alpha', 'DETAIL', 'bravo', 'zulu'], 'order must be preserved after poll refresh');
    const alphaAfterPoll = Array.from(tbody.children).find(r => r.cells[0]?.textContent.trim() === 'alpha');
    const detailAfterPoll = alphaAfterPoll?.nextElementSibling;
    assert.strictEqual(detailAfterPoll?.classList.contains('vpn-session-drilldown-row'), true, 'detail row must remain adjacent to parent after poll refresh');

    // 4. Search for alpha
    w.vpnSessionsTableInstance.searchInputEl.value = 'alpha';
    w.vpnSessionsTableInstance.searchInputEl.dispatchEvent(new w.Event('input'));
    await new Promise(r => setTimeout(r, 200));
    assert.deepStrictEqual(rowOrder(), ['alpha', 'DETAIL'], 'detail row must remain visible when parent matches search');

    // 5. Search for bravo (different user)
    w.vpnSessionsTableInstance.searchInputEl.value = 'bravo';
    w.vpnSessionsTableInstance.searchInputEl.dispatchEvent(new w.Event('input'));
    await new Promise(r => setTimeout(r, 200));
    assert.deepStrictEqual(rowOrder(), ['bravo'], 'detail row must be hidden when parent is filtered out by search');
    const detailRows = Array.from(tbody.querySelectorAll('.vpn-session-drilldown-row'));
    assert.strictEqual(detailRows.length, 1, 'must have 1 drilldown row');
    assert.strictEqual(detailRows[0].style.display, 'none', 'drilldown row must have display none when parent is hidden');

    // 6. Fix F2: Configuration deduplication by unique connection identity
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [],
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Loss A', user_id: 'u-a', username: 'alpha', connection_id: 'c-a', connection_name: 'default' },
                { severity: 'DEGRADED', message: 'Loss B', user_id: 'u-b', username: 'bravo', connection_id: 'c-b', connection_name: 'default' }
            ]
        }
    });
    const summaryHeader = w.document.getElementById('vpn-fwd-summary-header');
    assert(summaryHeader, 'summary header must exist');
    assert(summaryHeader.textContent.includes('2 client configs'), 'different connection_ids with common name default must count as 2 configs: ' + summaryHeader.textContent);
    assert(summaryHeader.textContent.includes('2 affected users'), 'must count 2 affected users: ' + summaryHeader.textContent);
    assert(summaryHeader.textContent.includes('2 active problems'), 'must count 2 active problems: ' + summaryHeader.textContent);

    console.log('PASS');
})().catch(e => {
    console.error(e);
    process.exit(1);
});
`, tmplStr, string(enData), string(tablesJS))

	out, err := execNodeScript(node, testScript)
	if err != nil {
		t.Fatalf("TestVPNNexusTableLifecycleDrilldownAndConfigDedup failed: %v\n%s", err, string(out))
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		t.Skip("jsdom is not available in Node environment")
	}
}
