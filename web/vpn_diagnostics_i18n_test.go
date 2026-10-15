package web

import (
	"bytes"
	"encoding/json"
	"html"
	"html/template"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func vpnDiagnosticsLocalizationScript(t *testing.T, source, lang string) string {
	t.Helper()
	script := vpnDOMMock(t, source) + "\n" + vpnDiagnosticsTranslationsJS(t, source, lang)
	for _, name := range []string{
		"vpnFormatTime", "vpnFormatPeerKey",
		"parseConditionMessage", "deriveStableConditionCode", "extractConditionEntities", "createSeverityBadge",
		"vpnRenderActiveProblemsCards", "vpnRenderTechDiagnosticCards",
		"vpnResetHealthProblems", "vpnResetTechDiagnosticCards",
		"vpnGenerateSparklineSVG", "vpnRenderHistoryCharts", "vpnRenderForwarderHealth",
		"vpnSetHistoryWindow", "vpnToggleShowAllRoutes",
	} {
		if strings.Contains(source, "function "+name+"(") || strings.Contains(source, "function "+name+" ") {
			function, err := extractJSFunction(source, "function "+name)
			if err != nil {
				t.Fatalf("extract %s failed: %v", name, err)
			}
			script += "\n" + function
		}
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
 drop_rates_available:true,drop_reason_rates:{return_queue_full:1,future_reason:1},fwd_p95_ms:0,fwd_p95_samples:1,
 be_p95_ms:0,be_latency_samples:1,backends:[{id:3,rx_bps:0,traffic_available:true,probe_latency_ms:0,probe_available:true}],backends_omitted:5};
const fixture={forwarder_available:true,forwarder_queue_capacity:100,listener_running:true,
 virtual_tun:{
  upstream_to_nexus:{occupancy:10,capacity:100,peak:20,drops:0},
  nexus_to_upstream:{occupancy:15,capacity:100,peak:25,drops:0}},
 health_assessment:{status:'HEALTHY',conditions:[]},rates:{available:false,rx_bps:999,tx_bps:999},
 drop_categories:{rates_available:false,total_drops:12},routing_consistency:{is_consistent:false,ownership_mismatch_drops:4,inconsistency_details:['Server detail']},
 problem_routes:[route],all_routes:[route],
 queue_pressure:{total_seconds_above_50:65,consecutive_above_50_sec:2,total_seconds_above_80:3600,consecutive_above_80_sec:0},
 forward_latency:{p95_health_samples:0,stalls_recent:2,stalls:8,p50_ms:1.5,p95_ms:2.5,p99_ms:3.5,max_ms:7,in_flight:2,oldest_in_flight_ms:9,write_total:10,write_errors:3,write_error_rate_pps:1.25},
 backends:{eligibility_known:true,healthy_count:1,enabled_count:2,total_count:3,disabled_count:1,latency_samples:0,backends:[
  {server_name:'Server < & "quote">',enabled:true,traffic_available:false},
  {server_name:'Server 2',enabled:true,health_state:'active',traffic_available:true},
  {server_name:'Server 3',enabled:true,health_state:'future_state',traffic_available:true},
  {server_name:'Server Disabled',enabled:false,traffic_available:true}]},
 historical_series:{window_15m:[point]},peer_sync:{desired_peers:1,actual_peers:1,sync_failures:3,sync_failures_recent:2}};
const original=JSON.stringify(fixture);
vpnRenderForwarderHealth(fixture);
assert.strictEqual(text('vpn-kpi-throughput'),E('vpn_diag_traffic_unavailable'),'traffic state');
assert.strictEqual(text('vpn-diag-throughput'),E('vpn_diag_traffic_unavailable'));
assert.strictEqual(text('vpn-kpi-packet-loss'),E('vpn_diag_with_cumulative',{value:E('vpn_diag_loss_unavailable'),count:12}),'unknown loss');
assert.strictEqual(text('vpn-kpi-client-engine'),E('vpn_diag_engine_state',{state:E('vpn_running')}),'engine running');
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (' + E('vpn_diag_state_active') + ') • VirtualTUN: ' + E('vpn_fwd_healthy'));
assert.strictEqual(text('vpn-diag-routing-badge'),E('vpn_fwd_inconsistent'),'routing state');
assert.strictEqual(text('vpn-diag-routing-alerts'),'Server detail','server detail unchanged');
assert(text('vpn-diag-routing-counts').includes(E('vpn_diag_mismatch_drops',{count:4})));
assert.strictEqual(text('vpn-kpi-backends'),E('vpn_diag_healthy_count',{healthy:1,enabled:2})+E('vpn_diag_disabled_count',{count:1}));
const backendRows=document.getElementById('vpn-diag-be-traffic').children;
assert(backendRows[0].textContent.includes('Server < & "quote"> (' + E('vpn_diag_loss_unavailable') + ')') && backendRows[0].innerHTML==='','backend name uses text');
assert(!backendRows[0].textContent.includes('Server Disabled'),'disabled backend is excluded');
assert.strictEqual(text('vpn-kpi-slow-writes'),E('vpn_diag_slow_writes',{count:2,latency:E('vpn_diag_latency_unavailable')}));
assert.strictEqual(document.getElementById('vpn-kpi-slow-writes').title,E('vpn_diag_slow_writes_title',{count:8,latency:'2.5'}));
assert.strictEqual(text('vpn-diag-lat-percentiles'),E('vpn_diag_historical_percentiles',{p50:'1.5',p95:'2.5',p99:'3.5'}),'percentile interpolation');
assert.strictEqual(text('vpn-diag-lat-max'),E('vpn_diag_historical_ms',{value:7}));
function seriesLabel(id,label) {
 return document.getElementById(id).children.some(child=>child.textContent===label+' ('+vpnHistoryWindow+')');
}
assert(seriesLabel('vpn-chart-reasons',E('vpn_diag_loss_return_queue_full')+' (drops/s)'),'known loss label');
assert(seriesLabel('vpn-chart-reasons','future reason (drops/s)'),'unknown reason unchanged');
assert(seriesLabel('vpn-chart-backend-series',E('vpn_diag_backend_series',{id:3,label:'RX (bps)'})),'backend history label');
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
assert.strictEqual(text('vpn-diag-engine-status'),'amneziawg-go (' + E('vpn_diag_state_stopped') + ') • VirtualTUN: ' + E('vpn_fwd_healthy'));
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
assert.strictEqual(document.getElementById('vpn-chart-reasons').children.length,0);
fixture.rates={available:true,rx_bps:0,tx_bps:0,rx_pps:0,tx_pps:0};
fixture.drop_categories={rates_available:true,total_drops:12,total_drop_rate_pps:0};
fixture.problem_routes[0].traffic={available:true,rx_bytes_per_sec:0,rx_pps:0};
fixture.problem_routes[0].p95_write_samples=1;fixture.problem_routes[0].last_traffic_age_sec=0;
fixture.health_assessment={status:'HEALTHY',conditions:[]};
vpnRenderForwarderHealth(fixture);
assert.strictEqual(text('vpn-fwd-status-text'),E('vpn_forwarder_healthy'),'recovered localized healthy');
assert.strictEqual(text('vpn-kpi-throughput'),'0 bps / 0.0 pps','measured zero differs from unknown');
assert.strictEqual(text('vpn-kpi-packet-loss'),E('vpn_diag_with_cumulative',{value:'0.00 pps',count:12}));

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
	fixture := NewVPNTestFixture(t)
	tmplHTML := fixture.TemplateHTML
	source := fixture.CombinedSource()
	nodePath := fixture.RequireNode()
	for _, lang := range []string{"en", "ru", "fa", "fr", "zh"} {
		t.Run(lang, func(t *testing.T) {
			dict := vpnDiagnosticsLocale(t, lang)
			rendered := vpnDiagnosticsRenderedHTML(t, tmplHTML, dict)
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
		rendered := vpnDiagnosticsRenderedHTML(t, tmplHTML, dict)
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
	fixture := NewVPNTestFixture(t)
	tmplHTML := fixture.TemplateHTML
	source := fixture.CombinedSource()
	lang := "ru"
	dict := vpnDiagnosticsLocale(t, lang)
	t.Run("HardcodedStaticLabel", func(t *testing.T) {
		before := `{{ _ "vpn_diag_avg_5m" }}`
		if !strings.Contains(tmplHTML, before) {
			t.Fatal("static mutation target missing")
		}
		mutated := strings.Replace(tmplHTML, before, "5-Min Average", 1)
		err := vpnDiagnosticsStaticOracle(vpnDiagnosticsRenderedHTML(t, mutated, dict), dict)
		if err == nil || !strings.Contains(err.Error(), "vpn-diag-ewma5m") {
			t.Fatalf("hardcoded static label escaped the rendered oracle: %v", err)
		}
	})
	nodePath := fixture.RequireNode()
	for _, mutation := range []struct{ name, before, after, failure string }{
		{"HardcodedTrafficState", "rates.available !== true ? _('vpn_diag_traffic_unavailable')", "rates.available !== true ? 'Traffic unavailable'", "traffic state"},
		{"WrongAuthoritativeSeverity", "statusText.textContent = _('vpn_forwarder_degraded');", "statusText.textContent = _('vpn_forwarder_warning');", "authoritative severity DEGRADED"},
		{"HardcodedHistoryLabel", "_(lossLabels[key])", "'return queue full'", "known loss label"},
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

// vpnBackendDeviceReasonsBody is the shared renderer oracle for Card 2 drop reasons.
// It supplies each supported backend-device reason on its own, requires the danger
// alarm highlight for it in the drop reasons table, and pins the availability, zero,
// recovery, unknown and locale contracts around the Card 2 drop reasons table.
// It prints RESULT <json> so the caller can compare locales byte for byte instead
// of trusting that one locale happened to be exercised.
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
	'backend_device_unattributed must drive the backend loss alarm');
for (const retired of ['client_backend_device_retired_drops']) {
	assert(!deviceReasons.includes(retired), 'retired-only reason must stay out of canonical map: ' + retired);
}
const reasonRows = () => Array.from(document.getElementById('vpn-diag-drop-reasons').children);
const findReasonRow = (reason) => {
	const labelKey = vpnLossReasonLabels()[reason];
	if (!labelKey) return undefined;
	const label = _(labelKey);
	return reasonRows().find(r => r.textContent.includes(label));
};
const reasonAlarm = (reason) => {
	const row = findReasonRow(reason);
	return row ? row.style.color : 'missing';
};
const observed = [];
function render(drop_categories, backends) {
	vpnRenderForwarderHealth(Object.assign({
		forwarder_available: true,
		forwarder_queue_capacity: 100,
		health_assessment: {status: 'HEALTHY', conditions: []}
	}, backends ? {backends} : {}, {drop_categories}));
}
// Every supported backend-device reason alarms on its own positive current rate in Card 2.
for (const reason of apiReasons) {
	render({rates_available: true, reason_rates: {[reason]: 3}}, {total_drops: 17});
	assert.strictEqual(reasonAlarm(reason), 'var(--danger)', reason + ' current backend loss must alarm');
	observed.push(reason + '=' + reasonAlarm(reason));
}
// Nonzero lifetime alone is history, not a current alarm.
render({rates_available: true, total_drops: 4242, backend_device_unattributed: 4242}, {total_drops: 4242});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), '', 'lifetime backend drops alone must not alarm');
observed.push('lifetime=' + reasonAlarm('backend_device_unattributed'));

// A measured zero rate clears a prior alarm while the loss stays visible.
render({rates_available: true, total_drops: 4242, reason_rates: {backend_device_unattributed: 3}, backend_device_unattributed: 4242}, {total_drops: 4242});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), 'var(--danger)', 'fresh current loss must alarm');
observed.push('fresh=' + reasonAlarm('backend_device_unattributed'));
render({rates_available: true, total_drops: 4242, reason_rates: {backend_device_unattributed: 0}, backend_device_unattributed: 4242}, {total_drops: 4242});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), '', 'measured zero must clear the alarm');
observed.push('zero=' + reasonAlarm('backend_device_unattributed'));

// Unavailable rates and an unavailable forwarder both suppress the alarm.
render({rates_available: false, total_drops: 4242, reason_rates: {backend_device_unattributed: 9}, backend_device_unattributed: 4242}, {total_drops: 4242});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), '', 'unavailable rates must not alarm');
observed.push('unavailable=' + reasonAlarm('backend_device_unattributed'));
render({}, {total_drops: 4242});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), 'missing', 'missing rates_available must not alarm');
observed.push('missing-flag=' + (reasonAlarm('backend_device_unattributed') === 'missing'));
vpnRenderForwarderHealth({forwarder_available: false});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), 'missing', 'unavailable forwarder must clear the alarm');
observed.push('unavailable-forwarder=' + (reasonAlarm('backend_device_unattributed') === 'missing'));

// Unknown, retired-only and overlapping non-device reasons stay out of the sum.
render({rates_available: true, total_drops: 7, reason_rates: {
	client_backend_device_retired_drops: 5, future_reason: 5, return_injection_errors: 5,
	client_backend_queue_full: 5}}, {total_drops: 7});
assert.strictEqual(reasonAlarm('backend_device_unattributed'), 'missing', 'unattributed stays out');
observed.push('excluded=' + (reasonAlarm('backend_device_unattributed') === 'missing'));

// Fresh recovery after an unavailable poll alarms again on a live reason.
render({rates_available: true, reason_rates: {return_backend_device_shutdown: 1}}, {total_drops: 8});
assert.strictEqual(reasonAlarm('return_backend_device_shutdown'), 'var(--danger)', 'recovered poll must alarm on live loss');
observed.push('recovery=' + reasonAlarm('return_backend_device_shutdown'));
console.log('RESULT ' + JSON.stringify(observed));
`
}

// TestVPNBackendDeviceKPIAlarmCoverage pins the backend-device reason contract against the
// canonical reason map for every active locale. In Card 2, active backend-device loss
// rates alarm with danger highlighting in the drop reasons table.
func TestVPNBackendDeviceKPIAlarmCoverage(t *testing.T) {
	node, err := findNodeBinary()
	if err != nil {
		t.Fatal(err)
	}
	fixture := NewVPNTestFixture(t)
	source := fixture.CombinedSource()
	body := vpnBackendDeviceReasonsBody(t)
	var baseline string
	for i, lang := range []string{"en", "ru", "fa", "fr", "zh"} {
		t.Run(lang, func(t *testing.T) {
			script, err := vpnDiagnosticsHealthScriptLocale(t, source, lang, body)
			if err != nil {
				t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
			}
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
// reason danger styling is disabled, and the API-to-label inventory must break
// when backend_device_unattributed is dropped from the canonical map.
func TestVPNBackendDeviceKPIAlarmMutations(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	node := fixture.RequireNode()
	body := vpnBackendDeviceReasonsBody(t)
	for _, mutation := range []struct{ name, before, after, failure string }{
		{
			name:    "ReasonDangerColorDisabled",
			before:  "row.style.color = dc.rates_available === true && rateVal > 0 ? 'var(--danger)' : '';",
			after:   "row.style.color = '';",
			failure: "current backend loss must alarm",
		},
		{
			name:    "UnattributedDroppedFromCanonicalMap",
			before:  "backend_device_unattributed: 'vpn_diag_loss_backend_device_unattributed',",
			after:   "",
			failure: "API-to-label backend-device reason inventory drifted",
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			original := fixture.CombinedSource()
			if !strings.Contains(original, mutation.before) {
				t.Fatal("mutation target missing from combined source")
			}
			mutated := strings.Replace(original, mutation.before, mutation.after, 1)
			script, err := vpnDiagnosticsHealthScriptLocale(t, mutated, "en", body)
			if err != nil {
				t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
			}
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
	fixture := NewVPNTestFixture(t)
	source := fixture.CombinedSource()
	body := vpnBackendDeviceConditionBody(t)
	var baseline string
	for i, lang := range []string{"en", "ru", "fa", "fr", "zh"} {
		t.Run(lang, func(t *testing.T) {
			script, err := vpnDiagnosticsHealthScriptLocale(t, source, lang, body)
			if err != nil {
				t.Fatalf("vpnDiagnosticsHealthScriptLocale failed: %v", err)
			}
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
