package web

import (
	"strings"
	"testing"
)

// Issue #955 acceptance coverage, part 2: the aggregate diagnostic values the
// compact health redesign left without a UI consumer. Split from
// vpn_health_acceptance_test.go when that file approached the SG1 ceiling; the
// tests are unchanged, only their home module is different.
//
// Each subtest asserts the RENDERED TEXT of a specific element, so deleting the
// row, its writer, or its availability gate fails here.

// VPN955-07: the four aggregate diagnostic values that the compact redesign had
// left without any UI consumer are restored under the accepted Advanced
// Diagnostics sections, NOT by reinstating the eight summary tiles. Each
// assertion reads the RENDERED TEXT of a specific element, so deleting the row,
// its writer, or its availability gate fails here.
func TestVPN955Acceptance07RestoredAggregateDiagnostics(t *testing.T) {
	t.Run("AggregatePacketRate", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
assert(el('vpn-diag-packet-rate'), 'the Traffic & Performance dl carries an aggregate packet-rate row');

// rx_pps + tx_pps for the whole forwarder: 1.5 Mpps. Neither directional value
// alone equals the rendered text, so a per-direction read fails; all_routes
// carries a different per-route rate, so a per-route read fails too.
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { available: true, rx_bps: 0, tx_bps: 0, rx_pps: 1000000, tx_pps: 500000 },
    all_routes: [{ peer_key: 'p1', traffic: { available: true, rx_pps: 10, tx_pps: 20 } }]
});
const measured = el('vpn-diag-packet-rate').textContent;
assert.strictEqual(measured, '1.50 Mpps', 'the AGGREGATE packet rate is rendered: ' + measured);
assert(!el('vpn-diag-packet-rate').classList.contains('vpn-not-measured'), 'a measured aggregate is not marked unmeasured');

// A measured zero is a measurement with its unit, not "Not measured".
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { available: true, rx_bps: 0, tx_bps: 0, rx_pps: 0, tx_pps: 0 }
});
assert.strictEqual(el('vpn-diag-packet-rate').textContent, '0.0 pps', 'a sampled zero aggregate is numeric');

// No rate sample: the availability flag decides. Both pps fields present but the
// flag false must NOT render a number.
vpnRenderForwarderHealth({
    forwarder_available: true,
    rates: { available: false, rx_bps: 5000, tx_bps: 5000, rx_pps: 1000, tx_pps: 2000 }
});
assert.strictEqual(el('vpn-diag-packet-rate').textContent, 'Not measured',
    'an unavailable rate payload is not a measurement');
assert(el('vpn-diag-packet-rate').classList.contains('vpn-not-measured'), 'and it is marked unmeasured');

// A missing pps field is absent data, never a half-drawn sum.
vpnRenderForwarderHealth({ forwarder_available: true, rates: { available: true, rx_bps: 0, tx_bps: 0, rx_pps: 1000 } });
assert.strictEqual(el('vpn-diag-packet-rate').textContent, 'Not measured',
    'one missing direction is not summed as a zero');

// A failed poll clears it.
vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-diag-packet-rate').textContent, 'Not measured', 'no stale packet rate after a failed poll');
console.log('VPN955_07_PPS_OK');
`, "VPN955_07_PPS_OK")
	})

	t.Run("AccumulatedQueuePressureDuration", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
assert(el('vpn-diag-queue-dwell'), 'the Routing & Drops queue dl carries an accumulated above-50% row');

// 605s total above 50% is "10m 5s"; the current streak of 90s is "1m 30s". The
// seconds remainder is kept, so a floored single-unit render fails.
vpnRenderForwarderHealth({
    forwarder_available: true,
    queue_pressure: { occupancy: 10, capacity: 100, utilization_pct: 10,
                      total_seconds_above_50: 605, consecutive_above_50_sec: 90 }
});
const measured = el('vpn-diag-queue-dwell').textContent;
assert(measured.includes('10m 5s'), 'the accumulated total is rendered: ' + measured);
assert(measured.includes('1m 30s'), 'and the current streak: ' + measured);
assert(!measured.includes('Not measured'), 'a reported counter is measured');

// Over an hour switches unit but keeps the value.
vpnRenderForwarderHealth({
    forwarder_available: true,
    queue_pressure: { total_seconds_above_50: 7325, consecutive_above_50_sec: 0 }
});
assert(el('vpn-diag-queue-dwell').textContent.includes('2h 2m'),
    'an hour-scale total renders hours and minutes: ' + el('vpn-diag-queue-dwell').textContent);

// A genuine zero is a measurement, not an absence.
vpnRenderForwarderHealth({
    forwarder_available: true,
    queue_pressure: { total_seconds_above_50: 0, consecutive_above_50_sec: 0 }
});
const zero = el('vpn-diag-queue-dwell').textContent;
assert(zero.includes('0s'), 'a measured zero duration is numeric: ' + zero);
assert(!zero.includes('Not measured'), 'zero accumulated seconds is a measurement');

// An absent counter is not measured; it must not become 0s.
vpnRenderForwarderHealth({ forwarder_available: true, queue_pressure: { occupancy: 1, capacity: 10 } });
assert.strictEqual(el('vpn-diag-queue-dwell').textContent, 'Not measured',
    'an absent dwell counter is not a measured zero');

vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-diag-queue-dwell').textContent, 'Not measured', 'no stale dwell after a failed poll');
console.log('VPN955_07_DWELL_OK');
`, "VPN955_07_DWELL_OK")
	})

	t.Run("AggregateCumulativeWriteStalls", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
assert(el('vpn-diag-write-stalls-total'), 'the Runtime Details stalls dl carries a cumulative row');

// The cumulative total is a DIFFERENT fact from the recent window: 412 lifetime
// against 7 recent. Reading stalls_recent here would render 7 and fail.
vpnRenderForwarderHealth({
    forwarder_available: true,
    forward_latency: { stalls: 412, stalls_recent: 7, stalls_window_sec: 60 }
});
const measured = el('vpn-diag-write-stalls-total').textContent;
assert.strictEqual(measured, '412', 'the cumulative aggregate stall count is rendered: ' + measured);
assert(!el('vpn-diag-write-stalls-total').classList.contains('vpn-not-measured'), 'a measured total is not marked unmeasured');
// The round-2 recent row is untouched by this: both values coexist.
assert(el('vpn-diag-write-stalls-recent').textContent.includes('7'),
    'the recent count keeps its own value: ' + el('vpn-diag-write-stalls-recent').textContent);

// A lifetime zero is a measurement.
vpnRenderForwarderHealth({ forwarder_available: true, forward_latency: { stalls: 0, stalls_recent: 0, stalls_window_sec: 60 } });
assert.strictEqual(el('vpn-diag-write-stalls-total').textContent, '0', 'a measured zero total is numeric');

// Absent is not measured.
vpnRenderForwarderHealth({ forwarder_available: true, forward_latency: { stalls_recent: 3, stalls_window_sec: 60 } });
assert.strictEqual(el('vpn-diag-write-stalls-total').textContent, 'Not measured',
    'an absent cumulative counter is not a measured zero');

vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-diag-write-stalls-total').textContent, 'Not measured', 'no stale total after a failed poll');
console.log('VPN955_07_STALLS_TOTAL_OK');
`, "VPN955_07_STALLS_TOTAL_OK")
	})

	t.Run("AggregateHistoricalMaxWriteDuration", func(t *testing.T) {
		runVPNHealthAcceptance(t, "en", `
const el = id => document.getElementById(id);
assert(el('vpn-diag-lat-max'), 'the Traffic & Performance dl carries a historical maximum row');

// max_ms is the aggregate maximum over completed writes; 240 renders with the
// existing historical formatter and its unit. all_routes carries a DIFFERENT
// per-route maximum, so a renderer that reads the per-route reservoir instead of
// the aggregate produces 35 and fails below.
vpnRenderForwarderHealth({
    forwarder_available: true,
    forward_latency: { max_ms: 240 },
    all_routes: [{ peer_key: 'p1', max_write_ms: 35 }]
});
const measured = el('vpn-diag-lat-max').textContent;
assert(measured.includes('240'), 'the AGGREGATE maximum duration is rendered: ' + measured);
assert(!measured.includes('35'), 'not the per-route maximum: ' + measured);
assert(measured.includes('ms'), 'with its millisecond unit: ' + measured);
assert(!el('vpn-diag-lat-max').classList.contains('vpn-not-measured'), 'a measured maximum is not marked unmeasured');

// max_ms starts at 0 and only advances on a COMPLETED write, so 0 cannot be
// distinguished from "nothing completed". It must read not measured rather than
// an invented sampled zero, even when write_total is high (write_total counts
// admitted writes, before completion).
vpnRenderForwarderHealth({ forwarder_available: true, forward_latency: { max_ms: 0, write_total: 900 } });
assert.strictEqual(el('vpn-diag-lat-max').textContent, 'Not measured',
    'an unprovable zero maximum is not a measurement');
assert(el('vpn-diag-lat-max').classList.contains('vpn-not-measured'), 'and it is marked unmeasured');

// An absent field is likewise not measured.
vpnRenderForwarderHealth({ forwarder_available: true, forward_latency: { p95_health_samples: 0 } });
assert.strictEqual(el('vpn-diag-lat-max').textContent, 'Not measured', 'an absent maximum is not measured');

vpnRenderForwarderHealth(null);
assert.strictEqual(el('vpn-diag-lat-max').textContent, 'Not measured', 'no stale maximum after a failed poll');
console.log('VPN955_07_LAT_MAX_OK');
`, "VPN955_07_LAT_MAX_OK")
	})

	t.Run("RestoredUnderDiagnosticsNotEmptySummaryTiles", func(t *testing.T) {
		// The restoration must live in the accepted diagnostics sections; the eight
		// summary tiles stay retired, and the four new rows are inside them.
		r := NewVPNTestFixtureForPage(t, "vpn_diagnostics")
		templateHTML := r.TemplateHTML
		if strings.Contains(templateHTML, `id="vpn-kpi-`) {
			t.Error("the eight summary tiles must stay retired")
		}
		for _, section := range []struct{ sectionID, rowID string }{
			{"vpn-traffic-performance", "vpn-diag-packet-rate"},
			{"vpn-traffic-performance", "vpn-diag-lat-max"},
			{"vpn-routing-drops", "vpn-diag-queue-dwell"},
			{"vpn-runtime-details", "vpn-diag-write-stalls-total"},
		} {
			start := strings.Index(templateHTML, `id="`+section.sectionID+`"`)
			if start < 0 {
				t.Fatalf("missing diagnostics section %q", section.sectionID)
			}
			end := strings.Index(templateHTML[start:], "</section>")
			if end < 0 {
				t.Fatalf("unterminated section %q", section.sectionID)
			}
			if !strings.Contains(templateHTML[start:start+end], `id="`+section.rowID+`"`) {
				t.Errorf("%s must live inside #%s", section.rowID, section.sectionID)
			}
		}
	})
}
