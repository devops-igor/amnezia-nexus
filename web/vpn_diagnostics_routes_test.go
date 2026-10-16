package web

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
)

func vpnConnectionTroubleshootingScriptLocale(t *testing.T, source, lang, assertions string) string {
	t.Helper()
	templateSource, companionScripts, err := splitVPNTemplateAndCompanionScripts(source)
	if err != nil {
		t.Fatalf("splitVPNTemplateAndCompanionScripts failed: %v", err)
	}

	script := vpnDOMMock(t, templateSource) + "\n" + vpnDiagnosticsTranslationsJS(t, templateSource, lang)
	script += "\n" + companionScripts
	extraDecls := ""
	if !strings.Contains(companionScripts, "vpnLastStatus") {
		extraDecls = "\nlet vpnLastStatus = null;\nlet vpnShowAllRoutes = false;\n"
	}
	return script + extraDecls + `
const UI = { escapeHtml: escapeHtml };
` + assertions
}

func TestVPNConnectionTroubleshootingTableAndCorrelation(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	node := fixture.RequireNode()
	tmplStr := fixture.TemplateHTML
	combinedSource := fixture.CombinedSource()

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

	// Invariant: #vpnSessionsTable thead tr has 5 headers, and header 1 is vpn_col_user_device (#464)
	tableMatches := regexp.MustCompile(`<table[^>]*id="vpnSessionsTable"[^>]*>([\s\S]*?)</table>`).FindStringSubmatch(tmplStr)
	if len(tableMatches) < 2 {
		t.Fatal("vpnSessionsTable not found in template")
	}
	thMatches := regexp.MustCompile(`<th[^>]*>([\s\S]*?)</th>`).FindAllStringSubmatch(tableMatches[1], -1)
	if len(thMatches) != 5 {
		t.Fatalf("expected 5 <th> headers in #vpnSessionsTable thead, got %d", len(thMatches))
	}
	if !strings.Contains(thMatches[0][1], `vpn_col_user_device`) {
		t.Fatalf("expected header 1 to be vpn_col_user_device, got %q", thMatches[0][1])
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

// Assertion 1: Count badge, row count, and thead 5-column contract
assert.strictEqual(countBadge.textContent, '4', 'badge count must match session count');
assert.strictEqual(tbody.children.length, 4, 'table must render 4 session rows');

// Row 0 (alice - nominal correlated route):
const row0 = tbody.children[0];
assert.strictEqual(row0.children.length, 5, 'session row must have 5 columns');
assert(row0.children[0].textContent.includes('alice'), 'col 0 must render username');
assert(row0.children[0].textContent.includes('alice-phone'), 'col 0 must render config subtitle');
assert(row0.children[0].textContent.includes('10.8.0.2'), 'col 0 must render IP subtitle');
assert.strictEqual(row0.children[0].style.cursor, 'pointer', 'user cell must have pointer style');
assert.notStrictEqual(row0.children[0].style.display, 'flex', 'user cell td must NOT have style.display flex');
assert(row0.children[0].innerHTML.includes('inline-flex'), 'user cell must contain inline-flex wrapper');
assert(row0.children[0].innerHTML.includes('vpn-expand-icon'), 'user cell must render chevron icon');
assert.strictEqual(row0.children[1].textContent, 'Frankfurt-1', 'col 1 must render server name');
assert(row0.children[2].textContent.includes('1.00 Mbps') && row0.children[2].textContent.includes('2.00 Mbps'), 'col 2 must render live traffic rates');
assert.strictEqual(row0.children[2].getAttribute('data-sort-value'), '3000000', 'tdTraffic must carry numeric data-sort-value');
assert.strictEqual(row0.children[3].textContent, '0', 'col 3 must render 0 drops');
assert.strictEqual(row0.children[3].getAttribute('data-sort-value'), '0', 'tdLoss must carry numeric data-sort-value');
assert(row0.children[4].textContent.includes('Active'), 'col 4 must render Active status badge');
assert(row0.children[4].innerHTML.includes('badge-success'), 'col 4 must render badge-success for connected session');

// Row 1 (bob - degraded correlated route):
const row1 = tbody.children[1];
assert.strictEqual(row1.children.length, 5, 'session row must have 5 columns');
assert(row1.children[0].textContent.includes('bob'));
assert.strictEqual(row1.children[1].textContent, 'Frankfurt-1');
assert.strictEqual(row1.children[2].getAttribute('data-sort-value'), '600000');
assert.strictEqual(row1.children[3].getAttribute('data-sort-value'), '10000000002400');
assert(row1.children[3].innerHTML.includes('text-danger'), 'packet loss must be highlighted with text-danger');
assert(row1.children[3].textContent.includes('2.4 drops/s'), 'loss rate column must render drop rate pps');
assert(row1.children[3].textContent.includes('15'), 'drops count must be 15');
assert(row1.children[4].innerHTML.includes('badge-warn'), 'degraded route must reflect degraded status badge');
assert(row1.children[4].textContent.includes('Degraded'), 'status text must show Degraded');

// Row 2 (charlie - active session without route):
const row2 = tbody.children[2];
assert.strictEqual(row2.children.length, 5, 'session row must have 5 columns');
assert(row2.children[0].textContent.includes('charlie'));
assert.strictEqual(row2.children[1].textContent, 'Frankfurt-2');
assert.strictEqual(row2.children[2].textContent, '-', 'traffic must be dash when route is absent');
assert.strictEqual(row2.children[2].getAttribute('data-sort-value'), '0');
assert.strictEqual(row2.children[3].textContent, '-', 'loss must be dash when route is absent');
assert.strictEqual(row2.children[3].getAttribute('data-sort-value'), '0');
assert(row2.children[4].textContent.includes('Unroutable'), 'active session without route must reflect unroutable status badge');
assert(row2.children[4].innerHTML.includes('badge-warn'), 'unroutable session must have badge-warn');

// Row 3 (dan - nominal session with historical drops):
const row3 = tbody.children[3];
assert.strictEqual(row3.children.length, 5, 'session row must have 5 columns');
assert(row3.children[0].textContent.includes('dan'));
assert.strictEqual(row3.children[1].textContent, 'Frankfurt-1');
assert.strictEqual(row3.children[3].textContent, '10', 'historical drops must render count');
assert(!row3.children[3].innerHTML.includes('text-danger'), 'historical drops alone must NOT have text-danger styling');
assert.strictEqual(row3.children[3].getAttribute('data-sort-value'), '10');
assert(row3.children[4].textContent.includes('Active'), 'session with only historical drops must remain Active status');
assert(row3.children[4].innerHTML.includes('badge-success'), 'nominal session with historical drops must have badge-success');

// Assertion 2: Expandable drilldown with 4 telemetry cards
vpnToggleSessionDrilldown(sessions[0], tbody.children[0]);
assert(vpnExpandedSessionIds.has('sess-1'), 'session ID must be tracked in expanded set');
assert(tbody.children[0].classList.contains('row-expanded'), 'row must gain row-expanded class');
assert.strictEqual(tbody.children.length, 5, 'tbody must have drilldown row inserted');
const drilldown0 = tbody.children[1];
assert(drilldown0.className.includes('vpn-session-drilldown-row'), 'drilldown row must have correct class');
assert.strictEqual(drilldown0.children[0].colSpan, 5, 'drilldown td must span all 5 columns');

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
assert(updatedAlice.children[2].textContent.includes('4.00 Mbps') && updatedAlice.children[2].textContent.includes('8.00 Mbps'), 'live traffic must be synced with status refresh');
assert.strictEqual(updatedAlice.children[2].getAttribute('data-sort-value'), '12000000');
assert(updatedAlice.children[3].innerHTML.includes('text-danger'), 'packet loss alarm must update dynamically');
assert.strictEqual(updatedAlice.children[3].getAttribute('data-sort-value'), '10000000012');
assert(updatedAlice.children[4].innerHTML.includes('badge-warn'), 'status must update to Degraded dynamically');

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

	script := vpnConnectionTroubleshootingScriptLocale(t, combinedSource, "en", enAssertions)
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
assert(row0.children[4].textContent.includes('Деградировано'), 'Russian degraded status label');

// Russian unroutable status badge for session without route
const row1Before = tbody.children[1];
assert(row1Before.children[4].textContent.includes('Немаршрутизируемый'), 'Russian unroutable status label');
assert(row1Before.children[4].innerHTML.includes('badge-warn'));

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

	ruScript := vpnConnectionTroubleshootingScriptLocale(t, combinedSource, "ru", ruAssertions)
	if out, err := execNodeScript(node, ruScript); err != nil {
		t.Fatalf("Russian connection troubleshooting table test failed: %v\n%s", err, out)
	}

	// 3. Rendered template localized headers verification in Russian
	ruDict := vpnDiagnosticsLocale(t, "ru")
	renderedHTML := vpnDiagnosticsRenderedHTML(t, tmplStr, ruDict)
	for _, expectedRussianHeader := range []string{
		"Пользователь и устройство",
		"Текущий трафик",
		"Потеря пакетов",
		"Диагностика подключений",
		"Только с проблемами",
	} {
		if !strings.Contains(renderedHTML, expectedRussianHeader) {
			t.Fatalf("rendered Russian template missing header %q", expectedRussianHeader)
		}
	}
}

func TestVPNReconnectSessionIDMismatchShowsUnroutable(t *testing.T) {
	fixture := NewVPNTestFixture(t)
	node := fixture.RequireNode()
	combinedSource := fixture.CombinedSource()

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
const dropsCell = row.children[3];
assert.strictEqual(dropsCell.textContent, '-', 'unroutable session must have dash for drops without inheriting old route telemetry');

// Assert status column renders with Unroutable badge
const statusCell = row.children[4];
assert(statusCell.textContent.includes('Unroutable'), 'session without matching route must show Unroutable status badge');
assert(statusCell.innerHTML.includes('badge-warn'), 'unroutable status badge must have badge-warn');

// 3. Switch to "Problems Only" filter
vpnToggleSessionsProblemFilter();
assert.strictEqual(tbody.children.length, 1, 'unroutable session must appear under Problems Only filter');
const probRow = tbody.children[0];
assert(probRow.children[4].textContent.includes('Unroutable'), 'session in Problems Only must show Unroutable status');
`

	script := vpnConnectionTroubleshootingScriptLocale(t, combinedSource, "en", assertions)
	if out, err := execNodeScript(node, script); err != nil {
		t.Fatalf("TestVPNReconnectSessionIDMismatchShowsUnroutable failed: %v\n%s", err, out)
	}
}

func TestVPNNexusTableLifecycleDrilldownAndConfigDedup(t *testing.T) {
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

try {
    const globalRoot = require('child_process').execSync('npm root -g').toString().trim();
    if (globalRoot && fs.existsSync(globalRoot) && !module.paths.includes(globalRoot)) {
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
    // Table header assertion (Requirement 4):
    // - #vpnSessionsTable thead tr has 5 headers, and header 1 is vpn_col_user_device.
    const theadHeaders = Array.from(w.document.querySelectorAll('#vpnSessionsTable thead th'));
    assert.strictEqual(theadHeaders.length, 5, '#vpnSessionsTable thead tr must have 5 headers');
    assert(theadHeaders[0].textContent.includes('vpn_col_user_device'), 'header 1 must be vpn_col_user_device');

    const tbody = w.document.getElementById('vpn-sessions-tbody');
    function rowOrder() {
        return Array.from(tbody.children).filter(r => r.style.display !== 'none').map(r => r.classList.contains('vpn-session-drilldown-row') ? 'DETAIL' : (r.cells[0]?.querySelector('.font-weight-600')?.textContent.trim() || r.cells[0]?.textContent.trim()));
    }

    // 1. Sort ascending
    w.document.querySelector('#vpnSessionsTable thead th').click();
    assert.deepStrictEqual(rowOrder(), ['alpha', 'bravo', 'zulu'], 'table must sort ascending by user');

    // 2. Expand alpha
    const alpha = Array.from(tbody.children).find(r => (r.cells[0]?.querySelector('.font-weight-600')?.textContent.trim() || r.cells[0]?.textContent.trim()) === 'alpha');
    assert(alpha, 'alpha row must exist');
    alpha.cells[0].click();
    assert.deepStrictEqual(rowOrder(), ['alpha', 'DETAIL', 'bravo', 'zulu'], 'detail row must follow alpha');
    assert.strictEqual(alpha.nextElementSibling?.classList.contains('vpn-session-drilldown-row'), true, 'detail row must be adjacent to alpha');

    // 3. Polling refresh
    w.renderSessions(sessions);
    assert.deepStrictEqual(rowOrder(), ['alpha', 'DETAIL', 'bravo', 'zulu'], 'order must be preserved after poll refresh');
    const alphaAfterPoll = Array.from(tbody.children).find(r => (r.cells[0]?.querySelector('.font-weight-600')?.textContent.trim() || r.cells[0]?.textContent.trim()) === 'alpha');
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
`, tmplStr, string(enData), string(tablesJS), string(sessionsJS), fixture.HealthProblemsJS, fixture.HealthSummaryJS, fixture.BackendsJS)

	out, err := execNodeScript(node, testScript)
	if err != nil {
		t.Fatalf("TestVPNNexusTableLifecycleDrilldownAndConfigDedup failed: %v\n%s", err, string(out))
	}
	if strings.Contains(string(out), "JSDOM_NOT_AVAILABLE") {
		if os.Getenv("CI") != "" {
			t.Fatalf("jsdom is not available in CI environment: %s", out)
		}
		t.Skip("jsdom is not available in Node environment")
	}
}
