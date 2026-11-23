package web

// vpnSessionsAccordionPersistenceSnippet contains Part B of TestVPNSessionsTableSortingAndAccordionPersistence:
// Advanced Diagnostics disclosure ownership across repeated poll cycles (#955).
const vpnSessionsAccordionPersistenceSnippet = `    // Part B: Advanced Diagnostics disclosure ownership across repeated polls.
    // #955 reverses the old auto-expand behaviour: a problem must never open the
    // technical panel. What still matters, and is preserved here, is that the
    // operator's own open/closed choice survives every poll and every new problem.
    const entry = w.document.getElementById('vpn-advanced-entry');
    const panel = w.document.getElementById('vpn-diagnostics');
    assert(entry, 'vpn-advanced-entry must exist in template');
    assert(panel, 'vpn-diagnostics must exist in template');
    const closed = () => panel.hidden !== false && entry.getAttribute('aria-expanded') !== 'true';

    // 1. Initial healthy state: closed.
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: { status: 'HEALTHY', conditions: [] }
    });
    assert(closed(), 'diagnostics must be closed initially when healthy');

    // 2. Healthy with route pressure: still closed (no auto-open on any problem).
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        forwarder_queue_capacity: 100,
        problem_routes: [{ peer_key: 'p1', capacity: 100, occupancy: 95, drops: 3, has_pressure: true }],
        all_routes: [{ peer_key: 'p1', capacity: 100, occupancy: 95, drops: 3, has_pressure: true }],
        health_assessment: { status: 'HEALTHY', conditions: [] }
    });
    assert(closed(), 'route pressure must not open diagnostics');

    // 3. Degraded with an actionable problem: still closed.
    const degradedStatusA = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Queue full drops active', connection_id: 'c-1', username: 'alice' }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusA);
    assert(closed(), 'an actionable problem must not open diagnostics');
    assert.strictEqual(w.document.getElementById('vpn-fwd-problem-list').children.length, 1,
        'the problem is surfaced on the page instead');

    // 4. Operator opens the panel; it must stay open across repeated polls.
    w.vpnSetDiagnosticsOpen(true);
    assert.strictEqual(panel.hidden, false, 'operator-open panel is visible');
    assert.strictEqual(entry.getAttribute('aria-expanded'), 'true');
    w.vpnRenderForwarderHealth(degradedStatusA);
    assert.strictEqual(panel.hidden, false, 'operator-open panel survives poll 1');
    w.vpnRenderForwarderHealth(degradedStatusA);
    assert.strictEqual(panel.hidden, false, 'operator-open panel survives poll 2');

    // 5. A NEW problem arriving must not change the operator's choice.
    const degradedStatusB = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Return queue full drops for Client A', connection_id: 'c-10', username: 'charlie' },
                { severity: 'CRITICAL', message: 'Backend latency critical', connection_id: 'c-2', username: 'bob' }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusB);
    assert.strictEqual(panel.hidden, false, 'a new problem keeps an open panel open');

    // 6. Operator closes it; a subsequent problem must NOT reopen it.
    w.vpnSetDiagnosticsOpen(false);
    assert(closed(), 'operator-closed panel is closed');
    w.vpnRenderForwarderHealth(degradedStatusB);
    assert(closed(), 'a repeated problem must not reopen a closed panel');
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [{ category: 'routing', severity: 'CRITICAL', message: '1 duplicate IP address(es) detected across active routes: 10.8.0.2' }]
        }
    });
    assert(closed(), 'an escalated severity must not reopen a closed panel');

    // 7. A failed poll must not close a panel the operator opened.
    w.vpnSetDiagnosticsOpen(true);
    w.vpnRenderForwarderHealth(null);
    assert.strictEqual(panel.hidden, false, 'a failed poll leaves an open panel open');
    w.vpnSetDiagnosticsOpen(false);

    // 8. Problems resolving to healthy leaves everything closed.
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: { status: 'HEALTHY', conditions: [] }
    });
    assert(closed(), 'diagnostics remains closed when healthy');
`
