package web

// vpnSessionsAccordionPersistenceSnippet contains Part B of TestVPNSessionsTableSortingAndAccordionPersistence:
// technical diagnostics accordion collapse persistence across repeated poll cycles.
const vpnSessionsAccordionPersistenceSnippet = `    // Part B: Technical diagnostics accordion collapse persistence across multiple poll renders
    const techDetails = w.document.getElementById('vpn-fwd-tech-details');
    assert(techDetails, 'vpn-fwd-tech-details must exist in template');

    // 1. Initial healthy state: accordion is closed
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: { status: 'HEALTHY', conditions: [] }
    });
    assert.strictEqual(techDetails.open, false, 'techDetails must be closed initially when healthy');

    // 2. Degraded state with Problem A appears -> auto-expands
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
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on active problem detection');

    // 3. Operator manually collapses the details panel
    techDetails.open = false;
    assert.strictEqual(techDetails.open, false, 'operator manually collapsed techDetails');

    // 4. Repeated polling render cycle 1 with identical degradedStatusA -> must STAY closed
    w.vpnRenderForwarderHealth(degradedStatusA);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed across poll tick 1 with same problem');

    // 5. Repeated polling render cycle 2 with identical degradedStatusA -> must STAY closed
    w.vpnRenderForwarderHealth(degradedStatusA);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed across poll tick 2 with same problem');

    // 5a. Telemetry changes within existing actionable problem (rates, counters, message text change) -> must STAY closed
    const degradedStatusA_tick3 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                {
                    severity: 'DEGRADED',
                    category: 'dataplane',
                    message_key: 'vpn_problem_route_queue_drops',
                    message: 'Return queue full drops (10 recent) for 10.0.0.2',
                    connection_id: 'c-1',
                    assigned_ip: '10.0.0.2',
                    username: 'alice',
                    observed_rate: '2.0 drops/s'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusA_tick3);
    techDetails.open = false; // operator collapses

    // Tick 4: telemetry fluctuates (10 recent -> 11 recent, rate 2.0 -> 2.1 drops/s) -> MUST STAY CLOSED
    const degradedStatusA_tick4 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                {
                    severity: 'DEGRADED',
                    category: 'dataplane',
                    message_key: 'vpn_problem_route_queue_drops',
                    message: 'Return queue full drops (11 recent) for 10.0.0.2',
                    connection_id: 'c-1',
                    assigned_ip: '10.0.0.2',
                    username: 'alice',
                    observed_rate: '2.1 drops/s'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusA_tick4);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when actionable problem telemetry numbers fluctuate');

    // Tick 5: telemetry fluctuates further (11 recent -> 15 recent, rate 2.1 -> 3.5 drops/s) -> MUST STAY CLOSED
    const degradedStatusA_tick5 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                {
                    severity: 'DEGRADED',
                    category: 'dataplane',
                    message_key: 'vpn_problem_route_queue_drops',
                    message: 'Return queue full drops (15 recent) for 10.0.0.2',
                    connection_id: 'c-1',
                    assigned_ip: '10.0.0.2',
                    username: 'alice',
                    observed_rate: '3.5 drops/s'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusA_tick5);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed across repeated telemetry counter updates');

    // 5b. Unkeyed qualifying condition with fluctuating rates/counters -> must STAY closed
    const degradedStatusCond_tick1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'drops',
                    severity: 'DEGRADED',
                    message: 'Active queue drops: 2.0 drops/sec due to full return queues'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusCond_tick1);
    techDetails.open = false; // operator collapses

    const degradedStatusCond_tick2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'drops',
                    severity: 'DEGRADED',
                    message: 'Active queue drops: 2.1 drops/sec due to full return queues'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusCond_tick2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when unkeyed condition rate fluctuates');

    // 5c. Keyed qualifying condition with fluctuating rates -> must STAY closed
    const degradedStatusKeyedCond_tick1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'drops',
                    severity: 'DEGRADED',
                    message_key: 'vpn_diag_condition_backend_device_unattributed',
                    message: 'Backend device drops are active but detailed per-direction attribution is unavailable: 2.0 drops/sec'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusKeyedCond_tick1);
    techDetails.open = false; // operator collapses

    const degradedStatusKeyedCond_tick2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'drops',
                    severity: 'DEGRADED',
                    message_key: 'vpn_diag_condition_backend_device_unattributed',
                    message: 'Backend device drops are active but detailed per-direction attribution is unavailable: 2.1 drops/sec'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusKeyedCond_tick2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when keyed condition rate fluctuates');

    // 5d. Actionable problem lacking message_key where message text has changing telemetry counters -> must STAY closed
    const degradedStatusUnkeyedAct_tick1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Return queue full drops (10 recent) for Client A', connection_id: 'c-10', username: 'charlie' }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusUnkeyedAct_tick1);
    techDetails.open = false; // operator collapses

    const degradedStatusUnkeyedAct_tick2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Return queue full drops (11 recent) for Client A', connection_id: 'c-10', username: 'charlie' }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusUnkeyedAct_tick2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when unkeyed actionable problem numbers fluctuate');

    // 5e. Distinct routing conditions affecting different IPs with identical count and severity -> must AUTO-EXPAND
    // 1. Operator closes #vpn-fwd-tech-details on duplicate-IP condition affecting 10.8.0.2
    const degradedStatusDupIP_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '1 duplicate IP address(es) detected across active routes: 10.8.0.2'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusDupIP_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on duplicate-IP condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with same 10.8.0.2 duplicate IP condition -> must STAY closed
    w.vpnRenderForwarderHealth(degradedStatusDupIP_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of duplicate-IP condition');

    // 2. Telemetry updates to a replacement duplicate-IP condition affecting 10.8.0.3 with the exact same count and severity
    const degradedStatusDupIP_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '1 duplicate IP address(es) detected across active routes: 10.8.0.3'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusDupIP_2);
    // 3. Assert that #vpn-fwd-tech-details AUTO-EXPANDS (techDetails.open === true) because the affected IP identity changed!
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when replacement duplicate-IP condition affects a different IP (10.8.0.3 vs 10.8.0.2)');

    // Operator collapses accordion after observing new IP incident
    techDetails.open = false;
    w.vpnRenderForwarderHealth(degradedStatusDupIP_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of replacement condition');

    // 5f. Routing ownership mismatch condition with fluctuating drop counts -> must STAY closed
    const degradedStatusOwnership_tick1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '3 client-direction and 2 return-direction ownership mismatch drop(s) in the last 30.0s'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusOwnership_tick1);
    techDetails.open = false; // operator collapses accordion

    const degradedStatusOwnership_tick2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '5 client-direction and 7 return-direction ownership mismatch drop(s) in the last 30.0s'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusOwnership_tick2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when ownership mismatch drop counts fluctuate');

    // 5g. Distinct routing conditions affecting leading-compressed IPv6 addresses with identical count and severity -> must AUTO-EXPAND
    // 1. Operator closes #vpn-fwd-tech-details on duplicate-IP condition affecting ::200
    const degradedStatusDupIPv6_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '1 duplicate IP address(es) detected across active routes: ::200'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusDupIPv6_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on leading-compressed IPv6 duplicate-IP condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with same ::200 duplicate IP condition -> must STAY closed
    w.vpnRenderForwarderHealth(degradedStatusDupIPv6_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of leading-compressed IPv6 condition');

    // 2. Telemetry updates to a replacement duplicate-IP condition affecting ::201 with the exact same count and severity
    const degradedStatusDupIPv6_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '1 duplicate IP address(es) detected across active routes: ::201'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusDupIPv6_2);
    // 3. Assert that #vpn-fwd-tech-details AUTO-EXPANDS (techDetails.open === true) because the affected IP identity changed!
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when replacement duplicate-IP condition affects a different leading-compressed IPv6 (::201 vs ::200)');

    // Operator collapses accordion after observing new IPv6 incident
    techDetails.open = false;
    w.vpnRenderForwarderHealth(degradedStatusDupIPv6_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of replacement leading-compressed IPv6 condition');

    // 5h. Space-separated timestamp condition updating -> must STAY closed
    const degradedStatusSpaceTs_tick1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: 'Last sample at 2026-10-09 09:00:00'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusSpaceTs_tick1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on space-separated timestamp condition');
    techDetails.open = false; // operator collapses accordion

    const degradedStatusSpaceTs_tick2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: 'Last sample at 2026-10-09 09:00:05'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusSpaceTs_tick2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when space-separated timestamp advances');

    // 5i. Embedded-clock IPv6 replacement: 2001:db8::19:10:10 vs 2001:db8::19:10:15 -> must AUTO-EXPAND
    // 1. Duplicate-IP condition affecting 2001:db8::19:10:10 is rendered
    const degradedStatusDupClockIPv6_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '1 duplicate IP address(es) detected across active routes: 2001:db8::19:10:10'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusDupClockIPv6_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on embedded-clock IPv6 duplicate-IP condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with same 2001:db8::19:10:10 duplicate IP condition -> must STAY closed
    w.vpnRenderForwarderHealth(degradedStatusDupClockIPv6_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of embedded-clock IPv6 condition');

    // 2. Replacement duplicate-IP condition affecting 2001:db8::19:10:15 arrives with identical count 1 and severity CRITICAL
    const degradedStatusDupClockIPv6_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'CRITICAL',
            conditions: [
                {
                    category: 'routing',
                    severity: 'CRITICAL',
                    message: '1 duplicate IP address(es) detected across active routes: 2001:db8::19:10:15'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusDupClockIPv6_2);
    // 3. Assert that #vpn-fwd-tech-details AUTO-EXPANDS (techDetails.open === true) because the affected IP identity changed!
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when replacement duplicate-IP condition affects a different embedded-clock IPv6 (2001:db8::19:10:15 vs 2001:db8::19:10:10)');

    // Operator collapses accordion after observing new IPv6 incident
    techDetails.open = false;
    w.vpnRenderForwarderHealth(degradedStatusDupClockIPv6_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of replacement embedded-clock IPv6 condition');

    // 5j. Table-driven mixed IPv6 duplicate-IP replacement cases -> must AUTO-EXPAND on IP change
    const mixedIPv6Cases = [
        { initial: '::1234:192.0.2.1', replacement: '::1235:192.0.2.1', desc: 'leading-compressed mixed IPv6 (::1234:192.0.2.1 vs ::1235:192.0.2.1)' },
        { initial: '::ffff:0:192.0.2.1', replacement: '::ffff:1:192.0.2.1', desc: 'mapped-expanded mixed IPv6 (::ffff:0:192.0.2.1 vs ::ffff:1:192.0.2.1)' }
    ];
    for (const tc of mixedIPv6Cases) {
        const makeDupStatus = (ip) => ({
            forwarder_available: true,
            health_assessment: {
                status: 'CRITICAL',
                conditions: [
                    {
                        category: 'routing',
                        severity: 'CRITICAL',
                        message: '1 duplicate IP address(es) detected across active routes: ' + ip
                    }
                ]
            }
        });
        // 1. Initial mixed IPv6 duplicate-IP condition
        w.vpnRenderForwarderHealth(makeDupStatus(tc.initial));
        assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on ' + tc.desc + ' duplicate-IP condition');
        techDetails.open = false; // operator collapses accordion

        // Repeated poll with same address -> must STAY closed
        w.vpnRenderForwarderHealth(makeDupStatus(tc.initial));
        assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of ' + tc.desc + ' with same address');

        // 2. Replacement duplicate-IP condition arrives with identical count 1 and severity CRITICAL
        w.vpnRenderForwarderHealth(makeDupStatus(tc.replacement));
        assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when replacement duplicate-IP condition affects a different mixed IPv6 (' + tc.desc + ')');

        // Operator collapses accordion after observing new incident
        techDetails.open = false;
        w.vpnRenderForwarderHealth(makeDupStatus(tc.replacement));
        assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of replacement mixed IPv6 (' + tc.desc + ')');
    }

    // 5k. Escalated backend degradation ratio (1 of 3 vs 2 of 3 enabled backends) -> must AUTO-EXPAND
    const backendDegraded_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'backend',
                    severity: 'DEGRADED',
                    message: '1 of 3 enabled backends are degraded or unavailable (0 administratively disabled, not counted as failures)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(backendDegraded_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on 1 of 3 backend degradation condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with same 1 of 3 backend condition -> must STAY closed
    w.vpnRenderForwarderHealth(backendDegraded_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 1 of 3 backend condition');

    // Condition updates to 2 of 3 enabled backends degraded with identical total condition count 1 and severity DEGRADED
    const backendDegraded_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'backend',
                    severity: 'DEGRADED',
                    message: '2 of 3 enabled backends are degraded or unavailable (0 administratively disabled, not counted as failures)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(backendDegraded_2);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when backend degradation escalates from 1 of 3 to 2 of 3');

    // Operator collapses accordion after observing escalated backend degradation
    techDetails.open = false;
    w.vpnRenderForwarderHealth(backendDegraded_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 2 of 3 backend condition');

    // 5l. Actionable problem moving to a different backend node -> must AUTO-EXPAND
    const backendMove_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                {
                    category: 'dataplane',
                    severity: 'DEGRADED',
                    message: 'High packet loss on egress for Client X',
                    connection_id: 'c-100',
                    username: 'charlie',
                    backend_id: 'backend-1'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(backendMove_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on actionable problem on backend-1');
    techDetails.open = false; // operator collapses accordion

    // Poll with same backend-1 problem -> must STAY closed
    w.vpnRenderForwarderHealth(backendMove_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of problem on backend-1');

    // Problem shifts to backend-2 with identical count 1 and severity DEGRADED
    const backendMove_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                {
                    category: 'dataplane',
                    severity: 'DEGRADED',
                    message: 'High packet loss on egress for Client X',
                    connection_id: 'c-100',
                    username: 'charlie',
                    backend_id: 'backend-2'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(backendMove_2);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when actionable problem shifts to backend-2');

    // Operator collapses accordion after observing shifted problem
    techDetails.open = false;
    w.vpnRenderForwarderHealth(backendMove_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of problem on backend-2');

    // 5m. Stale sessions escalation (1 active live session(s) vs 2 active live session(s)) -> must AUTO-EXPAND
    const staleSessions_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'WARNING',
            conditions: [
                {
                    category: 'sessions',
                    severity: 'WARNING',
                    message: '1 active live session(s) have stale upstream handshakes (> 3m0s)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(staleSessions_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on 1 active live session stale handshake condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with same condition -> must STAY closed
    w.vpnRenderForwarderHealth(staleSessions_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 1 active live session stale handshake');

    // Condition updates to 2 active live sessions with total count remaining 1 and unchanged severity WARNING
    const staleSessions_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'WARNING',
            conditions: [
                {
                    category: 'sessions',
                    severity: 'WARNING',
                    message: '2 active live session(s) have stale upstream handshakes (> 3m0s)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(staleSessions_2);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when stale active live sessions escalate from 1 to 2');

    // Operator collapses accordion after observing escalated stale sessions
    techDetails.open = false;
    w.vpnRenderForwarderHealth(staleSessions_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 2 active live sessions stale handshake');

    // 5n. Invalid durable peer rows escalation (1 vs 2 invalid durable peer rows) -> must AUTO-EXPAND
    const invalidPeerRows_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: '1 invalid durable peer row(s) excluded from the desired set; those peers are not enforced upstream and their traffic is unauthorized until the rows are repaired'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(invalidPeerRows_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on 1 invalid durable peer row condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with same 1 invalid durable peer row condition -> must STAY closed
    w.vpnRenderForwarderHealth(invalidPeerRows_1);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 1 invalid durable peer row');

    // Condition updates to 2 invalid durable peer rows at unchanged total count 1 and severity DEGRADED
    const invalidPeerRows_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: '2 invalid durable peer row(s) excluded from the desired set; those peers are not enforced upstream and their traffic is unauthorized until the rows are repaired'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(invalidPeerRows_2);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when invalid durable peer rows escalate from 1 to 2');

    // Operator collapses accordion after observing escalated invalid peer rows
    techDetails.open = false;
    w.vpnRenderForwarderHealth(invalidPeerRows_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 2 invalid durable peer rows');

    // 5o. Peer sync divergence escalation (5 desired vs 3 actual peers -> 6 desired vs 3 actual peers) -> must AUTO-EXPAND
    const peerDivergence_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Peer sync divergence for 10s: 5 desired vs 3 actual peers'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(peerDivergence_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on peer sync divergence condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with elapsed time advancing (10s -> 20s) with same 5 desired vs 3 actual peers -> must STAY closed
    const peerDivergence_1_tick2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Peer sync divergence for 20s: 5 desired vs 3 actual peers'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(peerDivergence_1_tick2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when divergence duration advances with unchanged peer counts');

    // Condition updates to 6 desired vs 3 actual peers at unchanged count 1 and severity DEGRADED
    const peerDivergence_2 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Peer sync divergence for 20s: 6 desired vs 3 actual peers'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(peerDivergence_2);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when peer sync divergence escalates from 5 to 6 desired peers');

    // Operator collapses accordion after observing escalated peer divergence
    techDetails.open = false;
    w.vpnRenderForwarderHealth(peerDivergence_2);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of 6 desired vs 3 actual peers');

    // 5p. Cumulative sync/enqueue counter growth alone (10 -> 11 cumulative) with unchanged recent activity -> must STAY closed
    const activePeerSync_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Active peer sync failures: 1 sync, 0 enqueue in the last 30.0s (10 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(activePeerSync_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on active peer sync failure condition');
    techDetails.open = false; // operator collapses accordion

    // Poll with cumulative counter growth (10 -> 11 cumulative) and unchanged recent activity -> must STAY closed
    const activePeerSync_cumTick = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Active peer sync failures: 1 sync, 0 enqueue in the last 30.0s (11 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(activePeerSync_cumTick);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when cumulative sync counters advance with unchanged recent activity');

    // Recent active sync failure escalates from 1 to 2 sync failures -> must AUTO-EXPAND
    const activePeerSync_escalated = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Active peer sync failures: 2 sync, 0 enqueue in the last 30.0s (12 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(activePeerSync_escalated);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when active peer sync failures escalate from 1 to 2');
    techDetails.open = false; // operator collapses accordion

    // Repeated poll of 2 sync, 0 enqueue with further cumulative growth -> must STAY closed
    const activePeerSync_escalated_cumTick = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Active peer sync failures: 2 sync, 0 enqueue in the last 30.0s (13 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(activePeerSync_escalated_cumTick);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of escalated active sync failures');

    // 5q. Unresolved peer sync failure: cooling recent activity, advancing elapsed duration, and cumulative totals -> must STAY closed
    const unresolvedSync_1 = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Unresolved peer sync failure: database unavailable (last successful reconcile 2m; recent activity: 1 sync, 0 enqueue failures in the last 30.0s; 10 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(unresolvedSync_1);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand on unresolved peer sync failure condition');
    techDetails.open = false; // operator collapses accordion

    // Poll where recent activity cools from 1 to 0 recent sync failures -> must STAY closed
    const unresolvedSync_coolActivity = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Unresolved peer sync failure: database unavailable (last successful reconcile 2m; recent activity: 0 sync, 0 enqueue failures in the last 30.0s; 10 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(unresolvedSync_coolActivity);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when recent activity cools from 1 to 0 on unresolved peer sync failure');

    // Poll where elapsed duration alone advances (2m -> 3m) -> must STAY closed
    const unresolvedSync_advancingDuration = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Unresolved peer sync failure: database unavailable (last successful reconcile 3m; recent activity: 0 sync, 0 enqueue failures in the last 30.0s; 10 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(unresolvedSync_advancingDuration);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when elapsed duration alone advances on unresolved peer sync failure');

    // Poll where cumulative counters advance (10 -> 11 cumulative) -> must STAY closed
    const unresolvedSync_advancingCumulative = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Unresolved peer sync failure: database unavailable (last successful reconcile 3m; recent activity: 0 sync, 0 enqueue failures in the last 30.0s; 11 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(unresolvedSync_advancingCumulative);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed when cumulative counters advance on unresolved peer sync failure');

    // Condition updates to a different unresolved error -> must AUTO-EXPAND
    const unresolvedSync_differentError = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            conditions: [
                {
                    category: 'peer_sync',
                    severity: 'DEGRADED',
                    message: 'Unresolved peer sync failure: context deadline exceeded (last successful reconcile 3m; recent activity: 0 sync, 0 enqueue failures in the last 30.0s; 11 sync, 0 enqueue cumulative)'
                }
            ]
        }
    };
    w.vpnRenderForwarderHealth(unresolvedSync_differentError);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when unresolved peer sync failure error changes');
    techDetails.open = false; // operator collapses accordion

    // Repeated poll of the new error -> must STAY closed
    w.vpnRenderForwarderHealth(unresolvedSync_differentError);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll of replacement unresolved error');

    // 6. Polling render cycle 3 with NEW Problem B added -> must AUTO-EXPAND
    const degradedStatusB = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Return queue full drops (11 recent) for Client A', connection_id: 'c-10', username: 'charlie' },
                { severity: 'DEGRADED', message: 'Backend latency critical', connection_id: 'c-2', username: 'bob' }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusB);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when a new problem appears');

    // 7. Operator collapses again after observing new problem -> must STAY closed on poll with same 2 problems
    techDetails.open = false;
    w.vpnRenderForwarderHealth(degradedStatusB);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed after second manual collapse');

    // 7b. Increased count (from 2 to 3 problems) -> must AUTO-EXPAND
    const degradedStatusC = {
        forwarder_available: true,
        health_assessment: {
            status: 'DEGRADED',
            actionable_problems: [
                { severity: 'DEGRADED', message: 'Return queue full drops (11 recent) for Client A', connection_id: 'c-10', username: 'charlie' },
                { severity: 'DEGRADED', message: 'Backend latency critical', connection_id: 'c-2', username: 'bob' },
                { severity: 'WARNING', message: 'High route pressure', connection_id: 'c-3', username: 'david' }
            ]
        }
    };
    w.vpnRenderForwarderHealth(degradedStatusC);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when problem count increases');

    // Operator manually collapses after observing 3 problems
    techDetails.open = false;
    w.vpnRenderForwarderHealth(degradedStatusC);
    assert.strictEqual(techDetails.open, false, 'techDetails must remain closed on repeated poll with 3 problems');

    // 8. Problems resolve completely -> healthy state
    w.vpnRenderForwarderHealth({
        forwarder_available: true,
        health_assessment: { status: 'HEALTHY', conditions: [] }
    });
    assert.strictEqual(techDetails.open, false, 'techDetails remains closed when healthy');

    // 9. Problem recurs -> must AUTO-EXPAND again on transition from healthy to degraded
    w.vpnRenderForwarderHealth(degradedStatusA);
    assert.strictEqual(techDetails.open, true, 'techDetails must auto-expand when problem recurs from healthy state');

`
