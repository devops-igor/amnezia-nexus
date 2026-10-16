// VPN Forwarder Health Summary Orchestration, KPI Summary Bar & Route Pressure
// Extracted from web/templates/vpn.html per #496 (Epic #475 Phase 3).

function vpnRenderForwarderHealth(status) {
    function fmtBps(bps) {
        const b = Number(bps || 0);
        if (b >= 1e9) return (b / 1e9).toFixed(2) + ' Gbps';
        if (b >= 1e6) return (b / 1e6).toFixed(2) + ' Mbps';
        if (b >= 1e3) return (b / 1e3).toFixed(2) + ' Kbps';
        return b.toFixed(0) + ' bps';
    }
    function fmtPps(pps) {
        const p = Number(pps || 0);
        if (p >= 1e6) return (p / 1e6).toFixed(2) + ' Mpps';
        if (p >= 1e3) return (p / 1e3).toFixed(2) + ' Kpps';
        return p.toFixed(1) + ' pps';
    }
    function fmtDurationSec(sec) {
        const s = Math.max(0, Number(sec) || 0);
        if (s < 60) return s + 's';
        if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
        return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
    }
    function vpnFormatCountersSince(val) {
        if (!val) return '';
        try {
            const d = new Date(val);
            if (!isNaN(d.getTime())) {
                const y = d.getUTCFullYear();
                const m = String(d.getUTCMonth() + 1).padStart(2, '0');
                const day = String(d.getUTCDate()).padStart(2, '0');
                const h = String(d.getUTCHours()).padStart(2, '0');
                const min = String(d.getUTCMinutes()).padStart(2, '0');
                return y + '-' + m + '-' + day + ' ' + h + ':' + min + ' UTC';
            }
            return String(val);
        } catch (_) {
            return String(val);
        }
    }

    const isAvailable = !!status && status.forwarder_available === true;

    const statusBadge = document.getElementById('vpn-fwd-status-badge');
    const statusText = document.getElementById('vpn-fwd-status-text');
    const badgeElem = document.getElementById('vpn-fwd-routes-badge');
    const summaryStatus = document.getElementById('vpn-fwd-routes-summary-status');
    const tbody = document.getElementById('vpn-fwd-routes-tbody');
    const table = document.getElementById('vpn-fwd-routes-table');
    const emptyDiv = document.getElementById('vpn-fwd-routes-empty');

    if (!isAvailable) {
        if (statusBadge) statusBadge.className = 'badge';
        if (statusText) statusText.textContent = _('vpn_forwarder_unavailable') || 'Not reported';
        const headlineElem = document.getElementById('vpn-fwd-headline-summary');
        if (headlineElem) headlineElem.textContent = _('vpn_forwarder_unavailable') || 'Not reported';

        vpnResetHealthProblems();

        const countersSinceElem = document.getElementById('vpn-fwd-counters-since');
        if (countersSinceElem) { countersSinceElem.textContent = ''; countersSinceElem.style.display = 'none'; }
        const kpiLossSub = document.getElementById('vpn-kpi-packet-loss-sub');
        if (kpiLossSub) { kpiLossSub.textContent = ''; kpiLossSub.style.display = 'none'; }

        if (badgeElem) badgeElem.textContent = '0';
        if (summaryStatus) {
            summaryStatus.textContent = _('vpn_forwarder_unavailable') || 'Not reported';
            summaryStatus.style.color = 'var(--text-muted)';
        }
        if (tbody) tbody.textContent = '';
        if (table) table.style.display = 'none';
        if (emptyDiv) emptyDiv.style.display = 'block';
        const detailsElem = document.getElementById('vpn-fwd-routes-details');
        if (detailsElem) detailsElem.open = false;

        const kpiIds = ['vpn-kpi-throughput', 'vpn-kpi-routes-sessions', 'vpn-kpi-queue-pressure', 'vpn-kpi-packet-loss', 'vpn-kpi-client-engine', 'vpn-kpi-peer-sync', 'vpn-kpi-backends', 'vpn-kpi-slow-writes'];
        for (let i = 0; i < kpiIds.length; i++) {
            const el = document.getElementById(kpiIds[i]);
            if (el) { el.textContent = '-'; el.style.color = ''; }
        }

        vpnResetTechDiagnosticCards();

        if (typeof vpnDisposeChartInteractions === 'function') {
            vpnDisposeChartInteractions(true);
        }
        const historyIds = ['vpn-chart-throughput', 'vpn-chart-queue', 'vpn-chart-latency', 'vpn-chart-drops', 'vpn-chart-reasons', 'vpn-chart-backends', 'vpn-diag-be-traffic', 'vpn-history-fleet-note'];
        for (let i = 0; i < historyIds.length; i++) {
            const el = document.getElementById(historyIds[i]);
            if (el) {
                el.textContent = '';
                el.innerHTML = '';
            }
        }
        const extraHistoryIds = [
            'vpn-chart-throughput-badges', 'vpn-chart-drops-badges', 'vpn-chart-queue-badges', 'vpn-chart-latency-badges',
            'vpn-chart-throughput-axis', 'vpn-chart-drops-axis', 'vpn-chart-queue-axis', 'vpn-chart-latency-axis'
        ];
        for (let i = 0; i < extraHistoryIds.length; i++) {
            const el = document.getElementById(extraHistoryIds[i]);
            if (el) { el.textContent = ''; el.innerHTML = ''; }
        }
        const tipEl = document.getElementById('vpn-chart-tooltip');
        if (tipEl) { tipEl.style.display = 'none'; tipEl.innerHTML = ''; }
        if (typeof window !== 'undefined') window._vpnActiveChartHover = null;

        if (typeof vpnLastStatus !== 'undefined') {
            vpnLastStatus = null;
        }
        if (typeof window !== 'undefined' && typeof window.vpnLastStatus !== 'undefined') {
            window.vpnLastStatus = null;
        }
        if (typeof vpnLastSessions !== 'undefined' && vpnLastSessions && Array.isArray(vpnLastSessions.sessions)) {
            if (typeof renderSessions === 'function') {
                renderSessions(vpnLastSessions.sessions);
            }
        } else if (typeof window !== 'undefined' && window.vpnLastSessions && Array.isArray(window.vpnLastSessions.sessions)) {
            if (typeof renderSessions === 'function') {
                renderSessions(window.vpnLastSessions.sessions);
            }
        }

        return isAvailable;
    }

    if (typeof vpnLastStatus !== 'undefined') {
        vpnLastStatus = status;
    }
    if (typeof window !== 'undefined' && typeof window.vpnLastStatus !== 'undefined') {
        window.vpnLastStatus = status;
    }

    const countersSinceElem = document.getElementById('vpn-fwd-counters-since');
    if (countersSinceElem) {
        const rawSince = status.counters_since || status.uptime_baseline;
        if (rawSince) {
            const formattedSince = vpnFormatCountersSince(rawSince);
            countersSinceElem.textContent = vpnDiagText('vpn_fwd_counters_since', {time: formattedSince});
            countersSinceElem.style.display = '';
        } else {
            countersSinceElem.textContent = '';
            countersSinceElem.style.display = 'none';
        }
    }

    const cap = Number(status.forwarder_queue_capacity || 0);
    const occ = Number(status.forwarder_queue_occupancy || 0);
    const peak = Number(status.forwarder_queue_high_water || 0);
    const dropsQueueFull = Number(status.forwarder_drops_queue_full || 0);
    const dropsNoRoute = Number(status.forwarder_drops_no_route || 0);
    const dropsOversize = Number(status.forwarder_drops_packet_too_large || 0);
    const writeErrors = Number(status.forwarder_device_write_errors || 0);

    // Route Queues & Pressure (Problem-first by default)
    let routeItems = [];
    let allRouteList = [];
    if (Array.isArray(status.all_routes)) {
        allRouteList = status.all_routes;
    } else if (Array.isArray(status.problem_routes)) {
        allRouteList = status.problem_routes;
    }

    const showAll = (typeof window !== 'undefined' && typeof window.vpnShowAllRoutes !== 'undefined') ?
        window.vpnShowAllRoutes : (typeof vpnShowAllRoutes !== 'undefined' && vpnShowAllRoutes);
    routeItems = showAll ? allRouteList : (status.problem_routes || []);

    let routeHasPressure = false;
    for (let i = 0; i < allRouteList.length; i++) {
        const r = allRouteList[i];
        const currentPressure = typeof r.has_pressure === 'boolean' ? r.has_pressure :
            ((r.capacity > 0 && r.occupancy / r.capacity >= 0.8) ||
             Number(r.oldest_write_ms || 0) >= 100 ||
             Number(r.queue_full_drops_recent || 0) > 0 ||
             Number(r.write_errors_recent || 0) > 0 ||
             Number(r.write_stalls_recent || 0) > 0);
        if (currentPressure) {
            routeHasPressure = true;
        }
    }
    if (Array.isArray(status.problem_routes) && status.problem_routes.length > 0) {
        routeHasPressure = true;
    }

    if (badgeElem) {
        badgeElem.textContent = String(routeItems.length);
    }

    if (tbody) {
        tbody.textContent = '';
        for (let i = 0; i < routeItems.length; i++) {
            const r = routeItems[i];
            const peerKey = r.peer_key || '';
            const rOcc = Number(r.occupancy || 0);
            const rCap = Number(r.capacity || 0);
            const rPeak = Number(r.high_water || 0);
            const rDrops = Number(r.drops !== undefined ? r.drops : (r.queue_full_drops || 0));
            const rWrites = Number(r.write_count || 0);
            const rErrors = Number(r.write_errors || 0);
            const rP95 = Number(r.p95_write_ms || 0);
            const rNote = r.pressure_note || '';

            const tr = document.createElement('tr');

            // Complete payload telemetry. Unknown rates and never-observed traffic
            // are explicit; percentiles/max/errors/drops retain historical labels.
            function routeTooltip(route) {
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
                const lines = [];
                for (const key of Object.keys(route)) {
                    const value = route[key];
                    const label = labels[key] || key.replace(/_/g, ' ');
                    if (key === 'traffic' && value && typeof value === 'object') {
                        for (const name of Object.keys(value)) {
                            const unavailable = !value.available && ['rx_bytes_per_sec','tx_bytes_per_sec','rx_pps','tx_pps'].includes(name);
                            lines.push(label + ' ' + (trafficLabels[name] || name.replace(/_/g, ' ')) + ': ' + (unavailable ? _('vpn_diag_peer_sync_unavailable') : String(value[name])));
                        }
                    } else {
                        const unknown = key === 'last_traffic_age_sec' && Number(value) < 0 ||
                            key === 'p95_write_ms' && route.p95_write_samples === 0;
                        lines.push(label + ': ' + (unknown ? _('vpn_diag_peer_sync_unavailable') : (value === '' ? _('vpn_diag_peer_sync_none') : String(value))));
                    }
                }
                return lines.join('\n');
            }

            // Peer column (truncated + tooltip)
            const tdPeer = document.createElement('td');
            tdPeer.className = 'font-mono text-sm';
            tdPeer.style.whiteSpace = 'nowrap';
            tdPeer.title = routeTooltip(r);
            tdPeer.textContent = vpnFormatPeerKey(peerKey);
            tr.appendChild(tdPeer);

            // Queue column
            const tdQueue = document.createElement('td');
            tdQueue.className = 'font-mono text-sm';
            tdQueue.style.textAlign = 'right';
            tdQueue.textContent = rCap > 0 ? (rOcc + ' / ' + rCap) : String(rOcc);
            if (rCap > 0 && rOcc >= rCap * 0.8) {
                tdQueue.style.color = 'var(--danger)';
                tdQueue.style.fontWeight = 'bold';
            }
            tr.appendChild(tdQueue);

            // Peak column
            const tdPeak = document.createElement('td');
            tdPeak.className = 'font-mono text-sm';
            tdPeak.style.textAlign = 'right';
            tdPeak.textContent = String(rPeak);
            tr.appendChild(tdPeak);

            // Drops column
            const tdDrops = document.createElement('td');
            tdDrops.className = 'font-mono text-sm';
            tdDrops.style.textAlign = 'right';
            tdDrops.textContent = String(rDrops);
            if (Number(r.queue_full_drops_recent || 0) > 0) {
                tdDrops.style.color = 'var(--danger)';
                tdDrops.style.fontWeight = 'bold';
            }
            tr.appendChild(tdDrops);

            // Writes column
            const tdWrites = document.createElement('td');
            tdWrites.className = 'font-mono text-sm text-muted';
            tdWrites.style.textAlign = 'right';
            if (rNote) {
                tdWrites.textContent = rNote;
                tdWrites.style.color = 'var(--warning)';
            } else if (rErrors > 0) {
                tdWrites.textContent = vpnDiagText('vpn_diag_route_errors', {writes:rWrites, errors:rErrors});
                if (Number(r.write_errors_recent || 0) > 0) tdWrites.style.color = 'var(--warning)';
            } else if (rP95 > 0) {
                tdWrites.textContent = vpnDiagText('vpn_diag_route_p95', {value:rP95.toFixed(1)});
            } else {
                tdWrites.textContent = String(rWrites);
            }
            tr.appendChild(tdWrites);

            tbody.appendChild(tr);
        }
    }

    if (routeItems.length > 0 && table && emptyDiv) {
        table.style.display = '';
        emptyDiv.style.display = 'none';
    } else if (table && emptyDiv) {
        table.style.display = 'none';
        emptyDiv.style.display = 'block';
    }

    if (summaryStatus) {
        if (routeHasPressure) {
            summaryStatus.textContent = _('vpn_forwarder_pressure') || 'Pressure Detected';
            summaryStatus.style.color = 'var(--danger)';
        } else {
            summaryStatus.textContent = _('vpn_forwarder_no_route_pressure') || 'All route queues clear';
            summaryStatus.style.color = 'var(--text-muted)';
        }
    }

    const toggleBtn = document.getElementById('vpn-routes-toggle-all-btn');
    if (toggleBtn) {
        toggleBtn.textContent = showAll ? (_('vpn_fwd_show_problems') || 'Show Problems Only') : (_('vpn_fwd_show_all') || 'Show All Routes');
    }

    // Overall Forwarder Health Assessment
    const ha = status.health_assessment;

    if (statusBadge && statusText) {
        if (ha && ha.status) {
            const s = String(ha.status).toUpperCase();
            if (s === 'CRITICAL' || s === 'DOWN') {
                statusBadge.className = 'badge badge-danger';
                statusText.textContent = s === 'DOWN' ? (_('vpn_forwarder_down') || 'Down') : _('vpn_forwarder_critical');
            } else if (s === 'DEGRADED') {
                statusBadge.className = 'badge badge-warn';
                statusText.textContent = _('vpn_forwarder_degraded');
            } else if (s === 'HEALTHY') {
                statusBadge.className = 'badge badge-success';
                statusText.textContent = _('vpn_forwarder_healthy') || 'Healthy';
            } else {
                statusBadge.className = 'badge';
                statusText.textContent = _('vpn_forwarder_unavailable') || 'Not reported';
            }
        } else {
            statusBadge.className = 'badge';
            statusText.textContent = _('vpn_forwarder_unavailable');
        }
    }

    const headlineElem = document.getElementById('vpn-fwd-headline-summary');
    if (headlineElem) {
        if (ha && ha.summary_key && _(ha.summary_key) && _(ha.summary_key) !== ha.summary_key) {
            headlineElem.textContent = _(ha.summary_key);
        } else if (ha && ha.summary === 'Active VPN session routing or dataplane issues detected' && _('vpn_diag_summary_actionable_issues') && _('vpn_diag_summary_actionable_issues') !== 'vpn_diag_summary_actionable_issues') {
            headlineElem.textContent = _('vpn_diag_summary_actionable_issues');
        } else if (ha && ha.summary) {
            headlineElem.textContent = ha.summary;
        } else if (statusBadge && statusBadge.className.includes('badge-danger')) {
            headlineElem.textContent = _('vpn_diag_summary_critical');
        } else if (statusBadge && statusBadge.className.includes('badge-warn')) {
            headlineElem.textContent = _('vpn_diag_summary_degraded');
        } else {
            headlineElem.textContent = ha && ha.status === 'HEALTHY' ? _('vpn_diag_summary_healthy') : _('vpn_forwarder_unavailable');
        }
    }

    // Delegate Active Problems & Technical Details Accordion to health_problems.js
    vpnRenderActiveProblemsCards(status, { allRouteList: allRouteList, routeHasPressure: routeHasPressure });

    // Auto-expand route details only for current pressure.
    if (routeHasPressure) {
        const detailsElem = document.getElementById('vpn-fwd-routes-details');
        if (detailsElem) {
            detailsElem.open = true;
        }
    }

    // KPI Summary Bar
    const kpiThroughput = document.getElementById('vpn-kpi-throughput');
    if (kpiThroughput) {
        const rates = status.rates || {};
        const totalBps = (rates.rx_bps || 0) + (rates.tx_bps || 0);
        const totalPps = (rates.rx_pps || 0) + (rates.tx_pps || 0);
        kpiThroughput.textContent = rates.available !== true ? _('vpn_diag_traffic_unavailable') : fmtBps(totalBps) + ' / ' + fmtPps(totalPps);
    }

    const kpiRoutes = document.getElementById('vpn-kpi-routes-sessions');
    if (kpiRoutes) {
        const routing = status.routing_consistency || {};
        const rCount = routing.active_routes_count !== undefined ? routing.active_routes_count : allRouteList.length;
        const sCount = routing.active_sessions_count !== undefined ? routing.active_sessions_count : (status.connected_sessions || 0);
        kpiRoutes.textContent = rCount + ' / ' + sCount;
    }

    const kpiPressure = document.getElementById('vpn-kpi-queue-pressure');
    if (kpiPressure) {
        const qp = status.queue_pressure || {};
        const util = qp.utilization_pct !== undefined ? qp.utilization_pct.toFixed(1) + '%' : ((cap > 0 ? (occ / cap * 100).toFixed(1) : '0.0') + '%');
        const dur = fmtDurationSec(qp.total_seconds_above_50 || 0);
        kpiPressure.textContent = util + ' / ' + dur;
        if (qp.utilization_pct >= 80 || (cap > 0 && occ >= cap * 0.8)) {
            kpiPressure.style.color = 'var(--danger)';
        } else if (qp.utilization_pct >= 50 || (cap > 0 && occ >= cap * 0.5)) {
            kpiPressure.style.color = 'var(--warning)';
        } else {
            kpiPressure.style.color = '';
        }
    }

    const kpiLoss = document.getElementById('vpn-kpi-packet-loss');
    const kpiLossSub = document.getElementById('vpn-kpi-packet-loss-sub');
    if (kpiLoss) {
        const drops = status.drop_categories || {};
        const totDrops = drops.total_drops !== undefined ? drops.total_drops : (dropsQueueFull + dropsNoRoute + dropsOversize);
        const rate = drops.total_drop_rate_pps !== undefined ? drops.total_drop_rate_pps.toFixed(2) : '0.00';
        const rateStr = drops.rates_available !== true ? _('vpn_diag_loss_unavailable') : rate + ' pps';
        kpiLoss.textContent = vpnDiagText('vpn_diag_with_cumulative', {value:rateStr, count:totDrops});
        kpiLoss.style.color = drops.rates_available === true && Number(drops.total_drop_rate_pps || 0) > 0 ? 'var(--danger)' : '';
        const liveLabel = _('vpn_fwd_horizon_current') || 'Current / Live';
        const resetLabel = _('vpn_fwd_horizon_since_reset') || 'Since Startup / Reset';
        kpiLoss.title = liveLabel + ': ' + rateStr + ' | ' + resetLabel + ': ' + totDrops;
        if (kpiLossSub) {
            kpiLossSub.textContent = liveLabel + ': ' + rateStr + ' | ' + resetLabel + ': ' + totDrops;
            kpiLossSub.style.display = 'block';
        }
    }

    const kpiEngine = document.getElementById('vpn-kpi-client-engine');
    if (kpiEngine) {
        const isRunning = !!status.listener_running;
        kpiEngine.textContent = vpnDiagText('vpn_diag_engine_state', {state:isRunning ? _('vpn_running') : _('vpn_stopped')});
        kpiEngine.style.color = isRunning ? 'var(--success)' : 'var(--danger)';
    }

    const kpiPeerSync = document.getElementById('vpn-kpi-peer-sync');
    if (kpiPeerSync) {
        const psKpi = status.peer_sync;
        if (psKpi && typeof psKpi === 'object') {
            const psDesired = Number(psKpi.desired_peers || 0);
            const psActual = Number(psKpi.actual_peers || 0);
            kpiPeerSync.textContent = psActual + ' / ' + psDesired;
            kpiPeerSync.style.color = psDesired === psActual ? '' : 'var(--warning)';
        } else {
            kpiPeerSync.textContent = (_('vpn_diag_peer_sync_unavailable'));
            kpiPeerSync.style.color = 'var(--text-muted)';
        }
    }

    const kpiBackends = document.getElementById('vpn-kpi-backends');
    if (kpiBackends) {
        const be = status.backends || {};
        if (be.total_count !== undefined) {
            const enabled = be.eligibility_known ? Number(be.enabled_count || 0) : be.total_count;
            kpiBackends.textContent = vpnDiagText('vpn_diag_healthy_count', {healthy:be.healthy_count, enabled:enabled}) + (be.disabled_count ? vpnDiagText('vpn_diag_disabled_count', {count:be.disabled_count}) : '');
            kpiBackends.style.color = !be.healthy_count ? 'var(--danger)' : (be.healthy_count < enabled ? 'var(--warning)' : '');
        } else {
            kpiBackends.textContent = vpnDiagText('vpn_diag_active_count', {count:status.active_tunnels || 0});
        }
    }

    const kpiSlowWrites = document.getElementById('vpn-kpi-slow-writes');
    if (kpiSlowWrites) {
        const fl = status.forward_latency || {};
        const samples = Number(fl.p95_health_samples || 0);
        const recentStalls = Number(fl.stalls_recent || 0);
        const currentP95 = Number(fl.p95_health_ms || 0);
        const oldest = Number(fl.oldest_in_flight_ms || 0);
        const latencyText = samples > 0 ? currentP95.toFixed(1) + 'ms p95' : _('vpn_diag_latency_unavailable');
        kpiSlowWrites.textContent = vpnDiagText('vpn_diag_slow_writes', {count:recentStalls, latency:latencyText});
        kpiSlowWrites.title = vpnDiagText('vpn_diag_slow_writes_title', {count:fl.stalls || 0, latency:Number(fl.p95_ms || 0).toFixed(1)});
        kpiSlowWrites.style.color = oldest >= 1000 || (samples > 0 && currentP95 >= 100) ? 'var(--danger)' :
            (recentStalls > 0 || oldest >= 100 || (samples > 0 && currentP95 >= 50) ? 'var(--warning)' : '');
    }

    // Delegate Diagnostic Cards 1-4 to health_problems.js
    vpnRenderTechDiagnosticCards(status, {
        cap: cap,
        occ: occ,
        peak: peak,
        dropsQueueFull: dropsQueueFull,
        dropsNoRoute: dropsNoRoute,
        dropsOversize: dropsOversize,
        fmtBps: fmtBps
    });

    // Panel 10: Historical Trends
    if (typeof vpnRenderHistoryCharts === 'function' && status.historical_series) {
        vpnRenderHistoryCharts(status.historical_series);
    }

    if (typeof vpnLastSessions !== 'undefined' && vpnLastSessions && Array.isArray(vpnLastSessions.sessions)) {
        if (typeof renderSessions === 'function') {
            renderSessions(vpnLastSessions.sessions);
        }
    } else if (typeof window !== 'undefined' && window.vpnLastSessions && Array.isArray(window.vpnLastSessions.sessions)) {
        if (typeof renderSessions === 'function') {
            renderSessions(window.vpnLastSessions.sessions);
        }
    }

    return isAvailable;
}

if (typeof window !== 'undefined') {
    window.vpnRenderForwarderHealth = vpnRenderForwarderHealth;
}
