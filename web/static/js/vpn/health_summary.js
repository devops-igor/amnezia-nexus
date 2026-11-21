// VPN Health orchestration: the compact health panel, the four essential signals,
// the Advanced Diagnostics disclosure and the per-route pressure table.
// Extracted from web/templates/vpn.html per #496 (Epic #475 Phase 3), and reduced
// to a problem-first surface for #955.

// vpnDiagnosticsOpen records whether the operator opened Advanced Diagnostics.
// It is owned by user intent alone: polling, a new problem or a severity
// transition never flips it, because a collapsed panel that expands itself is
// exactly the behaviour #955 removes.
let vpnDiagnosticsOpen = false;

// vpnAssignText writes text only when it actually changes. The health summary is
// a polite atomic live region, so re-assigning identical text on every 5s poll
// would re-announce an unchanged status to a screen reader.
function vpnAssignText(el, text) {
    if (!el) return;
    const next = String(text === null || typeof text === 'undefined' ? '' : text);
    if (el.textContent === next) return;
    el.textContent = next;
}

function vpnFormatHealthTime(val) {
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

// vpnSignalMeasured reports whether a numeric value is an actual measurement.
// `undefined`/`null`/NaN/Infinity and an absent availability flag are NOT a
// sample, and rendering them as 0 would assert a measurement nobody took.
function vpnSignalMeasured(value) {
    return typeof value === 'number' && Number.isFinite(value);
}

// vpnFormatHealthBps renders a byte-per-second rate with its unit, or returns
// null when the payload carries no trustworthy rate.
function vpnFormatHealthBps(bps) {
    if (!vpnSignalMeasured(bps)) return null;
    const b = bps;
    // Bits per second, matching the diagnostics panel wording so the overview and
    // the panel never describe the same number in different units.
    if (b >= 1e9) return (b / 1e9).toFixed(2) + ' Gbps';
    if (b >= 1e6) return (b / 1e6).toFixed(2) + ' Mbps';
    if (b >= 1e3) return (b / 1e3).toFixed(2) + ' Kbps';
    return b.toFixed(0) + ' bps';
}

function vpnFormatHealthPps(pps) {
    if (!vpnSignalMeasured(pps)) return null;
    if (pps >= 1e6) return (pps / 1e6).toFixed(2) + ' Mpps';
    if (pps >= 1e3) return (pps / 1e3).toFixed(2) + ' Kpps';
    return pps.toFixed(1) + ' pps';
}

// vpnSetSignalValue writes a measured value plus its unit, or the not-measured
// text. A measured zero renders as a number with its unit; an unmeasured value
// never becomes "0".
function vpnSetSignalValue(id, value, unit) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = '';
    // A null/undefined value is an ABSENT measurement, never a numeric zero.
    if (value === null || typeof value === 'undefined') {
        el.classList.add('vpn-not-measured');
        el.textContent = _('vpn_diag_not_measured');
        return;
    }
    el.classList.remove('vpn-not-measured');
    const valueSpan = document.createElement('span');
    valueSpan.className = 'font-mono';
    valueSpan.textContent = String(value);
    el.appendChild(valueSpan);
    if (unit) {
        const unitSpan = document.createElement('span');
        unitSpan.className = 'vpn-signal-unit';
        unitSpan.textContent = unit;
        const separator = document.createTextNode(' ');
        el.appendChild(separator);
        el.appendChild(unitSpan);
    }
}

function vpnSetSignalSub(id, text, isProblem) {
    const el = document.getElementById(id);
    if (!el) return;
    vpnAssignText(el, text || '');
    if (isProblem) {
        el.classList.add('vpn-signal-mismatch');
    } else {
        el.classList.remove('vpn-signal-mismatch');
    }
}

// vpnRenderSignals renders the four essential signals. Configured peers,
// synchronized peers and live sessions are separate facts: only the reported
// active-session count feeds the Sessions signal, and a route mismatch appears
// only when routing_consistency actually reports one.
function vpnRenderSignals(status) {
    const s = (status && typeof status === 'object') ? status : null;

    // Backends: disabled inventory is never counted as failed, and when
    // eligibility is unknown the enabled denominator is not invented.
    const be = (s && s.backends) || {};
    if (vpnSignalMeasured(be.healthy_count) && be.eligibility_known === true && vpnSignalMeasured(be.enabled_count)) {
        vpnSetSignalValue('vpn-signal-backends-value', be.healthy_count, '/ ' + be.enabled_count);
        vpnSetSignalSub('vpn-signal-backends-sub', _('vpn_signal_backends_enabled'), false);
    } else if (vpnSignalMeasured(be.healthy_count) && vpnSignalMeasured(be.total_count)) {
        vpnSetSignalValue('vpn-signal-backends-value', be.healthy_count, '/ ' + be.total_count);
        vpnSetSignalSub('vpn-signal-backends-sub', _('vpn_signal_backends_total'), false);
    } else {
        vpnSetSignalValue('vpn-signal-backends-value', null);
        vpnSetSignalSub('vpn-signal-backends-sub', _('vpn_diag_not_measured'), false);
    }

    // Sessions: the LIVE count only. connected_sessions is the reported live
    // session count; routing_consistency.active_sessions_count is the routing
    // view's count and is used only as a fallback when the live field is absent.
    // Configured peers and synchronized peers are never substituted here.
    const rcCounts = (s && s.routing_consistency) || {};
    const sessions = (s && vpnSignalMeasured(s.connected_sessions)) ? s.connected_sessions
        : (vpnSignalMeasured(rcCounts.active_sessions_count) ? rcCounts.active_sessions_count : null);
    const sessionsEl = document.getElementById('vpn-sessions');
    if (sessionsEl) {
        vpnAssignText(sessionsEl, sessions === null ? _('vpn_diag_not_measured') : String(sessions));
        if (sessions === null) {
            sessionsEl.classList.add('vpn-not-measured');
        } else {
            sessionsEl.classList.remove('vpn-not-measured');
        }
    }
    // A route mismatch is shown only when the payload reports one, never inferred
    // from count equality.
    const rc = (s && s.routing_consistency) || {};
    const withoutRoute = Array.isArray(rc.sessions_without_route) ? rc.sessions_without_route.length : 0;
    const mismatchEl = document.getElementById('vpn-session-mismatch');
    if (mismatchEl) {
        if (withoutRoute > 0) {
            mismatchEl.hidden = false;
            mismatchEl.textContent = vpnDiagText('vpn_signal_sessions_mismatch', {count:withoutRoute});
        } else {
            mismatchEl.hidden = true;
            mismatchEl.textContent = '';
        }
    }

    // Throughput: current rate, only when the rate payload says it is available.
    const rates = (s && s.rates) || {};
    const throughputTotalBps = (Number(rates.rx_bps) || 0) + (Number(rates.tx_bps) || 0);
    const throughputValue = (rates.available === true) ? vpnFormatHealthBps(throughputTotalBps) : null;
    const throughputEl = document.getElementById('vpn-signal-throughput-value');
    if (throughputEl) {
        throughputEl.textContent = '';
        if (throughputValue === null) {
            throughputEl.classList.add('vpn-not-measured');
            throughputEl.textContent = _('vpn_diag_not_measured');
        } else {
            throughputEl.classList.remove('vpn-not-measured');
            const parts = throughputValue.split(' ');
            const num = document.createElement('span');
            num.className = 'font-mono';
            num.textContent = parts[0];
            const unit = document.createElement('span');
            unit.className = 'vpn-signal-unit';
            unit.textContent = parts.slice(1).join(' ');
            throughputEl.appendChild(num);
            throughputEl.appendChild(document.createTextNode(' '));
            throughputEl.appendChild(unit);
        }
    }
    vpnSetSignalSub('vpn-signal-throughput-sub',
        throughputValue === null ? _('vpn_signal_throughput_none') : _('vpn_signal_throughput_horizon'), false);

    // Dataplane drops: the CURRENT rate and the since-reset total are separate
    // facts with separate labels and units. Scoped to the dataplane, not
    // end-to-end packet loss.
    const dc = (s && s.drop_categories) || {};
    const dropRate = (dc.rates_available === true && vpnSignalMeasured(dc.total_drop_rate_pps)) ? dc.total_drop_rate_pps : null;
    const dropTotal = vpnSignalMeasured(dc.total_drops) ? dc.total_drops : null;
    vpnSetSignalValue('vpn-signal-drops-value', dropRate === null ? null : dropRate.toFixed(2), dropRate === null ? '' : _('vpn_unit_dps'));
    // The supporting line always states the dataplane scope, so the number cannot
    // be read as end-to-end packet loss, and always separates the cumulative
    // since-reset count from the current rate.
    const dropSubParts = [];
    if (dropRate === null) {
        dropSubParts.push(_('vpn_signal_drops_unmeasured'));
    }
    if (dropTotal !== null) {
        dropSubParts.push(vpnDiagText('vpn_signal_drops_since_reset', {count:dropTotal}));
    }
    dropSubParts.push(_('vpn_dataplane_drops_scope'));
    vpnSetSignalSub('vpn-signal-drops-sub', dropSubParts.join(' \u00b7 '), false);
}

// vpnSetDiagnosticsOpen is the ONLY writer of #vpn-diagnostics visibility. It is
// called from explicit operator controls, so polling cannot change it.
function vpnSetDiagnosticsOpen(open, focusTarget) {
    const panel = document.getElementById('vpn-diagnostics');
    const entry = document.getElementById('vpn-advanced-entry');
    if (!panel || !entry) return;
    vpnDiagnosticsOpen = !!open;
    panel.hidden = !vpnDiagnosticsOpen;
    entry.setAttribute('aria-expanded', String(vpnDiagnosticsOpen));
    if (focusTarget === 'panel') {
        const title = document.getElementById('vpn-diagnostics-title');
        if (title && typeof title.focus === 'function') title.focus();
    } else if (focusTarget === 'entry' && typeof entry.focus === 'function') {
        entry.focus();
    }
}

function vpnToggleDiagnostics() {
    vpnSetDiagnosticsOpen(!vpnDiagnosticsOpen, vpnDiagnosticsOpen ? 'entry' : 'panel');
}

function vpnCloseDiagnostics() {
    vpnSetDiagnosticsOpen(false, 'entry');
}

function vpnRenderRoutePressure(status, allRouteList) {
    const isAvailable = !!status && status.forwarder_available === true;
    const badgeElem = document.getElementById('vpn-fwd-routes-badge');
    const summaryStatus = document.getElementById('vpn-fwd-routes-summary-status');
    const tbody = document.getElementById('vpn-fwd-routes-tbody');
    const table = document.getElementById('vpn-fwd-routes-table');
    const emptyDiv = document.getElementById('vpn-fwd-routes-empty');

    if (!isAvailable) {
        if (badgeElem) badgeElem.textContent = '0';
        if (summaryStatus) {
            summaryStatus.textContent = _('vpn_forwarder_unavailable') || 'Not reported';
            summaryStatus.style.color = 'var(--text-muted)';
        }
        if (tbody) tbody.textContent = '';
        if (table) table.hidden = true;
        if (emptyDiv) emptyDiv.hidden = false;
        return { routeHasPressure: false };
    }

    const showAll = (typeof window !== 'undefined' && typeof window.vpnShowAllRoutes !== 'undefined') ?
        window.vpnShowAllRoutes : (typeof vpnShowAllRoutes !== 'undefined' && vpnShowAllRoutes);
    const routeItems = showAll ? allRouteList : (status.problem_routes || []);

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
        table.hidden = false;
        emptyDiv.hidden = true;
    } else if (table && emptyDiv) {
        table.hidden = true;
        emptyDiv.hidden = false;
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

    return { routeHasPressure: routeHasPressure };
}

// vpnRenderHealthStatus renders the single visible status. A reported active
// warning may present as Warning even when the legacy assessment says HEALTHY,
// as #955 specifies; the assessment and severity logic itself is untouched.
function vpnRenderHealthStatus(status, problemCount) {
    const ha = (status && status.health_assessment) || {};
    const rawStatus = ha.status ? String(ha.status).toUpperCase() : '';
    const statusBadge = document.getElementById('vpn-fwd-status-badge');
    const statusText = document.getElementById('vpn-fwd-status-text');
    const statusIcon = document.getElementById('vpn-fwd-status-icon');
    const headlineElem = document.getElementById('vpn-fwd-headline-summary');

    let label = '';
    let badgeClass = 'badge';
    let icon = '#icon-activity';
    let summary = '';

    if (rawStatus === 'CRITICAL' || rawStatus === 'DOWN') {
        badgeClass = 'badge badge-danger';
        label = rawStatus === 'DOWN' ? (_('vpn_forwarder_down') || 'Down') : _('vpn_forwarder_critical');
        icon = '#icon-x';
        summary = _('vpn_diag_summary_critical');
    } else if (rawStatus === 'DEGRADED') {
        badgeClass = 'badge badge-warn';
        label = _('vpn_forwarder_degraded');
        icon = '#icon-alert-triangle';
        summary = _('vpn_diag_summary_degraded');
    } else if (rawStatus === 'WARNING' || rawStatus === 'WARN') {
        // A reported warning is a warning. The assessment itself is untouched; only
        // the presentation names it.
        badgeClass = 'badge badge-warn';
        label = _('vpn_forwarder_warning');
        icon = '#icon-alert-triangle';
        summary = _('vpn_diag_summary_actionable_issues');
    } else if (rawStatus === 'HEALTHY' && problemCount > 0) {
        // Warning-only conditions keep a HEALTHY assessment; present the problem
        // instead of a healthy badge.
        badgeClass = 'badge badge-warn';
        label = _('vpn_forwarder_warning');
        icon = '#icon-alert-triangle';
        summary = _('vpn_diag_summary_actionable_issues');
    } else if (rawStatus === 'HEALTHY') {
        badgeClass = 'badge badge-success';
        label = _('vpn_forwarder_healthy') || 'Healthy';
        icon = '#icon-check';
        summary = _('vpn_diag_summary_healthy');
    } else {
        // No trustworthy assessment: neutral, never a healthy badge.
        badgeClass = 'badge';
        label = _('vpn_forwarder_unavailable') || 'Not reported';
        icon = '#icon-activity';
        summary = _('vpn_forwarder_unavailable') || 'Not reported';
    }

    // A better human sentence from the payload wins over the generic fallback.
    if (rawStatus && ha.summary_key && _(ha.summary_key) && _(ha.summary_key) !== ha.summary_key) {
        summary = _(ha.summary_key);
    } else if (rawStatus && ha.summary) {
        summary = ha.summary;
    }

    if (statusBadge && statusText) {
        statusBadge.className = badgeClass;
        vpnAssignText(statusText, label);
        statusBadge.hidden = false;
        if (statusIcon && typeof statusIcon.setAttribute === 'function') {
            statusIcon.setAttribute('href', icon);
        }
    }
    vpnAssignText(headlineElem, summary);
    // The folded problem counts: the headline carries the number of active
    // problems and how many users/configs they affect, so the information the old
    // separate summary strip showed is still visible without a second banner.
    vpnSetProblemCounts(status, problemCount, headlineElem);
    return label;
}

// vpnSetProblemCounts writes the affected-user/config counts into one secondary
// line under the summary. It is additive detail for a problem state only; a healthy
// or unavailable page shows nothing extra.
function vpnSetProblemCounts(status, problemCount, headlineElem) {
    const countsEl = document.getElementById('vpn-fwd-problem-counts');
    if (!countsEl) return;
    const ha = (status && status.health_assessment) || {};
    const problems = Array.isArray(ha.actionable_problems) ? ha.actionable_problems : [];
    if (!problemCount || problemCount <= 0) {
        vpnAssignText(countsEl, '');
        countsEl.hidden = true;
        return;
    }
    const users = new Set(problems.map(function(p) { return p.user_id || p.username; }).filter(Boolean)).size;
    const configs = new Set(problems.map(function(p) {
        return p.connection_id || (p.user_id ? p.user_id + ':' + (p.connection_name || '') : p.connection_name);
    }).filter(Boolean)).size;
    // These three keys are printf-style (%d), so substitute directly.
    const parts = [(_('vpn_fwd_active_problems_count') || '%d active problems').replace('%d', problemCount)];
    if (users > 0) parts.push((_('vpn_fwd_affected_users_count') || '%d affected users').replace('%d', users));
    if (configs > 0) parts.push((_('vpn_fwd_affected_configs_count') || '%d client configs').replace('%d', configs));
    vpnAssignText(countsEl, parts.join(' \u00b7 '));
    countsEl.hidden = false;
}

function vpnRenderForwarderHealth(status) {
    const isAvailable = !!status && status.forwarder_available === true;

    const card = document.getElementById('vpn-forwarder-card');
    if (card && typeof card.setAttribute === 'function') {
        card.setAttribute('aria-busy', 'false');
    }

    if (!isAvailable) {
        vpnRenderHealthStatus(null, 0);
        vpnRenderActiveProblemsCards(null, {});
        vpnResetTechDiagnosticCards();
        vpnRenderSignals(null);
        vpnRenderRoutePressure(null, []);

        const countersSinceElem = document.getElementById('vpn-fwd-counters-since');
        if (countersSinceElem) countersSinceElem.textContent = '-';

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
        if (tipEl) { tipEl.hidden = true; tipEl.innerHTML = ''; }
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
        countersSinceElem.textContent = rawSince
            ? vpnDiagText('vpn_fwd_counters_since', {time: vpnFormatHealthTime(rawSince)})
            : _('vpn_diag_not_measured');
    }

    const cap = Number(status.forwarder_queue_capacity || 0);
    const occ = Number(status.forwarder_queue_occupancy || 0);
    const peak = Number(status.forwarder_queue_high_water || 0);
    const dropsQueueFull = Number(status.forwarder_drops_queue_full || 0);
    const dropsNoRoute = Number(status.forwarder_drops_no_route || 0);
    const dropsOversize = Number(status.forwarder_drops_packet_too_large || 0);

    let allRouteList = [];
    if (Array.isArray(status.all_routes)) {
        allRouteList = status.all_routes;
    } else if (Array.isArray(status.problem_routes)) {
        allRouteList = status.problem_routes;
    }

    const pressure = vpnRenderRoutePressure(status, allRouteList);
    const routeHasPressure = pressure.routeHasPressure;

    // Problems and the single health status are rendered together: the status
    // label depends on whether an actionable problem exists.
    const problemCount = vpnRenderActiveProblemsCards(status, {
        allRouteList: allRouteList,
        routeHasPressure: routeHasPressure
    });
    vpnRenderHealthStatus(status, typeof problemCount === 'number' ? problemCount : 0);
    vpnRenderSignals(status);

    // Delegate the technical detail panels and the historical charts. They live
    // inside the Advanced Diagnostics disclosure, whose open state is never
    // touched here.
    vpnRenderTechDiagnosticCards(status, {
        cap: cap,
        occ: occ,
        peak: peak,
        dropsQueueFull: dropsQueueFull,
        dropsNoRoute: dropsNoRoute,
        dropsOversize: dropsOversize,
        fmtBps: vpnFormatHealthBps
    });

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
    window.vpnRenderSignals = vpnRenderSignals;
    window.vpnSetDiagnosticsOpen = vpnSetDiagnosticsOpen;
    window.vpnToggleDiagnostics = vpnToggleDiagnostics;
    window.vpnCloseDiagnostics = vpnCloseDiagnostics;
    window.vpnFormatHealthBps = vpnFormatHealthBps;
}
