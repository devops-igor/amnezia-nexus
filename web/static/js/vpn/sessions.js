/* ===== VPN Sessions & Connection Troubleshooting Controller ===== */

var vpnSessionsTableInstance = null;
var vpnLastSessions = null;
var vpnSessionsStale = false;
var vpnSessionsFilterOnlyProblems = false;
var vpnExpandedSessionIds = (typeof vpnExpandedSessionIds !== 'undefined' && vpnExpandedSessionIds instanceof Set)
    ? vpnExpandedSessionIds
    : new Set();

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

function vpnFormatBytes(bytes) {
    if (typeof Telemetry !== 'undefined' && typeof Telemetry.formatBytes === 'function') {
        return Telemetry.formatBytes(bytes);
    }
    const b = Number(bytes || 0);
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(2) + ' KB';
    return b + ' B';
}

function vpnFindRouteForSession(s) {
    if (!s || !vpnLastStatus) return null;
    const routes = [];
    if (Array.isArray(vpnLastStatus.all_routes)) {
        routes.push(...vpnLastStatus.all_routes);
    }
    if (Array.isArray(vpnLastStatus.problem_routes)) {
        for (let i = 0; i < vpnLastStatus.problem_routes.length; i++) {
            const pr = vpnLastStatus.problem_routes[i];
            if (!routes.includes(pr)) {
                routes.push(pr);
            }
        }
    }
    if (!routes.length) return null;

    // 1. Exact session ID match first
    const sSess = (s.session_id !== undefined && s.session_id !== null && s.session_id !== '') ? s.session_id : s.id;
    const hasSSess = sSess !== undefined && sSess !== null && sSess !== '';
    if (hasSSess) {
        for (let i = 0; i < routes.length; i++) {
            const r = routes[i];
            const rSess = r && ((r.session_id !== undefined && r.session_id !== null && r.session_id !== '') ? r.session_id : r.id);
            if (r && rSess !== undefined && rSess !== null && rSess !== '' && String(sSess) === String(rSess)) {
                return r;
            }
        }
    }

    // 2. Connection ID match second
    // Permitted ONLY when session ID is absent on s or r.
    // If both provide a session ID and they differ, r is strictly disqualified for s.
    const sConn = s.connection_id;
    const hasSConn = sConn !== undefined && sConn !== null && sConn !== '';
    if (hasSConn) {
        for (let i = 0; i < routes.length; i++) {
            const r = routes[i];
            if (!r) continue;
            const rSess = (r.session_id !== undefined && r.session_id !== null && r.session_id !== '') ? r.session_id : r.id;
            const hasRSess = rSess !== undefined && rSess !== null && rSess !== '';
            if (hasSSess && hasRSess && String(sSess) !== String(rSess)) {
                continue;
            }
            const rConn = r.connection_id;
            const hasRConn = rConn !== undefined && rConn !== null && rConn !== '';
            if (hasRConn && String(sConn) === String(rConn)) {
                return r;
            }
        }
    }

    // 3. Fall back to assigned IP match as display/fallback
    // Permitted ONLY when both session ID and connection ID are absent on one/both sides.
    // If session IDs contradict, or connection IDs contradict, r is strictly disqualified.
    if (s.assigned_ip) {
        for (let i = 0; i < routes.length; i++) {
            const r = routes[i];
            if (!r || !r.assigned_ip || s.assigned_ip !== r.assigned_ip) {
                continue;
            }
            const rSess = (r.session_id !== undefined && r.session_id !== null && r.session_id !== '') ? r.session_id : r.id;
            const hasRSess = rSess !== undefined && rSess !== null && rSess !== '';
            if (hasSSess && hasRSess && String(sSess) !== String(rSess)) {
                continue;
            }
            const rConn = r.connection_id;
            const hasRConn = rConn !== undefined && rConn !== null && rConn !== '';
            if (hasSConn && hasRConn && String(sConn) === String(rConn)) {
                continue;
            }
            const sAbsent = !hasSSess && !hasSConn;
            const rAbsent = !hasRSess && !hasRConn;
            if (sAbsent || rAbsent) {
                return r;
            }
        }
    }

    return null;
}

function vpnRenderSessionRow(s, route) {
    if (route === undefined) {
        route = vpnFindRouteForSession(s);
    }
    const tr = document.createElement('tr');
    tr.setAttribute('data-status', (s && s.status) || '');

    const sessId = s ? (s.session_id || s.id) : null;
    if (sessId !== null && sessId !== undefined && sessId !== '') {
        tr.setAttribute('data-session-id', sessId);
    }
    tr._sessionData = s;
    if (sessId && vpnExpandedSessionIds && vpnExpandedSessionIds.has(sessId)) {
        if (tr.classList) tr.classList.add('row-expanded');
        else tr.className = ((tr.className || '') + ' row-expanded').trim();
    }

    // 1. User cell
    const tdUser = document.createElement('td');
    tdUser.className = 'font-weight-600';
    tdUser.style.cursor = 'pointer';
    tdUser.setAttribute('data-action', 'vpn-toggle-session');
    if (sessId !== null && sessId !== undefined && sessId !== '') {
        tdUser.setAttribute('data-session-id', sessId);
    }
    const safeUsername = (typeof UI !== 'undefined' && UI.escapeHtml) ? UI.escapeHtml((s && s.username) || '-') : ((s && s.username) || '-');
    const safeConfig = (typeof UI !== 'undefined' && UI.escapeHtml) ? UI.escapeHtml((s && s.connection_name) || '-') : ((s && s.connection_name) || '-');
    const safeIP = (typeof UI !== 'undefined' && UI.escapeHtml) ? UI.escapeHtml((s && s.assigned_ip) || '-') : ((s && s.assigned_ip) || '-');
    tdUser.innerHTML = `
        <div style="display: inline-flex; align-items: center; gap: var(--space-xs); max-width: 100%; min-width: 0;">
            <svg class="icon vpn-expand-icon" style="width: 14px; height: 14px; flex-shrink: 0; transition: transform 0.15s ease;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><use href="#icon-chevron-right"></use></svg>
            <div style="min-width: 0; max-width: 100%;">
                <div class="font-weight-600" style="white-space: nowrap;">${safeUsername}</div>
                <div class="text-muted text-xs font-mono" style="font-weight: normal; overflow: hidden; text-overflow: ellipsis; max-width: 100%;">${safeConfig} &bull; ${safeIP}</div>
            </div>
        </div>
    `;
    tr.appendChild(tdUser);

    // 2. Server cell
    const tdServer = document.createElement('td');
    tdServer.className = 'font-weight-600';
    tdServer.textContent = (s && s.server_name) || '-';
    tr.appendChild(tdServer);

    // 3. Live Traffic cell
    const tdTraffic = document.createElement('td');
    tdTraffic.className = 'font-mono text-sm';
    let rx = 0;
    let tx = 0;
    if (route && route.traffic) {
        rx = route.traffic.rx_bps !== undefined ? route.traffic.rx_bps : ((route.traffic.rx_bytes_per_sec || 0) * 8);
        tx = route.traffic.tx_bps !== undefined ? route.traffic.tx_bps : ((route.traffic.tx_bytes_per_sec || 0) * 8);
        tdTraffic.textContent = `↓ ${fmtBps(rx)} ↑ ${fmtBps(tx)}`;
    } else {
        tdTraffic.textContent = '-';
    }
    const totalBps = (route && route.traffic) ? (rx + tx) : 0;
    tdTraffic.setAttribute('data-sort-value', String(totalBps));
    tr.appendChild(tdTraffic);

    // 4. Packet Loss cell
    const tdLoss = document.createElement('td');
    tdLoss.className = 'font-mono text-sm';
    let dropRate = 0;
    let drops = 0;
    let recentDrops = 0;
    if (route) {
        dropRate = Number(route.queue_full_drop_rate_pps || 0);
        drops = Number(route.drops !== undefined ? route.drops : (route.queue_full_drops || 0));
        recentDrops = Number(route.queue_full_drops_recent || 0);
        if (dropRate > 0 || recentDrops > 0) {
            let dropText = '';
            if (dropRate > 0) {
                const lossFmt = _('vpn_fwd_loss_rate_format') || '%s drops/s (%d total)';
                dropText = lossFmt.replace('%s', dropRate.toFixed(1)).replace('%d', drops);
            } else {
                const recentLabel = _('vpn_fwd_recent') || 'recent';
                dropText = `${recentDrops} ${recentLabel} (${drops})`;
            }
            tdLoss.innerHTML = `<span class="text-danger font-weight-600">${dropText}</span>`;
        } else if (drops > 0) {
            tdLoss.textContent = String(drops);
        } else {
            tdLoss.textContent = '0';
        }
    } else {
        tdLoss.textContent = '-';
    }
    let sortLoss = 0;
    if (route) {
        if (dropRate > 0) {
            // Tier 1: Active drop rate (millidrops/sec integer encoding to preserve decimal precision without float loss)
            const scaledRate = Math.max(1, Math.round(dropRate * 1000));
            sortLoss = 1e13 + Math.min(scaledRate, 999999999);
        } else if (recentDrops > 0) {
            // Tier 2: Recent drops with zero active drop rate
            sortLoss = 1e10 + Math.min(recentDrops, 999999999);
        } else if (drops > 0) {
            // Tier 3: Historical lifetime drops with zero recent and zero active drops
            sortLoss = Math.min(drops, 999999999);
        }
    }
    tdLoss.setAttribute('data-sort-value', String(sortLoss));
    tr.appendChild(tdLoss);

    // 5. Status cell
    const tdStatus = document.createElement('td');
    const isNominalActive = s && (s.status === 'connected' || s.status === 'active');
    if (route && (route.has_pressure || (Number(route.queue_full_drops_recent || 0) > 0) || (Number(route.write_errors_recent || 0) > 0) || (Number(route.write_stalls_recent || 0) > 0))) {
        tdStatus.innerHTML = `<span class="badge badge-warn">${_('vpn_forwarder_degraded')}</span>`;
    } else if (isNominalActive) {
        if (!route) {
            let unroutableLabel = _('vpn_forwarder_unroutable');
            if (!unroutableLabel || unroutableLabel === 'vpn_forwarder_unroutable') {
                unroutableLabel = 'Unroutable';
            }
            tdStatus.innerHTML = `<span class="badge badge-warn">${unroutableLabel}</span>`;
        } else {
            let activeLabel = _('vpn_status_active');
            if (!activeLabel || activeLabel === 'vpn_status_active') {
                activeLabel = (typeof vpnStatusLabel === 'function' ? vpnStatusLabel('active') : '') || _('active') || 'Active';
            }
            tdStatus.innerHTML = `<span class="badge badge-success">${activeLabel}</span>`;
        }
    } else {
        const otherStatus = s ? (typeof vpnStatusLabel === 'function' ? vpnStatusLabel(s.status) : (s.status || '-')) : '-';
        tdStatus.innerHTML = `<span class="badge badge-secondary">${otherStatus}</span>`;
    }
    tr.appendChild(tdStatus);

    return tr;
}

function vpnCreateSessionDrilldownRow(s, route) {
    if (route === undefined) {
        route = vpnFindRouteForSession(s);
    }
    const tr = document.createElement('tr');
    tr.className = 'vpn-session-drilldown-row table-empty-state';
    const sessId = s ? (s.session_id || s.id) : null;
    if (sessId !== null && sessId !== undefined && sessId !== '') {
        tr.setAttribute('data-parent-session-id', sessId);
    }

    const td = document.createElement('td');
    td.colSpan = 5;
    td.style.background = 'var(--bg-surface-secondary, rgba(0,0,0,0.02))';
    td.style.padding = 'var(--space-md) var(--space-lg)';

    if (!route) {
        td.innerHTML = `<div class="text-muted" style="font-size: 0.85rem; font-style: italic;">${_('vpn_drilldown_no_telemetry')}</div>`;
    } else {
        // 1) Latency Reservoirs (vpn_drilldown_reservoir)
        const p95Val = (route.reservoir && route.reservoir.p95_ms !== undefined) ? route.reservoir.p95_ms : route.p95_write_ms;
        const p95Samples = (route.reservoir && route.reservoir.samples !== undefined) ? route.reservoir.samples : (route.p95_write_samples !== undefined ? route.p95_write_samples : 0);
        const p95Str = (p95Samples === 0 || p95Val === undefined) ? '-' : (Number(p95Val || 0).toFixed(1) + ' ms');
        const maxVal = (route.reservoir && route.reservoir.max_ms !== undefined) ? route.reservoir.max_ms : (route.max_write_ms !== undefined ? route.max_write_ms : route.oldest_write_ms);
        const maxStr = (maxVal !== undefined && maxVal !== null) ? (Number(maxVal || 0).toFixed(1) + ' ms') : '-';

        // 2) Queue Dwell & Buffer (vpn_drilldown_dwell)
        const occ = route.queue_occupancy !== undefined ? route.queue_occupancy : (route.occupancy || 0);
        const cap = route.queue_capacity !== undefined ? route.queue_capacity : (route.capacity || 0);
        const hwm = route.high_water !== undefined ? route.high_water : (route.queue_high_water || 0);
        const dwell = route.queue_dwell_p95_ms !== undefined ? route.queue_dwell_p95_ms : (route.dwell_p95_ms !== undefined ? route.dwell_p95_ms : route.p95_dwell_ms);
        const dwellStr = (dwell !== undefined && dwell !== null) ? (Number(dwell).toFixed(1) + ' ms') : '-';

        // 3) Errors & Stalls (vpn_drilldown_write_stalls)
        const stalls = route.write_stalls !== undefined ? route.write_stalls : (route.stalls || 0);
        const errors = route.write_errors !== undefined ? route.write_errors : (route.errors || 0);
        const inflight = route.writes_in_flight !== undefined ? route.writes_in_flight : (route.in_flight !== undefined ? route.in_flight : (route.inflight || 0));

        // 4) Traffic Details (vpn_drilldown_traffic_details)
        let trafficContent = '-';
        if (route.traffic) {
            const trf = route.traffic;
            const rxB = trf.rx_bytes !== undefined ? vpnFormatBytes(trf.rx_bytes) : '-';
            const txB = trf.tx_bytes !== undefined ? vpnFormatBytes(trf.tx_bytes) : '-';
            const rxP = trf.rx_packets !== undefined ? trf.rx_packets : (trf.rx_pps !== undefined ? fmtPps(trf.rx_pps) : '-');
            const txP = trf.tx_packets !== undefined ? trf.tx_packets : (trf.tx_pps !== undefined ? fmtPps(trf.tx_pps) : '-');
            const rxR = fmtBps(trf.rx_bps !== undefined ? trf.rx_bps : ((trf.rx_bytes_per_sec || 0) * 8));
            const txR = fmtBps(trf.tx_bps !== undefined ? trf.tx_bps : ((trf.tx_bytes_per_sec || 0) * 8));
            trafficContent = `
                <div style="font-size: 0.8rem; line-height: 1.4;">
                    <div>Bytes: ↓ ${rxB} ↑ ${txB}</div>
                    <div>Packets: ↓ ${rxP} ↑ ${txP}</div>
                    <div>Rate: ↓ ${rxR} ↑ ${txR}</div>
                </div>
            `;
        }

        td.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: var(--space-md);">
                <div class="card" style="padding: var(--space-sm) var(--space-md); background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm);">
                    <div class="text-muted" style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-bottom: 4px;">${_('vpn_drilldown_reservoir')}</div>
                    <div style="font-size: 0.8rem; line-height: 1.4;">
                        <div>p95: <span class="font-mono">${p95Str}</span></div>
                        <div>Samples: <span class="font-mono">${p95Samples}</span></div>
                        <div>Max: <span class="font-mono">${maxStr}</span></div>
                    </div>
                </div>
                <div class="card" style="padding: var(--space-sm) var(--space-md); background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm);">
                    <div class="text-muted" style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-bottom: 4px;">${_('vpn_drilldown_dwell')}</div>
                    <div style="font-size: 0.8rem; line-height: 1.4;">
                        <div>Queue: <span class="font-mono">${occ} / ${cap}</span></div>
                        <div>High-Water: <span class="font-mono">${hwm}</span></div>
                        <div>Dwell p95: <span class="font-mono">${dwellStr}</span></div>
                    </div>
                </div>
                <div class="card" style="padding: var(--space-sm) var(--space-md); background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm);">
                    <div class="text-muted" style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-bottom: 4px;">${_('vpn_drilldown_write_stalls')}</div>
                    <div style="font-size: 0.8rem; line-height: 1.4;">
                        <div>Stalls: <span class="font-mono">${stalls}</span></div>
                        <div>Errors: <span class="font-mono">${errors}</span></div>
                        <div>In-Flight: <span class="font-mono">${inflight}</span></div>
                    </div>
                </div>
                <div class="card" style="padding: var(--space-sm) var(--space-md); background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm);">
                    <div class="text-muted" style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; margin-bottom: 4px;">${_('vpn_drilldown_traffic_details')}</div>
                    <div>${trafficContent}</div>
                </div>
            </div>
        `;
    }

    tr.appendChild(td);
    return tr;
}

function vpnToggleSessionDrilldown(s, tr) {
    let sessId = null;
    if (s && typeof s === 'object') {
        sessId = s.session_id || s.id || null;
    } else if (s !== null && s !== undefined && s !== '') {
        sessId = String(s);
    }

    if (!tr && sessId && typeof document !== 'undefined') {
        tr = document.querySelector(`tr[data-session-id="${sessId}"]`);
    }
    if (!tr) return;

    if (!s || typeof s !== 'object') {
        if (tr._sessionData) {
            s = tr._sessionData;
        } else if (vpnLastSessions && Array.isArray(vpnLastSessions.sessions)) {
            s = vpnLastSessions.sessions.find(x => String(x.session_id || x.id) === sessId) || { id: sessId, session_id: sessId };
        } else {
            s = { id: sessId, session_id: sessId };
        }
    }

    const isExpanded = sessId ? vpnExpandedSessionIds.has(sessId) : (tr.classList && tr.classList.contains('row-expanded'));

    if (isExpanded) {
        if (sessId) vpnExpandedSessionIds.delete(sessId);
        if (tr.classList) tr.classList.remove('row-expanded');
        else tr.className = (tr.className || '').replace(/\brow-expanded\b/g, '').trim();

        const next = tr.nextElementSibling || tr.nextSibling;
        if (next && ((next.classList && next.classList.contains('vpn-session-drilldown-row')) || (next.className && next.className.includes('vpn-session-drilldown-row')))) {
            next.remove();
        }
    } else {
        if (sessId) vpnExpandedSessionIds.add(sessId);
        if (tr.classList) tr.classList.add('row-expanded');
        else tr.className = ((tr.className || '') + ' row-expanded').trim();

        const next = tr.nextElementSibling || tr.nextSibling;
        if (next && ((next.classList && next.classList.contains('vpn-session-drilldown-row')) || (next.className && next.className.includes('vpn-session-drilldown-row')))) {
            next.remove();
        }

        const route = vpnFindRouteForSession(s);
        const drilldownRow = vpnCreateSessionDrilldownRow(s, route);
        if (tr.parentNode) {
            tr.parentNode.insertBefore(drilldownRow, tr.nextSibling);
        }
    }
}

function vpnToggleSessionsProblemFilter() {
    vpnSessionsFilterOnlyProblems = !vpnSessionsFilterOnlyProblems;
    const btn = document.getElementById('vpn-sessions-toggle-problems-btn');
    const textSpan = document.getElementById('vpn-sessions-toggle-problems-text');
    if (btn) {
        if (vpnSessionsFilterOnlyProblems) {
            if (btn.classList) {
                btn.classList.remove('btn-ghost');
                btn.classList.add('btn-primary');
            } else {
                btn.className = (btn.className || '').replace(/\bbtn-ghost\b/g, '').trim() + ' btn-primary';
            }
        } else {
            if (btn.classList) {
                btn.classList.remove('btn-primary');
                btn.classList.add('btn-ghost');
            } else {
                btn.className = (btn.className || '').replace(/\bbtn-primary\b/g, '').trim() + ' btn-ghost';
            }
        }
    }
    if (textSpan) {
        textSpan.textContent = vpnSessionsFilterOnlyProblems
            ? _('vpn_show_all_connections')
            : _('vpn_show_problems_only');
    }
    if (vpnLastSessions && vpnLastSessions.sessions) {
        renderSessions(vpnLastSessions.sessions);
    }
}

function vpnRenderSessionsStaleBanner() {
    const tbody = document.getElementById('vpn-sessions-tbody');
    if (!tbody) return;
    let banner = document.getElementById('vpnSessionsStaleBanner');
    if (!vpnSessionsStale) {
        if (banner) banner.remove();
        return;
    }
    if (banner) return;
    banner = document.createElement('tr');
    banner.id = 'vpnSessionsStaleBanner';
    banner.className = 'table-empty-state';
    const safeStaleText = (typeof UI !== 'undefined' && UI.escapeHtml) ? UI.escapeHtml(_('vpn_sessions_stale') || 'Session data unavailable - showing last known values') : (_('vpn_sessions_stale') || 'Session data unavailable - showing last known values');
    banner.innerHTML = `
        <td colspan="5" style="padding: var(--space-md);">
            <div class="empty-state" style="padding: 0;">
                <div class="empty-title" style="display: flex; align-items: center; justify-content: center; gap: var(--space-sm); font-size: 0.9rem; font-weight: 600; margin: 0; color: var(--warning, #b45309);">
                    <svg class="icon" style="width: 18px; height: 18px; flex-shrink: 0;"><use href="#icon-x"></use></svg>
                    <span>${safeStaleText}</span>
                </div>
            </div>
        </td>
    `;
    tbody.insertBefore(banner, tbody.firstChild);
}

function vpnFindSessionById(sessId) {
    if (sessId === null || sessId === undefined) return null;
    let list = [];
    if (typeof vpnLastSessions !== 'undefined' && vpnLastSessions) {
        if (Array.isArray(vpnLastSessions.sessions)) {
            list = vpnLastSessions.sessions;
        } else if (Array.isArray(vpnLastSessions)) {
            list = vpnLastSessions;
        }
    }
    for (let i = 0; i < list.length; i++) {
        const item = list[i];
        if (item && String(item.session_id || item.id) === String(sessId)) {
            return item;
        }
    }
    return null;
}

function vpnSyncExpandedDrilldowns() {
    const tbody = document.getElementById('vpn-sessions-tbody');
    if (!tbody) return;

    const isExpanded = function(id) {
        if (!vpnExpandedSessionIds || id === null || id === undefined) return false;
        return vpnExpandedSessionIds.has(id) || vpnExpandedSessionIds.has(String(id)) || (!isNaN(id) && vpnExpandedSessionIds.has(Number(id)));
    };

    const escapeAttr = function(val) {
        if (typeof CSS !== 'undefined' && typeof CSS.escape === 'function') {
            return CSS.escape(val);
        }
        return String(val).replace(/["\\]/g, '\\$&');
    };

    const drilldowns = Array.from(tbody.querySelectorAll('.vpn-session-drilldown-row'));
    drilldowns.forEach(function(d) {
        const sessId = d.getAttribute('data-parent-session-id');
        const safeId = sessId ? escapeAttr(sessId) : null;
        const parent = safeId ? tbody.querySelector('tr[data-session-id="' + safeId + '"]') : null;
        if (!parent || !sessId || !isExpanded(sessId)) {
            d.remove();
            return;
        }
        if (parent.style.display === 'none') {
            d.style.display = 'none';
        } else {
            d.style.display = '';
            if (parent.nextElementSibling !== d) {
                if (typeof parent.after === 'function') {
                    parent.after(d);
                } else if (parent.parentNode) {
                    parent.parentNode.insertBefore(d, parent.nextSibling);
                }
            }
        }
    });

    if (vpnExpandedSessionIds && vpnExpandedSessionIds.size > 0) {
        vpnExpandedSessionIds.forEach(function(sessId) {
            if (sessId === null || sessId === undefined) return;
            const safeId = escapeAttr(sessId);
            const existing = tbody.querySelector('tr.vpn-session-drilldown-row[data-parent-session-id="' + safeId + '"]');
            if (existing) return;
            const parent = tbody.querySelector('tr[data-session-id="' + safeId + '"]');
            if (!parent) return;
            const s = vpnFindSessionById(sessId) || { session_id: sessId, id: sessId };
            const route = vpnFindRouteForSession(s);
            const d = vpnCreateSessionDrilldownRow(s, route);
            if (parent.style.display === 'none') {
                d.style.display = 'none';
            } else {
                d.style.display = '';
            }
            if (typeof parent.after === 'function') {
                parent.after(d);
            } else if (parent.parentNode) {
                parent.parentNode.insertBefore(d, parent.nextSibling);
            }
        });
    }
}

function vpnWrapSessionsTableRender(tableInstance) {
    if (!tableInstance || tableInstance._vpnDrilldownWrapped) return;
    tableInstance._vpnDrilldownWrapped = true;
    const origRender = typeof tableInstance._render === 'function' ? tableInstance._render : tableInstance.render;
    const wrapped = function() {
        if (typeof origRender === 'function') {
            origRender.apply(tableInstance, arguments);
        }
        vpnSyncExpandedDrilldowns();
    };
    tableInstance._render = wrapped;
    tableInstance.render = wrapped;
}

function renderSessions(sessions) {
    const tbody = document.getElementById('vpn-sessions-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    if (sessions && (!vpnLastSessions || !vpnLastSessions.sessions)) {
        vpnLastSessions = { sessions: sessions };
    }
    vpnRenderSessionsStaleBanner();

    const countBadge = document.getElementById('vpn-sessions-count-badge');
    if (countBadge) {
        countBadge.textContent = String(sessions ? sessions.length : 0);
    }

    let sessionsToRender = sessions || [];
    if (vpnSessionsFilterOnlyProblems) {
        sessionsToRender = sessionsToRender.filter(function(s) {
            const route = vpnFindRouteForSession(s);
            const isNominalActive = s && (s.status === 'connected' || s.status === 'active');
            if (!route) {
                return true;
            }
            const hasRouteProblem = (
                route.has_pressure === true ||
                Number(route.queue_full_drops_recent || 0) > 0 ||
                Number(route.write_errors_recent || 0) > 0 ||
                Number(route.write_stalls_recent || 0) > 0
            );
            return hasRouteProblem || !isNominalActive;
        });
    }

    if (vpnSessionsTableInstance) {
        vpnWrapSessionsTableRender(vpnSessionsTableInstance);
        for (const s of sessionsToRender) {
            const route = vpnFindRouteForSession(s);
            const tr = vpnRenderSessionRow(s, route);
            tbody.appendChild(tr);
            const sessId = s ? (s.session_id || s.id) : null;
            if (sessId && vpnExpandedSessionIds && vpnExpandedSessionIds.has(sessId)) {
                const drilldownTr = vpnCreateSessionDrilldownRow(s, route);
                tbody.appendChild(drilldownTr);
            }
        }
        vpnSessionsTableInstance.refresh();
        vpnSyncExpandedDrilldowns();
        return;
    }

    if (!sessionsToRender || !sessionsToRender.length) {
        const tr = document.createElement('tr');
        tr.className = 'table-empty-state';
        const td = document.createElement('td');
        td.colSpan = 5;
        td.style.padding = 'var(--space-2xl) var(--space-md)';
        td.style.textAlign = 'center';
        const safeNoSessions = (typeof UI !== 'undefined' && UI.escapeHtml) ? UI.escapeHtml(_('vpn_no_sessions')) : (_('vpn_no_sessions') || 'No active sessions');
        td.innerHTML = `
            <div class="empty-state" style="padding: 0;">
                <div class="empty-icon" style="margin-bottom: var(--space-sm);">
                    <svg class="icon text-muted" style="width: 48px; height: 48px;"><use href="#icon-users"></use></svg>
                </div>
                <div class="empty-title" style="font-size: 1.1rem; font-weight: 600; margin-bottom: var(--space-xs); color: var(--text-primary);">${safeNoSessions}</div>
            </div>
        `;
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }

    for (const s of sessionsToRender) {
        const route = vpnFindRouteForSession(s);
        const tr = vpnRenderSessionRow(s, route);
        tbody.appendChild(tr);
        const sessId = s ? (s.session_id || s.id) : null;
        if (sessId && vpnExpandedSessionIds && vpnExpandedSessionIds.has(sessId)) {
            const drilldownTr = vpnCreateSessionDrilldownRow(s, route);
            tbody.appendChild(drilldownTr);
        }
    }

    if (typeof NexusTable === 'function') {
        vpnSessionsTableInstance = new NexusTable('#vpnSessionsTable', {
            searchable: true,
            sortable: true,
            paginate: true,
            pageSize: 10,
            searchPlaceholder: _('vpn_search_sessions') || _('search_placeholder') || 'Search sessions...',
            emptyMessage: _('vpn_no_sessions') || 'No active sessions'
        });
        vpnWrapSessionsTableRender(vpnSessionsTableInstance);
        vpnSyncExpandedDrilldowns();
    }
}

if (typeof window !== 'undefined') {
    window.vpnSessionsTableInstance = vpnSessionsTableInstance;
    window.vpnLastSessions = vpnLastSessions;
    window.vpnSessionsStale = vpnSessionsStale;
    window.vpnSessionsFilterOnlyProblems = vpnSessionsFilterOnlyProblems;
    window.vpnExpandedSessionIds = vpnExpandedSessionIds;
    window.fmtBps = fmtBps;
    window.fmtPps = fmtPps;
    window.vpnFormatBytes = vpnFormatBytes;
    window.vpnFindRouteForSession = vpnFindRouteForSession;
    window.vpnRenderSessionRow = vpnRenderSessionRow;
    window.vpnCreateSessionDrilldownRow = vpnCreateSessionDrilldownRow;
    window.vpnToggleSessionDrilldown = vpnToggleSessionDrilldown;
    window.vpnToggleSessionsProblemFilter = vpnToggleSessionsProblemFilter;
    window.vpnRenderSessionsStaleBanner = vpnRenderSessionsStaleBanner;
    window.vpnFindSessionById = vpnFindSessionById;
    window.vpnSyncExpandedDrilldowns = vpnSyncExpandedDrilldowns;
    window.vpnWrapSessionsTableRender = vpnWrapSessionsTableRender;
    window.renderSessions = renderSessions;
}
