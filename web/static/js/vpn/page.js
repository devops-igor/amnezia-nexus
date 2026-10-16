/* ===== Modernized VPN Admin Dashboard: NexusTable, NexusTelemetry & UI Components ===== */

let vpnCachedServers = [];
let vpnCurrentBackends = [];
let vpnConfiguredPublicEndpoint = '';
let vpnTableInstance = null;
let vpnShowAllRoutes = false;
let vpnLastStatus = null;

function vpnToggleShowAllRoutes() {
    vpnShowAllRoutes = !vpnShowAllRoutes;
    const btn = document.getElementById('vpn-routes-toggle-all-btn');
    if (btn) {
        btn.textContent = vpnShowAllRoutes ? (_('vpn_fwd_show_problems') || 'Show Problems Only') : (_('vpn_fwd_show_all') || 'Show All Routes');
    }
    if (vpnLastStatus && vpnLastStatus.forwarder_available === true) {
        vpnRenderForwarderHealth(vpnLastStatus);
    }
}

async function vpnLoadData() {
    try {
        const [status, cfg, backendData, sessionsData] = await Promise.all([
            API.get('/api/vpn/status'),
            API.get('/api/vpn/config').catch(() => ({})),
            API.get('/api/vpn/backends'),
            API.get('/api/vpn/sessions').then(function (data) {
                // Success: remember the payload and clear the stale flag
                // (review-2 P3 - flag resets on next success).
                vpnLastSessions = data;
                vpnSessionsStale = false;
                return data;
            }).catch(function () {
                // Failure: keep showing the LAST successful payload and
                // flag the table as stale instead of faking an empty list.
                vpnSessionsStale = true;
                return { sessions: vpnLastSessions && vpnLastSessions.sessions ? vpnLastSessions.sessions : [] };
            })
        ]);

        const backends = (backendData && (backendData.backends || backendData.tunnels)) || [];
        vpnCurrentBackends = backends;

        vpnSetListenerBadge(!!status.listener_running);
        vpnConfiguredPublicEndpoint = (cfg && cfg.public_endpoint) ? cfg.public_endpoint.trim() : '';
        const epElem = document.getElementById('vpn-public-endpoint');
        if (epElem) {
            if (vpnConfiguredPublicEndpoint) {
                epElem.textContent = vpnConfiguredPublicEndpoint;
            } else if (status && status.public_endpoint) {
                const tpl = _('vpn_unset_auto_detected') || 'Auto: %s';
                epElem.textContent = tpl.replace('%s', status.public_endpoint);
            } else {
                epElem.textContent = _('vpn_unset_auto') || 'Auto-detect';
            }
        }
        document.getElementById('vpn-listen-port').textContent = String(cfg.listen_port || '-');
        document.getElementById('vpn-subnet').textContent = cfg.subnet_cidr || '-';
        document.getElementById('vpn-sessions').textContent = String(status.connected_sessions || 0);
        document.getElementById('vpn-active-tunnels').textContent = String(status.active_tunnels || 0);
        document.getElementById('vpn-rx').textContent = Telemetry.formatBytes(status.rx_bytes || 0);
        document.getElementById('vpn-tx').textContent = Telemetry.formatBytes(status.tx_bytes || 0);
        vpnRenderForwarderHealth(status);

        const tbody = document.getElementById('vpn-backends-tbody');
        tbody.textContent = '';
        if (!backends.length) {
            const tr = document.createElement('tr');
            tr.className = 'table-empty-state';
            const td = document.createElement('td');
            td.colSpan = 6;
            td.style.padding = 'var(--space-2xl) var(--space-md)';
            td.style.textAlign = 'center';
            td.innerHTML = `
                <div class="empty-state" style="padding: 0;">
                    <div class="empty-icon" style="margin-bottom: var(--space-sm);">
                        <svg class="icon text-muted" style="width: 48px; height: 48px;"><use href="#icon-server"></use></svg>
                    </div>
                    <div class="empty-title" style="font-size: 1.1rem; font-weight: 600; margin-bottom: var(--space-xs); color: var(--text-primary);">${UI.escapeHtml(_('vpn_no_backends'))}</div>
                    <div class="empty-desc" style="font-size: 0.875rem; color: var(--text-muted); max-width: 420px; margin: 0 auto var(--space-md);">${UI.escapeHtml(_('vpn_no_backends_desc'))}</div>
                    <button type="button" class="btn btn-primary btn-sm" onclick="vpnOpenAddBackendModal()">
                        <svg class="icon"><use href="#icon-plus"></use></svg>
                        <span>${UI.escapeHtml(_('vpn_add_backend'))}</span>
                    </button>
                </div>
            `;
            tr.appendChild(td);
            tbody.appendChild(tr);
            if (vpnTableInstance) vpnTableInstance.refresh();
            renderSessions((sessionsData && sessionsData.sessions) || []);
            return;
        }

        for (const b of backends) {
            tbody.appendChild(vpnRenderBackendRow(b));
        }

        if (vpnTableInstance) {
            vpnTableInstance.refresh();
        } else {
            vpnTableInstance = new NexusTable('#vpnBackendsTable', {
                searchable: true,
                sortable: true,
                paginate: true,
                pageSize: 10,
                statusFilters: ['all', 'active', 'degraded', 'disabled'],
                statusAttribute: 'data-status',
                searchPlaceholder: _('vpn_search_backends') || _('search_placeholder') || 'Search backends...',
                emptyMessage: _('vpn_no_backends') || 'No backends configured'
            });
        }

        renderSessions((sessionsData && sessionsData.sessions) || []);
    } catch (err) {
        vpnRenderForwarderHealth(null);
        const tbody = document.getElementById('vpn-backends-tbody');
        if (tbody) {
            tbody.textContent = '';
            const tr = document.createElement('tr');
            tr.className = 'table-empty-state';
            const td = document.createElement('td');
            td.colSpan = 6;
            td.style.textAlign = 'center';
            td.style.color = 'var(--text-muted)';
            td.textContent = _('error');
            tr.appendChild(td);
            tbody.appendChild(tr);
        }
    }
}

function vpnStopPolling() {
    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.stop === 'function') {
        NexusTelemetry.stop('vpn-status');
    }
}

document.addEventListener('DOMContentLoaded', function () {
    // Also precache server metadata for quick name matching
    if (typeof API !== 'undefined' && typeof API.get === 'function') {
        API.get('/api/servers').then(servers => {
            if (Array.isArray(servers)) vpnCachedServers = servers;
        }).catch(() => {});
    }

    // Start live telemetry polling via NexusTelemetry engine
    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
        NexusTelemetry.poll('vpn-status', async function () {
            await vpnLoadData();
        }, 5000);
    }
});

if (typeof window !== 'undefined') {
    window.vpnLoadData = vpnLoadData;
    window.vpnToggleShowAllRoutes = vpnToggleShowAllRoutes;
    window.vpnStopPolling = vpnStopPolling;
}
