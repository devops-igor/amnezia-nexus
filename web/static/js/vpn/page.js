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
        // Cumulative Rx/Tx live in Advanced Diagnostics as since-reset totals, so
        // they are written here rather than described as rates.
        const rxElem = document.getElementById('vpn-rx');
        if (rxElem) rxElem.textContent = Telemetry.formatBytes(status.rx_bytes || 0);
        const txElem = document.getElementById('vpn-tx');
        if (txElem) txElem.textContent = Telemetry.formatBytes(status.tx_bytes || 0);
        // The sessions signal and every other overview value are owned by
        // vpnRenderForwarderHealth -> vpnRenderSignals, which distinguishes a
        // measured zero from an unmeasured value.
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
                    <button type="button" class="btn btn-primary btn-sm" data-action="vpn-open-add-backend">
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

// vpnFindSessionRow returns the session table row for one identifier. It walks the
// tbody's rows rather than relying on a selector engine, so the same lookup works
// in every environment and never depends on CSS.escape for an id.
function vpnFindSessionRow(sessionId) {
    const tbody = document.getElementById('vpn-sessions-tbody');
    if (!tbody || !tbody.children) return null;
    const wanted = String(sessionId);
    for (let i = 0; i < tbody.children.length; i++) {
        const candidate = tbody.children[i];
        if (!candidate || typeof candidate.getAttribute !== 'function') continue;
        if (candidate.getAttribute('data-session-id') === wanted) {
            return candidate;
        }
    }
    return null;
}

// vpnFocusHeading moves the caller's focus to a table heading that already exists
// in the template with tabindex="-1", so it is genuinely focusable.
function vpnFocusHeading(id, explanationKey) {
    const heading = document.getElementById(id);
    if (heading && typeof heading.focus === 'function') heading.focus();
    const summaryEl = document.getElementById('vpn-fwd-headline-summary');
    if (summaryEl && explanationKey) summaryEl.textContent = _(explanationKey);
}

// vpnBackendFocusCell returns the focusable cell for one backend row. Row cells are
// matched by kind, never by element name: a plain <td> always satisfies
// typeof node.focus === 'function', so checking the function alone would claim a
// non-focusable cell can take focus. The search is restricted to the row's own cells
// so a nested control's tabindex cannot stand in for the cell's.
function vpnBackendFocusCell(row) {
    const cells = row.children || [];
    for (let i = 0; i < cells.length; i++) {
        const cell = cells[i];
        if (cell && cell.getAttribute && cell.getAttribute('tabindex') !== null) return cell;
    }
    return null;
}

// vpnFocusFirstFocusable focuses the first candidate that carries an explicit
// tabindex. A plain element satisfies typeof node.focus === 'function' even when
// the browser refuses to focus it, so focusability is read from the attribute that
// actually grants it.
function vpnFocusFirstFocusable(candidates) {
    for (let i = 0; i < candidates.length; i++) {
        const node = candidates[i];
        if (node && typeof node.focus === 'function' && node.getAttribute && node.getAttribute('tabindex') !== null) {
            node.focus();
            return true;
        }
    }
    return false;
}

// vpnRevealSessionRow makes one session row EXIST and be visible, so a focus call
// that follows actually moves. A session can be missing from the table for a reason
// that is not a missing session: the problems-only filter excludes it BEFORE
// rendering, so no row is appended and the table's own filters never see it. The
// order therefore matters — leave the problems-only view so the row is rendered,
// resolve it again, then let the table clear its search/status filter and page to it.
//
// The problems-only choice is NOT restored afterwards. Restoring it would re-render
// the list without the row, so focus would land on a node no longer in the document
// and the revealed detail would disappear under the operator. It is instead LEFT
// CLEARED through the toggle handler that owns that state, so the toolbar button's
// class and label both read as inactive. This function never writes
// vpnSessionsFilterOnlyProblems itself, so the flag and the control cannot disagree.
function vpnRevealSessionRow(sessionId) {
    if (!document.getElementById('vpn-sessions-tbody')) return null;

    if (vpnSessionsFilterOnlyProblems === true && typeof vpnToggleSessionsProblemFilter === 'function') {
        vpnToggleSessionsProblemFilter();
    }

    const tr = vpnFindSessionRow(sessionId);
    if (!tr) return null;
    if (vpnSessionsTableInstance && typeof vpnSessionsTableInstance.revealRow === 'function') {
        return vpnSessionsTableInstance.revealRow(tr) ? tr : null;
    }
    return tr.style.display === 'none' ? null : tr;
}

// vpnRevealBackendRow makes one backend row visible before focus is called on it.
//
// The row EXISTS whenever the backend is listed, so a failed lookup can only mean
// "not listed". It can still be invisible, because NexusTable hides a row for two
// separate reasons — a search term or status filter excluded it, or it sits on a
// page the table is not showing — and only the table knows which. Clearing either
// one from here would be a guess, so the reveal goes through the table's own
// operation, which resolves the page AFTER the filters are cleared.
//
// A revealed row stays revealed: the operator's search term and status chip are
// visibly cleared, and restoring them would hide the row the moment focus landed.
function vpnRevealBackendRow(tr) {
    if (!tr) return null;
    if (vpnTableInstance && typeof vpnTableInstance.revealRow === 'function') {
        return vpnTableInstance.revealRow(tr) ? tr : null;
    }
    return tr.style.display === 'none' ? null : tr;
}

// vpnFocusSessionIssue reveals one session's drill-down and moves focus to the
// affected session row's action cell. Diagnostics is never touched.
//
// The missing-entity explanation is reported only when the session is genuinely not
// in the polled data. A session the problems-only filter excluded exists in the
// data, so it is revealed instead: the operator is never told a session is gone
// while it is still listed.
function vpnFocusSessionIssue(row) {
    const wanted = String(row.sessionId || row.connectionId);
    const tr = vpnRevealSessionRow(wanted);
    if (!tr) {
        const known = (typeof vpnFindSessionById === 'function') ? vpnFindSessionById(wanted) : null;
        if (!known) {
            vpnFocusHeading('vpn-troubleshooting-title', 'vpn_issue_entity_missing_session');
            return;
        }
        // The session is in the data but no row could be produced for it. That is
        // not the missing-session statement, so nothing is rewritten here.
        vpnFocusHeading('vpn-troubleshooting-title', null);
        return;
    }
    // Reveal, never toggle: the action means "show me this", so it must not close a
    // fold the operator is already reading.
    if (typeof vpnSetSessionDrilldownOpen === 'function') {
        vpnSetSessionDrilldownOpen(wanted, tr, true);
    }
    const cell = (typeof tr.querySelector === 'function') ? tr.querySelector('[data-action="vpn-toggle-session"]') : null;
    if (!vpnFocusFirstFocusable([cell, tr])) {
        // No focusable target on the row means focus would silently stay put.
        vpnFocusHeading('vpn-troubleshooting-title', null);
    }
}

// vpnFindBackendRowByTunnelId returns the backend table row whose own tunnel id is
// the one the problem reports. It walks the tbody's rows rather than depending on a
// selector engine, the same way the session lookup does.
//
// The row's own tunnel id (data-tunnel-id) is what the diagnostics payload reports
// as backend_id, because that value comes from the session/route backend tunnel id.
// The row's data-server-id is a DIFFERENT id space — it is the server the row's
// enable/delete actions post to — so it is never compared against a problem.
function vpnFindBackendRowByTunnelId(tbody, tunnelId) {
    const rows = (tbody && tbody.children) ? tbody.children : [];
    const wanted = String(tunnelId);
    for (let i = 0; i < rows.length; i++) {
        const candidate = rows[i];
        if (!candidate || typeof candidate.getAttribute !== 'function') continue;
        if (candidate.getAttribute('data-tunnel-id') === wanted) return candidate;
    }
    return null;
}

// vpnFocusBackendIssue moves focus to the affected backend's name cell, or to the
// backend table heading when that backend is no longer listed.
function vpnFocusBackendIssue(row) {
    const found = vpnFindBackendRowByTunnelId(document.getElementById('vpn-backends-tbody'), row.backendId);
    const tr = vpnRevealBackendRow(found);
    if (!tr) {
        vpnFocusHeading('vpn-backends-title', 'vpn_issue_entity_missing_backend');
        return;
    }
    const nameCell = vpnBackendFocusCell(tr);
    if (nameCell && vpnFocusFirstFocusable([nameCell])) return;
    vpnFocusHeading('vpn-backends-title', null);
}

// vpnIssueDestinationHeading names the card that owns a problem carrying no entity
// id. Such a problem is a statement about a SURFACE rather than about a row that has
// vanished, and the surface is named by its category. Keying this on an explicit
// category set is what keeps a backend-scoped condition (for example "no healthy
// backends available to route traffic") out of the sessions table while a
// connection, routing or dataplane condition keeps the destination it already had;
// pointing every fallback at one card would only move the error.
const VPN_BACKEND_CATEGORIES = ['backend'];
function vpnIssueDestinationHeading(category) {
    const c = String(category || '').toLowerCase();
    if (VPN_BACKEND_CATEGORIES.indexOf(c) !== -1) return 'vpn-backends-title';
    return 'vpn-troubleshooting-title';
}

// vpnFocusIssueTarget moves focus to the existing detail for a problem WITHOUT
// opening Advanced Diagnostics. The destination must be a node that can actually
// take focus, and the reveal is idempotent: a second Inspect on an already-open
// detail keeps it open instead of toggling it shut.
function vpnFocusIssueTarget(row) {
    if (row.sessionId || row.connectionId) {
        vpnFocusSessionIssue(row);
    } else if (row.backendId) {
        vpnFocusBackendIssue(row);
    } else {
        vpnFocusHeading(vpnIssueDestinationHeading(row.category), null);
    }
}


const VPN_ACTIONS = {
    'vpn-open-edit-endpoint': function () {
        if (typeof vpnOpenEditEndpointModal === 'function') vpnOpenEditEndpointModal();
    },
    'vpn-open-add-backend': function () {
        if (typeof vpnOpenAddBackendModal === 'function') vpnOpenAddBackendModal();
    },
    'vpn-toggle-problems-filter': function () {
        if (typeof vpnToggleSessionsProblemFilter === 'function') vpnToggleSessionsProblemFilter();
    },
    'vpn-toggle-show-all-routes': function () {
        if (typeof vpnToggleShowAllRoutes === 'function') vpnToggleShowAllRoutes();
    },
    'vpn-toggle-diagnostics': function () {
        if (typeof vpnToggleDiagnostics === 'function') vpnToggleDiagnostics();
    },
    'vpn-close-diagnostics': function () {
        if (typeof vpnCloseDiagnostics === 'function') vpnCloseDiagnostics();
    },
    'vpn-issue-inspect': function (btn) {
        // Focus is handled by the row's own listener; this entry keeps the
        // delegated handler from treating the button as an unknown action.
        if (btn && btn.getAttribute && btn.getAttribute('data-issue-key')) return;
    },
    'vpn-set-history-window': function (btn) {
        const win = btn.dataset ? btn.dataset.window : (btn.getAttribute ? btn.getAttribute('data-window') : null);
        if (typeof vpnSetHistoryWindow === 'function') vpnSetHistoryWindow(win);
    },
    'vpn-close-modal': function (btn) {
        const modalId = btn.dataset ? btn.dataset.modal : (btn.getAttribute ? btn.getAttribute('data-modal') : null);
        if (typeof closeModal === 'function') {
            closeModal(modalId);
        } else if (typeof UI !== 'undefined' && UI.modal && typeof UI.modal.close === 'function') {
            UI.modal.close(modalId);
        }
    },
    'vpn-trigger-quick-check': function () {
        if (typeof vpnTriggerQuickCheck === 'function') vpnTriggerQuickCheck();
    },
    'vpn-toggle-backend': function (btn) {
        const srvId = btn.dataset ? btn.dataset.serverId : (btn.getAttribute ? btn.getAttribute('data-server-id') : null);
        const action = btn.dataset ? btn.dataset.backendAction : (btn.getAttribute ? btn.getAttribute('data-backend-action') : null);
        if (typeof vpnToggleBackend === 'function') vpnToggleBackend(srvId, action);
    },
    'vpn-delete-backend': function (btn) {
        const srvId = btn.dataset ? btn.dataset.serverId : (btn.getAttribute ? btn.getAttribute('data-server-id') : null);
        if (typeof vpnDeleteBackend === 'function') vpnDeleteBackend(srvId);
    },
    'vpn-toggle-session': function (btn) {
        const sessId = btn.dataset ? btn.dataset.sessionId : (btn.getAttribute ? btn.getAttribute('data-session-id') : null);
        const tr = btn.closest ? btn.closest('tr') : null;
        if (typeof vpnToggleSessionDrilldown === 'function') vpnToggleSessionDrilldown(sessId, tr);
    }
};

function getVpnContainerRoots() {
    if (typeof document === 'undefined') return [];
    const vpnRoot = (typeof document.querySelector === 'function' && (document.querySelector('#vpn-app') || document.querySelector('main'))) || document.body;
    if (!vpnRoot) return [];
    const roots = [vpnRoot];
    ['addBackendModal', 'editEndpointModal'].forEach(function (id) {
        const modal = typeof document.getElementById === 'function' ? document.getElementById(id) : null;
        if (modal && !roots.some(function (r) { return r === modal || (r.contains && r.contains(modal)); })) {
            roots.push(modal);
        }
    });
    return roots;
}

function initVpnEventListeners() {
    if (typeof document === 'undefined') return;

    const roots = getVpnContainerRoots();
    roots.forEach(function (root) {
        if (!root || root._vpnListenersBound || typeof root.addEventListener !== 'function') return;
        root._vpnListenersBound = true;

        root.addEventListener('click', function (e) {
            const btn = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
            if (!btn) return;

            const action = btn.dataset ? btn.dataset.action : (btn.getAttribute ? btn.getAttribute('data-action') : null);
            if (!action || !Object.prototype.hasOwnProperty.call(VPN_ACTIONS, action)) return;

            if (e && typeof e.preventDefault === 'function') {
                e.preventDefault();
            }

            VPN_ACTIONS[action](btn);
        });

        root.addEventListener('submit', function (e) {
            if (!e.target) return;
            const targetId = e.target.id || (e.target.closest ? (e.target.closest('form') || {}).id : null);
            if (targetId === 'addBackendForm') {
                if (e && typeof e.preventDefault === 'function') e.preventDefault();
                if (typeof vpnSubmitAddBackend === 'function') vpnSubmitAddBackend();
            } else if (targetId === 'editEndpointForm') {
                if (e && typeof e.preventDefault === 'function') e.preventDefault();
                if (typeof vpnSubmitEditEndpoint === 'function') vpnSubmitEditEndpoint();
            }
        });

        root.addEventListener('change', function (e) {
            if (e && e.target && e.target.id === 'vpnServerSelect') {
                if (typeof vpnOnServerSelected === 'function') vpnOnServerSelected();
            }
        });
    });
}

if (typeof document !== 'undefined') {
    initVpnEventListeners();
}

document.addEventListener('DOMContentLoaded', function () {
    initVpnEventListeners();

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
    window.initVpnEventListeners = initVpnEventListeners;
    window.vpnFindSessionRow = vpnFindSessionRow;
    window.vpnRevealSessionRow = vpnRevealSessionRow;
    window.vpnBackendFocusCell = vpnBackendFocusCell;
    window.vpnFocusIssueTarget = vpnFocusIssueTarget;
    window.vpnIssueDestinationHeading = vpnIssueDestinationHeading;
}
