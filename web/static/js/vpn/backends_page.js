// VPN Backends page controller.
//
// This document owns the backend inventory: the table, its row actions and the
// add-backend dialog. It reads /api/vpn/backends on each tick and /api/servers
// once for the display-name enrichment the rows already had (the add dialog
// refreshes that list itself when it opens, as before). It reads no status,
// config or session data, so a failure on another VPN page cannot blank it.

let vpnCachedServers = [];
let vpnCurrentBackends = [];
let vpnTableInstance = null;
var vpnBackendsAnchorApplied = false;

// vpnRenderBackendsError renders the existing error row. It is the read's own
// failure state: a failed read is never reported as "this backend is gone".
function vpnRenderBackendsError(message) {
    const tbody = document.getElementById('vpn-backends-tbody');
    if (!tbody) return;
    tbody.textContent = '';
    const tr = document.createElement('tr');
    tr.className = 'table-empty-state';
    const td = document.createElement('td');
    td.colSpan = 6;
    td.style.textAlign = 'center';
    td.style.color = 'var(--text-muted)';
    td.textContent = message;
    tr.appendChild(td);
    tbody.appendChild(tr);
    if (vpnTableInstance) vpnTableInstance.refresh();
}

// vpnRenderBackendsEmpty renders the empty inventory with its Add action, which
// is the same delegated action as the persistent button.
function vpnRenderBackendsEmpty() {
    const tbody = document.getElementById('vpn-backends-tbody');
    if (!tbody) return;
    tbody.textContent = '';
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
}

// vpnEnsureBackendsTable creates the table engine once, after the first render
// produced rows it can index.
function vpnEnsureBackendsTable() {
    if (vpnTableInstance || typeof NexusTable !== 'function') return;
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

// vpnRenderBackendsStaleRow states that the last refresh failed without discarding
// the rows it could not replace: a silent failure would leave a populated table
// looking current, and clearing it would lose the last known inventory.
function vpnRenderBackendsStaleRow() {
    const tbody = document.getElementById('vpn-backends-tbody');
    if (!tbody) return;
    const message = _('vpn_backends_stale') || 'Backend list unavailable - showing last known values';
    let stale = document.getElementById('vpnBackendsStaleBanner');
    if (!stale) {
        stale = document.createElement('tr');
        stale.id = 'vpnBackendsStaleBanner';
        stale.className = 'table-empty-state';
        const cell = document.createElement('td');
        cell.colSpan = 6;
        cell.style.textAlign = 'center';
        stale.appendChild(cell);
    }
    stale.querySelector('td').textContent = message;
    tbody.insertBefore(stale, tbody.firstChild);
    vpnAnnounceBackends(message);
}

// vpnModalFocusFallback answers where focus goes when the control that opened a
// dialog no longer exists: the permanent Add control for the add dialog (the
// empty-state CTA that may have opened it is replaced by the next render), and the
// inventory's own heading otherwise.
function vpnModalFocusFallback(modalId) {
    if (modalId === 'addBackendModal') {
        return document.getElementById('vpn-add-backend-btn') || document.getElementById('vpn-backends-title');
    }
    return document.getElementById('vpn-backends-title') || document.getElementById('vpn-add-backend-btn');
}

if (typeof window !== 'undefined') {
    window.vpnModalFocusFallback = vpnModalFocusFallback;
}

// vpnLoadBackends refreshes the inventory only.
async function vpnLoadBackends() {
    let backendData;
    try {
        backendData = await API.get('/api/vpn/backends');
    } catch (err) {
        // A cold page has nothing to keep, so it states the failure in place of the
        // inventory. A populated one keeps its rows and says the refresh failed
        // instead of looking current, which is what the sessions table does too.
        if (Array.isArray(vpnCurrentBackends) && vpnCurrentBackends.length) {
            vpnRenderBackendsStaleRow();
        } else {
            vpnRenderBackendsError(_('error'));
        }
        return null;
    }

    const backends = (backendData && (backendData.backends || backendData.tunnels)) || [];
    vpnCurrentBackends = backends;
    const staleBanner = document.getElementById('vpnBackendsStaleBanner');
    if (staleBanner) staleBanner.remove();

    if (!backends.length) {
        vpnRenderBackendsEmpty();
    } else {
        const tbody = document.getElementById('vpn-backends-tbody');
        tbody.textContent = '';
        for (const b of backends) {
            tbody.appendChild(vpnRenderBackendRow(b));
        }
        vpnEnsureBackendsTable();
        if (vpnTableInstance) vpnTableInstance.refresh();
    }

    if (!vpnBackendsAnchorApplied) {
        vpnBackendsAnchorApplied = true;
        vpnApplyBackendsLanding();
    }
    return backends;
}

// ---- Anchors and the cross-document Inspect handoff ----

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

// vpnBackendFocusCell returns the row's focusable name cell. Row cells are
// matched by the attribute that grants focus, never by `typeof focus`, which
// every element satisfies.
function vpnBackendFocusCell(row) {
    const cells = row.children || [];
    for (let i = 0; i < cells.length; i++) {
        const cell = cells[i];
        if (cell && cell.getAttribute && cell.getAttribute('tabindex') !== null) return cell;
    }
    return null;
}

// vpnRevealBackendRow makes one row visible through the table's own reveal, which
// clears a search or status filter and pages to it. A revealed row stays
// revealed: restoring the filter would hide it the moment focus landed.
function vpnRevealBackendRow(tr) {
    if (!tr) return null;
    if (vpnTableInstance && typeof vpnTableInstance.revealRow === 'function') {
        return vpnTableInstance.revealRow(tr) ? tr : null;
    }
    return tr.style.display === 'none' ? null : tr;
}

function vpnAnnounceBackends(message) {
    const region = document.getElementById('vpn-backends-announcement');
    if (region) vpnAssignText(region, message || '');
}

// vpnFocusBackendsHeading lands on the inventory heading, which is focusable and
// never destroyed by a re-render.
function vpnFocusBackendsHeading() {
    const heading = document.getElementById('vpn-backends-title');
    if (heading) {
        vpnScrollToTarget(heading);
        vpnFocusIfFocusable(heading);
    }
}

// vpnApplyBackendsLanding runs once, after the first successful read.
//
// The Inspect handoff wins over a plain fragment: it is a one-shot request that
// names a specific row. It is consumed here and nowhere else, so an ordinary
// bookmark or a reload never replays a previous Inspect. A row that is absent
// after a SUCCESSFUL read is genuinely missing, and the existing missing-entity
// statement is announced at the destination heading.
// vpnPendingInspectTunnelId holds this ARRIVAL's Inspect request. The durable slot is
// read once, when the document starts, because the request belongs to the navigation
// that carried it: keeping it in tab storage let a later ordinary visit replay an
// arrival whose first read had failed.
let vpnPendingInspectTunnelId = (typeof vpnConsumeBackendHandoff === 'function')
    ? vpnConsumeBackendHandoff()
    : null;

function vpnTakePendingInspect() {
    const tunnelId = vpnPendingInspectTunnelId;
    vpnPendingInspectTunnelId = null;
    return tunnelId;
}

function vpnApplyBackendsLanding() {
    const tunnelId = vpnTakePendingInspect();
    if (tunnelId) {
        const row = vpnFindBackendRowByTunnelId(document.getElementById('vpn-backends-tbody'), tunnelId);
        const tr = vpnRevealBackendRow(row);
        if (tr) {
            const nameCell = vpnBackendFocusCell(tr);
            vpnScrollToTarget(nameCell || tr);
            if (!vpnFocusIfFocusable(nameCell)) vpnFocusBackendsHeading();
            return 'inspect';
        }
        vpnAnnounceBackends(_('vpn_issue_entity_missing_backend'));
        vpnFocusBackendsHeading();
        return 'inspect-missing';
    }

    const id = vpnOwnedAnchorId();
    if (!id) return null;
    const el = document.getElementById(id);
    if (!el) return null;
    vpnScrollToTarget(el);
    if (!vpnFocusIfFocusable(el)) {
        const heading = vpnNearestHeading(el, 'vpn-backends-title');
        vpnFocusIfFocusable(heading);
    }
    return id;
}

// ---- Delegation ----

const VPN_BACKENDS_ACTIONS = {
    'vpn-open-add-backend': function () {
        if (typeof vpnOpenAddBackendModal === 'function') vpnOpenAddBackendModal();
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
    }
};

function initVpnBackendsListeners() {
    if (typeof document === 'undefined') return;
    const root = (typeof document.querySelector === 'function' && (document.querySelector('#vpn-app') || document.querySelector('main'))) || document.body;
    if (!root || root._vpnBackendsBound || typeof root.addEventListener !== 'function') return;
    root._vpnBackendsBound = true;

    root.addEventListener('click', function (e) {
        const btn = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
        if (!btn) return;
        const action = btn.dataset ? btn.dataset.action : (btn.getAttribute ? btn.getAttribute('data-action') : null);
        if (!action || !Object.prototype.hasOwnProperty.call(VPN_BACKENDS_ACTIONS, action)) return;
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
        VPN_BACKENDS_ACTIONS[action](btn);
    });

    root.addEventListener('submit', function (e) {
        if (!e.target) return;
        const targetId = e.target.id || (e.target.closest ? (e.target.closest('form') || {}).id : null);
        if (targetId !== 'addBackendForm') return;
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
        if (typeof vpnSubmitAddBackend === 'function') vpnSubmitAddBackend();
    });

    root.addEventListener('change', function (e) {
        if (e && e.target && e.target.id === 'vpnServerSelect') {
            if (typeof vpnOnServerSelected === 'function') vpnOnServerSelected();
        }
    });
}

if (typeof document !== 'undefined') {
    initVpnBackendsListeners();
}

document.addEventListener('DOMContentLoaded', function () {
    initVpnBackendsListeners();

    // Server metadata for the row names: read once, not on every poll. The add
    // dialog refreshes the same list when it opens.
    if (typeof API !== 'undefined' && typeof API.get === 'function') {
        API.get('/api/servers').then(function (servers) {
            if (Array.isArray(servers)) vpnCachedServers = servers;
        }).catch(function () {});
    }

    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
        NexusTelemetry.poll('vpn-backends', async function () {
            await vpnLoadBackends();
        }, 5000);
    }
});

if (typeof window !== 'undefined') {
    window.vpnLoadBackends = vpnLoadBackends;
    window.vpnFindBackendRowByTunnelId = vpnFindBackendRowByTunnelId;
    window.vpnBackendFocusCell = vpnBackendFocusCell;
    window.vpnRevealBackendRow = vpnRevealBackendRow;
    window.vpnApplyBackendsLanding = vpnApplyBackendsLanding;
    window.vpnAnnounceBackends = vpnAnnounceBackends;
    window.initVpnBackendsListeners = initVpnBackendsListeners;
}
