// VPN Backends section controller.
//
// This section owns the backend inventory: the table, its row actions and the
// add-backend dialog. It reads /api/vpn/backends on each tick and /api/servers
// once for the display-name enrichment the rows already had (the add dialog
// refreshes that list itself when it opens, as before). It reads no status,
// config or session data, so a failure in another section cannot blank it.
//
// The page boot (page.js) starts the tick and reads the server list, because on
// the merged page the inventory must not start before the reader is near it.

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

// vpnModalFocusFallbackFor answers where focus goes when the control that opened a
// dialog no longer exists: the permanent Add control for the add dialog (the
// empty-state CTA that may have opened it is replaced by the next render), and the
// inventory's own heading for anything else this section does not own.
//
// The page has one window-level handler (page.js), because both dialogs now live in
// the same document: two modules assigning window.vpnModalFocusFallback would leave
// whichever loaded last answering for the other section's dialog.
function vpnModalFocusFallbackFor(modalId) {
    if (modalId === 'addBackendModal') {
        return document.getElementById('vpn-add-backend-btn') || document.getElementById('backends');
    }
    return null;
}

if (typeof window !== 'undefined') {
    window.vpnModalFocusFallbackFor = vpnModalFocusFallbackFor;
}

// Resolve a replaced row control by its action and server identity, never by
// row position. A removed or filtered-out row falls back to the stable heading.
function vpnReplacementBackendFocus(focused, tbody) {
    if (focused.dataset.action === 'vpn-open-add-backend') {
        return document.getElementById('vpn-add-backend-btn');
    }
    const equivalent = Array.from(tbody.querySelectorAll('[data-action]')).find(function (candidate) {
        return candidate.dataset.action === focused.dataset.action && candidate.dataset.serverId === focused.dataset.serverId;
    });
    if (equivalent && equivalent.closest('tr').style.display !== 'none') return equivalent;
    return document.getElementById('backends');
}

// vpnLoadBackends refreshes the inventory only.
async function vpnLoadBackends() {
    // The arrival's Inspect request is taken off durable storage before the read, so a
    // failed first read cannot leave it for a later visit to replay.
    vpnHoldInspectRequest();
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

    const focused = document.activeElement;
    const tbodyBefore = document.getElementById('vpn-backends-tbody');
    const replacingFocus = tbodyBefore && tbodyBefore.contains(focused);
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

    if (replacingFocus) vpnFocusIfFocusable(vpnReplacementBackendFocus(focused, tbodyBefore));

    if (!vpnBackendsAnchorApplied || vpnPendingInspectTunnelId !== null) {
        // The ordinary anchor landing runs once. A pending Inspect is a request that
        // names a specific row, so the read that follows it must honour it even when
        // an earlier ordinary visit already consumed the anchor rule: otherwise an
        // Inspect issued from the Diagnostics section - after this inventory had
        // loaded - could never be rescued by the one-time flag.
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
    const heading = document.getElementById('backends');
    if (heading) {
        vpnScrollToTarget(heading);
        vpnFocusIfFocusable(heading);
    }
}

// vpnApplyBackendsLanding runs its rules once per arrival, and again whenever a
// one-shot Inspect request is pending.
//
// The Inspect handoff wins over a plain fragment: it is a one-shot request that
// names a specific row. It is consumed here and nowhere else, so an ordinary
// bookmark or a reload never replays a previous Inspect. A row that is absent
// after a SUCCESSFUL read is genuinely missing, and the existing missing-entity
// statement is announced at the destination heading.
//
// landingTarget is the id the page's resolver decided on. A legacy inventory id
// whose node no longer exists (the split's card title is now the section heading)
// still lands where the id MEANS, instead of being looked up by its removed raw id
// and silently doing nothing.
// vpnPendingInspectTunnelId holds this ARRIVAL's Inspect request once the page has
// taken it off durable tab storage. The request belongs to the navigation that carried
// it: leaving it in storage let a later ordinary visit replay an arrival whose first
// read had failed, so the first thing the page and its landing do is take it.
let vpnPendingInspectTunnelId = null;

// vpnHoldInspectRequest pulls the durable request into this page, if it has not been
// taken already. It does not consume the page-local copy: the arrival keeps its
// request while a failed read is retried, and drops it only once a render has used it.
function vpnHoldInspectRequest() {
    if (vpnPendingInspectTunnelId !== null) return;
    vpnPendingInspectTunnelId = (typeof vpnConsumeBackendHandoff === 'function')
        ? vpnConsumeBackendHandoff()
        : null;
}

function vpnTakePendingInspect() {
    const tunnelId = vpnPendingInspectTunnelId;
    vpnPendingInspectTunnelId = null;
    return tunnelId;
}

function vpnApplyBackendsLanding(landingTarget) {
    vpnHoldInspectRequest();
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

    const id = (typeof landingTarget === 'string' && landingTarget)
        ? landingTarget
        : vpnOwnedAnchorId();
    if (!id) return null;
    const el = document.getElementById(id);
    if (!el) return null;
    // Dialog contents are never a landing target while the dialog is inactive.
    // Resolve by ownership so every named child, including conditional controls,
    // converges with legacy links on the permanent opener without opening it.
    const modal = document.getElementById('addBackendModal');
    const target = modal && modal.contains(el) ? document.getElementById('vpn-add-backend-btn') : el;
    const focusTarget = vpnIsFocusable(target) ? target : vpnNearestHeading(target, 'backends');
    vpnScrollToTarget(focusTarget);
    vpnFocusIfFocusable(focusTarget);
    return target.id;
}

// ---- Delegation ----

const VPN_BACKENDS_ACTIONS = {
    'vpn-open-add-backend': function () {
        if (typeof vpnOpenAddBackendModal === 'function') vpnOpenAddBackendModal();
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

// The tick and the one-off server read are the page boot's (page.js), which starts
// them when this section approaches the viewport or is targeted. A module that
// also polled here would double every inventory request on the merged page.

if (typeof window !== 'undefined') {
    window.vpnLoadBackends = vpnLoadBackends;
    window.vpnFindBackendRowByTunnelId = vpnFindBackendRowByTunnelId;
    window.vpnBackendFocusCell = vpnBackendFocusCell;
    window.vpnRevealBackendRow = vpnRevealBackendRow;
    window.vpnApplyBackendsLanding = vpnApplyBackendsLanding;
    window.vpnAnnounceBackends = vpnAnnounceBackends;
    window.initVpnBackendsListeners = initVpnBackendsListeners;
}

// This file has been evaluated: the page boot asks this registry before it
// requests a module, so the answer is recorded by the module itself rather than
// by the loader that hopes it arrived.
if (typeof vpnMarkModule === 'function') vpnMarkModule('backends_page');
