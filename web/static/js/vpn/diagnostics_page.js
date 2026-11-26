// VPN Diagnostics page controller.
//
// This document owns forwarder health, the Advanced Diagnostics disclosure and
// the connection (sessions) table. It reads /api/vpn/status and
// /api/vpn/sessions only: no configuration, no backend inventory and no server
// list, so the other pages' failures cannot blank this one.
//
// The Inspect controls that health renders land here for sessions and hand off to
// the backends page for a backend, carrying one opaque tunnel id in a one-shot
// slot. They never open Advanced Diagnostics.

let vpnShowAllRoutes = false;

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

// vpnLoadDiagnostics refreshes health and sessions. A status failure renders the
// unavailable state while the sessions list keeps its LAST successful payload with
// the stale warning; a later success clears the warning.
async function vpnLoadDiagnostics() {
    let status = null;
    try {
        status = await API.get('/api/vpn/status');
    } catch (_) {
        status = null;
    }

    try {
        const sessionsData = await API.get('/api/vpn/sessions');
        vpnLastSessions = sessionsData;
        vpnSessionsStale = false;
    } catch (_) {
        // Failure: keep showing the LAST successful payload and flag the table as
        // stale instead of faking an empty list.
        vpnSessionsStale = true;
    }

    // Cumulative Rx/Tx live in Advanced Diagnostics as since-reset totals, so
    // they are written here rather than described as rates.
    const rxElem = document.getElementById('vpn-rx');
    if (rxElem && status) rxElem.textContent = Telemetry.formatBytes(status.rx_bytes || 0);
    const txElem = document.getElementById('vpn-tx');
    if (txElem && status) txElem.textContent = Telemetry.formatBytes(status.tx_bytes || 0);

    // Renders health, the problem list, the technical panels and the charts, and
    // re-renders the sessions table from the payload stored above — once.
    vpnRenderForwarderHealth(status);
    return status;
}

function vpnStopPolling() {
    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.stop === 'function') {
        NexusTelemetry.stop('vpn-diagnostics');
    }
}

// ---- Session Inspect (same document) ----

// vpnFindSessionRow walks the tbody's rows rather than relying on a selector
// engine, so the same lookup works everywhere and never needs CSS.escape.
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

// vpnFocusHeading moves the caller's focus to a heading that already exists in
// the template with tabindex="-1", so it is genuinely focusable.
function vpnFocusHeading(id, explanationKey) {
    const heading = document.getElementById(id);
    if (heading) {
        vpnScrollToTarget(heading);
        vpnFocusIfFocusable(heading);
    }
    const summaryEl = document.getElementById('vpn-fwd-headline-summary');
    if (summaryEl && explanationKey) summaryEl.textContent = _(explanationKey);
}

// vpnFocusFirstFocusable focuses the first candidate that can actually take
// focus. A plain element satisfies typeof node.focus === 'function' even when the
// browser refuses to focus it, so focusability is read from the attribute that
// grants it.
function vpnFocusFirstFocusable(candidates) {
    for (let i = 0; i < candidates.length; i++) {
        const node = candidates[i];
        if (vpnFocusIfFocusable(node)) return true;
    }
    return false;
}

// vpnRevealSessionRow makes one session row EXIST and be visible, so a focus call
// that follows actually moves. A session can be missing from the table for a
// reason that is not a missing session: the problems-only filter excludes it
// BEFORE rendering. The order therefore matters — leave the problems-only view so
// the row is rendered, resolve it again, then let the table clear its search,
// status filter and page to it.
//
// The problems-only choice is LEFT CLEARED through the toggle handler that owns
// that state, so the toolbar button's class and label both read as inactive.
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

// vpnFocusSessionIssue reveals one session's drill-down and moves focus to the
// affected session row's action cell. Advanced Diagnostics is never touched.
//
// The missing-entity explanation is reported only when the session is genuinely
// not in the polled data. A session the problems-only filter excluded exists in
// the data, so it is revealed instead.
function vpnFocusSessionIssue(row) {
    const wanted = String(row.sessionId || row.connectionId);
    const tr = vpnRevealSessionRow(wanted);
    if (!tr) {
        const known = (typeof vpnFindSessionById === 'function') ? vpnFindSessionById(wanted) : null;
        if (!known) {
            vpnFocusHeading('vpn-troubleshooting-title', 'vpn_issue_entity_missing_session');
            return;
        }
        vpnFocusHeading('vpn-troubleshooting-title', null);
        return;
    }
    // Reveal, never toggle: the action means "show me this", so it must not close
    // a fold the operator is already reading.
    if (typeof vpnSetSessionDrilldownOpen === 'function') {
        vpnSetSessionDrilldownOpen(wanted, tr, true);
    }
    const cell = (typeof tr.querySelector === 'function') ? tr.querySelector('[data-action="vpn-toggle-session"]') : null;
    if (!vpnFocusFirstFocusable([cell, tr])) {
        vpnFocusHeading('vpn-troubleshooting-title', null);
    }
}

// vpnIssueDestinationHeading names the card that owns a problem carrying no
// entity id: a backend-scoped surface belongs to the backends document, and a
// connection/routing/dataplane condition keeps the sessions heading here.
const VPN_BACKEND_CATEGORIES = ['backend'];

function vpnIssueDestinationHeading(category) {
    const c = String(category || '').toLowerCase();
    if (VPN_BACKEND_CATEGORIES.indexOf(c) !== -1) return 'vpn-backends-title';
    return 'vpn-troubleshooting-title';
}

// vpnNavigateToBackends performs the same-tab navigation to the backend inventory.
// It is a named seam so the handoff can be observed without driving a real
// navigation.
function vpnNavigateToBackends(targetId) {
    const hash = '#' + encodeURIComponent(targetId || 'vpn-backends-title');
    if (typeof window !== 'undefined' && window.location && typeof window.location.assign === 'function') {
        window.location.assign('/vpn/backends' + hash);
    }
}

// vpnFocusBackendIssue hands a backend problem to the backends document. Only the
// opaque tunnel id travels, in a one-shot slot; the URL carries no payload. A
// backend-category problem with no id goes straight to the inventory heading with
// no handoff and no missing-entity statement.
function vpnFocusBackendIssue(row) {
    if (row && row.backendId) {
        // If the slot is unavailable the destination is still reached; only the
        // row-level focus is lost.
        vpnStoreBackendHandoff(row.backendId);
    }
    vpnNavigateToBackends('vpn-backends-title');
}

// vpnFocusIssueTarget moves focus to the existing detail for a problem WITHOUT
// opening Advanced Diagnostics. The session reveal is idempotent: a second
// Inspect on an already-open detail keeps it open instead of toggling it shut.
function vpnFocusIssueTarget(row) {
    if (row.sessionId || row.connectionId) {
        vpnFocusSessionIssue(row);
    } else if (row.backendId || vpnIssueDestinationHeading(row.category) === 'vpn-backends-title') {
        vpnFocusBackendIssue(row);
    } else {
        vpnFocusHeading(vpnIssueDestinationHeading(row.category), null);
    }
}

const VPN_DIAGNOSTICS_ACTIONS = {
    'vpn-toggle-problems-filter': function () {
        if (typeof vpnToggleSessionsProblemFilter === 'function') vpnToggleSessionsProblemFilter();
    },
    'vpn-toggle-show-all-routes': function () {
        vpnToggleShowAllRoutes();
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
    'vpn-toggle-session': function (btn) {
        const sessId = btn.dataset ? btn.dataset.sessionId : (btn.getAttribute ? btn.getAttribute('data-session-id') : null);
        const tr = btn.closest ? btn.closest('tr') : null;
        if (typeof vpnToggleSessionDrilldown === 'function') vpnToggleSessionDrilldown(sessId, tr);
    }
};

function initVpnDiagnosticsListeners() {
    if (typeof document === 'undefined') return;
    const root = (typeof document.querySelector === 'function' && (document.querySelector('#vpn-app') || document.querySelector('main'))) || document.body;
    if (!root || root._vpnDiagnosticsBound || typeof root.addEventListener !== 'function') return;
    root._vpnDiagnosticsBound = true;

    root.addEventListener('click', function (e) {
        const btn = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
        if (!btn) return;
        const action = btn.dataset ? btn.dataset.action : (btn.getAttribute ? btn.getAttribute('data-action') : null);
        if (!action || !Object.prototype.hasOwnProperty.call(VPN_DIAGNOSTICS_ACTIONS, action)) return;
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
        VPN_DIAGNOSTICS_ACTIONS[action](btn);
    });
}

// ---- Anchor landing ----

// vpnRevealAncestorDetails opens every fold that CONTAINS the target. The target's
// own fold is not expanded when the fragment names the fold itself: the landing is
// its summary, and the operator decides whether to open it.
function vpnRevealAncestorDetails(el) {
    let node = el ? el.parentElement : null;
    while (node && node !== document.body) {
        if (node.tagName && String(node.tagName).toLowerCase() === 'details') {
            node.open = true;
        }
        node = node.parentElement;
    }
}

// Ids whose owning heading is not the enclosing labelled region.
var VPN_DIAGNOSTICS_ANCHOR_FALLBACK = {
    'vpnSessionsTable': 'vpn-troubleshooting-title',
    'vpn-sessions-tbody': 'vpn-troubleshooting-title',
    'vpn-sessions-count-badge': 'vpn-troubleshooting-title',
    'vpn-sessions-toggle-problems-btn': 'vpn-troubleshooting-title',
    'vpn-sessions-toggle-problems-text': 'vpn-troubleshooting-title',
    'vpnSessionsStaleBanner': 'vpn-troubleshooting-title',
    'vpn-chart-tooltip': 'vpn-traffic-performance-title'
};

// vpnApplyDiagnosticsAnchor reveals and focuses a fragment this page owns, once,
// after the first render. A target inside the disclosure opens it (a deliberate
// deep link may do that) without toggling it shut, and an invisible chart target
// falls back to its section heading.
function vpnApplyDiagnosticsAnchor() {
    const id = vpnOwnedAnchorId();
    if (!id) return null;
    const fallbackId = VPN_DIAGNOSTICS_ANCHOR_FALLBACK[id] || 'vpn-diagnostics-title';
    const el = document.getElementById(id);
    if (!el) {
        // A conditional target (the stale banner) is not always rendered. Landing on
        // the heading that owns it is a visible, named destination; doing nothing
        // would leave focus on the document body.
        const fallback = document.getElementById(fallbackId);
        if (!fallback) return null;
        vpnScrollToTarget(fallback);
        vpnFocusIfFocusable(fallback);
        return id;
    }

    const panel = document.getElementById('vpn-diagnostics');
    // The disclosure's own id is a landing like any other: opening it is what makes
    // the target - and its title - visible.
    if (panel && typeof panel.contains === 'function' && (panel === el || panel.contains(el))) {
        if (typeof vpnSetDiagnosticsOpen === 'function') vpnSetDiagnosticsOpen(true, null);
    }
    vpnRevealAncestorDetails(el);


    let focusTarget = el;
    if (!vpnIsFocusable(el)) {
        focusTarget = vpnNearestHeading(el, fallbackId);
    }
    vpnScrollToTarget(el);
    vpnFocusIfFocusable(focusTarget);
    return id;
}

if (typeof document !== 'undefined') {
    initVpnDiagnosticsListeners();
}

document.addEventListener('DOMContentLoaded', function () {
    initVpnDiagnosticsListeners();

    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
        NexusTelemetry.poll('vpn-diagnostics', async function () {
            await vpnLoadDiagnostics();
            if (!vpnDiagnosticsAnchorApplied) {
                vpnDiagnosticsAnchorApplied = true;
                vpnApplyDiagnosticsAnchor();
            }
        }, 5000);
    }
});

var vpnDiagnosticsAnchorApplied = false;

if (typeof window !== 'undefined') {
    window.vpnLoadDiagnostics = vpnLoadDiagnostics;
    window.vpnStopPolling = vpnStopPolling;
    window.vpnToggleShowAllRoutes = vpnToggleShowAllRoutes;
    window.vpnFindSessionRow = vpnFindSessionRow;
    window.vpnRevealSessionRow = vpnRevealSessionRow;
    window.vpnFocusIssueTarget = vpnFocusIssueTarget;
    window.vpnIssueDestinationHeading = vpnIssueDestinationHeading;
    window.vpnNavigateToBackends = vpnNavigateToBackends;
    window.vpnApplyDiagnosticsAnchor = vpnApplyDiagnosticsAnchor;
    window.initVpnDiagnosticsListeners = initVpnDiagnosticsListeners;
    // The previous whole-surface loader name is kept as an alias for this page's
    // own refresh; it no longer touches another document's data.
    window.vpnLoadData = vpnLoadDiagnostics;
}
