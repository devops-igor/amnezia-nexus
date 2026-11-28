// VPN Diagnostics section controller.
//
// This section owns the Advanced Diagnostics disclosure, the connection
// (sessions) table and the Inspect landings behind the Active problems rows.
//
// It reads /api/vpn/sessions only, and it does NOT read /api/vpn/status: the
// forwarder health it renders comes from the one status sample the page boot takes
// for the Overview, so the health headline and the four signals are the same
// measurement and a second status loop cannot exist. It reads no configuration and
// no backend inventory, so a failure in another section cannot blank this one.
//
// The Inspect controls that health renders resolve inside this document now: a
// session reveals its own drilldown, and a backend hands its tunnel id to the
// Backends landing through the same one-shot slot it used across documents.

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

// vpnLoadSessions refreshes the sessions read alone. A failure keeps the LAST
// successful payload and flags the table as stale; a later success clears the flag.
// The payload is cached, not rendered here, so the renderer that runs after it sees
// the same rows whichever order the boot's reads complete in.
async function vpnLoadSessions() {
    try {
        const sessionsData = await API.get('/api/vpn/sessions');
        vpnLastSessions = sessionsData;
        vpnSessionsStale = false;
    } catch (_) {
        // Failure: keep showing the LAST successful payload and flag the table as
        // stale instead of faking an empty list.
        vpnSessionsStale = true;
    }
    return vpnLastSessions;
}

// vpnRenderSessionsFromCache re-renders the table from the payload vpnLoadSessions
// stored. Splitting the read from the render is what lets the page paint the health
// headline and the sessions table in one pass without reading the status twice.
function vpnRenderSessionsFromCache() {
    if (typeof renderSessions !== 'function') return false;
    if (vpnLastSessions && Array.isArray(vpnLastSessions.sessions)) {
        renderSessions(vpnLastSessions.sessions);
        return true;
    }
    if (typeof vpnRenderSessionsUnavailable === 'function') {
        // A first read that failed with no earlier snapshot has nothing to show and
        // must not leave the table on its loading row.
        vpnRenderSessionsUnavailable();
    }
    return false;
}

// vpnLoadDiagnostics is kept as the section's own refresh name: it reads the
// sessions and repaints. The status sample is passed in by the page boot, because
// this section does not own a status stream of its own.
async function vpnLoadDiagnostics(status) {
    // The totals are written through the same function the health renderer uses, so
    // this entry point and the shared tick cannot describe the same sample
    // differently. That writer lives in the eager health module because the shared
    // tick reaches it before this file has been loaded.
    if (typeof vpnRenderCumulativeTotals === 'function') vpnRenderCumulativeTotals(status);
    await vpnLoadSessions();
    vpnRenderSessionsFromCache();
    return status;
}

// vpnStopPolling stops the streams this page started. They are named explicitly
// because one document now runs three of them, and a bare stop would leave the
// others running after the reader has left.
function vpnStopPolling() {
    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.stop === 'function') {
        NexusTelemetry.stop('vpn-sessions');
    }
}

// vpnStopPagePolling tears down every stream the merged page owns. The page boot
// calls it on departure; no section keeps a timer the others do not know about.
function vpnStopPagePolling() {
    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.stop === 'function') {
        NexusTelemetry.stop('vpn-overview');
        NexusTelemetry.stop('vpn-backends');
        NexusTelemetry.stop('vpn-sessions');
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
    if (VPN_BACKEND_CATEGORIES.indexOf(c) !== -1) return 'backends';
    return 'vpn-troubleshooting-title';
}

// vpnNavigateToBackends lands on the backend inventory inside this same document.
// It is a named seam so the handoff can be observed without driving a real
// navigation: the section is mounted, the landing runs, and the fragment is the
// canonical one the rail and a bookmark use.
function vpnNavigateToBackends(targetId) {
    const hash = '#' + encodeURIComponent(targetId || 'backends');
    if (typeof window === 'undefined' || !window.history) return;
    if (typeof window.history.pushState === 'function') {
        window.history.pushState(window.history.state, '', hash);
    }
    if (typeof window.vpnLandOnFragment === 'function') {
        window.vpnLandOnFragment(hash, 'click');
    }
}

// vpnFocusBackendIssue hands a backend problem to the backends document. Only the
// opaque tunnel id travels, in a one-shot slot; the URL carries no payload. A
// backend-category problem with no id goes straight to the inventory heading with
// no handoff and no missing-entity statement.
function vpnFocusBackendIssue(row) {
    const nonce = row && row.backendId ? vpnStoreBackendHandoff(row.backendId) : null;
    // The URL carries only a random arrival identity, never an entity id. If
    // storage is unavailable the heading remains a usable destination.
    vpnNavigateToBackends(nonce ? 'vpn-inspect-' + nonce : 'backends');
}

// vpnFocusIssueTarget moves focus to the existing detail for a problem WITHOUT
// opening Advanced Diagnostics. The session reveal is idempotent: a second
// Inspect on an already-open detail keeps it open instead of toggling it shut.
function vpnFocusIssueTarget(row) {
    if (row.sessionId || row.connectionId) {
        vpnFocusSessionIssue(row);
    } else if (row.backendId || vpnIssueDestinationHeading(row.category) === 'backends') {
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
//
// landingTarget is the id the page's resolver decided on; without it the fragment
// itself is read, which is what a direct call in this section's own document used.
function vpnApplyDiagnosticsAnchor(landingTarget) {
    const id = (typeof landingTarget === 'string' && landingTarget) ? landingTarget : vpnOwnedAnchorId();
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
    vpnScrollToTarget(focusTarget);
    vpnFocusIfFocusable(focusTarget);
    return id;
}

if (typeof document !== 'undefined') {
    initVpnDiagnosticsListeners();
}

// The sessions tick is the page boot's (page.js). Landing is the boot's too: a
// jump, a cold fragment and a browser Back reach vpnApplyDiagnosticsAnchor through
// it, and a poll tick never lands.

if (typeof window !== 'undefined') {
    window.vpnLoadDiagnostics = vpnLoadDiagnostics;
    window.vpnLoadSessions = vpnLoadSessions;
    window.vpnRenderSessionsFromCache = vpnRenderSessionsFromCache;
    window.vpnStopPolling = vpnStopPolling;
    window.vpnStopPagePolling = vpnStopPagePolling;
    window.vpnToggleShowAllRoutes = vpnToggleShowAllRoutes;
    window.vpnFindSessionRow = vpnFindSessionRow;
    window.vpnRevealSessionRow = vpnRevealSessionRow;
    window.vpnFocusIssueTarget = vpnFocusIssueTarget;
    window.vpnIssueDestinationHeading = vpnIssueDestinationHeading;
    window.vpnNavigateToBackends = vpnNavigateToBackends;
    window.vpnApplyDiagnosticsAnchor = vpnApplyDiagnosticsAnchor;
    window.initVpnDiagnosticsListeners = initVpnDiagnosticsListeners;
    // The previous whole-surface loader name is kept as an alias for this
    // section's own refresh; it no longer touches another section's data.
    window.vpnLoadData = vpnLoadDiagnostics;
}

// This file has been evaluated: the page boot asks this registry before it
// requests a module, so the answer is recorded by the module itself rather than
// by the loader that hopes it arrived.
if (typeof vpnMarkModule === 'function') vpnMarkModule('diagnostics_page');
