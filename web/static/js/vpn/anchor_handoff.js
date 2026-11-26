/* Legacy-fragment handoff for the VPN overview.
 *
 * The VPN subject used to be one document, so old bookmarks and external links
 * point at /vpn#<id> for blocks that now render on /vpn/backends or
 * /vpn/diagnostics. Fragments never reach the server, so the overview resolves
 * them here, before its own controllers start: a recognised child-page id is
 * handed off with location.replace (so Back reaches the previous document, not
 * this redirecting URL) and the query string is carried across.
 *
 * The allowlist is literal and by owner, not by prefix: `vpn-sessions` is the
 * overview's session-count signal, while the sessions table is
 * `vpnSessionsTable`, and a prefix rule would send the signal away from its page.
 * An id this page owns needs no handoff; an unknown or malformed one does
 * nothing, leaving a usable overview.
 */
(function () {
    var PAGE_BY_OWNER = {
        backends: '/vpn/backends',
        diagnostics: '/vpn/diagnostics'
    };

    // Ids inside a dialog canonicalise to the control that opens it. A fragment
    // must never open a dialog or run an action by itself.
    var CANONICAL_TARGET = {
        'addBackendModal': 'vpn-add-backend-btn',
        'addBackendForm': 'vpn-add-backend-btn',
        'vpnServerSelect': 'vpn-add-backend-btn',
        'vpnServerDetails': 'vpn-add-backend-btn',
        'vpnServerDetailHost': 'vpn-add-backend-btn',
        'vpnServerDetailPort': 'vpn-add-backend-btn',
        'vpnServerDetailStatus': 'vpn-add-backend-btn',
        'vpnServerDetailAwgBadge': 'vpn-add-backend-btn',
        'vpnServerDetailCheckRow': 'vpn-add-backend-btn',
        'vpnServerDetailCheckHint': 'vpn-add-backend-btn',
        'vpnQuickCheckBtn': 'vpn-add-backend-btn',
        'vpnQuickCheckIcon': 'vpn-add-backend-btn',
        'vpnQuickCheckBtnText': 'vpn-add-backend-btn',
        'vpnQuickCheckSpinner': 'vpn-add-backend-btn',
        'vpnNoServersNotice': 'vpn-add-backend-btn',
        'vpnModalError': 'vpn-add-backend-btn',
        'vpnAddBackendSubmitBtn': 'vpn-add-backend-btn',
        // Transient loading rows: the owning heading is the stable landing.
        'vpn-backends-loading': 'vpn-backends-title',
        'vpn-sessions-loading': 'vpn-troubleshooting-title'
    };

    var BACKENDS_IDS = [
        'vpn-backends-title',
        'vpn-add-backend-btn',
        'vpnTableContainer',
        'vpnBackendsTable',
        'vpn-backends-tbody',
        'vpn-backends-loading',
        'vpn-backends-announcement',
        'addBackendModal',
        'addBackendForm',
        'vpnServerSelect',
        'vpnServerDetails',
        'vpnServerDetailHost',
        'vpnServerDetailPort',
        'vpnServerDetailStatus',
        'vpnServerDetailAwgBadge',
        'vpnServerDetailCheckRow',
        'vpnServerDetailCheckHint',
        'vpnQuickCheckBtn',
        'vpnQuickCheckIcon',
        'vpnQuickCheckBtnText',
        'vpnQuickCheckSpinner',
        'vpnNoServersNotice',
        'vpnModalError',
        'vpnAddBackendSubmitBtn'
    ];

    var DIAGNOSTICS_IDS = [
        'vpn-forwarder-card',
        'vpn-health-title',
        'vpn-fwd-status-badge',
        'vpn-fwd-status-icon',
        'vpn-fwd-status-text',
        'vpn-fwd-health-live',
        'vpn-fwd-headline-summary',
        'vpn-fwd-problem-counts',
        'vpn-fwd-problem-announcement',
        'vpn-fwd-problem-list',
        'vpn-advanced-entry',
        'vpn-diagnostics',
        'vpn-diagnostics-title',
        'vpn-close-diagnostics',
        'vpn-traffic-performance',
        'vpn-traffic-performance-title',
        'vpn-history-window-toggles',
        'vpn-chart-throughput-badges',
        'vpn-chart-throughput',
        'vpn-chart-throughput-axis',
        'vpn-chart-drops-badges',
        'vpn-chart-drops',
        'vpn-chart-drops-axis',
        'vpn-chart-latency-badges',
        'vpn-chart-latency',
        'vpn-chart-latency-axis',
        'vpn-chart-queue-badges',
        'vpn-chart-queue',
        'vpn-chart-queue-axis',
        'vpn-chart-tooltip',
        'vpn-diag-throughput',
        'vpn-diag-packet-rate',
        'vpn-diag-ewma5m',
        'vpn-diag-ewma1h',
        'vpn-diag-lat-percentiles',
        'vpn-diag-lat-max',
        'vpn-cumulative-totals',
        'vpn-rx',
        'vpn-tx',
        'vpn-routing-drops',
        'vpn-routing-drops-title',
        'vpn-diag-routing-counts',
        'vpn-diag-routing-badge',
        'vpn-diag-queue-occ',
        'vpn-diag-queue-peak',
        'vpn-diag-queue-dwell',
        'vpn-fwd-counters-since',
        'vpn-diag-routing-alerts',
        'vpn-diag-drops-client',
        'vpn-diag-drops-return',
        'vpn-diag-drops-total',
        'vpn-diag-drop-reasons',
        'vpn-fwd-routes-details',
        'vpn-fwd-routes-badge',
        'vpn-routes-toggle-all-btn',
        'vpn-fwd-routes-summary-status',
        'vpn-fwd-routes-empty',
        'vpn-fwd-routes-table',
        'vpn-fwd-routes-tbody',
        'vpn-reason-history',
        'vpn-chart-reasons',
        'vpn-runtime-details',
        'vpn-runtime-details-title',
        'vpn-diag-engine-status',
        'vpn-diag-peers-status',
        'vpn-diag-hs-freshness',
        'vpn-diag-write-stalls-recent',
        'vpn-diag-write-stalls-total',
        'vpn-diag-res-cpu',
        'vpn-diag-res-mem',
        'vpn-diag-res-fd',
        'vpn-per-backend',
        'vpn-diag-be-traffic',
        'vpn-chart-backends',
        'vpn-history-backend-select',
        'vpn-chart-backend-series',
        'vpn-history-fleet-note',
        'vpn-troubleshooting-title',
        'vpn-sessions-count-badge',
        'vpn-sessions-toggle-problems-btn',
        'vpn-sessions-toggle-problems-text',
        'vpnSessionsTable',
        'vpn-sessions-tbody',
        'vpn-sessions-loading',
        'vpnSessionsStaleBanner'
    ];

    var OWNER_BY_ID = {};
    BACKENDS_IDS.forEach(function (id) { OWNER_BY_ID[id] = 'backends'; });
    DIAGNOSTICS_IDS.forEach(function (id) { OWNER_BY_ID[id] = 'diagnostics'; });

    function vpnAnchorOwner(id) {
        if (!id || !Object.prototype.hasOwnProperty.call(OWNER_BY_ID, id)) return null;
        return OWNER_BY_ID[id];
    }

    function vpnCanonicalAnchorId(id) {
        if (Object.prototype.hasOwnProperty.call(CANONICAL_TARGET, id)) return CANONICAL_TARGET[id];
        return id;
    }

    function vpnIsOverviewPath(path) {
        return path === '/vpn' || path === '/vpn/';
    }

    // vpnLegacyHandoffDestination resolves a legacy fragment to the URL of its
    // owning page, or null when this page owns the id (or does not know it). It is
    // a pure function so the whole allowlist can be exercised without driving a
    // real navigation.
    function vpnLegacyHandoffDestination(path, search, hash) {
        if (!vpnIsOverviewPath(path)) return null;
        if (!hash || hash.length < 2) return null;
        let id;
        try {
            id = decodeURIComponent(hash.slice(1));
        } catch (_) {
            return null;
        }
        if (!id || id.indexOf('#') !== -1) return null;
        const owner = vpnAnchorOwner(id);
        if (!owner) return null;
        const target = vpnCanonicalAnchorId(id);
        return PAGE_BY_OWNER[owner] + (search || '') + '#' + encodeURIComponent(target);
    }

    // vpnHandoffLegacyFragment returns true when it started a navigation. The
    // overview's own controller checks that flag so a handoff never runs a poll
    // for a page it is leaving.
    function vpnHandoffLegacyFragment() {
        if (typeof window === 'undefined' || !window.location) return false;
        const destination = vpnLegacyHandoffDestination(
            window.location.pathname, window.location.search, window.location.hash);
        if (!destination) return false;
        window.vpnHandoffPending = true;
        window.location.replace(destination);
        return true;
    }

    if (typeof window !== 'undefined') {
        window.vpnHandoffPending = false;
        window.vpnAnchorOwner = vpnAnchorOwner;
        window.vpnCanonicalAnchorId = vpnCanonicalAnchorId;
        window.vpnLegacyHandoffDestination = vpnLegacyHandoffDestination;
        window.vpnHandoffLegacyFragment = vpnHandoffLegacyFragment;
        vpnHandoffLegacyFragment();
        window.addEventListener('hashchange', vpnHandoffLegacyFragment);
    }
})();
