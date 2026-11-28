/* Fragment resolution for the merged VPN page.
 *
 * The VPN subject is one document again: Overview, Backends and Diagnostics are
 * sections of /vpn. The id families the three documents had are unchanged, so a
 * bookmark, an Inspect handoff or an external link still names a real node. What
 * changed is what happens to it: instead of navigating to another document, this
 * page resolves the fragment locally - it decides which section owns the id and
 * hands both facts to the page boot, which mounts that section before landing.
 *
 * The retired ROUTES are not here: /vpn/backends and /vpn/diagnostics are answered by
 * the Go handlers, which own the redirect and its transient ?section= marker. A
 * second copy of that map in JavaScript would be a third party to the same decision,
 * and this page only has to know how to consume the marker it receives.
 *
 * The allowlist is literal and by owner, not by prefix: `vpn-sessions` is the
 * Overview's session-count signal while the sessions table is `vpnSessionsTable`,
 * and a prefix rule would send the signal to the wrong section. An id this table
 * does not know resolves to nothing at all, so an unknown or malformed fragment
 * leaves a usable page rather than guessing.
 */
(function () {
    'use strict';

    // Which section of the merged page owns an id. Every entry is a literal id
    // that some shipped markup, controller or legacy link can name.
    var SECTION_BY_ID = {
        // --- Overview: the four signals, the health headline, the configuration ---
        'overview': 'overview',
        'overview-region': 'overview',
        'vpn-signal-backends-value': 'overview',
        'vpn-signal-backends-sub': 'overview',
        'vpn-sessions': 'overview',
        'vpn-session-mismatch': 'overview',
        'vpn-signal-throughput-value': 'overview',
        'vpn-signal-throughput-sub': 'overview',
        'vpn-signal-drops-value': 'overview',
        'vpn-signal-drops-sub': 'overview',
        'vpn-forwarder-card': 'overview',
        'vpn-health-title': 'overview',
        'vpn-fwd-status-badge': 'overview',
        'vpn-fwd-status-icon': 'overview',
        'vpn-fwd-status-text': 'overview',
        'vpn-fwd-health-live': 'overview',
        'vpn-fwd-headline-summary': 'overview',
        'vpn-fwd-problem-counts': 'overview',
        'vpn-fwd-problem-announcement': 'overview',
        'vpn-view-problems-link': 'overview',
        'vpn-configuration': 'overview',
        'vpn-listener-badge': 'overview',
        'vpn-listen-port': 'overview',
        'vpn-subnet': 'overview',
        'vpn-public-endpoint': 'overview',
        'vpn-edit-endpoint-btn': 'overview',
        // The endpoint dialog's own ids canonicalise to the control that opens it.
        'editEndpointModal': 'overview',
        'editEndpointForm': 'overview',
        'vpnPublicEndpointInput': 'overview',
        'vpnEditEndpointSubmitBtn': 'overview',
        'vpnEndpointModalError': 'overview',

        // --- Backends: the inventory card and its add dialog ---
        'backends': 'backends',
        'backends-region': 'backends',
        // The split's inventory card title. It is not a node any more: the section
        // heading IS the card title, so this legacy id canonicalises to it below.
        'vpn-backends-title': 'backends',
        'vpn-backends-announcement': 'backends',
        'vpn-add-backend-btn': 'backends',
        'vpnTableContainer': 'backends',
        'vpnBackendsTable': 'backends',
        'vpn-backends-tbody': 'backends',
        'vpn-backends-loading': 'backends',
        'vpn-backends-stale': 'backends',
        'vpnBackendsStaleBanner': 'backends',
        'addBackendModal': 'backends',
        'addBackendForm': 'backends',
        'vpnServerSelect': 'backends',
        'vpnServerDetails': 'backends',
        'vpnServerDetailHost': 'backends',
        'vpnServerDetailPort': 'backends',
        'vpnServerDetailStatus': 'backends',
        'vpnServerDetailAwgBadge': 'backends',
        'vpnServerDetailCheckRow': 'backends',
        'vpnServerDetailCheckHint': 'backends',
        'vpnQuickCheckBtn': 'backends',
        'vpnQuickCheckIcon': 'backends',
        'vpnQuickCheckBtnText': 'backends',
        'vpnQuickCheckSpinner': 'backends',
        'vpnNoServersNotice': 'backends',
        'vpnModalError': 'backends',
        'vpnAddBackendSubmitBtn': 'backends',

        // --- Diagnostics: active problems, sessions, Advanced Diagnostics ---
        'diagnostics': 'diagnostics',
        'diagnostics-region': 'diagnostics',
        'active-problems': 'diagnostics',
        'vpn-active-problems-card': 'diagnostics',
        'vpn-fwd-problems-empty': 'diagnostics',
        'vpn-fwd-problem-list': 'diagnostics',
        'vpn-sessions-card': 'diagnostics',
        'vpn-troubleshooting-title': 'diagnostics',
        'vpn-sessions-count-badge': 'diagnostics',
        'vpn-sessions-toggle-problems-btn': 'diagnostics',
        'vpn-sessions-toggle-problems-text': 'diagnostics',
        'vpnSessionsTable': 'diagnostics',
        'vpn-sessions-tbody': 'diagnostics',
        'vpn-sessions-loading': 'diagnostics',
        'vpnSessionsStaleBanner': 'diagnostics',
        'vpn-advanced-entry': 'diagnostics',
        'vpn-advanced-block': 'diagnostics',
        'vpn-diagnostics': 'diagnostics',
        'vpn-diagnostics-title': 'diagnostics',
        'vpn-close-diagnostics': 'diagnostics',
        'vpn-traffic-performance': 'diagnostics',
        'vpn-traffic-performance-title': 'diagnostics',
        'vpn-history-window-toggles': 'diagnostics',
        'vpn-chart-throughput-badges': 'diagnostics',
        'vpn-chart-throughput': 'diagnostics',
        'vpn-chart-throughput-axis': 'diagnostics',
        'vpn-chart-drops-badges': 'diagnostics',
        'vpn-chart-drops': 'diagnostics',
        'vpn-chart-drops-axis': 'diagnostics',
        'vpn-chart-latency-badges': 'diagnostics',
        'vpn-chart-latency': 'diagnostics',
        'vpn-chart-latency-axis': 'diagnostics',
        'vpn-chart-queue-badges': 'diagnostics',
        'vpn-chart-queue': 'diagnostics',
        'vpn-chart-queue-axis': 'diagnostics',
        'vpn-chart-tooltip': 'diagnostics',
        'vpn-diag-throughput': 'diagnostics',
        'vpn-diag-packet-rate': 'diagnostics',
        'vpn-diag-ewma5m': 'diagnostics',
        'vpn-diag-ewma1h': 'diagnostics',
        'vpn-diag-lat-percentiles': 'diagnostics',
        'vpn-diag-lat-max': 'diagnostics',
        'vpn-cumulative-totals': 'diagnostics',
        'vpn-rx': 'diagnostics',
        'vpn-tx': 'diagnostics',
        'vpn-routing-drops': 'diagnostics',
        'vpn-routing-drops-title': 'diagnostics',
        'vpn-diag-routing-counts': 'diagnostics',
        'vpn-diag-routing-badge': 'diagnostics',
        'vpn-diag-queue-occ': 'diagnostics',
        'vpn-diag-queue-peak': 'diagnostics',
        'vpn-diag-queue-dwell': 'diagnostics',
        'vpn-fwd-counters-since': 'diagnostics',
        'vpn-diag-routing-alerts': 'diagnostics',
        'vpn-diag-drops-client': 'diagnostics',
        'vpn-diag-drops-return': 'diagnostics',
        'vpn-diag-drops-total': 'diagnostics',
        'vpn-diag-drop-reasons': 'diagnostics',
        'vpn-fwd-routes-details': 'diagnostics',
        'vpn-fwd-routes-badge': 'diagnostics',
        'vpn-routes-toggle-all-btn': 'diagnostics',
        'vpn-fwd-routes-summary-status': 'diagnostics',
        'vpn-fwd-routes-empty': 'diagnostics',
        'vpn-fwd-routes-table': 'diagnostics',
        'vpn-fwd-routes-tbody': 'diagnostics',
        'vpn-reason-history': 'diagnostics',
        'vpn-chart-reasons': 'diagnostics',
        'vpn-runtime-details': 'diagnostics',
        'vpn-runtime-details-title': 'diagnostics',
        'vpn-diag-engine-status': 'diagnostics',
        'vpn-diag-peers-status': 'diagnostics',
        'vpn-diag-hs-freshness': 'diagnostics',
        'vpn-diag-write-stalls-recent': 'diagnostics',
        'vpn-diag-write-stalls-total': 'diagnostics',
        'vpn-diag-res-cpu': 'diagnostics',
        'vpn-diag-res-mem': 'diagnostics',
        'vpn-diag-res-fd': 'diagnostics',
        'vpn-per-backend': 'diagnostics',
        'vpn-diag-be-traffic': 'diagnostics',
        'vpn-chart-backends': 'diagnostics',
        'vpn-history-backend-select': 'diagnostics',
        'vpn-chart-backend-series': 'diagnostics',
        'vpn-history-fleet-note': 'diagnostics'
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
        'editEndpointModal': 'vpn-edit-endpoint-btn',
        'editEndpointForm': 'vpn-edit-endpoint-btn',
        'vpnPublicEndpointInput': 'vpn-edit-endpoint-btn',
        'vpnEditEndpointSubmitBtn': 'vpn-edit-endpoint-btn',
        'vpnEndpointModalError': 'vpn-edit-endpoint-btn',
        // Transient loading rows and a conditional banner: the owning heading is
        // the stable landing when the row is not rendered.
        'vpn-backends-loading': 'backends',
        'vpn-backends-title': 'backends',
        'vpnBackendsStaleBanner': 'backends',
        'vpn-backends-stale': 'backends',
        'vpn-sessions-loading': 'vpn-troubleshooting-title',
        'vpnSessionsStaleBanner': 'vpn-troubleshooting-title',
        // A tooltip is not a landing target; its chart's section owns it.
        'vpn-chart-tooltip': 'vpn-traffic-performance-title'
    };

    // The three sections in document order. The default is the first one, which is
    // also where a cold arrival with no fragment belongs.
    var SECTION_ORDER = ['overview', 'backends', 'diagnostics'];
    var SECTION_HEADING = {
        overview: 'overview',
        backends: 'backends',
        diagnostics: 'diagnostics'
    };

    function vpnSectionHeadingId(section) {
        return Object.prototype.hasOwnProperty.call(SECTION_HEADING, section)
            ? SECTION_HEADING[section]
            : SECTION_HEADING.overview;
    }

    // vpnOwnsId reports which section an id belongs to, or null when this page
    // knows nothing about it.
    function vpnSectionForId(id) {
        if (!id || !Object.prototype.hasOwnProperty.call(SECTION_BY_ID, id)) return null;
        return SECTION_BY_ID[id];
    }

    function vpnCanonicalAnchorId(id) {
        if (Object.prototype.hasOwnProperty.call(CANONICAL_TARGET, id)) return CANONICAL_TARGET[id];
        return id;
    }

    // vpnDecodeFragment decodes a raw location.hash once. A malformed escape, an
    // empty fragment or a nested '#' yields null.
    function vpnDecodeFragment(hash) {
        if (!hash || hash.length < 2 || hash.charAt(0) !== '#') return null;
        var id;
        try {
            id = decodeURIComponent(hash.slice(1));
        } catch (_) {
            return null;
        }
        if (!id || id.indexOf('#') !== -1) return null;
        if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(id)) return null;
        return id;
    }

    // VPN_INSPECT_FRAGMENT is the arrival identity an Inspect writes. It is not an
    // element id and it is deliberately NOT in the allowlist above: it names a
    // one-shot request, which the backends section is the only thing that can honour.
    // Claiming it here as an id would make the resolver answer for a node that does
    // not exist, so it is recognised as its own family instead.
    var VPN_INSPECT_FRAGMENT = /^#vpn-inspect-[a-f0-9]{32}$/;

    // vpnIsInspectFragment reports whether a fragment is an Inspect arrival. Its
    // caller mounts Backends and lets the completed inventory read consume the
    // request, because only a SUCCESSFUL read can say whether the row is there.
    function vpnIsInspectFragment(hash) {
        return typeof hash === 'string' && VPN_INSPECT_FRAGMENT.test(hash);
    }

    // vpnResolveFragment maps a fragment to the section that owns it and the id the
    // landing should focus. An id this page does not know returns null, and the
    // caller then leaves the page where the browser put it.
    function vpnResolveFragment(hash) {
        var id = vpnDecodeFragment(hash);
        if (!id) return null;
        var section = vpnSectionForId(id);
        if (!section) return null;
        return { id: id, section: section, target: vpnCanonicalAnchorId(id) };
    }

    // vpnSectionFromMarker reads the transient marker a retired child route leaves
    // behind. The value is matched against the fixed section list, so a query
    // string can never decide where the page goes beyond naming a section that
    // exists.
    function vpnSectionFromMarker(search) {
        if (!search) return null;
        var match = /[?&]section=([A-Za-z]+)/.exec(search);
        if (!match) return null;
        var name = match[1].toLowerCase();
        return SECTION_ORDER.indexOf(name) === -1 ? null : name;
    }

    if (typeof window !== 'undefined') {
        window.vpnSectionForId = vpnSectionForId;
        window.vpnCanonicalAnchorId = vpnCanonicalAnchorId;
        window.vpnResolveFragment = vpnResolveFragment;
        window.vpnIsInspectFragment = vpnIsInspectFragment;
        window.vpnSectionFromMarker = vpnSectionFromMarker;
        window.vpnSectionHeadingId = vpnSectionHeadingId;
    }
})();
