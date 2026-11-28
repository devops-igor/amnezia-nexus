/* Helpers and shared actions the VPN page needs.
 *
 * The VPN subject is one document with three sections, and every section's
 * controllers load beside this module. The pieces below are used by two or more of
 * them, so they live here rather than being duplicated: a second copy of a
 * formatter or a status label is how two sections start describing the same value
 * differently.
 *
 * The one delegated action here is the dialog CLOSE control, because on the merged
 * page both dialogs are in the same document and each section's handler would
 * otherwise close the same dialog a second time. It is a single listener on the
 * document, bound once; nothing here polls an endpoint or reads a value a section
 * owns.
 */

// vpnAssignText writes text only when it actually changes. Several of these
// nodes are polite atomic live regions, so re-assigning identical text on every
// poll would re-announce an unchanged status to a screen reader.
function vpnAssignText(el, text) {
    if (!el) return;
    const next = String(text === null || typeof text === 'undefined' ? '' : text);
    if (el.textContent === next) return;
    el.textContent = next;
}

// vpnDiagText renders a translated string with {name} placeholders. The bundle
// spells its placeholders with braces, so substitution stays with the caller.
function vpnDiagText(key, values) {
    const parameters = values || {};
    return _(key).replace(/\{([a-z0-9_]+)\}/g, function (match, name) {
        return Object.prototype.hasOwnProperty.call(parameters, name) ? String(parameters[name]) : match;
    });
}

// vpnFormatApiError picks the most specific message an API failure carries.
function vpnFormatApiError(err, res, data) {
    const errMsg = (data && (data.detail || data.message || data.error)) ||
        (err && err.data && (err.data.detail || err.data.message || err.data.error)) ||
        (res && `HTTP ${res.status} ${res.statusText || _('error')}`.trim()) ||
        (err && err.status ? `HTTP ${err.status}` : '') ||
        (err && err.message) || _('error');
    return errMsg;
}

function vpnStatusBadgeClass(status) {
    switch (status) {
        case 'active': return 'badge-success';
        case 'degraded': return 'badge-warn';
        case 'connecting': return 'badge-info';
        case 'disabled': return 'badge-danger';
        default: return 'badge-secondary';
    }
}

function vpnStatusLabel(status) {
    switch (status) {
        case 'active': return _('active');
        case 'degraded': return _('vpn_degraded');
        case 'connecting': return _('connecting');
        case 'disabled': return _('disabled');
        default: return String(status);
    }
}

function vpnSetListenerBadge(running) {
    const badge = document.getElementById('vpn-listener-badge');
    if (!badge) return;
    badge.className = 'badge ' + (running ? 'badge-success' : 'badge-secondary');
    badge.textContent = '';
    const dot = document.createElement('span');
    dot.className = 'badge-dot';
    badge.appendChild(dot);
    badge.appendChild(document.createTextNode(' ' + (running ? _('vpn_running') : _('vpn_stopped'))));
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

// vpnFormatHealthPps renders an aggregate packet rate. A value that is not a
// measurement returns null so the caller renders the not-measured state instead
// of a number nobody sampled.
function vpnFormatHealthPps(pps) {
    if (!vpnSignalMeasured(pps)) return null;
    if (pps >= 1e6) return (pps / 1e6).toFixed(2) + ' Mpps';
    if (pps >= 1e3) return (pps / 1e3).toFixed(2) + ' Kpps';
    return pps.toFixed(1) + ' pps';
}

// vpnFormatHealthDuration renders an ACCUMULATED duration, keeping the remainder
// of each unit so a since-reset counter is not silently floored: 90s is "1m 30s",
// not "1m". Distinct from vpnFormatHealthWindow, which renders a sample horizon.
function vpnFormatHealthDuration(sec) {
    const s = Math.max(0, Math.floor(Number(sec) || 0));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

// vpnSetDiagnosticText is the single writer of a diagnostic row's value AND its
// measured/unmeasured state. Writing both together is what stops a row from
// showing a number while still carrying the not-measured marker, or the reverse.
function vpnSetDiagnosticText(el, measured, text) {
    if (!el) return;
    el.textContent = text;
    if (measured) {
        el.classList.remove('vpn-not-measured');
    } else {
        el.classList.add('vpn-not-measured');
    }
}

// vpnIsFocusable reports whether focus() on this node would actually move focus.
// `typeof el.focus === 'function'` is true for every element, including ones the
// browser refuses to focus, so the attribute (or the element's own native
// focusability) is what decides.
function vpnIsFocusable(el) {
    if (!el || typeof el.focus !== 'function' || typeof el.getAttribute !== 'function') return false;
    if (el.getAttribute('tabindex') !== null) return true;
    const tag = el.tagName ? String(el.tagName).toLowerCase() : '';
    if (tag === 'summary') return true;
    if (tag === 'a') return typeof el.hasAttribute === 'function' && el.hasAttribute('href');
    return tag === 'button' || tag === 'input' || tag === 'select' || tag === 'textarea';
}

// vpnFocusIfFocusable moves focus only when the node can take it, and reports
// whether focus moved.
function vpnFocusIfFocusable(el) {
    if (!vpnIsFocusable(el)) return false;
    el.focus();
    return true;
}

// vpnScrollToTarget positions the intended landing target.
//
// The scroll is INSTANT, and that is stated rather than inherited. The merged page
// reuses the Settings sub-navigation, whose stylesheet asks for smooth scrolling on
// any page that has one - so an unqualified scrollIntoView here would animate. An
// animated landing is not merely slower: the focus call that follows it interrupts
// the animation, the page stops part way, and the reader ends up mid-document with
// the rail naming the wrong section. Instant also gives a reduced-motion visitor the
// same destination without travel, which is what this helper always promised.
function vpnScrollToTarget(el) {
    if (el && typeof el.scrollIntoView === 'function') {
        try {
            el.scrollIntoView({ block: 'start', behavior: 'instant' });
        } catch (_) {
            // A host that rejects the options object still has the CSS path.
            el.scrollIntoView(true);
        }
    }
}

// vpnNearestHeading returns the named heading that owns a region, used when the
// landing target itself cannot take focus (a value, a table container, a chart
// body). A disclosure lands on its summary; a labelled region lands on the
// heading its aria-labelledby names.
function vpnNearestHeading(el, fallbackId) {
    if (!el || typeof el.closest !== 'function') return null;
    const details = el.closest('details');
    if (details) {
        const summary = details.querySelector ? details.querySelector('summary') : null;
        if (summary) return summary;
    }
    const labelled = el.closest('[aria-labelledby]');
    if (labelled && typeof labelled.getAttribute === 'function') {
        const heading = document.getElementById(labelled.getAttribute('aria-labelledby'));
        if (heading) return heading;
    }
    const byId = fallbackId ? document.getElementById(fallbackId) : null;
    if (byId) return byId;
    const h1 = document.querySelector ? document.querySelector('h1.section-title') : null;
    return h1;
}

// The cross-document Inspect handoff: one opaque tunnel id, in a one-shot slot
// that only the backends page reads. The URL carries a random navigation identity,
// not the entity payload; a destination that never activates cannot leave an intent
// that an unrelated later bookmark consumes.
var VPN_BACKEND_HANDOFF_KEY = 'vpn.backend-inspect.tunnel';

function vpnStoreBackendHandoff(tunnelId) {
    try {
        if (typeof window === 'undefined' || !window.sessionStorage) return false;
        if (tunnelId === null || typeof tunnelId === 'undefined' || String(tunnelId) === '') return false;
        const nonce = Array.from(window.crypto.getRandomValues(new Uint8Array(16)), function (byte) {
            return byte.toString(16).padStart(2, '0');
        }).join('');
        window.sessionStorage.setItem(VPN_BACKEND_HANDOFF_KEY, JSON.stringify({ nonce: nonce, tunnelId: String(tunnelId) }));
        return nonce;
    } catch (_) {
        return false;
    }
}

function vpnConsumeBackendHandoff() {
    try {
        if (typeof window === 'undefined' || !window.sessionStorage) return null;
        const stored = window.sessionStorage.getItem(VPN_BACKEND_HANDOFF_KEY);
        window.sessionStorage.removeItem(VPN_BACKEND_HANDOFF_KEY);
        const hash = window.location.hash;
        const match = /^#vpn-inspect-([a-f0-9]{32})$/.exec(hash);
        if (match) {
            // Remove the navigation identity even on a refused/expired arrival. A
            // reload or saved bookmark must not become another Inspect request.
            window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search + '#backends');
        }
        if (!stored || !match) return null;
        const request = JSON.parse(stored);
        return request.nonce === match[1] && typeof request.tunnelId === 'string' ? request.tunnelId : null;
    } catch (_) {
        return null;
    }
}

// vpnOwnedAnchorId decodes the current fragment once. A malformed escape or an
// empty fragment yields null, and callers then do nothing at all.
function vpnOwnedAnchorId() {
    if (typeof window === 'undefined' || !window.location) return null;
    const raw = window.location.hash;
    if (!raw || raw.length < 2) return null;
    let id;
    try {
        id = decodeURIComponent(raw.slice(1));
    } catch (_) {
        return null;
    }
    if (!id || id.indexOf('#') !== -1) return null;
    if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(id)) return null;
    return id;
}

// vpnModuleRegistry names the modules that have been evaluated in this document.
// The page boot loads a section's controllers on demand and needs to know whether a
// module is already present - included eagerly by a shell, loaded earlier, or
// assembled by a test harness - so it does not fetch a second copy. Each module
// registers ITSELF here at load, so the answer cannot drift from what was actually
// evaluated: a name is present exactly when its file ran.
var VPN_REGISTERED_MODULES = {};

function vpnMarkModule(name) {
    if (!name) return;
    VPN_REGISTERED_MODULES[String(name)] = true;
}

function vpnModuleRegistered(name) {
    return !!name && VPN_REGISTERED_MODULES[String(name)] === true;
}

// vpnBindSharedActions binds the actions more than one section dispatches. It
// takes the DOCUMENT, not a section's content root: the control belongs to the page,
// and a binding that waited for a section's own root would fire twice when two
// sections share it. It binds at load rather than at readiness so the control works
// the moment the markup is parsed - a delegated listener on the document does not
// need the document to be finished.
function vpnBindSharedActions() {
    if (typeof document === 'undefined' || !document || document._vpnSharedBound) return false;
    if (typeof document.addEventListener !== 'function') return false;
    document._vpnSharedBound = true;
    document.addEventListener('click', function (event) {
        const btn = event.target && event.target.closest ? event.target.closest('[data-action="vpn-close-modal"]') : null;
        if (!btn) return;
        if (event && typeof event.preventDefault === 'function') event.preventDefault();
        const modalId = btn.dataset ? btn.dataset.modal : (btn.getAttribute ? btn.getAttribute('data-modal') : null);
        if (typeof closeModal === 'function') {
            closeModal(modalId);
        } else if (typeof UI !== 'undefined' && UI.modal && typeof UI.modal.close === 'function') {
            UI.modal.close(modalId);
        }
    });
    return true;
}

// Bind at load. A harness that assembles a document mock AFTER these modules
// declares it in the same scope has no document yet, and reading it there is a
// temporal-dead-zone error rather than a falsy check, so the attempt is guarded:
// the page boot binds again, and the binding is idempotent.
try {
    vpnBindSharedActions();
} catch (_) { /* the host provides no document yet; the boot binds later */ }

if (typeof window !== 'undefined') {
    window.vpnBindSharedActions = vpnBindSharedActions;
    window.vpnMarkModule = vpnMarkModule;
    window.vpnModuleRegistered = vpnModuleRegistered;
    window.vpnAssignText = vpnAssignText;
    window.vpnDiagText = vpnDiagText;
    window.vpnFormatApiError = vpnFormatApiError;
    window.vpnStatusBadgeClass = vpnStatusBadgeClass;
    window.vpnStatusLabel = vpnStatusLabel;
    window.vpnSetListenerBadge = vpnSetListenerBadge;
    window.vpnSignalMeasured = vpnSignalMeasured;
    window.vpnFormatHealthBps = vpnFormatHealthBps;
    window.vpnFormatHealthPps = vpnFormatHealthPps;
    window.vpnFormatHealthDuration = vpnFormatHealthDuration;
    window.vpnSetDiagnosticText = vpnSetDiagnosticText;
    window.vpnIsFocusable = vpnIsFocusable;
    window.vpnFocusIfFocusable = vpnFocusIfFocusable;
    window.vpnScrollToTarget = vpnScrollToTarget;
    window.vpnNearestHeading = vpnNearestHeading;
    window.vpnStoreBackendHandoff = vpnStoreBackendHandoff;
    window.vpnConsumeBackendHandoff = vpnConsumeBackendHandoff;
    window.vpnOwnedAnchorId = vpnOwnedAnchorId;
}
