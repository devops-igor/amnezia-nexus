// VPN Overview page controller: the four essential signals and the
// listener/public-endpoint configuration.
//
// This document owns exactly two reads — /api/vpn/status and /api/vpn/config —
// plus the endpoint write they feed. It loads none of the diagnostics, chart,
// session or backend-table controllers and prefetches none of their data, so a
// failure on another page cannot blank this one. The formatters and label
// helpers it shares with the other VPN documents come from common.js.

// vpnConfiguredPublicEndpoint holds the configured value (never the detected
// fallback), so the endpoint dialog starts from what the operator saved.
let vpnConfiguredPublicEndpoint = '';

// vpnSetSignalValue writes a measured value plus its unit, or the not-measured
// text. A measured zero renders as a number with its unit; an unmeasured value
// never becomes "0".
function vpnSetSignalValue(id, value, unit) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = '';
    // A null/undefined value is an ABSENT measurement, never a numeric zero.
    if (value === null || typeof value === 'undefined') {
        el.classList.add('vpn-not-measured');
        el.textContent = _('vpn_diag_not_measured');
        return;
    }
    el.classList.remove('vpn-not-measured');
    const valueSpan = document.createElement('span');
    valueSpan.className = 'font-mono';
    valueSpan.textContent = String(value);
    el.appendChild(valueSpan);
    if (unit) {
        const unitSpan = document.createElement('span');
        unitSpan.className = 'vpn-signal-unit';
        unitSpan.textContent = unit;
        const separator = document.createTextNode(' ');
        el.appendChild(separator);
        el.appendChild(unitSpan);
    }
}

function vpnSetSignalSub(id, text, isProblem) {
    const el = document.getElementById(id);
    if (!el) return;
    vpnAssignText(el, text || '');
    if (isProblem) {
        el.classList.add('vpn-signal-mismatch');
    } else {
        el.classList.remove('vpn-signal-mismatch');
    }
}

// vpnRenderSignals renders the four essential signals. Configured peers,
// synchronized peers and live sessions are separate facts: only the reported
// active-session count feeds the Sessions signal, and a route mismatch appears
// only when routing_consistency actually reports one.
function vpnRenderSignals(status) {
    const s = (status && typeof status === 'object') ? status : null;

    // Backends: disabled inventory is never counted as failed, and when
    // eligibility is unknown the enabled denominator is not invented.
    const be = (s && s.backends) || {};
    if (vpnSignalMeasured(be.healthy_count) && be.eligibility_known === true && vpnSignalMeasured(be.enabled_count)) {
        vpnSetSignalValue('vpn-signal-backends-value', be.healthy_count, '/ ' + be.enabled_count);
        vpnSetSignalSub('vpn-signal-backends-sub', _('vpn_signal_backends_enabled'), false);
    } else if (vpnSignalMeasured(be.healthy_count) && vpnSignalMeasured(be.total_count)) {
        vpnSetSignalValue('vpn-signal-backends-value', be.healthy_count, '/ ' + be.total_count);
        vpnSetSignalSub('vpn-signal-backends-sub', _('vpn_signal_backends_total'), false);
    } else {
        vpnSetSignalValue('vpn-signal-backends-value', null);
        vpnSetSignalSub('vpn-signal-backends-sub', _('vpn_diag_not_measured'), false);
    }

    // Sessions: the LIVE count only. connected_sessions is the reported live
    // session count; routing_consistency.active_sessions_count is the routing
    // view's count and is used only as a fallback when the live field is absent.
    // Configured peers and synchronized peers are never substituted here.
    const rcCounts = (s && s.routing_consistency) || {};
    const sessions = (s && vpnSignalMeasured(s.connected_sessions)) ? s.connected_sessions
        : (vpnSignalMeasured(rcCounts.active_sessions_count) ? rcCounts.active_sessions_count : null);
    const sessionsEl = document.getElementById('vpn-sessions');
    if (sessionsEl) {
        vpnAssignText(sessionsEl, sessions === null ? _('vpn_diag_not_measured') : String(sessions));
        if (sessions === null) {
            sessionsEl.classList.add('vpn-not-measured');
        } else {
            sessionsEl.classList.remove('vpn-not-measured');
        }
    }
    // A route mismatch is shown only when the payload reports one, never inferred
    // from count equality.
    const rc = (s && s.routing_consistency) || {};
    const withoutRoute = Array.isArray(rc.sessions_without_route) ? rc.sessions_without_route.length : 0;
    const mismatchEl = document.getElementById('vpn-session-mismatch');
    if (mismatchEl) {
        if (withoutRoute > 0) {
            mismatchEl.hidden = false;
            mismatchEl.textContent = vpnDiagText('vpn_signal_sessions_mismatch', { count: withoutRoute });
        } else {
            mismatchEl.hidden = true;
            mismatchEl.textContent = '';
        }
    }

    // Throughput: current rate, only when the rate payload says it is available.
    const rates = (s && s.rates) || {};
    const throughputTotalBps = (Number(rates.rx_bps) || 0) + (Number(rates.tx_bps) || 0);
    const throughputValue = (rates.available === true) ? vpnFormatHealthBps(throughputTotalBps) : null;
    const throughputEl = document.getElementById('vpn-signal-throughput-value');
    if (throughputEl) {
        throughputEl.textContent = '';
        if (throughputValue === null) {
            throughputEl.classList.add('vpn-not-measured');
            throughputEl.textContent = _('vpn_diag_not_measured');
        } else {
            throughputEl.classList.remove('vpn-not-measured');
            const parts = throughputValue.split(' ');
            const num = document.createElement('span');
            num.className = 'font-mono';
            num.textContent = parts[0];
            const unit = document.createElement('span');
            unit.className = 'vpn-signal-unit';
            unit.textContent = parts.slice(1).join(' ');
            throughputEl.appendChild(num);
            throughputEl.appendChild(document.createTextNode(' '));
            throughputEl.appendChild(unit);
        }
    }
    // The value cell already reads "Not measured" when the rate payload has no
    // sample, so the supporting line only states the horizon when there IS one.
    vpnSetSignalSub('vpn-signal-throughput-sub',
        throughputValue === null ? '' : _('vpn_signal_throughput_horizon'), false);

    // Dataplane drops: the CURRENT rate and the since-reset total are separate
    // facts with separate labels and units. Scoped to the dataplane, not
    // end-to-end packet loss.
    const dc = (s && s.drop_categories) || {};
    const dropRate = (dc.rates_available === true && vpnSignalMeasured(dc.total_drop_rate_pps)) ? dc.total_drop_rate_pps : null;
    const dropTotal = vpnSignalMeasured(dc.total_drops) ? dc.total_drops : null;
    vpnSetSignalValue('vpn-signal-drops-value', dropRate === null ? null : dropRate.toFixed(2), dropRate === null ? '' : _('vpn_unit_dps'));
    // The supporting line always states the dataplane scope, so the number cannot
    // be read as end-to-end packet loss, and always separates the cumulative
    // since-reset count from the current rate.
    const dropSubParts = [];
    if (dropTotal !== null) {
        dropSubParts.push(vpnDiagText('vpn_signal_drops_since_reset', { count: dropTotal }));
    }
    dropSubParts.push(_('vpn_dataplane_drops_scope'));
    vpnSetSignalSub('vpn-signal-drops-sub', dropSubParts.join(' \u00b7 '), false);
}

// vpnRenderConfiguration writes the listener badge, port, subnet and endpoint.
// The endpoint shows the CONFIGURED value when there is one; otherwise the
// auto-detected address is labelled as such, and a missing detection says so
// instead of rendering an empty line.
function vpnRenderConfiguration(status, cfg) {
    const config = (cfg && typeof cfg === 'object') ? cfg : {};
    vpnSetListenerBadge(!!(status && status.listener_running));

    vpnConfiguredPublicEndpoint = config.public_endpoint ? String(config.public_endpoint).trim() : '';
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
    const portEl = document.getElementById('vpn-listen-port');
    if (portEl) portEl.textContent = String(config.listen_port || '-');
    const subnetEl = document.getElementById('vpn-subnet');
    if (subnetEl) subnetEl.textContent = config.subnet_cidr || '-';
}

// vpnLoadOverview refreshes the overview only. A status failure renders the
// unavailable state; a config failure leaves the configuration rows at their
// last written values instead of blanking the page or failing the signals.
async function vpnLoadOverview() {
    let status = null;
    let cfg = {};
    try {
        status = await API.get('/api/vpn/status');
    } catch (_) {
        status = null;
    }
    try {
        cfg = (await API.get('/api/vpn/config')) || {};
    } catch (_) {
        cfg = {};
    }
    vpnRenderConfiguration(status, cfg);
    vpnRenderSignals(status);
    return status;
}

// ---- Endpoint dialog (this page owns it) ----

function vpnOpenEditEndpointModal() {
    const input = document.getElementById('vpnPublicEndpointInput');
    input.value = vpnConfiguredPublicEndpoint || '';
    const errBox = document.getElementById('vpnEndpointModalError');
    if (errBox) {
        errBox.style.display = 'none';
        errBox.textContent = '';
    }
    openModal('editEndpointModal');
}

async function vpnSubmitEditEndpoint() {
    const input = document.getElementById('vpnPublicEndpointInput');
    const newEndpoint = input.value.trim();
    const errBox = document.getElementById('vpnEndpointModalError');
    if (errBox) {
        errBox.style.display = 'none';
        errBox.textContent = '';
    }
    const submitBtn = document.getElementById('vpnEditEndpointSubmitBtn');
    submitBtn.disabled = true;

    try {
        await API.request('/api/vpn/config', {
            method: 'PUT',
            body: { public_endpoint: newEndpoint }
        });
        UI.toast(_('vpn_endpoint_updated_success'), 'success');
        closeModal('editEndpointModal');
        await vpnLoadOverview();
    } catch (err) {
        const errMsg = vpnFormatApiError(err);
        if (errBox) {
            errBox.textContent = errMsg;
            errBox.style.display = 'block';
        }
        UI.toast(errMsg, 'error');
    } finally {
        submitBtn.disabled = false;
    }
}

// ---- Delegation ----

const VPN_OVERVIEW_ACTIONS = {
    'vpn-open-edit-endpoint': function () {
        vpnOpenEditEndpointModal();
    },
    'vpn-close-modal': function (btn) {
        const modalId = btn.dataset ? btn.dataset.modal : (btn.getAttribute ? btn.getAttribute('data-modal') : null);
        if (typeof closeModal === 'function') {
            closeModal(modalId);
        } else if (typeof UI !== 'undefined' && UI.modal && typeof UI.modal.close === 'function') {
            UI.modal.close(modalId);
        }
    }
};

function initVpnOverviewListeners() {
    if (typeof document === 'undefined') return;
    const root = (typeof document.querySelector === 'function' && (document.querySelector('#vpn-app') || document.querySelector('main'))) || document.body;
    if (!root || root._vpnOverviewBound || typeof root.addEventListener !== 'function') return;
    root._vpnOverviewBound = true;

    root.addEventListener('click', function (e) {
        const btn = e.target && e.target.closest ? e.target.closest('[data-action]') : null;
        if (!btn) return;
        const action = btn.dataset ? btn.dataset.action : (btn.getAttribute ? btn.getAttribute('data-action') : null);
        if (!action || !Object.prototype.hasOwnProperty.call(VPN_OVERVIEW_ACTIONS, action)) return;
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
        VPN_OVERVIEW_ACTIONS[action](btn);
    });

    root.addEventListener('submit', function (e) {
        if (!e.target) return;
        const targetId = e.target.id || (e.target.closest ? (e.target.closest('form') || {}).id : null);
        if (targetId !== 'editEndpointForm') return;
        if (e && typeof e.preventDefault === 'function') e.preventDefault();
        vpnSubmitEditEndpoint();
    });
}

// ---- Anchor landing ----

// vpnLandOverviewAnchor reveals and focuses a fragment this page owns. It runs
// once after the first render: a later poll must not move focus under the
// operator. Configuration is revealed when the target is one of its fields, and
// a target that cannot take focus lands on its summary or the page heading.
function vpnLandOverviewAnchor() {
    const id = vpnOwnedAnchorId();
    if (!id) return null;
    const el = document.getElementById(id);
    if (!el) return null;
    const config = document.getElementById('vpn-configuration');
    if (config && config !== el && typeof config.contains === 'function' && config.contains(el)) {
        config.open = true;
    }
    const focusTarget = vpnIsFocusable(el) ? el : vpnNearestHeading(el, null);
    vpnScrollToTarget(el);
    vpnFocusIfFocusable(focusTarget);
    return id;
}

if (typeof document !== 'undefined') {
    initVpnOverviewListeners();
}

document.addEventListener('DOMContentLoaded', function () {
    initVpnOverviewListeners();

    // A recognised legacy fragment is already navigating to its owner; starting
    // the poll here would ask for Overview data the visitor never sees.
    if (window.vpnHandoffPending === true) return;

    if (typeof NexusTelemetry !== 'undefined' && typeof NexusTelemetry.poll === 'function') {
        NexusTelemetry.poll('vpn-overview', async function () {
            await vpnLoadOverview();
            // After the first tick only: a bare re-poll never re-jumps.
            if (!vpnOverviewAnchorLanded) {
                vpnOverviewAnchorLanded = true;
                vpnLandOverviewAnchor();
            }
        }, 5000);
    }
});

var vpnOverviewAnchorLanded = false;

if (typeof window !== 'undefined') {
    window.vpnLoadOverview = vpnLoadOverview;
    window.vpnRenderSignals = vpnRenderSignals;
    window.vpnRenderConfiguration = vpnRenderConfiguration;
    window.vpnSetSignalValue = vpnSetSignalValue;
    window.vpnSetSignalSub = vpnSetSignalSub;
    window.vpnOpenEditEndpointModal = vpnOpenEditEndpointModal;
    window.vpnSubmitEditEndpoint = vpnSubmitEditEndpoint;
    window.initVpnOverviewListeners = initVpnOverviewListeners;
    window.vpnLandOverviewAnchor = vpnLandOverviewAnchor;
    // Kept for callers that still name the whole-surface refresh. On this document
    // that refresh IS the overview.
    window.vpnLoadData = vpnLoadOverview;
}
