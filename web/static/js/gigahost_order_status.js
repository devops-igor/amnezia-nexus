/* Read-only Gigahost order status, and the single 30-second refresh that keeps
 * it current while the settings page is open.
 *
 * The status states what is confirmed, so this module reads status fields and
 * never derives VPS readiness from an assigned address: an order whose provider
 * still reports "deploying" stays in the deploying stage even after an address
 * appears. Three axes stay separate, because conflating them is how a previous
 * view could present a VPS as ready when only one provider read had answered:
 *
 *   provider  requested -> deploying -> ready, or failed / cancelled / unknown
 *   VPN setup none | scheduled | needs an operator | installing | ready | failed | revoked
 *   backend   none | unknown | pending | healthy | degraded | unhealthy | disabled
 *
 * Opening the details is a read-only disclosure. Every value in it comes from the
 * order record, the deploy status DTO, the saved setup approval or the backend
 * list, so opening it performs no request and cannot place an order, start setup
 * or cancel anything.
 */

// GIGAHOST_ORDER_STATUS_REFRESH_MS is the one refresh interval the status view owns.
const GIGAHOST_ORDER_STATUS_REFRESH_MS = 30000;

let gigahostOrderStatusRefreshTimer = null;
let gigahostOrderStatusRefreshTask = null;
let gigahostOrderStatusRefreshInFlight = false;
let gigahostOrderStatusRefreshGeneration = 0;
let gigahostOrderStatusLastSuccessAt = '';
let gigahostOrderStatusLifecycleBound = false;
let gigahostOrderStatusDetailsCounter = 0;
let gigahostOrderStatusBackendIndex = null;

/* gigahostOrderStatusBadgeClass maps a stage to the existing badge vocabulary. */
function gigahostOrderStatusBadgeClass(stage) {
    if (stage === 'ready') return 'badge-success';
    if (stage === 'failed' || stage === 'cancelled') return 'badge-danger';
    if (stage === 'deploying') return 'badge-info';
    return 'badge-secondary';
}

/* gigahostOrderStatusTime renders one timestamp as a time element. The machine
 * readable value is an attribute, so the local rendering never carries meaning of
 * its own and a test can assert an exact value. */
function gigahostOrderStatusTime(isoValue, absentKey) {
    const text = String(isoValue || '');
    const el = document.createElement('span');
    el.className = 'gigahost-order-status-time';
    if (!text) {
        el.textContent = _(absentKey);
        return el;
    }
    const stamp = document.createElement('time');
    stamp.setAttribute('datetime', text);
    const parsed = new Date(text);
    stamp.textContent = isNaN(parsed.getTime()) ? text : parsed.toLocaleString();
    el.appendChild(stamp);
    return el;
}

/* gigahostOrderStatusDetail puts one labelled fact in the panel. Every value is
 * written with textContent: a provider diagnostic is untrusted input and must not
 * become markup. */
function gigahostOrderStatusDetail(container, labelKey, valueNode) {
    const row = document.createElement('div');
    row.style.display = 'flex';
    row.style.justifyContent = 'space-between';
    row.style.gap = 'var(--space-sm)';
    row.style.padding = '2px 0';

    const label = document.createElement('span');
    label.style.color = 'var(--text-muted)';
    label.textContent = _(labelKey);
    row.appendChild(label);

    const value = document.createElement('span');
    value.style.textAlign = 'right';
    value.style.wordBreak = 'break-word';
    if (typeof valueNode === 'string') value.textContent = valueNode;
    else if (valueNode) value.appendChild(valueNode);
    row.appendChild(value);

    container.appendChild(row);
}

/* gigahostOrderStatusPanel builds the read-only details for one order. It reads
 * the model only and makes no request. */
function gigahostOrderStatusPanel(model) {
    const panel = document.createElement('div');
    panel.className = 'gigahost-order-status-details';
    panel.style.maxWidth = '340px';
    panel.style.fontSize = '0.78rem';
    panel.style.lineHeight = '1.45';

    const note = document.createElement('div');
    note.style.color = 'var(--text-muted)';
    note.style.marginBottom = '4px';
    note.textContent = _('gigahost_status_read_only');
    panel.appendChild(note);

    gigahostOrderStatusDetail(panel, 'gigahost_status_provider',
        _('gigahost_status_stage_' + model.stage) + (model.providerStatus ? ' (' + model.providerStatus + ')' : ''));
    gigahostOrderStatusDetail(panel, 'gigahost_status_vpn_setup', _('gigahost_status_setup_' + model.setup));
    gigahostOrderStatusDetail(panel, 'gigahost_status_backend_health', _('gigahost_status_health_' + model.health));
    gigahostOrderStatusAddressDetail(panel, model);
    gigahostOrderStatusDetail(panel, 'gigahost_status_last_check',
        gigahostOrderStatusTime(model.lastCheckedAt, 'gigahost_status_not_checked'));
    gigahostOrderStatusDetail(panel, 'gigahost_status_last_change',
        gigahostOrderStatusTime(model.lastChangeAt, 'gigahost_status_never'));

    gigahostOrderStatusStepDetail(panel, model);
    gigahostOrderStatusFailureDetail(panel, model);
    gigahostOrderStatusDetail(panel, 'gigahost_status_next_action', _(model.nextActionKey));
    return panel;
}

/* gigahostOrderStatusStepDetail shows the step in flight, from the deploy read when
 * it answered and from the saved approval otherwise. */
function gigahostOrderStatusStepDetail(panel, model) {
    const step = model.step || (model.setupIntent && model.setupIntent.step) || '';
    if (step) gigahostOrderStatusDetail(panel, 'gigahost_status_step', step);
}

/* gigahostOrderStatusFailureDetail shows the reported reason as text: a provider
 * diagnostic is untrusted input and must never become markup. */
function gigahostOrderStatusFailureDetail(panel, model) {
    const failure = model.failure || (model.setupIntent && model.setupIntent.last_error) || '';
    if (!failure) return;
    const node = document.createElement('span');
    node.style.color = 'var(--danger-color, #e53e3e)';
    node.textContent = failure;
    gigahostOrderStatusDetail(panel, 'gigahost_status_failure', node);
}

/* gigahostOrderStatusAddressDetail shows the address when there is one, and says
 * what it does and does not prove while the provider is still provisioning: an
 * address on an unready server is not a usable VPN endpoint. */
function gigahostOrderStatusAddressDetail(panel, model) {
    if (!model.assignedIP) return;
    gigahostOrderStatusDetail(panel, 'gigahost_status_address', model.assignedIP);
    // An address proves nothing about readiness when the provider state is unknown, so
    // the explanation is due in that case too, not only while actively deploying.
    if (!model.addressWhileProvisioning && !model.providerUnknown) return;
    const hint = document.createElement('div');
    hint.style.color = 'var(--text-muted)';
    hint.textContent = _('gigahost_status_ip_while_provisioning');
    panel.appendChild(hint);
}

/* gigahostOrderStatusCell builds one interactive status: a button carrying the
 * stage progression, plus a panel of read-only details.
 *
 * The button is a native button so it is reachable with Tab. Enter and Space are
 * handled here for two reasons: the disclosure then opens on the same press in
 * every browser, and it is assertable without a browser that synthesizes a click
 * for a key event. preventDefault stops a browser from delivering the activation
 * a second time as a click, so one press opens the panel once. */
function gigahostOrderStatusCell(order, context) {
    const model = gigahostOrderStatusModel(order, context);
    gigahostOrderStatusDetailsCounter += 1;
    const safeId = model.orderId.replace(/[^A-Za-z0-9_-]/g, '-');
    const detailsID = 'gigahost-order-status-' + gigahostOrderStatusDetailsCounter + '-' + (safeId || 'row');

    const wrapper = document.createElement('div');
    wrapper.className = 'gigahost-order-status';
    wrapper.setAttribute('data-stage', model.stage);
    if (model.orderId) wrapper.setAttribute('data-order-id', model.orderId);

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'badge gigahost-order-status-toggle ' + gigahostOrderStatusBadgeClass(model.stage);
    toggle.style.fontSize = '0.75rem';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-controls', detailsID);
    model.chain.forEach((entry, index) => {
        if (index > 0) toggle.appendChild(document.createTextNode(' \u2192 '));
        const part = document.createElement('span');
        part.className = 'gigahost-order-status-stage';
        part.setAttribute('data-stage', entry.stage);
        part.setAttribute('data-state', entry.state);
        part.textContent = _('gigahost_status_stage_' + entry.stage);
        toggle.appendChild(part);
    });

    const panel = gigahostOrderStatusPanel(model);
    panel.id = detailsID;
    panel.hidden = true;

    const setOpen = (open) => {
        panel.hidden = !open;
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    };
    toggle.addEventListener('click', () => setOpen(panel.hidden));
    toggle.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar') return;
        event.preventDefault();
        setOpen(panel.hidden);
    });

    wrapper.appendChild(toggle);
    wrapper.appendChild(panel);
    return wrapper;
}

/* gigahostOrderStatusLoaded records a provider read that actually succeeded. It is
 * the only place "last successful check" advances, so a panel read that returned
 * cached rows cannot certify a provider check nobody completed. */
function gigahostOrderStatusLoaded(container, checkedAt) {
    gigahostOrderStatusLastSuccessAt = String(checkedAt || '');
    if (!container) return;
    container.removeAttribute('data-stale');
    const stale = container.querySelector('#recentOrdersStale');
    if (stale) stale.remove();
}

/* gigahostOrderStatusProviderFailed marks the view stale without inventing a
 * result: the rows already on screen are kept and labelled, and the last successful
 * check keeps the time of the last read that genuinely answered. When nothing was
 * ever confirmed, the notice says so instead of borrowing a time. */
function gigahostOrderStatusProviderFailed(container, reason) {
    if (!container) return;
    container.setAttribute('data-stale', 'true');
    const existing = container.querySelector('#recentOrdersStale');
    if (existing) existing.remove();
    container.insertBefore(gigahostOrderStatusStaleNotice(reason), container.firstChild);
}

/* gigahostOrderStatusStaleNotice builds the explicit stale marker. The time it shows
 * is the last check that genuinely confirmed a provider state, and it says so when
 * there is none: an unconfirmed view must not display a time as if one had answered. */
function gigahostOrderStatusStaleNotice(reason) {
    const notice = document.createElement('div');
    notice.id = 'recentOrdersStale';
    notice.setAttribute('role', 'status');
    notice.style.padding = 'var(--space-sm) var(--space-md)';
    notice.style.marginBottom = 'var(--space-sm)';
    notice.style.borderRadius = 'var(--radius-sm)';
    notice.style.background = 'rgba(245, 158, 11, 0.12)';
    notice.style.border = '1px solid var(--warning, #f59e0b)';
    notice.style.fontSize = '0.8rem';
    notice.textContent = _('gigahost_status_stale');
    notice.appendChild(document.createTextNode(' '));
    notice.appendChild(gigahostOrderStatusTime(gigahostOrderStatusLastSuccessAt, 'gigahost_status_stale_never'));
    if (reason) {
        const detail = document.createElement('div');
        detail.style.marginTop = '2px';
        detail.style.fontSize = '0.75rem';
        // A provider diagnostic is untrusted input: text, never markup.
        detail.textContent = _('gigahost_status_provider_error') + ': ' + reason;
        notice.appendChild(detail);
    }
    return notice;
}

/* gigahostOrderStatusLoadFailed reports a read that failed.
 *
 * A failure never replaces what is on screen when the screen still shows orders
 * read earlier: those rows are kept and marked stale, so old data is labelled
 * rather than presented as current. When there is nothing earlier to keep, the
 * container says the status is unavailable - it does not say, and no terminal
 * stage is invented from, a read that never answered. */
function gigahostOrderStatusLoadFailed(container) {
    if (!container) return;
    container.setAttribute('data-stale', 'true');
    if (!container.querySelector('.gigahost-order-status')) {
        container.replaceChildren();
        const el = document.createElement('span');
        el.className = 'text-muted';
        el.textContent = _('gigahost_status_load_failed');
        container.appendChild(el);
        return;
    }
    if (!container.querySelector('#recentOrdersStale')) {
        container.insertBefore(gigahostOrderStatusStaleNotice(), container.firstChild);
    }
}

/* bindGigahostOrderStatusLifecycle stops the timer when the page goes away, so a
 * closed page leaves no timer behind. */
function bindGigahostOrderStatusLifecycle() {
    if (gigahostOrderStatusLifecycleBound || typeof window === 'undefined' || !window.addEventListener) return;
    window.addEventListener('pagehide', stopGigahostOrderStatusRefresh);
    window.addEventListener('beforeunload', stopGigahostOrderStatusRefresh);
    gigahostOrderStatusLifecycleBound = true;
}

function unbindGigahostOrderStatusLifecycle() {
    if (!gigahostOrderStatusLifecycleBound || typeof window === 'undefined' || !window.removeEventListener) return;
    window.removeEventListener('pagehide', stopGigahostOrderStatusRefresh);
    window.removeEventListener('beforeunload', stopGigahostOrderStatusRefresh);
    gigahostOrderStatusLifecycleBound = false;
}

function scheduleGigahostOrderStatusRefresh() {
    if (!gigahostOrderStatusRefreshTask) return;
    if (gigahostOrderStatusRefreshTimer !== null) clearTimeout(gigahostOrderStatusRefreshTimer);
    gigahostOrderStatusRefreshTimer = setTimeout(runGigahostOrderStatusRefresh, GIGAHOST_ORDER_STATUS_REFRESH_MS);
}

/* runGigahostOrderStatusRefresh runs one scheduled refresh. The next one is armed
 * only after this one settles, so two refreshes cannot overlap however slow a
 * request is, and at most one timer is ever pending.
 *
 * The generation token is what makes a restart safe: a refresh left over from a
 * stopped view resolves into a view that has moved on, and it must neither clear
 * the new view's in-flight flag nor re-arm its own timer. */
async function runGigahostOrderStatusRefresh() {
    gigahostOrderStatusRefreshTimer = null;
    const task = gigahostOrderStatusRefreshTask;
    const generation = gigahostOrderStatusRefreshGeneration;
    if (!task || gigahostOrderStatusRefreshInFlight) return;
    gigahostOrderStatusRefreshInFlight = true;
    try {
        await task();
    } catch (_) {
        // The task reports its own failure through gigahostOrderStatusLoadFailed.
    } finally {
        if (generation === gigahostOrderStatusRefreshGeneration) {
            gigahostOrderStatusRefreshInFlight = false;
            scheduleGigahostOrderStatusRefresh();
        }
    }
}

/* startGigahostOrderStatusRefresh arms the view's one refresh timer. Starting
 * again replaces the timer instead of adding a second one, so a second call site
 * cannot create duplicate polling. */
function startGigahostOrderStatusRefresh(task) {
    if (typeof task !== 'function') return false;
    stopGigahostOrderStatusRefresh();
    gigahostOrderStatusRefreshTask = task;
    bindGigahostOrderStatusLifecycle();
    scheduleGigahostOrderStatusRefresh();
    return true;
}

/* stopGigahostOrderStatusRefresh clears the timer and forgets the task. A request
 * already in flight cannot be cancelled from here, but it will not re-arm a timer:
 * the generation it holds is retired, and the task it would reschedule is gone.
 *
 * The in-flight flag is retired with it, so a view stopped and started again gets
 * its first refresh on schedule instead of having that tick swallowed by a request
 * nobody is waiting for any more. */
function stopGigahostOrderStatusRefresh() {
    gigahostOrderStatusRefreshGeneration += 1;
    if (gigahostOrderStatusRefreshTimer !== null) {
        clearTimeout(gigahostOrderStatusRefreshTimer);
        gigahostOrderStatusRefreshTimer = null;
    }
    gigahostOrderStatusRefreshTask = null;
    gigahostOrderStatusRefreshInFlight = false;
    unbindGigahostOrderStatusLifecycle();
}

/* gigahostOrderStatusRefreshState reports the timer the view owns, so a test can
 * assert there is exactly one and none after teardown. */
function gigahostOrderStatusRefreshState() {
    return {
        intervalMs: GIGAHOST_ORDER_STATUS_REFRESH_MS,
        scheduled: gigahostOrderStatusRefreshTimer !== null,
        inFlight: gigahostOrderStatusRefreshInFlight,
        running: typeof gigahostOrderStatusRefreshTask === 'function',
        lastSuccessAt: gigahostOrderStatusLastSuccessAt
    };
}

/* readGigahostSetupIntents reads the saved setup approvals, which are the only
 * record of a paused install or a trust pause. Returning null means the list could
 * not be read, so the setup axis is reported as unknown rather than as "none". */
async function readGigahostSetupIntents() {
    try {
        const res = await API.get('/api/admin/hosting/gigahost/setup-intents');
        const intents = (res && res.setup_intents) ? res.setup_intents : [];
        const index = {};
        intents.forEach((intent) => {
            if (intent && intent.order_id) index[String(intent.order_id)] = intent;
        });
        return index;
    } catch (_) {
        return null;
    }
}

/* refreshGigahostBackendHealth reads the panel's own backend records, which are the
 * only evidence of verified backend health.
 *
 * A failed read clears the index instead of reusing the last one: an unavailable
 * answer is not evidence that a backend is still healthy, and showing a previous
 * "healthy" for a state nobody could read would be exactly the invented result this
 * view must not present. Health then reads as unknown for that tick. */
async function refreshGigahostBackendHealth() {
    try {
        const res = await API.get('/api/vpn/backends');
        const backends = (res && res.backends) ? res.backends : [];
        const index = {};
        backends.forEach((backend) => {
            if (backend && backend.server_id) index[String(backend.server_id)] = backend;
        });
        gigahostOrderStatusBackendIndex = index;
    } catch (_) {
        gigahostOrderStatusBackendIndex = null;
    }
}

/* gigahostOrderStatusHealthFor returns the health context for one order. Backends
 * are keyed by the panel's own server id, so an order that registered no panel
 * server has no backend health to report yet. */
function gigahostOrderStatusHealthFor(order) {
    if (!gigahostOrderStatusBackendIndex) return {known: false, backend: null};
    const serverID = order && order.nexus_server_id ? String(order.nexus_server_id) : '';
    if (!serverID) return {known: true, backend: null};
    return {known: true, backend: gigahostOrderStatusBackendIndex[serverID] || null};
}

/* readGigahostOrderDeploy reads the deploy status DTO for one order, which carries
 * the step, the last provider diagnostic and the panel server the order registered.
 * A failure is reported as detailOK=false rather than thrown, so one unreadable
 * order does not discard the whole list. */
async function readGigahostOrderDeploy(orderId) {
    if (!orderId) return {deploy: null, detailOK: false};
    try {
        const res = await API.get('/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/status');
        const deploy = res && (res.deploy || res);
        return {deploy: deploy || null, detailOK: !!deploy};
    } catch (_) {
        return {deploy: null, detailOK: false};
    }
}

/* gigahostOrderStatusRow builds one recent order: identity, the interactive status
 * cell and the actions this state allows. The setup, retry and saved-approval
 * actions are the pre-existing ones, unchanged; the status cell replaced the raw
 * status label, which was neither interactive nor able to separate provider
 * readiness from setup and backend health. */
function gigahostOrderStatusRow(order, context) {
    const row = document.createElement('div');
    row.className = 'gigahost-order-row';
    row.style.display = 'flex';
    row.style.justifyContent = 'space-between';
    row.style.alignItems = 'center';
    row.style.padding = '6px 0';
    row.style.borderBottom = '1px solid rgba(255,255,255,0.05)';

    const left = document.createElement('div');
    const idSpan = document.createElement('span');
    idSpan.style.fontFamily = 'monospace';
    idSpan.style.fontWeight = '600';
    idSpan.textContent = '#' + (order.order_id || '');
    left.appendChild(idSpan);

    if (order.assigned_ip) {
        const ipSpan = document.createElement('span');
        ipSpan.style.fontFamily = 'monospace';
        ipSpan.style.marginLeft = '6px';
        ipSpan.style.color = 'var(--text-secondary)';
        ipSpan.textContent = order.assigned_ip;
        left.appendChild(ipSpan);
    }

    const right = document.createElement('div');
    right.style.display = 'flex';
    right.style.alignItems = 'center';
    right.style.gap = '6px';
    right.appendChild(gigahostOrderStatusCell(order, context));

    if (order.status === 'failed') {
        const btnRetry = document.createElement('button');
        btnRetry.type = 'button';
        btnRetry.className = 'btn btn-secondary gigahost-order-action';
        btnRetry.style.padding = '2px 8px';
        btnRetry.style.fontSize = '0.75rem';
        btnRetry.textContent = _('deploy_retry_btn') || 'Retry';
        btnRetry.addEventListener('click', () => triggerGigahostSetup(order.order_id));
        right.appendChild(btnRetry);
    } else if (!order.nexus_onboarded) {
        // The immediate path needs an address to reach right now; the saved path
        // does not, because the panel keeps working after this browser closes and
        // discovers the address when the provider assigns it.
        if (order.assigned_ip) {
            const btnSetup = document.createElement('button');
            btnSetup.type = 'button';
            btnSetup.className = 'btn btn-primary gigahost-order-action';
            btnSetup.style.padding = '2px 8px';
            btnSetup.style.fontSize = '0.75rem';
            btnSetup.textContent = _('deploy_setup_btn') || 'Setup Backend';
            btnSetup.addEventListener('click', () => triggerGigahostSetup(order.order_id));
            right.appendChild(btnSetup);
        }
        appendSetupApprovalAction(right, order.order_id);
    }

    row.appendChild(left);
    row.appendChild(right);
    return row;
}

/* mergeGigahostOrderDetail copies the deploy detail onto the order row exactly as
 * the pre-existing view did: the step, the provider diagnostic and the panel
 * server id feed the status axes, and a failed provider answer makes the row
 * failed. onboarding is recorded separately, so a provider-ready VPS that the
 * panel has not onboarded is not presented as a finished backend. */
function mergeGigahostOrderDetail(order, deploy) {
    const merged = Object.assign({}, order);
    if (deploy) {
        if (deploy.step) merged.step = deploy.step;
        if (deploy.error) merged.last_error = deploy.error;
        if (deploy.server_id) merged.nexus_server_id = deploy.server_id;
        if (deploy.status === 'failed') merged.status = 'failed';
        else if (deploy.status === 'ready' && deploy.server_id > 0) merged.nexus_onboarded = true;
    }
    return merged;
}

/* loadRecentOrders reads the recent orders once and renders their status.
 *
 * One tick reads the order list (the server refreshes it from the provider and says,
 * per order, what the provider actually answered), the saved setup approvals and the
 * panel's backend records, then the per-order deploy detail as onboarding-journal
 * evidence. Only a response in which the provider actually answered counts as a
 * successful check: a 200 carrying cached rows is a read of the panel, not of the
 * provider, and it must not advance the last successful check or clear a stale
 * notice. Nothing here writes: no order is placed, no setup is started and no
 * approval is touched. */
async function loadRecentOrders() {
    const container = document.getElementById('recentOrdersContainer');
    if (!container) return;

    const read = await gigahostOrderStatusReadOnce();
    if (!read.ok) {
        gigahostOrderStatusLoadFailed(container);
        return;
    }

    const {merged, details, setupIndex, observations, checkedAt} = read;
    const freshness = gigahostOrderStatusFreshness(container, merged, observations, checkedAt);
    if (freshness.providerFailed && merged.length > 0) {
        gigahostOrderStatusProviderFailed(container, freshness.reason);
    }

    if (merged.length === 0) {
        gigahostOrderStatusRenderEmpty(container, freshness);
        return;
    }
    gigahostOrderStatusRenderList(container, merged, details, setupIndex, observations, checkedAt);
}

/* gigahostOrderStatusReadOnce performs one tick's reads and reports them as data.
 *
 * Only the order list can fail the tick: it is the read that decides whether anything
 * is known at all. The approval list, the backend records and the per-order detail each
 * carry their own explicit unknown, so a partial failure there cannot become a claim
 * about readiness. A null setupIndex means the approval list was unreadable. */
async function gigahostOrderStatusReadOnce() {
    let orders;
    let observations;
    try {
        const res = await API.get('/api/admin/hosting/gigahost/orders');
        orders = (res && res.orders) ? res.orders : [];
        observations = (res && res.provider_observations) ? res.provider_observations : {};
    } catch (_) {
        return {ok: false};
    }

    const checkedAt = gigahostOrderStatusNow().toISOString();
    const setupIndex = await readGigahostSetupIntents();
    await refreshGigahostBackendHealth();
    const details = await Promise.all(orders.map((order) => readGigahostOrderDeploy(order && order.order_id)));
    const merged = orders.map((order, index) => mergeGigahostOrderDetail(order, (details[index] || {}).deploy));
    return {ok: true, merged: merged, details: details, setupIndex: setupIndex, observations: observations, checkedAt: checkedAt};
}

/* gigahostOrderStatusRenderList renders the first five orders and keeps any stale
 * notice above them, so a stale label survives a rerender of the same rows. */
function gigahostOrderStatusRenderList(container, merged, details, setupIndex, observations, checkedAt) {
    const list = document.createElement('div');
    list.style.display = 'flex';
    list.style.flexDirection = 'column';
    list.style.gap = '6px';
    merged.slice(0, 5).forEach((order, index) => {
        list.appendChild(gigahostOrderStatusRow(order,
            gigahostOrderStatusContext(order, details[index], setupIndex, checkedAt, observations)));
    });
    const stale = container.querySelector('#recentOrdersStale');
    container.replaceChildren(list);
    if (stale) container.insertBefore(stale, container.firstChild);
}

/* gigahostOrderStatusFreshness decides what this tick established about the provider,
 * and records the last successful check only when one actually happened.
 *
 * A 200 carrying cached rows is a read of the panel, not of the provider, so it can
 * neither advance the last successful check nor clear a stale notice. Only an
 * observation that says the provider answered may do that. */
function gigahostOrderStatusFreshness(container, merged, observations, checkedAt) {
    const reads = observations || {};
    const outcomes = merged.map((order) =>
        gigahostOrderStatusObservation(reads[String(order.order_id || '')]));
    const failures = outcomes.filter((obs) => obs.outcome === 'unavailable');
    const confirmed = outcomes.some((obs) => obs.outcome === 'confirmed');

    if (confirmed) {
        gigahostOrderStatusLoaded(container, checkedAt);
        return {confirmed: true, providerFailed: false, reason: ''};
    }
    if (failures.length > 0) {
        return {confirmed: false, providerFailed: true, reason: failures[0].error};
    }
    // No read was attempted for anything on screen (an all-terminal list). That is not
    // a failure, and it is not a confirmation either: nothing is advanced.
    return {confirmed: false, providerFailed: false, reason: ''};
}

/* gigahostOrderStatusRenderEmpty renders a list with no orders.
 *
 * "No orders have been placed" is a statement about the provider's answer, so it is
 * only made when a provider read confirmed it. An empty list whose provider read failed
 * is an unreachable panel read, and saying "no orders" there would invent a history. */
function gigahostOrderStatusRenderEmpty(container, freshness) {
    const empty = document.createElement('span');
    empty.className = 'text-muted';
    empty.textContent = freshness.providerFailed
        ? _('gigahost_status_load_failed')
        : _('gigahost_status_empty');
    container.replaceChildren(empty);
    if (!freshness.providerFailed) return;
    container.setAttribute('data-stale', 'true');
    container.insertBefore(gigahostOrderStatusStaleNotice(freshness.reason), container.firstChild);
}

/* gigahostOrderStatusContext assembles the context one row classifies, from the reads
 * this tick already performed. setupIndex of null means the approval list could not be
 * read, which is reported as an unknown setup axis rather than "none"; the deploy DTO
 * supplies the onboarding-journal evidence the immediate setup path writes. */
function gigahostOrderStatusContext(order, detail, setupIndex, checkedAt, observations) {
    const deploy = detail || {};
    const orderId = String(order.order_id || '');
    const setupKnown = setupIndex !== null;
    const reads = observations || {};
    return {
        deploy: deploy.deploy || null,
        detailOK: deploy.detailOK === true,
        checkedAt: checkedAt,
        observation: reads[orderId] || null,
        setup: {
            known: setupKnown,
            intent: setupKnown ? setupIndex[orderId] || null : null,
            journal: gigahostOrderStatusJournalEvidence(deploy.deploy)
        },
        health: gigahostOrderStatusHealthFor(order)
    };
}

