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
// gigahostOrderStatusConfirmedAt remembers, per order, the last time the provider actually
// confirmed that order. It is the view's own record of observed truth, so a failed or absent
// read can never overwrite it and cannot lend another order's success to this row.
let gigahostOrderStatusConfirmedAt = {};
// gigahostOrderStatusCurrentRead is the one running full read ({token, controller, retired}).
// It is cleared only when that chain actually settles, so its presence means "a full read is
// live" and never "a read was asked to stop".
let gigahostOrderStatusCurrentRead = null;
// gigahostOrderStatusPendingFollowUp records that a caller asked for a read while one was
// running. It is coalesced: many clicks produce one follow-up after settlement.
let gigahostOrderStatusPendingFollowUp = false;
let gigahostOrderStatusReadSequence = 0;
// gigahostOrderStatusSettledReads counts full read chains that ran to completion. It is the
// lifetime fact a caller (and a test) needs to distinguish "the chain finished" from "the chain
// was asked to abort": only this counter may be used to decide that a new read may begin.
let gigahostOrderStatusSettledReads = 0;
// gigahostOrderStatusOverlapDetected counts admissions that happened while a previous chain was
// still running. It must remain 0: it is the direct measurement of the original requirement,
// taken at admission rather than inferred from abort notifications or from test timing.
let gigahostOrderStatusOverlapDetected = 0;

/* gigahostOrderStatusBadgeClass maps a stage to the existing badge vocabulary. */
function gigahostOrderStatusBadgeClass(stage) {
    if (stage === 'ready') return 'badge-success';
    // A deleted deployment is as unusable as a failed or cancelled one, so it wears the
    // same danger badge rather than a treatment of its own.
    if (stage === 'failed' || stage === 'cancelled' || stage === 'deleted') return 'badge-danger';
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


/* gigahostOrderStatusCell builds one interactive status: a button carrying the
 * stage progression, plus a panel of read-only details.
 *
 * The button is a native button so it is reachable with Tab. Enter and Space are
 * handled here for two reasons: the disclosure then opens on the same press in
 * every browser, and it is assertable without a browser that synthesizes a click
 * for a key event. preventDefault stops a browser from delivering the activation
 * a second time as a click, so one press opens the panel once. */
function gigahostOrderStatusCell(order, context, classification) {
    const model = classification || gigahostOrderStatusModel(order, context);
    gigahostOrderStatusDetailsCounter += 1;
    const safeId = model.orderId.replace(/[^A-Za-z0-9_-]/g, '-');
    const detailsID = 'gigahost-order-status-' + gigahostOrderStatusDetailsCounter + '-' + (safeId || 'row');

    const wrapper = document.createElement('div');
    wrapper.className = 'gigahost-order-status';
    wrapper.setAttribute('data-stage', model.stage);
    if (model.orderId) wrapper.setAttribute('data-order-id', model.orderId);
    // A row whose provider read failed is stale in its own right. Marking the row (not only
    // the view) is what keeps the failure visible when a different order in the same response
    // succeeded, which is the case an aggregate banner cannot express.
    if (model.providerReadFailed) wrapper.setAttribute('data-stale', 'true');

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'badge gigahost-order-status-toggle ' + gigahostOrderStatusBadgeClass(model.stage);
    // The state is carried on the badge itself, not only on its wrapper, because the
    // ink is the badge's: the shared danger ink does not clear 4.5:1 on the danger fill
    // it is painted on at the 12 px this label sets, so the state decides the colour.
    toggle.setAttribute('data-stage', model.stage);
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-controls', detailsID);
    model.chain.forEach((entry, index) => {
        if (index > 0) toggle.appendChild(document.createTextNode(' \u2192 '));
        const part = document.createElement('span');
        part.className = 'gigahost-order-status-stage';
        part.setAttribute('data-stage', entry.stage);
        part.setAttribute('data-state', entry.state);
        // Bold and underline are visual only: they cannot tell a screen reader which
        // step is in flight, and every row's collapsed name was otherwise the same
        // three words. The state is exposed here, in the accessibility tree, and the
        // button's name below says it in words.
        if (entry.state === 'current') part.setAttribute('aria-current', 'step');
        part.textContent = _('gigahost_status_stage_' + entry.stage);
        toggle.appendChild(part);
    });
    // The name carries the visible progression followed by the step in flight, so the
    // visible text is still part of the name (label-in-name) and the current step is
    // announced. No second visible label is added. A terminal stage has no step in
    // flight to announce: saying so would claim progress on an ended attempt.
    if (gigahostOrderStatusStageInFlight(model.stage) &&
        model.chain.some((entry) => entry.state === 'current')) {
        toggle.setAttribute('aria-label', toggle.textContent + '. ' +
            _('gigahost_status_current_step') + ': ' + _('gigahost_status_stage_' + model.stage));
    }

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
function gigahostOrderStatusProviderFailed(container, reason, failures) {
    if (!container) return;
    container.setAttribute('data-stale', 'true');
    const existing = container.querySelector('#recentOrdersStale');
    if (existing) existing.remove();
    container.insertBefore(gigahostOrderStatusStaleNotice(reason, failures), container.firstChild);
}

/* gigahostOrderStatusStaleNotice builds the explicit stale marker. The time it shows
 * is the last check that genuinely confirmed a provider state, and it says so when
 * there is none: an unconfirmed view must not display a time as if one had answered. */
function gigahostOrderStatusStaleNotice(reason, failures) {
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
    // Every failed order is named with its own diagnostic, so a mixed response cannot show
    // one headline reason that belongs to a different row. A diagnostic is untrusted input:
    // text, never markup.
    const named = (failures || []).filter((entry) => entry && entry.orderId);
    if (named.length > 0) {
        named.forEach((entry) => {
            const detail = document.createElement('div');
            detail.style.marginTop = '2px';
            detail.style.fontSize = '0.75rem';
            detail.setAttribute('data-failed-order', entry.orderId);
            const who = document.createElement('span');
            who.style.fontFamily = 'monospace';
            who.textContent = '#' + entry.orderId + ' ';
            detail.appendChild(who);
            detail.appendChild(document.createTextNode(
                _('gigahost_status_provider_error') + ': ' + String(entry.error || '')));
            notice.appendChild(detail);
        });
        return notice;
    }
    if (reason) {
        const detail = document.createElement('div');
        detail.style.marginTop = '2px';
        detail.style.fontSize = '0.75rem';
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

/* gigahostOrderStatusRead is the one entry point into a full status read, and it enforces two
 * separate invariants at once:
 *
 *   lifetime  at most one full read chain (list, intents, backends, per-order details) is
 *             running at any moment. A full read is only started when the previous chain has
 *             truly settled — not when it is asked to abort. This is the original
 *             "no overlapping refresh" requirement.
 *
 *   ownership only the current read may commit. A read that was retired cannot write the DOM,
 *             the backend index, the freshness/stale state or the last-success time, even if
 *             it keeps running to completion.
 *
 * A caller arriving while a read is running is therefore not dropped and not allowed to start
 * a second read: it records one coalesced follow-up that starts after the running chain
 * settles. That is what makes an operator's click during a slow refresh produce a current
 * answer instead of nothing, without ever overlapping. This resolves the earlier conflict in
 * which either the click was lost or two reads ran at once.
 *
 * The scheduled tick does not queue a follow-up at all: it defers, because polling has another
 * tick in 30 seconds and must never stack work behind a user's read.
 *
 * Nothing here writes to the panel: no order is placed, no setup is started and no approval is
 * touched. */
async function loadRecentOrders(options) {
    const container = document.getElementById('recentOrdersContainer');
    if (!container) return;
    await gigahostOrderStatusRead(container, options);
}

async function gigahostOrderStatusRead(container, options) {
    const settings = options || {};
    const supersede = settings.supersede !== false;

    if (gigahostOrderStatusCurrentRead) {
        if (!supersede) return false;
        // A full read is running. Request exactly one follow-up; it starts when this chain
        // settles, so the two never overlap.
        gigahostOrderStatusPendingFollowUp = true;
        return false;
    }

    if (gigahostOrderStatusCurrentRead) gigahostOrderStatusOverlapDetected += 1;
    const read = {
        token: gigahostOrderStatusReadSequence += 1,
        controller: gigahostOrderStatusNewAbortController()
    };
    gigahostOrderStatusCurrentRead = read;
    try {
        const outcome = await gigahostOrderStatusAwaitRead(read);
        if (!gigahostOrderStatusIsCurrentRead(read)) return false;
        gigahostOrderStatusCommitRead(container, outcome);
        return true;
    } finally {
        // The chain has genuinely settled here, which is the only moment a new full read may
        // begin. Abort only asks; this is where the lifetime actually ends.
        if (gigahostOrderStatusCurrentRead === read) gigahostOrderStatusCurrentRead = null;
        gigahostOrderStatusSettledReads += 1;
        gigahostOrderStatusStartPendingFollowUp(container);
    }
}

/* gigahostOrderStatusStartPendingFollowUp starts the coalesced follow-up, if one was requested
 * while a read was running. It is called from the settled read's finally, so it can never
 * overlap the chain that just finished. */
function gigahostOrderStatusStartPendingFollowUp(container) {
    if (!gigahostOrderStatusPendingFollowUp) return;
    gigahostOrderStatusPendingFollowUp = false;
    if (!container) return;
    // Supersede is irrelevant when nothing is running; the call simply starts the read.
    gigahostOrderStatusRead(container, {supersede: true});
}

/* runGigahostOrderStatusRefresh runs one scheduled refresh. A tick that finds a read
 * already outstanding skips rather than superseding it, and the next tick is armed
 * only after this one settles, so scheduled polling never overlaps and never abandons
 * a read an operator asked for.
 *
 * The generation token retires a refresh belonging to a stopped view: it must neither
 * clear the new view's in-flight flag nor re-arm its own timer. */
async function runGigahostOrderStatusRefresh() {
    gigahostOrderStatusRefreshTimer = null;
    const generation = gigahostOrderStatusRefreshGeneration;
    const task = gigahostOrderStatusRefreshTask;
    if (!task) return;
    if (gigahostOrderStatusCurrentRead) {
        // Skipped, not superseded: the outstanding read keeps its ownership.
        scheduleGigahostOrderStatusRefresh();
        return;
    }
    gigahostOrderStatusRefreshInFlight = true;
    try {
        // The registered task is the scheduled read; it is told not to supersede, because
        // polling must never cut a user-initiated read short.
        await task({supersede: false});
    } catch (_) {
        // The task reports its own failure through gigahostOrderStatusLoadFailed.
    } finally {
        if (generation === gigahostOrderStatusRefreshGeneration && gigahostOrderStatusRefreshTask === task) {
            gigahostOrderStatusRefreshInFlight = false;
        }
        if (generation === gigahostOrderStatusRefreshGeneration) {
            scheduleGigahostOrderStatusRefresh();
        }
    }
}

/* startGigahostOrderStatusRefresh arms the view's one refresh timer. Starting again
 * replaces the timer instead of adding a second one, so a second call site cannot create
 * duplicate polling.
 *
 * Two different owners live here and they are retired by different things:
 *
 *   - the *scheduled run* (this timer's own work, tracked by the in-flight flag). Re-arming
 *     retires it: the run belongs to the schedule that is being replaced, and its finally
 *     must not re-arm a timer behind the new one. This is why a restart always gets its own
 *     first tick.
 *   - the *loader's read* (gigahostOrderStatusCurrentRead). Re-arming leaves it alone,
 *     because the manual Refresh control calls the loader and then restarts the timer in
 *     the same handler; that read must keep ownership and commit its answer. Only stop()
 *     and page teardown retire a read. */
function startGigahostOrderStatusRefresh(task) {
    if (typeof task !== 'function') return false;
    gigahostOrderStatusRefreshGeneration += 1;
    if (gigahostOrderStatusRefreshTimer !== null) {
        clearTimeout(gigahostOrderStatusRefreshTimer);
        gigahostOrderStatusRefreshTimer = null;
    }
    gigahostOrderStatusRefreshTask = task;
    gigahostOrderStatusRefreshInFlight = false;
    bindGigahostOrderStatusLifecycle();
    scheduleGigahostOrderStatusRefresh();
    return true;
}

/* stopGigahostOrderStatusRefresh clears the timer and forgets the task, and retires any
 * read still outstanding so it cannot commit into a view that no longer exists.
 *
 * The generation it holds is retired, so the read will not re-arm a timer either. The
 * in-flight flag is retired with it, so a view stopped and started again gets its first
 * refresh on schedule instead of having that tick swallowed by a read nobody waits for. */
function stopGigahostOrderStatusRefresh() {
    gigahostOrderStatusRefreshGeneration += 1;
    if (gigahostOrderStatusRefreshTimer !== null) {
        clearTimeout(gigahostOrderStatusRefreshTimer);
        gigahostOrderStatusRefreshTimer = null;
    }
    gigahostOrderStatusRefreshTask = null;
    gigahostOrderStatusRefreshInFlight = false;
    gigahostOrderStatusRetireCurrentRead();
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
        // reading reports that a full read chain is actually live, whatever started it;
        // inFlight only describes the timer's scheduled work. followUp reports a queued
        // coalesced read that will start once the live chain settles.
        reading: gigahostOrderStatusCurrentRead !== null,
        followUp: gigahostOrderStatusPendingFollowUp,
        reads: gigahostOrderStatusReadSequence,
        // settledReads counts chains that finished; reads counts chains that started. A new
        // full read is admitted only when these are equal.
        settledReads: gigahostOrderStatusSettledReads,
        overlapDetected: gigahostOrderStatusOverlapDetected,
        lastSuccessAt: gigahostOrderStatusLastSuccessAt
    };
}

/* readGigahostSetupIntents reads the saved setup approvals, which are the only
 * record of a paused install or a trust pause. Returning null means the list could
 * not be read, so the setup axis is reported as unknown rather than as "none". */
async function readGigahostSetupIntents(signal) {
    try {
        const res = await API.get('/api/admin/hosting/gigahost/setup-intents', {signal: signal, silent: true});
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

/* readGigahostBackendIndex reads the panel's own backend records, which are the only
 * evidence of verified backend health, and returns them keyed by panel server id.
 *
 * A failed read returns null instead of reusing the last index: an unavailable answer is
 * not evidence that a backend is still healthy, and showing a previous "healthy" for a
 * state nobody could read would be exactly the invented result this view must not
 * present. Health then reads as unknown for that read.
 *
 * Returning the index rather than assigning it is what keeps a retired read harmless: the
 * index is applied by the caller that still owns the view. */
async function readGigahostBackendIndex(signal) {
    try {
        const res = await API.get('/api/vpn/backends', {signal: signal, silent: true});
        const backends = (res && res.backends) ? res.backends : [];
        const index = {};
        backends.forEach((backend) => {
            if (backend && backend.server_id) index[String(backend.server_id)] = backend;
        });
        return index;
    } catch (_) {
        return null;
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
async function readGigahostOrderDeploy(orderId, signal) {
    if (!orderId) return {deploy: null, detailOK: false};
    try {
        const res = await API.get('/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/status', {signal: signal, silent: true});
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
 * readiness from setup and backend health.
 *
 * `classification` is optional: the list already classifies every row to decide which
 * of them it renders, so passing that decision in keeps the row from classifying the
 * same order a second time - and keeps the surface and its affordances on one model. */
function gigahostOrderStatusRow(order, context, classification) {
    const row = document.createElement('div');
    // Layout is owned by settings.css (.gigahost-order-row and its two sides), so the
    // row wraps instead of widening the card. Markup here only decides what the row says.
    row.className = 'gigahost-order-row';

    const left = document.createElement('div');
    left.className = 'gigahost-order-identity';
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
    right.className = 'gigahost-order-state';
    // One classification decides both what the row says and what it offers, so the
    // status cell and the action area can never disagree about the same order.
    const model = classification || gigahostOrderStatusModel(order, context);
    right.appendChild(gigahostOrderStatusCell(order, context, model));

    // A deployment that reads as deleted gets no action, whichever fact produced that
    // state: the provider's own `deleted` answer, or the panel's durable inventory
    // mark. Both are combined into the stage already, so the affordances read that one
    // decision rather than either input. Every action here - retry, immediate setup, a
    // saved approval - ends in a connection to the deployment's address.
    //
    // A cancelled order is deliberately not in this class: cancellation stops the order
    // while its VPS may still be running, which is why it keeps its actions.
    if (model.stage === 'deleted') {
        row.appendChild(left);
        row.appendChild(right);
        return row;
    }

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
function mergeGigahostOrderDetail(order, deploy, listedAbsence) {
    const merged = Object.assign({}, order);
    // The list's own durable record of absence. Applied on its own, because the deploy
    // read below is a second request that can fail without undoing it.
    if (listedAbsence === true) merged.provider_absent = true;
    if (deploy) {
        if (deploy.step) merged.step = deploy.step;
        if (deploy.error) merged.last_error = deploy.error;
        if (deploy.server_id) merged.nexus_server_id = deploy.server_id;
        // The deploy read is the second place this view is told that the provider's own
        // server inventory no longer lists the server this order registered. Only a
        // true value is carried: an order the panel has no such record for keeps the
        // ordinary treatment rather than reading a missing field as agreement.
        if (deploy.provider_absent === true) merged.provider_absent = true;
        if (deploy.status === 'failed') merged.status = 'failed';
        else if (gigahostOrderStatusRecordedOnboarding(deploy)) merged.nexus_onboarded = true;
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
/* gigahostOrderStatusRead performs one status read under the view's admission rule and
 * commits its result only if it is still the authoritative read.
 *
 * A read is registered before it awaits anything, so a second caller can see it. When
 * `supersede` is set (every user-initiated and post-action caller) the outstanding read
 * is retired and aborted first; the timer calls with `supersede: false` and never gets
 * here while a read exists, because it skips instead.
 *
 * The token check before each write is what makes a retired read harmless: it may still
 * be resolving in the background, but it cannot touch the DOM, the last-success/stale
 * state or the backend index once it is no longer current. The backend index is
 * deliberately returned by the reader rather than written as a side effect, so a retired
 * read has nothing to overwrite. */
/* gigahostOrderStatusAwaitRead runs the requests and never throws: a failed read is an
 * outcome, because "could not read" is a state the view has to show rather than an error
 * to propagate into a timer tick. */
async function gigahostOrderStatusAwaitRead(read) {
    try {
        return await gigahostOrderStatusReadOnce(read.controller ? read.controller.signal : undefined);
    } catch (_) {
        return {ok: false};
    }
}

/* gigahostOrderStatusCommitRead applies one claimed read's result to the view. The caller
 * has already established that this read still owns it. */
function gigahostOrderStatusCommitRead(container, outcome) {
    if (!outcome || !outcome.ok) {
        gigahostOrderStatusLoadFailed(container);
        return;
    }

    const {merged, details, setupIndex, observations, checkedAt, backendIndex} = outcome;
    gigahostOrderStatusBackendIndex = backendIndex;

    const freshness = gigahostOrderStatusFreshness(container, merged, observations, checkedAt);
    if (freshness.providerFailed && merged.length > 0) {
        gigahostOrderStatusProviderFailed(container, freshness.reason, freshness.failures);
    }

    if (merged.length === 0) {
        gigahostOrderStatusRenderEmpty(container, freshness);
        return;
    }
    gigahostOrderStatusRenderList(container, merged, details, setupIndex, observations, checkedAt);
}

/* gigahostOrderStatusIsCurrentRead reports whether this read still owns the view. A read
 * retired by a newer one, by an explicit stop or by page teardown is not current. */
function gigahostOrderStatusIsCurrentRead(read) {
    return !!read && gigahostOrderStatusCurrentRead === read && !read.retired;
}

/* gigahostOrderStatusRetireCurrentRead retires and aborts the outstanding read, if any, and
 * drops any follow-up it had queued.
 *
 * Retiring is what stops it writing; aborting is what asks it to stop running. Neither ends
 * the read's lifetime — the chain ends when its own await settles, and only then may another
 * full read begin. Dropping the follow-up is what keeps a stopped view from resurrecting
 * itself one tick later. */
function gigahostOrderStatusRetireCurrentRead() {
    const read = gigahostOrderStatusCurrentRead;
    gigahostOrderStatusPendingFollowUp = false;
    if (!read) return;
    read.retired = true;
    if (read.controller && typeof read.controller.abort === 'function') {
        read.controller.abort();
    }
}

/* gigahostOrderStatusNewAbortController returns an abort controller when the environment
 * provides one, and null otherwise. Node and every supported browser do. */
function gigahostOrderStatusNewAbortController() {
    if (typeof AbortController === 'function') return new AbortController();
    if (typeof window !== 'undefined' && typeof window.AbortController === 'function') return new window.AbortController();
    return null;
}

/* gigahostOrderStatusReadOnce performs one read's requests and reports them as data.
 *
 * Only the order list can fail the read: it is the request that decides whether
 * anything is known at all. The approval list, the backend records and the per-order
 * detail each carry their own explicit unknown, so a partial failure there cannot
 * become a claim about readiness. A null setupIndex means the approval list was
 * unreadable; a null backendIndex means the backend records were.
 *
 * It writes nothing: the backend index is returned so that only the read that still
 * owns the view applies it. A retired read therefore has no state to overwrite. */
async function gigahostOrderStatusReadOnce(signal) {
    let orders;
    let observations;
    let absence;
    try {
        const res = await API.get('/api/admin/hosting/gigahost/orders', {signal: signal, silent: true});
        orders = (res && res.orders) ? res.orders : [];
        observations = (res && res.provider_observations) ? res.provider_observations : {};
        // The list's own durable absence record, so the stage does not depend on the
        // per-order detail request below, which may fail.
        absence = (res && res.provider_absent_orders) ? res.provider_absent_orders : {};
    } catch (_) {
        return {ok: false};
    }

    const checkedAt = gigahostOrderStatusNow().toISOString();
    const setupIndex = await readGigahostSetupIntents(signal);
    const backendIndex = await readGigahostBackendIndex(signal);
    // Only an order the provider can still say something about is asked about. A row
    // the panel has recorded as gone, and a cancelled one, are both finished, so the
    // status request is not issued for them at all - the decision the panel already
    // holds is the answer. The classification is the same one the row renders, taken
    // from the recorded row and the list's own absence record.
    const details = await Promise.all(orders.map((order) => {
        const orderID = order && order.order_id;
        if (!gigahostOrderStatusPollable(order, absence[String(orderID || '')])) {
            return {deploy: null, detailOK: true, skipped: true};
        }
        return readGigahostOrderDeploy(orderID, signal);
    }));
    const merged = orders.map((order, index) => mergeGigahostOrderDetail(
        order,
        (details[index] || {}).deploy,
        absence[String((order && order.order_id) || '')]
    ));
    return {
        ok: true,
        merged: merged,
        details: details,
        setupIndex: setupIndex,
        backendIndex: backendIndex,
        observations: observations,
        checkedAt: checkedAt
    };
}

/* GIGAHOST_ORDER_STATUS_RECENT_LIMIT is how many orders the recent list shows by
 * default. The cap is pre-existing and unchanged: only a row the view classifies as
 * deleted is rendered beyond it, because such a row is hidden from the Servers grid by
 * design and would otherwise have no surface that names its order at all. */
const GIGAHOST_ORDER_STATUS_RECENT_LIMIT = 5;

/* gigahostOrderStatusRenderList renders the recent list: the default five, plus every
 * older row that reads as deleted, and keeps any stale notice above them so a stale
 * label survives a rerender of the same rows.
 *
 * One classification per order decides both what the row says and whether it is
 * rendered, so the surface and its affordances cannot disagree about the same order. */
function gigahostOrderStatusRenderList(container, merged, details, setupIndex, observations, checkedAt) {
    const list = document.createElement('div');
    list.style.display = 'flex';
    list.style.flexDirection = 'column';
    list.style.gap = '6px';
    const contexts = merged.map((order, index) =>
        gigahostOrderStatusContext(order, details[index], setupIndex, checkedAt, observations));
    const models = merged.map((order, index) => gigahostOrderStatusModel(order, contexts[index]));
    merged.forEach((order, index) => {
        if (index >= GIGAHOST_ORDER_STATUS_RECENT_LIMIT && models[index].stage !== 'deleted') return;
        list.appendChild(gigahostOrderStatusRow(order, contexts[index], models[index]));
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
/* gigahostOrderStatusFreshness records what this read established, and reports the failures
 * this read must make visible.
 *
 * Confirmation and failure are evaluated independently, because they belong to different
 * orders. One order answering successfully is not evidence about another order, so a success
 * may advance the global last-success time but must never suppress a failure reported for
 * some other displayed order. The earlier shape returned on the first confirmation, which
 * silently dropped every failure in a mixed response.
 *
 * A read that confirmed nothing and failed nothing was not attempted at all (an all-terminal
 * list); that is neither a confirmation nor a failure, and nothing is advanced. */
function gigahostOrderStatusFreshness(container, merged, observations, checkedAt) {
    const reads = observations || {};
    const outcomes = merged.map((order) =>
        gigahostOrderStatusObservation(reads[String(order.order_id || '')]));
    const confirmed = outcomes.some((obs) => obs.outcome === 'confirmed');

    if (confirmed) gigahostOrderStatusLoaded(container, checkedAt);

    const failures = merged
        .map((order, index) => ({order: order, observation: outcomes[index]}))
        .filter((entry) => entry.observation.outcome === 'unavailable');
    if (failures.length === 0) {
        return {confirmed: confirmed, providerFailed: false, reason: '', failures: []};
    }
    return {
        confirmed: confirmed,
        providerFailed: true,
        // The first failure is the notice's headline reason; every failed order is named
        // below, and each failed row carries its own diagnostic as well.
        reason: failures[0].observation.error,
        failures: failures.map((entry) => ({
            orderId: String((entry.order.order_id) || ''),
            error: entry.observation.error
        }))
    };
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
 * supplies the onboarding-journal evidence the immediate setup path writes.
 *
 * The check time is per order, because "last successful check" is a statement about that
 * order's provider answer and not about this page read. It is this read's time only when
 * this read actually confirmed this order; otherwise the order keeps the last time it was
 * confirmed, and a never-confirmed order keeps an empty value so the panel says "Not
 * checked" rather than borrowing a success nobody observed for it. */
function gigahostOrderStatusContext(order, detail, setupIndex, checkedAt, observations) {
    const deploy = detail || {};
    const orderId = String(order.order_id || '');
    const setupKnown = setupIndex !== null;
    const reads = observations || {};
    const observation = reads[orderId] || null;
    const confirmedHere = gigahostOrderStatusObservation(observation).outcome === 'confirmed';
    return {
        deploy: deploy.deploy || null,
        detailOK: deploy.detailOK === true,
        checkedAt: gigahostOrderStatusOrderCheckedAt(orderId, checkedAt, confirmedHere),
        observation: observation,
        setup: {
            known: setupKnown,
            intent: setupKnown ? setupIndex[orderId] || null : null,
            journal: gigahostOrderStatusJournalEvidence(deploy.deploy)
        },
        health: gigahostOrderStatusHealthFor(order)
    };
}

/* gigahostOrderStatusOrderCheckedAt returns the check time this row may display, and
 * records a new one only when this read confirmed the order.
 *
 * The map is the view's own memory of what it has actually seen confirmed, so it survives
 * an outage: a failed read cannot overwrite a confirmed time, and one order's confirmation
 * cannot supply a time for another. */
function gigahostOrderStatusOrderCheckedAt(orderId, readAt, confirmedHere) {
    if (!orderId) return confirmedHere ? readAt : '';
    if (confirmedHere) {
        gigahostOrderStatusConfirmedAt[orderId] = String(readAt || '');
        return gigahostOrderStatusConfirmedAt[orderId];
    }
    return gigahostOrderStatusConfirmedAt[orderId] || '';
}

