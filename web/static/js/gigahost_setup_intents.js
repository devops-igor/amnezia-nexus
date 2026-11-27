/* Durable Gigahost setup jobs: the browser-independent, actionable view.
 *
 * These records live in the panel, so an administrator can see and act on saved
 * setup work long after the browser that approved it is closed. Every value taken
 * from a record is rendered with textContent, never as markup: a provider
 * diagnostic is untrusted input and must not become HTML.
 *
 * The actions offered here are exactly the two the durable job can ask for:
 * a resume after a pause, and a host-identity confirmation after a trust pause.
 * Neither action installs anything from the browser - both hand the decision to
 * the panel's own worker, which owns the install journal.
 */

/* setupIntentsInFlight holds the orders whose action request is currently being
 * served. It is the duplicate-click guard: a second click on the same order while
 * its request is open must not issue a second request, because a repeated resume
 * or confirmation is a second administrative decision the operator did not make.
 * The key is the order id, so acting on one order never blocks another. */
const setupIntentsInFlight = new Set();

/* SETUP_INTENTS_MOVING_REFRESH_MS is the pace at which a job the panel is still
 * provisioning is followed. SETUP_INTENTS_PRESENCE_REFRESH_MS is the pace at which a
 * job whose row still offers a contact action is re-observed: the mark that the
 * provider no longer lists its server is written by the panel's own inventory pass,
 * which runs on a schedule of its own, so this waits for an observation that has had
 * time to arrive instead of re-reading a settled list every few seconds.
 * SETUP_INTENTS_RETRY_MS and SETUP_INTENTS_RETRY_MAX bound the reads a failed one may
 * cause: a rejected list is retried a few times at the same pace, and then the view
 * stops asking rather than holding a permanent poll of an unreachable panel. */
const SETUP_INTENTS_MOVING_REFRESH_MS = 4000;
const SETUP_INTENTS_PRESENCE_REFRESH_MS = 30000;
const SETUP_INTENTS_RETRY_MS = 30000;
const SETUP_INTENTS_RETRY_MAX = 5;

/* setupIntentsMovingStates are the states in which the panel itself is still working
 * on the job. They are the only ones whose step is a claim about the present: the list
 * follows them at the moving pace rather than the observation pace, and their row shows
 * the step as current. Every other state is an outcome the operator reads, so its step
 * is the last one recorded - the same wording the order disclosure uses for it. The
 * provider's recorded absence ends a job whatever its stored state says, so it is not
 * in flight either; that is decided by setupIntentStepInFlight rather than by adding a
 * second list here. */
const setupIntentsMovingStates = ['pending', 'installing'];

/* withSetupIntentAction runs one action for one order under that guard.
 *
 * It returns false when an action for the same order was already in flight, so a
 * caller's own follow-up work is skipped as well as the duplicate request. */
async function withSetupIntentAction(orderId, run) {
    if (!orderId || setupIntentsInFlight.has(orderId)) return false;
    setupIntentsInFlight.add(orderId);
    try {
        return await run();
    } finally {
        setupIntentsInFlight.delete(orderId);
    }
}

/* setupApprovalURL is the one place this module spells an order's approval
 * route. The order id is a provider identifier, so it is encoded: an id with a
 * separator in it must address its own order and no other. */
function setupApprovalURL(orderId) {
    return '/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup-approval';
}

/* The protocols an approval may name, in the order the prompt offers them. This
 * list is only for validating what the administrator typed; the panel decides
 * what it supports and refuses anything else. */
const setupApprovalProtocols = ['awg', 'vless', 'naive'];

/* setupApprovalPayload asks what to install and returns the exact approval body,
 * or null when the administrator cancelled.
 *
 * Cancelling a prompt is an answer: a cancelled choice must produce no approval
 * at all. That is why nothing here has a fallback protocol - the pre-existing
 * immediate setup path defaults a missing answer to awg, but a durable approval
 * is the administrator's own statement about work the panel performs later, so a
 * default would record a decision nobody made.
 *
 * The body carries no credential: the approval references the managed key the
 * order was placed with. An order without one pauses for credentials in the
 * panel, which is the supported safe stop, rather than claiming it can install
 * unattended. */
function setupApprovalPayload() {
    const typed = prompt(_('deploy_protocol_prompt'));
    if (typed === null) return null;
    const protocol = typed.toLowerCase().trim();
    if (setupApprovalProtocols.indexOf(protocol) === -1) {
        UI.toast(_('setup_intents_protocol_invalid'), 'error');
        return null;
    }
    const payload = {protocol: protocol, use_order_credential: true};
    if (protocol === 'awg') return payload;
    const domain = prompt(_('deploy_domain_prompt'));
    if (domain === null) return null;
    const trimmed = domain.trim();
    if (trimmed) payload.tls_domain = trimmed;
    return payload;
}

/* approveSetupIntent records the administrator's setup approval for one order.
 *
 * The approval is the explicit decision to hand this order to the panel's own
 * worker: from here the job is tracked in the panel and continues when this
 * browser is closed. It is not a request to install now, and it confirms no host
 * identity - the panel shows the identity it observed, and the administrator
 * confirms that value later from the saved list.
 *
 * The posted body is exactly what the endpoint validates, and its answer is the
 * existing DTO: created=false is a repeated approval, not a failure, because the
 * panel answers a repeat with the job it already has instead of starting a second
 * one. */
async function approveSetupIntent(orderId) {
    if (!orderId) return;
    const payload = setupApprovalPayload();
    if (!payload) return;
    if (!confirm(_('setup_intents_approve_confirm'))) return;
    await withSetupIntentAction(orderId, async () => {
        try {
            const res = await API.post(setupApprovalURL(orderId), payload, {silent: true});
            const created = !!(res && res.created);
            UI.toast(_(created ? 'setup_intents_saved' : 'setup_intents_already_saved'),
                created ? 'success' : 'info');
        } catch (err) {
            UI.toast(err.message || _('error'), 'error');
        } finally {
            loadSetupIntents();
        }
    });
}

/* appendSetupApprovalAction adds the save-for-setup action to one recent order.
 *
 * It is offered for any order the page displays. The saved path exists precisely
 * for the interval the immediate path cannot cover: the provider may not have
 * assigned an address yet, and the panel discovers it later on its own. Requiring
 * an address here would make the durable approval unreachable in the one state it
 * was built for.
 *
 * An order whose id is still a ledger placeholder is not offered, because there is
 * no confirmed provider order behind it. That refusal is the server's to make and
 * this is only the matching client-side affordance; the endpoint refuses the same
 * ids independently.
 */
function appendSetupApprovalAction(container, orderId) {
    if (!container || !orderId || isPlaceholderOrderID(orderId)) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-secondary';
    btn.style.padding = '2px 8px';
    btn.style.fontSize = '0.75rem';
    btn.textContent = _('setup_intents_approve');
    btn.addEventListener('click', () => approveSetupIntent(orderId));
    container.appendChild(btn);
}

/* isPlaceholderOrderID mirrors the ledger's placeholder ids for an order whose
 * purchase never resolved. Such a row has no confirmed provider order, so no setup
 * can be approved for it - the endpoint says so as well. */
function isPlaceholderOrderID(orderId) {
    return orderId.indexOf('intent_') === 0 || orderId.indexOf('unknown_') === 0;
}

async function loadSetupIntents() {
    const container = document.getElementById('setupIntentsContainer');
    if (!container) return;
    try {
        const res = await API.get('/api/admin/hosting/gigahost/setup-intents', {silent: true});
        const intents = (res && res.setup_intents) ? res.setup_intents : [];
        window.setupIntentsRetryAttempts = 0;
        if (intents.length === 0) {
            renderSetupIntentsEmpty(container);
            return;
        }
        const list = document.createElement('div');
        list.style.display = 'flex';
        list.style.flexDirection = 'column';
        list.style.gap = '6px';
        intents.forEach(i => list.appendChild(setupIntentRow(i)));
        container.replaceChildren(list);
        container.removeAttribute('data-stale');
        scheduleSetupIntentsPolling(intents);
    } catch (_) {
        /* A failed read is not an empty list.
         *
         * The panel answers this list from its own database, so a rejected request says
         * nothing about which jobs exist: rendering "no setup approval has been recorded"
         * hid a paused job that was still there, and because the timer had already cleared
         * itself before the read it also stopped the view from ever reading again, so a
         * later observation could not reach the operator without a reload. The row is
         * kept, the container records that its freshness is unproven, and a bounded retry
         * keeps asking so the corrected list can arrive on its own. */
        if (!container.firstChild) {
            renderSetupIntentsFailed(container);
        }
        container.setAttribute('data-stale', 'true');
        scheduleSetupIntentsRetry();
    }
}

/* renderSetupIntentsEmpty is the "no saved jobs" statement. It is only made when a read
 * answered and the answer was empty, because it is a claim about what the panel holds. */
function renderSetupIntentsEmpty(container) {
    const emptySpan = document.createElement('span');
    emptySpan.className = 'text-muted';
    emptySpan.textContent = _('setup_intents_none');
    container.replaceChildren(emptySpan);
    container.removeAttribute('data-stale');
}

/* renderSetupIntentsFailed is what an unreadable list says when there is no earlier row to
 * keep. It states that the read failed, which is the fact the operator needs, rather than
 * presenting an unanswered read as an empty list. */
function renderSetupIntentsFailed(container) {
    const failedSpan = document.createElement('span');
    failedSpan.className = 'text-muted';
    failedSpan.textContent = _('gigahost_status_load_failed');
    container.replaceChildren(failedSpan);
    container.setAttribute('data-stale', 'true');
}

/* setupIntentRow builds one saved job. The left side is the record, the right
 * side is the state and the actions that state makes possible.
 *
 * Layout is owned by settings.css (.gigahost-order-row and its two sides), the
 * same rules the recent-orders rows use, so a saved row reflows inside the card
 * instead of widening it. Both sides wrap and the row stacks below 600 px, which
 * is what keeps the state and any action in one frame on a phone: with a fixed
 * flex row the identity pushed the badge and the action past the right edge of
 * the card, and the document then scrolled sideways to reveal them. */
function setupIntentRow(i) {
    const row = document.createElement('div');
    row.className = 'gigahost-order-row';

    const left = document.createElement('div');
    left.className = 'gigahost-order-identity';
    const idSpan = document.createElement('span');
    idSpan.style.fontFamily = 'monospace';
    idSpan.style.fontWeight = '600';
    idSpan.textContent = '#' + (i.order_id || '');
    left.appendChild(idSpan);

    const protoSpan = document.createElement('span');
    protoSpan.style.marginLeft = '8px';
    protoSpan.style.color = 'var(--text-secondary)';
    protoSpan.textContent = (i.protocol || '') + (i.port ? ':' + i.port : '');
    left.appendChild(protoSpan);

    if (i.step) {
        const stepSpan = document.createElement('span');
        stepSpan.style.fontSize = '0.75rem';
        stepSpan.style.marginLeft = '8px';
        stepSpan.style.color = 'var(--text-secondary)';
        // A step is a claim about the present only while the panel can still move the
        // job. Every other state is an outcome whose step is the last one recorded,
        // and the same wording the order disclosure uses for the same fact - a bare
        // [installing_protocol] on an ended row read as work still underway.
        stepSpan.textContent = setupIntentStepInFlight(i)
            ? '[' + i.step + ']'
            : _('gigahost_status_recorded_step') + ': ' + i.step;
        left.appendChild(stepSpan);
    }

    if (i.last_error) {
        const errSpan = document.createElement('span');
        errSpan.style.fontSize = '0.75rem';
        errSpan.style.marginLeft = '8px';
        errSpan.style.color = 'var(--danger-color, #e53e3e)';
        errSpan.textContent = i.last_error;
        left.appendChild(errSpan);
    }

    /* A trust pause shows the identity it is asking about. An administrator
     * confirms a value they can read and compare, so it is part of the record
     * rather than hidden behind the button. */
    const displayedHost = i.state === 'awaiting_host_confirmation'
        ? setupIntentDisplayedIdentity(i)
        : '';
    if (displayedHost) {
        const hostSpan = document.createElement('div');
        hostSpan.style.fontSize = '0.7rem';
        hostSpan.style.fontFamily = 'monospace';
        hostSpan.style.color = 'var(--text-secondary)';
        hostSpan.textContent = displayedHost;
        left.appendChild(hostSpan);
    }

    const right = document.createElement('div');
    right.className = 'gigahost-order-state';

    const badge = document.createElement('span');
    // A job whose registered server the provider's own inventory no longer lists is
    // shown as what it is, rather than as a paused install with nothing to press: the
    // state badge and the action area must not disagree about the same job.
    const absent = setupIntentProviderAbsent(i);
    badge.className = 'badge ' + (absent ? 'badge-danger' : setupIntentBadgeClass(i.state));
    // The stage is carried as data as well as in the label, so the stylesheet can give
    // this one state its own ink. The danger fill is the same on both surfaces; the
    // shared danger ink does not clear 4.5:1 on it in the dark theme, and the recent
    // deployments badge already has a deleted-stage step of its own.
    if (absent) badge.setAttribute('data-stage', 'deleted');
    badge.style.fontSize = '0.75rem';
    badge.textContent = absent
        ? _('gigahost_status_stage_deleted')
        : (_('setup_state_' + i.state) || (i.state || ''));
    right.appendChild(badge);

    setupIntentActions(i).forEach(btn => right.appendChild(btn));

    row.appendChild(left);
    row.appendChild(right);
    return row;
}

/* setupIntentBadgeClass maps a durable state to the existing badge vocabulary. */
function setupIntentBadgeClass(state) {
    if (state === 'ready' || state === 'ready_for_setup') return 'badge-success';
    if (state === 'failed' || state === 'cancelled' || state === 'canceled') return 'badge-danger';
    return 'badge-warn';
}

/* setupIntentDisplayedIdentity returns the host identity this job actually put in
 * front of an administrator, or '' when there is none.
 *
 * The panel's own read-only challenge records a candidate first; a job whose
 * approval already carried a confirmed identity reports that instead. Both are
 * values the panel displayed, so both are confirmable. An empty result means no
 * identity was ever shown, and the confirmation action must not exist: the
 * browser may not invent one. */
function setupIntentDisplayedIdentity(i) {
    if (!i) return '';
    const candidate = (i.host_candidate_fingerprint || '').trim();
    if (candidate) return candidate;
    return (i.host_fingerprint || '').trim();
}

/* setupIntentProviderAbsent reports the panel's durable record that the provider's own
 * inventory no longer lists the server this job registered.
 *
 * It is the same presence fact the Recent Deployments row reads, resolved from the
 * identity the job journaled at registration - a saved job can be paused after that
 * point, before the order ledger mirrors the id. Only an explicit true counts; a job
 * with no such record keeps its ordinary treatment. */
function setupIntentProviderAbsent(i) {
    return !!i && i.provider_absent === true;
}

/* setupIntentStepInFlight reports whether this job's recorded step is still the step it
 * is on, rather than the last one it reached.
 *
 * It is one predicate over the module's own moving-state list, so the pace the list is
 * followed at and the wording of its step cannot disagree about which jobs are still
 * running. A provider-confirmed absence ends the job regardless of the recorded state:
 * the deployment is gone, so nothing about it is in flight. */
function setupIntentStepInFlight(i) {
    if (!i || setupIntentProviderAbsent(i)) return false;
    return setupIntentsMovingStates.indexOf(i.state) !== -1;
}

/* setupIntentActions returns the buttons a state allows.
 *
 * Only a pending approval can be revoked: a job past the install handoff is
 * tracked by the worker, and revoking it would strand an install nobody can
 * follow. Only a paused job can be resumed, because a resume is the
 * administrator's statement that an unproven outcome may be retried. Only a
 * trust pause asks for an identity confirmation, and it carries the exact
 * fingerprint the panel displayed for this job - never a value from this page.
 *
 * Every one of those actions except revocation ends in a connection to the server
 * the job registered, so none of them may be offered once the provider's inventory
 * has confirmed that server is gone. Revocation stays: it is a local decision about
 * the panel's own approval and contacts nothing. */
function setupIntentActions(i) {
    const buttons = [];
    const add = (label, kind, handler) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-' + kind;
        btn.style.padding = '2px 8px';
        btn.style.fontSize = '0.75rem';
        btn.textContent = label;
        btn.addEventListener('click', handler);
        buttons.push(btn);
    };

    if (i.state === 'pending') {
        add(_('setup_intents_cancel'), 'secondary', () => cancelSetupIntent(i.order_id));
    }
    if (setupIntentProviderAbsent(i)) return buttons;
    const displayed = setupIntentDisplayedIdentity(i);
    if (i.state === 'install_paused' || i.state === 'awaiting_credentials') {
        add(_('setup_intents_resume'), 'primary', () => resumeSetupIntent(i.order_id));
    }
    if (i.state === 'awaiting_host_confirmation' && displayed) {
        add(_('setup_intents_confirm_host'), 'primary', () => confirmSetupHost(i.order_id, displayed));
    }
    if (i.state === 'awaiting_credentials') {
        const hint = document.createElement('span');
        hint.style.fontSize = '0.75rem';
        hint.style.color = 'var(--text-secondary)';
        hint.textContent = _('setup_intents_credentials_hint');
        buttons.push(hint);
    }
    return buttons;
}

/* scheduleSetupIntentsPolling refreshes while any job is still moving, so the
 * view follows provisioning and installation without the browser that started
 * it. A settled list is not polled.
 *
 * A job that still offers an action ending in a connection to its server is
 * polled too, at the pace of a durable observation rather than of provisioning:
 * the panel records that the provider's inventory no longer lists that server
 * from another surface, on its own schedule, so a list that stopped reading
 * after the first render kept offering Resume for a server already known to be
 * gone until the operator reloaded the page. One timer owns that refresh, it is
 * armed only while such a row is still shown, and it stops as soon as none is
 * left, so a list with nothing actionable left is not polled at all. */
function scheduleSetupIntentsPolling(intents) {
    if (window.setupIntentsPollTimer) return;
    const moving = intents.some(i => setupIntentsMovingStates.indexOf(i.state) !== -1);
    const contactable = intents.some(setupIntentsContactable);
    if (!moving && !contactable) return;
    bindSetupIntentsLifecycle();
    const delay = moving ? SETUP_INTENTS_MOVING_REFRESH_MS : SETUP_INTENTS_PRESENCE_REFRESH_MS;
    window.setupIntentsPollTimer = setTimeout(() => {
        window.setupIntentsPollTimer = null;
        loadSetupIntents();
    }, delay);
}

/* scheduleSetupIntentsRetry re-arms the list after a failed read.
 *
 * It is deliberately bounded: the point is to survive a transient failure, not to keep a
 * panel that is down under a permanent poll. The attempt counter is reset by the next
 * successful read, so a long outage costs a fixed handful of requests and a recovery
 * restores the ordinary watch. It shares the one timer field with the watch above, so the
 * view never has two refreshes racing to render the same list. */
function scheduleSetupIntentsRetry() {
    const attempts = window.setupIntentsRetryAttempts || 0;
    if (attempts >= SETUP_INTENTS_RETRY_MAX) return;
    if (window.setupIntentsPollTimer) return;
    window.setupIntentsRetryAttempts = attempts + 1;
    bindSetupIntentsLifecycle();
    window.setupIntentsPollTimer = setTimeout(() => {
        window.setupIntentsPollTimer = null;
        loadSetupIntents();
    }, SETUP_INTENTS_RETRY_MS);
}

/* setupIntentsContactable reports whether a saved job offers an action that ends
 * in a connection to the server it registered, which is the state a fresh
 * observation can change. Revocation is deliberately not one of them: it is a
 * local decision about the panel's own approval and contacts nothing. */
function setupIntentsContactable(i) {
    if (!i || setupIntentProviderAbsent(i)) return false;
    if (i.state === 'install_paused' || i.state === 'awaiting_credentials') return true;
    return i.state === 'awaiting_host_confirmation' && !!setupIntentDisplayedIdentity(i);
}

/* stopSetupIntentsPolling clears the view's refresh, so a settled list stops
 * asking and a closed page leaves no timer behind. */
function stopSetupIntentsPolling() {
    if (!window.setupIntentsPollTimer) return;
    clearTimeout(window.setupIntentsPollTimer);
    window.setupIntentsPollTimer = null;
}

/* bindSetupIntentsLifecycle stops the refresh when the page goes away, and re-observes the
 * list when the browser hands the document back. It is bound once, by the load that arms
 * the first timer. */
function bindSetupIntentsLifecycle() {
    if (window.setupIntentsLifecycleBound || typeof window === 'undefined' || !window.addEventListener) return;
    window.addEventListener('pagehide', stopSetupIntentsPolling);
    window.addEventListener('pageshow', setupIntentsRestored);
    window.setupIntentsLifecycleBound = true;
}

/* setupIntentsRestored re-observes the list when the browser restores this document from
 * its page cache.
 *
 * `pagehide` clears the refresh before the document is frozen and a restored document is
 * not rendered again, so without this the rows on screen kept offering an action the panel
 * had since decided against - the same stale list the watch exists to prevent, reachable
 * only by navigating away and back. The event's `persisted` flag is what separates a
 * restore from the initial page load, which renders the list itself. */
function setupIntentsRestored(event) {
    if (!event || !event.persisted) return;
    loadSetupIntents();
}

/* cancelSetupIntent revokes an approval. The confirmation is explicit because
 * revocation stops the panel tracking the job; it never cancels or deletes the
 * provider VPS itself. */
async function cancelSetupIntent(orderId) {
    if (!orderId) return;
    if (!confirm(_('setup_intents_cancel_confirm'))) return;
    await withSetupIntentAction(orderId, async () => {
        try {
            await API.delete(setupApprovalURL(orderId));
            UI.toast(_('setup_intents_cancelled'), 'info');
        } catch (err) {
            UI.toast(err.message || _('error'), 'error');
        } finally {
            loadSetupIntents();
        }
    });
}

/* resumeSetupIntent asks the panel's worker to continue a paused job. The
 * browser sends a decision, not an instruction to install: the worker re-reads
 * its own journal and verifies any step whose outcome is unknown. */
async function resumeSetupIntent(orderId) {
    if (!orderId) return;
    if (!confirm(_('setup_intents_resume_confirm'))) return;
    await withSetupIntentAction(orderId, async () => {
        try {
            await API.post('/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup-resume', {}, {silent: true});
            UI.toast(_('setup_intents_resumed'), 'info');
        } catch (err) {
            UI.toast(err.message || _('error'), 'error');
        } finally {
            loadSetupIntents();
        }
    });
}

/* confirmSetupHost records the exact host identity the job is waiting on. The
 * fingerprint comes from the record, never from this page's own guess, so the
 * confirmation is bound to what the panel presented to an administrator. */
async function confirmSetupHost(orderId, fingerprint) {
    if (!orderId || !fingerprint) return;
    await withSetupIntentAction(orderId, async () => {
        try {
            await API.post('/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup-host-confirmation',
                {fingerprint: fingerprint}, {silent: true});
            UI.toast(_('setup_intents_host_confirmed'), 'success');
        } catch (err) {
            UI.toast(err.message || _('error'), 'error');
        } finally {
            loadSetupIntents();
        }
    });
}
