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

async function loadSetupIntents() {
    const container = document.getElementById('setupIntentsContainer');
    if (!container) return;
    const renderEmpty = () => {
        const emptySpan = document.createElement('span');
        emptySpan.className = 'text-muted';
        emptySpan.textContent = _('setup_intents_none');
        container.replaceChildren(emptySpan);
    };
    try {
        const res = await API.get('/api/admin/hosting/gigahost/setup-intents');
        const intents = (res && res.setup_intents) ? res.setup_intents : [];
        if (intents.length === 0) {
            renderEmpty();
            return;
        }
        const list = document.createElement('div');
        list.style.display = 'flex';
        list.style.flexDirection = 'column';
        list.style.gap = '6px';
        intents.forEach(i => list.appendChild(setupIntentRow(i)));
        container.replaceChildren(list);
        scheduleSetupIntentsPolling(intents);
    } catch (_) {
        renderEmpty();
    }
}

/* setupIntentRow builds one saved job. The left side is the record, the right
 * side is the state and the actions that state makes possible. */
function setupIntentRow(i) {
    const row = document.createElement('div');
    row.style.display = 'flex';
    row.style.justifyContent = 'space-between';
    row.style.alignItems = 'center';
    row.style.padding = '6px 0';
    row.style.borderBottom = '1px solid rgba(255,255,255,0.05)';

    const left = document.createElement('div');
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
        stepSpan.style.color = 'var(--text-muted)';
        stepSpan.textContent = '[' + i.step + ']';
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
    right.style.display = 'flex';
    right.style.alignItems = 'center';
    right.style.gap = '6px';

    const badge = document.createElement('span');
    badge.className = 'badge ' + setupIntentBadgeClass(i.state);
    badge.style.fontSize = '0.75rem';
    badge.textContent = _('setup_state_' + i.state) || (i.state || '');
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

/* setupIntentActions returns the buttons a state allows.
 *
 * Only a pending approval can be revoked: a job past the install handoff is
 * tracked by the worker, and revoking it would strand an install nobody can
 * follow. Only a paused job can be resumed, because a resume is the
 * administrator's statement that an unproven outcome may be retried. Only a
 * trust pause asks for an identity confirmation, and it carries the exact
 * fingerprint the panel displayed for this job - never a value from this page. */
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
        hint.style.color = 'var(--text-muted)';
        hint.textContent = _('setup_intents_credentials_hint');
        buttons.push(hint);
    }
    return buttons;
}

/* scheduleSetupIntentsPolling refreshes while any job is still moving, so the
 * view follows provisioning and installation without the browser that started
 * it. A settled list is not polled. */
function scheduleSetupIntentsPolling(intents) {
    const moving = intents.some(i => i.state === 'pending' || i.state === 'installing');
    if (!moving || window.setupIntentsPollTimer) return;
    window.setupIntentsPollTimer = setTimeout(() => {
        window.setupIntentsPollTimer = null;
        loadSetupIntents();
    }, 4000);
}

/* cancelSetupIntent revokes an approval. The confirmation is explicit because
 * revocation stops the panel tracking the job; it never cancels or deletes the
 * provider VPS itself. */
async function cancelSetupIntent(orderId) {
    if (!orderId) return;
    if (!confirm(_('setup_intents_cancel_confirm'))) return;
    await withSetupIntentAction(orderId, async () => {
        try {
            await API.delete('/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup-approval');
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
