/* Durable Gigahost setup approvals: the browser-independent view.
 *
 * These records live in the panel, so an administrator can see saved setup work
 * long after the browser that approved it is closed. Every value taken from a
 * record is rendered with textContent, never as markup: a provider diagnostic is
 * untrusted input and must not become HTML.
 */
/* Saved setup approvals are rendered from the panel's own durable records, so
 * what the administrator sees here does not depend on any browser holding the
 * original request open. Every string rendered from a record goes in as
 * textContent, never as markup, because a provider diagnostic is untrusted. */
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
        intents.forEach(i => {
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

            const right = document.createElement('div');
            right.style.display = 'flex';
            right.style.alignItems = 'center';
            right.style.gap = '6px';

            const badge = document.createElement('span');
            badge.className = 'badge ' + (i.state === 'ready_for_setup' ? 'badge-success' : (i.state === 'failed' ? 'badge-danger' : (i.state === 'cancelled' ? 'badge-danger' : 'badge-warn')));
            badge.style.fontSize = '0.75rem';
            badge.textContent = _('setup_state_' + i.state) || (i.state || '');
            right.appendChild(badge);

            // A pending approval can be revoked; one already at handoff cannot,
            // and one that needs the operator is pointed at, not re-run here.
            const revocable = i.state === 'pending';
            if (revocable) {
                const btnCancel = document.createElement('button');
                btnCancel.type = 'button';
                btnCancel.className = 'btn btn-secondary';
                btnCancel.style.padding = '2px 8px';
                btnCancel.style.fontSize = '0.75rem';
                btnCancel.textContent = _('setup_intents_cancel');
                btnCancel.addEventListener('click', () => cancelSetupIntent(i.order_id));
                right.appendChild(btnCancel);
            }

            row.appendChild(left);
            row.appendChild(right);
            list.appendChild(row);
        });
        container.replaceChildren(list);
    } catch (_) {
        renderEmpty();
    }
}

/* cancelSetupIntent revokes an approval. The confirmation is explicit because
 * revocation stops the panel tracking the job; it never cancels or deletes the
 * provider VPS itself. */
async function cancelSetupIntent(orderId) {
    if (!orderId) return;
    if (!confirm(_('setup_intents_cancel_confirm'))) return;
    try {
        await API.delete('/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup-approval');
        UI.toast(_('setup_intents_cancelled'), 'info');
    } catch (err) {
        UI.toast(err.message || _('error'), 'error');
    } finally {
        loadSetupIntents();
    }
}
