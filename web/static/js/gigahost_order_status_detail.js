/* Gigahost order status: the read-only detail panel.
 *
 * The interactive status cell carries the stage progression; underneath it sits the panel
 * of facts an operator reads about one order - the provider axis, the VPN setup axis, the
 * backend health, the recorded step, the reported failure and the address with what it
 * does and does not prove. Those are one concern: every function here renders a labelled
 * fact and makes no request, so this file is the one to read when the question is "what
 * does this panel claim and where does the claim come from".
 *
 * It was partitioned out of gigahost_order_status.js to keep that controller under the
 * repository's per-file size ceiling; the controller still owns the progression, the
 * interaction and the polling, and calls gigahostOrderStatusPanel to build the details.
 */

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
    // Labels name the fact beside them, so they are informative text: --text-muted
    // measures 2.95:1 (dark) and 2.56:1 (light) on a card, under the 4.5:1 minimum.
    label.style.color = 'var(--text-secondary)';
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

/* gigahostOrderStatusProviderDetail states the provider axis, labelled with what it is.
 *
 * The value is either a provider answer read in this response or the panel's own recorded
 * copy, which is served whether or not anybody was reachable. Labelling the copy "Provider"
 * claims a read that did not happen: a cancelled order is deliberately never asked. The
 * recorded role reuses the string the inventory cards already use for the same meaning. */
function gigahostOrderStatusProviderDetail(panel, model) {
    const labelKey = model.providerConfirmed ? 'gigahost_status_provider' : 'gigahost_deployment_recorded_state';
    gigahostOrderStatusDetail(panel, labelKey,
        _('gigahost_status_stage_' + model.stage) + (model.providerStatus ? ' (' + model.providerStatus + ')' : ''));
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
    note.style.color = 'var(--text-secondary)';
    note.style.marginBottom = '4px';
    note.textContent = _('gigahost_status_read_only');
    panel.appendChild(note);

    gigahostOrderStatusProviderDetail(panel, model);

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

/* gigahostOrderStatusStepDetail shows the recorded step. A terminal order is not in
 * flight, so its step is the last one that was attempted: the fact is kept and the
 * claim changes, because "Current step" beside "Next action: Nothing to do" reads as
 * progress on a finished attempt. */
function gigahostOrderStatusStepDetail(panel, model) {
    const step = model.step || (model.setupIntent && model.setupIntent.step) || '';
    if (!step) return;
    gigahostOrderStatusDetail(panel,
        gigahostOrderStatusStageInFlight(model.stage) ? 'gigahost_status_step' : 'gigahost_status_recorded_step',
        step);
}

/* gigahostOrderStatusFailureDetail shows the reported reason as text: a provider
 * diagnostic is untrusted input and must never become markup.
 *
 * A row whose provider read failed shows that read's own diagnostic here, because that is
 * this order's known failure. Without it the failure would only exist in an aggregate notice
 * that a different order's success can hide. */
function gigahostOrderStatusFailureDetail(panel, model) {
    const failure = model.failure
        || (model.setupIntent && model.setupIntent.last_error)
        || (model.providerReadFailed ? model.providerError : '')
        || '';
    if (!failure) return;
    const node = document.createElement('span');
    node.style.color = 'var(--danger-color, #e53e3e)';
    node.textContent = failure;
    if (model.providerReadFailed) node.setAttribute('data-provider-error', 'true');
    gigahostOrderStatusDetail(panel, model.providerReadFailed ? 'gigahost_status_provider_error' : 'gigahost_status_failure', node);
}

/* gigahostOrderStatusAddressDetail shows the address when there is one, and says
 * what it does and does not prove: an address on an unready server is not a usable VPN
 * endpoint, and an address on a deleted server may already belong to somebody else. */
function gigahostOrderStatusAddressDetail(panel, model) {
    if (!model.assignedIP) return;
    gigahostOrderStatusDetail(panel, 'gigahost_status_address', model.assignedIP);
    // A deleted deployment keeps its last recorded address as a fact about the past. The
    // provisioning explanation would be false for it - the provider is not deploying
    // anything - and the address is not contacted, which is why nothing here may dial it.
    //
    // What the sentence may claim depends on which fact ended the order. Only a recorded
    // omission from a successful server inventory is evidence that the provider no longer
    // lists the server, and only that case may say so. A cancellation is the order's own
    // final decision and a recorded `deleted` spelling is the provider's word about the
    // order; neither establishes anything about the inventory, so neither may borrow the
    // inventory sentence. The address is the same address either way, so the fact shown
    // is unchanged and only the claim about it narrows to what was observed.
    if (model.stage === 'deleted') {
        const stale = document.createElement('div');
        stale.style.color = 'var(--text-secondary)';
        stale.textContent = _(model.providerAbsent
            ? 'gigahost_status_ip_deleted'
            : 'gigahost_status_ip_ended');
        panel.appendChild(stale);
        return;
    }
    // An address proves nothing about readiness when the provider state is unknown, so
    // the explanation is due in that case too, not only while actively deploying.
    if (!model.addressWhileProvisioning && !model.providerUnknown) return;
    const hint = document.createElement('div');
    hint.style.color = 'var(--text-secondary)';
    hint.textContent = _('gigahost_status_ip_while_provisioning');
    panel.appendChild(hint);
}
