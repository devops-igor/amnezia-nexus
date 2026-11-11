/* Gigahost first-contact trust is a decision about a displayed identity, never
 * a blanket approval for any key offered on the next connection.
 *
 * The order was placed with a panel-managed SSH key, so setup first asks the
 * server to use the credential stored against that order. Only when the order has
 * no stored credential (an older order, or one placed by hand) does it ask the
 * administrator for a password, which is the pre-existing path. */
async function triggerGigahostSetup(orderId) {
    const payload = gigahostSetupPayload();
    if (!payload) return;
    const url = '/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup';
    UI.toast(_('deploy_status_polling'), 'info');
    try {
        const response = await sendGigahostSetupWithCredential(url, payload);
        if (response === null) return;
        const outcome = gigahostSetupOutcome(response);
        UI.toast(outcome.text, outcome.kind);
    } catch (err) {
        UI.toast(err.message || _('error'), 'error');
    } finally {
        loadRecentOrders();
    }
}

/* gigahostSetupOutcome turns a setup answer into the notification to show.
 *
 * A failed deploy is a real failure the administrator must see, and it carries
 * the reason the panel reported. Any other answer is progress rather than
 * success: the panel keeps polling the job itself, so claiming success before the
 * last step settles would report work that has not finished. */
function gigahostSetupOutcome(response) {
    const deploy = response && (response.deploy || response);
    if (!deploy || deploy.status === 'failed') throw new Error((deploy && deploy.error) || _('error'));
    const ready = deploy.status === 'ready';
    return {text: _(ready ? 'success' : 'deploy_status_polling'), kind: ready ? 'success' : 'info'};
}

/* gigahostSetupPayload returns the setup body for the answers given, or null
 * when the administrator declined one of the questions.
 *
 * Declining a prompt is an answer, and it authorizes nothing: a cancelled
 * protocol or TLS-domain prompt must not be turned into the default protocol or
 * an empty domain, because either one authorizes an install the administrator
 * explicitly refused. Accepting the offered default is a different answer - the
 * prompt returns the text it was shown, so a blank accepted answer still selects
 * AWG, which is the pre-existing behavior. */
function gigahostSetupPayload() {
    const typed = prompt(_('deploy_protocol_prompt'), 'awg');
    if (typed === null) return null;
    const choice = typed.toLowerCase().trim();
    const protocol = choice === 'vless' || choice === 'naive' ? choice : 'awg';
    const payload = {use_order_credential: true, protocol: protocol, tls_domain: ''};
    if (protocol === 'awg') return payload;
    const domain = prompt(_('deploy_domain_prompt'));
    if (domain === null) return null;
    payload.tls_domain = domain;
    return payload;
}

/* sendGigahostSetupWithCredential posts the setup request, and when the server
 * paused because the order has no managed key, asks for a password and retries
 * once with it instead of the stored-credential opt-in. That pause is the
 * pre-existing credential path.
 *
 * It returns null when the administrator declined the password prompt, so the
 * caller neither reports a failed deployment nor a successful one - no second
 * request was authorized. */
async function sendGigahostSetupWithCredential(url, payload) {
    try {
        return await sendGigahostSetup(url, payload);
    } catch (err) {
        const data = err.data;
        if (err.status !== 409 || !data || data.code !== 'credential_missing') throw err;
        const password = prompt(_('deploy_ssh_password_prompt'));
        if (!password) return null;
        delete payload.use_order_credential;
        payload.ssh_password = password;
        return await sendGigahostSetup(url, payload);
    }
}

/* sendGigahostSetup posts the setup request and resolves the host identity
 * challenge: the administrator confirms the exact presented fingerprint, and only
 * that fingerprint is sent back. It returns null when the administrator declines,
 * so a declined confirmation is not reported as a failed deployment. */
async function sendGigahostSetup(url, payload) {
    try {
        return await API.post(url, payload, {silent: true});
    } catch (err) {
        const data = err.data;
        if (err.status !== 409 || !data || data.status !== 'host_key_confirmation_required' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(data.fingerprint || '')) throw err;
        if (!confirm(_('deploy_host_key_confirm') + '\n' + data.host + '\n' + data.fingerprint)) return null;
        payload.expected_fingerprint = data.fingerprint;
        return await API.post(url, payload, {silent: true});
    }
}
