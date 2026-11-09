/* Gigahost first-contact trust is a decision about a displayed identity, never
 * a blanket approval for any key offered on the next connection.
 *
 * The order was placed with a panel-managed SSH key, so setup first asks the
 * server to use the credential stored against that order. Only when the order has
 * no stored credential (an older order, or one placed by hand) does it ask the
 * administrator for a password, which is the pre-existing path. */
async function triggerGigahostSetup(orderId) {
    const choice = (prompt(_('deploy_protocol_prompt'), 'awg') || 'awg').toLowerCase().trim();
    const protocol = choice === 'vless' || choice === 'naive' ? choice : 'awg';
    const tlsDomain = protocol === 'awg' ? '' : (prompt(_('deploy_domain_prompt')) || '');
    const url = '/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup';
    const payload = {use_order_credential: true, protocol: protocol, tls_domain: tlsDomain};
    UI.toast(_('deploy_status_polling'), 'info');
    try {
        let response;
        try {
            response = await sendGigahostSetup(url, payload);
        } catch (err) {
            const data = err.data;
            if (err.status !== 409 || !data || data.code !== 'credential_missing') throw err;
            // The server paused because this order has no managed key: ask for a
            // credential instead of failing, which is the pre-existing path.
            const password = prompt(_('deploy_ssh_password_prompt'));
            if (!password) return;
            delete payload.use_order_credential;
            payload.ssh_password = password;
            response = await sendGigahostSetup(url, payload);
        }
        if (response === null) return;
        const deploy = response && (response.deploy || response);
        if (!deploy || deploy.status === 'failed') throw new Error((deploy && deploy.error) || _('error'));
        UI.toast(deploy.status === 'ready' ? _('success') : _('deploy_status_polling'), deploy.status === 'ready' ? 'success' : 'info');
    } catch (err) {
        UI.toast(err.message || _('error'), 'error');
    } finally {
        loadRecentOrders();
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
