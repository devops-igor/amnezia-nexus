/* Gigahost first-contact trust is a decision about a displayed identity, never
 * a blanket approval for any key offered on the next connection. */
async function triggerGigahostSetup(orderId) {
    const password = prompt(_('deploy_ssh_password_prompt'));
    if (!password) return;
    const choice = (prompt(_('deploy_protocol_prompt'), 'awg') || 'awg').toLowerCase().trim();
    const protocol = choice === 'vless' || choice === 'naive' ? choice : 'awg';
    const tlsDomain = protocol === 'awg' ? '' : (prompt(_('deploy_domain_prompt')) || '');
    const url = '/api/admin/hosting/gigahost/orders/' + encodeURIComponent(orderId) + '/setup';
    const payload = {ssh_password: password, protocol: protocol, tls_domain: tlsDomain};
    UI.toast(_('deploy_status_polling'), 'info');
    try {
        let response;
        try {
            response = await API.post(url, payload, {silent: true});
        } catch (err) {
            const data = err.data;
            if (err.status !== 409 || !data || data.status !== 'host_key_confirmation_required' || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(data.fingerprint || '')) throw err;
            if (!confirm(_('deploy_host_key_confirm') + '\n' + data.host + '\n' + data.fingerprint)) return;
            payload.expected_fingerprint = data.fingerprint;
            response = await API.post(url, payload, {silent: true});
        }
        const deploy = response && (response.deploy || response);
        if (!deploy || deploy.status === 'failed') throw new Error((deploy && deploy.error) || _('error'));
        UI.toast(deploy.status === 'ready' ? _('success') : _('deploy_status_polling'), deploy.status === 'ready' ? 'success' : 'info');
    } catch (err) {
        UI.toast(err.message || _('error'), 'error');
    } finally {
        loadRecentOrders();
    }
}
