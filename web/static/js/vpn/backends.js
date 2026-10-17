/* ===== VPN Backend Management Interactions Controller ===== */
// Extracted from web/templates/vpn.html per #498 (Epic #475 Phase 3).

function vpnFormatApiError(err, res, data) {
    const errMsg = (data && (data.detail || data.message || data.error)) ||
        (err && err.data && (err.data.detail || err.data.message || err.data.error)) ||
        (res && `HTTP ${res.status} ${res.statusText || _('error')}`.trim()) ||
        (err && err.status ? `HTTP ${err.status}` : '') ||
        (err && err.message) || _('error');
    return errMsg;
}

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
        await vpnLoadData();
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

function vpnServerHasAwg(srv) {
    if (!srv || !srv.protocols) return false;
    const awg = srv.protocols.awg;
    if (!awg) return false;
    if (typeof awg === 'boolean') return awg;
    if (typeof awg === 'object') {
        return !!(awg.installed || awg.public_key || (typeof awg.port === 'number' && awg.port > 0));
    }
    return false;
}

function vpnStatusBadgeClass(status) {
    switch (status) {
        case 'active': return 'badge-success';
        case 'degraded': return 'badge-warn';
        case 'connecting': return 'badge-info';
        case 'disabled': return 'badge-danger';
        default: return 'badge-secondary';
    }
}

function vpnStatusLabel(status) {
    switch (status) {
        case 'active': return _('active');
        case 'degraded': return _('vpn_degraded');
        case 'connecting': return _('connecting');
        case 'disabled': return _('disabled');
        default: return String(status);
    }
}

function vpnSetListenerBadge(running) {
    const badge = document.getElementById('vpn-listener-badge');
    if (!badge) return;
    badge.className = 'badge ' + (running ? 'badge-success' : 'badge-secondary');
    badge.textContent = '';
    const dot = document.createElement('span');
    dot.className = 'badge-dot';
    badge.appendChild(dot);
    badge.appendChild(document.createTextNode(' ' + (running ? _('vpn_running') : _('vpn_stopped'))));
}

function vpnRenderBackendRow(b) {
    const tr = document.createElement('tr');
    const srvId = b.server_id || b.id || '';
    const displayStatus = b.enabled === false ? 'disabled' : (b.status || '');
    tr.setAttribute('data-status', displayStatus);

    const tdServer = document.createElement('td');
    const srvMatch = vpnCachedServers.find(function (s) { return String(s.id) === String(srvId); });
    const srvName = srvMatch ? srvMatch.name : ('Server #' + srvId);
    tdServer.innerHTML = `
        <div class="flex items-center gap-sm">
            <div style="width: 30px; height: 30px; border-radius: var(--radius-sm); background: var(--bg-surface); border: 1px solid var(--border-color); display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                <svg class="icon text-muted" style="width: 15px; height: 15px;"><use href="#icon-server"></use></svg>
            </div>
            <div style="display: flex; flex-direction: column; gap: 2px;">
                <span style="font-weight: 600; color: var(--text-primary); line-height: 1.2;">${UI.escapeHtml(srvName)}</span>
                <span class="font-mono text-muted" style="font-size: 0.75rem; line-height: 1;">#${UI.escapeHtml(String(srvId))}</span>
            </div>
        </div>
    `;
    tr.appendChild(tdServer);

    const tdEndpoint = document.createElement('td');
    tdEndpoint.className = 'font-mono text-sm';
    tdEndpoint.textContent = b.endpoint || '-';
    tr.appendChild(tdEndpoint);

    const tdStatus = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + vpnStatusBadgeClass(displayStatus);
    badge.setAttribute('data-status', displayStatus);
    const dot = document.createElement('span');
    dot.className = 'badge-dot';
    badge.appendChild(dot);
    badge.appendChild(document.createTextNode(' ' + vpnStatusLabel(displayStatus)));
    if (b.enabled === false && b.status) {
        badge.title = vpnStatusLabel(b.status);
    }
    tdStatus.appendChild(badge);
    tr.appendChild(tdStatus);

    const tdLatency = document.createElement('td');
    const lat = (typeof b.latency_ms === 'number') ? b.latency_ms : null;
    tdLatency.setAttribute('data-sort-val', String(lat !== null ? lat : -1));
    if (lat !== null && lat > 0) {
        let tierClass = 'latency-good';
        if (lat > 150) {
            tierClass = 'latency-poor';
        } else if (lat >= 50) {
            tierClass = 'latency-fair';
        }
        tdLatency.innerHTML = `
            <span class="latency-pill ${tierClass}">
                <span class="latency-dot"></span>
                ${lat} ms
            </span>
        `;
    } else {
        tdLatency.innerHTML = `<span class="text-muted">-</span>`;
    }
    tr.appendChild(tdLatency);

    const tdConns = document.createElement('td');
    const conns = Number(b.active_connections || 0);
    tdConns.setAttribute('data-sort-val', String(conns));
    tdConns.innerHTML = `
        <span class="flex items-center gap-xs" style="font-size: 0.875rem; font-variant-numeric: tabular-nums;">
            <svg class="icon text-muted" style="width: 14px; height: 14px;"><use href="#icon-users"></use></svg>
            <strong>${conns}</strong>
        </span>
    `;
    tr.appendChild(tdConns);

    const tdActions = document.createElement('td');
    tdActions.style.textAlign = 'right';
    const actionsDiv = document.createElement('div');
    actionsDiv.style.display = 'flex';
    actionsDiv.style.alignItems = 'center';
    actionsDiv.style.justifyContent = 'flex-end';
    actionsDiv.style.gap = 'var(--space-xs)';

    // Toggle Enable/Disable
    const disabledBackend = b.enabled === false;
    const toggleBtn = document.createElement('button');
    toggleBtn.type = 'button';
    toggleBtn.className = 'btn btn-ghost btn-sm btn-icon' + (disabledBackend ? ' btn-success-hover' : '');
    toggleBtn.title = disabledBackend ? _('vpn_enable') : _('vpn_disable');
    toggleBtn.setAttribute('aria-label', disabledBackend ? _('vpn_enable') : _('vpn_disable'));
    toggleBtn.setAttribute('data-action', 'vpn-toggle-backend');
    toggleBtn.setAttribute('data-server-id', String(srvId));
    toggleBtn.setAttribute('data-backend-action', disabledBackend ? 'enable' : 'disable');
    toggleBtn.innerHTML = disabledBackend
        ? `<svg class="icon" style="color: var(--success);"><use href="#icon-play"></use></svg>`
        : `<svg class="icon text-muted"><use href="#icon-pause"></use></svg>`;
    actionsDiv.appendChild(toggleBtn);

    // Delete backend
    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.className = 'btn btn-ghost btn-sm btn-icon btn-danger-hover';
    delBtn.style.color = 'var(--danger)';
    delBtn.title = _('vpn_delete');
    delBtn.setAttribute('aria-label', _('vpn_delete'));
    delBtn.setAttribute('data-action', 'vpn-delete-backend');
    delBtn.setAttribute('data-server-id', String(srvId));
    delBtn.innerHTML = `<svg class="icon"><use href="#icon-trash"></use></svg>`;
    actionsDiv.appendChild(delBtn);

    tdActions.appendChild(actionsDiv);
    tr.appendChild(tdActions);

    return tr;
}

async function vpnToggleBackend(serverId, action) {
    if (action === 'disable') {
        const confirmed = await UI.confirm({
            title: _('vpn_disable') || 'Disable Backend',
            message: _('vpn_confirm_disable') || 'Are you sure you want to disable this backend?',
            confirmText: _('vpn_disable') || 'Disable',
            confirmVariant: 'warning'
        });
        if (!confirmed) return;
    }

    try {
        await API.post('/api/vpn/backends/' + encodeURIComponent(serverId) + '/' + action);
        UI.toast((action === 'enable' ? _('vpn_enable') : _('vpn_disable')) + ' OK', 'success');
        await vpnLoadData();
    } catch (err) {
        UI.toast((_('error') || 'Error') + ': ' + err.message, 'error');
    }
}

async function vpnDeleteBackend(serverId) {
    const confirmed = await UI.confirm({
        title: _('vpn_delete') || 'Delete Backend',
        message: _('vpn_confirm_delete') || 'Are you sure you want to delete this backend? This cannot be undone.',
        confirmText: _('vpn_delete') || 'Delete',
        confirmVariant: 'danger'
    });
    if (!confirmed) return;

    try {
        await API.post('/api/vpn/backends/' + encodeURIComponent(serverId) + '/delete');
        UI.toast((_('vpn_delete') || 'Delete') + ' OK', 'success');
        await vpnLoadData();
    } catch (err) {
        UI.toast((_('error') || 'Error') + ': ' + err.message, 'error');
    }
}

function vpnResetAddModal() {
    const select = document.getElementById('vpnServerSelect');
    select.textContent = '';
    const defOpt = document.createElement('option');
    defOpt.value = '';
    defOpt.textContent = '- ' + _('select') + ' -';
    select.appendChild(defOpt);
    select.disabled = false;

    document.getElementById('vpnServerDetails').style.display = 'none';
    document.getElementById('vpnNoServersNotice').style.display = 'none';
    const errBox = document.getElementById('vpnModalError');
    errBox.style.display = 'none';
    errBox.textContent = '';

    const submitBtn = document.getElementById('vpnAddBackendSubmitBtn');
    submitBtn.disabled = false;
    submitBtn.textContent = _('vpn_enable_backend');
}

async function vpnOpenAddBackendModal() {
    vpnResetAddModal();
    openModal('addBackendModal');

    const select = document.getElementById('vpnServerSelect');
    const loadingOpt = document.createElement('option');
    loadingOpt.value = '';
    loadingOpt.textContent = _('loading') + '...';
    select.appendChild(loadingOpt);
    select.disabled = true;

    try {
        const servers = await API.get('/api/servers');
        vpnCachedServers = Array.isArray(servers) ? servers : [];

        select.textContent = '';
        const defOpt = document.createElement('option');
        defOpt.value = '';
        defOpt.textContent = '- ' + _('select') + ' -';
        select.appendChild(defOpt);

        if (!vpnCachedServers.length) {
            document.getElementById('vpnNoServersNotice').style.display = 'block';
            select.disabled = true;
            document.getElementById('vpnAddBackendSubmitBtn').disabled = true;
            return;
        }

        select.disabled = false;

        const existingBackendIds = new Set(
            vpnCurrentBackends.map(function (b) { return String(b.server_id || b.id); })
        );

        let awgServerCount = 0;
        for (const srv of vpnCachedServers) {
            const hasAwg = vpnServerHasAwg(srv);
            if (hasAwg) awgServerCount++;

            const opt = document.createElement('option');
            opt.value = String(srv.id);

            const name = srv.name || ('Server #' + srv.id);
            const hostPort = srv.host ? (srv.host + (srv.ssh_port ? ':' + srv.ssh_port : '')) : '';
            const hasAnyProtocols = srv.protocols && Object.keys(srv.protocols).length > 0;
            const awgTag = hasAwg ? ' [AWG]' : (' (' + (hasAnyProtocols ? _('no_protocols') : _('not_checked')) + ')');
            const isBackend = existingBackendIds.has(String(srv.id));
            const backendTag = isBackend ? ' - ' + _('active') : '';

            opt.textContent = name + (hostPort ? ' (' + hostPort + ')' : '') + awgTag + backendTag;
            select.appendChild(opt);
        }

        if (awgServerCount === 0) {
            document.getElementById('vpnNoServersNotice').style.display = 'block';
        }
    } catch (err) {
        select.textContent = '';
        const errOpt = document.createElement('option');
        errOpt.value = '';
        errOpt.textContent = _('error');
        select.appendChild(errOpt);
        select.disabled = true;
        const errBox = document.getElementById('vpnModalError');
        errBox.textContent = err.message || _('error');
        errBox.style.display = 'block';
        document.getElementById('vpnAddBackendSubmitBtn').disabled = true;
    }
}

function vpnOnServerSelected() {
    const select = document.getElementById('vpnServerSelect');
    const selectedId = select.value;
    const detailsBox = document.getElementById('vpnServerDetails');
    const errBox = document.getElementById('vpnModalError');
    errBox.style.display = 'none';
    errBox.textContent = '';

    if (!selectedId) {
        detailsBox.style.display = 'none';
        return;
    }

    const srv = vpnCachedServers.find(function (s) { return String(s.id) === String(selectedId); });
    if (!srv) {
        detailsBox.style.display = 'none';
        return;
    }

    detailsBox.style.display = 'block';
    document.getElementById('vpnServerDetailHost').textContent = srv.host || '-';
    document.getElementById('vpnServerDetailPort').textContent = String(srv.ssh_port || 22);
    document.getElementById('vpnServerDetailStatus').textContent = srv.status || 'unknown';

    const hasAwg = vpnServerHasAwg(srv);
    const hasAnyProtocols = srv.protocols && Object.keys(srv.protocols).length > 0;
    const awgBadge = document.getElementById('vpnServerDetailAwgBadge');
    const checkRow = document.getElementById('vpnServerDetailCheckRow');
    const checkHint = document.getElementById('vpnServerDetailCheckHint');

    if (hasAwg) {
        awgBadge.className = 'badge badge-success';
        awgBadge.textContent = '';
        const dot = document.createElement('span');
        dot.className = 'badge-dot';
        awgBadge.appendChild(dot);
        awgBadge.appendChild(document.createTextNode(' AmneziaWG'));
        if (checkRow) checkRow.style.display = 'none';
        errBox.style.display = 'none';
        errBox.textContent = '';
    } else {
        awgBadge.className = 'badge badge-warn';
        awgBadge.textContent = '';
        const dot = document.createElement('span');
        dot.className = 'badge-dot';
        awgBadge.appendChild(dot);
        const badgeLabel = hasAnyProtocols ? _('no_protocols') : _('not_checked');
        awgBadge.appendChild(document.createTextNode(' ' + badgeLabel));

        if (checkRow) {
            checkRow.style.display = 'flex';
            checkHint.textContent = hasAnyProtocols ? _('vpn_server_no_awg_warning') : (_('not_checked') + ' - ' + _('server_check'));
        }

        errBox.textContent = _('vpn_server_no_awg_warning');
        errBox.style.display = 'block';
    }
}

async function vpnTriggerQuickCheck() {
    const select = document.getElementById('vpnServerSelect');
    const serverId = select.value;
    if (!serverId) return;

    const btn = document.getElementById('vpnQuickCheckBtn');
    const btnText = document.getElementById('vpnQuickCheckBtnText');
    const spinner = document.getElementById('vpnQuickCheckSpinner');
    const icon = document.getElementById('vpnQuickCheckIcon');
    const errBox = document.getElementById('vpnModalError');
    const checkHint = document.getElementById('vpnServerDetailCheckHint');

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = _('server_checking');
    if (icon) icon.classList.add('hidden');
    if (spinner) spinner.classList.remove('hidden');
    if (checkHint) checkHint.textContent = _('server_checking');

    try {
        const data = await API.post('/api/servers/' + encodeURIComponent(serverId) + '/check');
        const srv = vpnCachedServers.find(function (s) { return String(s.id) === String(serverId); });
        if (data && data.protocols && data.protocols.awg && data.protocols.awg.container_running) {
            if (srv) {
                srv.protocols = srv.protocols || {};
                srv.protocols.awg = data.protocols.awg;
                const opt = select.querySelector('option[value="' + serverId + '"]');
                if (opt) {
                    opt.textContent = opt.textContent.replace(' (' + _('no_protocols') + ')', ' [AWG]').replace(' (' + _('not_checked') + ')', ' [AWG]');
                    if (!opt.textContent.includes('[AWG]')) {
                        opt.textContent += ' [AWG]';
                    }
                }
            }
            const noServers = document.getElementById('vpnNoServersNotice');
            if (noServers) noServers.style.display = 'none';
            vpnOnServerSelected();
            UI.toast(_('check_done') + ': AmneziaWG OK', 'success');
        } else {
            if (checkHint) checkHint.textContent = _('vpn_server_no_awg_warning');
            errBox.textContent = _('vpn_server_no_awg_warning');
            errBox.style.display = 'block';
            UI.toast(_('vpn_server_no_awg_warning'), 'warning');
        }
    } catch (err) {
        const errMsg = err.message || _('check_error');
        if (checkHint) checkHint.textContent = _('check_error') + ': ' + errMsg;
        errBox.textContent = errMsg;
        errBox.style.display = 'block';
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = _('server_check');
        if (icon) icon.classList.remove('hidden');
        if (spinner) spinner.classList.add('hidden');
    }
}

async function vpnSubmitAddBackend() {
    const select = document.getElementById('vpnServerSelect');
    const serverId = select.value;
    const errBox = document.getElementById('vpnModalError');
    errBox.style.display = 'none';
    errBox.textContent = '';

    if (!serverId) {
        errBox.textContent = _('vpn_please_select_server');
        errBox.style.display = 'block';
        return;
    }

    const srv = vpnCachedServers.find(function (s) { return String(s.id) === String(serverId); });
    if (srv && !vpnServerHasAwg(srv)) {
        const submitBtn = document.getElementById('vpnAddBackendSubmitBtn');
        submitBtn.disabled = true;
        submitBtn.textContent = _('server_checking');
        try {
            const checkData = await API.post('/api/servers/' + encodeURIComponent(serverId) + '/check').catch(() => ({}));
            if (checkData.protocols && checkData.protocols.awg && checkData.protocols.awg.container_running) {
                srv.protocols = srv.protocols || {};
                srv.protocols.awg = checkData.protocols.awg;
                const noServers = document.getElementById('vpnNoServersNotice');
                if (noServers) noServers.style.display = 'none';
                vpnOnServerSelected();
            }
        } catch (_) {
            // If check fails, allow backend enable to attempt dynamic fallback
        }
    }

    const submitBtn = document.getElementById('vpnAddBackendSubmitBtn');
    submitBtn.disabled = true;
    submitBtn.textContent = _('loading') + '...';

    try {
        await API.post('/api/vpn/backends/' + encodeURIComponent(serverId) + '/enable');
        UI.toast(_('vpn_backend_enabled_success'), 'success');
        closeModal('addBackendModal');
        await vpnLoadData();
    } catch (err) {
        const errMsg = err.message || _('error');
        errBox.textContent = errMsg;
        errBox.style.display = 'block';
        UI.toast(errMsg, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = _('vpn_enable_backend');
    }
}

if (typeof window !== 'undefined') {
    window.vpnFormatApiError = vpnFormatApiError;
    window.vpnOpenEditEndpointModal = vpnOpenEditEndpointModal;
    window.vpnSubmitEditEndpoint = vpnSubmitEditEndpoint;
    window.vpnServerHasAwg = vpnServerHasAwg;
    window.vpnStatusBadgeClass = vpnStatusBadgeClass;
    window.vpnStatusLabel = vpnStatusLabel;
    window.vpnSetListenerBadge = vpnSetListenerBadge;
    window.vpnRenderBackendRow = vpnRenderBackendRow;
    window.vpnToggleBackend = vpnToggleBackend;
    window.vpnDeleteBackend = vpnDeleteBackend;
    window.vpnResetAddModal = vpnResetAddModal;
    window.vpnOpenAddBackendModal = vpnOpenAddBackendModal;
    window.vpnOnServerSelected = vpnOnServerSelected;
    window.vpnTriggerQuickCheck = vpnTriggerQuickCheck;
    window.vpnSubmitAddBackend = vpnSubmitAddBackend;
}
