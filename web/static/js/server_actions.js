/* ===== Amnezia Nexus — Server Page Actions & Modals Controller ===== */
// Extracted from web/templates/server.html per Issue #501 (Epic #475 Phase 3).

let currentInstallProto = 'awg';
let currentConfig = '';
let currentVpnLink = '';
let currentConfigName = 'connection';
let serverConfigFilename = 'server.conf';
let isEditingConn = false;
let editingClientId = null;
let renameServerId = null;
let editHostServerId = null;

function switchCategory(cat) {
    const grids = ['protocols-grid', 'services-grid', 'management-grid'];
    const tabs = ['tab-protocols', 'tab-services', 'tab-management'];

    grids.forEach(g => {
        const el = document.getElementById(g);
        if (el) el.classList.add('hidden');
    });
    tabs.forEach(t => {
        const el = document.getElementById(t);
        if (el) el.classList.remove('active');
    });

    const activeGrid = document.getElementById(cat + '-grid');
    const activeTab = document.getElementById('tab-' + cat);

    if (activeGrid) activeGrid.classList.remove('hidden');
    if (activeTab) activeTab.classList.add('active');
}

function getProtoTitle(proto) {
    switch (proto) {
        case 'awg': return 'AmneziaWG';
        case 'telemt': return 'MTProxyL';
        case 'dns': return 'AmneziaDNS';
        default: return proto;
    }
}

// Toggle Docker container start/stop
async function toggleContainer(proto, isRunning) {
    const name = getProtoTitle(proto);
    const action = isRunning ? _('stopping') : _('starting');
    const confirmed = await UI.confirm({
        title: isRunning ? (_('stop_btn') || 'Stop') : (_('start_btn') || 'Start'),
        message: `${isRunning ? _('stop_container_confirm') : _('start_container_confirm')}`.replace('{}', name),
        confirmVariant: isRunning ? 'danger' : 'primary'
    });
    if (!confirmed) return;

    try {
        UI.toast(`${action} ${name}...`, 'info');
        const res = await API.post(`/api/servers/${SERVER_ID}/container/toggle`, { protocol: proto });
        UI.toast(`${name} ${res.action === 'stopped' ? _('stopped') : _('started')}`, 'success');
        setTimeout(() => checkServer(), 1500);
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

// View server-side config
async function showServerConfig(proto) {
    const name = getProtoTitle(proto);
    try {
        UI.toast(_('loading'), 'info');
        const res = await API.post(`/api/servers/${SERVER_ID}/server_config`, { protocol: proto });
        document.getElementById('serverConfigModalTitle').textContent = `${_('server_config')} — ${name}`;
        document.getElementById('serverConfigProto').value = proto;
        document.getElementById('serverConfigText').value = res.config || '';
        serverConfigFilename = `server_${proto}.conf`;
        openModal('serverConfigModal');
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

// Save server config changes
async function saveServerConfig() {
    const proto = document.getElementById('serverConfigProto').value;
    const newConfig = document.getElementById('serverConfigText').value;
    const btn = document.getElementById('saveServerConfigBtn');
    const oldText = btn.textContent;
    btn.disabled = true;
    btn.textContent = _('saving');

    try {
        await API.post(`/api/servers/${SERVER_ID}/server_config/save`, {
            protocol: proto,
            config: newConfig
        });
        UI.toast(_('success'), 'success');
        closeModal('serverConfigModal');
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = oldText;
    }
}

// ========== Protocol Installation ==========
function openInstallModal(proto) {
    currentInstallProto = proto;
    const name = getProtoTitle(proto);
    document.getElementById('installModalTitle').textContent = `${_('install')} ${name}`;

    const portInput = document.getElementById('installPort');
    const portLabel = document.getElementById('installPortLabel');
    const portHint = document.getElementById('installPortHint');
    const telemtOpts = document.getElementById('telemtOptions');
    const awgOpts = document.getElementById('awgOptions');

    telemtOpts.style.display = 'none';
    awgOpts.style.display = 'none';

    if (proto === 'dns') {
        portLabel.textContent = _('port') + ' (Internal)';
        portInput.value = '53';
        portInput.disabled = true;
        portHint.textContent = _('internal_network_hint');
    } else if (proto === 'telemt') {
        portLabel.textContent = _('port') + ' (TCP)';
        portInput.value = '443';
        portInput.disabled = false;
        portHint.textContent = _('port_telemt_hint');
        telemtOpts.style.display = 'block';
    } else {
        portLabel.textContent = _('port') + ' (UDP)';
        portInput.value = '55424';
        portInput.disabled = false;
        portHint.textContent = _('port_default_hint');
        awgOpts.style.display = 'block';
    }

    document.getElementById('installForm').classList.remove('hidden');
    document.getElementById('installProgress').classList.add('hidden');
    document.getElementById('installDone').style.display = 'none';
    openModal('installModal');
}

async function installProtocol() {
    const port = document.getElementById('installPort').value;
    const btn = document.getElementById('installBtn');
    const text = document.getElementById('installBtnText');
    const spinner = document.getElementById('installSpinner');
    btn.disabled = true;
    text.textContent = _('installing');
    spinner.classList.remove('hidden');
    document.getElementById('installForm').classList.add('hidden');
    const progressDiv = document.getElementById('installProgress');
    progressDiv.classList.remove('hidden');
    const logEl = document.getElementById('installLog');
    const fillEl = document.getElementById('installProgressFill');
    logEl.innerHTML = `<div class="log-line info">${_('start_install')}</div>`;
    fillEl.style.width = '10%';
    fillEl.style.background = '';
    let progressInterval = null;
    try {
        const progressSteps = [
            { pct: 20, msg: _('check_docker') },
            { pct: 40, msg: _('prepare_host') },
            { pct: 50, msg: _('build_container') },
        ];
        let stepIdx = 0;
        progressInterval = setInterval(() => {
            if (stepIdx < progressSteps.length) {
                fillEl.style.width = progressSteps[stepIdx].pct + '%';
                logEl.innerHTML += `<div class="log-line info">${progressSteps[stepIdx].msg}</div>`;
                logEl.scrollTop = logEl.scrollHeight;
                stepIdx++;
            }
        }, 2000);
        const params = {
            protocol: currentInstallProto, port: port,
        };
        if (currentInstallProto === 'telemt') {
            params.tls_emulation = document.getElementById('installTelemtTls').checked;
            params.tls_domain = document.getElementById('installTelemtDomain').value;
            params.max_connections = parseInt(document.getElementById('installTelemtMaxConns').value) || 0;
        }
        if (['awg'].includes(currentInstallProto)) {
            const profileSelect = document.getElementById('installAwgProfile');
            if (profileSelect && profileSelect.value) {
                params.awg_profile = profileSelect.value;
            }
            if (profileSelect && profileSelect.value === 'pro') {
                const cpsSelect = document.getElementById('installAwgCpsProtocol');
                if (cpsSelect && cpsSelect.value) {
                    params.awg_cps_protocol = cpsSelect.value;
                }
            }
        }
        const result = await API.post(`/api/servers/${SERVER_ID}/install`, params);
        fillEl.style.width = '100%';
        if (result.log) {
            result.log.forEach(line => {
                logEl.innerHTML += `<div class="log-line success">✓ ${line}</div>`;
            });
        }
        logEl.scrollTop = logEl.scrollHeight;
        UI.toast(_('install_success'), 'success');
        document.getElementById('installDone').style.display = '';
    } catch (err) {
        fillEl.style.width = '100%';
        fillEl.style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
        logEl.innerHTML += `<div class="log-line error">✕ ${_('error')}: ${err.message}</div>`;
        logEl.scrollTop = logEl.scrollHeight;
        UI.toast(_('install_error') + err.message, 'error');
        document.getElementById('installDone').style.display = '';
    } finally {
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
    }
}

async function uninstallProtocol(proto) {
    const name = getProtoTitle(proto);
    const confirmed = await UI.confirm({
        title: _('uninstall') || 'Uninstall Protocol',
        message: _('uninstall_confirm').replace('{}', name),
        confirmVariant: 'danger'
    });
    if (!confirmed) return;
    try {
        await API.post(`/api/servers/${SERVER_ID}/uninstall`, { protocol: proto });
        UI.toast(`${name} ${_('stopped')}`, 'success');
        setTimeout(() => window.location.reload(), 800);
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

// ========== Connection Management Actions ==========
async function copyConnectionConfig(clientId, connName, btnEl) {
    const proto = document.getElementById('connProtoSelect').value;
    try {
        UI.toast(_('loading'), 'info');
        const result = await API.post(`/api/servers/${SERVER_ID}/connections/config`, {
            protocol: proto,
            client_id: clientId,
        });
        if (result && result.config) {
            await UI.copy(result.config, btnEl);
        } else {
            UI.toast(_('config_unavailable') || 'Config unavailable', 'warning');
        }
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

async function rotateClientMimicry(clientId) {
    try {
        UI.toast(_('loading'), 'info');
        const res = await API.post(`/api/servers/${SERVER_ID}/connections/${clientId}/rotate-mimicry`);
        UI.toast(`Rotated to ${(res.rotation && res.rotation.awg_mimicry ? res.rotation.awg_mimicry : 'next').toUpperCase()}`, 'success');
        loadConnections();
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

async function addConnection() {
    const proto = document.getElementById('connProtoSelect').value;
    const connName = document.getElementById('connectionName').value.trim();
    const userId = document.getElementById('connectionUserId').value || null;
    const btn = document.getElementById('addConnBtn');
    const text = document.getElementById('addConnBtnText');
    const spinner = document.getElementById('addConnSpinner');
    btn.disabled = true;
    text.textContent = isEditingConn ? _('saving') : _('creating');
    spinner.classList.remove('hidden');
    try {
        const params = {
            protocol: proto, user_id: userId,
        };
        if (isEditingConn) {
            params.client_id = editingClientId;
            if (connName) {
                params.name = connName;
            }
        } else {
            params.name = connName || 'Connection';
        }
        if (proto === 'awg') {
            const mimicrySelect = document.getElementById('awgMimicryProfile');
            if (mimicrySelect && mimicrySelect.value) {
                params.awg_mimicry = mimicrySelect.value;
            }
        }
        if (proto === 'telemt' && isEditingConn) {
            params.telemt_quota = document.getElementById('telemtQuota').value || null;
            params.telemt_max_ips = parseInt(document.getElementById('telemtMaxIps').value) || null;
            params.telemt_expiry = document.getElementById('telemtExpiry').value || null;
        }
        const result = await API.post(isEditingConn ? `/api/servers/${SERVER_ID}/connections/edit` : `/api/servers/${SERVER_ID}/connections/add`, params);
        if (isEditingConn) {
            UI.toast(_('connection_updated'), 'success');
            closeModal('addConnectionModal');
        } else {
            UI.toast(_('connection_created').replace('{}', connName || 'Connection'), 'success');
            closeModal('addConnectionModal');
            document.getElementById('connectionName').value = '';
            if (result.config) {
                currentConfig = result.config;
                currentVpnLink = result.vpn_link || '';
                currentConfigName = (connName || 'Connection').replace(/\s+/g, '_');
                document.getElementById('configModalTitle').textContent = `${_('config')} — ${connName || 'Connection'}`;
                document.getElementById('configText').textContent = result.config;
                document.getElementById('vpnLinkText').textContent = currentVpnLink;
                document.getElementById('panel-vpn').style.display = (proto === 'telemt' ? 'none' : '');
                document.querySelectorAll('.config-tab')[1].style.display = (proto === 'telemt' ? 'none' : '');
                document.getElementById('qrHint').textContent = (proto === 'telemt') ? _('qr_hint_telemt') : _('qr_hint');
                switchConfigTab('conf');
                openModal('configModal');
                generateQR(result.config);
            }
        }
        loadConnections();
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        text.textContent = isEditingConn ? _('save') : _('create');
        spinner.classList.add('hidden');
    }
}

function openAddConnectionModal(isEdit = false, clientData = null) {
    isEditingConn = isEdit;
    const proto = document.getElementById('connProtoSelect').value;
    const telemtOpts = document.getElementById('telemtConnOptions');
    const awgMimicryOpts = document.getElementById('awgMimicryOptions');

    document.getElementById('addConnectionModalTitle').textContent = isEdit ? _('edit_connection') : _('add_connection');
    document.getElementById('addConnBtnText').textContent = isEdit ? _('save') : _('create');
    document.getElementById('connectionNameGroup').style.display = 'block';
    document.getElementById('connectionName').value = (isEdit && clientData && (clientData.name || clientData.clientName)) ? (clientData.name || clientData.clientName) : '';
    document.getElementById('connectionUserId').value = (isEdit && clientData && clientData.assigned_user_id) ? clientData.assigned_user_id : '';

    if (proto === 'awg') {
        if (awgMimicryOpts) awgMimicryOpts.style.display = isEdit ? 'none' : 'block';
        if (!isEdit) {
            if (document.getElementById('awgMimicryProfile')) document.getElementById('awgMimicryProfile').value = 'auto';
        }
    } else {
        if (awgMimicryOpts) awgMimicryOpts.style.display = 'none';
    }

    if (isEdit && clientData) {
        editingClientId = (clientData && (clientData.clientId || clientData.clientName)) || null;
    } else {
        editingClientId = null;
    }

    if (proto === 'telemt' && isEdit) {
        telemtOpts.style.display = 'block';
        if (isEdit && clientData) {
            document.getElementById('telemtQuota').value = clientData.quota || '';
            document.getElementById('telemtMaxIps').value = clientData.active_ips || '';
            document.getElementById('telemtExpiry').value = clientData.expiry || '';
        } else {
            document.getElementById('telemtQuota').value = '';
            document.getElementById('telemtMaxIps').value = '';
            document.getElementById('telemtExpiry').value = '';
        }
    } else {
        telemtOpts.style.display = 'none';
    }
    openModal('addConnectionModal', '#connectionName');
}

function editConnection(clientId) {
    const userData = window.connectionsStore[clientId];
    if (userData) {
        userData.clientId = clientId;
        openAddConnectionModal(true, userData);
    }
}

async function removeConnection(clientId) {
    const confirmed = await UI.confirm({
        title: _('delete') || 'Delete Connection',
        message: _('delete_connection_confirm') || 'Are you sure you want to delete this connection?',
        confirmVariant: 'danger'
    });
    if (!confirmed) return;

    const proto = document.getElementById('connProtoSelect').value;
    try {
        await API.post(`/api/servers/${SERVER_ID}/connections/remove`, {
            protocol: proto, client_id: clientId,
        });
        UI.toast(_('connection_deleted'), 'success');
        loadConnections();
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

async function showConnectionConfig(clientId, connName, hasKey) {
    const proto = document.getElementById('connProtoSelect').value;

    document.getElementById('panel-vpn').style.display = (proto === 'telemt' ? 'none' : '');
    document.getElementById('panel-qr').style.display = '';
    document.querySelectorAll('.config-tab')[1].style.display = (proto === 'telemt' ? 'none' : '');
    document.querySelectorAll('.config-tab')[2].style.display = '';

    document.getElementById('qrHint').textContent = (proto === 'telemt') ? _('qr_hint_telemt') : _('qr_hint');

    if (!hasKey) {
        document.getElementById('configModalTitle').textContent = `${_('config')} — ${connName}`;
        currentConfig = '';
        currentVpnLink = '';
        currentConfigName = connName.replace(/\s+/g, '_');
        document.getElementById('configText').innerHTML = `<div style="padding:var(--space-md);background:var(--bg-primary);border-radius:var(--radius-md);border:1px solid var(--border-color);"><div style="font-size:1.4rem;margin-bottom:var(--space-sm);">⚠️</div><div style="font-weight:600;margin-bottom:var(--space-sm);">${_('config_unavailable')}</div><div style="font-size:0.85rem;color:var(--text-muted);line-height:1.6;">${_('config_unavailable_desc').replace(/\\n/g, '<br>')}<br><br><strong>${_('client_public_key')}</strong><br><code style="word-break:break-all;font-size:0.78rem;">${UI.escapeHtml(clientId)}</code></div></div>`;
        document.getElementById('vpnLinkText').textContent = '';
        document.getElementById('panel-vpn').style.display = 'none';
        document.getElementById('panel-qr').style.display = 'none';
        document.querySelectorAll('.config-tab')[1].style.display = 'none';
        document.querySelectorAll('.config-tab')[2].style.display = 'none';
        switchConfigTab('conf');
        openModal('configModal');
        return;
    }

    try {
        UI.toast(_('loading'), 'info');
        const result = await API.post(`/api/servers/${SERVER_ID}/connections/config`, {
            protocol: proto, client_id: clientId,
        });
        if (result.config) {
            currentConfig = result.config;
            currentVpnLink = result.vpn_link || '';
            currentConfigName = connName.replace(/\s+/g, '_');
            document.getElementById('configModalTitle').textContent = `${_('config')} — ${connName}`;
            document.getElementById('configText').textContent = result.config;
            document.getElementById('vpnLinkText').textContent = currentVpnLink;
            switchConfigTab('conf');
            openModal('configModal');
            generateQR(result.config);
        }
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

async function toggleConnection(clientId, enable) {
    const proto = document.getElementById('connProtoSelect').value;
    try {
        UI.toast(_('connection_enabled_disabled').replace('{status}', enable ? _('enabling') : _('disabling')) + '...', 'info');
        await API.post(`/api/servers/${SERVER_ID}/connections/toggle`, {
            protocol: proto, client_id: clientId, enable: enable,
        });
        UI.toast(_('connection_enabled_disabled').replace('{status}', enable ? _('enabled') : _('disabled')), 'success');
        loadConnections();
    } catch (err) {
        UI.toast(_('error') + ': ' + err.message, 'error');
    }
}

function switchConfigTab(tab) {
    document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.config-panel').forEach(p => p.classList.remove('active'));
    const tabs = document.querySelectorAll('.config-tab');
    const panels = { conf: 'panel-conf', vpn: 'panel-vpn', qr: 'panel-qr' };
    const tabIdx = { conf: 0, vpn: 1, qr: 2 };
    if (tabs[tabIdx[tab]]) tabs[tabIdx[tab]].classList.add('active');
    if (document.getElementById(panels[tab])) document.getElementById(panels[tab]).classList.add('active');
}

function generateQR(text) {
    const container = document.getElementById('qrCode');
    container.innerHTML = '';
    try {
        new QRCode(container, {
            text: text, width: 280, height: 280,
            colorDark: '#000000', colorLight: '#ffffff',
            correctLevel: QRCode.CorrectLevel.L
        });
    } catch (e) {
        console.error('QR lib error:', e);
        container.innerHTML = `<div style="color:var(--text-muted);font-size:0.85rem;">${_('qr_error')}</div>`;
    }
}

function formatDate(dateStr) {
    try {
        const d = new Date(dateStr);
        if (isNaN(d)) return dateStr;
        return d.toLocaleDateString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric' });
    } catch { return dateStr; }
}

// ========== Server Management Modals ==========
async function rebootServer() {
    const confirmed = await UI.confirm({
        title: _('reboot_server') || 'Reboot Server',
        message: 'Are you sure you want to reboot the server? Disconnections will occur.',
        confirmText: 'Reboot',
        confirmVariant: 'warning'
    });
    if (!confirmed) return;

    try {
        UI.toast('Rebooting server...', 'info');
        await API.post(`/api/servers/${SERVER_ID}/reboot`);
        UI.toast('Server is rebooting', 'success');
    } catch (err) {
        UI.toast('Error: ' + err.message, 'error');
    }
}

async function clearServer() {
    const confirmed = await UI.confirm({
        title: _('clear_server') || 'Clear Server',
        message: '⚠️ WARNING: This will completely delete all Amnezia configurations, containers, and data from /opt/amnezia on the server! Are you absolutely sure?',
        confirmText: 'Clear Server Data',
        confirmVariant: 'danger'
    });
    if (!confirmed) return;

    try {
        UI.toast('Clearing server from Amnezia software...', 'info');
        await API.post(`/api/servers/${SERVER_ID}/clear`);
        UI.toast('Server cleared successfully!', 'success');
        setTimeout(() => location.reload(), 1500);
    } catch (err) {
        UI.toast('Error: ' + err.message, 'error');
    }
}

async function removeServer() {
    const confirmed = await UI.confirm({
        title: _('remove_server') || 'Remove Server',
        message: 'Are you sure you want to remove this server from the panel? (The server itself will not be erased).',
        confirmText: 'Remove',
        confirmVariant: 'danger'
    });
    if (!confirmed) return;

    try {
        await API.post(`/api/servers/${SERVER_ID}/delete`);
        window.location.href = '/';
    } catch (err) {
        UI.toast('Error: ' + err.message, 'error');
    }
}

function openRenameServerModal(serverId, currentName) {
    renameServerId = serverId;
    const titleEl = document.getElementById('serverNameTitle');
    const name = titleEl ? titleEl.textContent.trim() : (currentName || '');
    const input = document.getElementById('renameServerInput');
    if (input) {
        input.value = name;
    }
    openModal('renameServerModal', '#renameServerInput');
}

function closeRenameServerModal() {
    closeModal('renameServerModal');
    renameServerId = null;
}

async function submitRenameServer() {
    if (!renameServerId) return;
    const input = document.getElementById('renameServerInput');
    const newName = input ? input.value.trim() : '';
    if (!newName) {
        UI.toast(_('validation_failed') || 'Name cannot be empty', 'error');
        return;
    }
    try {
        await API.post(`/api/servers/${renameServerId}/rename`, { name: newName });
        UI.toast(_('server_renamed') || 'Server renamed', 'success');
        closeRenameServerModal();
        const titleEl = document.getElementById('serverNameTitle');
        if (titleEl) {
            titleEl.textContent = newName;
        }
        document.title = document.title.replace(/— .*$/, `— ${newName}`);
    } catch (err) {
        UI.toast(err.message, 'error');
    }
}

function isValidHost(host) {
    if (typeof host !== 'string') return false;
    host = host.trim();
    if (!host) return false;
    if (/\s/.test(host)) return false;
    if (host.includes('://')) return false;

    // IPv4 validation: 4 octets, 0-255
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/;
    if (ipv4Regex.test(host)) {
        return true;
    }

    // If string consists only of digits and dots, it is an invalid IPv4
    if (/^[\d.]+$/.test(host)) {
        return false;
    }

    // IPv6 validation: hex segments, colons, bracketed or unbracketed
    let ipv6Candidate = host;
    if (ipv6Candidate.startsWith('[') && ipv6Candidate.endsWith(']')) {
        ipv6Candidate = ipv6Candidate.slice(1, -1);
    }
    if (ipv6Candidate.includes(':')) {
        const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
        return ipv6Regex.test(ipv6Candidate);
    }

    // Hostname / FQDN validation: valid domain labels, a-z, 0-9, hyphens, dots, no leading/trailing hyphen
    if (host.length > 253) return false;
    const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return hostnameRegex.test(host);
}

function openEditHostModal(serverId, currentHost) {
    editHostServerId = serverId;
    const hostEl = document.getElementById('serverHostDisplay');
    const host = hostEl ? hostEl.textContent.trim() : (currentHost || '');
    const input = document.getElementById('editHostInput');
    if (input) {
        input.value = host;
    }
    openModal('editHostModal', '#editHostInput');
}

function closeEditHostModal() {
    closeModal('editHostModal');
    editHostServerId = null;
}

async function submitEditHost() {
    if (!editHostServerId) return;
    const serverId = editHostServerId;
    const input = document.getElementById('editHostInput');
    const newHost = input ? input.value.trim() : '';
    if (!isValidHost(newHost)) {
        UI.toast(_('validation_failed') || 'Invalid IP address or hostname', 'error');
        return;
    }
    try {
        await API.post('/api/servers/' + serverId + '/host', { host: newHost });
        UI.toast(_('server_host_updated') || 'Server IP updated', 'success');
        closeEditHostModal();
        const hostEl = document.getElementById('serverHostDisplay');
        if (hostEl) {
            hostEl.textContent = newHost;
        }
    } catch (err) {
        UI.toast(err.message, 'error');
    }
}

function initServerActions() {
    const awgProfileEl = document.getElementById('installAwgProfile');
    if (awgProfileEl) {
        awgProfileEl.addEventListener('change', function() {
            const cpsGroup = document.getElementById('awgCpsProtocolGroup');
            if (cpsGroup) {
                cpsGroup.style.display = (this.value === 'pro') ? 'block' : 'none';
            }
        });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initServerActions);
} else {
    initServerActions();
}

