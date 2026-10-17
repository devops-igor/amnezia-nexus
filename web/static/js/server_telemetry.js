/* ===== Amnezia Nexus — Server Page Telemetry & Background Polling ===== */
// Extracted from web/templates/server.html per Issue #502 (Epic #475 Phase 3).

const STATS_REFRESH_INTERVAL_MS = 30000;
let telemetryInitialized = false;
let installedProtocols = {};
let connectionsTableInstance = null;

// ========== Server Stats ==========
async function loadServerStats() {
    try {
        const stats = await API.post(`/api/servers/${SERVER_ID}/stats`, null, { silent: true });
        if (!stats || typeof stats !== 'object' || stats.error || Object.keys(stats).length === 0 || (stats.ram_total === 0 && stats.disk_total === 0)) {
            throw new Error(stats && stats.error ? stats.error : 'Empty or invalid server stats');
        }
        const el = document.getElementById('serverStats');
        if (el) {
            el.style.display = '';
            el.innerHTML = `
            <span class="stat-pill" title="CPU"><svg class="icon" style="width:12px;height:12px;"><use href="#icon-activity"></use></svg> CPU: ${stats.cpu || 0}%</span>
            <span class="stat-pill" title="RAM: ${UI.formatBytes(stats.ram_used)} / ${UI.formatBytes(stats.ram_total)}"><svg class="icon" style="width:12px;height:12px;"><use href="#icon-server"></use></svg> RAM: ${stats.ram_percent || 0}%</span>
            <span class="stat-pill" title="Disk: ${UI.formatBytes(stats.disk_used)} / ${UI.formatBytes(stats.disk_total)}"><svg class="icon" style="width:12px;height:12px;"><use href="#icon-server"></use></svg> Disk: ${stats.disk_percent || 0}%</span>
            <span class="stat-pill" title="Network"><svg class="icon" style="width:12px;height:12px;"><use href="#icon-network"></use></svg> ↓${UI.formatBytes(stats.net_rx)} ↑${UI.formatBytes(stats.net_tx)}</span>
        `;
        }
        return stats;
    } catch (err) {
        console.warn('Stats load failed:', err);
        throw err;
    }
}

// ========== Reachability & Network Health ==========
async function updateReachability() {
    try {
        const data = await API.get(`/api/servers/${SERVER_ID}/reachability`, { silent: true });
        const reach = (data && typeof data.reachability === 'object' && data.reachability !== null)
            ? data.reachability
            : { reachable: !!data.reachable, latency_ms: data.latency_ms, last_checked: data.last_checked };
        const overallBadge = document.getElementById('reachabilityOverallBadge');
        const mimicryBadges = document.getElementById('mimicryHealthBadges');
        const awgMimicryBadges = document.getElementById('awg-mimicry-health');
        const lastCheckedEl = document.getElementById('reachabilityLastChecked');

        if (!overallBadge) return;

        if (!reach) {
            overallBadge.innerHTML = `<span class="badge badge-warn" style="font-size: 0.75rem; padding: 2px 8px;"><span class="badge-dot"></span> ${_('pending')}</span>`;
            if (mimicryBadges) mimicryBadges.innerHTML = '';
            if (awgMimicryBadges) awgMimicryBadges.innerHTML = '';
            if (lastCheckedEl) lastCheckedEl.textContent = '';
            return;
        }

        if (reach.reachable) {
            const latency = (reach.latency_ms !== null && reach.latency_ms !== undefined) ? `${reach.latency_ms}ms` : _('reachable');
            let badgeClass = 'badge-success';
            if (reach.latency_ms !== null && reach.latency_ms !== undefined) {
                if (reach.latency_ms >= 150) {
                    badgeClass = 'badge-danger';
                } else if (reach.latency_ms >= 50) {
                    badgeClass = 'badge-warn';
                }
            }
            overallBadge.innerHTML = `<span class="badge ${badgeClass}" style="font-size: 0.75rem; padding: 2px 8px;"><span class="badge-dot"></span> ${UI.escapeHtml(latency)}</span>`;
        } else {
            overallBadge.innerHTML = `<span class="badge badge-danger" style="font-size: 0.75rem; padding: 2px 8px;"><span class="badge-dot"></span> ${_('unreachable')}</span>`;
        }

        if (lastCheckedEl && reach.last_checked) {
            const timeStr = reach.last_checked.length >= 19 ? reach.last_checked.substring(11, 19) : reach.last_checked;
            lastCheckedEl.textContent = `⏱ ${timeStr}`;
            lastCheckedEl.title = reach.last_checked;
        }

        if (reach.auto_trials && typeof reach.auto_trials === 'object') {
            const profiles = ['tls', 'quic', 'dns', 'sip'];
            let badgesHtml = '';
            for (const p of profiles) {
                const trial = reach.auto_trials[p];
                const label = p.toUpperCase();
                if (trial && trial.reachable) {
                    const lat = (trial.latency_ms !== null && trial.latency_ms !== undefined) ? ` (${trial.latency_ms}ms)` : '';
                    let trialBadgeClass = 'badge-success';
                    if (trial.latency_ms !== null && trial.latency_ms !== undefined) {
                        if (trial.latency_ms >= 150) trialBadgeClass = 'badge-danger';
                        else if (trial.latency_ms >= 50) trialBadgeClass = 'badge-warn';
                    }
                    badgesHtml += `<span class="badge ${trialBadgeClass}" id="mimicry-badge-${UI.escapeHtml(p)}" style="font-size: 0.7rem; padding: 2px 6px;" title="${UI.escapeHtml(label)}: ${_('reachable')}${UI.escapeHtml(lat)}"><span class="badge-dot"></span> ${UI.escapeHtml(label)}</span>`;
                } else if (trial && !trial.reachable) {
                    badgesHtml += `<span class="badge badge-danger" id="mimicry-badge-${UI.escapeHtml(p)}" style="font-size: 0.7rem; padding: 2px 6px;" title="${UI.escapeHtml(label)}: ${_('unreachable')}"><span class="badge-dot"></span> ${UI.escapeHtml(label)}</span>`;
                } else {
                    badgesHtml += `<span class="badge badge-warn" id="mimicry-badge-${UI.escapeHtml(p)}" style="font-size: 0.7rem; padding: 2px 6px; opacity: 0.7;" title="${UI.escapeHtml(label)}: ${_('pending')}"><span class="badge-dot"></span> ${UI.escapeHtml(label)}</span>`;
                }
            }
            if (mimicryBadges) mimicryBadges.innerHTML = badgesHtml;
            if (awgMimicryBadges) awgMimicryBadges.innerHTML = badgesHtml;
        }
        return reach;
    } catch (err) {
        console.warn('Reachability update failed:', err);
        throw err;
    }
}

// ========== Server Check ==========
async function checkServer() {
    const btn = document.getElementById('checkBtn');
    const text = document.getElementById('checkBtnText');
    const spinner = document.getElementById('checkSpinner');
    const icon = document.getElementById('checkIcon');
    if (btn) btn.disabled = true;
    if (text) text.textContent = _('server_checking');
    if (spinner) spinner.classList.remove('hidden');
    if (icon) icon.classList.add('hidden');
    try {
        const data = await API.post(`/api/servers/${SERVER_ID}/check`);
        const statusDiv = document.getElementById('serverStatus');
        const badges = document.getElementById('statusBadges');
        if (statusDiv) statusDiv.classList.remove('hidden');
        let html = '';
        if (data && data.connection === 'ok') {
            html += `<span class="badge badge-success"><span class="badge-dot"></span> ${_('ssh_ok')}</span>`;
        }
        if (data && data.docker_installed) {
            html += `<span class="badge badge-success"><span class="badge-dot"></span> ${_('docker_ok')}</span>`;
        } else {
            html += `<span class="badge badge-warn"><span class="badge-dot"></span> ${_('docker_not_installed')}</span>`;
        }
        if (badges) badges.innerHTML = html;
        if (data && data.protocols) {
            const protoSelect = document.getElementById('connProtoSelect');
            if (protoSelect) {
                const currentVal = protoSelect.value;
                protoSelect.innerHTML = '';
                let firstVal = null;

                for (const [proto, info] of Object.entries(data.protocols)) {
                    updateProtocolCard(proto, info);
                    const isVPN = ['awg', 'telemt'].includes(proto);
                    if (info.container_running && isVPN) {
                        const opt = document.createElement('option');
                        opt.value = proto;
                        opt.textContent = getProtoTitle(proto);
                        protoSelect.appendChild(opt);
                        if (!firstVal) firstVal = proto;
                    }
                }

                if (protoSelect.innerHTML === '') {
                    const opt = document.createElement('option');
                    opt.textContent = _('no_protocols');
                    opt.disabled = true;
                    protoSelect.appendChild(opt);
                    hideConnectionsSection();
                } else {
                    if (data.protocols[currentVal] && data.protocols[currentVal].container_running) {
                        protoSelect.value = currentVal;
                    } else if (firstVal) {
                        protoSelect.value = firstVal;
                    }
                    loadConnections();
                }
            } else {
                for (const [proto, info] of Object.entries(data.protocols)) {
                    updateProtocolCard(proto, info);
                }
            }
        }
        updateStatusCounts((data && data.protocols) || {});
        updateReachability();
        UI.toast(_('check_done'), 'success');
        return data;
    } catch (err) {
        UI.toast(_('error') + ': ' + (err && err.message ? err.message : String(err)), 'error');
        const statusDiv = document.getElementById('serverStatus');
        const badges = document.getElementById('statusBadges');
        if (statusDiv) statusDiv.classList.remove('hidden');
        if (badges) badges.innerHTML = `<span class="badge badge-danger"><span class="badge-dot"></span> ${_('check_error')}</span>`;
    } finally {
        if (btn) btn.disabled = false;
        if (text) text.textContent = _('server_check');
        if (spinner) spinner.classList.add('hidden');
        if (icon) icon.classList.remove('hidden');
    }
}

function updateStatusCounts(protocols) {
    const protos = ['awg', 'telemt'];
    const servs = ['dns'];
    let pRunning = 0, pTotal = protos.length;
    let sRunning = 0, sTotal = servs.length;
    protos.forEach(p => {
        if (protocols && protocols[p] && protocols[p].container_running) pRunning++;
    });
    servs.forEach(s => {
        if (protocols && protocols[s] && protocols[s].container_running) sRunning++;
    });
    const protoCountEl = document.getElementById('protocols-count');
    if (protoCountEl) protoCountEl.textContent = `${pRunning}/${pTotal}`;
    const servCountEl = document.getElementById('services-count');
    if (servCountEl) servCountEl.textContent = `${sRunning}/${sTotal}`;
}

function updateProtocolCard(proto, info) {
    const protoKey = proto.replace('_', '-');
    const statusEl = document.getElementById(`${protoKey}-status`);
    const infoEl = document.getElementById(`${protoKey}-info`);
    const infoGrid = document.getElementById(`${protoKey}-info-grid`);
    const actionsEl = document.getElementById(`${protoKey}-actions`);
    const ctrlEl = document.getElementById(`${protoKey}-ctrl`);

    if (info && info.container_running) {
        installedProtocols[proto] = true;
        if (statusEl) statusEl.innerHTML = `<span class="badge badge-success"><span class="badge-dot"></span> ${_('run')}</span>`;
        if (info.port || info.clients_count !== undefined) {
            if (infoEl) infoEl.classList.remove('hidden');
            let grid = '';
            if (info.port) {
                if (proto === 'dns') {
                    grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('port')}</span><span class="protocol-info-value">172.29.172.254:53 (Internal)</span></div>`;
                } else {
                    grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('port')}</span><span class="protocol-info-value">${info.port}/${(proto === 'telemt') ? 'TCP' : 'UDP'}</span></div>`;
                }
            }
            if (info.clients_count !== undefined) grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('connections')}</span><span class="protocol-info-value">${info.clients_count}</span></div>`;
            // AWG obfuscation params
            if (proto === 'awg' && info.awg_params) {
                const p = info.awg_params;
                if (p.mtu) grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('awg_mtu')}</span><span class="protocol-info-value">${p.mtu}</span></div>`;
                const jParts = [];
                if (p.junk_packet_count) jParts.push(`Jc=${UI.escapeHtml(String(p.junk_packet_count))}`);
                if (p.junk_packet_min_size) jParts.push(`Jmin=${UI.escapeHtml(String(p.junk_packet_min_size))}`);
                if (p.junk_packet_max_size) jParts.push(`Jmax=${UI.escapeHtml(String(p.junk_packet_max_size))}`);
                if (jParts.length) grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('awg_junk_packets')}</span><span class="protocol-info-value">${jParts.join(' ')}</span></div>`;
                const sParts = [];
                const sLabels = {init_packet_junk_size:'S1', response_packet_junk_size:'S2', cookie_reply_packet_junk_size:'S3', transport_packet_junk_size:'S4'};
                for (const [key, label] of Object.entries(sLabels)) {
                    if (p[key]) sParts.push(`${label}=${UI.escapeHtml(String(p[key]))}`);
                }
                if (sParts.length) grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('awg_junk_sizes')}</span><span class="protocol-info-value">${sParts.join(' ')}</span></div>`;
                const hLabels = {init_packet_magic_header:'H1', response_packet_magic_header:'H2', underload_packet_magic_header:'H3', transport_packet_magic_header:'H4'};
                const hParts = [];
                for (const [key, label] of Object.entries(hLabels)) {
                    if (p[key]) hParts.push(`${label}=${UI.escapeHtml(String(p[key]))}`);
                }
                if (hParts.length) grid += `<div class="protocol-info-item"><span class="protocol-info-label">${_('awg_magic_headers')}</span><span class="protocol-info-value">${hParts.join(' ')}</span></div>`;
            }
            if (infoGrid) infoGrid.innerHTML = grid;
        }
        if (actionsEl) {
            if (proto === 'dns') {
                actionsEl.innerHTML = `
                    <button class="btn btn-danger btn-sm" onclick="uninstallProtocol('${proto}')" style="flex:1">
                        <svg class="icon"><use href="#icon-trash"></use></svg> ${_('uninstall')}
                    </button>
                `;
            } else {
                actionsEl.innerHTML = `
                    <button class="btn btn-secondary btn-sm" onclick="selectProtocolForConns('${proto}')" style="flex:1">
                        <svg class="icon"><use href="#icon-network"></use></svg> ${_('connections')}
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="uninstallProtocol('${proto}')">
                        <svg class="icon"><use href="#icon-trash"></use></svg> ${_('uninstall')}
                    </button>
                `;
                showConnectionsSection();
            }
        }
        // Show control buttons (stop + config)
        if (ctrlEl) {
            ctrlEl.style.cssText = '';
            if (proto === 'dns') {
                ctrlEl.innerHTML = `
                    <button class="btn btn-danger btn-sm" onclick="toggleContainer('${proto}', true)" title="${_('stop_container_confirm').replace('{}', '')}">
                        <svg class="icon"><use href="#icon-x"></use></svg> ${_('stop_btn')}
                    </button>
                `;
            } else {
                ctrlEl.innerHTML = `
                    <button class="btn btn-secondary btn-sm" onclick="showServerConfig('${proto}')" title="${_('server_config')}">
                        <svg class="icon"><use href="#icon-settings"></use></svg> ${_('config_btn')}
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="toggleContainer('${proto}', true)" title="${_('stop_container_confirm').replace('{}', '')}">
                        <svg class="icon"><use href="#icon-x"></use></svg> ${_('stop_btn')}
                    </button>
                `;
            }
        }
    } else if (info && info.container_exists) {
        installedProtocols[proto] = false;
        if (statusEl) statusEl.innerHTML = `<span class="badge badge-danger"><span class="badge-dot"></span> ${_('stop')}</span>`;
        if (actionsEl) {
            if (proto === 'dns') {
                actionsEl.innerHTML = `
                    <button class="btn btn-danger btn-sm" onclick="uninstallProtocol('${proto}')" style="flex:1">
                        <svg class="icon"><use href="#icon-trash"></use></svg> ${_('uninstall')}
                    </button>
                `;
            } else {
                actionsEl.innerHTML = `
                    <button class="btn btn-primary btn-sm" onclick="openInstallModal('${proto}')" style="flex:1">
                        <svg class="icon"><use href="#icon-refresh"></use></svg> ${_('reinstall')}
                    </button>
                    <button class="btn btn-danger btn-sm" onclick="uninstallProtocol('${proto}')">
                        <svg class="icon"><use href="#icon-trash"></use></svg> ${_('uninstall')}
                    </button>
                `;
            }
        }
        // Show control buttons (start + config)
        if (ctrlEl) {
            ctrlEl.style.cssText = '';
            if (proto === 'dns') {
                ctrlEl.innerHTML = `
                    <button class="btn btn-primary btn-sm" onclick="toggleContainer('${proto}', false)" title="${_('start_container_confirm').replace('{}', '')}">
                        <svg class="icon"><use href="#icon-refresh"></use></svg> ${_('start_btn')}
                    </button>
                `;
            } else {
                ctrlEl.innerHTML = `
                    <button class="btn btn-secondary btn-sm" onclick="showServerConfig('${proto}')" title="${_('server_config')}">
                        <svg class="icon"><use href="#icon-settings"></use></svg> ${_('config_btn')}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="toggleContainer('${proto}', false)" title="${_('start_container_confirm').replace('{}', '')}">
                        <svg class="icon"><use href="#icon-refresh"></use></svg> ${_('start_btn')}
                    </button>
                `;
            }
        }
    } else {
        installedProtocols[proto] = false;
        if (statusEl) statusEl.innerHTML = `<span class="badge badge-warn"><span class="badge-dot"></span> ${_('not_installed')}</span>`;
        if (actionsEl) {
            actionsEl.innerHTML = `
                <button class="btn btn-primary btn-sm" onclick="openInstallModal('${proto}')" style="flex:1">
                    <svg class="icon"><use href="#icon-plus"></use></svg> ${_('install')}
                </button>
            `;
        }
        if (ctrlEl) {
            ctrlEl.style.cssText = 'display:none!important;';
            ctrlEl.innerHTML = '';
        }
    }
}

function showConnectionsSection() {
    const section = document.getElementById('connectionsSection');
    if (section) section.style.display = 'block';
}

function hideConnectionsSection() {
    const section = document.getElementById('connectionsSection');
    if (section) section.style.display = 'none';
    const select = document.getElementById('connProtoSelect');
    if (select) {
        select.innerHTML = '';
        const opt = document.createElement('option');
        opt.textContent = _('no_protocols');
        opt.disabled = true;
        select.appendChild(opt);
    }
}

function selectProtocolForConns(proto) {
    const section = document.getElementById('connectionsSection');
    if (section) section.style.display = '';
    const select = document.getElementById('connProtoSelect');
    if (select) {
        const hasOpt = Array.from(select.options || []).some(o => o.value === proto);
        select.value = hasOpt ? proto : '';
    }
    loadConnections();
    if (section && typeof section.scrollIntoView === 'function') {
        section.scrollIntoView({ behavior: 'smooth' });
    }
}

async function loadConnections() {
    const selectEl = document.getElementById('connProtoSelect');
    const proto = selectEl ? selectEl.value : '';
    const loading = document.getElementById('connectionsLoading');
    const emptyEl = document.getElementById('connectionsEmpty');
    const tableContainer = document.getElementById('connectionsTableContainer');
    const tableBody = document.getElementById('connectionsTableBody');

    if (!proto) {
        if (loading) loading.style.display = 'none';
        return;
    }

    if (loading) loading.style.display = '';
    if (emptyEl) emptyEl.classList.add('hidden');
    if (tableContainer) tableContainer.style.display = 'none';
    if (tableBody) tableBody.innerHTML = '';
    try {
        const data = await API.get(`/api/servers/${SERVER_ID}/connections?protocol=${proto}`);
        if (loading) loading.style.display = 'none';
        if (!data || !data.clients || data.clients.length === 0) {
            if (emptyEl) emptyEl.classList.remove('hidden');
            if (tableContainer) tableContainer.style.display = 'none';
            return;
        }
        window.connectionsStore = {};
        data.clients.forEach((client, idx) => {
            const userData = client.userData || {};
            userData.assigned_user_id = client.assigned_user_id || '';
            userData.clientId = client.clientId || '';
            if (client.name) {
                userData.name = client.name;
                userData.clientName = client.name;
            }
            window.connectionsStore[client.clientId] = userData;
            const name = userData.clientName || client.name || `Connection ${idx}`;
            const created = userData.creationDate || '';
            const handshake = userData.latestHandshake || '';
            const received = userData.dataReceived || '';
            const sent = userData.dataSent || '';
            const initial = name.charAt(0).toUpperCase();
            const enabled = (client.enabled !== undefined) ? client.enabled : (userData.enabled !== false);
            const assignedUser = client.assigned_user || '';
            const clientIp = client.clientIp || userData.clientIp || client.clientId || '—';

            // Metadata tags below name
            let metaHtml = '';
            if (assignedUser) metaHtml += `<span class="badge badge-info" style="font-size:0.65rem;"><svg class="icon" style="width:10px;height:10px;"><use href="#icon-user"></use></svg> ${UI.escapeHtml(assignedUser)}</span>`;
            if (created) metaHtml += `<span>📅 ${formatDate(created)}</span>`;

            // Status & Mimicry column
            let statusHtml = '';
            if (enabled) {
                statusHtml += `<span class="badge badge-success"><span class="badge-dot"></span> ${_('active') || 'Active'}</span>`;
                if (handshake) statusHtml += ` <span style="font-size:0.75rem; color:var(--text-muted);">🤝 ${UI.escapeHtml(handshake)}</span>`;
            } else {
                statusHtml += `<span class="badge badge-danger"><span class="badge-dot"></span> ${_('stop')}</span>`;
            }

            if (proto === 'awg') {
                const mimicry = userData.awg_mimicry || 'auto';
                if (mimicry === 'auto') {
                    statusHtml += ` <span class="badge badge-info" style="font-size:0.65rem;">🛡 ${_('mimicry_auto')}</span>`;
                } else {
                    statusHtml += ` <span class="badge badge-success" style="font-size:0.65rem;">🔒 ${UI.escapeHtml(mimicry.toUpperCase())}</span>`;
                }
            } else if (proto === 'telemt' && userData.current_connections !== undefined) {
                statusHtml += ` <span style="font-size:0.75rem; color:var(--text-muted);">🔌 ${UI.escapeHtml(String(userData.current_connections))} conns</span>`;
            }

            // Traffic Rx/Tx column
            let trafficHtml = '';
            let numericBytes = 0;
            if (proto === 'telemt') {
                const octets = userData.total_octets || 0;
                numericBytes = octets;
                trafficHtml = `<span class="traffic-badge">📊 ${UI.escapeHtml(UI.formatBytes(octets))}</span>`;
            } else {
                trafficHtml = `<div class="traffic-cell"><span class="traffic-badge traffic-down">↓ ${UI.escapeHtml(received || '0 B')}</span><span class="traffic-badge traffic-up">↑ ${UI.escapeHtml(sent || '0 B')}</span></div>`;
            }

            // Quota badge (telemt quota shares the traffic column)
            let quotaHtml = `<span class="text-muted" style="font-size:0.8rem;">—</span>`;
            if (proto === 'telemt' && userData.quota) {
                quotaHtml = `<span class="badge" style="font-size:0.7rem;">Quota: ${UI.escapeHtml(UI.formatBytes(userData.quota))}</span>`;
            }

            const toggleTitle = enabled ? _('stop') : _('starting');
            const awgRotateBtn = proto === 'awg' ? `<button class="btn btn-ghost btn-sm btn-icon" data-cid="${UI.escapeHtml(client.clientId)}" onclick="rotateClientMimicry(this.dataset.cid)" title="${_('rotate_profile')}"><svg class="icon"><use href="#icon-refresh"></use></svg></button>` : '';

            const tr = document.createElement('tr');
            tr.setAttribute('data-status', enabled ? 'active' : 'stopped');
            if (!enabled) tr.style.opacity = '0.6';

            tr.innerHTML = `
                <td>
                    <div class="conn-name-cell">
                        <div class="client-avatar">${UI.escapeHtml(initial)}</div>
                        <div>
                            <div style="font-weight:600; color:var(--text-primary);">${UI.escapeHtml(name)}</div>
                            <div class="flex gap-xs items-center" style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">
                                ${metaHtml}
                            </div>
                        </div>
                    </div>
                </td>
                <td>
                    <code style="font-size:0.8rem; font-family:var(--font-mono, monospace);">${UI.escapeHtml(clientIp)}</code>
                </td>
                <td>${statusHtml}</td>
                <td data-sort-val="${numericBytes}">${trafficHtml}${quotaHtml !== `<span class="text-muted" style="font-size:0.8rem;">—</span>` ? ' ' + quotaHtml : ''}</td>
                <td data-searchable="false" style="text-align: right;">
                    <div class="client-actions">
                        <button class="btn btn-ghost btn-sm btn-icon" data-cid="${UI.escapeHtml(client.clientId)}" data-cname="${UI.escapeHtml(name)}" onclick="copyConnectionConfig(this.dataset.cid, this.dataset.cname, this)" title="${_('copy')}">
                            <svg class="icon"><use href="#icon-copy"></use></svg>
                        </button>
                        <button class="btn btn-ghost btn-sm btn-icon" data-cid="${UI.escapeHtml(client.clientId)}" data-cname="${UI.escapeHtml(name)}" data-haskey="${!!userData.clientPrivateKey || proto === 'telemt'}" onclick="showConnectionConfig(this.dataset.cid, this.dataset.cname, this.dataset.haskey === 'true')" title="${_('config')}">
                            <svg class="icon"><use href="#icon-file-text"></use></svg>
                        </button>
                        ${awgRotateBtn}
                        ${proto === 'telemt' ? `<button class="btn btn-ghost btn-sm btn-icon" data-cid="${UI.escapeHtml(client.clientId)}" onclick="editConnection(this.dataset.cid)" title="${_('edit')}"><svg class="icon"><use href="#icon-pencil"></use></svg></button>` : ''}
                        <button class="btn btn-ghost btn-sm btn-icon" data-cid="${UI.escapeHtml(client.clientId)}" data-enabled="${!enabled}" onclick="toggleConnection(this.dataset.cid, this.dataset.enabled === 'true')" title="${toggleTitle}">
                            <span class="badge-dot" style="background:${enabled ? 'var(--success)' : 'var(--text-muted)'}; width:10px; height:10px; display:inline-block;"></span>
                        </button>
                        <button class="btn btn-ghost btn-sm btn-icon" style="color:var(--danger);" data-cid="${UI.escapeHtml(client.clientId)}" onclick="removeConnection(this.dataset.cid)" title="${_('delete')}">
                            <svg class="icon"><use href="#icon-trash"></use></svg>
                        </button>
                    </div>
                </td>
            `;
            if (tableBody) tableBody.appendChild(tr);
        });

        if (tableContainer) tableContainer.style.display = '';

        if (connectionsTableInstance) {
            connectionsTableInstance.refresh();
        } else if (typeof NexusTable !== 'undefined') {
            connectionsTableInstance = new NexusTable('#connectionsTable', {
                searchable: true,
                sortable: true,
                paginate: true,
                pageSize: 10,
                searchPlaceholder: _('search') || 'Search connections...',
                emptyMessage: _('no_matching_records') || 'No matching connections found'
            });
        }
    } catch (err) {
        if (loading) loading.style.display = 'none';
        UI.toast(_('loading_connections_error') + ': ' + (err && err.message ? err.message : String(err)), 'error');
    }
}

// ========== Background Polling Lifecycle ==========
function startServerTelemetryPolling() {
    if (typeof Telemetry !== 'undefined' && typeof Telemetry.poll === 'function') {
        Telemetry.poll('server-stats-' + SERVER_ID, loadServerStats, STATS_REFRESH_INTERVAL_MS);
        Telemetry.poll('server-reachability-' + SERVER_ID, updateReachability, STATS_REFRESH_INTERVAL_MS);
    }
}

function stopServerTelemetryPolling() {
    if (typeof Telemetry !== 'undefined' && typeof Telemetry.stop === 'function') {
        Telemetry.stop('server-stats-' + SERVER_ID);
        Telemetry.stop('server-reachability-' + SERVER_ID);
    }
    telemetryInitialized = false;
}

function initServerTelemetry() {
    if (telemetryInitialized) return;
    telemetryInitialized = true;
    checkServer();
    startServerTelemetryPolling();
}
