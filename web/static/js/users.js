/* ===== Amnezia Nexus — User Administration & Client Connections Controller ===== */
// Extracted from web/templates/users.html per Issue #542 (Epic #475).

// Global State & Session Variables
let currentUserId = '';
let currentUsername = '';
let currentConfig = '';
let currentVpnLink = '';
let currentConfigName = 'connection';

let currentPage = 1;
let pageSize = 12;
let searchQuery = '';
let selectedRole = 'all';
let searchTimeout = null;
let userConnsTableInstance = null;
let currentSharedUser = null;

// Bootstrap configuration injected from template
const _usersPageData = window.usersPageData || {};
let serversData = _usersPageData.serversData || window.serversData || {};
let currentAdminUsername = _usersPageData.currentAdminUsername || window.currentAdminUsername || '';
let currentIsAdmin = _usersPageData.currentIsAdmin !== undefined ? Boolean(_usersPageData.currentIsAdmin) : Boolean(window.currentIsAdmin);
let currentUserID = _usersPageData.currentUserID || window.currentUserID || '';

// Expose state and synchronize with window for inline event handlers and external callers
Object.defineProperty(window, 'currentConfig', {
    get: () => currentConfig,
    set: (v) => { currentConfig = v; },
    configurable: true
});
Object.defineProperty(window, 'currentVpnLink', {
    get: () => currentVpnLink,
    set: (v) => { currentVpnLink = v; },
    configurable: true
});
Object.defineProperty(window, 'currentConfigName', {
    get: () => currentConfigName,
    set: (v) => { currentConfigName = v; },
    configurable: true
});
Object.defineProperty(window, 'currentUserId', {
    get: () => currentUserId,
    set: (v) => { currentUserId = v; },
    configurable: true
});
Object.defineProperty(window, 'currentUsername', {
    get: () => currentUsername,
    set: (v) => { currentUsername = v; },
    configurable: true
});
Object.defineProperty(window, 'currentSharedUser', {
    get: () => currentSharedUser,
    set: (v) => { currentSharedUser = v; },
    configurable: true
});
Object.defineProperty(window, 'currentPage', {
    get: () => currentPage,
    set: (v) => { currentPage = v; },
    configurable: true
});
Object.defineProperty(window, 'pageSize', {
    get: () => pageSize,
    set: (v) => { pageSize = v; },
    configurable: true
});

window.serversData = serversData;
window.currentAdminUsername = currentAdminUsername;
window.currentIsAdmin = currentIsAdmin;
window.currentUserID = currentUserID;

function handleSearch(val) {
    clearTimeout(searchTimeout);
    const clearBtn = document.getElementById('userSearchClear');
    if (clearBtn) {
        clearBtn.style.display = val ? 'flex' : 'none';
    }
    searchTimeout = setTimeout(() => {
        searchQuery = val.trim();
        currentPage = 1;
        refreshUsersList();
    }, 300);
}

function clearUserSearch() {
    const input = document.getElementById('userSearch');
    if (input) {
        input.value = '';
        handleSearch('');
        input.focus();
    }
}

function setRoleFilter(role) {
    selectedRole = role;
    document.querySelectorAll('#roleFilterChips .filter-chip').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-role') === role);
    });
    currentPage = 1;
    refreshUsersList();
}

function changePage(delta) {
    currentPage += delta;
    refreshUsersList();
}

async function refreshUsersList() {
    const loading = document.getElementById('usersLoading');
    const container = document.getElementById('usersContainer');
    const empty = document.getElementById('usersEmpty');
    const grid = document.getElementById('usersGrid');

    if (loading) loading.classList.remove('hidden');
    if (container) container.classList.add('hidden');
    if (empty) empty.classList.add('hidden');

    try {
        const data = await API.get(`/api/users?search=${encodeURIComponent(searchQuery)}&role=${encodeURIComponent(selectedRole)}&page=${currentPage}&size=${pageSize}`);

        if (!data.users || data.users.length === 0) {
            if (loading) loading.classList.add('hidden');
            if (empty) empty.classList.remove('hidden');
            return;
        }

        if (grid) {
            grid.innerHTML = data.users.map(u => {
                const initial = (u.username && u.username[0]) ? u.username[0].toUpperCase() : 'U';
                const roleClass = u.role === 'admin' ? 'badge-success' : (u.role === 'support' ? 'badge-info' : 'badge-warn');
                const roleLabel = (u.role || '').toUpperCase();
                const sourceLabel = UI.escapeHtml(u.source || 'Local');
                const enabledBadge = u.enabled ? '' : `<span class="badge badge-danger" style="font-size:0.65rem;">${_('disabled')}</span>`;

                // Traffic limit gauge
                let trafficHtml = '';
                if (u.traffic_limit && u.traffic_limit > 0) {
                    let pct = (u.traffic_used / u.traffic_limit) * 100;
                    if (pct > 100) pct = 100;
                    let barColor = pct > 90 ? 'var(--danger)' : (pct > 70 ? 'var(--warning)' : 'var(--accent)');
                    trafficHtml = `
                        <div style="margin-top: var(--space-sm); font-size: 0.75rem;">
                            <div style="display:flex; justify-content:space-between; color:var(--text-muted); margin-bottom: 4px;">
                                <span>${_('traffic')}: <strong>${Telemetry.formatBytes(u.traffic_used)}</strong></span>
                                <span>${_('out_of')} ${Telemetry.formatBytes(u.traffic_limit)}</span>
                            </div>
                            <div style="width: 100%; height: 6px; background: var(--bg-surface); border-radius: var(--radius-sm); overflow: hidden; border: 1px solid var(--border-color);">
                                <div style="background-color: ${barColor}; height: 100%; width: ${pct}%; transition: width 0.3s ease; border-radius: var(--radius-sm);"></div>
                            </div>
                        </div>
                    `;
                } else if (u.traffic_used > 0) {
                    trafficHtml = `
                        <div style="margin-top: var(--space-sm); font-size: 0.75rem; color:var(--text-muted);">
                            <span>${_('traffic')}: <strong>${Telemetry.formatBytes(u.traffic_used)}</strong></span>
                        </div>
                    `;
                }

                // Total traffic
                const totalTrafficHtml = u.traffic_total > 0
                    ? `<div class="client-meta" style="font-size: 0.75rem; opacity: 0.75; margin-top: 2px;">📈 ${_('traffic_used_total')}: ${Telemetry.formatBytes(u.traffic_total)}</div>`
                    : '';

                // Expiration
                const exp = u.expires_at || u.expiration_date;
                let expHtml = '';
                if (exp) {
                    const isExpired = new Date(exp) < new Date();
                    expHtml = `
                        <div class="client-meta" style="font-size: 0.75rem; margin-top: 4px;">
                            <span class="badge ${isExpired ? 'badge-danger' : 'badge-info'}" style="font-size: 0.65rem;">
                                ${isExpired ? _('expired') : _('expires')}: ${new Date(exp).toLocaleDateString()}
                            </span>
                        </div>
                    `;
                }

                const strategyHtml = (u.traffic_reset_strategy && u.traffic_reset_strategy !== 'never')
                    ? `<div class="client-meta" style="font-size: 0.75rem; opacity: 0.75; margin-top: 2px;">🔄 ${_('traffic_reset_strategy_label')}: ${_('traffic_reset_' + u.traffic_reset_strategy)}</div>`
                    : '';

                return `
                    <div class="card client-item user-card" id="user-${UI.escapeHtml(u.id)}" style="${u.enabled ? '' : 'opacity:0.65;'} padding: var(--space-md); margin-bottom: 0; display: flex; flex-direction: column; justify-content: space-between; border-radius: var(--radius-md); border: 1px solid var(--border-color); background: var(--bg-card);">
                        <div class="client-info" style="gap: var(--space-md); align-items: flex-start;">
                            <div class="client-avatar user-avatar-circle" style="width: 44px; height: 44px; min-width: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; background: var(--bg-surface); border: 1px solid var(--border-color); font-weight: 700; font-size: 1.1rem; color: var(--accent); flex-shrink: 0;">
                                ${initial}
                            </div>
                            <div style="flex: 1; min-width: 0;">
                                <div class="client-name" style="display: flex; align-items: center; gap: var(--space-xs); flex-wrap: wrap;">
                                    <span style="font-weight: 600; font-size: 1rem; color: var(--text-primary);">${UI.escapeHtml(u.username)}</span>
                                    <span class="badge ${roleClass}" style="font-size:0.65rem;">${roleLabel}</span>
                                    <span class="badge badge-secondary" style="font-size:0.65rem;">${sourceLabel}</span>
                                    ${enabledBadge}
                                </div>
                                <div class="client-meta" style="display: flex; flex-wrap: wrap; gap: var(--space-sm); margin-top: var(--space-xs); font-size: 0.8rem; color: var(--text-muted); align-items: center;">
                                    <span style="cursor:pointer; color:var(--accent); text-decoration: none; display: inline-flex; align-items: center; gap: 4px; font-weight: 500;"
                                          data-uid="${UI.escapeHtml(u.id)}" data-uname="${UI.escapeHtml(u.username)}"
                                          onclick="viewUserConnections(this.dataset.uid, this.dataset.uname)"
                                          title="${_('connections')}">
                                        <svg class="icon" style="width:13px;height:13px;"><use href="#icon-network"></use></svg>
                                        ${u.connections_count || 0} ${_('connections')}
                                    </span>
                                    ${u.created_at ? `<span style="display: inline-flex; align-items: center; gap: 4px;"><svg class="icon text-muted" style="width:12px;height:12px;"><use href="#icon-activity"></use></svg> ${u.created_at.substring(0, 10)}</span>` : ''}
                                    ${u.telegramId ? `<span style="display: inline-flex; align-items: center; gap: 4px;"><svg class="icon text-muted" style="width:12px;height:12px;"><use href="#icon-send"></use></svg> @${UI.escapeHtml(u.telegramId.replace(/^@/, ''))}</span>` : ''}
                                    ${u.email ? `<span style="display: inline-flex; align-items: center; gap: 4px;">✉️ ${UI.escapeHtml(u.email)}</span>` : ''}
                                </div>
                                ${u.description ? `<div class="client-meta" style="font-size: 0.75rem; opacity: 0.85; margin-top: var(--space-xs); color: var(--text-secondary);">${UI.escapeHtml(u.description)}</div>` : ''}
                                ${trafficHtml}
                                ${totalTrafficHtml}
                                ${expHtml}
                                ${strategyHtml}
                            </div>
                        </div>
                        <div class="client-actions" style="display: flex; gap: var(--space-xs); align-items: center; justify-content: flex-end; flex-wrap: wrap; margin-top: var(--space-md); padding-top: var(--space-sm); border-top: 1px solid var(--border-color);">
                            ${currentIsAdmin ? `
                            <button class="btn btn-ghost btn-sm btn-icon"
                                    data-uid="${UI.escapeHtml(u.id)}" data-uname="${UI.escapeHtml(u.username)}"
                                    onclick="openAddConnectionForUser(this.dataset.uid, this.dataset.uname)"
                                    title="${_('add_connection')}"
                                    aria-label="${_('add_connection')}">
                                <svg class="icon"><use href="#icon-plus"></use></svg>
                            </button>
                            <button class="btn btn-ghost btn-sm btn-icon"
                                    onclick="openEditUser(this.dataset)"
                                    data-id="${UI.escapeHtml(u.id)}"
                                    data-username="${UI.escapeHtml(u.username)}"
                                    data-tg="${UI.escapeHtml(u.telegramId || '')}"
                                    data-email="${UI.escapeHtml(u.email || '')}"
                                    data-desc="${UI.escapeHtml(u.description || '')}"
                                    data-limit="${u.traffic_limit ? (u.traffic_limit / Math.pow(1024, 3)).toFixed(2) : 0}"
                                    data-strategy="${UI.escapeHtml(u.traffic_reset_strategy || 'never')}"
                                    data-expiration="${UI.escapeHtml(u.expires_at || u.expiration_date || '')}"
                                    title="${_('edit')}"
                                    aria-label="${_('edit')}">
                                <svg class="icon"><use href="#icon-pencil"></use></svg>
                            </button>
                            <button class="btn btn-ghost btn-sm btn-icon" onclick="openShareModal(this.dataset)"
                                    data-id="${UI.escapeHtml(u.id)}" data-username="${UI.escapeHtml(u.username)}" data-token="${UI.escapeHtml(u.share_token || '')}"
                                    data-enabled="${u.share_enabled ? 'true' : 'false'}"
                                    data-haspassword="${u.has_share_password ? 'true' : 'false'}"
                                    title="${_('share_access')}"
                                    aria-label="${_('share_access')}">
                                <svg class="icon"><use href="#icon-file-text"></use></svg>
                            </button>
                            ${u.id !== currentUserID ? `
                                <button class="btn btn-ghost btn-sm btn-icon ${u.enabled ? '' : 'btn-success-hover'}" onclick="toggleUser(this.dataset)"
                                        data-id="${UI.escapeHtml(u.id)}" data-enable="${u.enabled ? 'false' : 'true'}"
                                        title="${u.enabled ? _('user_disable') : _('user_enable')}"
                                        aria-label="${u.enabled ? _('user_disable') : _('user_enable')}">
                                    ${u.enabled
                                        ? `<svg class="icon text-muted"><use href="#icon-pause"></use></svg>`
                                        : `<svg class="icon" style="color: var(--success);"><use href="#icon-play"></use></svg>`}
                                </button>
                                <button class="btn btn-ghost btn-sm btn-icon btn-danger-hover" style="color:var(--danger);" onclick="deleteUser(this.dataset.id)"
                                        data-id="${UI.escapeHtml(u.id)}"
                                        title="${_('delete')}"
                                        aria-label="${_('delete')}">
                                    <svg class="icon"><use href="#icon-trash"></use></svg>
                                </button>
                            ` : ''}
                            ` : ''}
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Pagination UI
        const pageInfo = document.getElementById('pageInfo');
        if (pageInfo) pageInfo.textContent = _('page_info').replace('{}', data.page).replace('{}', data.pages || 1);
        const prevPage = document.getElementById('prevPage');
        if (prevPage) prevPage.disabled = (data.page <= 1);
        const nextPage = document.getElementById('nextPage');
        if (nextPage) nextPage.disabled = (data.page >= data.pages);

        if (loading) loading.classList.add('hidden');
        if (container) container.classList.remove('hidden');
    } catch (err) {
        UI.toast(`${_('error')}: ` + err.message, 'error');
    }
}

function updateProtocols(serverId, selectId, groupId = null) {
    const select = document.getElementById(selectId);
    if (!select) return;
    const group = groupId ? document.getElementById(groupId) : null;
    select.innerHTML = '';

    if (serverId === '') {
        if (group) group.style.display = 'none';
        const mimicryGroup = document.getElementById('newUserMimicryGroup');
        if (selectId === 'newUserProtocol' && mimicryGroup) mimicryGroup.style.display = 'none';
        const ucMimicryGroup = document.getElementById('ucAwgMimicryGroup');
        if (selectId === 'ucProtocol' && ucMimicryGroup) ucMimicryGroup.style.display = 'none';
        return;
    }

    const server = serversData[serverId];
    const protocols = (server && server.protocols) ? server.protocols : {};
    let count = 0;

    for (const [key, info] of Object.entries(protocols)) {
        if (info && info.installed) {
            const opt = document.createElement('option');
            opt.value = key;
            opt.textContent = key === 'awg' ? 'AmneziaWG' : (key === 'telemt' ? 'MTProxyL' : (key === 'dns' ? 'AmneziaDNS' : key.toUpperCase()));
            select.appendChild(opt);
            count++;
        }
    }

    if (count > 0) {
        if (group) group.style.display = '';
        if (selectId === 'newUserProtocol') {
            const mimicryGroup = document.getElementById('newUserMimicryGroup');
            if (mimicryGroup) mimicryGroup.style.display = select.value === 'awg' ? '' : 'none';
        }
        if (selectId === 'ucProtocol') {
            const ucMimicryGroup = document.getElementById('ucAwgMimicryGroup');
            if (ucMimicryGroup) ucMimicryGroup.style.display = select.value === 'awg' ? '' : 'none';
        }
    } else {
        const opt = document.createElement('option');
        opt.textContent = _('no_protocols');
        opt.disabled = true;
        select.appendChild(opt);
        if (group) group.style.display = '';
        if (selectId === 'newUserProtocol') {
            const mimicryGroup = document.getElementById('newUserMimicryGroup');
            if (mimicryGroup) mimicryGroup.style.display = 'none';
        }
        if (selectId === 'ucProtocol') {
            const ucMimicryGroup = document.getElementById('ucAwgMimicryGroup');
            if (ucMimicryGroup) ucMimicryGroup.style.display = 'none';
        }
    }
}

function initUserSelectListeners() {
    const newUserServer = document.getElementById('newUserServer');
    if (newUserServer) {
        newUserServer.addEventListener('change', (e) => {
            const show = e.target.value !== '';
            updateProtocols(e.target.value, 'newUserProtocol', 'newUserProtoGroup');
            const connGroup = document.getElementById('newUserConnNameGroup');
            if (connGroup) connGroup.style.display = show ? '' : 'none';
        });
    }

    const newUserProtocol = document.getElementById('newUserProtocol');
    if (newUserProtocol) {
        newUserProtocol.addEventListener('change', (e) => {
            const mimicryGroup = document.getElementById('newUserMimicryGroup');
            if (mimicryGroup) mimicryGroup.style.display = e.target.value === 'awg' ? '' : 'none';
        });
    }

    const ucServer = document.getElementById('ucServer');
    if (ucServer) {
        ucServer.addEventListener('change', (e) => {
            updateProtocols(e.target.value, 'ucProtocol');
            const ucMode = document.getElementById('ucMode');
            if (ucMode && ucMode.value === 'existing') {
                fetchExistingClients();
            }
        });
    }

    const ucProtocol = document.getElementById('ucProtocol');
    if (ucProtocol) {
        ucProtocol.addEventListener('change', (e) => {
            const ucAwgMimicryGroup = document.getElementById('ucAwgMimicryGroup');
            if (ucAwgMimicryGroup) ucAwgMimicryGroup.style.display = e.target.value === 'awg' ? '' : 'none';
            const ucMode = document.getElementById('ucMode');
            if (ucMode && ucMode.value === 'existing') {
                fetchExistingClients();
            }
        });
    }
}

async function addUser(e) {
    e.preventDefault();
    const btn = document.getElementById('addUserBtn');
    const text = document.getElementById('addUserBtnText');
    const spinner = document.getElementById('addUserSpinner');
    if (btn) btn.disabled = true;
    if (text) text.textContent = _('creating');
    if (spinner) spinner.classList.remove('hidden');
    try {
        const body = {
            username: document.getElementById('newUsername').value,
            password: document.getElementById('newPassword').value,
            role: document.getElementById('newRole').value,
            telegramId: document.getElementById('newTelegramId').value || null,
            email: document.getElementById('newEmail').value || null,
            description: document.getElementById('newDescription').value || null,
            traffic_limit: parseFloat(document.getElementById('newTrafficLimit').value || '0'),
            traffic_reset_strategy: document.getElementById('newTrafficResetStrategy').value,
            expiration_date: document.getElementById('newExpirationDate').value || null,
            expires_at: document.getElementById('newExpirationDate').value || null,
        };
        const serverId = document.getElementById('newUserServer').value;
        if (serverId !== '') {
            body.server_id = parseInt(serverId);
            body.protocol = document.getElementById('newUserProtocol').value;
            body.connection_name = document.getElementById('newUserConnName').value || null;
            if (body.protocol === 'awg') {
                body.awg_mimicry = document.getElementById('newUserAwgMimicry').value || 'auto';
            }
        }
        const result = await API.post('/api/users/add', body);
        UI.toast(_('success'), 'success');

        if (result.config) {
            currentConfig = result.config;
            currentVpnLink = result.vpn_link || '';
            currentConfigName = body.username;
            document.getElementById('configModalTitle').textContent = `${_('config')} — ${body.username}`;
            document.getElementById('configText').textContent = result.config;
            document.getElementById('vpnLinkText').textContent = currentVpnLink;
            switchConfigTab('conf');
            closeModal('addUserModal');
            openModal('configModal');
            generateQR(result.config);
        } else {
            closeModal('addUserModal');
            refreshUsersList();
        }
    } catch (err) {
        UI.toast(`${_('error')}: ` + err.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
        if (text) text.textContent = _('create');
        if (spinner) spinner.classList.add('hidden');
    }
}

async function deleteUser(userId) {
    const confirmed = await UI.confirm({
        title: _('delete_user_title') || 'Delete User',
        message: _('delete_user_confirm') || 'Are you sure you want to delete this user?',
        confirmText: _('delete') || 'Delete',
        confirmVariant: 'danger'
    });
    if (!confirmed) return;

    try {
        await API.post(`/api/users/${userId}/delete`);
        UI.toast(_('success'), 'success');
        refreshUsersList();
    } catch (err) {
        UI.toast(`${_('error')}: ` + err.message, 'error');
    }
}

async function toggleUser(dataset) {
    try {
        const userId = dataset.id;
        const enable = dataset.enable === 'true';
        const action = enable ? _('enabling') : _('disabling');
        UI.toast(`${action}...`, 'info');
        await API.post(`/api/users/${userId}/toggle`, { enabled: enable });
        UI.toast(enable ? _('user_enabled') : _('user_disabled'), 'success');
        refreshUsersList();
    } catch (err) {
        UI.toast(`${_('error')}: ` + err.message, 'error');
    }
}

function openAddConnectionForUser(userId, username) {
    currentUserId = userId;
    if (document.getElementById('ucUserId')) document.getElementById('ucUserId').value = userId;
    document.getElementById('addUserConnTitle').textContent = `${_('add_connection')} — ${username}`;
    document.getElementById('ucName').value = `${username}_vpn`;
    document.getElementById('ucMode').value = 'new';
    toggleUCMode();
    updateProtocols(document.getElementById('ucServer').value, 'ucProtocol');
    openModal('addUserConnModal');
}

function toggleUCMode() {
    const mode = document.getElementById('ucMode').value;
    const existingGroup = document.getElementById('ucExistingClientGroup');
    const ucAddBtnText = document.getElementById('ucAddBtnText');

    if (mode === 'existing') {
        if (existingGroup) existingGroup.style.display = 'block';
        if (ucAddBtnText) ucAddBtnText.textContent = _('linking');
        fetchExistingClients();
    } else {
        if (existingGroup) existingGroup.style.display = 'none';
        if (ucAddBtnText) ucAddBtnText.textContent = _('add');
    }
}

async function fetchExistingClients() {
    const serverId = document.getElementById('ucServer').value;
    const protocol = document.getElementById('ucProtocol').value;
    const select = document.getElementById('ucExistingClient');
    if (!select) return;
    select.innerHTML = `<option value="">${_('loading')}</option>`;

    try {
        const data = await API.get(`/api/servers/${serverId}/${protocol}/clients`);
        if (!data.clients || data.clients.length === 0) {
            select.innerHTML = `<option value="">${_('no_free_conns')}</option>`;
            return;
        }
        select.innerHTML = '';
        data.clients.forEach(c => {
            select.innerHTML += `<option value="${UI.escapeHtml(c.id)}">${UI.escapeHtml(c.name || 'Unnamed')} (${UI.escapeHtml(c.id.substring(0, 8))}...)</option>`;
        });
    } catch (err) {
        select.innerHTML = `<option value="">${_('error')}: ${UI.escapeHtml(err.message)}</option>`;
    }
}

async function doAddUserConnection() {
    const btn = document.getElementById('ucAddBtn');
    const text = document.getElementById('ucAddBtnText');
    const spinner = document.getElementById('ucAddSpinner');
    if (btn) btn.disabled = true;

    const mode = document.getElementById('ucMode').value;
    if (text) text.textContent = mode === 'existing' ? _('linking') : _('creating');
    if (spinner) spinner.classList.remove('hidden');

    try {
        const body = {
            server_id: parseInt(document.getElementById('ucServer').value),
            protocol: document.getElementById('ucProtocol').value,
            name: document.getElementById('ucName').value || 'VPN Connection',
        };

        if (body.protocol === 'awg') {
            body.awg_mimicry = document.getElementById('ucAwgMimicry').value || 'auto';
        }

        if (mode === 'existing') {
            const clientId = document.getElementById('ucExistingClient').value;
            if (!clientId) throw new Error(_('select_connection'));
            body.client_id = clientId;
        }

        const result = await API.post(`/api/users/${currentUserId}/connections/add`, body);
        UI.toast(mode === 'existing' ? _('conn_linked') : _('connection_created').replace('{}', body.name), 'success');
        closeModal('addUserConnModal');

        if (result.config) {
            currentConfig = result.config;
            currentVpnLink = result.vpn_link || '';
            currentConfigName = document.getElementById('ucName').value.replace(/\s+/g, '_');
            document.getElementById('configModalTitle').textContent = _('config');
            document.getElementById('configText').textContent = result.config;
            document.getElementById('vpnLinkText').textContent = currentVpnLink;
            switchConfigTab('conf');
            openModal('configModal');
            generateQR(result.config);
        }
        refreshUsersList();
    } catch (err) {
        UI.toast(`${_('error')}: ` + err.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
        if (text) text.textContent = _('create');
        if (spinner) spinner.classList.add('hidden');
    }
}

async function viewUserConnections(userId, username) {
    currentUserId = userId;
    currentUsername = username;
    document.getElementById('userConnsTitle').textContent = `${_('connections')} — ${username}`;
    const tableContainer = document.getElementById('userConnsTableContainer');
    const emptyEl = document.getElementById('userConnsEmpty');
    const tbody = document.getElementById('userConnsTableBody');
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:var(--space-xl);color:var(--text-muted);"><div class="spinner" style="width:24px;height:24px;margin:0 auto var(--space-sm);"></div>${_('loading')}</td></tr>`;
    tableContainer.style.display = 'block';
    emptyEl.classList.add('hidden');
    openModal('userConnsModal');

    try {
        const data = await API.get(`/api/users/${userId}/connections`);
        if (!data.connections || data.connections.length === 0) {
            tableContainer.style.display = 'none';
            emptyEl.classList.remove('hidden');
            return;
        }

        tbody.innerHTML = '';
        const protoDisplay = {
            awg: 'AmneziaWG',
            telemt: 'MTProxyL',
            dns: 'AmneziaDNS',
        };

        data.connections.forEach(c => {
            const totalRx = c.traffic_total_rx || 0;
            const totalTx = c.traffic_total_tx || 0;
            const totalTraffic = (c.traffic_total || (totalRx + totalTx)) || 0;
            const protoLabel = protoDisplay[c.protocol] || (c.protocol ? c.protocol.toUpperCase() : '');

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>
                    <div class="flex items-center gap-xs">
                        <svg class="icon text-muted" style="width:14px;height:14px;"><use href="#icon-network"></use></svg>
                        <span style="font-weight:600;">${UI.escapeHtml(c.name || 'Connection')}</span>
                    </div>
                </td>
                <td>${(Number(c.server_id) === 0) ? 'Cluster (Auto)' : UI.escapeHtml(c.server_name || ('#' + c.server_id))}</td>
                <td><span class="badge badge-info">${UI.escapeHtml(protoLabel)}</span></td>
                <td data-sort-val="${totalTraffic}">
                    <div class="traffic-cell" style="font-size:0.8rem;">
                        <span>↓ ${Telemetry.formatBytes(totalRx)}</span>
                        <span>↑ ${Telemetry.formatBytes(totalTx)}</span>
                    </div>
                </td>
                <td style="text-align: right;">
                    <div class="flex items-center justify-end gap-xs">
                        <button type="button" class="btn btn-ghost btn-sm btn-icon" title="${_('copy_config')}" aria-label="${_('copy_config')}"
                                onclick="copyUserConnectionDirect('${UI.escapeJs(c.id)}', ${Number(c.server_id)}, '${UI.escapeJs(c.client_id)}', '${UI.escapeJs(c.protocol)}', this)">
                            <svg class="icon"><use href="#icon-copy"></use></svg>
                        </button>
                        <button type="button" class="btn btn-ghost btn-sm btn-icon" title="${_('config')}" aria-label="${_('config')}"
                                onclick="showUserConnectionConfig('${UI.escapeJs(c.id)}', ${Number(c.server_id)}, '${UI.escapeJs(c.client_id)}', '${UI.escapeJs(c.protocol)}', '${UI.escapeJs(c.name || 'VPN')}')">
                            <svg class="icon"><use href="#icon-file-text"></use></svg>
                        </button>
                        <button type="button" class="btn btn-ghost btn-sm btn-icon btn-danger-hover" style="color:var(--danger);" title="${_('delete')}" aria-label="${_('delete')}"
                                onclick="unlinkUserConnection('${UI.escapeJs(c.id)}', ${Number(c.server_id)}, '${UI.escapeJs(c.client_id)}', '${UI.escapeJs(c.protocol)}', '${UI.escapeJs(c.name || 'VPN')}')">
                            <svg class="icon"><use href="#icon-trash"></use></svg>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });

        if (userConnsTableInstance) {
            userConnsTableInstance.refresh();
        } else {
            userConnsTableInstance = new NexusTable('#userConnsTable', {
                searchable: true,
                sortable: true,
                paginate: true,
                pageSize: 5,
                searchPlaceholder: _('search') || 'Search connections...',
                emptyMessage: _('no_connections') || 'No connections found'
            });
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="color:var(--danger);padding:var(--space-md);text-align:center;">${_('error')}: ${UI.escapeHtml(err.message)}</td></tr>`;
    }
}

async function copyUserConnectionDirect(connIdOrServerId, serverIdOrClientId, clientIdOrProto, protocolOrBtn, maybeBtn) {
    let connId, serverId, clientId, protocol, btnEl;
    if (typeof connIdOrServerId === 'number') {
        serverId = connIdOrServerId;
        clientId = serverIdOrClientId;
        protocol = clientIdOrProto;
        btnEl = protocolOrBtn;
        connId = '';
    } else {
        connId = connIdOrServerId;
        serverId = serverIdOrClientId;
        clientId = clientIdOrProto;
        protocol = protocolOrBtn;
        btnEl = maybeBtn;
    }

    try {
        let result;
        if (Number(serverId) === 0 && (!clientId || clientId === '')) {
            result = await API.post(`/api/connections/${connId}/config`);
        } else {
            result = await API.post(`/api/servers/${serverId}/connections/config`, {
                protocol: protocol,
                client_id: clientId || connId,
            });
        }
        if (result && result.config) {
            await UI.copy(result.config, btnEl);
        } else {
            UI.toast(_('config_unavailable') || 'Config unavailable', 'warning');
        }
    } catch (err) {
        UI.toast((_('error') || 'Error') + ': ' + err.message, 'error');
    }
}

async function unlinkUserConnection(connIdOrServerId, serverIdOrClientId, clientIdOrProto, protocolOrName, maybeName) {
    let connId, serverId, clientId, protocol, connName;
    if (typeof connIdOrServerId === 'number') {
        serverId = connIdOrServerId;
        clientId = serverIdOrClientId;
        protocol = clientIdOrProto;
        connName = protocolOrName || 'VPN';
        connId = '';
    } else {
        connId = connIdOrServerId;
        serverId = serverIdOrClientId;
        clientId = clientIdOrProto;
        protocol = protocolOrName;
        connName = maybeName || 'VPN';
    }

    const confirmed = await UI.confirm({
        title: _('delete_connection') || 'Delete Connection',
        message: _('delete_conn_confirm') || `Are you sure you want to delete connection "${connName}"?`,
        confirmText: _('delete') || 'Delete',
        confirmVariant: 'danger'
    });
    if (!confirmed) return;

    try {
        if (Number(serverId) === 0 && (!clientId || clientId === '')) {
            await API.post(`/api/connections/${connId}/delete`);
        } else {
            await API.post(`/api/servers/${serverId}/connections/remove`, {
                protocol: protocol,
                client_id: clientId || connId,
            });
        }
        UI.toast(_('success'), 'success');
        await viewUserConnections(currentUserId, currentUsername);
        refreshUsersList();
    } catch (err) {
        UI.toast((_('error') || 'Error') + ': ' + err.message, 'error');
    }
}

function switchConfigTab(tab) {
    document.querySelectorAll('.config-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.config-panel').forEach(p => p.classList.remove('active'));
    const tabs = document.querySelectorAll('.config-tab');
    const panels = { conf: 'panel-conf', vpn: 'panel-vpn', qr: 'panel-qr' };
    const tabIdx = { conf: 0, vpn: 1, qr: 2 };
    if (tabs[tabIdx[tab]]) tabs[tabIdx[tab]].classList.add('active');
    const panel = document.getElementById(panels[tab]);
    if (panel) panel.classList.add('active');
}

function generateQR(text) {
    const container = document.getElementById('qrCode');
    if (!container) return;
    container.innerHTML = '';
    try {
        new QRCode(container, { text, width: 280, height: 280, colorDark: '#000000', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.L });
    } catch (e) {
        container.innerHTML = `<div style="color:var(--text-muted);">${_('qr_error')}</div>`;
    }
}

async function showUserConnectionConfig(connIdOrServerId, serverIdOrClientId, clientIdOrProto, protocolOrName, maybeName) {
    let connId, serverId, clientId, protocol, connName;
    if (typeof connIdOrServerId === 'number') {
        serverId = connIdOrServerId;
        clientId = serverIdOrClientId;
        protocol = clientIdOrProto;
        connName = protocolOrName || 'VPN';
        connId = '';
    } else {
        connId = connIdOrServerId;
        serverId = serverIdOrClientId;
        clientId = clientIdOrProto;
        protocol = protocolOrName;
        connName = maybeName || 'VPN';
    }

    try {
        UI.toast(_('loading'), 'info');
        let result;
        if (Number(serverId) === 0 && (!clientId || clientId === '')) {
            result = await API.post(`/api/connections/${connId}/config`);
        } else {
            result = await API.post(`/api/servers/${serverId}/connections/config`, {
                protocol: protocol,
                client_id: clientId || connId,
            });
        }
        if (result && result.config) {
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
        UI.toast(`${_('error')}: ` + err.message, 'error');
    }
}

function openEditUser(data) {
    document.getElementById('editUserId').value = data.id;
    document.getElementById('editUserTitle').textContent = data.username;
    if (document.getElementById('editUsername')) document.getElementById('editUsername').value = data.username;
    document.getElementById('editUserTG').value = data.tg || '';
    if (document.getElementById('editTelegramId')) document.getElementById('editTelegramId').value = data.tg || '';
    document.getElementById('editUserEmail').value = data.email || '';
    if (document.getElementById('editEmail')) document.getElementById('editEmail').value = data.email || '';
    document.getElementById('editUserDesc').value = data.desc || '';
    if (document.getElementById('editDescription')) document.getElementById('editDescription').value = data.desc || '';
    document.getElementById('editUserLimit').value = data.limit || '0';
    if (document.getElementById('editTrafficLimit')) document.getElementById('editTrafficLimit').value = data.limit || '0';
    document.getElementById('editUserTrafficResetStrategy').value = data.strategy || 'never';
    if (document.getElementById('editTrafficResetStrategy')) document.getElementById('editTrafficResetStrategy').value = data.strategy || 'never';
    document.getElementById('editUserExpiration').value = data.expiration || '';
    if (document.getElementById('editExpirationDate')) document.getElementById('editExpirationDate').value = data.expiration || '';
    document.getElementById('editUserPass').value = '';
    openModal('editUserModal');
}

async function saveEditUser() {
    const uid = document.getElementById('editUserId').value;
    const btn = document.getElementById('saveEditBtn');
    const text = document.getElementById('saveEditBtnText');
    const spinner = document.getElementById('saveEditSpinner');

    const payload = {
        telegramId: document.getElementById('editUserTG').value,
        email: document.getElementById('editUserEmail').value,
        description: document.getElementById('editUserDesc').value,
        traffic_limit: parseFloat(document.getElementById('editUserLimit').value || '0'),
        traffic_reset_strategy: document.getElementById('editUserTrafficResetStrategy').value,
        expiration_date: document.getElementById('editUserExpiration').value || null,
        expires_at: document.getElementById('editUserExpiration').value || null,
        password: document.getElementById('editUserPass').value || null
    };

    if (btn) btn.disabled = true;
    if (text) text.textContent = _('saving');
    if (spinner) spinner.classList.remove('hidden');

    try {
        await API.post(`/api/users/${uid}/update`, payload);
        UI.toast(_('success'), 'success');
        closeModal('editUserModal');
        refreshUsersList();
    } catch (err) {
        UI.toast(`${_('error')}: ` + err.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
        if (text) text.textContent = _('save');
        if (spinner) spinner.classList.add('hidden');
    }
}

function openShareModal(dataset) {
    currentSharedUser = dataset.id;
    document.getElementById('shareModalTitle').textContent = `${_('share_access')} — ${dataset.username}`;
    if (document.getElementById('shareUserId')) document.getElementById('shareUserId').value = dataset.id;
    if (document.getElementById('shareUsername')) document.getElementById('shareUsername').value = dataset.username;
    document.getElementById('shareEnabled').checked = dataset.enabled === 'true';
    document.getElementById('sharePassword').value = '';

    let token = dataset.token;
    if (!token || token === '') {
        token = Math.random().toString(36).substring(2, 15);
    }
    const link = window.location.origin + '/share/' + token;
    document.getElementById('shareLink').value = link;
    if (document.getElementById('shareLinkInput')) document.getElementById('shareLinkInput').value = link;

    updateShareSetup();
    openModal('shareUserModal');
}

function updateShareSetup() {
    const enabled = document.getElementById('shareEnabled').checked;
    const setupFields = document.getElementById('shareSetupFields');
    if (setupFields) setupFields.style.display = enabled ? '' : 'none';
}

async function saveShareSetup() {
    const btn = document.getElementById('saveShareBtn');
    const text = document.getElementById('saveShareBtnText');
    const spinner = document.getElementById('saveShareSpinner');

    if (btn) btn.disabled = true;
    if (text) text.textContent = _('saving');
    if (spinner) spinner.classList.remove('hidden');

    try {
        const body = {
            enabled: document.getElementById('shareEnabled').checked,
            password: document.getElementById('sharePassword').value
        };
        const result = await API.post(`/api/users/${currentSharedUser}/share/setup`, body);
        if (result.share_token) {
            const link = window.location.origin + '/share/' + result.share_token;
            document.getElementById('shareLink').value = link;
        }
        UI.toast(_('success'), 'success');
        closeModal('shareUserModal');
        refreshUsersList();
    } catch (err) {
        UI.toast(err.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
        if (text) text.textContent = _('save');
        if (spinner) spinner.classList.add('hidden');
    }
}

async function copyShareLink(btnEl) {
    const input = document.getElementById('shareLink');
    if (!input || !input.value) return;
    await UI.copy(input.value, btnEl);
}

// Expose functions globally for inline template event handlers
window.handleSearch = handleSearch;
window.clearUserSearch = clearUserSearch;
window.setRoleFilter = setRoleFilter;
window.changePage = changePage;
window.refreshUsersList = refreshUsersList;
window.updateProtocols = updateProtocols;
window.addUser = addUser;
window.deleteUser = deleteUser;
window.toggleUser = toggleUser;
window.openAddConnectionForUser = openAddConnectionForUser;
window.toggleUCMode = toggleUCMode;
window.fetchExistingClients = fetchExistingClients;
window.doAddUserConnection = doAddUserConnection;
window.viewUserConnections = viewUserConnections;
window.copyUserConnectionDirect = copyUserConnectionDirect;
window.unlinkUserConnection = unlinkUserConnection;
window.switchConfigTab = switchConfigTab;
window.generateQR = generateQR;
window.showUserConnectionConfig = showUserConnectionConfig;
window.openEditUser = openEditUser;
window.saveEditUser = saveEditUser;
window.openShareModal = openShareModal;
window.updateShareSetup = updateShareSetup;
window.saveShareSetup = saveShareSetup;
window.copyShareLink = copyShareLink;

// Automatic DOM initialization
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        initUserSelectListeners();
        refreshUsersList();
    });
} else {
    initUserSelectListeners();
    refreshUsersList();
}
