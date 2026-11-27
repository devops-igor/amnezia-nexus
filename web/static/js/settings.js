    document.getElementById('ssl_enabled').addEventListener('change', (e) => {
        document.getElementById('sslFields').style.display = e.target.checked ? 'block' : 'none';
    });

    const tgEnabledCheck = document.getElementById('telegram_enabled');
    if (tgEnabledCheck) {
        tgEnabledCheck.addEventListener('change', (e) => {
            const tgFields = document.getElementById('telegramFields');
            if (tgFields) tgFields.style.display = e.target.checked ? 'block' : 'none';
        });
    }

    async function handleRestore(e) {
        const file = e.target.files[0];
        if (!file) return;

        const confirmed = await UI.confirmWith('destructive', {
            title: _('restore_backup'),
            message: _('restore_confirm'),
            confirmText: _('restore_backup'),
            // A restore overwrites the current data and restarts the panel, so the
            // confirming control carries the destructive variant, not a warning.
            confirmVariant: 'danger'
        });

        if (!confirmed) {
            e.target.value = '';
            return;
        }

        const btn = document.getElementById('restoreBtn');
        const text = document.getElementById('restoreBtnText');
        const spinner = document.getElementById('restoreSpinner');
        btn.disabled = true;
        text.textContent = _('loading');
        spinner.classList.remove('hidden');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const data = await API.post('/api/settings/backup/restore', formData);
            if (data.status === 'success') {
                UI.toast(_('restore_success'), 'success');
                setTimeout(() => window.location.reload(), 2000);
            } else {
                UI.toast(data.error || _('invalid_backup_file'), 'error');
            }
        } catch (err) {
            UI.toast(`${_('error')}: ` + (err.message || err), 'error');
        } finally {
            btn.disabled = false;
            text.textContent = _('restore_backup');
            spinner.classList.add('hidden');
            e.target.value = '';
        }
    }

    async function checkUpstreamStatus(force) {
        const btn = document.getElementById('upstreamCheckBtn');
        const spinner = document.getElementById('upstreamSpinner');
        const overallBadge = document.getElementById('upstreamOverallBadge');
        const banner = document.getElementById('upstreamUpdateBanner');
        const checkedAtSpan = document.getElementById('upstreamCheckedAt');

        if (btn) btn.disabled = true;
        if (spinner) spinner.classList.remove('hidden');

        try {
            const url = force ? '/api/system/upstream-status?refresh=true' : '/api/system/upstream-status';
            const data = await API.get(url, {silent: true});

            if (!data) return;

            if (data.checked_at && checkedAtSpan) {
                const date = new Date(data.checked_at);
                checkedAtSpan.textContent = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            }

            if (data.base_image && document.getElementById('upstreamBaseImage')) {
                document.getElementById('upstreamBaseImage').textContent = data.base_image;
            }

            if (data.components && Array.isArray(data.components)) {
                data.components.forEach(comp => {
                    const pinnedEl = document.getElementById('pinned-' + comp.name);
                    const latestEl = document.getElementById('latest-' + comp.name);
                    const badgeEl = document.getElementById('badge-' + comp.name);
                    const linkEl = document.getElementById('repoLink-' + comp.name);

                    if (pinnedEl && comp.pinned_version) pinnedEl.textContent = comp.pinned_version;
                    if (latestEl && comp.latest_version) latestEl.textContent = comp.latest_version;
                    if (linkEl && comp.release_url) linkEl.href = comp.release_url;

                    if (badgeEl) {
                        if (comp.error) {
                            badgeEl.className = 'badge badge-secondary';
                            badgeEl.textContent = 'Error';
                            badgeEl.title = comp.error;
                        } else if (comp.update_available) {
                            badgeEl.className = 'badge badge-warning';
                            badgeEl.textContent = _('update_available') || 'Update available';
                            badgeEl.title = '';
                        } else {
                            badgeEl.className = 'badge badge-success';
                            badgeEl.textContent = _('up_to_date') || 'Up to date';
                            badgeEl.title = '';
                        }
                    }
                });
            }

            if (overallBadge) {
                if (data.status === 'degraded') {
                    overallBadge.className = 'badge badge-secondary';
                    overallBadge.textContent = _('status_degraded') || 'Degraded';
                } else if (data.status === 'error') {
                    overallBadge.className = 'badge badge-secondary';
                    overallBadge.textContent = _('error') || 'Error';
                } else if (data.update_available) {
                    overallBadge.className = 'badge badge-warning';
                    overallBadge.textContent = _('update_available') || 'Update available';
                } else {
                    overallBadge.className = 'badge badge-success';
                    overallBadge.textContent = _('up_to_date') || 'Up to date';
                }
            }

            if (banner) {
                banner.style.display = data.update_available ? 'block' : 'none';
            }
        } catch (err) {
            console.error('Failed to fetch upstream status:', err);
            if (overallBadge) {
                overallBadge.className = 'badge badge-secondary';
                overallBadge.textContent = _('error') || 'Error';
            }
        } finally {
            if (btn) btn.disabled = false;
            if (spinner) spinner.classList.add('hidden');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        checkUpstreamStatus(false);
    });
