/**
 * Amnezia Nexus — administrator notification settings (epic #785 phase 1).
 *
 * Loads the masked policy from the admin API, saves it, sends one explicit
 * test through the durable dispatcher and renders the real delivery history.
 * Nothing is mutated until the initial read succeeds, so a slow read cannot
 * overwrite stored configuration with markup defaults.
 */
(function (root) {
    'use strict';

    var state = {
        loaded: false,
        loading: false,
        saving: false,
        testing: false,
        tokenSet: false,
        maxAttempts: 6
    };

    function byId(id) {
        return typeof document !== 'undefined' ? document.getElementById(id) : null;
    }

    function translate(key, fallback) {
        if (typeof root._ === 'function') {
            var value = root._(key);
            if (value && value !== key) return value;
        }
        return fallback || key;
    }

    var CARD = 'notificationsCard';

    // cardReport writes a commit result into this card. The page toast is only a
    // fallback for a page that did not load the card module.
    function cardReport(kind, message) {
        if (root.SettingsCards && root.SettingsCards.report(CARD, kind, message)) return;
        if (root.UI && root.UI.toast) root.UI.toast(message, kind === 'success' ? 'success' : 'error');
    }

    // cardRebase makes what the card now shows its saved state, so the dirty
    // badge clears once a stored record has been applied.
    function cardRebase() {
        if (root.SettingsCards) root.SettingsCards.rebase(CARD);
    }

    function setBusy(buttonId, spinnerId, textId, busy, text) {
        var button = byId(buttonId);
        var spinner = byId(spinnerId);
        var label = textId ? byId(textId) : null;
        if (button) button.disabled = busy;
        if (spinner) spinner.classList.toggle('hidden', !busy);
        if (label && text) label.textContent = text;
    }

    function categoryInputs() {
        return typeof document !== 'undefined'
            ? Array.prototype.slice.call(document.querySelectorAll('.notification-category'))
            : [];
    }

    function renderSettings(settings) {
        var enabled = byId('notifications_enabled');
        var url = byId('notifications_url');
        var token = byId('notifications_token');
        var severity = byId('notifications_min_severity');
        var cooldown = byId('notifications_cooldown');
        if (enabled) enabled.checked = !!settings.enabled;
        if (url) url.value = settings.url || '';
        state.tokenSet = !!settings.app_token_set;
        if (token) {
            token.value = '';
            token.placeholder = state.tokenSet ? '********' : '';
        }
        if (severity) severity.value = settings.min_severity || 'info';
        if (cooldown) cooldown.value = String(settings.cooldown_seconds == null ? 60 : settings.cooldown_seconds);
        state.maxAttempts = settings.max_attempts || 6;
        var categories = settings.categories || {};
        categoryInputs().forEach(function (input) {
            var key = input.getAttribute('data-category');
            input.checked = categories[key] !== false;
        });
        toggleFields();
        cardRebase();
    }

    function toggleFields() {
        var enabled = byId('notifications_enabled');
        var fields = byId('notificationFields');
        if (enabled && fields) fields.style.display = enabled.checked ? 'block' : 'none';
    }

    async function load() {
        if (state.loading) return;
        state.loading = true;
        try {
            var settings = await root.API.get('/api/notifications/settings', { silent: true });
            renderSettings(settings || {});
            state.loaded = true;
            var saveBtn = byId('notificationSaveBtn');
            var testBtn = byId('notificationTestBtn');
            if (saveBtn) saveBtn.disabled = false;
            if (testBtn) testBtn.disabled = false;
            await loadHistory();
        } catch (err) {
            state.loaded = false;
            showTestResult(translate('notifications_load_failed', 'Could not load notification settings') + ': ' + (err.message || err), true);
            var save = byId('notificationSaveBtn');
            var test = byId('notificationTestBtn');
            if (save) save.disabled = true;
            if (test) test.disabled = true;
        } finally {
            state.loading = false;
        }
    }

    function collect() {
        var categories = {};
        categoryInputs().forEach(function (input) {
            categories[input.getAttribute('data-category')] = !!input.checked;
        });
        var cooldown = parseInt((byId('notifications_cooldown') || {}).value || '60', 10);
        if (!isFinite(cooldown)) cooldown = 60;
        var tokenInput = byId('notifications_token');
        return {
            enabled: !!(byId('notifications_enabled') || {}).checked,
            url: ((byId('notifications_url') || {}).value || '').trim(),
            app_token: tokenInput ? tokenInput.value.trim() : '',
            min_severity: (byId('notifications_min_severity') || {}).value || 'info',
            categories: categories,
            cooldown_seconds: cooldown,
            max_attempts: state.maxAttempts
        };
    }

    async function save(silent) {
        if (!state.loaded || state.saving) return false;
        state.saving = true;
        setBusy('notificationSaveBtn', 'notificationSaveSpinner', 'notificationSaveBtnText', true, translate('loading', 'Loading'));
        try {
            var saved = await root.API.post('/api/notifications/settings', collect(), { silent: true });
            renderSettings(saved || {});
            if (!silent) cardReport('success', translate('settings_saved', 'Settings saved'));
            return true;
        } catch (err) {
            cardReport('error', err.message || String(err));
            return false;
        } finally {
            state.saving = false;
            setBusy('notificationSaveBtn', 'notificationSaveSpinner', 'notificationSaveBtnText', false, translate('save_changes', 'Save changes'));
        }
    }

    async function testConnection() {
        if (!state.loaded || state.testing) return;
        // Test exactly the configuration the administrator sees. Persist it
        // first, so a passing test cannot belong to a different destination.
        var saved = await save(true);
        if (!saved) {
            showTestResult(translate('notifications_test_save_failed', 'Save the notification settings before testing'), true);
            return;
        }
        state.testing = true;
        setBusy('notificationTestBtn', 'notificationTestSpinner', 'notificationTestBtnText', true, translate('notifications_test_sending', 'Sending test…'));
        showTestResult(translate('notifications_test_sending', 'Sending test…'), false);
        try {
            var result = await root.API.post('/api/notifications/test', {}, { silent: true });
            var status = result && result.status;
            if (status === 'sent') {
                showTestResult(translate('notifications_test_sent', 'Test notification accepted by Gotify'), false);
            } else {
                showTestResult(translate('notifications_test_failed', 'Test notification was not delivered') + ': ' + ((result && (result.reason || status)) || ''), true);
            }
            await loadHistory();
        } catch (err) {
            showTestResult(translate('notifications_test_failed', 'Test notification was not delivered') + ': ' + (err.message || err), true);
            await loadHistory();
        } finally {
            state.testing = false;
            setBusy('notificationTestBtn', 'notificationTestSpinner', 'notificationTestBtnText', false, translate('notifications_test', 'Send test'));
        }
    }

    function showTestResult(message, isError) {
        var target = byId('notificationTestResult');
        if (!target) return;
        target.textContent = message;
        target.style.color = isError ? 'var(--color-danger, #e5484d)' : 'var(--color-success, #2f9e44)';
    }

    async function loadHistory() {
        var container = byId('notificationHistory');
        if (!container) return;
        try {
            var data = await root.API.get('/api/notifications/history?limit=25', { silent: true });
            renderHistory(container, (data && data.events) || []);
        } catch (err) {
            container.textContent = translate('notifications_history_failed', 'Could not load notification history');
        }
    }

    function renderHistory(container, items) {
        while (container.firstChild) container.removeChild(container.firstChild);
        if (!items.length) {
            var empty = document.createElement('span');
            empty.className = 'text-muted';
            empty.textContent = translate('notifications_history_empty', 'No notifications yet');
            container.appendChild(empty);
            return;
        }
        items.forEach(function (item) {
            var event = item.event || {};
            var delivery = item.delivery || {};
            var row = document.createElement('div');
            row.style.padding = 'var(--space-sm) 0';
            row.style.borderTop = '1px solid var(--border-color)';

            var title = document.createElement('div');
            title.style.display = 'flex';
            title.style.justifyContent = 'space-between';
            title.style.gap = 'var(--space-sm)';
            var summary = document.createElement('strong');
            summary.textContent = event.summary || event.type || '';
            var status = document.createElement('span');
            status.className = 'badge badge-secondary';
            status.textContent = translate('notifications_status_' + (delivery.status || 'pending'), delivery.status || 'pending');
            title.appendChild(summary);
            title.appendChild(status);

            var meta = document.createElement('div');
            meta.className = 'text-muted';
            meta.style.fontSize = '0.78rem';
            meta.style.marginTop = '2px';
            var when = event.occurred_at ? new Date(event.occurred_at).toLocaleString() : '';
            meta.textContent = [when, event.severity || '', event.category || ''].filter(Boolean).join(' · ');

            row.appendChild(title);
            row.appendChild(meta);
            if (delivery.last_error) {
                var reason = document.createElement('div');
                reason.className = 'text-muted';
                reason.style.fontSize = '0.78rem';
                reason.textContent = delivery.last_error;
                row.appendChild(reason);
            }
            container.appendChild(row);
        });
    }

    function init() {
        if (!byId('notificationsCard')) return;
        var enabled = byId('notifications_enabled');
        if (enabled) enabled.addEventListener('change', toggleFields);
        var saveBtn = byId('notificationSaveBtn');
        if (saveBtn) saveBtn.addEventListener('click', function () { save(false); });
        var testBtn = byId('notificationTestBtn');
        if (testBtn) testBtn.addEventListener('click', function () { testConnection(); });
        return load();
    }

    root.NotificationSettingsUI = {
        init: init,
        load: load,
        save: save,
        testConnection: testConnection,
        collect: collect,
        renderHistory: renderHistory,
        state: state
    };

    if (typeof document !== 'undefined') {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }
}(typeof self !== 'undefined' ? self : this));
