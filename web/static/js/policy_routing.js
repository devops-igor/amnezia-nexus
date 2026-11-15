/* Admin controller for the policy routing settings section (#679).
 *
 * The backend of #678 is the single authority for this page: it validates the
 * record before anything is persisted, refuses enablement when the data plane
 * cannot serve it, and rolls the stored record back when activation fails. This
 * module therefore never decides whether a configuration is acceptable and never
 * guesses the resulting state:
 *
 *   - the form is populated from GET /api/vpn/policy, not from the markup;
 *   - a save sends the operator's intent and then adopts whatever the server
 *     answered with;
 *   - a refusal is shown verbatim and the form is reloaded from the saved
 *     record, so a rejected "enabled" can never stay visible as enabled;
 *   - the status block and counters are read from the server's own snapshot and
 *     are never derived from local counters.
 *
 * URLs are intentionally not validated here. The server applies the same SSRF
 * and HTTPS rules the fetcher enforces, and a client-side copy of that policy
 * would only disagree with it.
 */

(function (root) {
    'use strict';

    var POLICY_ENDPOINT = '/api/vpn/policy';
    var SYNC_ENDPOINT = '/api/vpn/policy/sync';
    var STATS_ENDPOINT = '/api/vpn/policy/stats';

    // Last record the server returned. It is the fallback used to restore the form
    // when a refused save cannot be followed by a successful reload.
    var lastServerRecord = null;
    var initialized = false;
    // One save and one sync at a time. The Save button is disabled while its
    // request runs, but pressing Enter in the form reaches the submit handler
    // anyway, so the guard cannot live in the button alone.
    var inFlight = { save: false, sync: false };
    // The control that owns the busy state, so focus can be given back: browsers
    // drop focus from a control the moment it is disabled.
    var busyFocus = null;

    function policyText(key) {
        if (typeof root._ === 'function') {
            var translated = root._(key);
            if (translated && translated !== key) {
                return translated;
            }
        }
        return key;
    }

    function policyElement(id) {
        if (!root.document) {
            return null;
        }
        return root.document.getElementById(id);
    }

    function policyRequest(url, options) {
        if (!root.API || typeof root.API.request !== 'function') {
            var err = new Error(policyText('policy_load_failed'));
            err.status = 0;
            throw err;
        }
        // This section renders every failure inline, so the shared client must not
        // raise its global toast for the same answer: two error surfaces make a
        // screen reader announce the same refusal twice.
        return root.API.request(url, Object.assign({ silent: true }, options));
    }

    // policyErrorDetail prefers the server's own wording. api.js already resolves
    // detail/error/message into err.message, but a caller that throws before the
    // response is parsed still carries the structured body.
    function policyErrorDetail(err) {
        if (!err) {
            return '';
        }
        if (err.data && typeof err.data === 'object') {
            var detail = err.data.detail || err.data.error || err.data.message;
            if (detail) {
                return String(detail);
            }
        }
        return err.message ? String(err.message) : String(err);
    }

    function policyFormatBytes(raw) {
        var bytes = Number(raw);
        if (!isFinite(bytes) || bytes < 0) {
            return '-';
        }
        var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
        var value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.length - 1) {
            value = value / 1024;
            unit++;
        }
        if (unit === 0) {
            return Math.round(value) + ' ' + units[unit];
        }
        return value.toFixed(2) + ' ' + units[unit];
    }

    function policyFormatCount(raw) {
        var count = Number(raw);
        if (!isFinite(count) || count < 0) {
            return '-';
        }
        return String(Math.round(count));
    }

    function policyFormatTimestamp(raw) {
        if (!raw) {
            return policyText('policy_never');
        }
        var parsed = new Date(raw);
        if (isNaN(parsed.getTime())) {
            return String(raw);
        }
        // Format in the page's language so a Russian portal does not fall back to
        // the browser's own locale for the same timestamp.
        var lang = root.document && root.document.documentElement
            ? root.document.documentElement.lang
            : '';
        return parsed.toLocaleString(lang || undefined);
    }

    function policyPresetLabel(preset) {
        if (!preset) {
            return policyText('policy_none');
        }
        return policyText('policy_preset_' + preset);
    }

    // policySyncStateLabel translates the runtime's own sync_state token. The set
    // is closed (disabled/synced/pending/error); an unknown token is shown as
    // received rather than replaced by a guess.
    function policySyncStateLabel(state) {
        if (!state) {
            return policyText('policy_none');
        }
        var key = 'policy_sync_state_' + state;
        var label = policyText(key);
        return label === key ? state : label;
    }

    function policySelectedPreset() {
        var inputs = policyPresetInputs();
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].checked) {
                return inputs[i].value;
            }
        }
        return '';
    }

    function policyPresetInputs() {
        if (!root.document || typeof root.document.querySelectorAll !== 'function') {
            return [];
        }
        var nodes = root.document.querySelectorAll('input[name="policy_preset"]');
        return Array.prototype.slice.call(nodes);
    }

    function policyCustomURLs() {
        var textarea = policyElement('policy_custom_urls');
        if (!textarea || typeof textarea.value !== 'string') {
            return [];
        }
        return textarea.value
            .split('\n')
            .map(function (line) { return line.trim(); })
            .filter(function (line) { return line.length > 0; });
    }

    // setPolicyAlert renders one inline banner. An empty message hides it, so a
    // recovered action clears a previous failure instead of leaving stale text.
    function setPolicyAlert(kind, message) {
        var banner = policyElement('policyAlert');
        if (!banner) {
            return;
        }
        if (!message) {
            banner.style.display = 'none';
            banner.textContent = '';
            banner.setAttribute('data-state', '');
            return;
        }
        // Theme tokens, not literals: --success-bg/--danger-bg already carry the
        // light and dark variants. The message keeps the primary text colour
        // because --danger is tuned for dark surfaces and measures 3.2:1 on the
        // light theme's card, under the 4.5:1 minimum for this text size. The
        // state is still carried by the tint, the border and the wording rather
        // than by colour alone.
        if (kind === 'success') {
            banner.style.background = 'var(--success-bg)';
            banner.style.border = '1px solid var(--success-border)';
        } else {
            banner.style.background = 'var(--danger-bg)';
            banner.style.border = '1px solid var(--danger-border)';
        }
        banner.style.color = 'var(--text-primary)';
        banner.setAttribute('data-state', kind);
        banner.textContent = message;
        banner.style.display = 'block';
    }

    function setPolicyBusy(role, busy) {
        var button = policyElement(role === 'sync' ? 'policySyncBtn' : 'policySaveBtn');
        var spinner = policyElement(role === 'sync' ? 'policySyncSpinner' : 'policySaveSpinner');
        var label = policyElement(role === 'sync' ? 'policySyncBtnText' : 'policySaveBtnText');
        if (button) {
            if (busy && root.document && root.document.activeElement === button) {
                busyFocus = button;
            }
            button.disabled = !!busy;
            button.setAttribute('aria-busy', busy ? 'true' : 'false');
            // Disabling a focused control moves focus to the document body, so a
            // keyboard operator would lose their place for the whole request.
            if (!busy) {
                if (busyFocus === button && root.document && root.document.activeElement === root.document.body) {
                    button.focus();
                }
                busyFocus = null;
            }
        }
        if (spinner) {
            if (busy) {
                spinner.classList.remove('hidden');
            } else {
                spinner.classList.add('hidden');
            }
        }
        if (label && role === 'sync') {
            label.textContent = busy ? policyText('policy_sync_running') : policyText('policy_sync_btn');
        }
    }

    function updatePolicyCustomGroup() {
        var group = policyElement('policyCustomUrlsGroup');
        if (!group) {
            return;
        }
        group.style.display = policySelectedPreset() === 'custom' ? 'block' : 'none';
    }

    function updatePolicyPresetHighlight() {
        if (!root.document || typeof root.document.querySelectorAll !== 'function') {
            return;
        }
        var selected = policySelectedPreset();
        var rows = root.document.querySelectorAll('[data-policy-preset]');
        Array.prototype.forEach.call(rows, function (row) {
            var isSelected = row.getAttribute('data-policy-preset') === selected;
            row.style.borderColor = isSelected ? 'var(--accent)' : 'var(--border-color)';
        });
    }

    // applyPolicyRecord populates the form from a server record. It is the only
    // writer of the toggle and preset controls, so the displayed intent is always
    // a record the server accepted.
    function applyPolicyRecord(record) {
        if (!record) {
            return;
        }
        lastServerRecord = record;

        var enabled = policyElement('policy_enabled');
        if (enabled) {
            enabled.checked = !!record.enabled;
        }

        var urls = Array.isArray(record.custom_urls) ? record.custom_urls : [];
        var textarea = policyElement('policy_custom_urls');
        if (textarea) {
            textarea.value = urls.join('\n');
        }

        var interval = policyElement('policy_sync_interval');
        if (interval && typeof record.sync_interval_seconds === 'number') {
            interval.value = String(record.sync_interval_seconds);
        }

        var selected = record.preset || '';
        var inputs = policyPresetInputs();
        for (var i = 0; i < inputs.length; i++) {
            inputs[i].checked = inputs[i].value === selected;
        }

        updatePolicyCustomGroup();
        updatePolicyPresetHighlight();
    }

    function renderPolicyStatus(record, status) {
        var snapshot = status || null;
        var runtimeEnabled = snapshot && typeof snapshot.enabled === 'boolean'
            ? snapshot.enabled
            : !!(record && record.enabled);

        var badge = policyElement('policyStatusBadge');
        if (badge) {
            badge.className = runtimeEnabled ? 'badge badge-success' : 'badge badge-secondary';
            badge.textContent = policyText(runtimeEnabled ? 'policy_status_enabled' : 'policy_status_disabled');
            badge.setAttribute('data-enabled', runtimeEnabled ? 'true' : 'false');
        }

        var preset = (snapshot && snapshot.preset) || (record && record.preset) || '';
        var presetEl = policyElement('policyActivePreset');
        if (presetEl) {
            presetEl.textContent = policyPresetLabel(preset);
        }

        var lastSuccessEl = policyElement('policyLastSuccess');
        if (lastSuccessEl) {
            lastSuccessEl.textContent = policyFormatTimestamp(snapshot && snapshot.last_success);
        }

        var syncStateEl = policyElement('policySyncState');
        if (syncStateEl) {
            syncStateEl.textContent = policySyncStateLabel(snapshot && snapshot.sync_state);
        }

        var ruleCountEl = policyElement('policyRuleCount');
        if (ruleCountEl) {
            if (snapshot) {
                var domains = Number(snapshot.domain_count) || 0;
                var cidrs = Number(snapshot.cidr_count) || 0;
                ruleCountEl.textContent = policyText('policy_rule_count_value')
                    .replace('{domains}', policyFormatCount(domains))
                    .replace('{cidrs}', policyFormatCount(cidrs));
            } else {
                ruleCountEl.textContent = policyText('policy_none');
            }
        }

        var lastErrorEl = policyElement('policyLastError');
        if (lastErrorEl) {
            lastErrorEl.textContent = snapshot && snapshot.last_error
                ? snapshot.last_error
                : policyText('policy_none');
        }
    }

    function renderPolicyCounters(stats) {
        if (!stats) {
            return;
        }
        var mapping = [
            ['policyProxyBytes', policyFormatBytes(stats.proxy_bytes)],
            ['policyDirectBytes', policyFormatBytes(stats.direct_bytes)],
            ['policyProxyDrops', policyFormatCount(stats.proxy_drops)],
            ['policyDirectDrops', policyFormatCount(stats.direct_drops)]
        ];
        mapping.forEach(function (entry) {
            var el = policyElement(entry[0]);
            if (el) {
                el.textContent = entry[1];
            }
        });
    }

    // refreshPolicyStatus re-reads the server's own snapshot. A failed read never
    // invents a state: the previous rendering is left untouched and the caller
    // decides whether the failure is worth reporting.
    async function refreshPolicyStatus() {
        var policy = null;
        try {
            policy = await policyRequest(POLICY_ENDPOINT, { method: 'GET' });
        } catch (err) {
            return { ok: false, error: err };
        }
        renderPolicyStatus(policy, policy && policy.status);

        var stats = null;
        try {
            stats = await policyRequest(STATS_ENDPOINT, { method: 'GET' });
        } catch (err) {
            // Counters are advisory: a stats read failure must not claim the save
            // or the sync failed, so it is reported only when nothing else is shown.
            return { ok: true, statsError: err, record: policy };
        }
        renderPolicyCounters(stats);
        return { ok: true, record: policy };
    }

    async function loadPolicySettings() {
        var policy = await policyRequest(POLICY_ENDPOINT, { method: 'GET' });
        applyPolicyRecord(policy);
        renderPolicyStatus(policy, policy && policy.status);
        try {
            var stats = await policyRequest(STATS_ENDPOINT, { method: 'GET' });
            renderPolicyCounters(stats);
        } catch (err) {
            renderPolicyCounters(null);
        }
        return policy;
    }

    function policySavePayload() {
        var preset = policySelectedPreset();
        var enabledInput = policyElement('policy_enabled');
        var intervalInput = policyElement('policy_sync_interval');
        var interval = intervalInput ? Number(intervalInput.value) : NaN;
        return {
            enabled: !!(enabledInput && enabledInput.checked),
            preset: preset,
            custom_urls: preset === 'custom' ? policyCustomURLs() : [],
            sync_interval_seconds: isFinite(interval) && interval > 0 ? interval : 0
        };
    }

    async function savePolicySettings() {
        if (inFlight.save) {
            return null;
        }
        inFlight.save = true;
        var payload = policySavePayload();
        setPolicyBusy('save', true);
        setPolicyAlert('', '');
        try {
            var saved = await policyRequest(POLICY_ENDPOINT, { method: 'PUT', body: payload });
            applyPolicyRecord(saved);
            renderPolicyStatus(saved, saved && saved.policy_status);
            try {
                var stats = await policyRequest(STATS_ENDPOINT, { method: 'GET' });
                renderPolicyCounters(stats);
            } catch (statsErr) {
                // Leave the last known counters in place rather than showing zeroes.
            }
            setPolicyAlert('success', policyText('policy_saved'));
            return saved;
        } catch (err) {
            var detail = policyErrorDetail(err);
            var refusal = policyText('policy_save_failed') + ': ' + detail;
            // Two sentences in one banner: the server's detail does not always end
            // with a stop, and without one the refusal reads as a run-on sentence.
            if (!/[.!?…]$/.test(detail)) {
                refusal += '.';
            }
            setPolicyAlert('error', refusal + ' ' + policyText('policy_save_refused'));
            // Reload the accepted record. If that fails too, the snapshot from the
            // last successful read is restored, so the refused intent is cleared
            // either way.
            try {
                await loadPolicySettings();
            } catch (reloadErr) {
                if (lastServerRecord) {
                    applyPolicyRecord(lastServerRecord);
                    renderPolicyStatus(lastServerRecord, null);
                }
            }
            return null;
        } finally {
            inFlight.save = false;
            setPolicyBusy('save', false);
        }
    }

    async function syncPolicy() {
        if (inFlight.sync) {
            return null;
        }
        inFlight.sync = true;
        setPolicyBusy('sync', true);
        setPolicyAlert('', '');
        try {
            var result = await policyRequest(SYNC_ENDPOINT, { method: 'POST' });
            renderPolicyStatus(lastServerRecord, result && result.policy_status);
            try {
                var stats = await policyRequest(STATS_ENDPOINT, { method: 'GET' });
                renderPolicyCounters(stats);
            } catch (statsErr) {
                // The sync outcome is already known; counters stay as they were.
            }
            setPolicyAlert('success', policyText('policy_sync_ok'));
            return result;
        } catch (err) {
            setPolicyAlert('error', policyText('policy_sync_failed') + ': ' + policyErrorDetail(err));
            // The status block carries the server's own last_error, so refresh it
            // while the failure banner stays on screen.
            try {
                await refreshPolicyStatus();
            } catch (refreshErr) {
                // Nothing newer to display; the banner already states the outcome.
            }
            return null;
        } finally {
            inFlight.sync = false;
            setPolicyBusy('sync', false);
        }
    }

    // initPolicyRouting wires the section once. It returns false when the section
    // is absent (a non-admin render, or a page that does not include it), which is
    // what keeps the controller inert everywhere else.
    function initPolicyRouting() {
        var form = policyElement('policyRoutingForm');
        if (!form) {
            return false;
        }
        if (initialized) {
            return true;
        }
        initialized = true;

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            savePolicySettings();
        });

        var saveBtn = policyElement('policySaveBtn');
        if (saveBtn) {
            saveBtn.addEventListener('click', function (event) {
                event.preventDefault();
                savePolicySettings();
            });
        }

        var syncBtn = policyElement('policySyncBtn');
        if (syncBtn) {
            syncBtn.addEventListener('click', function (event) {
                event.preventDefault();
                syncPolicy();
            });
        }

        policyPresetInputs().forEach(function (input) {
            input.addEventListener('change', function () {
                updatePolicyCustomGroup();
                updatePolicyPresetHighlight();
            });
        });

        updatePolicyCustomGroup();
        updatePolicyPresetHighlight();

        loadPolicySettings().catch(function (err) {
            setPolicyAlert('error', policyText('policy_load_failed') + ': ' + policyErrorDetail(err));
        });
        return true;
    }

    root.initPolicyRouting = initPolicyRouting;
    root.savePolicySettings = savePolicySettings;
    root.syncPolicy = syncPolicy;
    root.loadPolicySettings = loadPolicySettings;

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', initPolicyRouting);
        } else {
            initPolicyRouting();
        }
    }
}(typeof window !== 'undefined' ? window : this));
