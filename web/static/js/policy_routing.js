/* Admin controller for the policy routing settings section (#679).
 *
 * The backend of #678 is the single authority for this page: it validates the
 * record before anything is persisted, refuses enablement when the data plane
 * cannot serve it, and rolls the stored record back when activation fails. This
 * module therefore never decides whether a configuration is acceptable and never
 * guesses the resulting state:
 *
 *   - the form is populated from GET /api/vpn/policy, not from the markup;
 *   - nothing is persisted until that read has succeeded: before it the controls
 *     still hold markup defaults (switch off, interval blank), so a save would
 *     write values the operator never chose over a stored configuration;
 *   - a save sends the operator's intent and then adopts whatever the server
 *     answered with;
 *   - a refusal is shown verbatim and the form is reloaded from the saved
 *     record, so a rejected "enabled" can never stay visible as enabled;
 *   - the status block and counters are read from the server's own snapshot and
 *     are never derived from local counters. In particular the enabled badge only
 *     ever mirrors a runtime observation: the stored record is intent, and the two
 *     deliberately differ while a startup activation failure is being recovered.
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
    // Read-only dry run of issue #825: explains one destination without sending
    // traffic, so it is a POST (it carries a destination) that mutates nothing.
    var EXPLAIN_ENDPOINT = '/api/vpn/policy/explain';

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
    // The newest runtime snapshot a server response actually carried. It is never
    // rebuilt from the stored record: persisted intent and the live runtime are
    // different facts, and a failed read must not turn one into the other.
    var lastRuntimeSnapshot = null;
    // Mutating controls stay inert until the stored record has been read. Before
    // that the form still holds markup defaults, and a save built from them would
    // overwrite a configuration nobody chose to change.
    var policyReady = false;
    // Ordering guard: a read applies only while no mutation was accepted after it
    // was issued, so a slow earlier GET cannot overwrite a newer accepted result.
    var requestSeq = 0;
    var lastAcceptedMutation = 0;

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

    // policyRuntimeSnapshot extracts a runtime observation from a server response.
    // GET returns it as `status`; a successful PUT and a sync return it as
    // `policy_status`. A PUT also returns `status: "ok"`, which is a result code and
    // never a runtime observation, so anything that is not an object carrying a
    // boolean `enabled` is rejected rather than read as one.
    function policyRuntimeSnapshot(payload) {
        if (!payload || typeof payload !== 'object') {
            return null;
        }
        var candidate = payload.policy_status || payload.status;
        if (!candidate || typeof candidate !== 'object' || typeof candidate.enabled !== 'boolean') {
            return null;
        }
        return candidate;
    }

    // policyReadApplies reports whether a read issued as `seq` may still be shown.
    // Any mutation accepted after it started owns the form from then on.
    function policyReadApplies(seq) {
        return seq > lastAcceptedMutation;
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
            // A save also stays disabled until the stored record has been read.
            button.disabled = !!busy || (role === 'save' && !policyReady);
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

    // setPolicyReady opens or closes the mutation gate and keeps the Save control
    // in step with it. Only a successful read of the stored record opens it.
    function setPolicyReady(ready) {
        policyReady = !!ready;
        var saveBtn = policyElement('policySaveBtn');
        if (saveBtn) {
            saveBtn.disabled = !policyReady || inFlight.save;
        }
        var form = policyElement('policyRoutingForm');
        if (form) {
            form.setAttribute('data-policy-ready', policyReady ? 'true' : 'false');
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
        var snapshot = policyRuntimeSnapshot({ status: status });
        if (snapshot) {
            // The newest real observation is also what a failed recovery read keeps.
            lastRuntimeSnapshot = snapshot;
        }

        // Runtime enabled mirrors one server observation or nothing at all. It is
        // never derived from `record.enabled`: storage keeps `enabled:true` through
        // a failed startup activation while the runtime is inactive, so intent is
        // not evidence about the running policy.
        var runtimeEnabled = snapshot ? snapshot.enabled : null;

        var badge = policyElement('policyStatusBadge');
        if (badge) {
            if (runtimeEnabled === null) {
                badge.className = 'badge badge-secondary';
                badge.textContent = policyText('policy_status_unknown');
                badge.setAttribute('data-enabled', 'unknown');
            } else {
                badge.className = runtimeEnabled ? 'badge badge-success' : 'badge badge-secondary';
                badge.textContent = policyText(runtimeEnabled ? 'policy_status_enabled' : 'policy_status_disabled');
                badge.setAttribute('data-enabled', runtimeEnabled ? 'true' : 'false');
            }
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
        var seq = ++requestSeq;
        var policy = null;
        try {
            policy = await policyRequest(POLICY_ENDPOINT, { method: 'GET' });
        } catch (err) {
            return { ok: false, error: err };
        }
        if (policyReadApplies(seq)) {
            renderPolicyStatus(policy, policyRuntimeSnapshot(policy));
        }

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

    // loadPolicySettings reads the stored record, applies it and opens the mutation
    // gate. It is the only opener: an unread record is not a default record.
    async function loadPolicySettings() {
        var seq = ++requestSeq;
        var policy = await policyRequest(POLICY_ENDPOINT, { method: 'GET' });
        if (!policyReadApplies(seq)) {
            // A mutation accepted after this read started owns the form; replaying
            // the older record here would undo it.
            return policy;
        }
        applyPolicyRecord(policy);
        renderPolicyStatus(policy, policyRuntimeSnapshot(policy));
        setPolicyReady(true);
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
        if (!policyReady) {
            // Nothing may be persisted before the stored record has been read: the
            // controls still hold markup defaults, so this payload would carry
            // values the operator never chose over an existing configuration.
            setPolicyAlert('error', policyText('policy_not_ready'));
            return null;
        }
        if (inFlight.save) {
            return null;
        }
        inFlight.save = true;
        var seq = ++requestSeq;
        var payload = policySavePayload();
        setPolicyBusy('save', true);
        setPolicyAlert('', '');
        try {
            var saved = await policyRequest(POLICY_ENDPOINT, { method: 'PUT', body: payload });
            // The accepted write owns the form from now on: a read issued before it
            // must not replace it when it lands later.
            lastAcceptedMutation = seq;
            applyPolicyRecord(saved);
            renderPolicyStatus(saved, policyRuntimeSnapshot(saved));
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
            // Re-read the accepted record. If that fails too, the last accepted
            // record and the last runtime observation are restored: a failed read
            // must not clear the badge, the counts or the activation diagnostic, and
            // it must never turn stored intent into a runtime "enabled".
            try {
                await loadPolicySettings();
            } catch (reloadErr) {
                if (lastServerRecord) {
                    applyPolicyRecord(lastServerRecord);
                    renderPolicyStatus(lastServerRecord, lastRuntimeSnapshot);
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
        var seq = ++requestSeq;
        setPolicyBusy('sync', true);
        setPolicyAlert('', '');
        try {
            var result = await policyRequest(SYNC_ENDPOINT, { method: 'POST' });
            // A completed sync publishes a new snapshot, so it is a newer
            // observation than any read still in flight.
            lastAcceptedMutation = seq;
            renderPolicyStatus(lastServerRecord, policyRuntimeSnapshot(result));
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

    // One explanation at a time. The button is disabled while it runs, but Enter
    // in the field reaches the same function, so the guard cannot live in the
    // button alone.
    var explainInFlight = false;

    // policyExplainDecisionLabel translates the server's decision token. The set
    // is closed (DIRECT, PROXY, DROP, UNKNOWN); an unknown token is shown as
    // received rather than replaced by a guess.
    function policyExplainDecisionLabel(decision) {
        if (!decision) {
            return policyText('policy_none');
        }
        var key = 'policy_explain_decision_' + String(decision).toLowerCase();
        var label = policyText(key);
        return label === key ? String(decision) : label;
    }

    // policyExplainHasClientContext reports whether the answer can support any
    // statement about this client's route. The service echoes the session whose
    // evidence it read, and an empty echo means no client evidence was consulted
    // at all. An answer that still lists the no-session limitation contradicts
    // its own echo, so it is treated the same way: without client context the
    // module may report the policy evaluation but must not name a route.
    function policyExplainHasClientContext(answer) {
        if (!answer || !answer.input || !answer.input.session) {
            return false;
        }
        return !policyExplainListsLimitation(answer, 'evidence_requires_a_selected_session');
    }

    // policyExplainListsLimitation reports whether the answer carries one
    // limitation token. limitations is part of the answer contract; an answer
    // from a server that does not send it simply lists nothing.
    function policyExplainListsLimitation(answer, token) {
        return Array.isArray(answer && answer.limitations)
            && answer.limitations.indexOf(token) !== -1;
    }

    // policyExplainDecisionState maps the server's decision to the readout state
    // token. It is only meaningful when client context was inspected: without it
    // no decision is reported as a route.
    function policyExplainDecisionState(decision) {
        switch (String(decision || '').toUpperCase()) {
        case 'DIRECT':
            return 'direct';
        case 'PROXY':
            return 'proxy';
        case 'DROP':
            return 'drop';
        default:
            return 'unknown';
        }
    }

    // policyExplainReasonLabel translates the machine-readable cause. The server
    // is the authority on which causes exist; a token without a translation is
    // displayed verbatim, so a new cause degrades to a readable answer instead of
    // an empty line. Only the session-scoped wording of no_trusted_evidence has
    // a variant: that cause is also what an answer reaches when no session was
    // selected, and then the evidence was not inspected rather than absent.
    function policyExplainReasonLabel(reason, hasContext) {
        if (!reason) {
            return policyText('policy_none');
        }
        var key = 'policy_explain_reason_' + String(reason);
        if (String(reason) === 'no_trusted_evidence' && !hasContext) {
            key = 'policy_explain_reason_no_trusted_evidence_no_session';
        }
        var label = policyText(key);
        return label === key ? String(reason) : label;
    }

    // policyExplainPayload classifies what the operator typed. It is a routing
    // hint only: the server still validates the value and rejects anything
    // malformed, so this never becomes a second validator.
    function policyExplainPayload(value) {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
            return { ip: value };
        }
        return { domain: value };
    }

    // setPolicyExplainResult writes the single result line. An empty message
    // restores the shipped hint, so a recovered request clears a stale error.
    function setPolicyExplainResult(message, state) {
        var el = policyElement('policyExplainResult');
        if (!el) {
            return;
        }
        el.textContent = message || policyText('policy_explain_hint');
        el.setAttribute('data-state', state || '');
    }

    // policyExplainSource renders the lists behind a match, or the "none" token
    // when a merged snapshot could not attribute it.
    function policyExplainSource(source) {
        if (Array.isArray(source) && source.length > 0) {
            return source.join(', ');
        }
        return policyText('policy_none');
    }

    // setPolicyExplainDetail shows what the policy itself did, naming its source.
    // The rule match is prospective and is labelled as such: the packet path
    // never looks at a name, so a rule only becomes a destination's route after
    // the client's own answer is observed. Without client context the whole line
    // is introduced as a policy evaluation and carries the cause, because none of
    // it is a measurement of this client's connection.
    function setPolicyExplainDetail(answer, hasContext) {
        var el = policyElement('policyExplainDetail');
        if (!el) {
            return;
        }
        var parts = [];
        var prospective = answer && answer.prospective;
        if (prospective && prospective.matched && prospective.rule) {
            parts.push(policyText('policy_explain_prospective_rule')
                .replace('{rule}', prospective.rule.base || '')
                .replace('{shape}', prospective.rule.shape || '')
                .replace('{source}', policyExplainSource(prospective.rule.contributors)));
        }
        if (answer && answer.prefix) {
            parts.push(policyText('policy_explain_current_prefix')
                .replace('{prefix}', answer.prefix.prefix || '')
                .replace('{source}', policyExplainSource(answer.prefix.sources)));
        }
        if (!hasContext && answer && answer.reason) {
            parts.unshift(policyExplainReasonLabel(answer.reason, false));
        }
        if (parts.length === 0) {
            el.textContent = '';
            el.hidden = true;
            return;
        }
        if (hasContext) {
            el.textContent = parts.join(' · ');
        } else {
            // The label introduces the whole line, so the first part follows it as
            // prose; the remaining parts stay separated.
            el.textContent = policyText('policy_explain_policy_evaluation_label') + ' ' + parts.join(' · ');
        }
        el.hidden = false;
    }

    // explainPolicyDestination asks the server to explain one destination and
    // renders the decision with its cause. It changes no settings and reloads
    // nothing: the answer is a read.
    async function explainPolicyDestination() {
        if (explainInFlight) {
            return null;
        }
        var input = policyElement('policy_explain_value');
        var value = input && typeof input.value === 'string' ? input.value.trim() : '';
        if (!value) {
            setPolicyExplainResult(policyText('policy_explain_needs_value'), 'error');
            return null;
        }
        explainInFlight = true;
        var button = policyElement('policyExplainBtn');
        if (button) {
            button.disabled = true;
            button.setAttribute('aria-busy', 'true');
        }
        setPolicyExplainResult(policyText('policy_explain_running'), '');
        setPolicyExplainDetail(null, false);
        try {
            var answer = await policyRequest(EXPLAIN_ENDPOINT, {
                method: 'POST',
                body: policyExplainPayload(value)
            });
            var normalized = answer && answer.input && answer.input.normalized
                ? answer.input.normalized
                : value;
            var hasContext = policyExplainHasClientContext(answer);
            var result;
            var state;
            if (hasContext) {
                result = policyText('policy_explain_result')
                    .replace('{value}', normalized)
                    .replace('{decision}', policyExplainDecisionLabel(answer && answer.decision))
                    .replace('{reason}', policyExplainReasonLabel(answer && answer.reason, true));
                state = policyExplainDecisionState(answer && answer.decision);
            } else {
                // No client evidence was read, so no route may be named: the
                // headline says the route is not determined and the policy
                // evaluation is rendered separately below.
                result = policyText('policy_explain_result_no_context')
                    .replace('{value}', normalized);
                state = 'no-context';
            }
            setPolicyExplainResult(result, state);
            setPolicyExplainDetail(answer, hasContext);
            return answer;
        } catch (err) {
            setPolicyExplainDetail(null, false);
            setPolicyExplainResult(policyText('policy_explain_failed') + ': ' + policyErrorDetail(err), 'error');
            return null;
        } finally {
            explainInFlight = false;
            if (button) {
                button.disabled = false;
                button.setAttribute('aria-busy', 'false');
            }
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

        // The gate starts closed and is opened only by a successful read, so the
        // markup defaults can never be submitted while the record is unknown.
        setPolicyReady(false);

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

        // The dry run lives outside the settings form, so Enter here cannot submit
        // settings; it runs the explanation instead.
        var explainBtn = policyElement('policyExplainBtn');
        if (explainBtn) {
            explainBtn.addEventListener('click', function (event) {
                event.preventDefault();
                explainPolicyDestination();
            });
        }
        var explainInput = policyElement('policy_explain_value');
        if (explainInput) {
            explainInput.addEventListener('keydown', function (event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    explainPolicyDestination();
                }
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
            // A failed initial read leaves the section read-only and says why: with
            // the stored record unknown there is nothing safe to submit.
            setPolicyReady(false);
            setPolicyAlert('error', policyText('policy_load_failed') + ': '
                + policyErrorDetail(err) + ' ' + policyText('policy_not_ready'));
        });
        return true;
    }

    root.initPolicyRouting = initPolicyRouting;
    root.savePolicySettings = savePolicySettings;
    root.syncPolicy = syncPolicy;
    root.loadPolicySettings = loadPolicySettings;
    root.explainPolicyDestination = explainPolicyDestination;

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', initPolicyRouting);
        } else {
            initPolicyRouting();
        }
    }
}(typeof window !== 'undefined' ? window : this));
