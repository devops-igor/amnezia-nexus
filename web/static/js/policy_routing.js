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

    // setPolicyElementText writes one status value and tolerates an absent element,
    // so a section rendered without a block never throws in the controller.
    function setPolicyElementText(id, text) {
        var el = policyElement(id);
        if (el) {
            el.textContent = text;
        }
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

    // setPolicyAlert reports into the card's own two regions, the same ones every
    // other card has: a success goes to the status region and anything else to the
    // alert region, each with a role that never changes. An empty message clears
    // both, so a recovered action does not leave a stale failure behind. The
    // #policyAlert wrapper only carries the state for readers that look at it.
    function setPolicyAlert(kind, message) {
        var cards = root.SettingsCards;
        if (!cards) {
            return;
        }
        if (!message) {
            cards.clearReport('policyRoutingCard');
            return;
        }
        cards.report('policyRoutingCard', kind === 'success' ? 'success' : 'error', message,
            kind === 'success' ? 'saved' : 'refused');
    }

    function setPolicyBusy(role, busy) {
        if (role === 'save') {
            // The card module owns the save control: aria-busy on the card, the
            // disabled commit, the spinner and the focus that has to survive it.
            if (root.SettingsCards) {
                root.SettingsCards.busy('policyRoutingCard', busy);
            }
            return;
        }
        var button = policyElement('policySyncBtn');
        var spinner = policyElement('policySyncSpinner');
        var label = policyElement('policySyncBtnText');
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
            spinner.classList.toggle('hidden', !busy);
        }
        if (label) {
            label.textContent = busy ? policyText('policy_sync_running') : policyText('policy_sync_btn');
        }
    }

    // setPolicyReady opens or closes the mutation gate and keeps the Save control
    // in step with it. Only a successful read of the stored record opens it.
    function setPolicyReady(ready) {
        policyReady = !!ready;
        if (root.SettingsCards) {
            root.SettingsCards.gate('policyRoutingCard', !policyReady);
        }
        var form = policyElement('policyRoutingForm');
        if (form) {
            form.setAttribute('data-policy-ready', policyReady ? 'true' : 'false');
        }
    }

    // applyPolicyRecord populates the form from a server record. It is the only
    // writer of the toggle and the exception list, so the displayed intent is
    // always a record the server accepted.
    //
    // With keepForm the record is remembered as the last accepted one and the
    // fields are left as the operator has them. That is for a save whose answer
    // arrives after the operator kept typing: what was sent is stored, what is on
    // screen now is not.
    function applyPolicyRecord(record, keepForm) {
        if (!record) {
            return;
        }
        lastServerRecord = record;
        if (keepForm) {
            return;
        }

        var enabled = policyElement('policy_enabled');
        if (enabled) {
            enabled.checked = !!record.enabled;
        }

        var exceptions = Array.isArray(record.proxy_exceptions) ? record.proxy_exceptions : [];
        var exceptionsTextarea = policyElement('policy_proxy_exceptions');
        if (exceptionsTextarea) {
            exceptionsTextarea.value = exceptions.join('\n');
        }
        // The inventory override is a stored record field like the list above: the
        // textarea always shows what the server accepted, never a local guess.
        var override = Array.isArray(record.inventory_override) ? record.inventory_override : [];
        var overrideTextarea = policyElement('policy_inventory_override');
        if (overrideTextarea) {
            overrideTextarea.value = override.join('\n');
        }

        var interval = policyElement('policy_sync_interval');
        if (interval && typeof record.sync_interval_seconds === 'number') {
            interval.value = String(record.sync_interval_seconds);
        }

        if (root.SettingsCards) {
            root.SettingsCards.rebase('policyRoutingCard');
        }
    }

    // renderPolicyInventory states which allocation inventory the classifier is
    // using. The shipped set's provenance is reported as its own facts, and an
    // operator override is reported beside it rather than as part of it: an
    // operator who cannot tell the two apart cannot tell whether a routing
    // decision came from the committed artifact or from their own correction.
    //
    // Every value comes from the server's snapshot. When the artifact is unusable
    // the notice carries the reported error, because an empty grid would read as
    // "no data" instead of "the set is broken and everything is proxied".
    function renderPolicyInventory(snapshot) {
        var inventory = snapshot && snapshot.inventory ? snapshot.inventory : null;
        var source = policyElement('policyInventorySource');
        var prefixes = policyElement('policyInventoryPrefixes');
        var retrieved = policyElement('policyInventoryRetrieved');
        var age = policyElement('policyInventoryAge');
        var override = policyElement('policyInventoryOverrideStatus');
        var notice = policyElement('policyInventoryNotice');

        if (!inventory) {
            [source, prefixes, retrieved, age, override].forEach(function (el) {
                if (el) {
                    el.textContent = '-';
                }
            });
            if (notice) {
                notice.textContent = '';
            }
            return;
        }

        if (source) {
            source.textContent = inventory.source || policyText('policy_none');
        }
        if (prefixes) {
            prefixes.textContent = policyFormatCount(inventory.prefix_count);
        }
        if (retrieved) {
            retrieved.textContent = inventory.retrieved_at || policyText('policy_none');
        }
        if (age) {
            var ageText = policyText('policy_inventory_age_value')
                .replace('{days}', policyFormatCount(inventory.age_days))
                .replace('{max}', policyFormatCount(inventory.max_age_days));
            if (inventory.stale) {
                ageText = ageText + ' · ' + policyText('policy_inventory_stale');
            }
            age.textContent = ageText;
        }
        if (override) {
            var overrideCount = Number(inventory.override_prefix_count) || 0;
            if (overrideCount > 0) {
                // The digest is what distinguishes two overrides with the same
                // number of prefixes; it is truncated for reading, never invented.
                var digest = inventory.override_sha256 ? String(inventory.override_sha256).slice(0, 12) : '';
                override.textContent = policyText('policy_inventory_override_active')
                    .replace('{count}', policyFormatCount(overrideCount))
                    .replace('{digest}', digest);
            } else {
                override.textContent = policyText('policy_inventory_override_none');
            }
        }
        if (notice) {
            notice.textContent = inventory.error
                ? policyText('policy_inventory_unusable') + ' ' + inventory.error
                : '';
        }
    }

    // policyCDNEntryText renders one exclusion the way the list reads: the
    // provider name, then the autonomous system the classifier matches against.
    // A missing half is left out rather than filled with a placeholder, so the
    // line never claims something the server did not send.
    function policyCDNEntryText(entry) {
        var provider = entry && entry.provider ? String(entry.provider) : '';
        var asn = entry && entry.asn ? 'AS' + String(entry.asn) : '';
        if (provider === '') {
            return asn;
        }
        if (asn === '') {
            return provider;
        }
        return provider + ' · ' + asn;
    }

    // renderPolicyCDNEntryList fills the exclusion list, distinguishing the three
    // states a reader must not confuse: a reported empty set (the classifier
    // excludes nothing), an unreported set (this deployment told us nothing), and
    // an unusable one (the set exists but cannot be described).
    function renderPolicyCDNEntryList(entries) {
        var list = policyElement('policyCdnEntries');
        if (!list) {
            return;
        }
        while (list.firstChild) {
            list.removeChild(list.firstChild);
        }
        var state = 'policy_cdn_unavailable';
        if (entries && entries.length === 0) {
            state = 'policy_cdn_empty';
        }
        if (!entries || entries.length === 0) {
            var placeholder = document.createElement('li');
            placeholder.className = 'text-muted';
            placeholder.textContent = policyText(state);
            list.appendChild(placeholder);
            return;
        }
        entries.forEach(function (entry) {
            var row = document.createElement('li');
            row.textContent = policyCDNEntryText(entry);
            list.appendChild(row);
        });
    }

    // renderPolicyCDNNotice states why the set could not be described. It is empty
    // when there is nothing to report, so a usable set carries no warning.
    function renderPolicyCDNNotice(cdn) {
        if (!cdn || !cdn.error) {
            return '';
        }
        return policyText('policy_cdn_unusable') + ' ' + cdn.error;
    }

    // renderPolicyCDNExclusions states the CDN exclusion set the classifier
    // consults (issue #934). The allocation block answers "is this address in the
    // Russian set"; this block answers the rest of the decision — a destination
    // inside that set is still proxied when its network belongs to a multi-region
    // CDN. Before it, that half was visible only one flow at a time.
    //
    // Every value comes from the server's snapshot, which reads the table the
    // classifier itself matches against; nothing is restated here.
    function renderPolicyCDNExclusions(snapshot) {
        var cdn = snapshot && snapshot.cdn ? snapshot.cdn : null;
        var entries = cdn && Array.isArray(cdn.entries) ? cdn.entries : null;
        setPolicyElementText('policyCdnSource', cdn && cdn.source ? cdn.source : '-');
        setPolicyElementText('policyCdnCount', entries ? policyFormatCount(entries.length) : '-');
        renderPolicyCDNEntryList(entries);
        setPolicyElementText('policyCdnNotice', renderPolicyCDNNotice(cdn));
    }

    // renderPolicyRetirement states what the stored record held and this build
    // could not carry. It is empty when the record carried nothing retired, so an
    // ordinary prefix-only upgrade shows no warning at all.
    //
    // Without it an operator whose predecessor list held domain lines would see a
    // shorter list than they saved and no explanation, which reads as lost
    // configuration. The text names the retired entries themselves rather than only
    // counting them, because the operator is the one who recognises what they wrote.
    function renderPolicyRetirement(record) {
        var notice = policyElement('policyLegacyNotice');
        if (!notice) {
            return;
        }
        var retired = record && record.retired ? record.retired : null;
        if (!retired) {
            notice.textContent = '';
            return;
        }
        var parts = [];
        var nonIPv4 = Array.isArray(retired.non_ipv4_entries) ? retired.non_ipv4_entries : [];
        if (nonIPv4.length > 0) {
            parts.push(policyText('policy_legacy_entries_retired')
                .replace('{entries}', nonIPv4.join(', ')));
        }
        if (retired.source_selection) {
            parts.push(policyText('policy_legacy_source_retired')
                .replace('{source}', String(retired.source_selection)));
        }
        var customURLs = Number(retired.custom_url_count) || 0;
        if (customURLs > 0) {
            parts.push(policyText('policy_legacy_urls_retired')
                .replace('{count}', String(customURLs)));
        }
        var excluded = Number(retired.excluded_domain_count) || 0;
        if (excluded > 0) {
            parts.push(policyText('policy_legacy_exclusions_retired')
                .replace('{count}', String(excluded)));
        }
        notice.textContent = parts.join(' ');
    }

    // renderPolicyStatus renders the runtime block. What the stored record could not
    // carry is rendered beside it by renderPolicyRetirement, because the two answer
    // different questions: what is running, and what the operator's saved record
    // used to hold.
    function renderPolicyStatus(record, status) {
        renderPolicyRetirement(record);
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

        renderPolicyInventory(snapshot);
        renderPolicyCDNExclusions(snapshot);

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
                ruleCountEl.textContent = policyFormatCount(Number(snapshot.cidr_count) || 0);
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

    function policyProxyExceptions() {
        var textarea = policyElement('policy_proxy_exceptions');
        if (!textarea || typeof textarea.value !== 'string') {
            return [];
        }
        return textarea.value.split('\n').map(function (line) {
            return line.trim();
        }).filter(function (line) {
            return line !== '';
        });
    }

    // policyInventoryOverride reads the operator's override field. An empty field
    // is sent as an explicit empty list, which the server treats as a deliberate
    // removal of a stored override.
    function policyInventoryOverride() {
        var textarea = policyElement('policy_inventory_override');
        if (!textarea || typeof textarea.value !== 'string') {
            return [];
        }
        return textarea.value.split('\n').map(function (line) {
            return line.trim();
        }).filter(function (line) {
            return line !== '';
        });
    }

    function policySavePayload() {
        var enabledInput = policyElement('policy_enabled');
        var intervalInput = policyElement('policy_sync_interval');
        var interval = intervalInput ? Number(intervalInput.value) : NaN;
        return {
            enabled: !!(enabledInput && enabledInput.checked),
            proxy_exceptions: policyProxyExceptions(),
            inventory_override: policyInventoryOverride(),
            sync_interval_seconds: isFinite(interval) && interval > 0 ? interval : 0
        };
    }

    // classifyPolicy turns what a request threw into the outcome the card module
    // understands: a refusal has a status from the server, a dropped request has none.
    function classifyPolicy(err) {
        var answered = err && typeof err.status === 'number' && err.status > 0;
        var detail = policyErrorDetail(err);
        var text = policyText('policy_save_failed') + ': ' + detail;
        // Two sentences in one banner: the server's detail does not always end
        // with a stop, and without one the refusal reads as a run-on sentence.
        if (!/[.!?\u2026]$/.test(detail)) {
            text += '.';
        }
        return {
            outcome: answered ? 'refused' : 'failed',
            message: text + ' ' + policyText('policy_save_kept')
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
        var cards = root.SettingsCards;
        var saved = null;
        try {
            var settled = await cards.submit('policyRoutingCard', function () {
                var payload = policySavePayload();
                setPolicyAlert('', '');
                return policyRequest(POLICY_ENDPOINT, { method: 'PUT', body: payload }).then(function (answer) {
                    // The accepted write owns the form from now on: a read issued
                    // before it must not replace it when it lands later.
                    lastAcceptedMutation = seq;
                    saved = answer;
                    // Remembered either way; the fields are replaced only by the
                    // card module, and only when nothing was typed meanwhile.
                    applyPolicyRecord(answer, true);
                    return {
                        outcome: 'saved',
                        message: policyText('policy_saved'),
                        reconcile: function () { applyPolicyRecord(answer); }
                    };
                }, classifyPolicy);
            });
            if (settled.outcome !== 'saved') {
                // The refused edits were never stored, so they stay in the form and
                // the card stays marked unsaved. Only what the server is running is
                // refreshed, by a read that never touches the form. If that read
                // fails the last observation stays on screen, and it is never turned
                // into stored intent shown as a runtime "enabled".
                await refreshPolicyStatus();
                return null;
            }
            renderPolicyStatus(saved, policyRuntimeSnapshot(saved));
            try {
                var stats = await policyRequest(STATS_ENDPOINT, { method: 'GET' });
                renderPolicyCounters(stats);
            } catch (statsErr) {
                // Leave the last known counters in place rather than showing zeroes.
            }
            return saved;
        } finally {
            inFlight.save = false;
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

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', initPolicyRouting);
        } else {
            initPolicyRouting();
        }
    }
}(typeof window !== 'undefined' ? window : this));
