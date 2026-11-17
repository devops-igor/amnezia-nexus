/* Admin controller for the upstream resolver editor (#865).
 *
 * The backend already owns every rule the editor needs: GET and PUT
 * /api/vpn/policy carry the persisted record, the PUT validates the whole
 * record before it is stored, and a refused activation is compensated by the
 * server. This module therefore never validates addresses or ports as an
 * authority, never guesses the effective default list and never sends a field
 * the operator did not edit from a value it invented:
 *
 *   - the rows are populated from GET, not from the markup, and every control
 *     stays disabled until that read has succeeded: before it the editor holds
 *     nothing, and a save would replace a stored list with an empty one;
 *   - a save re-reads the record first and refuses when another writer changed
 *     the upstream list in the meantime, because the PUT replaces the whole
 *     record and the other four fields are echoed from that fresh read;
 *   - `enabled` is never edited or toggled here. It is echoed exactly as read,
 *     because an upstream edit must not silently turn split egress on or off;
 *   - the answer is verified field by field. The server ignores unknown JSON
 *     fields, so a misspelled key would otherwise be dropped without an error
 *     and the editor would report a success that did not store what it sent;
 *   - an empty list is sent as an explicit `[]` and not as `null` or an omitted
 *     field: only `[]` means "use the built-in defaults", while an absent list
 *     means "keep the stored one";
 *   - the health line is the server's last runtime observation. It is never
 *     derived from the configured list, because the resolver keeps its last
 *     outcome until the next query: a named upstream may be one that is no
 *     longer configured.
 *
 * Nothing here is logged: a personal DoT hostname can identify a provider
 * account, so the operator-facing card is the only place an address appears.
 */

(function (root) {
    'use strict';

    var ENDPOINT = '/api/vpn/policy';
    // The resolver contacts the first two entries. MaxUpstreams (3) allows one
    // more to be stored, so adding stops at two while a third entry that is
    // already stored is rendered and labelled instead of being dropped.
    var ADD_CAP = 2;
    var STANDBY_FROM = 2;
    var TRANSPORT_DEFAULT_PORTS = { dot: 853, doh: 443 };
    // Closed set of failure kinds the resolver can report. A token outside it is
    // displayed verbatim rather than replaced by a guess.
    var FAILURE_KINDS = [
        'timeout', 'network', 'servfail', 'invalid_response', 'tls_handshake',
        'certificate', 'pin_mismatch', 'http_status', 'redirect', 'content_type',
        'response_too_large'
    ];

    var initialized = false;
    // Mutating controls stay inert until the stored record has been read.
    var ready = false;
    var inFlight = false;
    // Last record the server accepted. It is what a failed recovery read falls
    // back to, and what the health line is matched against.
    var baseline = null;
    // Newest runtime observation a response actually carried. Never rebuilt from
    // the stored record: intent and runtime are different facts.
    var lastHealth = null;
    var requestSeq = 0;
    var lastAcceptedMutation = 0;
    var busyFocus = null;

    function text(key) {
        if (typeof root._ === 'function') {
            var translated = root._(key);
            if (translated && translated !== key) {
                return translated;
            }
        }
        return key;
    }

    // fill substitutes one placeholder without the replace() special patterns.
    function fill(key, token, value) {
        return text(key).split(token).join(value);
    }

    function element(id) {
        if (!root.document) {
            return null;
        }
        return root.document.getElementById(id);
    }

    // Visibility is the repository's .hidden class (display: none !important), not
    // the hidden attribute: a class rule would otherwise outrank the attribute and
    // leave a warning permanently on screen.
    function setVisible(id, visible) {
        var el = element(id);
        if (el) {
            el.classList.toggle('hidden', !visible);
        }
    }

    function request(url, options) {
        if (!root.API || typeof root.API.request !== 'function') {
            var err = new Error(text('policy_upstream_load_failed'));
            err.status = 0;
            throw err;
        }
        // Every failure is rendered inline, so the shared client must not raise
        // its global toast for the same answer.
        return root.API.request(url, Object.assign({ silent: true }, options));
    }

    function errorDetail(err) {
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

    function defaultPort(transport) {
        return TRANSPORT_DEFAULT_PORTS[transport] || 0;
    }

    function normalizeEntry(entry) {
        var transport = typeof entry.transport === 'string' && entry.transport !== ''
            ? entry.transport
            : 'plain';
        var port = typeof entry.port === 'number' ? entry.port : defaultPort(transport);
        var pin = typeof entry.spki_pin === 'string' ? entry.spki_pin : '';
        return { address: entry.address, transport: transport, port: port, pin: pin };
    }

    // parseRecord accepts only a complete record. A response without an array
    // list or a string preset is malformed, and treating it as an empty list
    // would open the editor on a record nobody read.
    function parseRecord(payload) {
        if (!payload || typeof payload !== 'object') {
            return null;
        }
        if (!Array.isArray(payload.upstream_dns) || typeof payload.preset !== 'string'
            || typeof payload.enabled !== 'boolean'
            || typeof payload.sync_interval_seconds !== 'number'
            || !Array.isArray(payload.custom_urls)) {
            return null;
        }
        var list = [];
        for (var i = 0; i < payload.upstream_dns.length; i++) {
            var entry = payload.upstream_dns[i];
            if (!entry || typeof entry !== 'object' || typeof entry.address !== 'string') {
                return null;
            }
            list.push(normalizeEntry(entry));
        }
        return {
            enabled: payload.enabled,
            preset: payload.preset,
            custom_urls: payload.custom_urls.slice(),
            sync_interval_seconds: payload.sync_interval_seconds,
            upstream_dns: list,
            status: payload.status,
            policyStatus: payload.policy_status
        };
    }

    // runtimeSnapshot reads an observation. A PUT answers `status:"ok"`, which is
    // a result code; only an object carrying a boolean `enabled` is an
    // observation of the running policy.
    function runtimeSnapshot(payload) {
        if (!payload || typeof payload !== 'object' || typeof payload.enabled !== 'boolean') {
            return null;
        }
        return payload;
    }

    function recordHealth(record) {
        return runtimeSnapshot(record ? record.policyStatus : null)
            || runtimeSnapshot(record ? record.status : null);
    }

    // sameList compares the stored list the way the server replaces it: order
    // matters, and an empty list is a different list from an absent one.
    function sameList(left, right) {
        if (left.length !== right.length) {
            return false;
        }
        for (var i = 0; i < left.length; i++) {
            if (left[i].address !== right[i].address
                || left[i].transport !== right[i].transport
                || left[i].port !== right[i].port
                || left[i].pin !== right[i].pin) {
                return false;
            }
        }
        return true;
    }

    function effectivePort(row) {
        if (row.port === '' || row.port === null || typeof row.port === 'undefined') {
            return defaultPort(row.transport);
        }
        var parsed = Number(row.port);
        return isFinite(parsed) ? parsed : 0;
    }

    // upstreamString renders an entry exactly like the backend's Upstream.String:
    // a plain entry is host:port with IPv6 brackets, an encrypted one carries its
    // transport prefix, and the port is the effective one.
    function upstreamString(row) {
        var host = row.address;
        if (host.indexOf(':') !== -1) {
            host = '[' + host + ']';
        }
        var hostPort = host + ':' + String(effectivePort(row));
        if (row.transport === 'plain' || row.transport === '') {
            return hostPort;
        }
        return String(row.transport) + '://' + hostPort;
    }

    function rowNodes() {
        var container = element('policyUpstreamRows');
        if (!container || typeof container.querySelectorAll !== 'function') {
            return [];
        }
        return Array.prototype.slice.call(container.querySelectorAll('[data-upstream-role="row"]'));
    }

    function field(node, name) {
        return node.querySelector('[data-upstream-field="' + name + '"]');
    }

    function fieldValue(node, name) {
        var el = field(node, name);
        return el && typeof el.value === 'string' ? el.value : '';
    }

    function readRows() {
        return rowNodes().map(function (node) {
            return {
                address: fieldValue(node, 'address').trim(),
                port: fieldValue(node, 'port').trim(),
                transport: fieldValue(node, 'transport') || 'plain',
                pin: fieldValue(node, 'pin').trim()
            };
        });
    }

    function rowError(row) {
        if (!row.address) {
            return 'policy_upstream_address_required';
        }
        if (row.transport === 'doh' && /[/?#@]/.test(row.address)) {
            return 'policy_upstream_address_invalid_doh';
        }
        if (row.port === '') {
            return row.transport === 'plain' ? 'policy_upstream_port_required' : '';
        }
        var port = Number(row.port);
        if (!isFinite(port) || Math.floor(port) !== port || port < 1 || port > 65535) {
            return 'policy_upstream_port_invalid';
        }
        return '';
    }

    // rowErrors reports the client-side shape problems one per row. They are a
    // convenience: the server stays the authority and its message is shown as is.
    function rowErrors(rows) {
        var seen = {};
        return rows.map(function (row) {
            var key = rowError(row);
            if (key) {
                return key;
            }
            var identity = row.transport + '|' + upstreamString(row).toLowerCase();
            if (seen[identity]) {
                return 'policy_upstream_duplicate';
            }
            seen[identity] = true;
            return '';
        });
    }

    function setAlert(kind, message) {
        var banner = element('policyUpstreamAlert');
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
        // light and dark variants. The text keeps the primary colour because the
        // state is also carried by the tint, the border and the wording.
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

    function setBusy(busy) {
        var button = element('policyUpstreamSaveBtn');
        var spinner = element('policyUpstreamSaveSpinner');
        var label = element('policyUpstreamSaveBtnText');
        if (button) {
            if (busy && root.document && root.document.activeElement === button) {
                busyFocus = button;
            }
            button.setAttribute('aria-busy', busy ? 'true' : 'false');
            if (!busy) {
                // Disabling a focused control drops focus to the body; give it back.
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
            label.textContent = busy
                ? text('policy_upstream_saving')
                : text('policy_upstream_save_btn');
        }
    }

    function paintRows() {
        rowNodes().forEach(function (node, index) {
            var label = node.querySelector('[data-upstream-role="label"]');
            if (label) {
                label.textContent = fill('policy_upstream_row_label', '{n}', String(index + 1));
            }
            var standby = node.querySelector('[data-upstream-role="standby"]');
            if (standby) {
                standby.classList.toggle('hidden', index < STANDBY_FROM);
            }
        });
    }

    function paintRowErrors(errors) {
        rowNodes().forEach(function (node, index) {
            var slot = node.querySelector('[data-upstream-role="error"]');
            if (!slot) {
                return;
            }
            var key = errors[index] || '';
            slot.textContent = key ? text(key) : '';
        });
    }

    function paintPinGate(node) {
        var transport = fieldValue(node, 'transport') || 'plain';
        var pin = field(node, 'pin');
        if (!pin) {
            return;
        }
        var refused = transport === 'plain';
        pin.disabled = refused || !ready || inFlight;
        if (refused && pin.value !== '') {
            // The server refuses a pin on a plain entry, so it is cleared here
            // instead of being sent and rejected.
            pin.value = '';
        }
    }

    function paintRowControls() {
        var blocked = !ready || inFlight;
        rowNodes().forEach(function (node) {
            Array.prototype.forEach.call(
                node.querySelectorAll('[data-upstream-field], [data-upstream-action]'),
                function (control) {
                    control.disabled = blocked;
                }
            );
            paintPinGate(node);
        });
    }

    function paintGates(rows, errors) {
        var blocked = !ready || inFlight;
        var invalid = errors.some(function (key) { return !!key; });
        var form = element('policyUpstreamForm');
        if (form) {
            form.setAttribute('data-upstream-ready', ready ? 'true' : 'false');
        }
        var addBtn = element('policyUpstreamAddBtn');
        if (addBtn) {
            addBtn.disabled = blocked || rows.length >= ADD_CAP;
        }
        var defaultsBtn = element('policyUpstreamDefaultsBtn');
        if (defaultsBtn) {
            defaultsBtn.disabled = blocked;
        }
        var reloadBtn = element('policyUpstreamReloadBtn');
        if (reloadBtn) {
            reloadBtn.disabled = blocked;
        }
        var saveBtn = element('policyUpstreamSaveBtn');
        if (saveBtn) {
            saveBtn.disabled = blocked || invalid || !baseline || baseline.preset === '';
        }
        paintRowControls();
    }

    function paintWarnings(rows) {
        var anyPlain = rows.some(function (row) { return row.transport === 'plain'; });
        setVisible('policyUpstreamPlainWarning', ready && anyPlain);
        var mixed = false;
        var sawEncrypted = false;
        rows.forEach(function (row) {
            if (row.transport !== 'plain') {
                sawEncrypted = true;
            } else if (sawEncrypted) {
                // Configured order, not a defect: the resolver fails over to the
                // plain entry and continues in plaintext.
                mixed = true;
            }
        });
        setVisible('policyUpstreamMixedWarning', ready && mixed);
    }

    function paintSaveEffects() {
        var box = element('policyUpstreamSaveEffects');
        var label = element('policyUpstreamSaveEffectsText');
        if (!box || !label) {
            return;
        }
        var message = '';
        if (ready && baseline) {
            if (baseline.preset === '') {
                message = text('policy_upstream_needs_source');
            } else if (baseline.enabled) {
                message = lastHealth && lastHealth.enabled === false
                    ? text('policy_upstream_activation_save_notice')
                    : text('policy_upstream_enabled_save_notice');
            }
        }
        label.textContent = message;
        box.classList.toggle('hidden', message === '');
    }

    function paintDefaultsNotice(rows) {
        // An empty stored list means the built-in defaults, not "no resolver".
        // The addresses are not part of the API answer, so they are not repeated
        // here: a second definition could drift from the backend one.
        var notice = element('policyUpstreamDefaultsNotice');
        if (notice) {
            notice.classList.toggle('hidden', !(ready && rows.length === 0));
        }
    }

    // refresh repaints every derived view from the current DOM rows. It is the
    // only place the gates, warnings and row errors are computed.
    function refresh() {
        var rows = readRows();
        var errors = rowErrors(rows);
        paintRows();
        paintRowErrors(errors);
        paintWarnings(rows);
        paintDefaultsNotice(rows);
        paintGates(rows, errors);
        paintSaveEffects();
    }

    function failureKindLabel(kind) {
        if (FAILURE_KINDS.indexOf(kind) === -1) {
            return kind;
        }
        return text('policy_upstream_failure_' + kind);
    }

    function matchesStoredRow(name) {
        if (!baseline) {
            return false;
        }
        return baseline.upstream_dns.some(function (entry) {
            return upstreamString(entry) === name;
        });
    }

    // renderHealth shows the last observation the server reported. It is a
    // snapshot of the previous exchange, not a test of the list being edited. A
    // successful read that carries no runtime observation is not "no change": it
    // means this deployment does not report one.
    function renderHealth(payload) {
        var snapshot = runtimeSnapshot(payload);
        lastHealth = snapshot;
        var stateEl = element('policyUpstreamHealthState');
        var failureEl = element('policyUpstreamHealthFailure');
        if (failureEl) {
            failureEl.textContent = '';
        }
        if (!stateEl) {
            return;
        }
        if (!snapshot) {
            stateEl.textContent = text('policy_upstream_health_none');
            paintSaveEffects();
            return;
        }
        if (!snapshot.enabled) {
            stateEl.textContent = text('policy_upstream_health_off');
            paintSaveEffects();
            return;
        }
        var last = typeof snapshot.last_upstream === 'string' ? snapshot.last_upstream : '';
        if (!last) {
            stateEl.textContent = text('policy_upstream_health_waiting');
        } else if (matchesStoredRow(last)) {
            stateEl.textContent = fill('policy_upstream_health_last', '{upstream}', last);
        } else {
            stateEl.textContent = fill('policy_upstream_health_not_in_list', '{upstream}', last);
        }
        if (!failureEl) {
            return;
        }
        var failure = typeof snapshot.last_upstream_failure === 'string' ? snapshot.last_upstream_failure : '';
        var kind = typeof snapshot.last_upstream_failure_kind === 'string' ? snapshot.last_upstream_failure_kind : '';
        if (kind) {
            failureEl.textContent = fill('policy_upstream_health_failure', '{kind}', failureKindLabel(kind))
                + (failure ? ': ' + failure : '');
        } else if (failure) {
            // A failure without a kind is still shown as text, never as markup.
            failureEl.textContent = fill('policy_upstream_health_failure', '{kind}', failure);
        }
        paintSaveEffects();
    }

    function rowModel(entry) {
        return {
            address: entry.address,
            port: entry.port ? String(entry.port) : '',
            transport: entry.transport,
            pin: entry.pin
        };
    }

    function createRow(model) {
        var template = element('policyUpstreamRowTemplate');
        var container = element('policyUpstreamRows');
        if (!template || !container || !template.content) {
            return null;
        }
        var node = template.content.cloneNode(true).querySelector('[data-upstream-role="row"]');
        if (!node) {
            return null;
        }
        field(node, 'address').value = model.address;
        field(node, 'port').value = model.port;
        field(node, 'transport').value = model.transport;
        field(node, 'pin').value = model.pin;
        node.querySelectorAll('[data-upstream-field]').forEach(function (control) {
            control.addEventListener('input', refresh);
            control.addEventListener('change', function () {
                paintPinGate(node);
                refresh();
            });
        });
        node.querySelectorAll('[data-upstream-action]').forEach(function (button) {
            button.addEventListener('click', function (event) {
                event.preventDefault();
                var action = button.getAttribute('data-upstream-action');
                if (action === 'remove') {
                    node.remove();
                    refresh();
                } else {
                    moveRow(node, action === 'up' ? -1 : 1);
                }
            });
        });
        container.appendChild(node);
        paintPinGate(node);
        return node;
    }

    function moveRow(node, delta) {
        var container = element('policyUpstreamRows');
        if (!container) {
            return;
        }
        if (delta < 0 && node.previousElementSibling) {
            container.insertBefore(node, node.previousElementSibling);
        } else if (delta > 0 && node.nextElementSibling) {
            container.insertBefore(node.nextElementSibling, node);
        }
        refresh();
    }

    // applyRecord replaces the rows and the baseline with an accepted record.
    function applyRecord(record) {
        if (!record) {
            return;
        }
        baseline = record;
        var container = element('policyUpstreamRows');
        if (!container) {
            return;
        }
        container.innerHTML = '';
        record.upstream_dns.forEach(function (entry) {
            createRow(rowModel(entry));
        });
        refresh();
    }

    function fetchRecord() {
        return request(ENDPOINT, { method: 'GET' }).then(function (payload) {
            var record = parseRecord(payload);
            if (!record) {
                var err = new Error(text('policy_upstream_load_failed'));
                err.status = 0;
                throw err;
            }
            return record;
        });
    }

    // load applies a read unless a mutation was accepted after it was issued, so
    // a slow earlier read cannot replace a newer accepted record.
    async function load(seq) {
        var record = await fetchRecord();
        if (seq <= lastAcceptedMutation) {
            return record;
        }
        applyRecord(record);
        renderHealth(recordHealth(record));
        return record;
    }

    function setReady(value) {
        ready = !!value;
        refresh();
    }

    function buildPayload(record, rows) {
        return {
            enabled: record.enabled,
            preset: record.preset,
            custom_urls: record.custom_urls.slice(),
            sync_interval_seconds: record.sync_interval_seconds,
            upstream_dns: rows.map(function (row) {
                var entry = { address: row.address, transport: row.transport };
                if (row.port !== '') {
                    entry.port = Number(row.port);
                }
                if (row.transport !== 'plain' && row.pin) {
                    entry.spki_pin = row.pin;
                }
                return entry;
            })
        };
    }

    // echoMismatch compares the stored answer with what was sent, after the
    // server filled transport default ports. It returns a short description of
    // the first difference, or an empty string.
    function echoMismatch(payload, saved) {
        var expected = payload.upstream_dns.map(function (entry) {
            return {
                address: entry.address,
                transport: entry.transport || 'plain',
                port: typeof entry.port === 'number' ? entry.port : defaultPort(entry.transport),
                pin: entry.spki_pin || ''
            };
        });
        var actual = saved.upstream_dns;
        if (expected.length !== actual.length) {
            return 'count ' + actual.length + ' != ' + expected.length;
        }
        for (var i = 0; i < expected.length; i++) {
            if (expected[i].address !== actual[i].address) {
                return 'row ' + (i + 1) + ' address';
            }
            if (expected[i].transport !== actual[i].transport) {
                return 'row ' + (i + 1) + ' transport';
            }
            if (expected[i].port !== actual[i].port) {
                return 'row ' + (i + 1) + ' port';
            }
            if (expected[i].pin !== actual[i].pin) {
                return 'row ' + (i + 1) + ' pin';
            }
        }
        return '';
    }

    async function save() {
        if (!ready) {
            setAlert('error', text('policy_upstream_not_ready'));
            return null;
        }
        if (inFlight) {
            return null;
        }
        var rows = readRows();
        var firstError = rowErrors(rows).filter(Boolean)[0];
        if (firstError) {
            setAlert('error', text(firstError));
            return null;
        }
        if (!baseline) {
            setAlert('error', text('policy_upstream_not_ready'));
            return null;
        }
        if (baseline.preset === '') {
            // The server refuses a save without a preset, and the editor must not
            // invent one: choosing a list source is the operator's decision.
            setAlert('error', text('policy_upstream_needs_source'));
            return null;
        }
        inFlight = true;
        var seq = ++requestSeq;
        setBusy(true);
        setAlert('', '');
        refresh();
        try {
            // A fresh read first: the whole record is replaced, so the four
            // fields the operator did not edit are echoed from here, never from
            // the other card's DOM or from markup defaults.
            var fresh = await fetchRecord();
            if (!sameList(fresh.upstream_dns, baseline.upstream_dns)) {
                applyRecord(fresh);
                renderHealth(recordHealth(fresh));
                setAlert('error', text('policy_upstream_conflict'));
                return null;
            }
            var payload = buildPayload(fresh, rows);
            var answer = await request(ENDPOINT, { method: 'PUT', body: payload });
            lastAcceptedMutation = seq;
            var saved = parseRecord(answer);
            if (!saved) {
                setAlert('error', text('policy_upstream_echo_mismatch'));
                return null;
            }
            applyRecord(saved);
            renderHealth(saved.policyStatus || saved.status);
            var mismatch = echoMismatch(payload, saved);
            if (mismatch) {
                // Unknown fields are ignored silently by the server, so a
                // difference here means the stored list is not the edited one.
                setAlert('error', text('policy_upstream_echo_mismatch') + ': ' + mismatch);
                return null;
            }
            setAlert('success', text('policy_upstream_saved'));
            return saved;
        } catch (err) {
            var code = err && err.data && typeof err.data === 'object' ? err.data.error : '';
            var key = code === 'state_inconsistent'
                ? 'policy_upstream_state_inconsistent'
                : 'policy_upstream_save_failed';
            setAlert('error', text(key) + ': ' + errorDetail(err) + ' ' + text('policy_upstream_save_refused'));
            // Re-read the stored record so a rejected edit is not left on screen.
            // When that read fails too, the last accepted record is restored and
            // no success is claimed.
            try {
                await load(++requestSeq);
            } catch (reloadErr) {
                if (baseline) {
                    applyRecord(baseline);
                }
            }
            return null;
        } finally {
            inFlight = false;
            setBusy(false);
            refresh();
        }
    }

    async function reload() {
        if (!ready || inFlight) {
            return null;
        }
        setAlert('', '');
        try {
            return await load(++requestSeq);
        } catch (err) {
            setAlert('error', text('policy_upstream_load_failed') + ': ' + errorDetail(err));
            return null;
        }
    }

    function addRow() {
        if (!ready || inFlight) {
            return false;
        }
        if (readRows().length >= ADD_CAP) {
            return false;
        }
        if (!createRow({ address: '', port: '', transport: 'plain', pin: '' })) {
            return false;
        }
        refresh();
        return true;
    }

    // useDefaults sends an explicit empty list, which is the only value that
    // resets the record to the built-in defaults. It is a save like any other,
    // so it goes through the same fresh read and conflict refusal.
    async function useDefaults() {
        if (!ready || inFlight) {
            return null;
        }
        var container = element('policyUpstreamRows');
        if (container) {
            container.innerHTML = '';
        }
        refresh();
        return save();
    }

    function init() {
        var form = element('policyUpstreamForm');
        if (!form) {
            return false;
        }
        if (initialized) {
            return true;
        }
        initialized = true;
        setReady(false);

        form.addEventListener('submit', function (event) {
            event.preventDefault();
            save();
        });
        var saveBtn = element('policyUpstreamSaveBtn');
        if (saveBtn) {
            saveBtn.addEventListener('click', function (event) {
                event.preventDefault();
                save();
            });
        }
        var addBtn = element('policyUpstreamAddBtn');
        if (addBtn) {
            addBtn.addEventListener('click', function (event) {
                event.preventDefault();
                addRow();
            });
        }
        var defaultsBtn = element('policyUpstreamDefaultsBtn');
        if (defaultsBtn) {
            defaultsBtn.addEventListener('click', function (event) {
                event.preventDefault();
                useDefaults();
            });
        }
        var reloadBtn = element('policyUpstreamReloadBtn');
        if (reloadBtn) {
            reloadBtn.addEventListener('click', function (event) {
                event.preventDefault();
                reload();
            });
        }

        load(++requestSeq).then(function () {
            setReady(true);
        }).catch(function (err) {
            // Without an authoritative read there is nothing safe to submit: the
            // editor has no rows and no baseline, so it stays read-only.
            setReady(false);
            setAlert('error', text('policy_upstream_load_failed') + ': '
                + errorDetail(err) + ' ' + text('policy_upstream_not_ready'));
        });
        return true;
    }

    root.PolicyUpstreamEditor = {
        init: init,
        save: save,
        reload: reload,
        useDefaults: useDefaults,
        addRow: addRow
    };

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }
}(typeof window !== 'undefined' ? window : this));
