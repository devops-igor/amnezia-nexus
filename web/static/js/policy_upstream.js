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
    // The API stores up to three entries (policy.MaxUpstreams), and this editor
    // must be able to create, edit and reorder all three. The resolver, however,
    // queries only the first two in order, so the third is stored and shown but
    // is not contacted: the label says exactly that and never implies a standby
    // or failover capability the resolver does not have.
    var STORED_MAX = 3;
    var QUERIED_MAX = 2;
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

    // setAlert reports into the card's own two regions, the same ones every other
    // card has: a success goes to the status region and anything else to the alert
    // region, each with a role that never changes. An empty message clears both.
    // kind may also name the outcome ('conflict'), which is recorded on the region.
    function setAlert(kind, message) {
        var cards = root.SettingsCards;
        if (!cards) {
            return;
        }
        if (!message) {
            cards.clearReport('policyUpstreamCard');
            return;
        }
        cards.report('policyUpstreamCard', kind === 'success' ? 'success' : 'error', message,
            kind === 'success' ? 'saved' : (kind === 'conflict' ? 'conflict' : 'refused'));
    }

    // setBusy hands the save control to the card module: aria-busy on the card,
    // the disabled commit, the spinner and the focus that has to survive it. The
    // button label does not change, so the layout does not shift.
    function setBusy(busy) {
        if (root.SettingsCards) {
            root.SettingsCards.busy('policyUpstreamCard', busy);
        }
    }

    function paintRows() {
        rowNodes().forEach(function (node, index) {
            var label = node.querySelector('[data-upstream-role="label"]');
            if (label) {
                label.textContent = fill('policy_upstream_row_label', '{n}', String(index + 1));
            }
            var notQueried = node.querySelector('[data-upstream-role="not-queried"]');
            if (notQueried) {
                notQueried.classList.toggle('hidden', index < QUERIED_MAX);
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
        var invalid = errors.some(function (key) { return !!key; }) || rows.length > STORED_MAX;
        var form = element('policyUpstreamForm');
        if (form) {
            form.setAttribute('data-upstream-ready', ready ? 'true' : 'false');
        }
        var addBtn = element('policyUpstreamAddBtn');
        if (addBtn) {
            addBtn.disabled = blocked || rows.length >= STORED_MAX;
        }
        var defaultsBtn = element('policyUpstreamDefaultsBtn');
        if (defaultsBtn) {
            defaultsBtn.disabled = blocked;
        }
        var reloadBtn = element('policyUpstreamReloadBtn');
        if (reloadBtn) {
            reloadBtn.disabled = blocked;
        }
        if (root.SettingsCards) {
            root.SettingsCards.gate('policyUpstreamCard',
                blocked || invalid || !baseline || baseline.preset === '');
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
        if (root.SettingsCards) {
            root.SettingsCards.refresh('policyUpstreamCard');
        }
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

    // rebuildRows replaces the rows with a record's list and repaints. It does not
    // decide anything: callers call it only when replacing the editor is right.
    function rebuildRows(record) {
        var container = element('policyUpstreamRows');
        if (!container) {
            return;
        }
        container.innerHTML = '';
        record.upstream_dns.forEach(function (entry) {
            createRow(rowModel(entry));
        });
        refresh();
        if (root.SettingsCards) {
            root.SettingsCards.rebase('policyUpstreamCard');
        }
    }

    // applyRecord replaces the rows and the baseline with a record the operator is
    // meant to see: the first load, an explicit Reload, or a reset to the defaults.
    // It is never reached from a save outcome.
    function applyRecord(record) {
        if (!record) {
            return;
        }
        baseline = record;
        rebuildRows(record);
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

    // refreshHealth reads the stored record only to update the runtime
    // diagnostics. It never touches the rows or the baseline, so edits that were
    // refused stay in the editor. A failed read leaves the last observation on
    // screen, and a read that started before an accepted save is dropped.
    async function refreshHealth() {
        var seq = ++requestSeq;
        try {
            var record = await fetchRecord();
            if (seq > lastAcceptedMutation) {
                renderHealth(recordHealth(record));
            }
        } catch (err) {
            // The refusal is already on screen; there is nothing newer to show.
        }
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

    // classifySave turns what a request threw into the outcome the card module
    // understands: a refusal has a status from the server, a dropped request has none.
    function classifySave(err) {
        var code = err && err.data && typeof err.data === 'object' ? err.data.error : '';
        var key = code === 'state_inconsistent'
            ? 'policy_upstream_state_inconsistent'
            : 'policy_upstream_save_failed';
        var answered = err && typeof err.status === 'number' && err.status > 0;
        return {
            outcome: answered ? 'refused' : 'failed',
            message: text(key) + ': ' + errorDetail(err) + ' ' + text('policy_upstream_save_kept')
        };
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
        if (rows.length > STORED_MAX) {
            setAlert('error', text('policy_upstream_too_many'));
            return null;
        }
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
        var saved = null;
        try {
            refresh();
            var settled = await root.SettingsCards.submit('policyUpstreamCard', function () {
                return writeList(rows, seq).then(function (result) {
                    saved = result.saved || null;
                    // The request is over before the card module settles and puts
                    // focus back. inFlight gates the commit, so clearing it here
                    // makes the commit enabled again by the time focus is restored;
                    // clearing it afterwards would restore focus to a control that
                    // is still disabled and send it to the heading instead.
                    inFlight = false;
                    refresh();
                    return result;
                });
            });
            if (settled.outcome !== 'saved') {
                // Whatever went wrong, the rows and the unsaved mark stay. Only the
                // runtime diagnostics are refreshed, by a read that never touches
                // the editor. A conflict is the exception: the diagnostics belong to
                // the record somebody else saved, so they are not repainted either.
                if (settled.outcome !== 'conflict') await refreshHealth();
                return null;
            }
            return saved;
        } finally {
            inFlight = false;
            refresh();
        }
    }

    // writeList reads the stored record, refuses to overwrite one that changed since
    // the editor loaded it, and otherwise writes the edited list. It never changes
    // the editor: on a conflict it reports and returns, and the operator decides
    // whether to reload.
    async function writeList(rows, seq) {
        try {
            // A fresh read first: the whole record is replaced, so the four fields
            // the operator did not edit are echoed from here, never from the other
            // card's DOM or from markup defaults.
            var fresh = await fetchRecord();
            if (!sameList(fresh.upstream_dns, baseline.upstream_dns)) {
                return { outcome: 'conflict', message: text('policy_upstream_conflict') };
            }
            var payload = buildPayload(fresh, rows);
            var answer = await request(ENDPOINT, { method: 'PUT', body: payload });
            lastAcceptedMutation = seq;
            var saved = parseRecord(answer);
            if (!saved) {
                return { outcome: 'refused', message: text('policy_upstream_echo_mismatch') };
            }
            // The server accepted and stored the sent list. The baseline the next
            // save compares against moves to it now, and the rows are replaced only
            // by the card module, and only when nothing was typed meanwhile.
            baseline = saved;
            var mismatch = echoMismatch(payload, saved);
            if (mismatch) {
                // Unknown fields are ignored silently by the server, so a difference
                // here means the stored list is not the edited one: not a success.
                return {
                    outcome: 'refused',
                    message: text('policy_upstream_echo_mismatch') + ': ' + mismatch + ' ' + text('policy_upstream_save_kept')
                };
            }
            renderHealth(saved.policyStatus || saved.status);
            return {
                outcome: 'saved',
                message: text('policy_upstream_saved'),
                saved: saved,
                reconcile: function () { rebuildRows(saved); }
            };
        } catch (err) {
            return classifySave(err);
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
        if (readRows().length >= STORED_MAX) {
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
