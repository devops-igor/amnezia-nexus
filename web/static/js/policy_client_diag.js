/* Admin controller for the per-client diagnosis section (#861).
 *
 * The server is the only authority for this panel. The controller:
 *
 *   - lists selectable session incarnations from GET /api/vpn/policy/clients and
 *     never derives one from a connection, a user or the session table;
 *   - sends the exact selection the operator made, including its route
 *     generation, so the answer is bound to one incarnation;
 *   - clears the previous answer whenever the selection changes, and drops any
 *     response that arrives after a newer one — a late answer for client A must
 *     never render under client B;
 *   - refuses to render an answer that does not echo the session it asked for;
 *   - renders only what the answer says, with every unknown token shown as the
 *     server named it. It never infers a name, a cause, a decision time or a
 *     success from a route, an address or a timestamp.
 *
 * There is no polling: the list and the answer refresh only when the operator
 * asks. Query names are browsing metadata, so a background refresh would read it
 * for nobody.
 */

(function (root) {
    'use strict';

    var CLIENTS_ENDPOINT = '/api/vpn/policy/clients';
    var DIAG_ENDPOINT = '/api/vpn/policy/client-diagnosis';
    // Every user-visible string resolves through the shipped dictionaries. A key
    // with no translation is shown as the key itself: the panel never invents
    // wording.
    var TEXT_PREFIX = 'policy_client_';

    var initialized = false;
    // The newest request issued. A response whose sequence is not this one is
    // stale and is dropped, which is what keeps two deferred answers from
    // rendering in reverse order.
    var sequence = 0;
    var lastRendered = 0;
    var inFlight = {list: false, diagnose: false};
    // The last list the server returned, so the picker can be rebuilt without
    // re-reading it.
    var lastClients = [];
    var policyRoutingEnabled = false;

    function clientText(key) {
        if (typeof root._ === 'function') {
            var translated = root._(key);
            if (translated && translated !== key) {
                return translated;
            }
        }
        return key;
    }

    // clientTokenLabel translates a protocol token the server sent, falling back
    // to the token itself so a value this build does not know is still visible
    // instead of being replaced by a guess.
    function clientTokenLabel(kind, token) {
        if (!token) {
            return '';
        }
        var key = TEXT_PREFIX + kind + '_' + String(token).toLowerCase();
        if (typeof root._ === 'function') {
            var translated = root._(key);
            if (translated && translated !== key) {
                return translated;
            }
        }
        return token;
    }

    function clientElement(id) {
        if (!root.document) {
            return null;
        }
        return root.document.getElementById(id);
    }

    function clientRequest(url, options) {
        if (!root.API || typeof root.API.request !== 'function') {
            var err = new Error(clientText('policy_client_load_failed'));
            err.status = 0;
            return Promise.reject(err);
        }
        return root.API.request(url, options);
    }

    function clientErrorDetail(err) {
        if (!err) {
            return '';
        }
        if (err.data && typeof err.data.detail === 'string' && err.data.detail) {
            return err.data.detail;
        }
        if (typeof err.message === 'string' && err.message) {
            return err.message;
        }
        return '';
    }

    function setClientAlert(state, text) {
        var alert = clientElement('policyClientAlert');
        if (!alert) {
            return;
        }
        alert.textContent = text || '';
        alert.setAttribute('data-state', state || '');
        alert.style.display = text ? 'block' : 'none';
    }

    function setClientStatus(text) {
        var status = clientElement('policyClientStatus');
        if (status) {
            status.textContent = text || '';
        }
    }

    function setClientBusy(which, busy) {
        inFlight[which] = busy;
        var button = clientElement(which === 'list' ? 'policyClientRefreshBtn' : 'policyClientDiagnoseBtn');
        var spinner = clientElement(which === 'list' ? 'policyClientRefreshSpinner' : 'policyClientDiagnoseSpinner');
        if (button) {
            if (busy) {
                button.setAttribute('disabled', 'disabled');
                button.setAttribute('aria-busy', 'true');
            } else {
                button.removeAttribute('aria-busy');
                button.removeAttribute('disabled');
            }
        }
        if (spinner) {
            if (busy) {
                spinner.classList.remove('hidden');
            } else {
                spinner.classList.add('hidden');
            }
        }
        if (which === 'diagnose') {
            applyDiagnoseAvailability();
        }
    }

    // applyDiagnoseAvailability keeps the diagnose control inert unless a real
    // incarnation is selected and policy routing is on.
    function applyDiagnoseAvailability() {
        var button = clientElement('policyClientDiagnoseBtn');
        var select = clientElement('policyClientSelect');
        if (!button) {
            return;
        }
        var selectable = !!(select && select.value) && policyRoutingEnabled && !inFlight.diagnose;
        if (selectable) {
            button.removeAttribute('disabled');
        } else {
            button.setAttribute('disabled', 'disabled');
        }
    }

    function clearClientResult() {
        var result = clientElement('policyClientResult');
        if (result) {
            result.hidden = true;
        }
        var rows = clientElement('policyClientEvidenceRows');
        if (rows) {
            while (rows.firstChild) {
                rows.removeChild(rows.firstChild);
            }
        }
        rows = clientElement('policyClientFlowRows');
        if (rows) {
            while (rows.firstChild) {
                rows.removeChild(rows.firstChild);
            }
        }
        rows = clientElement('policyClientDNSRows');
        if (rows) {
            while (rows.firstChild) {
                rows.removeChild(rows.firstChild);
            }
        }
        var gaps = clientElement('policyClientDNSGaps');
        if (gaps) {
            while (gaps.firstChild) {
                gaps.removeChild(gaps.firstChild);
            }
        }
        var coverage = clientElement('policyClientDNSCoverage');
        if (coverage) {
            coverage.textContent = '';
        }
        var limits = clientElement('policyClientLimitations');
        if (limits) {
            while (limits.firstChild) {
                limits.removeChild(limits.firstChild);
            }
        }
        ['policyClientSessionValue', 'policyClientStateValue', 'policyClientGenerationValue', 'policyClientEvaluatedValue'].forEach(function (id) {
            var el = clientElement(id);
            if (el) {
                el.textContent = '-';
            }
        });
        ['policyClientEvidenceFoot', 'policyClientFlowFoot', 'policyClientDNSFoot'].forEach(function (id) {
            var el = clientElement(id);
            if (el) {
                el.hidden = true;
                el.textContent = '';
            }
        });
    }

    // selectedOption returns the chosen incarnation, or null. The route
    // generation travels with the option, so a rekey between listing and
    // diagnosis is visible to the server instead of silently following the newest
    // incarnation.
    function selectedOption() {
        var select = clientElement('policyClientSelect');
        if (!select || !select.value) {
            return null;
        }
        for (var i = 0; i < lastClients.length; i++) {
            if (lastClients[i].session_id === select.value) {
                return lastClients[i];
            }
        }
        return null;
    }

    function clientOptionLabel(client) {
        var parts = [];
        if (client.assigned_ip) {
            parts.push(client.assigned_ip);
        }
        if (client.connection_name) {
            parts.push(client.connection_name);
        } else if (client.connection_id) {
            parts.push(client.connection_id);
        }
        if (!client.route_live) {
            parts.push(clientText('policy_client_no_route_suffix'));
        }
        return parts.join(' · ') || client.session_id;
    }

    function renderClientPicker(clients) {
        var select = clientElement('policyClientSelect');
        if (!select) {
            return;
        }
        var previous = select.value;
        while (select.firstChild) {
            select.removeChild(select.firstChild);
        }
        var placeholder = root.document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = clientText('policy_client_select_placeholder');
        select.appendChild(placeholder);

        clients.forEach(function (client) {
            var option = root.document.createElement('option');
            option.value = client.session_id;
            option.textContent = clientOptionLabel(client);
            if (client.route_generation) {
                option.setAttribute('data-route-generation', String(client.route_generation));
            }
            select.appendChild(option);
        });

        // Keep the operator's choice across a refresh when the incarnation still
        // exists; otherwise the selection is gone and the answer must be too.
        var stillPresent = clients.some(function (client) {
            return client.session_id === previous;
        });
        if (stillPresent) {
            select.value = previous;
        } else {
            select.value = '';
            if (previous) {
                clearClientResult();
            }
        }
        applyDiagnoseAvailability();
    }

    // refreshPolicyClients reads the selectable incarnations. It is the only
    // list source; nothing here derives a session from another fact.
    function refreshPolicyClients() {
        if (inFlight.list) {
            return Promise.resolve(null);
        }
        setClientBusy('list', true);
        setClientStatus(clientText('policy_client_loading'));
        return clientRequest(CLIENTS_ENDPOINT, {method: 'GET'}).then(function (answer) {
            setClientBusy('list', false);
            lastClients = (answer && answer.clients) || [];
            policyRoutingEnabled = !!(answer && answer.policy_routing_enabled);
            renderClientPicker(lastClients);
            setClientStatus('');
            if (!policyRoutingEnabled) {
                setClientAlert('policy-off', clientText('policy_client_policy_off'));
                return answer;
            }
            setClientAlert('', '');
            if (lastClients.length === 0) {
                setClientStatus(clientText('policy_client_no_clients'));
            }
            return answer;
        }).catch(function (err) {
            setClientBusy('list', false);
            lastClients = [];
            policyRoutingEnabled = false;
            renderClientPicker([]);
            setClientStatus('');
            setClientAlert('error', clientFailureText(err));
            return null;
        });
    }

    function clientFailureText(err) {
        var status = err && typeof err.status === 'number' ? err.status : 0;
        if (status === 403 || status === 401) {
            return clientText('policy_client_permission_denied');
        }
        if (status === 429) {
            return clientText('policy_client_busy');
        }
        var detail = clientErrorDetail(err);
        if (detail) {
            return clientText('policy_client_failed') + ': ' + detail;
        }
        return clientText('policy_client_failed');
    }

    function appendCell(row, text) {
        var cell = root.document.createElement('td');
        cell.textContent = text == null || text === '' ? '-' : String(text);
        row.appendChild(cell);
        return cell;
    }

    function renderEvidence(entries) {
        var body = clientElement('policyClientEvidenceRows');
        if (!body) {
            return;
        }
        entries.forEach(function (entry) {
            var row = root.document.createElement('tr');
            appendCell(row, entry.address);
            appendCell(row, clientTokenLabel('decision', entry.decision));
            appendCell(row, entry.observed_at);
            appendCell(row, entry.expires_at);
            appendCell(row, entry.state);
            body.appendChild(row);
        });
    }

    function renderFlows(entries) {
        var body = clientElement('policyClientFlowRows');
        if (!body) {
            return;
        }
        entries.forEach(function (flow) {
            var row = root.document.createElement('tr');
            appendCell(row, clientTokenLabel('protocol', flow.protocol));
            appendCell(row, flow.destination_ip + ':' + String(flow.destination_port));
            appendCell(row, clientTokenLabel('decision', flow.choice));
            appendCell(row, formatSeconds(flow.last_seen_age_seconds));
            var state = flow.expired ? 'expired' : 'active';
            if (flow.close_seen) {
                state = state + '/closed';
            }
            appendCell(row, state);
            body.appendChild(row);
        });
    }

    function formatSeconds(seconds) {
        if (typeof seconds !== 'number' || !isFinite(seconds)) {
            return '-';
        }
        return clientText('policy_client_seconds').replace('{seconds}', String(Math.max(0, Math.floor(seconds))));
    }

    // renderDNSRecords renders the observed answers. The name, its validated
    // aliases and the addresses with their decisions are the record's own facts;
    // nothing here re-derives a decision or a name.
    function renderDNSRecords(records) {
        var body = clientElement('policyClientDNSRows');
        if (!body) {
            return;
        }
        records.forEach(function (record) {
            var row = root.document.createElement('tr');
            var name = record.name || '';
            if (record.aliases && record.aliases.length) {
                name = name + ' → ' + record.aliases.join(' → ');
            }
            appendCell(row, name);
            appendCell(row, record.qtype);
            var addresses = (record.addresses || []).map(function (entry) {
                return entry.address + ' (' + clientTokenLabel('decision', entry.decision) + ')';
            }).join(', ');
            appendCell(row, addresses);
            appendCell(row, record.observed_at);
            appendCell(row, record.expires_at);
            appendCell(row, String(record.count || 1));
            appendCell(row, clientTokenLabel('state', record.state));
            body.appendChild(row);
        });
    }

    function renderDNSCoverage(coverage) {
        var el = clientElement('policyClientDNSCoverage');
        if (el) {
            if (!coverage) {
                el.textContent = '';
            } else {
                el.textContent = clientText('policy_client_dns_coverage')
                    .replace('{stored}', String(coverage.records_stored || 0))
                    .replace('{collapsed}', String(coverage.collapsed || 0))
                    .replace('{evicted}', String((coverage.evicted_per_session || 0) + (coverage.evicted_global || 0)))
                    .replace('{aged}', String(coverage.aged_out || 0));
            }
        }
        var gaps = clientElement('policyClientDNSGaps');
        if (gaps && coverage && coverage.not_recorded) {
            coverage.not_recorded.forEach(function (token) {
                var item = root.document.createElement('li');
                item.textContent = clientTokenLabel('limit', token);
                gaps.appendChild(item);
            });
        }
    }

    function renderLimitations(limitations) {
        var list = clientElement('policyClientLimitations');
        if (!list) {
            return;
        }
        (limitations || []).forEach(function (token) {
            var item = root.document.createElement('li');
            item.textContent = clientTokenLabel('limit', token);
            list.appendChild(item);
        });
    }

    function renderFoot(id, text) {
        var el = clientElement(id);
        if (!el) {
            return;
        }
        el.textContent = text || '';
        el.hidden = !text;
    }

    function renderClientDiagnosis(answer) {
        var selection = (answer && answer.selection) || {};
        var dns = (answer && answer.dns) || {};
        var flows = (answer && answer.flows) || {};

        var session = clientElement('policyClientSessionValue');
        if (session) {
            session.textContent = selection.session_id || '-';
        }
        var state = clientElement('policyClientStateValue');
        if (state) {
            state.textContent = clientTokenLabel('state', selection.state);
        }
        var generation = clientElement('policyClientGenerationValue');
        if (generation) {
            generation.textContent = selection.route_generation ? String(selection.route_generation) : '-';
        }
        var evaluated = clientElement('policyClientEvaluatedValue');
        if (evaluated) {
            evaluated.textContent = (answer && answer.evaluated_at) || '-';
        }

        renderEvidence(dns.entries || []);
        renderDNSRecords(dns.records || []);
        renderDNSCoverage(dns.record_coverage);
        renderFlows(flows.entries || []);
        renderLimitations((answer && answer.limitations) || []);

        var evidenceFoot = '';
        if (!(dns.entries || []).length) {
            evidenceFoot = clientText('policy_client_empty_evidence');
        } else if (dns.truncated) {
            evidenceFoot = clientText('policy_client_truncated').replace('{shown}', String((dns.entries || []).length)).replace('{total}', String(dns.total || 0));
        }
        renderFoot('policyClientEvidenceFoot', evidenceFoot);

        var dnsFoot = '';
        if (!(dns.records || []).length) {
            dnsFoot = dns.records_available ? clientText('policy_client_dns_empty') : clientText('policy_client_dns_not_recorded');
        } else if (dns.records_truncated) {
            dnsFoot = clientText('policy_client_dns_truncated')
                .replace('{shown}', String((dns.records || []).length))
                .replace('{total}', String(dns.records_total || 0));
        }
        renderFoot('policyClientDNSFoot', dnsFoot);

        var flowFoot = '';
        if (!(flows.entries || []).length) {
            flowFoot = clientText('policy_client_empty_flows');
        } else {
            flowFoot = clientText('policy_client_flow_count').replace('{shown}', String((flows.entries || []).length)).replace('{total}', String(flows.total || 0));
            if (!flows.scan_complete) {
                flowFoot = flowFoot + ' ' + clientText('policy_client_partial_scan').replace('{scanned}', String(flows.scanned || 0));
            }
        }
        renderFoot('policyClientFlowFoot', flowFoot);

        var result = clientElement('policyClientResult');
        if (result) {
            result.hidden = false;
        }
    }

    // diagnoseSelectedClient reads the retained state of the selected
    // incarnation. Its answer is applied only when it is the newest request AND
    // it echoes the session that was asked for.
    function diagnoseSelectedClient() {
        var client = selectedOption();
        if (!client) {
            setClientStatus(clientText('policy_client_select_prompt'));
            return Promise.resolve(null);
        }
        if (inFlight.diagnose) {
            return Promise.resolve(null);
        }

        var sentSession = client.session_id;
        var body = {session_id: sentSession};
        if (client.route_generation) {
            body.route_generation = client.route_generation;
        }
        var requestId = ++sequence;

        setClientBusy('diagnose', true);
        setClientStatus(clientText('policy_client_diagnosing'));
        clearClientResult();

        return clientRequest(DIAG_ENDPOINT, {method: 'POST', body: body}).then(function (answer) {
            setClientBusy('diagnose', false);
            setClientStatus('');
            if (requestId !== sequence) {
                // A newer request has been issued; this answer belongs to a
                // selection the operator already left.
                return null;
            }
            var echoed = answer && answer.selection && answer.selection.session_id;
            if (echoed !== sentSession) {
                // The answer is about another incarnation (or carries none), so
                // rendering it would attribute one client's records to another.
                setClientAlert('stale', clientText('policy_client_stale_answer'));
                return null;
            }
            lastRendered = requestId;
            setClientAlert('', '');
            renderClientDiagnosis(answer);
            return answer;
        }).catch(function (err) {
            setClientBusy('diagnose', false);
            if (requestId !== sequence) {
                return null;
            }
            setClientStatus('');
            setClientAlert('error', clientFailureText(err));
            return null;
        });
    }

    function initPolicyClientDiagnosis() {
        var card = clientElement('policyClientCard');
        if (!card || initialized) {
            return initialized ? true : false;
        }
        initialized = true;

        var refresh = clientElement('policyClientRefreshBtn');
        if (refresh) {
            refresh.addEventListener('click', function () {
                refreshPolicyClients();
            });
        }
        var select = clientElement('policyClientSelect');
        if (select) {
            select.addEventListener('change', function () {
                // Changing the selection invalidates any answer in flight and
                // clears the previous one: what is shown must belong to the
                // selected incarnation.
                sequence++;
                clearClientResult();
                setClientStatus('');
                applyDiagnoseAvailability();
            });
        }
        var diagnose = clientElement('policyClientDiagnoseBtn');
        if (diagnose) {
            diagnose.addEventListener('click', function () {
                diagnoseSelectedClient();
            });
        }

        refreshPolicyClients();
        return true;
    }

    root.initPolicyClientDiagnosis = initPolicyClientDiagnosis;
    root.refreshPolicyClients = refreshPolicyClients;
    root.diagnoseSelectedClient = diagnoseSelectedClient;

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', initPolicyClientDiagnosis);
        } else {
            initPolicyClientDiagnosis();
        }
    }
}(typeof window !== 'undefined' ? window : this));
