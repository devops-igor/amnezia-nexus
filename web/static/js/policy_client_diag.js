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
    // lastAnswer is the answer the operator is currently looking at. The destination
    // filter narrows these rows locally: switching sessions or issuing a new diagnosis
    // replaces it, so a filter can never show another incarnation's rows.
    var lastAnswer = null;

    // destinationFilter is the shipped destination-filter module. Its absence (an older
    // asset) degrades to "no filter" rather than to an error.
    function destinationFilter() {
        return root.clientDiagDestinationFilter || null;
    }

    // destinationRows applies the filter module's predicate for one row family.
    function destinationRows(kind, list) {
        var filter = destinationFilter();
        if (!filter) {
            return list;
        }
        return filter[kind](list);
    }
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
        lastAnswer = null;
        var filter = clientElement('policyClientDestinationFilter');
        if (filter) {
            filter.value = '';
        }
        var filterModule = destinationFilter();
        if (filterModule) {
            filterModule.set('');
        }
        renderFilterFoot(0, 0);
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
        rows = clientElement('policyClientEventRows');
        if (rows) {
            while (rows.firstChild) {
                rows.removeChild(rows.firstChild);
            }
        }
        var eventCoverage = clientElement('policyClientEventCoverage');
        if (eventCoverage) {
            eventCoverage.textContent = '';
        }
        rows = clientElement('policyClientDropRows');
        if (rows) {
            while (rows.firstChild) {
                rows.removeChild(rows.firstChild);
            }
        }
        var dropCoverage = clientElement('policyClientDropCoverage');
        if (dropCoverage) {
            dropCoverage.textContent = '';
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

    // selectedIncarnation is the exact incarnation the picker currently accepts: the
    // session id and the route generation the list carries for it. An absent generation is
    // its own value, so a refresh that loses it is a change of authority rather than an
    // unchanged selection. A refresh that removes the session or moves it to another
    // generation therefore invalidates whatever the panel shows or has pending; an
    // unchanged incarnation leaves a valid result alone.
    function selectedIncarnation() {
        var client = selectedOption();
        if (!client) {
            return {sessionID: '', generation: 0};
        }
        return {sessionID: client.session_id, generation: client.route_generation || 0};
    }

    function sameIncarnation(a, b) {
        return a.sessionID === b.sessionID && a.generation === b.generation;
    }

    // invalidateIfSelectionMoved drops a pending diagnosis and the rendered answer when the
    // refreshed list no longer accepts the incarnation they belong to. It bumps the request
    // sequence, so an answer already in flight is refused when it arrives instead of being
    // rendered under the new selection.
    function invalidateIfSelectionMoved(before) {
        if (sameIncarnation(before, selectedIncarnation())) {
            return;
        }
        sequence++;
        clearClientResult();
        setClientStatus('');
        applyDiagnoseAvailability();
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
        // The incarnation the panel is showing before this refresh. Both outcomes below
        // compare it with what the picker accepts afterwards.
        var before = selectedIncarnation();
        setClientBusy('list', true);
        setClientStatus(clientText('policy_client_loading'));
        return clientRequest(CLIENTS_ENDPOINT, {method: 'GET'}).then(function (answer) {
            setClientBusy('list', false);
            lastClients = (answer && answer.clients) || [];
            policyRoutingEnabled = !!(answer && answer.policy_routing_enabled);
            renderClientPicker(lastClients);
            invalidateIfSelectionMoved(before);
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
            invalidateIfSelectionMoved(before);
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

    // renderFlows renders the recorded decisions and outcomes. Every cell states
    // what the server sent: a branch token, a correlation class, or an explicit
    // "not recorded"/"not measured". Nothing here derives a cause, a name or a
    // success.
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

            var decision = flow.decision_time + ' · ' + clientTokenLabel('reason', flow.decision_reason);
            if (flow.policy_generation && flow.policy_generation !== 'not_recorded') {
                decision = decision + ' · ' + flow.policy_generation;
            }
            // The backend the branch selected, when the recorded decision carries one.
            // It is the producer's own value, not a lookup of the current configuration.
            if (flow.backend_tunnel_id != null) {
                decision = decision + ' · ' + clientText('policy_client_backend_fmt')
                    .replace('{backend}', String(flow.backend_tunnel_id));
            }
            appendCell(row, decision);

            var names = clientTokenLabel('name_match', flow.names_match);
            if (flow.names && flow.names.length) {
                names = names + ': ' + flow.names.join(', ');
            } else if (flow.name_attempts && flow.name_attempts.length) {
                // A failed query has no answer to attribute to this IP. These are
                // names the client tried near the decision, never "the flow's name".
                var tried = flow.name_attempts.map(function (attempt) {
                    var label = attempt.name + ' (' + clientTokenLabel('dns_event', attempt.kind);
                    if (attempt.qtype) {
                        label = label + ', ' + attempt.qtype;
                    }
                    return label + ')';
                }).join(', ');
                names = names + ': ' + clientText('policy_client_tried_names_fmt').replace('{names}', tried);
            } else if (flow.names_reason) {
                names = names + ': ' + clientTokenLabel('corr', flow.names_reason);
            }
            appendCell(row, names);

            var outcome = clientText('policy_client_outcome_fmt')
                .replace('{ok}', String((flow.forward && flow.forward.packets) || 0))
                .replace('{failed}', String((flow.forward && flow.forward.failed) || 0))
                .replace('{return}', clientTokenLabel('return_evidence', (flow.return && flow.return.evidence) || 'not_recorded'))
                .replace('{packets}', String((flow.return && flow.return.packets) || 0));
            if (flow.forward && flow.forward.failure) {
                outcome = outcome + ' · ' + clientTokenLabel('failure', flow.forward.failure);
            }
            // PROXY return: arrival, queue admission and the client handoff are three
            // different observations. They are rendered as a chain so "admitted" is never
            // read as "delivered", and a refusal states where the reply stopped.
            if (flow.choice === 'PROXY' && flow.return && flow.return.evidence === 'observed') {
                var chain = clientText('policy_client_return_chain_fmt')
                    .replace('{matched}', String(flow.return.matched || 0))
                    .replace('{admitted}', String(flow.return.admitted || 0))
                    .replace('{delivered}', String(flow.return.delivered || 0))
                    .replace('{failed}', String(flow.return.failed || 0));
                if (flow.return.failure) {
                    chain = chain + ' (' + clientTokenLabel('failure', flow.return.failure) + ')';
                }
                // The claim beside the numbers: this is the flow that owns the tuple now,
                // which is not proof of which remote incarnation answered.
                if (flow.return.authority) {
                    chain = chain + ' · ' + clientTokenLabel('return_authority', flow.return.authority);
                }
                outcome = outcome + ' · ' + chain;
            }
            // Admission and the backend device write are different facts: a proxy
            // flow states both, so "queued" is never read as "delivered".
            // Only stated when a device outcome exists: "0 written / 0 failed" on a
            // packet that has not reached the writer yet would read as a measurement.
            if (flow.choice === 'PROXY' && flow.forward &&
                ((flow.forward.backend_writes || 0) + (flow.forward.backend_write_failed || 0)) > 0) {
                var written = clientText('policy_client_backend_write_fmt')
                    .replace('{ok}', String(flow.forward.backend_writes || 0))
                    .replace('{failed}', String(flow.forward.backend_write_failed || 0));
                if (flow.forward.backend_write_failure) {
                    written = written + ' (' + clientTokenLabel('failure', flow.forward.backend_write_failure) + ')';
                }
                outcome = outcome + ' · ' + written;
            }
            appendCell(row, outcome);

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
            // The policy generation the answer was evaluated against, as recorded.
            appendCell(row, record.policy_generation);
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
        clearChildren('policyClientDNSGaps');
        if (gaps && coverage && coverage.not_recorded) {
            coverage.not_recorded.forEach(function (token) {
                var item = root.document.createElement('li');
                item.textContent = clientTokenLabel('limit', token);
                gaps.appendChild(item);
            });
        }
    }

    // renderDNSEvents renders the terminal client queries: including the ones that
    // produced no usable answer, which is why the table exists next to the answers.
    function renderDNSEvents(events) {
        var body = clientElement('policyClientEventRows');
        if (!body) {
            return;
        }
        (events || []).forEach(function (event) {
            var row = root.document.createElement('tr');
            appendCell(row, event.name);
            appendCell(row, event.qtype);
            var result = clientTokenLabel('dns_event', event.kind);
            if (event.upstream_error) {
                result = result + ' (' + clientTokenLabel('upstream', event.upstream_error) + ')';
            }
            appendCell(row, result);
            appendCell(row, String(event.transport || '').toUpperCase());
            appendCell(row, event.received_at);
            appendCell(row, event.answered_at);
            appendCell(row, event.delivered ? clientText('policy_client_delivered_yes') : clientText('policy_client_delivered_no'));
            body.appendChild(row);
        });
    }

    function renderEventCoverage(coverage) {
        var el = clientElement('policyClientEventCoverage');
        if (!el) {
            return;
        }
        if (!coverage) {
            el.textContent = '';
            return;
        }
        el.textContent = clientText('policy_client_dns_events_coverage')
            .replace('{stored}', String(coverage.events_stored || 0))
            .replace('{collapsed}', String(coverage.collapsed || 0))
            .replace('{evicted}', String((coverage.evicted_per_session || 0) + (coverage.evicted_global || 0)))
            .replace('{aged}', String(coverage.aged_out || 0));
    }

    function renderDrops(drops) {
        var body = clientElement('policyClientDropRows');
        if (!body) {
            return;
        }
        while (body.firstChild) {
            body.removeChild(body.firstChild);
        }
        (drops.entries || []).forEach(function (drop) {
            var row = document.createElement('tr');
            appendCell(row, clientTokenLabel('drop_reason', drop.reason));
            // A refusal that carried no tuple says so: an empty address is never shown as
            // a destination the packet did not have.
            appendCell(row, drop.has_tuple
                ? drop.destination_ip + (drop.destination_port ? ':' + drop.destination_port : '')
                : clientText('policy_client_drop_no_tuple'));
            appendCell(row, drop.has_tuple
                ? clientTokenLabel('protocol', drop.protocol)
                : clientText('policy_client_drop_no_tuple'));
            appendCell(row, String(drop.count || 0));
            appendCell(row, drop.last_seen || '');
            body.appendChild(row);
        });

        var foot = '';
        if (!(drops.entries || []).length) {
            foot = drops.state === 'observed'
                ? clientText('policy_client_drop_empty')
                : clientText('policy_client_drop_not_recorded');
        } else if (drops.truncated) {
            foot = clientText('policy_client_drop_truncated')
                .replace('{shown}', String((drops.entries || []).length))
                .replace('{total}', String(drops.total || 0));
        }
        renderFoot('policyClientDropFoot', foot);
        renderDropCoverage(drops.coverage);
    }

    // The coverage line states retention and loss, so an empty page is not read as "this
    // client was never refused".
    function renderDropCoverage(coverage) {
        var el = clientElement('policyClientDropCoverage');
        if (!el) {
            return;
        }
        if (!coverage) {
            el.textContent = '';
            return;
        }
        el.textContent = clientText('policy_client_drop_coverage')
            .replace('{stored}', String(coverage.stored || 0))
            .replace('{merged}', String(coverage.merged || 0))
            .replace('{evicted}', String(coverage.evicted || 0))
            .replace('{pruned}', String(coverage.pruned || 0))
            .replace('{session_keys}', String(coverage.session_keys || 0))
            .replace('{keys}', String(coverage.keys || 0))
            .replace('{key_limit}', String(coverage.key_limit || 0))
            .replace('{age}', String(coverage.age_limit_seconds || 0));
    }

    // clearChildren empties one list or table body. Every renderer that appends runs
    // after it, so re-rendering the same answer (the destination filter does exactly
    // that) cannot duplicate a row.
    function clearChildren(id) {
        var el = clientElement(id);
        if (!el) {
            return;
        }
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    }

    // renderNotCovered lists what no retained store holds. It is the coverage block's own
    // list, kept apart from the limitations of the recorded rows.
    function renderNotCovered(tokens) {
        var list = clientElement('policyClientNotCovered');
        if (!list) {
            return;
        }
        clearChildren('policyClientNotCovered');
        (tokens || []).forEach(function (token) {
            var item = root.document.createElement('li');
            item.textContent = clientTokenLabel('limit', token);
            list.appendChild(item);
        });
    }

    // renderFilterFoot states the applied filter and how many recorded rows it leaves.
    // The filter module owns the wording; this call site owns the counts.
    function renderFilterFoot(shown, total) {
        var filter = destinationFilter();
        if (filter) {
            filter.foot(shown, total);
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

        lastAnswer = answer;
        // The destination filter re-renders this same answer, so every appending
        // renderer starts from an empty body and the panels never accumulate rows.
        clearChildren('policyClientEvidenceRows');
        clearChildren('policyClientFlowRows');
        clearChildren('policyClientDNSRows');
        clearChildren('policyClientEventRows');
        clearChildren('policyClientDropRows');
        clearChildren('policyClientLimitations');

        var evidenceAll = dns.entries || [];
        var recordsAll = dns.records || [];
        var eventsAll = dns.events || [];
        var flowsAll = flows.entries || [];
        var dropView = (answer && answer.drops) || {};
        var dropsAll = dropView.entries || [];
        var evidence = destinationRows('evidence', evidenceAll);
        var records = destinationRows('records', recordsAll);
        var events = destinationRows('events', eventsAll);
        var flowEntries = destinationRows('flows', flowsAll);
        var dropEntries = destinationRows('drops', dropsAll);

        renderEvidence(evidence);
        renderDNSRecords(records);
        renderDNSCoverage(dns.record_coverage);
        renderDNSEvents(events);
        renderEventCoverage(dns.event_coverage);
        renderFlows(flowEntries);
        renderDrops({
            state: dropView.state,
            truncated: dropView.truncated,
            total: dropView.total,
            entries: dropEntries,
            coverage: dropView.coverage
        });
        renderLimitations((answer && answer.limitations) || []);
        renderNotCovered((answer && answer.coverage && answer.coverage.not_covered) || []);
        // Recorded rows the filter leaves, against all recorded rows. The section foots
        // above keep describing what was recorded, so an empty table under a filter is
        // never read as an empty history.
        renderFilterFoot(
            evidence.length + records.length + events.length + flowEntries.length + dropEntries.length,
            evidenceAll.length + recordsAll.length + eventsAll.length + flowsAll.length + dropsAll.length);

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

        var eventFoot = '';
        if (!(dns.events || []).length) {
            eventFoot = dns.events_available ? clientText('policy_client_dns_events_empty') : clientText('policy_client_dns_events_not_recorded');
        } else if (dns.events_truncated) {
            eventFoot = clientText('policy_client_dns_events_truncated')
                .replace('{shown}', String((dns.events || []).length))
                .replace('{total}', String(dns.events_total || 0));
        }
        renderFoot('policyClientEventFoot', eventFoot);

        var flowFoot = '';
        if (!(flows.entries || []).length) {
            flowFoot = clientText('policy_client_empty_flows');
        } else {
            flowFoot = clientText('policy_client_flow_count').replace('{shown}', String((flows.entries || []).length)).replace('{total}', String(flows.total || 0));
            if (!flows.scan_complete) {
                flowFoot = flowFoot + ' ' + clientText('policy_client_partial_scan').replace('{scanned}', String(flows.scanned || 0));
            }
        }
        if ((flows.entries || []).length) {
            flowFoot = flowFoot + ' ' + clientText('policy_client_counters_live_note');
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
        var sentGeneration = client.route_generation || 0;
        var body = {session_id: sentSession};
        if (client.route_generation) {
            body.route_generation = client.route_generation;
        }
        var requestId = ++sequence;

        setClientBusy('diagnose', true);
        setClientStatus(clientText('policy_client_diagnosing'));
        clearClientResult();

        return clientRequest(DIAG_ENDPOINT, {method: 'POST', body: body}).then(function (answer) {
            // The busy flag is released for every outcome: one request at a time, and a
            // stale answer must not leave a legitimate diagnosis permanently busy.
            setClientBusy('diagnose', false);
            if (requestId !== sequence) {
                // A newer request or a refresh that moved the selection; this answer
                // belongs to an incarnation the panel no longer shows.
                return null;
            }
            setClientStatus('');
            var selection = (answer && answer.selection) || {};
            if (selection.session_id !== sentSession ||
                (selection.route_generation || 0) !== sentGeneration) {
                // The answer is about another incarnation (or carries none), so
                // rendering it would attribute one client's records to another.
                setClientAlert('stale', clientText('policy_client_stale_answer'));
                return null;
            }
            if (!sameIncarnation(selectedIncarnation(), {sessionID: sentSession, generation: sentGeneration})) {
                // The picker moved to another generation of the same session while this
                // request travelled: the answer describes the incarnation it asked about,
                // not the one now selected.
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

    // applyDestinationFilter re-renders the answer already on screen with the current
    // filter text. It reads no new state and sends no request: the filter is applied to
    // the rows this panel already holds for the selected session.
    function applyDestinationFilter() {
        if (!lastAnswer) {
            return;
        }
        renderClientDiagnosis(lastAnswer);
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
        var destination = clientElement('policyClientDestinationFilter');
        if (destination) {
            destination.addEventListener('input', function () {
                var filter = destinationFilter();
                if (filter) {
                    filter.set(destination.value);
                }
                applyDestinationFilter();
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
