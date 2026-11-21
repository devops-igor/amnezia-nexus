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
 *     success from a route, an address or a timestamp. The sections it renders
 *     are the ones the answer carries — the live flows and the drop ledger. There
 *     is no DNS table: this build records no answer, query event or correlated
 *     name, so the controller looks none up.
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

    // DECISION_REASON_LABELS maps a recorded decision reason to the one short
    // label the flows table shows. The mapping is data, not a branch: a token this
    // build does not know falls back to one generic label, so a raw token never
    // reaches a cell. The two refusal conditions are listed as well - this build
    // records them as a refused packet or a failed dispatch rather than as a
    // flow's reason, so should a diagnosis ever carry either as one, it still
    // renders a label instead of the token.
    var DECISION_REASON_LABELS = {
        allocation_direct: 'policy_client_decision_reason_allocation_direct',
        allocation_cdn_excluded: 'policy_client_decision_reason_allocation_cdn_excluded',
        no_trusted_evidence: 'policy_client_decision_reason_no_trusted_evidence',
        prohibited_destination: 'policy_client_decision_reason_prohibited_destination',
        direct_egress_unavailable: 'policy_client_decision_reason_direct_egress_unavailable',
        proxy_cidr_rule: 'policy_client_decision_reason_proxy_cidr_rule',
        evidence_direct: 'policy_client_decision_reason_evidence_direct',
        proxy_cached_evidence: 'policy_client_decision_reason_proxy_cached_evidence',
        sticky_flow: 'policy_client_decision_reason_sticky_flow',
        non_tcp_udp_fallback: 'policy_client_decision_reason_non_tcp_udp_fallback',
        not_recorded: 'policy_client_decision_reason_not_recorded'
    };

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
        // The section reports every failure in its own alert; a second page-wide
        // toast for the same answer is two error surfaces for one fault.
        return root.API.request(url, Object.assign({ silent: true }, options));
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
        var rows = clientElement('policyClientFlowRows');
        if (rows) {
            while (rows.firstChild) {
                rows.removeChild(rows.firstChild);
            }
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
        var flowFoot = clientElement('policyClientFlowFoot');
        if (flowFoot) {
            flowFoot.hidden = true;
            flowFoot.textContent = '';
        }
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

    // detailSeq numbers the revealed detail regions so each opener can name the
    // element it controls. Ids only have to be unique in the document, so the
    // counter is never reset.
    var detailSeq = 0;

    // openDetail is the one revealed detail, as {toggle, region}. A table of many
    // rows must not accumulate open panels, so opening one closes the previous, and
    // a re-render drops the reference with the rows it belonged to.
    var openDetail = null;

    // appendCell writes one table cell. A cell whose full fact is longer than the
    // column carries that fact as its title, which native tooltips show on hover
    // only, and as a disclosure inside the same cell: a focusable opener that says
    // whether it is expanded and names the region it reveals. The row keeps its
    // cells; the detail is revealed in place, so a pointer or a keyboard can reach
    // what hover cannot.
    function appendCell(row, text, title) {
        var cell = root.document.createElement('td');
        var label = text == null || text === '' ? '-' : String(text);
        if (!title) {
            cell.textContent = label;
            row.appendChild(cell);
            return cell;
        }
        var detail = String(title);
        cell.title = detail;
        var regionId = 'policyClientCellDetail' + (++detailSeq);
        var toggle = root.document.createElement('span');
        toggle.className = 'cell-detail-toggle';
        toggle.setAttribute('role', 'button');
        toggle.setAttribute('tabindex', '0');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.setAttribute('aria-controls', regionId);
        toggle.setAttribute('data-detail', detail);
        toggle.textContent = label;
        var region = root.document.createElement('span');
        region.className = 'cell-detail';
        region.id = regionId;
        region.hidden = true;
        toggle.addEventListener('click', function (event) {
            if (event && typeof event.stopPropagation === 'function') {
                event.stopPropagation();
            }
            toggleCellDetail(toggle, region);
        });
        toggle.addEventListener('keydown', function (event) {
            handleDetailKey(event, toggle, region);
        });
        cell.addEventListener('click', function () {
            openCellDetail(toggle, region);
        });
        cell.appendChild(toggle);
        cell.appendChild(region);
        row.appendChild(cell);
        return cell;
    }

    // toggleCellDetail opens or closes one cell's detail, so a pointer or the
    // keyboard can put back what it revealed.
    function toggleCellDetail(toggle, region) {
        if (openDetail && openDetail.region === region) {
            closeDetail();
            return;
        }
        openCellDetail(toggle, region);
    }

    // openCellDetail reveals one cell's detail and closes whatever was open, so only
    // one panel is ever expanded.
    function openCellDetail(toggle, region) {
        if (openDetail && openDetail.region === region) {
            return;
        }
        closeDetail();
        region.textContent = toggle.getAttribute('data-detail') || '';
        region.hidden = false;
        toggle.setAttribute('aria-expanded', 'true');
        openDetail = {toggle: toggle, region: region};
    }

    // closeDetail hides the revealed detail and clears its text, so a closed cell
    // carries no hidden copy of the fact.
    function closeDetail() {
        if (!openDetail) {
            return;
        }
        openDetail.region.hidden = true;
        openDetail.region.textContent = '';
        openDetail.toggle.setAttribute('aria-expanded', 'false');
        openDetail = null;
    }

    // handleDetailKey gives the disclosure the keyboard it needs: Enter and Space
    // open or close it, Escape closes it and leaves focus on the opener so the
    // operator does not lose their place in the table.
    function handleDetailKey(event, toggle, region) {
        var key = event && event.key;
        if (key === 'Enter' || key === ' ' || key === 'Spacebar') {
            event.preventDefault();
            toggleCellDetail(toggle, region);
            return;
        }
        if (key === 'Escape' || key === 'Esc') {
            event.preventDefault();
            closeDetail();
            toggle.focus();
        }
    }

    // renderFlows renders the recorded decisions for one incarnation, as four
    // columns: the protocol, the destination, the route the flow was given and the
    // reason for that route. Every cell states what the server sent; nothing here
    // derives a cause, a name or a success. The route cell marks a delivery the
    // dispatch path refused, so a direct route that failed cannot read as one that
    // reached the WAN.
    function renderFlows(entries) {
        var body = clientElement('policyClientFlowRows');
        if (!body) {
            return;
        }
        // A detail revealed on the previous render belongs to a row that is being
        // replaced, so the panel is closed before the table is rebuilt.
        closeDetail();
        entries.forEach(function (flow) {
            var row = root.document.createElement('tr');
            appendCell(row, clientTokenLabel('protocol', flow.protocol));
            appendFlowDestination(row, flow);
            appendFlowRoute(row, flow);
            appendFlowDecision(row, flow);
            body.appendChild(row);
        });
    }

    // appendFlowDestination states the recorded tuple. The row no longer carries a
    // correlated name: the DNS history that could name an address is gone, so the
    // cell states what the flow record itself carries and nothing is inferred from
    // a query the client may have made.
    function appendFlowDestination(row, flow) {
        appendCell(row, flow.destination_ip + ':' + String(flow.destination_port));
    }

    // appendFlowRoute states the route the flow was given and marks every producer
    // that recorded a failed delivery: the dispatch path, the backend device writes
    // and the return delivery. Each failing producer is named on its own, so a flow
    // whose backend accepted some writes and refused one is never reported as a
    // failed flow, and a direct route whose packets were refused cannot read like a
    // direct route that reached the WAN. Only recorded states and counters mark the
    // cell: a success is never inferred from an absent failure.
    function appendFlowRoute(row, flow) {
        var state = dispatchState(flow);
        var markers = routeFailureMarkers(flow, state);
        var route = clientTokenLabel('decision', flow.choice);
        if (markers.length) {
            route = route ? route + ' (' + markers.join(', ') + ')' : markers.join(', ');
        }
        appendCell(row, route, routeFailureDetail(flow, state));
    }

    // dispatchState is the outcome the dispatch path recorded, or '' when the
    // answer carried none.
    function dispatchState(flow) {
        var dispatch = flow.dispatch || {};
        return dispatch.state == null ? '' : String(dispatch.state);
    }

    // dispatchFailed reports whether the dispatch path refused the flow's packets.
    // The recorded state is the producer's summary; the refused-packet counter is
    // checked as well, so an answer that carries the count without a state this
    // build knows is still marked instead of reading as a delivery that worked.
    function dispatchFailed(flow, state) {
        return state === 'failed' || recordedCount(flow.forward, 'failed') > 0;
    }

    // routeFailureMarkers names every producer that recorded a failed delivery, in
    // the order the wire states them: the dispatch outcome, the backend device
    // writes, then the return path. A producer with nothing refused contributes
    // nothing, so the marker count is what the record says, not a guess. The return
    // path refuses a reply in two different places - before the client writer
    // (dropped: queue full, rate limited, size cap, closed path) and inside it
    // (failed) - and either one is a delivery the panel did not make.
    function routeFailureMarkers(flow, state) {
        var markers = [];
        if (dispatchFailed(flow, state)) {
            markers.push(clientText('policy_client_dispatch_failed'));
        }
        if (recordedCount(flow.forward, 'backend_write_failed') > 0) {
            markers.push(clientText('policy_client_route_failed_backend_write'));
        }
        if (returnRefused(flow.return)) {
            markers.push(clientText('policy_client_route_failed_return'));
        }
        return markers;
    }

    // returnRefused reports whether the return path recorded a refusal: a reply
    // dropped before the client writer, or a writer failure. The two counters are
    // separate observations and neither is inferred from the other.
    function returnRefused(back) {
        return recordedCount(back, 'failed') > 0 || recordedCount(back, 'dropped') > 0;
    }

    // routeFailureDetail is the evidence behind the route cell: the dispatch
    // outcome, and for every producer that failed its recorded reason and the
    // counts it recorded, so a backend write refusal is not read as a client-side
    // queue failure. A flow that recorded nothing offers no tooltip.
    function routeFailureDetail(flow, state) {
        var parts = [];
        var forward = flow.forward || {};
        var back = flow.return || {};
        if (state && state !== 'not_recorded') {
            parts.push(clientTokenLabel('dispatch', state));
            appendFailureLabel(parts, (flow.dispatch && flow.dispatch.reason) || forward.failure);
        } else if (dispatchFailed(flow, state)) {
            // The count says packets were refused, but no state this build knows
            // was recorded: state the outcome from the counter, not from a guess.
            parts.push(clientText('policy_client_dispatch_failed'));
            appendFailureLabel(parts, forward.failure);
        }
        if (recordedCount(forward, 'backend_write_failed') > 0) {
            parts.push(clientText('policy_client_route_failed_backend_write'));
            appendFailureLabel(parts, forward.backend_write_failure);
            parts.push(filledText('policy_client_backend_write_fmt', {
                ok: recordedCount(forward, 'backend_writes'),
                failed: recordedCount(forward, 'backend_write_failed')
            }));
        }
        if (returnRefused(back)) {
            parts.push(clientText('policy_client_route_failed_return'));
            appendFailureLabel(parts, back.failure);
            // The chain keeps every return observation in its own slot: a dropped
            // reply and a failed write are different facts and are never summed.
            parts.push(filledText('policy_client_return_chain_fmt', {
                matched: recordedCount(back, 'matched'),
                admitted: recordedCount(back, 'admitted'),
                delivered: recordedCount(back, 'delivered'),
                failed: recordedCount(back, 'failed'),
                dropped: recordedCount(back, 'dropped')
            }));
        }
        return parts.join(' · ');
    }

    // appendFailureLabel adds the dictionary label of a recorded failure token, and
    // nothing when that producer recorded none.
    function appendFailureLabel(parts, token) {
        if (token) {
            parts.push(clientTokenLabel('failure', token));
        }
    }

    // filledText translates one format string and fills its placeholders here, so a
    // count is inserted into the shipped sentence instead of a sentence assembled
    // from fragments.
    function filledText(key, values) {
        var text = clientText(key);
        Object.keys(values).forEach(function (name) {
            text = text.replace('{' + name + '}', String(values[name]));
        });
        return text;
    }

    // recordedCount reads one recorded counter. An absent or non-numeric value is
    // the zero it is: it neither invents a failure nor hides one.
    function recordedCount(owner, field) {
        var value = Number(owner && owner[field]);
        return isFinite(value) && value > 0 ? value : 0;
    }

    // appendFlowDecision states the recorded reason as one short label. The instant,
    // the policy generation, the selected backend and the raw token stay out of the
    // cell: they are the background of the label, so they are offered as the cell's
    // title instead of crowding the row.
    function appendFlowDecision(row, flow) {
        var token = flow.decision_reason == null ? '' : String(flow.decision_reason);
        appendCell(row, clientText(decisionReasonLabelKey(token)), flowDecisionDetail(flow, token));
    }

    // decisionReasonLabelKey resolves a recorded reason to its label key. A flow
    // recorded without one is not a different condition, so it takes the
    // "not recorded" label; a token this build does not know takes the generic
    // one, which is also what keeps the token out of the cell text.
    function decisionReasonLabelKey(token) {
        if (!token) {
            return 'policy_client_decision_reason_not_recorded';
        }
        if (Object.prototype.hasOwnProperty.call(DECISION_REASON_LABELS, token)) {
            return DECISION_REASON_LABELS[token];
        }
        return 'policy_client_decision_reason_unknown';
    }

    // flowDecisionDetail is what the cell cannot show: when the decision was taken,
    // against which policy generation, for which backend, and the token the label
    // was derived from.
    function flowDecisionDetail(flow, token) {
        var parts = [];
        if (flow.decision_time && flow.decision_time !== 'not_recorded') {
            parts.push(String(flow.decision_time));
        }
        if (flow.policy_generation && flow.policy_generation !== 'not_recorded') {
            parts.push(String(flow.policy_generation));
        }
        if (flow.backend_tunnel_id != null) {
            parts.push(clientText('policy_client_backend_fmt')
                .replace('{backend}', String(flow.backend_tunnel_id)));
        }
        if (token && token !== 'not_recorded') {
            parts.push(token);
        }
        return parts.join(' · ');
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
        clearChildren('policyClientFlowRows');
        clearChildren('policyClientDropRows');
        clearChildren('policyClientLimitations');

        var flowsAll = flows.entries || [];
        var dropView = (answer && answer.drops) || {};
        var dropsAll = dropView.entries || [];
        var flowEntries = destinationRows('flows', flowsAll);
        var dropEntries = destinationRows('drops', dropsAll);

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
        // Recorded rows the filter leaves, against all recorded rows. The section foot
        // below keeps describing what was recorded, so an empty table under a filter is
        // never read as an empty history.
        renderFilterFoot(
            flowEntries.length + dropEntries.length,
            flowsAll.length + dropsAll.length);

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
