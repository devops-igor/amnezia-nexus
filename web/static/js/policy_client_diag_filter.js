// Destination filter for the per-client diagnosis panel (issue #861).
//
// The filter narrows rows the panel already holds for ONE selected session: flow
// destinations, answer names and addresses, query names and refusal tuples. It reads no
// state and sends no request, and it keeps each row's own facts — a row is shown or hidden
// by what it already says, never by anything inferred for the filter.
//
// The controller owns the rendering; this module owns the term and the predicates, so the
// filtering rule lives in one place instead of being spread through the table renderers.
(function (root) {
    'use strict';

    var term = '';

    function set(value) {
        term = String(value == null ? '' : value);
    }

    function current() {
        return term.trim().toLowerCase();
    }

    function active() {
        return current() !== '';
    }

    function label(key) {
        return typeof root._ === 'function' ? root._(key) : key;
    }

    // matches reports whether any of a row's own destination facts contains the term. A
    // row with no destination has nothing to compare and cannot match a filter.
    function matches(facts) {
        var needle = current();
        if (!needle) {
            return true;
        }
        for (var i = 0; i < facts.length; i++) {
            if (facts[i] && String(facts[i]).toLowerCase().indexOf(needle) >= 0) {
                return true;
            }
        }
        return false;
    }

    function rows(list, factsOf) {
        if (!active()) {
            return list;
        }
        return list.filter(function (row) {
            return matches(factsOf(row));
        });
    }

    function evidence(entries) {
        return rows(entries || [], function (entry) {
            return [entry.address];
        });
    }

    function records(list) {
        return rows(list || [], function (record) {
            var addresses = (record.addresses || []).map(function (entry) {
                return entry.address;
            });
            return [record.name, (record.aliases || []).join(' '), addresses.join(' ')];
        });
    }

    function events(list) {
        return rows(list || [], function (event) {
            return [event.name];
        });
    }

    function flows(entries) {
        return rows(entries || [], function (flow) {
            return [flow.destination_ip, String(flow.destination_port == null ? '' : flow.destination_port),
                (flow.names || []).join(' ')];
        });
    }

    function drops(entries) {
        return rows(entries || [], function (drop) {
            return drop.has_tuple
                ? [drop.destination_ip, String(drop.destination_port == null ? '' : drop.destination_port)]
                : [];
        });
    }

    // foot states the applied filter and how many recorded rows it leaves. An empty table
    // under a filter is not an empty history, and this line is what separates them.
    function foot(shown, total) {
        if (!root.document) {
            return;
        }
        var el = root.document.getElementById('policyClientFilterFoot');
        if (!el) {
            return;
        }
        if (!active()) {
            el.textContent = '';
            el.hidden = true;
            return;
        }
        var text = shown > 0
            ? label('policy_client_filter_count')
                .replace('{shown}', String(shown))
                .replace('{total}', String(total))
                .replace('{term}', current())
            : label('policy_client_filter_none').replace('{term}', current());
        el.textContent = text;
        el.hidden = false;
    }

    root.clientDiagDestinationFilter = {
        set: set,
        active: active,
        evidence: evidence,
        records: records,
        events: events,
        flows: flows,
        drops: drops,
        foot: foot
    };
}(typeof window !== 'undefined' ? window : this));
