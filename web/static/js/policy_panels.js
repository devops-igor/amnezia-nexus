/* The four policy readouts (#971).
 *
 * Settings → Network → Policy Routing carries four panels, each answering one
 * question: is split egress active (P1), is the shipped address list current
 * (P2), can a CDN keep a destination on the proxy path (P3), and did the latest
 * rule sync fail (P4). The markup and the state vocabulary belong to the design
 * contract; this module only renders what the server reported.
 *
 * Three rules decide every branch below, and each exists because the opposite
 * was shipped before:
 *
 *   - a value the server did not report is never rendered as a neutral answer.
 *     "Not available" and a loading placeholder are different facts, and only a
 *     real observation may produce "off", "current" or "no error";
 *   - runtime state and stored intent are separate inputs. Storage keeps
 *     `enabled:true` through a startup activation failure, so a saved-on record
 *     beside an inactive runtime is reported as "saved as on, not active",
 *     never as either value alone;
 *   - a disclosure holds supporting detail, never the answer or its
 *     consequence. The raw server strings stay verbatim inside one, in server
 *     order, and an entry the server sent is never dropped or merged.
 *
 * Loaded before policy_routing.js, which calls PolicyPanels.render(record,
 * snapshot) after every read and every accepted mutation.
 */

(function (root) {
    'use strict';

    function panelText(key) {
        if (typeof root._ === 'function') {
            var translated = root._(key);
            if (translated && translated !== key) {
                return translated;
            }
        }
        return key;
    }

    function panelElement(id) {
        if (!root.document) {
            return null;
        }
        return root.document.getElementById(id);
    }

    function setPanelText(id, text) {
        var el = panelElement(id);
        if (el) {
            el.textContent = text;
        }
    }

    // setPanelVisible hides or shows one element. A control that disappears
    // while it holds focus would strand the keyboard operator on the document
    // body, so focus moves to the panel's own heading first.
    function setPanelVisible(el, visible) {
        if (!el) {
            return;
        }
        if (visible) {
            el.removeAttribute('hidden');
            return;
        }
        var active = root.document ? root.document.activeElement : null;
        if (active && el.contains && el.contains(active)) {
            var panel = el.closest ? el.closest('.policy-panel') : null;
            var heading = panel ? panel.querySelector('.policy-panel-title') : null;
            if (heading && heading.focus) {
                heading.focus();
            }
        }
        el.setAttribute('hidden', 'hidden');
    }

    // panelPlural picks the singular form for exactly one item. A single template
    // would read "1 networks excluded", which is the kind of detail that makes an
    // operator distrust the number beside it.
    function panelPlural(base, count) {
        return panelText(base + (count === 1 ? '_one' : '_other'));
    }

    // panelCount renders a count the server reported, and only that. `Number(null)`
    // and `Number('')` are zero, so a payload field the server omitted would be
    // rendered as a factual zero; a count is a number or it is not reported.
    function panelCount(value) {
        if (typeof value !== 'number' || !isFinite(value) || value < 0) {
            return panelText('policy_not_available');
        }
        return String(Math.round(value));
    }

    function panelDays(value) {
        if (typeof value !== 'number' || !isFinite(value) || value < 0) {
            return panelText('policy_not_available');
        }
        return panelPlural('policy_days', value).replace('{days}', String(Math.round(value)));
    }

    // panelTimestamp formats a server instant in the portal's language, with the
    // zone named so an operator comparing it to a log line is not left guessing.
    function panelTimestamp(raw) {
        var parsed = new Date(raw);
        if (isNaN(parsed.getTime())) {
            return String(raw);
        }
        var lang = root.document && root.document.documentElement
            ? root.document.documentElement.lang
            : '';
        try {
            return parsed.toLocaleString(lang || undefined, { timeZoneName: 'short' });
        } catch (err) {
            // A browser that rejects the options still formats the instant; the
            // zone is the part it declines to name.
            return parsed.toLocaleString(lang || undefined);
        }
    }

    // panelFailure reports whether the runtime snapshot carries a sync failure.
    // Both halves are evidence: the runtime sets an error token and, for a
    // failure it can describe, the error text itself.
    function panelFailure(snapshot) {
        if (!snapshot) {
            return false;
        }
        return !!(snapshot.last_error || snapshot.sync_state === 'error');
    }

    function panelSyncStateLabel(snapshot) {
        if (!snapshot || !snapshot.sync_state) {
            return panelText('policy_not_available');
        }
        var key = 'policy_sync_state_' + snapshot.sync_state;
        var label = panelText(key);
        return label === key ? String(snapshot.sync_state) : label;
    }

    var PANEL_GLYPHS = {
        success: 'policy-glyph-check',
        warning: 'policy-glyph-warning',
        danger: 'policy-glyph-cross',
        info: 'policy-glyph-info',
        loading: 'policy-glyph-info'
    };

    // setPanelAnswer writes one panel's whole answer: the tinted inset, its
    // icon, the headline and the sentence that explains it.
    function setPanelAnswer(answerId, headlineId, bodyId, iconId, state, headline, body) {
        var answer = panelElement(answerId);
        if (answer) {
            answer.setAttribute('data-state', state);
        }
        setPanelText(headlineId, headline);
        var bodyEl = panelElement(bodyId);
        if (bodyEl) {
            bodyEl.textContent = body || '';
            setPanelVisible(bodyEl, !!body);
        }
        var icon = panelElement(iconId);
        if (icon) {
            icon.setAttribute('href', '#' + (PANEL_GLYPHS[state] || PANEL_GLYPHS.info));
        }
    }

    // setPanelActions shows exactly the named actions of one panel. The container
    // itself is hidden when none applies, so an empty action row is not rendered.
    function setPanelActions(actionsId, ids) {
        var container = panelElement(actionsId);
        if (!container) {
            return;
        }
        var items = container.querySelectorAll('[data-policy-action]');
        var shown = 0;
        for (var i = 0; i < items.length; i++) {
            var keep = ids.indexOf(items[i].id) !== -1;
            if (keep) {
                shown++;
            }
            setPanelVisible(items[i], keep);
        }
        setPanelVisible(container, shown > 0);
    }

    function renderStatusBadge(snapshot) {
        var badge = panelElement('policyStatusBadge');
        if (!badge) {
            return;
        }
        if (!snapshot) {
            badge.className = 'badge badge-secondary';
            badge.textContent = panelText('policy_status_unknown');
            badge.setAttribute('data-enabled', 'unknown');
            return;
        }
        badge.className = snapshot.enabled ? 'badge badge-success' : 'badge badge-secondary';
        badge.textContent = panelText(snapshot.enabled ? 'policy_status_enabled' : 'policy_status_disabled');
        badge.setAttribute('data-enabled', snapshot.enabled ? 'true' : 'false');
    }

    // renderPolicyStatus answers P1 from the runtime flag plus the sync outcome.
    // The stored switch is consulted only to tell "off" from "saved as on, not
    // active"; it is never shown as the runtime answer.
    function renderPolicyStatus(record, snapshot) {
        var savedOn = !!(record && record.enabled);
        if (!snapshot) {
            setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                'policyStatusAnswerIcon', 'info',
                panelText('policy_status_unavailable'), panelText('policy_status_unavailable_body'));
            setPanelActions('policyStatusActions', []);
        } else if (snapshot.enabled) {
            if (panelFailure(snapshot)) {
                setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                    'policyStatusAnswerIcon', 'warning',
                    panelText('policy_status_active_sync_failed'),
                    panelText('policy_status_active_sync_failed_body'));
                setPanelActions('policyStatusActions', ['policyStatusActionError']);
            } else if (snapshot.ready === true && snapshot.sync_state === 'synced') {
                setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                    'policyStatusAnswerIcon', 'success',
                    panelText('policy_status_active'), panelText('policy_status_active_body'));
                setPanelActions('policyStatusActions', []);
            } else {
                // Active, but nothing confirmed that the loaded rule set matches
                // the current configuration. That is not a failure and not a
                // healthy state either.
                setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                    'policyStatusAnswerIcon', 'info',
                    panelText('policy_status_active_unconfirmed'),
                    panelText('policy_status_active_unconfirmed_body'));
                setPanelActions('policyStatusActions', []);
            }
        } else if (panelFailure(snapshot)) {
            if (savedOn && snapshot.sync_state === 'error' && snapshot.last_error) {
                // The pictured startup failure: stored intent is on, the runtime
                // never started, and the server said why.
                setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                    'policyStatusAnswerIcon', 'warning',
                    panelText('policy_status_not_active'), panelText('policy_status_start_failed_body'));
            } else {
                setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                    'policyStatusAnswerIcon', 'warning',
                    panelText('policy_status_not_active'), panelText('policy_status_error_off_body'));
            }
            setPanelActions('policyStatusActions', ['policyStatusActionError']);
        } else if (savedOn) {
            setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                'policyStatusAnswerIcon', 'warning',
                panelText('policy_status_not_active'), panelText('policy_status_saved_on_body'));
            setPanelActions('policyStatusActions', ['policyStatusActionSettings']);
        } else {
            setPanelAnswer('policyStatusAnswer', 'policyStatusAnswerHeadline', 'policyStatusAnswerBody',
                'policyStatusAnswerIcon', 'info',
                panelText('policy_status_off'), panelText('policy_status_off_body'));
            setPanelActions('policyStatusActions', ['policyStatusActionSettings']);
        }

        setPanelText('policySyncState', panelSyncStateLabel(snapshot));
        // A snapshot that reports no last success reports "Never"; without any
        // snapshot there is nothing to report at all.
        setPanelText('policyLastSuccess', !snapshot
            ? panelText('policy_not_available')
            : (snapshot.last_success ? panelTimestamp(snapshot.last_success) : panelText('policy_never')));
        setPanelText('policyRuleCount', snapshot ? panelCount(snapshot.cidr_count) : panelText('policy_not_available'));
    }

    // renderPolicyInventory answers P2. Freshness is the server's verdict: the
    // client neither measures the age nor promotes a rounded day count into it.
    //
    // The error is honoured before any other field is consumed. The producer of an
    // unusable artifact sets `error`, the threshold and the configured override but
    // not the age, and `age_days` has no omitempty, so the payload necessarily
    // carries `age_days: 0` for a set it could not read. Rendering that zero would
    // describe a broken artifact as fresh-looking numeric data, which is the one
    // thing this panel exists to prevent.
    function renderPolicyInventory(record, snapshot) {
        var inventory = snapshot && snapshot.inventory ? snapshot.inventory : null;
        var errorText = inventory && inventory.error ? String(inventory.error) : '';
        var ageReported = !!inventory && !errorText && typeof inventory.age_days === 'number';
        var limitReported = !!inventory && typeof inventory.max_age_days === 'number';
        var prefixReported = !!inventory && !errorText && typeof inventory.prefix_count === 'number';
        var overrideCount = inventory && typeof inventory.override_prefix_count === 'number'
            ? inventory.override_prefix_count
            : null;
        // "Current" is a provenance claim, not only a freshness flag: without a
        // named source and a retrieval date the panel cannot say which list was
        // judged, so it reports that the freshness is unconfirmed instead.
        var provenance = !!inventory
            && !!inventory.source
            && !!inventory.retrieved_at
            && prefixReported
            && ageReported
            && limitReported;

        if (!inventory) {
            setPanelAnswer('policyInventoryAnswer', 'policyInventoryAnswerHeadline', 'policyInventoryAnswerBody',
                'policyInventoryAnswerIcon', 'info',
                panelText('policy_inventory_not_reported'), panelText('policy_inventory_not_reported_body'));
            setPanelActions('policyInventoryActions', ['policyInventoryActionOverride']);
        } else if (errorText) {
            setPanelAnswer('policyInventoryAnswer', 'policyInventoryAnswerHeadline', 'policyInventoryAnswerBody',
                'policyInventoryAnswerIcon', 'danger',
                panelText('policy_inventory_unusable_headline'), panelText('policy_inventory_unusable'));
            setPanelActions('policyInventoryActions', ['policyInventoryActionStatus']);
        } else if (inventory.stale === true) {
            setPanelAnswer('policyInventoryAnswer', 'policyInventoryAnswerHeadline', 'policyInventoryAnswerBody',
                'policyInventoryAnswerIcon', 'warning',
                panelText('policy_inventory_update_needed'), panelText('policy_inventory_update_needed_body'));
            setPanelActions('policyInventoryActions', ['policyInventoryActionOverride']);
        } else if (inventory.stale === false && provenance) {
            setPanelAnswer('policyInventoryAnswer', 'policyInventoryAnswerHeadline', 'policyInventoryAnswerBody',
                'policyInventoryAnswerIcon', 'success',
                panelText('policy_inventory_current'), panelText('policy_inventory_current_body'));
            setPanelActions('policyInventoryActions', ['policyInventoryActionOverride']);
        } else {
            // The artifact is present but the verdict or the provenance behind it
            // is not, so the panel says so instead of guessing from the date.
            setPanelAnswer('policyInventoryAnswer', 'policyInventoryAnswerHeadline', 'policyInventoryAnswerBody',
                'policyInventoryAnswerIcon', 'info',
                panelText('policy_inventory_freshness_not_reported'),
                panelText('policy_inventory_freshness_not_reported_body'));
            setPanelActions('policyInventoryActions', ['policyInventoryActionOverride']);
        }

        setPanelText('policyInventoryAge', ageReported ? panelDays(inventory.age_days) : panelText('policy_not_available'));
        setPanelText('policyInventoryLimit', limitReported ? panelDays(inventory.max_age_days) : panelText('policy_not_available'));
        if (!inventory) {
            setPanelText('policyInventoryOverrideStatus', panelText('policy_not_available'));
        } else if (overrideCount === 0) {
            setPanelText('policyInventoryOverrideStatus', panelText('policy_inventory_override_none'));
        } else if (overrideCount > 0) {
            setPanelText('policyInventoryOverrideStatus',
                panelPlural('policy_inventory_override_count', overrideCount).replace('{count}', String(overrideCount)));
        } else {
            // The count itself was not reported: that is not "no override configured".
            setPanelText('policyInventoryOverrideStatus', panelText('policy_not_available'));
        }

        // Provenance describes the shipped artifact, not its freshness, so it is
        // detail rather than an answer. A field the server did not report is not an
        // answer of "none": saying so would state a fact nobody observed, so it
        // reads as not available, the same word the other unreported facts use.
        setPanelText('policyInventorySource', inventory && inventory.source
            ? String(inventory.source)
            : panelText('policy_not_available'));
        setPanelText('policyInventoryPrefixes', prefixReported
            ? panelCount(inventory.prefix_count)
            : panelText('policy_not_available'));
        setPanelText('policyInventoryRetrieved', inventory && inventory.retrieved_at
            ? String(inventory.retrieved_at)
            : panelText('policy_not_available'));

        // The digest repeats only with an override, and only its reading-length
        // prefix: it exists to tell two same-size overrides apart.
        var digest = overrideCount > 0 && inventory.override_sha256
            ? String(inventory.override_sha256).slice(0, 12)
            : '';
        setPanelText('policyInventoryDigest', digest);
        setPanelVisible(panelElement('policyInventoryDigestRow'), digest !== '');

        setPanelText('policyInventoryNotice', errorText);
    }

    // panelCDNEntryText renders one exclusion the way the list reads: the provider
    // name, then the autonomous system the classifier matches against. A missing
    // half is left out rather than filled with a placeholder, and a repeated
    // provider keeps every one of its networks.
    function panelCDNEntryText(entry) {
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

    function renderPanelCDNEntries(entries, errorText) {
        var list = panelElement('policyCdnEntries');
        if (!list) {
            return;
        }
        while (list.firstChild) {
            list.removeChild(list.firstChild);
        }
        if (!entries || entries.length === 0) {
            // The placeholder names this list's own state: reported and empty, not
            // reported at all, or reported but unusable. "Not reported" would be a
            // false statement about a set the server did try to describe.
            var placeholderState = entries ? 'policy_cdn_empty'
                : (errorText ? 'policy_cdn_answer_unusable' : 'policy_cdn_unavailable');
            var placeholder = root.document.createElement('li');
            placeholder.className = 'text-muted';
            placeholder.textContent = panelText(placeholderState);
            list.appendChild(placeholder);
            return;
        }
        entries.forEach(function (entry) {
            var row = root.document.createElement('li');
            row.textContent = panelCDNEntryText(entry);
            list.appendChild(row);
        });
    }

    // renderPolicyCDN answers P3. It reports the set the classifier consults and
    // nothing about a particular destination: an empty list is evidence of no
    // exclusions in that list, not a promise about where a CDN destination goes.
    function renderPolicyCDN(record, snapshot) {
        var cdn = snapshot && snapshot.cdn ? snapshot.cdn : null;
        var entries = cdn && Array.isArray(cdn.entries) ? cdn.entries : null;
        var errorText = cdn && cdn.error ? String(cdn.error) : '';

        if (errorText) {
            setPanelAnswer('policyCdnAnswer', 'policyCdnAnswerHeadline', 'policyCdnAnswerBody',
                'policyCdnAnswerIcon', 'danger',
                panelText('policy_cdn_answer_unusable'), panelText('policy_cdn_unusable'));
        } else if (entries && entries.length > 0) {
            setPanelAnswer('policyCdnAnswer', 'policyCdnAnswerHeadline', 'policyCdnAnswerBody',
                'policyCdnAnswerIcon', 'success',
                panelPlural('policy_cdn_count_answer', entries.length).replace('{count}', String(entries.length)),
                panelText('policy_cdn_count_answer_body'));
        } else if (entries) {
            setPanelAnswer('policyCdnAnswer', 'policyCdnAnswerHeadline', 'policyCdnAnswerBody',
                'policyCdnAnswerIcon', 'info',
                panelPlural('policy_cdn_count_answer', 0).replace('{count}', '0'),
                panelText('policy_cdn_empty_body'));
        } else {
            setPanelAnswer('policyCdnAnswer', 'policyCdnAnswerHeadline', 'policyCdnAnswerBody',
                'policyCdnAnswerIcon', 'info',
                panelText('policy_cdn_not_reported'), panelText('policy_cdn_not_reported_body'));
        }

        // One disclosure answers every state, so an operator who opened it keeps it
        // open (and keeps focus on its summary) when the state changes under them.
        // Only the label and the contents change.
        var hasList = !errorText && !!entries && entries.length > 0;
        var label = panelElement('policyCdnDisclosureLabel');
        if (label) {
            label.textContent = panelText(hasList ? 'policy_cdn_view_networks' : 'policy_cdn_entries_details');
        }

        // Same rule as the inventory provenance: an unreported source is not a
        // source called "none".
        setPanelText('policyCdnSource', cdn && cdn.source ? String(cdn.source) : panelText('policy_not_available'));
        setPanelText('policyCdnCount', entries ? panelCount(entries.length) : panelText('policy_not_available'));
        renderPanelCDNEntries(errorText ? null : entries, errorText);
        setPanelText('policyCdnNotice', errorText);
    }

    // renderPolicySyncError answers P4: did the latest sync fail, and what can the
    // operator do about it. A retry is offered only where retrying can help; a
    // startup failure is not a failed download and gets no retry control.
    //
    // "No sync error reported" is a success only when a successful sync was
    // confirmed. An active runtime that reported no sync state at all is
    // unconfirmed — P1 already says so, and the two readouts must not disagree.
    function renderPolicySyncError(record, snapshot) {
        var failure = panelFailure(snapshot);
        if (!snapshot) {
            setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                'policySyncErrorAnswerIcon', 'info',
                panelText('policy_sync_error_unavailable'), panelText('policy_sync_error_unavailable_body'));
            setPanelActions('policySyncErrorActions', []);
        } else if (failure) {
            if (snapshot.enabled) {
                setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                    'policySyncErrorAnswerIcon', 'danger',
                    panelText('policy_sync_error_failed'),
                    panelText(snapshot.ready === true
                        ? 'policy_sync_error_failed_body_ready'
                        : 'policy_sync_error_failed_body_not_ready'));
                setPanelActions('policySyncErrorActions', ['policySyncNowBtn']);
            } else if (record && record.enabled) {
                setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                    'policySyncErrorAnswerIcon', 'danger',
                    panelText('policy_sync_error_did_not_start'),
                    panelText('policy_sync_error_did_not_start_body'));
                setPanelActions('policySyncErrorActions', []);
            } else {
                setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                    'policySyncErrorAnswerIcon', 'danger',
                    panelText('policy_sync_error_reported'), panelText('policy_sync_error_reported_body'));
                setPanelActions('policySyncErrorActions', []);
            }
        } else if (snapshot.sync_state === 'pending') {
            setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                'policySyncErrorAnswerIcon', 'info',
                panelText('policy_sync_error_none'), panelText('policy_sync_error_pending_body'));
            setPanelActions('policySyncErrorActions', []);
        } else if (snapshot.enabled && snapshot.sync_state === 'synced') {
            var when = snapshot.last_success ? panelTimestamp(snapshot.last_success) : '';
            setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                'policySyncErrorAnswerIcon', 'success',
                panelText('policy_sync_error_none'),
                when
                    ? panelText('policy_sync_error_none_body').replace('{when}', when)
                    : panelText('policy_sync_error_none_body_no_time'));
            setPanelActions('policySyncErrorActions', []);
        } else if (snapshot.enabled) {
            // Active, no error reported, but no confirmed successful sync either.
            setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                'policySyncErrorAnswerIcon', 'info',
                panelText('policy_sync_error_none'), panelText('policy_sync_error_pending_body'));
            setPanelActions('policySyncErrorActions', []);
        } else {
            setPanelAnswer('policySyncErrorAnswer', 'policySyncErrorAnswerHeadline', 'policySyncErrorAnswerBody',
                'policySyncErrorAnswerIcon', 'info',
                panelText('policy_sync_error_none'), panelText('policy_sync_error_off_body'));
            setPanelActions('policySyncErrorActions', []);
        }

        // The raw server string is preserved verbatim, never reworded. A failure
        // with no text still says so; a deployment that reported no snapshot at
        // all says that, rather than "None", which would read as an observation.
        var detail;
        if (!snapshot) {
            detail = panelText('policy_not_available');
        } else if (snapshot.last_error) {
            detail = String(snapshot.last_error);
        } else {
            detail = panelText(failure ? 'policy_no_error_detail' : 'policy_none');
        }
        setPanelText('policyLastError', detail);
    }

    // render writes all four panels from one consistent pair of inputs: the
    // record the server accepted (intent) and the runtime snapshot it reported
    // (observation).
    function render(record, snapshot) {
        if (!root.document) {
            return;
        }
        renderStatusBadge(snapshot);
        renderPolicyStatus(record, snapshot);
        renderPolicyInventory(record, snapshot);
        renderPolicyCDN(record, snapshot);
        renderPolicySyncError(record, snapshot);
    }

    root.PolicyPanels = {
        render: render
    };
}(typeof window !== 'undefined' ? window : this));
