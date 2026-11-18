/**
 * Amnezia Nexus - per-card save model for the Settings page.
 *
 * A card is any element marked data-settings-card. This module owns what is the
 * same for every card: whether its fields differ from the value they were loaded
 * with (the dirty state), the busy state of its commit control, and where the
 * result of a commit is reported (inside the card, never on the page).
 *
 * It does not know what a card saves. Each card's commit belongs to the script
 * that owns the card's data: settings_save.js for the staged cards, and the
 * notification and policy controllers for the cards that load their own record.
 *
 * Baseline. A card whose markup carries its stored values compares against the
 * defaults the server rendered (defaultValue, defaultChecked, defaultSelected),
 * so a value the browser restored on reload still counts as a change. A card
 * that loads its record by script calls rebase() once the record is applied.
 *
 * Secrets. A control marked data-secret is write-only: the server keeps the
 * stored secret when the submitted value is empty. Emptying such a control is
 * therefore not a change, and only a non-empty different value is.
 */
(function (root) {
    'use strict';

    var STATUS_MS = 6000;
    var states = new WeakMap();
    var dirtyCards = new Set();
    var guarded = false;

    function tr(key) {
        return typeof root._ === 'function' ? root._(key) : key;
    }

    function resolve(card) {
        if (typeof card === 'string') return root.document.getElementById(card);
        return card || null;
    }

    function part(card, selector) {
        return card.querySelector(selector);
    }

    // controls lists the staged fields of a card. A region marked
    // data-dirty-ignore holds inputs of an immediate action (the deployment
    // selectors, for example), which are not settings and never make a card dirty.
    function controls(card) {
        return Array.prototype.filter.call(card.querySelectorAll('input, select, textarea'), function (c) {
            var type = (c.type || '').toLowerCase();
            if (type === 'button' || type === 'submit' || type === 'reset' || type === 'file') return false;
            return !c.closest('[data-dirty-ignore]');
        });
    }

    function keyOf(control, index) {
        return control.id || control.name || ('#' + index);
    }

    function isChoice(control) {
        var type = (control.type || '').toLowerCase();
        return type === 'checkbox' || type === 'radio';
    }

    function valueOf(control, useDefaults) {
        if (isChoice(control)) return useDefaults ? control.defaultChecked : control.checked;
        if (control.tagName === 'SELECT' && useDefaults) {
            var options = Array.prototype.slice.call(control.options);
            var chosen = options.filter(function (o) { return o.defaultSelected; })[0] || options[0];
            return chosen ? chosen.value : '';
        }
        return useDefaults ? control.defaultValue : control.value;
    }

    function snapshot(card, useDefaults) {
        return controls(card).map(function (control, index) {
            return [keyOf(control, index), valueOf(control, useDefaults)];
        });
    }

    function differs(card, baseline) {
        var list = controls(card);
        if (list.length !== baseline.length) return true;
        return list.some(function (control, index) {
            var was = baseline[index];
            if (was[0] !== keyOf(control, index)) return true;
            var now = valueOf(control, false);
            if (control.hasAttribute('data-secret') && now === '') return false;
            return now !== was[1];
        });
    }

    function onBeforeUnload(event) {
        event.preventDefault();
        event.returnValue = '';
        return '';
    }

    // The prompt exists only while there is something to lose.
    function syncGuard() {
        if (dirtyCards.size > 0 && !guarded) {
            root.addEventListener('beforeunload', onBeforeUnload);
            guarded = true;
        } else if (dirtyCards.size === 0 && guarded) {
            root.removeEventListener('beforeunload', onBeforeUnload);
            guarded = false;
        }
    }

    function paint(card, state) {
        var badge = part(card, '[data-dirty]');
        if (badge) {
            badge.textContent = state.dirty ? tr('settings_unsaved') : '';
            badge.classList.toggle('hidden', !state.dirty);
        }
        // Only a commit that opts in is gated here. The notification and policy
        // controllers keep their own readiness gates on their own buttons.
        var commit = part(card, '[data-commit]');
        if (commit && commit.hasAttribute('data-commit-when-dirty')) {
            commit.disabled = state.busy || !state.dirty;
        }
    }

    function update(card, state) {
        var dirty = differs(card, state.baseline);
        state.dirty = dirty;
        if (dirty) dirtyCards.add(card); else dirtyCards["delete"](card);
        syncGuard();
        paint(card, state);
        return dirty;
    }

    function hideReport(card) {
        ['[data-status]', '[data-error]'].forEach(function (selector) {
            var region = part(card, selector);
            if (region) {
                region.textContent = '';
                region.hidden = true;
            }
        });
    }

    function onEdit(event) {
        var card = event.currentTarget;
        var state = states.get(card);
        if (!state) return;
        var wasShowing = state.reporting;
        if (wasShowing) {
            root.clearTimeout(state.timer);
            hideReport(card);
            state.reporting = false;
        }
        update(card, state);
    }

    function track(card) {
        var state = states.get(card);
        if (state) return state;
        state = { baseline: snapshot(card, true), dirty: false, busy: false, timer: null, reporting: false };
        states.set(card, state);
        card.addEventListener('input', onEdit);
        card.addEventListener('change', onEdit);
        // Enter in a staged field must neither reload the page nor commit.
        Array.prototype.forEach.call(card.querySelectorAll('form'), function (form) {
            form.addEventListener('submit', function (event) { event.preventDefault(); });
        });
        update(card, state);
        return state;
    }

    function stateFor(card) {
        var target = resolve(card);
        return target ? { card: target, state: track(target) } : null;
    }

    // rebase makes a set of values the card's saved state. With no argument it is
    // the values on screen, which is right after a stored record has been applied.
    // After a commit pass the snapshot taken when the request was built: anything
    // the operator typed while the request was in flight is then still unsaved.
    function rebase(card, saved) {
        var found = stateFor(card);
        if (!found) return false;
        found.state.baseline = saved || snapshot(found.card, false);
        update(found.card, found.state);
        return true;
    }

    // capture records what the card shows right now, to be handed back to rebase.
    function capture(card) {
        var found = stateFor(card);
        return found ? snapshot(found.card, false) : null;
    }

    // changedSince reports whether the card differs from a captured snapshot.
    function changedSince(card, saved) {
        var found = stateFor(card);
        return found && saved ? differs(found.card, saved) : false;
    }

    function refresh(card) {
        var found = stateFor(card);
        return found ? update(found.card, found.state) : false;
    }

    function isDirty(card) {
        var found = stateFor(card);
        return found ? found.state.dirty : false;
    }

    function busy(card, flag) {
        var found = stateFor(card);
        if (!found) return;
        found.state.busy = !!flag;
        found.card.setAttribute('aria-busy', flag ? 'true' : 'false');
        var spinner = part(found.card, '[data-commit] .spinner');
        if (spinner) spinner.classList.toggle('hidden', !flag);
        paint(found.card, found.state);
    }

    // report writes the outcome of a commit into the card that made it. Success
    // fades after a few seconds; a failure stays until the operator edits again.
    function report(card, kind, message) {
        var found = stateFor(card);
        if (!found) return false;
        var state = found.state;
        root.clearTimeout(state.timer);
        hideReport(found.card);
        var region = part(found.card, kind === 'success' ? '[data-status]' : '[data-error]');
        if (!region) return false;
        region.hidden = false;
        region.textContent = message;
        state.reporting = true;
        if (kind === 'success') {
            state.timer = root.setTimeout(function () {
                hideReport(found.card);
                state.reporting = false;
            }, STATUS_MS);
        }
        return true;
    }

    function clearReport(card) {
        var found = stateFor(card);
        if (!found) return;
        root.clearTimeout(found.state.timer);
        hideReport(found.card);
        found.state.reporting = false;
    }

    function init() {
        if (!root.document) return;
        Array.prototype.forEach.call(root.document.querySelectorAll('[data-settings-card]'), track);
    }

    root.SettingsCards = {
        init: init,
        rebase: rebase,
        capture: capture,
        changedSince: changedSince,
        refresh: refresh,
        isDirty: isDirty,
        busy: busy,
        report: report,
        clearReport: clearReport
    };

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }
}(typeof window !== 'undefined' ? window : this));
