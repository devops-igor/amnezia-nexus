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
 *
 * Announcements. The unsaved badge, the success region and the error region are
 * live regions that stay mounted and exposed while empty (the stylesheet keeps
 * an empty one out of the layout), so assistive technology has registered them
 * before their text changes. Text is written only when it changes: the unsaved
 * announcement fires on the transition to dirty, not on every keystroke.
 *
 * Commit gate. A commit control marked data-commit-when-dirty is enabled only
 * while its card is dirty and not blocked. A control that must wait for its
 * controller to load a record also carries data-commit-gated, which starts it
 * blocked;
 * the controller calls gate() with the outcome of its own readiness and
 * validation checks. This module is the only writer of the commit's disabled
 * property.
 *
 * One lifecycle. Every card commits through submit(card, work). A controller
 * supplies only the request and classifies what came back; this module owns what
 * must be the same everywhere, so it cannot differ from card to card:
 *
 *   invalid   an entry the card's own markup rejects. Nothing is sent, the field
 *             is named in the card's error region, and the card stays unsaved.
 *   saved     the draft that was sent is the saved state. If the operator typed
 *             more while the request ran, only the sent part is saved and the
 *             rest stays on screen, marked unsaved.
 *   refused   the server answered with a refusal      } the draft and its
 *   failed    no answer arrived (transport)            } baseline are never
 *   conflict  the stored state changed under the draft } touched, and the card
 *                                                        stays marked unsaved.
 *
 * Validation. The commit control is a button, so the browser never applies a
 * field's own required, min, max and step to it. submit() asks the platform
 * instead: every control the card would send must satisfy the constraints its
 * markup declares, and the report names the field. The constraints are therefore
 * the markup's, not a copy kept here, and a card that adds one gets it enforced
 * without a change to this module. A number field the markup does not require is
 * still not a place to guess, so submit() also refuses an entry that is not a
 * number rather than let a collector replace it with a default.
 *
 * The constraints bind entries, not stored values. A control that still holds the
 * value its card loaded is showing data the server already keeps, and the
 * operator did not type it: refusing it would make a card unsaveable over a
 * value nobody entered, which is the state a stored empty field produced. Such a
 * control is therefore left out of the check and sent back unchanged, while the
 * same value typed by the operator is an entry and must satisfy the markup.
 *
 * Busy is set before the request and cleared on every terminal outcome. A second
 * submit while one runs is ignored. Exactly one status region and one alert
 * region exist per card, at most one has text, and an outcome is written to the
 * region that matches it.
 *
 * Focus. Disabling a focused control drops keyboard focus. When the operation
 * ends, focus is put back only if the operation lost it: the active element is
 * the body, or a disabled control inside the submitting card. It goes to the
 * control that held it, or the card heading when that control is gone. Focus that
 * the operator moved to any other control, in this card or another, is never
 * touched.
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

    function setText(node, value) {
        if (node.textContent !== value) node.textContent = value;
    }

    function paint(card, state) {
        var badge = part(card, '[data-dirty]');
        if (badge) setText(badge, state.dirty ? tr('settings_unsaved') : '');
        var commit = part(card, '[data-commit]');
        if (commit && commit.hasAttribute('data-commit-when-dirty')) {
            commit.disabled = state.busy || state.blocked || !state.dirty;
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

    // The regions stay mounted: clearing a report empties its text and nothing else.
    function hideReport(card) {
        ['[data-status]', '[data-error]'].forEach(function (selector) {
            var region = part(card, selector);
            if (region) {
                setText(region, '');
                region.removeAttribute('data-outcome');
            }
        });
        var box = part(card, '[data-result]');
        if (box) box.setAttribute('data-state', '');
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
        state = {
            baseline: snapshot(card, true),
            dirty: false,
            busy: false,
            blocked: !!(part(card, '[data-commit]') && part(card, '[data-commit]').hasAttribute('data-commit-gated')),
            held: null,
            timer: null,
            reporting: false
        };
        // The heading is where focus lands when the control that had it is gone.
        var heading = part(card, '.card-title');
        if (heading && !heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
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

    function inside(card, node) {
        return !!node && node !== root.document.body && card.contains(node);
    }

    function focusable(node) {
        return !!node && node.isConnected && !node.disabled;
    }

    // lostFocus tells whether the operation itself took focus away: nothing has
    // it, or it sits on a control of the submitting card that is now disabled.
    // Focus on any enabled control, in this card or another, was put there by the
    // operator and is theirs.
    function lostFocus(card) {
        var active = root.document.activeElement;
        if (!active || active === root.document.body) return true;
        return card.contains(active) && !!active.disabled;
    }

    // restoreFocus puts focus back only when the operation lost it, on the control
    // that held it or, when that is gone or disabled, the card heading.
    function restoreFocus(card, held) {
        if (!held || !lostFocus(card)) return;
        var target = focusable(held) ? held : part(card, '.card-title');
        if (target && typeof target.focus === 'function') target.focus();
    }

    function busy(card, flag) {
        var found = stateFor(card);
        if (!found) return;
        var state = found.state;
        if (flag && !state.busy) {
            var active = root.document.activeElement;
            state.held = inside(found.card, active) ? active : null;
        }
        state.busy = !!flag;
        found.card.setAttribute('aria-busy', flag ? 'true' : 'false');
        var spinner = part(found.card, '[data-commit] .spinner');
        if (spinner) spinner.classList.toggle('hidden', !flag);
        paint(found.card, state);
        if (!flag) {
            var held = state.held;
            state.held = null;
            restoreFocus(found.card, held);
        }
    }

    function isBusy(card) {
        var found = stateFor(card);
        return found ? found.state.busy : false;
    }

    // gate blocks or opens the commit for reasons the controller owns: a record
    // that is not loaded yet, or input that fails validation.
    function gate(card, blocked) {
        var found = stateFor(card);
        if (!found) return;
        found.state.blocked = !!blocked;
        paint(found.card, found.state);
    }

    // report writes the outcome of a commit into the card that made it. Success
    // fades after a few seconds; a failure stays until the operator edits again.
    function report(card, kind, message, outcome) {
        var found = stateFor(card);
        if (!found) return false;
        var state = found.state;
        root.clearTimeout(state.timer);
        hideReport(found.card);
        var region = part(found.card, kind === 'success' ? '[data-status]' : '[data-error]');
        if (!region) return false;
        region.textContent = message;
        region.setAttribute('data-outcome', outcome || (kind === 'success' ? 'saved' : 'failed'));
        var box = part(found.card, '[data-result]');
        if (box) box.setAttribute('data-state', kind === 'success' ? 'success' : 'error');
        state.reporting = true;
        if (kind === 'success') {
            state.timer = root.setTimeout(function () {
                hideReport(found.card);
                state.reporting = false;
            }, STATUS_MS);
        }
        return true;
    }

    // OUTCOMES lists what a controller may return from its work. Anything else is
    // treated as a failure, so a controller that forgets to classify cannot make a
    // card look saved.
    var OUTCOMES = { saved: 1, refused: 1, failed: 1, conflict: 1 };

    // labelOf names a control the way its markup already does: the label it points
    // at, the label that wraps it, or the name it is addressed by.
    function labelOf(control) {
        var label = null;
        if (control.id) label = root.document.querySelector('label[for="' + control.id + '"]');
        if (!label && control.closest) label = control.closest('label');
        var text = label ? (label.textContent || '').replace(/\s+/g, ' ').trim() : '';
        if (text) return text;
        return control.getAttribute('aria-label') || control.name || control.id || '';
    }

    // fieldMessage says why one entry cannot be sent, naming the field.
    function fieldMessage(control) {
        var name = labelOf(control) || '';
        var reason = control.validity && control.validity.valueMissing
            ? tr('settings_field_required')
            : tr('settings_field_invalid');
        return name ? name + ': ' + reason : reason;
    }

    // unchanged reports whether a control still holds the value its card was
    // loaded with, or last stored. That value is data, not an entry: it is what
    // the server already keeps for the field, so sending it back cannot change
    // anything. The card's own baseline is the only record of it, which is why
    // this lives here and not in each controller.
    function unchanged(control) {
        var card = control && control.closest ? control.closest('[data-settings-card]') : null;
        var state = card ? states.get(card) : null;
        if (!state) return false;
        var list = controls(card);
        var index = list.indexOf(control);
        var was = index < 0 ? null : state.baseline[index];
        if (!was || was[0] !== keyOf(control, index)) return false;
        return valueOf(control, false) === was[1];
    }

    // invalidControl returns the first control of the card the commit may not send,
    // or null. The constraints are the ones the markup declares: checkValidity
    // covers required, min, max, step, pattern and the input's type, so a constraint
    // added to a template is enforced here without a matching rule in this file. A
    // number the markup does not require still has to be a number: an entry that is
    // not one is refused rather than replaced by a default somewhere further down.
    // A control the operator has not touched is not an entry and is not checked.
    function invalidControl(card) {
        var list = controls(card);
        for (var i = 0; i < list.length; i++) {
            var control = list[i];
            if (unchanged(control)) continue;
            if (control.willValidate === false) continue;
            if (typeof control.checkValidity === 'function' && !control.checkValidity()) return control;
            var numeric = (control.type || '').toLowerCase() === 'number';
            if (numeric && control.value !== '' && !isFinite(Number(control.value))) return control;
        }
        return null;
    }

    // submit runs one commit for a card and settles it the same way for every
    // controller. work() resolves to { outcome, message, reconcile }:
    //   saved     reconcile() may apply the server's answer to the form when
    //             nothing was typed meanwhile; the saved state moves to what was
    //             sent either way. quiet: true suppresses the status text.
    //   refused / failed / conflict   the draft and its baseline are untouched.
    // work() builds its request from the form when it is called, which is the same
    // step as the snapshot. A throw is a failure. It always clears busy and always reports, and never
    // reports success unless work() said saved.
    function submit(card, work) {
        var found = stateFor(card);
        if (!found) return Promise.resolve({ outcome: 'failed', ran: false });
        var state = found.state;
        if (state.busy) return Promise.resolve({ outcome: 'failed', ran: false });
        clearReport(found.card);
        // An entry the card's own markup rejects is not sent. The report names the
        // field, and nothing else changes: the draft is what the operator typed and
        // the card stays marked unsaved, because nothing was stored.
        var rejected = invalidControl(found.card);
        if (rejected) {
            report(found.card, 'error', fieldMessage(rejected), 'invalid');
            return Promise.resolve({ outcome: 'invalid', ran: false });
        }
        busy(found.card, true);
        // The snapshot is taken in the same synchronous step that calls work(), so
        // what work() reads from the form to build its request and what counts as
        // "sent" are the same instant. Nothing can be typed between the two.
        var sent = snapshot(found.card, false);
        var started;
        try {
            started = Promise.resolve(work());
        } catch (err) {
            started = Promise.reject(err);
        }
        return started.then(function (result) {
            return result || { outcome: 'failed', message: tr('error') };
        }, function (err) {
            return { outcome: 'failed', message: (err && err.message) || tr('error') };
        }).then(function (result) {
            var outcome = OUTCOMES[result.outcome] ? result.outcome : 'failed';
            try {
                if (outcome === 'saved') {
                    settleSaved(found.card, sent, result);
                } else {
                    report(found.card, 'error', result.message || tr('error'), outcome);
                }
            } finally {
                busy(found.card, false);
            }
            return { outcome: outcome, ran: true, result: result };
        });
    }

    // settleSaved moves the saved state to what was sent. If the operator kept
    // typing, the form is left alone and what they typed stays marked unsaved;
    // otherwise the controller may apply the server's answer to the form first.
    function settleSaved(card, sent, result) {
        if (differs(card, sent)) {
            rebase(card, sent);
        } else {
            if (typeof result.reconcile === 'function') result.reconcile();
            rebase(card);
        }
        // A controller that saves as a step of something else (a test that saves
        // first) passes quiet and reports its own result, so the card does not
        // announce a save the operator did not ask for.
        if (!result.quiet) report(card, 'success', result.message || tr('settings_saved'), 'saved');
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
        isBusy: isBusy,
        gate: gate,
        report: report,
        submit: submit,
        clearReport: clearReport,
        // unchanged tells whether a control still holds the value its card loaded,
        // which a controller that reads a typed number itself needs to know: a
        // stored value is sent back as it is, an entry must satisfy the markup.
        unchanged: unchanged,
        // A controller that reads a typed number itself refuses an entry it cannot
        // read through this, so the card names the field the same way it would if
        // submit() had rejected it.
        fieldMessage: fieldMessage
    };

    if (root.document) {
        if (root.document.readyState === 'loading') {
            root.document.addEventListener('DOMContentLoaded', init);
        } else {
            init();
        }
    }
}(typeof window !== 'undefined' ? window : this));
