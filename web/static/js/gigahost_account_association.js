/* One-time association of the servers this panel registered before it recorded
 * which hosting account owns them.
 *
 * A row with no recorded account is never judged by an inventory read - empty means
 * unknown - so a server the provider has deleted stays on the page and stays
 * dialled. This controller drives the one action that states that association,
 * once, for exactly those rows.
 *
 * Two things shape the code:
 *
 *  1. The counts come from the panel and are never recomputed here. The page shows
 *     what the preview answered and posts the administrator's own answer back; a
 *     count this script invented would be a number nobody checked.
 *  2. Associating a row the account no longer lists has a consequence the
 *     administrator must take separately: the next inventory read will mark it
 *     absent. That consent is its own control and its own effect (the
 *     include_unlisted field), so a client that never touches it cannot cause it.
 */

/* gigahostAssociationFormat fills a translated template's %d/%s placeholders in
 * order. The translation bundles carry the same placeholders in every language, so
 * one substitution order works for all of them. */
function gigahostAssociationFormat(template, values) {
    let next = 0;
    return String(template == null ? '' : template).replace(/%[ds]/g, () => {
        const value = values[next];
        next += 1;
        return value === undefined || value === null ? '' : String(value);
    });
}

/* gigahostAssociationReasonLabels names the reasons the panel reports for a row it
 * left unassociated. An unknown token is shown as it arrived: a reason this build
 * does not translate is still more use to an administrator than a blank. */
const gigahostAssociationReasonKeys = {
    provider_refused: 'gigahost_association_reason_provider_refused',
    provider_unanswered: 'gigahost_association_reason_provider_unanswered',
    provider_unnamed: 'gigahost_association_reason_provider_unnamed',
    write_failed: 'gigahost_association_reason_write_failed'
};

function gigahostAssociationReasonText(reasons) {
    if (!Array.isArray(reasons)) return '';
    return reasons
        .filter(entry => entry && entry.count > 0)
        .map(entry => {
            const key = gigahostAssociationReasonKeys[entry.reason];
            return key ? _(key) : String(entry.reason);
        })
        .join(', ');
}

/* gigahostAssociationWanted is how many rows the confirmation would associate. The
 * rows the account no longer lists count only when the administrator asked for
 * them, which is what makes the preview and the request agree. */
function gigahostAssociationWanted(preview, includeUnlisted) {
    if (!preview) return 0;
    const attributable = Number(preview.attributable) || 0;
    const unlisted = Number(preview.unlisted) || 0;
    return attributable + (includeUnlisted ? unlisted : 0);
}

/* gigahostAssociationPreviewText states what the confirmation would do, and what it
 * would cost: the rows this account no longer lists are the ones the next existence
 * check marks absent. */
function gigahostAssociationPreviewText(preview, includeUnlisted) {
    if (!preview || (Number(preview.candidates) || 0) === 0) {
        return _('gigahost_association_nothing');
    }
    const parts = [
        gigahostAssociationFormat(_('gigahost_association_preview'), [
            gigahostAssociationWanted(preview, includeUnlisted),
            Number(preview.candidates) || 0
        ])
    ];
    const unlisted = Number(preview.unlisted) || 0;
    if (unlisted > 0) {
        parts.push(gigahostAssociationFormat(_('gigahost_association_preview_unlisted'), [unlisted]));
    }
    const unattributed = Number(preview.unattributed) || 0;
    if (unattributed > 0) {
        parts.push(gigahostAssociationFormat(_('gigahost_association_preview_unattributed'), [
            unattributed,
            gigahostAssociationReasonText(preview.reasons)
        ]));
    }
    return parts.join(' ');
}

/* gigahostAssociationOutcomeText reports what the action did.
 *
 * A run that associated nothing has two very different meanings, and telling them
 * apart is the whole point of this function:
 *
 *   - nothing was written and rows remain (a write failed, or the provider could not
 *     answer for them). Reconciliation still skips those rows, so reporting the
 *     success copy here would tell the administrator the work is done when it is not;
 *   - nothing was written and nothing remains. That is a genuine all-clear: every row
 *     already records its account, which is what a repeated confirmation sees. */
function gigahostAssociationOutcomeText(result) {
    if (!result) return _('gigahost_association_done_none');
    const associated = Number(result.associated) || 0;
    const unattributed = Number(result.unattributed) || 0;
    if (associated === 0) {
        if (unattributed === 0) {
            // Nothing left to do: the idempotent repeat, or an account whose every
            // row already records itself.
            return _('gigahost_association_done_none');
        }
        return gigahostAssociationFormat(_('gigahost_association_preview_unattributed'), [
            unattributed,
            gigahostAssociationReasonText(result.reasons)
        ]);
    }
    const parts = [gigahostAssociationFormat(_('gigahost_association_done'), [associated])];
    const unlisted = Number(result.unlisted) || 0;
    if (unlisted > 0) {
        parts.push(gigahostAssociationFormat(_('gigahost_association_done_unlisted'), [unlisted]));
    }
    if (unattributed > 0) {
        parts.push(gigahostAssociationFormat(_('gigahost_association_preview_unattributed'), [
            unattributed,
            gigahostAssociationReasonText(result.reasons)
        ]));
    }
    return parts.join(' ');
}

/* gigahostAssociationRequest is the body the confirmation posts.
 *
 * It carries the preview it was given for, so the panel can refuse a consent that
 * belongs to a different account or to a screen the administrator has since left.
 * The unlisted field is derived from the administrator's own choice, never from a
 * default: an absent field and false mean the same thing to the panel, and false is
 * what an untouched control says. */
function gigahostAssociationRequest(previewID, includeUnlisted) {
    return {
        preview_id: previewID === undefined || previewID === null ? '' : String(previewID),
        include_unlisted: includeUnlisted === true
    };
}

/* gigahostAssociationState holds the last preview and the in-flight guard. Each
 * page gets one, so a second click cannot issue a second request while the first is
 * open - a repeated association is a statement the administrator did not make. */
function gigahostAssociationState() {
    this.preview = null;
    this.inFlight = false;
}

/* gigahostAssociationShow reveals or hides one control.
 *
 * It uses the shared .hidden class rather than the bare hidden attribute: several
 * controls on this card carry their own display rule (the switch is inline-flex), and
 * an author rule beats the user-agent [hidden] rule, so the attribute alone would
 * leave the control on screen. The attribute is set as well so assistive technology
 * sees the same state the layout shows. */
function gigahostAssociationShow(element, visible) {
    if (!element) return;
    element.hidden = !visible;
    if (element.classList) {
        element.classList.toggle('hidden', !visible);
    }
}

/* renderGigahostAssociationPreview shows the panel's counts and offers the
 * confirmation only when there is something to do.
 *
 * fresh marks a preview the panel just produced. Every fresh preview clears the
 * unlisted consent, because that consent was given for the previous counts: keeping
 * it checked would silently re-authorise the absent-marking consequence for a screen
 * the administrator has not answered yet. A re-render caused by the checkbox itself
 * is not fresh and preserves the administrator's current choice. */
function renderGigahostAssociationPreview(state, preview, fresh) {
    state.preview = preview || null;
    const choice = document.getElementById('gigahostAssociationUnlistedChoice');
    const checkbox = document.getElementById('gigahostAssociationIncludeUnlisted');
    const outcome = document.getElementById('gigahostAssociationOutcome');
    const confirm = document.getElementById('btnGigahostAssociationConfirm');

    const unlisted = preview ? (Number(preview.unlisted) || 0) : 0;
    if (checkbox && (fresh || unlisted === 0)) checkbox.checked = false;
    // The choice only exists when the account has stopped listing something: an
    // offered control that can do nothing would be a decision the administrator
    // cannot make meaningfully.
    gigahostAssociationShow(choice, unlisted > 0);

    const previewID = preview && preview.preview_id ? String(preview.preview_id) : '';
    if (outcome) {
        outcome.textContent = gigahostAssociationPreviewText(preview, checkbox && checkbox.checked);
        gigahostAssociationShow(outcome, true);
    }
    // A confirmation without the preview it answers has nothing to bind: the panel
    // would have to apply it to whichever account answers next.
    gigahostAssociationShow(confirm, previewID !== '' && gigahostAssociationWanted(preview, checkbox && checkbox.checked) > 0);
}

function renderGigahostAssociationOutcome(result) {
    const outcome = document.getElementById('gigahostAssociationOutcome');
    const confirm = document.getElementById('btnGigahostAssociationConfirm');
    if (outcome) {
        outcome.textContent = gigahostAssociationOutcomeText(result);
        gigahostAssociationShow(outcome, true);
    }
    // The action is one-time: once it has run there is nothing to confirm, and the
    // preview would report the rows it just associated as already bound.
    gigahostAssociationShow(confirm, false);
}

function gigahostAssociationBusy(state) {
    const spinner = document.getElementById('gigahostAssociationSpinner');
    const button = document.getElementById('btnGigahostAssociationPreview');
    if (spinner) spinner.classList.toggle('hidden', !state.inFlight);
    if (button) button.disabled = state.inFlight;
}

async function runGigahostAssociationPreview(state) {
    if (state.inFlight) return;
    state.inFlight = true;
    gigahostAssociationBusy(state);
    try {
        const preview = await API.get('/api/admin/hosting/gigahost/account-association', {silent: true});
        renderGigahostAssociationPreview(state, preview, true);
    } catch (err) {
        const outcome = document.getElementById('gigahostAssociationOutcome');
        if (outcome) {
            outcome.textContent = gigahostAssociationFormat(_('gigahost_association_failed'), [
                err && err.message ? err.message : ''
            ]);
            gigahostAssociationShow(outcome, true);
        }
        gigahostAssociationShow(document.getElementById('btnGigahostAssociationConfirm'), false);
    } finally {
        state.inFlight = false;
        gigahostAssociationBusy(state);
    }
}

async function runGigahostAssociation(state) {
    if (state.inFlight) return;
    const checkbox = document.getElementById('gigahostAssociationIncludeUnlisted');
    // Without a preview there is no account and no unlisted scope to bind the
    // confirmation to, so there is nothing this action could legitimately do.
    const previewID = state.preview && state.preview.preview_id ? String(state.preview.preview_id) : '';
    if (previewID === '') return;
    state.inFlight = true;
    gigahostAssociationBusy(state);
    try {
        const result = await API.post(
            '/api/admin/hosting/gigahost/account-association',
            gigahostAssociationRequest(previewID, checkbox && checkbox.checked),
            {silent: true}
        );
        renderGigahostAssociationOutcome(result);
        // The one-time action has run: the choice it covered is spent, so the switch
        // is hidden AND cleared. Leaving it checked would carry that consent into a
        // later preview for a different set of rows.
        if (checkbox) checkbox.checked = false;
        gigahostAssociationShow(document.getElementById('gigahostAssociationUnlistedChoice'), false);
        state.preview = null;
    } catch (err) {
        const outcome = document.getElementById('gigahostAssociationOutcome');
        if (outcome) {
            outcome.textContent = gigahostAssociationFormat(_('gigahost_association_failed'), [
                err && err.message ? err.message : ''
            ]);
            gigahostAssociationShow(outcome, true);
        }
    } finally {
        state.inFlight = false;
        gigahostAssociationBusy(state);
    }
}

/* initGigahostAssociation wires the section when the page has it. It is a function
 * rather than a module-scope side effect so the harness can call it against its own
 * document, and so a page without the section costs nothing.
 *
 * It is idempotent: a shell that loads this module twice, or a page that
 * initialises it and is also reached by the load event below, must not attach two
 * handlers to one button - a double-bound confirmation would issue the action
 * twice. */
let gigahostAssociationBound = false;

function initGigahostAssociation() {
    const section = document.getElementById('gigahostAssociationSection');
    if (!section || gigahostAssociationBound) return null;
    gigahostAssociationBound = true;
    const state = new gigahostAssociationState();

    const preview = document.getElementById('btnGigahostAssociationPreview');
    if (preview) preview.addEventListener('click', () => runGigahostAssociationPreview(state));

    const confirm = document.getElementById('btnGigahostAssociationConfirm');
    if (confirm) confirm.addEventListener('click', () => runGigahostAssociation(state));

    const checkbox = document.getElementById('gigahostAssociationIncludeUnlisted');
    if (checkbox) {
        // Re-render from the preview already on screen: the counts do not change
        // between a preview and its confirmation, only the administrator's choice
        // does, and re-reading the provider to learn the same numbers would make the
        // two disagree whenever the account changes in between.
        checkbox.addEventListener('change', () => {
            renderGigahostAssociationPreview(state, state.preview, false);
        });
    }
    return state;
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initGigahostAssociation);
    } else {
        initGigahostAssociation();
    }
}
