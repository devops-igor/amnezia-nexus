/* Gigahost order status classification.
 *
 * This module answers one question per order and answers it purely: given the order
 * row, the onboarding-journal DTO, the list's provider observation and the saved
 * approval, what may the view claim? It renders nothing and performs no request, so it
 * is the file to read when the question is "where does this fact come from".
 *
 * Three axes stay separate, because conflating them is how a previous view could
 * present a VPS as ready when only one provider read had answered:
 *
 *   provider  requested -> deploying -> ready, or failed / cancelled / unknown
 *   VPN setup none | scheduled | needs an operator | installing | ready | failed | revoked
 *   backend   none | unknown | pending | healthy | degraded | unhealthy | disabled
 *
 * The two producers of setup state are distinct on purpose: the saved approval list and
 * the onboarding journal the immediate setup path writes. Reading only the first would
 * report an installed backend as "not started".
 */

// Provider/ledger status spellings that decide a stage. A provider answer wins over the
// ledger row, which is only the panel's copy of the last answer.
const gigahostOrderStatusReadySpellings = ['ready', 'active'];
const gigahostOrderStatusFailedSpellings = ['failed', 'error'];
const gigahostOrderStatusCancelledSpellings = ['cancelled', 'canceled'];
// gigahostOrderStatusDeletedSpellings is the provider's vocabulary for a deployment it
// no longer has. Both spellings are one fact, and the backend already treats them as
// one (`isDeletedStatus` in the order-observation path): a `terminated` order that the
// client classified as `deploying` would keep the setups and retries that exist to
// contact a host the panel has evidence is gone. It is a stage of its own rather than a
// cancellation, because the fact the operator needs is that the server is gone: a
// cancelled order was stopped while its VPS could still be running, and a deleted one
// has no VPS at all.
const gigahostOrderStatusDeletedSpellings = ['deleted', 'terminated'];
// gigahostOrderStatusRequestedSpellings are the provider and ledger spellings for an
// order that exists but whose deployment has not started yet. `requested` is a stage in
// the progression below, so a queued order is not drawn as one already deploying: both
// vocabularies spell "queued" differently from "deploying", and flattening them made two
// different states render identically.
const gigahostOrderStatusRequestedSpellings = ['pending', 'waiting', 'pending_payment', 'pending_order'];

// gigahostOrderStatusStages are the provider stages an order passes through, in order.
// VPN setup and backend health are separate axes, never drawn as stages.
const gigahostOrderStatusStages = ['requested', 'deploying', 'ready'];

// gigahostOrderStatusTerminalStages name the stages that end the progression: their
// chain is the request plus the ending, because none of them can claim it ever deployed.
const gigahostOrderStatusTerminalStages = ['failed', 'cancelled', 'deleted', 'unknown'];

// gigahostOrderStatusSetupStates maps a saved setup-intent state to the setup axis. A
// state outside this table is reported as unknown rather than guessed into a group:
// reporting "not started" for a state the panel does not recognise would hide an
// approval that exists.
const gigahostOrderStatusSetupStates = {
    pending: 'scheduled',
    ready_for_setup: 'scheduled',
    installing: 'installing',
    install_paused: 'needs_operator',
    awaiting_credentials: 'needs_operator',
    awaiting_host_confirmation: 'needs_operator',
    ready: 'ready',
    failed: 'failed',
    cancelled: 'revoked',
    canceled: 'revoked'
};

// gigahostOrderStatusJournalSetupStates maps the onboarding journal's execution status to
// the setup axis. This vocabulary is what the immediate "Setup Backend" path writes; it is
// setup execution, never a provider observation.
const gigahostOrderStatusJournalSetupStates = {
    deploying: 'installing',
    ssh_verifying: 'installing',
    installing_protocol: 'installing',
    enabling_backend: 'installing',
    ready: 'ready',
    failed: 'failed'
};

// gigahostOrderStatusJournalStepStates maps a journal step to the same axis.
const gigahostOrderStatusJournalStepStates = {
    server_registration: 'installing',
    installing_protocol: 'installing',
    enabling_backend: 'installing',
    ready: 'ready'
};

// gigahostOrderStatusHealthStates maps a backend runtime status to the health axis.
// `active` is the panel's own word for a verified healthy tunnel. Any spelling outside
// this table is unknown, never healthy.
const gigahostOrderStatusHealthStates = {
    active: 'healthy',
    degraded: 'degraded',
    connecting: 'pending',
    disabled: 'disabled',
    unhealthy: 'unhealthy',
    failed: 'unhealthy'
};

// gigahostOrderStatusObservationOutcomes are the documented provider observations the list
// response may carry for one order.
const gigahostOrderStatusObservationOutcomes = ['confirmed', 'unconfirmed', 'unavailable', 'not_checked'];

/* gigahostOrderStatusNow is the clock. It is one function so a test can pin it
 * and assert an exact rendered timestamp instead of a moving one. */
function gigahostOrderStatusNow() {
    return new Date();
}

/* gigahostOrderStatusStageInFlight reports whether a stage is one the deployment can
 * still be making progress on. A terminal stage is an outcome, not a step in flight:
 * the attempt is over, so nothing drawn for that row may claim a step is current. */
function gigahostOrderStatusStageInFlight(stage) {
    return gigahostOrderStatusStages.indexOf(stage) !== -1;
}

/* gigahostOrderStatusPresentedStage maps a provider stage to the stage this view
 * presents. One mapping exists, and it is about a finished order:
 *
 * A cancellation is the final decision about an order, so it is presented as the
 * deletion it is rather than as a state that still awaits an operator. Nothing about a
 * cancelled order is actionable - every control this view could offer would contact a
 * deployment the order no longer covers - and presenting it as "not usable yet" was how
 * a cancelled order came to look like one still waiting for setup.
 *
 * The provider/ledger spelling stays available through gigahostOrderStatusProviderStage;
 * this function decides only what the interface claims. */
function gigahostOrderStatusPresentedStage(stage) {
    if (stage === 'cancelled') return 'deleted';
    return stage;
}

/* gigahostOrderStatusLedgerStage classifies one order from its recorded row and the
 * list's durable absence record, without any per-order provider read. It answers the
 * question a read has to ask before it asks anything: is there still an order at the
 * provider that this read could learn something about?
 *
 * It exists so the refresh performs no status request for a retired order, and so the
 * decision to skip that request is made from the same vocabulary the rendered row uses.
 * A provider-final failure is included: the order ended before any setup work, so there is
 * no deployment a status request could describe. The row's own step column is what keeps a
 * recoverable setup failure out of that class; it is present on the row the list returned,
 * so this question does not depend on the detail read succeeding. */
function gigahostOrderStatusLedgerStage(order, providerAbsent) {
    if (providerAbsent === true) return 'deleted';
    const id = String((order && order.order_id) || '');
    if (gigahostOrderStatusIsPlaceholderID(id)) return 'unknown';
    const stage = gigahostOrderStatusPresentedStage(gigahostOrderStatusProviderStage(order && order.status));
    const journal = gigahostOrderStatusRowJournalEvidence(order, null);
    if (gigahostOrderStatusProviderFinalFailure(order && order.status, journal)) return 'deleted';
    return stage;
}

/* gigahostOrderStatusPollable reports whether a per-order status request may be issued
 * for this order at all. A deleted or cancelled order is finished: the panel holds the
 * decision already, and a status request could only re-ask a provider that has nothing
 * left to say about it. */
function gigahostOrderStatusPollable(order, providerAbsent) {
    return gigahostOrderStatusLedgerStage(order, providerAbsent) !== 'deleted';
}

/* gigahostOrderStatusProviderStage maps a provider/ledger status spelling to one
 * stage. It reads no address: a VPS is ready only when the provider said so, and an
 * order the provider has accepted without starting is still `requested` rather than
 * `deploying`, because those are different facts for the operator. */
function gigahostOrderStatusProviderStage(status) {
    const s = String(status || '').trim().toLowerCase();
    if (gigahostOrderStatusReadySpellings.indexOf(s) !== -1) return 'ready';
    if (gigahostOrderStatusFailedSpellings.indexOf(s) !== -1) return 'failed';
    if (gigahostOrderStatusDeletedSpellings.indexOf(s) !== -1) return 'deleted';
    if (gigahostOrderStatusCancelledSpellings.indexOf(s) !== -1) return 'cancelled';
    if (gigahostOrderStatusRequestedSpellings.indexOf(s) !== -1) return 'requested';
    if (s === 'unknown' || s === '') return 'unknown';
    return 'deploying';
}

/* gigahostOrderStatusIsPlaceholderID reports a ledger id whose purchase never
 * resolved. There is no provider order behind such a row, so its stage is unknown
 * rather than whatever status the placeholder carries: claiming progress for an
 * order the provider never acknowledged is the invention this view must not make. */
function gigahostOrderStatusIsPlaceholderID(orderId) {
    const id = String(orderId || '');
    return id.indexOf('intent_') === 0 || id.indexOf('unknown_') === 0;
}

/* gigahostOrderStatusStageChain returns the progression to draw, each entry marked
 * done, current or pending. Steps the current state contradicts are not returned:
 * a failed, cancelled or unknown order does not claim it ever deployed. */
function gigahostOrderStatusStageChain(stage) {
    if (gigahostOrderStatusTerminalStages.indexOf(stage) !== -1) {
        return [
            {stage: 'requested', state: 'done'},
            {stage: stage, state: 'current'}
        ];
    }
    const currentIndex = gigahostOrderStatusStages.indexOf(stage);
    return gigahostOrderStatusStages.map((name, index) => ({
        stage: name,
        state: index < currentIndex ? 'done' : (index === currentIndex ? 'current' : 'pending')
    }));
}

/* gigahostOrderStatusSetupState maps the setup evidence to the setup axis.
 *
 * Two producers write setup progress and only one of them keeps a durable approval:
 * the saved-intent list, and the onboarding journal that the immediate "Setup
 * Backend" path writes without creating an intent (status/step/server_id on the order
 * row). The journal is therefore setup evidence in its own right: reading the
 * approval list alone would report "not started" for an install the panel already
 * completed. known=false on both means nothing could be read, which is not the same
 * statement as "no approval exists". */
function gigahostOrderStatusSetupState(setup) {
    if (!setup) return 'unknown';
    if (setup.intent) {
        return gigahostOrderStatusSetupStates[String(setup.intent.state || '')] || 'unknown';
    }
    // An approval is the more specific record, so it is read first; the journal is
    // consulted when no approval exists, not instead of one.
    const journal = gigahostOrderStatusJournalSetupState(setup.journal);
    if (journal) return journal;
    return setup.known ? 'none' : 'unknown';
}

/* gigahostOrderStatusJournalSetupState maps onboarding-journal evidence to the setup
 * axis.
 *
 * The journal is identified by what only onboarding writes: a step, or the panel server
 * id it registers. The bare status column is shared with provider refreshes, so a
 * provider's "deploying" is not by itself proof that an install was attempted - using
 * it would recreate the conflation this correction exists to remove, in the other
 * direction.
 *
 * It returns '' when the DTO carries no journal evidence at all, so an order the panel
 * never onboarded keeps reading as "not started". */
function gigahostOrderStatusJournalSetupState(journal) {
    if (!journal || !journal.present) return '';
    const status = String(journal.status || '').trim().toLowerCase();
    const step = String(journal.step || '').trim().toLowerCase();
    // A recorded failure is the operator's actionable fact, so it outranks the phase.
    if (status === 'failed' || step === 'failed') return 'failed';
    return gigahostOrderStatusJournalPhase(step, status, journal.serverID);
}

/* gigahostOrderStatusJournalPhase resolves the phase from a journal's step and status.
 *
 * The step names the phase unambiguously, so it is read before the shared status
 * column: "ready" as a status with a mid-install step is still mid-install. A
 * registered panel server then means onboarding ran past registration, so the honest
 * reading of an unrecognised phase is "somewhere in the install", not "done". */
function gigahostOrderStatusJournalPhase(step, status, serverID) {
    const byStep = gigahostOrderStatusJournalStepStates[step];
    if (byStep) return byStep;
    if (status === 'ready' || step === 'ready') return 'ready';
    const byStatus = gigahostOrderStatusJournalSetupStates[status];
    if (byStatus) return byStatus;
    if (step) return 'installing';
    return serverID > 0 ? 'installing' : 'unknown';
}

/* gigahostOrderStatusHealthState maps the panel's own backend record to the health
 * axis. A server that is not a backend has no health to report, and a read that
 * has not happened is unknown rather than healthy. */
function gigahostOrderStatusHealthState(health) {
    if (!health || !health.known) return 'unknown';
    const backend = health.backend;
    if (!backend) return 'none';
    // A backend the operator switched off carries no runtime health to report.
    if (backend.enabled === false) return 'disabled';
    const status = String(backend.status || '').trim().toLowerCase();
    return gigahostOrderStatusHealthStates[status] || 'unknown';
}

/* gigahostOrderStatusNextAction names the one thing an operator can do next for
 * this state. It never names a step the current stage forbids, so a provider that
 * has not finished deploying is always "wait", whatever else is recorded - a queued
 * order's remaining action is likewise to wait, not to set up a VPS that does not
 * exist yet.
 *
 * The setup axis is only consulted once the provider side is settled, and an
 * unreadable setup or health axis yields no advice rather than a guess. */
function gigahostOrderStatusNextAction(model) {
    if (model.stage === 'unknown') return 'gigahost_status_next_action_check_provider';
    // A deployment the provider no longer has is over: there is no server to check, to
    // set up or to retry, and every action the view could name would contact a host the
    // panel has evidence is not the provider's.
    if (model.stage === 'cancelled' || model.stage === 'deleted') return 'gigahost_status_next_action_none';
    if (model.stage === 'requested' || model.stage === 'deploying') return 'gigahost_status_next_action_wait';
    if (model.stage === 'failed' || model.setup === 'failed') return 'gigahost_status_next_action_retry';
    return gigahostOrderStatusSettledNextAction(model);
}

/* gigahostOrderStatusSettledNextAction is the advice for a provider-ready order,
 * where the remaining question is whether setup and health are actually done.
 *
 * A setup axis that is already installed is never advised to install: an order whose
 * backend was installed by the immediate path has no saved approval, and telling the
 * operator to approve setup for it would be advice contradicted by the panel's own
 * journal. */
function gigahostOrderStatusSettledNextAction(model) {
    if (model.setup === 'needs_operator') return 'gigahost_status_next_action_resume';
    if (model.setup === 'none') return 'gigahost_status_next_action_approve_setup';
    if (model.setup !== 'ready') return 'gigahost_status_next_action_none';
    if (model.health === 'healthy') return 'gigahost_status_next_action_none';
    return 'gigahost_status_next_action_check_health';
}

/* gigahostOrderStatusText returns the first non-empty value as a string, or ''.
 * It exists so "the provider's answer, else the panel's copy" reads the same way at
 * every field instead of repeating a null guard that can drift per field. */
function gigahostOrderStatusText(...values) {
    for (const value of values) {
        if (value === null || value === undefined) continue;
        const text = String(value);
        if (text !== '') return text;
    }
    return '';
}

/* gigahostOrderStatusProviderFacts classifies the provider axis for one order.
 *
 * The order row is the panel's copy of the last provider answer and is served even
 * when the provider could not be reached, so a 200 from the list is not proof that
 * anyone was read. The list therefore also carries an observation per order, and that
 * observation is what decides whether this view may claim a provider state:
 *
 *   confirmed    the provider answered in this response; its spelling is the stage
 *   unconfirmed  a read returned nothing usable, so nothing may be claimed
 *   unavailable  the read failed; the row is a copy and cannot be called current
 *   not_checked  no read was attempted (terminal row)
 *
 * The deploy DTO's status is the onboarding journal vocabulary and never a provider
 * observation, so it is not consulted for the stage at all. The ledger row is used
 * only when the provider explicitly answered nothing about this order.
 */
function gigahostOrderStatusProviderFacts(order, deploy, observation) {
    const record = order || {};
    const detail = deploy || {};
    const orderId = String(record.order_id || '');
    const obs = gigahostOrderStatusObservation(observation);
    const journal = gigahostOrderStatusJournalEvidence(detail);
    // The row's own recorded step is journal evidence too, and it survives a failed detail
    // read. It is deliberately NOT folded into `journal` above: that value also decides
    // whether the provider axis is claimable at all, and a completed `ready` row carries a
    // step, so feeding it there would make a finished install read as unknown whenever the
    // second request failed. It is used only to answer the narrower failure question.
    const journalForFailure = gigahostOrderStatusRowJournalEvidence(record, detail);
    const claimed = gigahostOrderStatusClaimedProviderStatus(obs, journal, record.status);

    // providerAbsent is the panel's durable record that the provider's own server
    // inventory no longer lists the server this order registered. It arrives from the
    // order list response (the row itself, read from the column the reconciliation
    // writes) and, additively, from the order's deploy read. The list's copy is what
    // makes the stage independent of the deploy read: that request is a second one and
    // can fail, and a failure must not hand a deleted deployment back to the ordinary
    // treatment. This view never infers absence; it renders the record the panel made.
    //
    // It decides the stage on its own, and outranks both the provider's order spelling
    // and the ledger copy. These are different questions - whether the order was stopped
    // versus whether the VPS exists - and the operator asked the second one. A provider
    // that still reports the order as ready while its server inventory no longer lists
    // the server is exactly the state this exists to present as DELETED.
    const providerAbsent = record.provider_absent === true;
    // Two separate questions about a recorded failure, and answering them together is what
    // made an ended order actionable:
    //
    //   providerFinalFailure  the order ended at the provider before any panel setup work,
    //                         so there is no deployment to act on. Only the RECORDED
    //                         failure and the panel's own journal decide it - a provider
    //                         answer cannot invent an install that never ran. A confirmed
    //                         live answer does supersede it, because that is positive
    //                         evidence the deployment exists.
    //   recoverableFailure    the panel ran an install and it failed, so the operator has an
    //                         action that can succeed. Deriving this from the presented
    //                         stage was wrong: a provider that answers `ready` for a failed
    //                         install moves the stage to ready, and the Retry the operator
    //                         needs disappeared with it.
    const recordedFailure = gigahostOrderStatusProviderFinalFailure(record.status, journalForFailure);
    const providerConfirmsAlive = claimed.source === 'provider' &&
        gigahostOrderStatusFailedSpellings.indexOf(
            String(claimed.status || '').trim().toLowerCase()) === -1;
    const providerFinalFailure = recordedFailure && !providerConfirmsAlive;
    const recoverableFailure = gigahostOrderStatusFailedSpellings.indexOf(
        String(record.status || '').trim().toLowerCase()) !== -1 && !providerFinalFailure;
    const orderStage = claimed.unknown ? 'unknown' : gigahostOrderStatusPresentedStage(
        gigahostOrderStatusProviderStage(claimed.status || record.status));
    let stage = providerAbsent ? 'deleted' : (gigahostOrderStatusIsPlaceholderID(orderId) ? 'unknown' : orderStage);
    if (providerFinalFailure) stage = 'deleted';
    const assignedIP = gigahostOrderStatusText(detail.assigned_ip, record.assigned_ip);
    return {
        orderId: orderId,
        providerAbsent: providerAbsent,
        providerFinalFailure: providerFinalFailure,
        recoverableFailure: recoverableFailure,
        providerStatus: claimed.unknown ? '' : gigahostOrderStatusText(claimed.status, record.status),
        providerSource: claimed.source,
        // The provider was actually read in this response. This is the only thing that
        // may advance "last successful check".
        providerConfirmedRead: obs.outcome === 'confirmed',
        // The provider was asked and did not answer. The displayed rows are then a
        // copy, which is a stale view rather than a current one.
        providerReadFailed: obs.outcome === 'unavailable',
        providerUnknown: claimed.unknown,
        providerError: obs.error,
        // A provider that has not confirmed readiness has not handed over a usable
        // address, whatever the order row shows.
        addressWhileProvisioning: assignedIP !== '' && stage !== 'ready',
        assignedIP: assignedIP,
        stage: stage,
        step: gigahostOrderStatusText(detail.step, record.step),
        failure: gigahostOrderStatusText(detail.error, record.last_error),
        lastChangeAt: gigahostOrderStatusText(detail.updated_at, record.updated_at)
    };
}

/* gigahostOrderStatusClaimedProviderStatus decides which status this view may present
 * as the provider's, and where it came from.
 *
 * Only a confirmed observation may become a claimed provider stage. Failing that, a
 * durably recorded deletion is presented as the stage it is: the panel accepted and
 * persisted the provider's own ending, and the onboarding journal cannot produce that
 * spelling. A journal step is history - the immediate setup can journal `deploying`
 * before the provider finishes, and the status request keeps reporting that step after
 * the panel recorded the ending - so it must not outrank the record of how the
 * deployment ended, or an ordinary refresh undoes the ending and re-offers provisioning
 * for a server the panel has recorded as gone. A fresh affirmative inventory repair still
 * wins over it, because that repair rewrites the ledger it is read from here.
 *
 * For every other recorded status the journal still decides. The status column is written
 * by two vocabularies, so a non-deletion status may only be read as a provider state when
 * nothing contradicts it: positive journal evidence means this row's status is onboarding
 * execution (an install that failed after the provider was ready carries "failed" there),
 * so the provider axis becomes an explicit unknown rather than letting the setup outcome
 * wear the provider's name. A view that cannot read the provider says so; it does not
 * inherit somebody else's answer. */
function gigahostOrderStatusClaimedProviderStatus(obs, journal, recordedStatus) {
    if (obs.outcome === 'confirmed') {
        const status = gigahostOrderStatusText(obs.status);
        if (status) return {status: status, source: 'provider', unknown: false};
    }
    const recorded = gigahostOrderStatusText(recordedStatus).trim().toLowerCase();
    if (gigahostOrderStatusDeletedSpellings.indexOf(recorded) !== -1) {
        return {status: recorded, source: 'ledger', unknown: false};
    }
    if (journal.present) return {status: '', source: 'ledger', unknown: true};
    return {status: '', source: 'ledger', unknown: false};
}

/* gigahostOrderStatusObservation normalises the list's additive observation. A
 * response without the key (an older panel, or a caller that did not supply one) is
 * treated as unconfirmed, not as confirmed: an absent answer must never be read as a
 * successful provider check. */
function gigahostOrderStatusObservation(observation) {
    const raw = observation || {};
    const outcome = String(raw.outcome || '').trim();
    const known = gigahostOrderStatusObservationOutcomes.indexOf(outcome) !== -1;
    return {
        outcome: known ? outcome : 'unconfirmed',
        status: gigahostOrderStatusText(raw.status),
        error: gigahostOrderStatusText(raw.error)
    };
}

/* gigahostOrderStatusJournalEvidence reports whether the deploy DTO carries
 * onboarding-journal evidence for this order, and which phase it names.
 *
 * The journal is identified by a step or a registered panel server id, because those
 * are what only onboarding writes. The status column is shared with provider refreshes,
 * so it is reported for interpretation but never used on its own as proof that an
 * install was attempted. `failed` is accepted from the status column only when a step or
 * server id already established that onboarding ran. */
function gigahostOrderStatusJournalEvidence(deploy) {
    const detail = deploy || {};
    const status = String(detail.status || '').trim().toLowerCase();
    const step = String(detail.step || '').trim().toLowerCase();
    const serverID = Number(detail.server_id || 0);
    const ran = step !== '' || serverID > 0;
    return {
        present: ran,
        status: status,
        step: step,
        serverID: serverID
    };
}

/* gigahostOrderStatusRowJournalEvidence builds the onboarding-journal evidence for one
 * order from both places it can be recorded: the deploy DTO (the panel server id and step
 * the journal writes) and the order row the list already returned, whose own step column
 * survives a failed detail read.
 *
 * Reading only the DTO made a recoverable setup failure look provider-final whenever that
 * second request failed: the row still recorded `installing_protocol`, but the evidence
 * was gone, so the failure was classified as ended and its Retry disappeared for a job the
 * operator had run and could retry. */
function gigahostOrderStatusRowJournalEvidence(order, deploy) {
    const evidence = gigahostOrderStatusJournalEvidence(deploy);
    const rowStep = String((order || {}).step || '').trim().toLowerCase();
    if (!evidence.present && rowStep !== '') {
        return {
            present: true,
            status: evidence.status,
            step: rowStep,
            serverID: evidence.serverID
        };
    }
    return evidence;
}

/* gigahostOrderStatusProviderFinalFailure reports a recorded failure that no onboarding
 * journal accompanies: the provider ended provisioning before the panel did any setup
 * work, so there is no recoverable execution behind the word and nothing an operator
 * could retry onto it.
 *
 * It is the browser half of models.GigahostOrder.FailureIsProviderFinal, and it exists so
 * the classification does not depend on which surface is asking. The row's own status
 * column carries `failed` in two situations that look identical there - a provider that
 * never provisioned the VPS, and an install this panel ran and failed - and only the
 * journal distinguishes them. Treating both as recoverable was how an ended order kept
 * offering Retry and kept being polled for a deployment that was never created.
 *
 * `journal` is the evidence gigahostOrderStatusJournalEvidence returned for this row. */
function gigahostOrderStatusProviderFinalFailure(status, journal) {
    const s = String(status || '').trim().toLowerCase();
    if (gigahostOrderStatusFailedSpellings.indexOf(s) === -1) return false;
    return !(journal && journal.present);
}


/* gigahostOrderStatusRecordedOnboarding reports whether the deploy read carries the panel's
 * own durable evidence that onboarding completed: a registered Nexus server and the
 * completed step in the install journal.
 *
 * It deliberately does not read the provider's status spelling. `ready` and `active` are the
 * provider's words for a running VPS, and it may use either on identical reads, so a row
 * recognised by that word switched between "installed" and "not installed" while nothing
 * about the backend changed - which re-offered Setup Backend and Approve on a backend that
 * was already installed. The journal's completed step plus the panel server it registered is
 * the fact, and the provider cannot rename it. */
function gigahostOrderStatusRecordedOnboarding(deploy) {
    const detail = deploy || {};
    if (!(Number(detail.server_id || 0) > 0)) return false;
    return String(detail.step || '').trim().toLowerCase() === 'ready';
}


/* gigahostOrderStatusModel is the whole classification, and it is pure: the same
 * inputs always produce the same model, so the rendered view can be asserted
 * without a browser. context carries what the page already read:
 *   {deploy, detailOK, setup:{known,intent}, health:{known,backend}, checkedAt} */
function gigahostOrderStatusModel(order, context) {
    const ctx = context || {};
    const provider = gigahostOrderStatusProviderFacts(order, ctx.deploy, ctx.observation);
    const setup = ctx.setup || {known: false, intent: null, journal: null};
    const health = ctx.health || {known: false, backend: null};

    const model = {
        orderId: provider.orderId,
        stage: provider.stage,
        chain: gigahostOrderStatusStageChain(provider.stage),
        providerAbsent: provider.providerAbsent,
        providerStatus: provider.providerStatus,
        providerFinalFailure: provider.providerFinalFailure,
        recoverableFailure: provider.recoverableFailure,
        providerSource: provider.providerSource,
        providerConfirmed: provider.providerConfirmedRead,
        providerReadFailed: provider.providerReadFailed,
        providerUnknown: provider.providerUnknown,
        providerError: provider.providerError,
        detailOK: ctx.detailOK !== false,
        assignedIP: provider.assignedIP,
        addressWhileProvisioning: provider.addressWhileProvisioning,
        step: provider.step,
        failure: provider.failure,
        setup: gigahostOrderStatusSetupState(setup),
        setupIntent: setup.intent || null,
        health: gigahostOrderStatusHealthState(health),
        healthBackend: health.backend || null,
        lastCheckedAt: String(ctx.checkedAt || ''),
        lastChangeAt: provider.lastChangeAt
    };
    model.nextActionKey = gigahostOrderStatusNextAction(model);
    return model;
}


