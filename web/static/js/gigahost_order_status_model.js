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
const gigahostOrderStatusCancelledSpellings = ['cancelled', 'canceled', 'deleted'];

// gigahostOrderStatusStages are the provider stages an order passes through, in order.
// VPN setup and backend health are separate axes, never drawn as stages.
const gigahostOrderStatusStages = ['requested', 'deploying', 'ready'];

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

/* gigahostOrderStatusProviderStage maps a provider/ledger status spelling to one
 * stage. It reads no address: a VPS is ready only when the provider said so. */
function gigahostOrderStatusProviderStage(status) {
    const s = String(status || '').trim().toLowerCase();
    if (gigahostOrderStatusReadySpellings.indexOf(s) !== -1) return 'ready';
    if (gigahostOrderStatusFailedSpellings.indexOf(s) !== -1) return 'failed';
    if (gigahostOrderStatusCancelledSpellings.indexOf(s) !== -1) return 'cancelled';
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
    if (stage === 'failed' || stage === 'cancelled' || stage === 'unknown') {
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
 * has not finished deploying is always "wait", whatever else is recorded.
 *
 * The setup axis is only consulted once the provider side is settled, and an
 * unreadable setup or health axis yields no advice rather than a guess. */
function gigahostOrderStatusNextAction(model) {
    if (model.stage === 'unknown') return 'gigahost_status_next_action_check_provider';
    if (model.stage === 'cancelled') return 'gigahost_status_next_action_none';
    if (model.stage === 'deploying') return 'gigahost_status_next_action_wait';
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
    const claimed = gigahostOrderStatusClaimedProviderStatus(obs, journal);

    const orderStage = claimed.unknown ? 'unknown' : gigahostOrderStatusProviderStage(claimed.status || record.status);
    const stage = gigahostOrderStatusIsPlaceholderID(orderId) ? 'unknown' : orderStage;
    const assignedIP = gigahostOrderStatusText(detail.assigned_ip, record.assigned_ip);
    return {
        orderId: orderId,
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
 * Only a confirmed observation may become a claimed provider stage. Failing that, the
 * order row is the panel's copy - but the status column is written by two vocabularies,
 * so it may only be read as a provider state when nothing contradicts it. Positive
 * journal evidence means this row's status is onboarding execution (an install that
 * failed after the provider was ready carries "failed" there), so the provider axis
 * becomes an explicit unknown rather than letting the setup outcome wear the provider's
 * name. A view that cannot read the provider says so; it does not inherit somebody
 * else's answer. */
function gigahostOrderStatusClaimedProviderStatus(obs, journal) {
    if (obs.outcome === 'confirmed') {
        const status = gigahostOrderStatusText(obs.status);
        if (status) return {status: status, source: 'provider', unknown: false};
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
        providerStatus: provider.providerStatus,
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


