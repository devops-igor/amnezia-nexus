package gigahostsetup

// Background tracking of administrator-approved Gigahost setup intents.
//
// Provisioning a VPS takes far longer than a browser session, so the progress
// cannot live in a request. This worker owns it: it reads the provider for each
// due intent, records what the provider actually said, and settles the intent
// into a state the operator can act on.
//
// Two boundaries are deliberately hard here:
//
//  1. The worker can only *read* from the provider. Its ProviderReader exposes
//     GetDeployStatus and GetServers and nothing else, so a purchase or a key
//     registration is not expressible from this package. Restarting the panel
//     can therefore never place a second order.
//  2. A provider read failure is not an answer. It is recorded as a failure
//     count and the intent stays pending; nothing here converts "we could not
//     ask" into "the provider failed".
//
// Installer effects are out of scope: ready_for_setup is a handoff, and no
// protocol installation, backend enablement or pool admission happens here.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/provider/gigahost"
)

// ProviderReader is the whole provider surface this worker may use. Both methods
// are reads; there is intentionally no way to order, cancel or register anything.
type ProviderReader interface {
	GetDeployStatus(ctx context.Context, orderID string) (*gigahost.DeployStatusResponse, error)
	GetServers(ctx context.Context) ([]gigahost.ServerInfo, error)
}

// Store is the persistence surface the worker needs. It is satisfied by
// *database.DB and narrowed here so the worker cannot issue its own SQL.
type Store interface {
	ListDueGigahostSetupIntents(ctx context.Context, now time.Time, limit int) ([]models.GigahostSetupIntent, error)
	TransitionGigahostSetupIntent(ctx context.Context, intent *models.GigahostSetupIntent, expectedStates []string) (bool, error)
	HasGigahostOrderCredential(ctx context.Context, orderID string) (bool, error)
	GetAllServers(ctx context.Context) ([]models.Server, error)
	GetKnownHostFingerprint(ctx context.Context, serverID int64) (string, error)
}

// ErrProviderUnavailable reports that no provider client could be built for this
// pass. It is a scheduling condition, never a statement about the intent.
var ErrProviderUnavailable = errors.New("gigahost provider client is not configured")

// Defaults are bounded so a forgotten intent cannot grow into an unbounded
// provider poll. They are fields rather than constants because the tests drive
// scheduling through a fake clock.
const (
	DefaultInterval       = 30 * time.Second
	DefaultFailureBackoff = 30 * time.Second
	DefaultMaxBackoff     = 5 * time.Minute
	DefaultBatch          = 20
	defaultCallTimeout    = 30 * time.Second
)

// Options configure a Tracker. Every field has a safe default.
type Options struct {
	// Resolve returns the provider reader for this pass. It is called per pass,
	// not once, so a key configured after startup is picked up without a restart.
	Resolve func(ctx context.Context) (ProviderReader, error)
	// ChallengeHost performs the read-only first-contact identity challenge for
	// an approval that has no confirmed identity yet, and reports the identity
	// the address actually presented. It must not authenticate, run a command,
	// bind anything or authorize the job: it only answers "which key is there",
	// so an administrator can be shown an exact value to confirm. It is nil when
	// no such challenge can be built, in which case the intent keeps pausing for
	// an identity the administrator supplies out of band.
	ChallengeHost func(ctx context.Context, intent models.GigahostSetupIntent) (string, error)
	// FirstContactEligible answers whether a job carrying the automation host
	// trust policy may pin the identity its own challenge observed. Nil means this
	// panel cannot answer, and every such job keeps the manual confirmation pause.
	FirstContactEligible FirstContactEligibility
	// Pinner records the observed identity as durable trust. Nil means automatic
	// trust is not available here, which is a supported configuration: the manual
	// path needs no pin.
	Pinner FirstContactPinner
	// AutomaticEffectAllowed reports whether the current unattended-setup policy
	// still permits a job carrying automation provenance to produce an effect. Nil
	// means this process cannot answer, and such a job is refused rather than
	// assumed enabled. It is consulted at the pin and before each phase, not once
	// per job, because the setting can change while a job runs.
	AutomaticEffectAllowed AutomaticEffectAllowed
	// Now is the clock. The zero value means time.Now; tests inject a fake and
	// advance it, which is how a >60 minute progress window is exercised without
	// a literal wait.
	Now         func() time.Time
	Interval    time.Duration
	FailureBack time.Duration
	MaxBackoff  time.Duration
	Batch       int
	CallTimeout time.Duration
}

// Tracker drives pending setup intents to a settled state.
type Tracker struct {
	store     Store
	resolve   func(ctx context.Context) (ProviderReader, error)
	challenge func(ctx context.Context, intent models.GigahostSetupIntent) (string, error)
	eligible  FirstContactEligibility
	pinner    FirstContactPinner
	// effectAllowed is the current unattended-setup permission, asked at each
	// effect boundary rather than cached.
	effectAllowed AutomaticEffectAllowed
	now           func() time.Time
	nudgeCh       chan struct{}

	interval    time.Duration
	failureBack time.Duration
	maxBackoff  time.Duration
	batch       int
	callTimeout time.Duration

	running     atomic.Bool
	lifecycleMu sync.Mutex
	cancel      context.CancelFunc
	stopped     chan struct{}
}

// New builds a Tracker over the store, applying defaults to unset options.
func New(store Store, opts Options) *Tracker {
	t := &Tracker{
		store:         store,
		resolve:       opts.Resolve,
		challenge:     opts.ChallengeHost,
		eligible:      opts.FirstContactEligible,
		pinner:        opts.Pinner,
		effectAllowed: opts.AutomaticEffectAllowed,
		now:           opts.Now,
		nudgeCh:       make(chan struct{}, 1),
		interval:      opts.Interval,
		failureBack:   opts.FailureBack,
		maxBackoff:    opts.MaxBackoff,
		batch:         opts.Batch,
		callTimeout:   opts.CallTimeout,
	}
	if t.now == nil {
		t.now = func() time.Time { return time.Now().UTC() }
	}
	if t.interval <= 0 {
		t.interval = DefaultInterval
	}
	if t.failureBack <= 0 {
		t.failureBack = DefaultFailureBackoff
	}
	if t.maxBackoff <= 0 {
		t.maxBackoff = DefaultMaxBackoff
	}
	if t.batch <= 0 {
		t.batch = DefaultBatch
	}
	if t.callTimeout <= 0 {
		t.callTimeout = defaultCallTimeout
	}
	return t
}

// Name identifies the worker to the supervisor.
func (t *Tracker) Name() string { return "gigahost-setup-tracker" }

// Start runs the tracking loop until the context ends.
//
// It is a supervisor BackgroundService, so the panel's normal startup and
// shutdown own it: closing a browser has no effect, and a panel restart resumes
// the same saved intents from the database.
func (t *Tracker) Start(ctx context.Context) error {
	if !t.running.CompareAndSwap(false, true) {
		return errors.New("gigahost setup tracker is already running")
	}
	subCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	t.lifecycleMu.Lock()
	t.cancel = cancel
	t.stopped = stopped
	t.lifecycleMu.Unlock()

	defer func() {
		cancel()
		t.lifecycleMu.Lock()
		t.cancel = nil
		t.stopped = nil
		t.lifecycleMu.Unlock()
		t.running.Store(false)
		close(stopped)
	}()

	slog.Info("Gigahost setup tracker started", "interval", t.interval.String())
	for {
		if err := t.RunOnce(subCtx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("Gigahost setup tracker pass failed", "err", err)
		}
		if !t.waitNext(subCtx) {
			slog.Info("Gigahost setup tracker stopped cleanly")
			return nil
		}
	}
}

// Nudge asks a running tracker to run a pass now instead of waiting out its
// interval. It never blocks: a nudge that arrives while one is already pending is
// the same request twice, and the interval sweep covers a dropped hint.
func (t *Tracker) Nudge() {
	select {
	case t.nudgeCh <- struct{}{}:
	default:
	}
}

// waitNext blocks until the interval elapses, a nudge arrives, or the context
// ends. It reports whether the tracker should keep running.
func (t *Tracker) waitNext(ctx context.Context) bool {
	timer := time.NewTimer(t.interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.nudgeCh:
		return true
	case <-timer.C:
		return true
	}
}

// Stop asks a running tracker to finish and waits for it to exit, or for the
// caller's deadline.
func (t *Tracker) Stop(ctx context.Context) error {
	t.lifecycleMu.Lock()
	cancel := t.cancel
	stopped := t.stopped
	t.lifecycleMu.Unlock()
	if cancel == nil || stopped == nil {
		return nil
	}
	cancel()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopped:
		return nil
	}
}

// RunOnce performs one scheduling pass over the intents that are due.
//
// It is the whole production pass and the unit the tests drive with a fake
// clock, so a long progress window is proven by advancing virtual time rather
// than by sleeping.
func (t *Tracker) RunOnce(ctx context.Context) error {
	if t.store == nil {
		return errors.New("gigahost setup tracker has no store")
	}
	now := t.now()
	due, err := t.store.ListDueGigahostSetupIntents(ctx, now, t.batch)
	if err != nil {
		return fmt.Errorf("failed to list due setup intents: %w", err)
	}
	if len(due) == 0 {
		return nil
	}
	reader, resolveErr := t.resolveReader(ctx)

	var passErr error
	for i := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if resolveErr != nil {
			// Without a provider we cannot ask. Record the failure so the
			// operator sees why nothing moved, and leave the intent pending.
			t.recordReadFailure(ctx, &due[i], providerReadFailure(resolveErr))
			continue
		}
		if err := t.observe(ctx, reader, &due[i]); err != nil {
			passErr = err
		}
	}
	return passErr
}

// resolveReader builds the provider reader once per pass.
func (t *Tracker) resolveReader(ctx context.Context) (ProviderReader, error) {
	if t.resolve == nil {
		return nil, ErrProviderUnavailable
	}
	return t.resolve(ctx)
}

// observe performs one provider read for one intent and records the outcome.
func (t *Tracker) observe(ctx context.Context, reader ProviderReader, intent *models.GigahostSetupIntent) error {
	if intent.IsCanceled() {
		// Revoked approvals must not produce effects. The CAS transition below
		// is the real guard; this is the cheap early exit.
		return nil
	}
	callCtx, cancel := context.WithTimeout(ctx, t.callTimeout)
	defer cancel()

	status, err := reader.GetDeployStatus(callCtx, intent.OrderID)
	if err != nil {
		t.recordReadFailure(ctx, intent, providerReadFailure(err))
		return nil
	}
	return t.recordProviderStatus(ctx, reader, intent, status)
}

// Step names recorded on a row whose pass could not obtain an answer.
const (
	stepProviderUnreadable = "provider_unreadable"
	stepHostUnreachable    = "host_identity_unreachable"
	// stepHostTrustUnavailable names a job whose host answered with an identity the
	// panel could not record. It is separate from unreachable because the operator's
	// next action differs: the host is there and the trust write is the problem.
	stepHostTrustUnavailable = "host_trust_unavailable"
)

// readFailure is one "could not ask" outcome: the step it is recorded under and
// the bounded reason an operator reads. Both are carried together so no caller
// can record a reason under a step that describes a different question.
type readFailure struct {
	step    string
	message string
}

// providerReadFailure reports that the provider could not be asked about the
// order. Nothing is known about the VPS, so no state transition may claim
// otherwise.
func providerReadFailure(err error) readFailure {
	return readFailure{step: stepProviderUnreadable, message: summarizeReadFailure(err)}
}

// hostChallengeFailure reports that the read-only first-contact challenge could
// not obtain an identity.
//
// This is the same category as an unreadable provider: a temporary condition
// rather than an answer, so it is recorded with the same growing backoff. The job
// keeps its place in the scheduled pass and asks again later; the identity stays
// unconfirmed and nothing is displayed to confirm. Settling it would be the
// defect, because a settled row produces no further provider read and none of the
// shipped actions can restore it.
func hostChallengeFailure(err error) readFailure {
	return readFailure{
		step:    stepHostUnreachable,
		message: "the host identity challenge did not complete: " + summarizeCause(err),
	}
}

// recordReadFailure keeps the intent pending and backs the next attempt off.
//
// This is the "could not ask" case: no answer arrived, so nothing is known about
// the VPS and no state transition may claim otherwise. Keeping the row pending
// with a due time is what makes a later scheduled pass retry the same question on
// the same approval, instead of settling a temporary condition into a state nobody
// can act on. The delay grows with consecutive failures and is capped, so a
// persistent outage is retried without becoming a poll loop.
func (t *Tracker) recordReadFailure(ctx context.Context, intent *models.GigahostSetupIntent, failure readFailure) {
	if intent == nil {
		return
	}
	failures := intent.ReadFailures + 1
	next := intent
	next.ReadFailures = failures
	next.Attempts = intent.Attempts + 1
	next.LastCheckedAt = t.now()
	next.NextAttemptAt = t.now().Add(t.backoffFor(failures))
	next.Step = failure.step
	next.LastError = failure.message
	next.State = models.SetupStatePending

	if _, err := t.store.TransitionGigahostSetupIntent(ctx, next, []string{models.SetupStatePending}); err != nil {
		slog.Warn("Failed to record setup intent read failure", "order_id", intent.OrderID, "err", err)
	}
}

// backoffFor grows the retry interval with consecutive failures, capped so a
// persistent outage is retried but never in a tight loop.
func (t *Tracker) backoffFor(failures int) time.Duration {
	d := t.failureBack
	for i := 1; i < failures && d < t.maxBackoff; i++ {
		d *= 2
	}
	if d > t.maxBackoff {
		d = t.maxBackoff
	}
	return d
}

// recordProviderStatus applies a real provider answer.
//
// ReadFailures is deliberately NOT reset here. The provider answered, but the pass
// may still stop on a gate that could not obtain its own answer (a first-contact
// challenge against a host that is still booting). Resetting the counter at the
// provider boundary would make those consecutive failures indistinguishable from
// the first one, and the backoff would stay flat for a job whose host keeps
// refusing. The counter is cleared where a pass actually decided something: the
// provisioning branch below and settleProvisioned.
func (t *Tracker) recordProviderStatus(
	ctx context.Context,
	reader ProviderReader,
	intent *models.GigahostSetupIntent,
	status *gigahost.DeployStatusResponse,
) error {
	next := *intent
	next.Attempts = intent.Attempts + 1
	next.LastCheckedAt = t.now()
	next.LastError = ""

	if status != nil {
		next.ProviderStatus = strings.TrimSpace(status.Status)
		next.AssignedIP, next.ProviderServerID = mergedIdentity(status, next.AssignedIP, next.ProviderServerID)
	} else {
		// A nil status with no error means the provider answered nothing about
		// this order. It is not progress and not a failure.
		next.ProviderStatus = gigahost.StatusUnknown
	}

	switch {
	case isProviderFailed(next.ProviderStatus):
		return t.settle(ctx, &next, models.SetupStateFailed, "provider_failed", providerFailureDetail(status))
	case !isProviderReady(next.ProviderStatus):
		next.ReadFailures = 0
		next.State = models.SetupStatePending
		next.Step = "provisioning"
		next.NextAttemptAt = t.now().Add(t.interval)
		return t.persist(ctx, &next)
	}
	return t.settleProvisioned(ctx, reader, &next)
}

// handoffDecision is the single outcome of one tracking pass over a provisioned
// server. Gates return a decision instead of writing, so a pass performs exactly
// one durable write and a pause can never fall through into the ready path.
type handoffDecision struct {
	state  string
	step   string
	detail string
	// candidate is the host identity this pass observed on a read-only
	// first-contact challenge. It is recorded so the administrator is shown the
	// exact value to confirm, and it authorizes nothing: the pause it accompanies
	// still requires an explicit confirmation. Nil means this pass made no
	// observation and the stored value stands; a non-nil empty string means the
	// challenge ran and produced no identity, so a stale value must not survive.
	candidate *string
	// readFailure marks a gate that could not obtain an answer. It keeps the
	// intent pending with a backed-off retry rather than claiming anything.
	readFailure bool
	cause       readFailure
}

// settleProvisioned decides the handoff state for a server the provider says is
// ready. Every check is fail-closed and ordered from identity outward, and the
// result is written once.
func (t *Tracker) settleProvisioned(
	ctx context.Context,
	reader ProviderReader,
	intent *models.GigahostSetupIntent,
) error {
	decision := t.decideHandoff(ctx, reader, intent)
	// A pass that observed the address and got no identity clears the displayed
	// candidate before anything else is decided, so a stale value cannot stay
	// confirmable. This applies to the retryable case as well as to a clean pause.
	if decision.candidate != nil {
		intent.HostCandidateFingerprint = *decision.candidate
	}
	if decision.readFailure {
		t.recordReadFailure(ctx, intent, decision.cause)
		return nil
	}
	// The pass reached a real decision, so any prior unanswered gate is over and
	// the next failure starts a fresh backoff.
	intent.ReadFailures = 0
	return t.settle(ctx, intent, decision.state, decision.step, decision.detail)
}

// decideHandoff evaluates the handoff preconditions in order and returns the
// first one that decides. It performs no writes.
func (t *Tracker) decideHandoff(
	ctx context.Context,
	reader ProviderReader,
	intent *models.GigahostSetupIntent,
) handoffDecision {
	if intent.ProviderServerID <= 0 {
		return handoffDecision{
			state: models.SetupStateFailed, step: "provider_failed",
			detail: "provider reported ready without a server id",
		}
	}
	if intent.AssignedIP == "" {
		return handoffDecision{
			state: models.SetupStateFailed, step: "provider_failed",
			detail: "provider reported ready without a public IP",
		}
	}

	// 1. The provider's own server list is the authority on which order a server
	// belongs to. A server id that belongs to a different order is a wrong or
	// stale association and must not be adopted.
	assoc, err := t.checkAssociation(ctx, reader, intent)
	if err != nil {
		return handoffDecision{readFailure: true, cause: providerReadFailure(err)}
	}
	if assoc != "" {
		return handoffDecision{
			state: models.SetupStateFailed, step: "association_mismatch", detail: assoc,
		}
	}

	// 2. A usable credential reference must exist before setup can log in.
	if decision, ok := t.decideCredential(ctx, intent); ok {
		return decision
	}

	// 3. Host identity must be settled: either already bound to a registered
	// server, or explicitly confirmed by this approval.
	return t.decideHostTrust(ctx, intent)
}

// checkAssociation reports a non-empty reason when the provider server id does
// not belong to this order. An unreadable server list is an error, not consent.
func (t *Tracker) checkAssociation(ctx context.Context, reader ProviderReader, intent *models.GigahostSetupIntent) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, t.callTimeout)
	defer cancel()
	servers, err := reader.GetServers(callCtx)
	if err != nil {
		return "", fmt.Errorf("failed to read provider servers: %w", err)
	}
	for _, s := range servers {
		if s.ID != intent.ProviderServerID {
			continue
		}
		if s.OrderID != "" && s.OrderID != intent.OrderID {
			return fmt.Sprintf("provider server %d belongs to order %q, not %q",
				s.ID, s.OrderID, intent.OrderID), nil
		}
		return "", nil
	}
	// The server list is not required to include the new server; absence means
	// the deploy status is the only evidence, which the caller already accepted.
	return "", nil
}

// decideCredential reports a pause when no usable credential reference exists.
func (t *Tracker) decideCredential(ctx context.Context, intent *models.GigahostSetupIntent) (handoffDecision, bool) {
	if intent.CredentialMode == models.SetupCredentialManual {
		return handoffDecision{
			state: models.SetupStateAwaitingCredentials, step: "awaiting_credentials",
		}, true
	}
	has, err := t.store.HasGigahostOrderCredential(ctx, intent.OrderID)
	if err != nil {
		return handoffDecision{readFailure: true, cause: providerReadFailure(err)}, true
	}
	if !has {
		return handoffDecision{
			state: models.SetupStateAwaitingCredentials, step: "awaiting_credentials",
		}, true
	}
	return handoffDecision{}, false
}

// decideHostTrust reports a pause when the SSH host identity is not settled.
//
// The unconfirmed case is the one a fresh managed order always hits, so it is
// also the one that must stay actionable: the pause names the exact identity the
// address presented on a read-only first-contact challenge, and confirmation of
// that value is still required. Discovery authorizes nothing on its own.
func (t *Tracker) decideHostTrust(ctx context.Context, intent *models.GigahostSetupIntent) handoffDecision {
	serverID, err := t.registeredServerID(ctx, intent.ProviderServerID)
	if err != nil {
		return handoffDecision{readFailure: true, cause: providerReadFailure(err)}
	}
	confirmed := strings.TrimSpace(intent.HostFingerprint)

	if serverID == 0 {
		// Nothing registered yet, so the only acceptable identity is the one the
		// administrator confirmed in this approval.
		if confirmed == "" {
			return t.discoverHostIdentity(ctx, intent)
		}
		return handoffDecision{state: models.SetupStateReadyForSetup, step: "ready_for_setup"}
	}

	bound, err := t.store.GetKnownHostFingerprint(ctx, serverID)
	if err != nil {
		return handoffDecision{readFailure: true, cause: providerReadFailure(err)}
	}
	if bound == "" {
		if confirmed == "" {
			return t.discoverHostIdentity(ctx, intent)
		}
		return handoffDecision{state: models.SetupStateReadyForSetup, step: "ready_for_setup"}
	}
	if confirmed != "" && confirmed != bound {
		// The identity the administrator approved contradicts the identity this
		// server is already bound to. Trust pauses; nothing is rewritten.
		intent.HostMismatch = true
		return handoffDecision{
			state: models.SetupStateAwaitingHostConfirm, step: "host_identity_changed",
			detail: "confirmed host identity does not match the identity already bound to this server",
		}
	}
	return handoffDecision{state: models.SetupStateReadyForSetup, step: "ready_for_setup"}
}

// discoverHostIdentity asks the address which host key it presents.
//
// The challenge is a handshake that stops at host-key verification: it sends no
// credential, runs no command, binds nothing and does not authorize the job. Its
// only product is the exact value an administrator can be shown and confirm, or -
// when the job carries durable automation authority and the ownership question
// answers yes - the exact value the panel may pin itself.
//
// Three outcomes are possible:
//
//   - the challenge answered and this job may pin it (see decideObservedIdentity).
//     The observed identity becomes the durable trusted one and the handoff
//     continues with no confirmation step;
//   - the challenge answered and this job may not pin it. The value becomes a
//     displayed candidate and the row pauses for confirmation. Nothing is
//     confirmed on the administrator's behalf;
//   - the challenge could not run. That is a temporary condition and is reported
//     as a read failure, so the same approval retries on a later pass. The pause
//     is not written: a settled pause produces no further provider read, which
//     would leave the job with nothing to confirm and nothing to act on.
//
// A row for which no challenge is expressible (no challenge wired, no address, no
// provider server id) keeps the original pause, where the administrator supplies
// the identity out of band.
func (t *Tracker) discoverHostIdentity(ctx context.Context, intent *models.GigahostSetupIntent) handoffDecision {
	decision := handoffDecision{
		state: models.SetupStateAwaitingHostConfirm, step: "awaiting_host_confirmation",
	}
	if t.challenge == nil || strings.TrimSpace(intent.AssignedIP) == "" ||
		intent.ProviderServerID <= 0 {
		// No challenge is expressible for this row: the pause stands and the
		// admin supplies the identity out of band, exactly as before.
		return decision
	}
	callCtx, cancel := context.WithTimeout(ctx, t.callTimeout)
	defer cancel()
	fingerprint, err := t.challenge(callCtx, *intent)
	if err != nil {
		// Retryable, not settled. An identity displayed by an earlier pass is
		// still cleared: the address did not present it this time, so it must not
		// stay confirmable.
		empty := ""
		return handoffDecision{
			readFailure: true,
			cause:       hostChallengeFailure(err),
			candidate:   &empty,
		}
	}
	trimmed := strings.TrimSpace(fingerprint)
	decision.candidate = &trimmed
	return t.decideObservedIdentity(ctx, intent, decision, trimmed)
}

// decideObservedIdentity decides what a successful challenge means for this job.
//
// The observed value and the eligibility answer are both required, and a job that
// cannot pin is left exactly as it was: the candidate stays displayed and the row
// pauses. That is the whole manual behavior, unchanged, and it is also the reason
// an ineligible job records a reason instead of failing.
func (t *Tracker) decideObservedIdentity(
	ctx context.Context,
	intent *models.GigahostSetupIntent,
	manual handoffDecision,
	fingerprint string,
) handoffDecision {
	if err := models.ValidateHostFingerprint(fingerprint); err != nil {
		// The challenge returned something this panel cannot store or compare. The
		// value is still shown, and a person decides; automatic trust must never
		// be built on a value that cannot be re-verified.
		return manual
	}
	pinnable, reason := t.firstContactEligible(ctx, *intent)
	if !pinnable {
		if reason != "" {
			manual.detail = reason
		}
		return manual
	}
	return t.pinFirstContactIdentity(ctx, *intent, fingerprint)
}

// settle writes a terminal state with no further scheduling.
func (t *Tracker) settle(
	ctx context.Context,
	intent *models.GigahostSetupIntent,
	state, step, detail string,
) error {
	intent.State = state
	intent.Step = step
	intent.NextAttemptAt = time.Time{}
	if detail != "" {
		intent.LastError = detail
	}
	return t.persist(ctx, intent)
}

// persist writes the intent, losing to any concurrent cancellation.
func (t *Tracker) persist(ctx context.Context, intent *models.GigahostSetupIntent) error {
	changed, err := t.store.TransitionGigahostSetupIntent(ctx, intent, []string{models.SetupStatePending})
	if err != nil {
		return fmt.Errorf("failed to persist setup intent %s: %w", intent.OrderID, err)
	}
	if !changed {
		// The row left pending while this read was in flight: an administrator
		// revoked the approval, or another pass settled it. Neither is an error,
		// and the write above was correctly refused.
		slog.Info("Setup intent changed during tracking; commit refused",
			"order_id", intent.OrderID, "attempted_state", intent.State)
	}
	return nil
}

// registeredServerID returns the panel server id registered for a provider
// server id, or 0 when none is.
func (t *Tracker) registeredServerID(ctx context.Context, providerServerID int64) (int64, error) {
	if providerServerID <= 0 {
		return 0, nil
	}
	servers, err := t.store.GetAllServers(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to read registered servers: %w", err)
	}
	for _, s := range servers {
		if s.Protocols == nil {
			continue
		}
		if p, ok := s.Protocols["provider"].(string); !ok || !strings.EqualFold(p, "gigahost") {
			continue
		}
		if matchesProviderServerID(s.Protocols["provider_server_id"], providerServerID) {
			return s.ID, nil
		}
	}
	return 0, nil
}

// matchesProviderServerID compares a stored protocols value against a provider
// server id. The stored value survives a JSON round trip, so several numeric
// shapes are legitimate.
func matchesProviderServerID(stored any, want int64) bool {
	switch v := stored.(type) {
	case int64:
		return v == want
	case int:
		return int64(v) == want
	case float64:
		return int64(v) == want
	case string:
		return strings.TrimSpace(v) == fmt.Sprintf("%d", want)
	default:
		return false
	}
}

// mergedIdentity keeps the strongest identity known so far. A later read that
// omits a value must not erase what an earlier answer established.
func mergedIdentity(status *gigahost.DeployStatusResponse, ip string, serverID int64) (string, int64) {
	if status == nil {
		return ip, serverID
	}
	if candidate := strings.TrimSpace(status.GetIP()); candidate != "" {
		ip = candidate
	}
	if status.ServerID > 0 {
		serverID = status.ServerID
	}
	return ip, serverID
}

// isProviderReady and isProviderFailed are the tracker's reading of provider
// vocabulary. They mirror the existing handler helpers rather than re-defining a
// second, drifting set: the tracker must agree with setup about what "ready"
// means.
func isProviderReady(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	return s == gigahost.StatusReady || s == "active"
}

func isProviderFailed(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	switch s {
	// Both spellings of the provider's terminal "cancelled" status are matched
	// literally: the API uses one in some fields and the other in others, and
	// missing either would leave a cancelled VPS reported as provisioning.
	//nolint:misspell // provider status vocabulary, matched literally
	case gigahost.StatusFailed, "error", "cancelled", "canceled", "deleted":
		return true
	default:
		return false
	}
}

// providerFailureDetail returns the provider's own diagnostic when it gave one.
func providerFailureDetail(status *gigahost.DeployStatusResponse) string {
	if status == nil {
		return ""
	}
	return strings.TrimSpace(status.Error)
}

// summarizeReadFailure renders a bounded single-line reason for an unreadable
// provider. It quotes only the error's own text.
func summarizeReadFailure(err error) string {
	if err == nil {
		return ""
	}
	return "could not read provider status: " + summarizeCause(err)
}

// summarizeCause renders an error as one bounded line. Collapsing whitespace is
// what keeps a multi-line transport error from becoming several diagnoses, and the
// limit keeps the stored reason readable.
func summarizeCause(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.Join(strings.Fields(err.Error()), " ")
	const limit = 240
	if len(msg) > limit {
		msg = msg[:limit] + "..."
	}
	return msg
}
