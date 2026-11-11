package gigahostsetup

// Automatic first-contact host trust.
//
// The manual path discovers which host key the address presents and then pauses so
// an administrator can confirm that exact value. This file adds the one other
// supported outcome: when the job carries durable automation authority and every
// ownership fact agrees, the panel pins the identity it observed itself and the job
// continues without a person in the loop.
//
// What it deliberately does not do:
//
//   - it does not authenticate. The pin is recorded from the read-only challenge,
//     which stops at host-key verification, so nothing is sent to the host before
//     the identity is durable.
//   - it does not broaden its own authority. The policy that permits a pin is
//     durable state written by an internal caller, never a value this pass derives
//     from the provider answer or from a request.
//   - it does not fall back to trusting anything. An ineligible row keeps the
//     existing discovery pause, so the administrator path is unchanged and still
//     available.

import (
	"context"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// FirstContactPinner records the identity a first-contact challenge observed.
//
// It is an interface at the consumer rather than a wider Store method for two
// reasons: the tracker already depends only on the narrow surface it uses, and the
// pin must be expressible as its own statement rather than as another
// snapshot-based transition. A nil pinner means this deployment cannot pin
// automatically, which keeps the manual pause and is not an error.
type FirstContactPinner interface {
	PinGigahostSetupFirstContact(ctx context.Context, orderID, fingerprint string) (string, error)
}

// FirstContactEligibility answers the whole ownership question for one job.
//
// It is injected rather than implemented here because the answer depends on the
// order ledger, the managed credential and the provider association, which this
// package deliberately cannot read. It returns true only when every fact holds;
// the reason it returns otherwise is recorded for the operator.
type FirstContactEligibility func(ctx context.Context, intent models.GigahostSetupIntent) (bool, string)

// AutomaticEffectAllowed answers whether the current unattended-setup policy still
// permits this job to produce an effect.
//
// It exists separately from FirstContactEligibility because the two questions have
// different lifetimes. Ownership is a fact about a resource and cannot change while a
// job runs; permission is a setting that a person may have turned off since the job was
// created, so it has to be asked again at the moment of the effect. Nil means this
// process cannot answer, and the effect is refused: a panel that cannot say whether
// unattended setup is enabled has not said that it is.
//
// It is only consulted for jobs that carry automation provenance. A manual job was
// approved by a person and is not subject to an unattended-setup setting.
type AutomaticEffectAllowed func(ctx context.Context, intent models.GigahostSetupIntent) (bool, string)

// AutomaticBindingGrantor acquires the scoped automation authority for a job that
// carries the policy but no binding yet.
//
// It is the one place authority is issued unattended, so it is injected rather than
// implemented here: the proof depends on the order ledger, the managed credential and
// the provider's association, none of which this package can read. It returns the
// current row so the pass continues from what is actually stored - a grant that did not
// apply is answered with the real state, not with an optimistic copy.
//
// Nil means no grant can be issued here, which is a supported configuration: the job
// simply stays inert, which is the C1 behavior.
type AutomaticBindingGrantor func(
	ctx context.Context, intent models.GigahostSetupIntent, reader ProviderReader,
) (models.GigahostSetupIntent, error)

// stepHostTrustedFirstContact is the recorded step of a job that trusted its own
// first observation. It is the durable evidence that no person confirmed this
// identity, which is what the confirmation path refuses to overwrite.
const stepHostTrustedFirstContact = "host_trusted_first_contact"

// stepAutomaticDisabled names a job that stopped because unattended setup is no
// longer enabled. It is separate from the trust and reachability steps because the
// operator's next action is different: nothing is wrong with the host, and the panel
// deliberately did not act.
const stepAutomaticDisabled = "automatic_setup_disabled"

// stepAutomaticUnavailable names a job that could not acquire its authority because the
// current policy does not permit it. It is separate from the pin-time step because the
// operator question is different: nothing was granted, so nothing about the host is
// involved yet.
const stepAutomaticUnavailable = "automatic_setup_unavailable"

// stepAutomaticGrantUnproven names a job whose scoped authority could not be established
// from the provider and ledger facts on this pass. It is retryable: the provider may not
// have published the association yet, and a purchase that is still provisioning is the
// normal case rather than a fault.
const stepAutomaticGrantUnproven = "automatic_grant_unproven"

// firstContactEligible asks the injected ownership check whether this job may trust
// its own first observation.
//
// The policy is checked first and locally, so a manual row (the default, and every
// row created before this existed) never reaches the injected check and never
// acquires a new recorded reason. A tracker with no check wired cannot answer the
// ownership question, and "cannot ask" is not "yes".
func (t *Tracker) firstContactEligible(
	ctx context.Context, intent models.GigahostSetupIntent,
) (bool, string) {
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		return false, ""
	}
	if t.eligible == nil {
		return false, "this panel has no configured ownership check for automatic host trust"
	}
	ok, reason := t.eligible(ctx, intent)
	return ok, strings.TrimSpace(reason)
}

// automaticEffectAllowed asks the current policy whether this job may still produce an
// effect, defaulting to refusal when nothing is wired.
//
// A manual job is answered yes without consulting anything: it was approved by a
// person, and an unattended-setup setting has no authority over it. The automation
// provenance is the recorded trust policy alone, because that is the only field a
// worker or a confirmation cannot rewrite - a job whose identity is already pinned, or
// whose phase journal is non-empty, is still the automatic job it was created as.
func (t *Tracker) automaticEffectAllowed(
	ctx context.Context, intent models.GigahostSetupIntent,
) (bool, string) {
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		return true, ""
	}
	if t.effectAllowed == nil {
		return false, "this panel cannot report whether unattended setup is enabled"
	}
	allowed, reason := t.effectAllowed(ctx, intent)
	return allowed, strings.TrimSpace(reason)
}

// automaticPinRefusal reports that a job may not pin because unattended setup does not
// currently permit it.
//
// It is a retryable stop rather than a settled pause, and deliberately not a confirmation
// request. Confirming an identity cannot enable unattended setup, so a confirmation prompt
// would send an operator down a path that cannot work; and settling the row would strand a
// job whose policy may simply be turned back on. Keeping it due for a later pass is what
// lets the same job pin the identity the address presented once the panel permits it
// again, while nothing is trusted and nothing authenticates in the meantime.
func automaticPinRefusal(fingerprint, reason string) handoffDecision {
	observed := fingerprint
	return handoffDecision{
		readFailure: true,
		cause:       readFailure{step: stepAutomaticDisabled, message: reason},
		candidate:   &observed,
	}
}

// pinFirstContactIdentity records the observed identity and reports the decision the
// pass should settle to.
//
// The current policy is asked here, immediately before the pin. It is the last moment
// before an identity becomes durably trusted, so the answer is taken now rather than
// inherited from an earlier decision.
//
// The outcomes are kept distinct because treating any of them as another would either
// trust an unproven host or hide a real answer, and because the operator's next action
// differs between them:
//
//   - pinned, or the same identity already pinned: the identity this job will use is
//     exactly the one the address presented, so the handoff may continue;
//   - a different identity is already pinned: trust does not move, and the pass pauses
//     with the same changed-identity diagnosis the manual path gives a contradictory
//     confirmation;
//   - unattended setup is no longer permitted: nothing is pinned. This one does not
//     present itself as a confirmation request, because confirming an identity cannot
//     enable unattended setup - only the setting can. The observed identity stays on the
//     row so a person can see exactly what was presented when they decide;
//   - anything else, including a store error: nothing was recorded, so nothing may
//     be trusted. It is reported as a retryable failure, so the row keeps its place
//     and the state machine re-evaluates it instead of claiming a decision it did
//     not make.
func (t *Tracker) pinFirstContactIdentity(
	ctx context.Context, intent models.GigahostSetupIntent, fingerprint string,
) handoffDecision {
	if t.pinner == nil {
		return handoffDecision{readFailure: true,
			cause:     firstContactTrustFailure(fmt.Errorf("no host trust store is configured")),
			candidate: &fingerprint}
	}
	if allowed, reason := t.automaticEffectAllowed(ctx, intent); !allowed {
		return automaticPinRefusal(fingerprint, reason)
	}
	outcome, err := t.pinner.PinGigahostSetupFirstContact(ctx, intent.OrderID, fingerprint)
	if err != nil {
		return handoffDecision{readFailure: true, cause: firstContactTrustFailure(err),
			candidate: &fingerprint}
	}
	// Every outcome below reports the identity this pass actually observed, so a
	// person looking at the job sees the value the address presented now - not a
	// value an earlier pass displayed and this host no longer answers with.
	observed := fingerprint
	switch outcome {
	case models.FirstContactPinned, models.FirstContactAlreadyPinnedSame:
		// The pin statement clears the displayed candidate; nothing else is left to
		// confirm, so this decision carries none.
		return handoffDecision{
			state: models.SetupStateReadyForSetup,
			step:  stepHostTrustedFirstContact,
		}
	case models.FirstContactIdentityChanged:
		intent.HostMismatch = true
		return handoffDecision{
			state: models.SetupStateAwaitingHostConfirm,
			step:  "host_identity_changed",
			detail: "the address presents a different host identity than the one already " +
				"trusted for this order",
			candidate: &observed,
		}
	default:
		return handoffDecision{
			readFailure: true,
			cause: firstContactTrustFailure(
				fmt.Errorf("the setup intent stopped being eligible before the identity was recorded")),
			candidate: &observed,
		}
	}
}

// firstContactTrustFailure reports that an observed identity could not be recorded.
//
// It is a distinct step from an unreachable host because the operator's question is
// different: the host answered, and the panel could not (or may not) trust the
// answer.
func firstContactTrustFailure(err error) readFailure {
	return readFailure{
		step:    stepHostTrustUnavailable,
		message: "the first-contact host identity could not be trusted: " + summarizeCause(err),
	}
}
