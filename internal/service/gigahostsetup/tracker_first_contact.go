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

// stepHostTrustedFirstContact is the recorded step of a job that trusted its own
// first observation. It is the durable evidence that no person confirmed this
// identity, which is what the confirmation path refuses to overwrite.
const stepHostTrustedFirstContact = "host_trusted_first_contact"

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

// pinFirstContactIdentity records the observed identity and reports the decision the
// pass should settle to.
//
// The outcomes are kept distinct because treating any of them as another would
// either trust an unproven host or hide a real answer:
//
//   - pinned, or the same identity already pinned: the identity this job will use is
//     exactly the one the address presented, so the handoff may continue;
//   - a different identity is already pinned: trust does not move, and the pass
//     pauses with the same changed-identity diagnosis the manual path gives a
//     contradictory confirmation;
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
