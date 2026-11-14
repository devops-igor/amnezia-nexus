package gigahostsetup

// Acquiring the scoped automation authority inside a tracking pass.
//
// The grant itself lives in the handler layer, because proving it needs the order ledger,
// the managed credential and the provider association. What this file owns is the
// *decision* to ask: which jobs are eligible to acquire authority, when in the pass the
// question is asked, and how a refusal is recorded.
//
// It is a separate file for the same reason tracker_first_contact.go is: the tracking
// state machine and the automatic-authority rules are two concerns that share a Tracker,
// and keeping them apart keeps each one readable. No behavior is duplicated - the grantor
// is injected, and this file only orders it against the provider checks that make its
// answer meaningful.

import (
	"context"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// acquireAutomaticBinding acquires the scoped authority a job needs before it may trust
// anything, and reports whether it decided the pass.
//
// It is skipped entirely for a job that already carries a binding, and for every manual
// job, so a granted or human-approved row never re-enters the grant path. It is also
// skipped when this deployment wired no grantor, which leaves the job exactly as inert as
// it was before this step existed.
//
// A refusal is a retryable stop with a recorded reason, not a settled pause: the whole
// point of the unattended path is that nobody is standing by, so the job keeps its place
// and the next pass asks the provider again once it can prove the association.
func (t *Tracker) acquireAutomaticBinding(
	ctx context.Context, reader ProviderReader, intent *models.GigahostSetupIntent,
) (handoffDecision, *models.GigahostSetupIntent, bool) {
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		return handoffDecision{}, nil, false
	}
	if strings.TrimSpace(intent.HostTrustOrderID) != "" || !intent.HostTrustGrantedAt.IsZero() {
		// Already granted. The pin and the install phases are what own it from here.
		return handoffDecision{}, nil, false
	}
	if t.grantor == nil {
		return handoffDecision{}, nil, false
	}
	// The policy is asked before issuing authority, not only before using it. A setting
	// turned off since the job was created must stop the grant itself.
	if allowed, reason := t.automaticEffectAllowed(ctx, *intent); !allowed {
		return handoffDecision{
			readFailure: true,
			cause:       readFailure{step: stepAutomaticUnavailable, message: reason},
		}, nil, true
	}
	granted, err := t.grantor(ctx, *intent, reader)
	if err != nil {
		// A failed grant is "could not establish authority yet", which is the same
		// category as an unreadable provider: retry on a later pass, settle nothing.
		return handoffDecision{
			readFailure: true,
			cause: readFailure{
				step:    stepAutomaticGrantUnproven,
				message: "the automatic setup authority could not be established: " + summarizeCause(err),
			},
		}, nil, true
	}
	// The grant applied (or was already there). Continue the pass from the stored row;
	// the trust decision below now has a binding to check the pin against.
	return handoffDecision{}, &granted, false
}
