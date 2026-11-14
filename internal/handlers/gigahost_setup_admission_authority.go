package handlers

// Carrying the automatic job's identity to the admission boundary.
//
// Backend promotion is reached through `enableDeployBackend`, a function shared by the
// manual deploy request and the setup installer. The automation policy must gate promotion
// for an automatic job and must not touch a manual one, so the deciding fact - which job is
// being admitted - has to travel with the call.
//
// A context value is the right carrier here rather than a new parameter on a shared
// function: the manual request path, the synchronous deploy path and every existing caller
// pass no intent and are therefore unaffected by construction, and the alternative - adding
// a parameter to the shared deploy surface - would have touched paths this assignment does
// not own. The value is set once, by the setup install runner, and read once, immediately
// before promotion.

import (
	"context"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// automaticAdmissionContextKey is unexported so no other package can forge the carrier.
type automaticAdmissionContextKey struct{}

// withAutomaticAdmissionIntent marks this context as belonging to one automatic setup job.
//
// It is applied by the setup install runner only. Every path that does not call it - the
// manual deploy request, the synchronous onboarding path, any background health check -
// carries no intent, which is what keeps the policy out of manual admission.
func withAutomaticAdmissionIntent(
	ctx context.Context, intent models.GigahostSetupIntent,
) context.Context {
	return context.WithValue(ctx, automaticAdmissionContextKey{}, intent)
}

// automaticAdmissionIntent returns the automatic job this call is admitting, if any.
//
// The bool is the whole permission question: false means "this path is not an automatic
// job's admission", and the caller must not consult the automation policy.
func automaticAdmissionIntent(ctx context.Context) (models.GigahostSetupIntent, bool) {
	if ctx == nil {
		return models.GigahostSetupIntent{}, false
	}
	intent, ok := ctx.Value(automaticAdmissionContextKey{}).(models.GigahostSetupIntent)
	if !ok {
		return models.GigahostSetupIntent{}, false
	}
	// A carrier without automation provenance is not an automatic job, whatever put it
	// there. This keeps the check honest if a future caller reuses the carrier.
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		return models.GigahostSetupIntent{}, false
	}
	return intent, true
}
