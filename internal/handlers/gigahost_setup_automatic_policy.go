package handlers

// Current-policy enforcement at the effect boundaries of an automatic setup job.
//
// A job that carries automation provenance was created because an administrator had
// unattended setup enabled. That decision is not permanent: it can be turned off, and
// a setting that cannot be read is not a setting that said "yes". So the durable
// policy on the row is not permission to keep acting - it is only the statement that
// this job belongs to the unattended pipeline. Permission is asked for again, at each
// boundary where the panel would otherwise do something to a real host or a real
// backend.
//
// What "automatic" means here is deliberately narrow and immutable: the recorded host
// trust policy. That field is written once, by the internal entry or by the audited
// grant writer, and no worker, confirmation or progress update rewrites it. The
// fields that do move while a job runs - its step, phase journal, displayed candidate
// and trusted identity - are evidence about what happened, not provenance, so they
// cannot be used to decide the job has become manual. An administrator confirming an
// identity is a real decision, but it changes how the identity became trusted, not
// who the job belongs to.
//
// The consequence is stated rather than hidden: while the policy is off, a job with
// automatic provenance does not progress, even if somebody confirmed its identity.
// That is the fail-closed direction, and the deliberate way out is the existing one -
// a fresh manual approval, which produces a job with no automation policy at all.
//
// Nothing here enables automation. There is still no production implementation of
// AutomationPolicy, so the shipped panel answers "off" for every job and no automatic
// job can be created in the first place.

import (
	"context"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// stepAutomaticSetupDisabled is the recorded step of a job that stopped because
// unattended setup is not enabled.
//
// One step for every boundary, because the operator's next action is the same
// wherever it stopped; the boundary that was refused is named in the recorded reason,
// which is what makes the stop diagnosable without the step vocabulary growing a
// variant per phase.
const stepAutomaticSetupDisabled = "automatic_setup_disabled"

// The effect boundaries where the current policy is consulted. They are named because
// a refusal has to say what did not happen, and "it refused" is not a diagnosis.
const (
	boundaryHostTrustPin      = "the host identity was not pinned"
	boundaryInstallPrecheck   = "the install precheck was not completed"
	boundaryAuthentication    = "no SSH authentication or server registration was attempted"
	boundaryProtocolInstall   = "the protocol was not installed"
	boundaryBackendEnablement = "the backend was not enabled"
	boundaryHealthyAdmission  = "the backend was not admitted to the healthy pool"
)

// automaticJobRefusal reports whether this job has automation provenance and, if so,
// whether the current policy still permits it to act.
//
// A manual job is answered nil without consulting any policy: a human approved it, and
// an unattended-setup setting has no business gating work a person asked for. That is
// also why the check is keyed on the policy field rather than on anything a running
// job might have accumulated.
//
// For an automatic job the answer is the same fail-closed question the entry asks, so
// the two cannot drift: no policy, a policy that says no and a policy that cannot be
// read all refuse, and each says which it was.
func (h *Handlers) automaticJobRefusal(ctx context.Context, intent models.GigahostSetupIntent) error {
	if intent.HostTrustPolicy != models.SetupTrustPolicyFirstContact {
		return nil
	}
	return h.requireAutomaticSetupEnabled(ctx)
}

// refuseAutomaticEffect turns a policy refusal into the pause the caller records.
//
// It returns nil when the effect may proceed. A refusal carries the boundary that was
// not performed and the policy's own reason, so the durable row explains itself to
// whoever finds the job stopped.
func (h *Handlers) refuseAutomaticEffect(
	ctx context.Context, intent models.GigahostSetupIntent, boundary string,
) *installPause {
	err := h.automaticJobRefusal(ctx, intent)
	if err == nil {
		return nil
	}
	return &installPause{
		step: stepAutomaticSetupDisabled,
		detail: fmt.Sprintf(
			"%s because unattended setup is not currently enabled: %v", boundary, err),
	}
}

// automaticEffectPermitted is the same decision expressed for the tracker worker.
//
// It is deliberately the same call the installer uses rather than a second
// implementation of the rule: the tracker and the installer are two processes over one
// row, and two copies of "is unattended setup enabled" would eventually disagree about
// the same job.
func (h *Handlers) automaticEffectPermitted(
	ctx context.Context, intent models.GigahostSetupIntent,
) (bool, string) {
	pause := h.refuseAutomaticEffect(ctx, intent, "the automatic effect was not permitted")
	if pause == nil {
		return true, ""
	}
	return false, pause.detail
}
