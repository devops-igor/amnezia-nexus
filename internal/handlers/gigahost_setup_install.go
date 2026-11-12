package handlers

// The install half of a durable Gigahost setup approval.
//
// The tracker reads the provider and settles credential/host trust; this file
// performs the side effects that follow, and it never invents a second path for
// any of them. Installation goes through the registered protocol manager,
// registration through the existing server store, and admission through the
// existing enable/qualify path. What is new here is only the ordering guarantee:
// each step is journalled before and after its effect, so a restart can prove
// what finished instead of repeating it.
//
// Verified phase -> what a later attempt does with it:
//
//	ssh_verified       the host identity was proven. Verification is read-only
//	                   apart from binding the same fingerprint again, so an
//	                   attempt that starts here simply verifies again.
//	server_registered  a panel server row exists. The store's own dedup makes a
//	                   second row impossible, so an absent row is re-registered
//	                   and a present row is reused.
//	protocol_installed the protocol manager reported success. Installing again
//	                   would replay a completed remote effect, so the attempt
//	                   verifies the recorded installation instead and pauses when
//	                   the record does not prove it.
//	backend_enabled    enrollment plus traffic qualification succeeded. The
//	                   attempt verifies the tunnel is admitted; it never
//	                   re-enables on the strength of a flag alone.
//
// An in-flight phase with no proven successor is the unknown case, and the answer
// to it is a pause, not a retry.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// installStepTimeout bounds one install attempt. It matches the request-path
// budget for a protocol installation: the panel already tolerates that long for
// the synchronous path, and an attempt that exceeds it has stopped making
// progress rather than being slow.
const installStepTimeout = 15 * time.Minute

// SetupInstallRunner executes a claimed install attempt through the existing
// handlers' managers.
type SetupInstallRunner struct {
	h *Handlers
}

// NewSetupInstallRunner builds the runner an Installer drives.
func (h *Handlers) NewSetupInstallRunner() *SetupInstallRunner {
	return &SetupInstallRunner{h: h}
}

// RunInstall performs one attempt.
//
// Every phase is recorded BEFORE its effect so a crash leaves evidence of what
// was in flight, and the phase-done marker is written only after the effect is
// proven. A journal write that reports the attempt no longer owns the row ends
// the attempt immediately, which is how an administrative revocation reaches
// work that is already running.
func (r *SetupInstallRunner) RunInstall(
	ctx context.Context, intent models.GigahostSetupIntent, journal *gigahostsetup.InstallJournal,
) error {
	if r == nil || r.h == nil {
		return errors.New("setup install runner has no handlers")
	}
	attemptCtx, cancel := context.WithTimeout(ctx, installStepTimeout)
	defer cancel()

	// A takeover of an automatic job whose admission already committed only records it;
	// see gigahost_setup_install_recovery.go. It runs before the precheck because the
	// precheck gates new effects, and a completed admission needs none.
	if recovered, err := r.h.finalizeRecoveredAdmission(attemptCtx, intent, journal); recovered {
		return err
	}

	req, pause, err := r.h.prepareInstall(attemptCtx, intent)
	if err != nil {
		journal.Pause(attemptCtx, "install_precheck", err)
		return nil
	}
	if pause != nil {
		// A pause the precheck decided on its own (missing credential, changed
		// host). It is not a failure of the server.
		journal.Pause(attemptCtx, pause.step, errors.New(pause.detail))
		return nil
	}

	inFlight, done := journal.ResumePhase()
	plan := newInstallPlan(intent, inFlight, done)
	server, err := r.h.installServer(attemptCtx, req, plan, journal)
	if err != nil {
		if errors.Is(err, gigahostsetup.ErrInstallNotOwned) {
			return nil
		}
		journal.Pause(attemptCtx, plan.currentStep(), err)
		return nil
	}
	return r.h.finishInstall(attemptCtx, req, server, plan, journal)
}

// installPause is a precheck decision that stops the attempt with a diagnosis.
type installPause struct {
	step   string
	detail string
}

// prepareInstall re-proves every precondition at the moment of the first remote
// command.
//
// These gates were already checked by the tracker, and they are checked again
// here for one reason: the tracker's answer is durable state, and durable state
// can be stale. A credential can be removed, a provider server identity can
// change, and an administrator can revoke the approval between the handoff and
// this attempt. Re-reading is what makes the answer true now.
func (h *Handlers) prepareInstall(
	ctx context.Context, intent models.GigahostSetupIntent,
) (GigahostDeployRequest, *installPause, error) {
	req, err := h.buildInstallRequest(ctx, intent)
	if err != nil {
		return req, nil, err
	}
	// The current policy is asked before the precheck dials the host at all, so a
	// job whose unattended setup was turned off sends no credential and registers
	// nothing. It is asked again at each later phase, because a pass can take
	// minutes and the answer can change while it runs.
	if pause := h.refuseAutomaticEffect(ctx, intent, boundaryAuthentication); pause != nil {
		return req, pause, nil
	}
	if pause, err := h.recheckInstallTrust(ctx, intent); err != nil || pause != nil {
		return req, pause, err
	}
	return req, nil, nil
}

// buildInstallRequest turns the approval into the request the existing deploy
// steps take. Nothing is defaulted: the approval already recorded the protocol,
// port and TLS domain, and re-defaulting them here would let the installed thing
// disagree with what the administrator approved.
func (h *Handlers) buildInstallRequest(
	ctx context.Context, intent models.GigahostSetupIntent,
) (GigahostDeployRequest, error) {
	protocol := intent.EffectiveProtocol()
	if protocol == "" {
		return GigahostDeployRequest{}, errors.New("the approval records no protocol")
	}
	req := GigahostDeployRequest{
		OrderID:             intent.OrderID,
		ProviderServerID:    intent.ProviderServerID,
		AssignedIP:          strings.TrimSpace(intent.AssignedIP),
		Protocol:            protocol,
		Port:                intent.Port,
		TLSDomain:           intent.TLSDomain,
		EngineProfile:       intent.EngineProfile,
		ExpectedFingerprint: intent.HostFingerprint,
		WaitReady:           true,
	}
	if req.AssignedIP == "" {
		return req, fmt.Errorf("order %s has no assigned address to install on", intent.OrderID)
	}
	if req.ProviderServerID <= 0 {
		return req, fmt.Errorf("order %s has no provider server identity", intent.OrderID)
	}
	if intent.CredentialMode == models.SetupCredentialManaged {
		// The private key never enters the durable row; it is reloaded from the
		// existing encrypted order credential at each attempt.
		req.UseOrderCredential = true
	}
	reloaded, err := h.applyStoredOrderCredential(ctx, req)
	if err != nil {
		return req, err
	}
	return reloaded, nil
}

// recheckInstallTrust re-proves host identity against the durable binding.
//
// A registered server whose bound identity contradicts the approval is the
// changed-host case, and it stops the attempt. An unbound server is acceptable
// only when the approval itself carries the confirmed identity, which is the same
// rule the tracker applies. Nothing is bound on the administrator's behalf.
func (h *Handlers) recheckInstallTrust(
	ctx context.Context, intent models.GigahostSetupIntent,
) (*installPause, error) {
	if h.db == nil {
		return nil, errors.New("database not available")
	}
	server, registered, err := h.isProviderServerRegistered(ctx, "gigahost", intent.ProviderServerID)
	if err != nil {
		return nil, fmt.Errorf("failed to recheck server identity: %w", err)
	}
	confirmed := strings.TrimSpace(intent.HostFingerprint)
	if !registered || server == nil {
		return decideUnregisteredTrust(confirmed), nil
	}
	bound, err := h.db.GetKnownHostFingerprint(ctx, server.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to recheck the bound host identity: %w", err)
	}
	return decideBoundTrust(bound, confirmed), nil
}

// decideUnregisteredTrust answers the trust question for a server that is not
// registered yet: only an identity confirmed in the approval can settle it.
func decideUnregisteredTrust(confirmed string) *installPause {
	if confirmed == "" {
		return &installPause{
			step:   "awaiting_host_confirmation",
			detail: "no host identity was confirmed for this order",
		}
	}
	return nil
}

// decideBoundTrust compares the identity already bound to the server with the one
// the approval confirmed. A contradiction pauses; an unconfirmed server also
// pauses; agreement settles. Nothing is ever written here.
func decideBoundTrust(bound, confirmed string) *installPause {
	if bound != "" && confirmed != "" {
		if bound != confirmed {
			return &installPause{
				step:   "host_identity_changed",
				detail: "the confirmed host identity contradicts the identity bound to this server",
			}
		}
		return nil
	}
	if bound == "" && confirmed == "" {
		return &installPause{
			step:   "awaiting_host_confirmation",
			detail: "this server has no bound host identity and none was confirmed",
		}
	}
	// Exactly one side has an identity: the approval's confirmation stands.
	return nil
}

// finishInstall performs enablement and admission for a server whose protocol
// installation is already proven, then records the terminal success.
//
// Promotion is the terminal authorization boundary. That is a deliberate decision, and
// it is the one the owner finding required be made explicit rather than left implicit.
//
// The automation policy is asked immediately BEFORE the promotion commit - in
// qualifyBackendTraffic (gigahost_deploy.go) and qualifyProxyBackendTraffic
// (gigahost_deploy_qualify.go) - and a refusal there quarantines the enrollment, so a
// backend is never promoted by a policy that had already been withdrawn. That gate is
// the healthy-admission check the recorded lifecycle decision requires.
//
// Asking again here, after the commit, could not withhold anything: the backend is
// already active and selectable, and undoing it would mean rolling back a completed
// effect, which the same lifecycle decision forbids. The only thing a second refusal
// could produce is a durable row that says the job never admitted a backend while the
// production pool selects it - exactly the inconsistency that was reported. So this
// function records what actually happened instead of narrating a refusal that did not
// and could not take place.
//
// installEnableStep returns nil only when the phase is genuinely complete: either it was
// already proven done, or enablement plus traffic qualification succeeded and the phase
// was journalled. Every other outcome pauses or errors there, so reaching the admission
// below means the backend really is admitted.
func (h *Handlers) finishInstall(
	ctx context.Context, req GigahostDeployRequest, server *models.Server,
	plan installPlan, journal *gigahostsetup.InstallJournal,
) error {
	if err := h.installEnableStep(ctx, req, server, plan, journal); err != nil {
		return err
	}
	if err := journal.Admit(ctx, "ready", server.ID); err != nil {
		return err
	}
	h.completeOrderDeployStatus(ctx, req, server)
	return nil
}

// installEnableStep enables the backend and admits it only after real
// qualification, journalling the phase around the effect.
func (h *Handlers) installEnableStep(
	ctx context.Context, req GigahostDeployRequest, server *models.Server,
	plan installPlan, journal *gigahostsetup.InstallJournal,
) error {
	switch plan.action(models.SetupPhaseEnabled) {
	case actionSkip:
		return nil
	case actionVerify:
		// Enablement was interrupted. Its outcome is asked for, not assumed, and
		// the action is decided once by resumeInstallAction so the two paths
		// cannot disagree.
		switch h.resumeInstallAction(ctx, req, server) {
		case actionSkip:
			return h.markPhaseDone(ctx, journal, models.SetupPhaseEnabled)
		case actionRun:
			// provably never enabled: enabling now is the first attempt
		default:
			return &unknownOutcomeError{phase: models.SetupPhaseEnabled,
				err: errors.New("a backend tunnel exists but is not admitted")}
		}
	}
	ok, err := h.beginInstallPhase(ctx, journal.Intent(), journal,
		models.SetupPhaseEnabled, "enabling_backend", boundaryBackendEnablement)
	if err != nil || !ok {
		return err
	}
	// The job's identity travels with this call so the admission boundary can ask the
	// automation policy before it promotes. Without it the promotion would happen before
	// finishInstall's journal refusal, leaving a selectable backend behind a job that never
	// claims success.
	enrollCtx := withAutomaticAdmissionIntent(ctx, journal.Intent())
	if err := h.enableDeployBackend(enrollCtx, server, req.GetEffectiveProtocol()); err != nil {
		return fmt.Errorf("backend enablement failed: %w", err)
	}
	// The enable path reports success only after traffic qualification, so the
	// phase is complete exactly when it returned nil.
	_, err = journal.CompletePhase(ctx, models.SetupPhaseEnabled, "backend_enabled", server.ID)
	return err
}

// Backend admission observations.
const (
	admissionAdmitted = iota
	admissionAbsent
	admissionAmbiguous
)

// backendAdmissionState classifies what the tunnel state proves about a previous
// enablement attempt.
//
// The distinction is the whole point of the verify action. "No tunnel row" and
// "a tunnel that is administratively not enabled" both prove enablement did not
// complete, so re-running it is the first attempt and not a replay - and the
// tunnel registration it performs is an upsert keyed by server id, so repeating it
// cannot create a second backend. "A tunnel that was enrolled but never reached
// admittance" is the genuinely unknown case, and it pauses.
func (h *Handlers) backendAdmissionState(ctx context.Context, server *models.Server, protocol string) int {
	if h.vpnSvc == nil {
		return admissionAmbiguous
	}
	tun, err := h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		// No tunnel row at all: enablement never registered one.
		return admissionAbsent
	}
	if !tun.Enabled {
		// Not administratively enabled: enablement either never completed or was
		// undone by the failure path, which disables the backend.
		return admissionAbsent
	}
	switch tun.Status {
	case models.TunnelStatusActive, models.TunnelStatusDegraded:
	default:
		// Enrolled but not admitted: the effect happened and its outcome is unproven.
		return admissionAmbiguous
	}
	if tun.Protocol != "" && models.NormalizeProtocol(tun.Protocol) != models.NormalizeProtocol(protocol) {
		return admissionAmbiguous
	}
	return admissionAdmitted
}

// resumeInstallAction decides what a resumed attempt may do at the enablement
// phase, in the plan's own vocabulary.
func (h *Handlers) resumeInstallAction(
	ctx context.Context, req GigahostDeployRequest, server *models.Server,
) string {
	switch h.backendAdmissionState(ctx, server, req.GetEffectiveProtocol()) {
	case admissionAdmitted:
		return actionSkip
	case admissionAbsent:
		return actionRun
	default:
		return actionVerify
	}
}

// completeOrderDeployStatus mirrors the finished state into the order ledger so
// the existing deploy status endpoint agrees with the setup intent. A failure here
// is ignored: the durable intent is already the authority and the ledger row is a
// progress view.
func (h *Handlers) completeOrderDeployStatus(
	ctx context.Context, req GigahostDeployRequest, server *models.Server,
) {
	if h.db == nil {
		return
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	_ = h.updateDeployOrderStatus(persistCtx, req.OrderID, DeployStatusReady, DeployStatusReady, "",
		req.ProviderServerID, server.ID, server.Host)
}

// unknownOutcomeError reports that an interrupted phase could not be proven
// complete. It is a pause, never a retry of the effect.
type unknownOutcomeError struct {
	phase string
	err   error
}

func (e *unknownOutcomeError) Error() string {
	return fmt.Sprintf("the %s step was interrupted and its outcome could not be verified: %v", e.phase, e.err)
}

func (e *unknownOutcomeError) Unwrap() error { return e.err }
