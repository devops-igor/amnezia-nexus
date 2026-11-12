package handlers

// Ordering plan for one install attempt.
//
// The plan is derived purely from the durable journal, so it is a decision about
// what has already happened rather than about what a process remembers. Each
// phase resolves to one of three actions:
//
//	actionRun    the effect has not happened; perform it.
//	actionVerify the effect was in flight when a previous attempt stopped, so its
//	             outcome is unknown; prove it or pause. Never re-run it.
//	actionSkip   the effect is proven complete; do nothing.
//
// actionVerify exists because a crash between "effect started" and "effect
// proven" is exactly the window in which a blind retry would duplicate a remote
// command. There is no phase for which a retry is the selected answer.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// Phase actions.
const (
	actionRun    = "run"
	actionVerify = "verify"
	actionSkip   = "skip"
)

// setupPhaseOrder is the fixed order of side-effecting install phases.
var setupPhaseOrder = []string{
	models.SetupPhaseVerified,
	models.SetupPhaseRegistered,
	models.SetupPhaseInstalled,
	models.SetupPhaseEnabled,
}

// installPlan holds the journal a resumed attempt started from.
type installPlan struct {
	inFlight string
	done     string
	step     string
}

// newInstallPlan captures the durable journal for this attempt.
func newInstallPlan(_ models.GigahostSetupIntent, inFlight, done string) installPlan {
	return installPlan{inFlight: inFlight, done: done}
}

// action resolves what this attempt may do for one phase.
func (p *installPlan) action(phase string) string {
	if phaseRank(p.done) >= phaseRank(phase) {
		return actionSkip
	}
	if p.inFlight == phase {
		// In flight with no proven successor: the outcome is unknown.
		return actionVerify
	}
	return actionRun
}

// currentStep names the step an attempt is about to perform, for a diagnosis.
func (p *installPlan) currentStep() string {
	if p.step != "" {
		return p.step
	}
	return "install"
}

// setStep records the step an attempt is entering, so a pause can name it.
func (p *installPlan) setStep(step string) { p.step = step }

// phaseRank orders the phases; an unknown name ranks below the first phase.
func phaseRank(phase string) int {
	for k, candidate := range setupPhaseOrder {
		if candidate == phase {
			return k
		}
	}
	return -1
}

// errPhaseUse is returned when the plan asks for an action it cannot express.
var errPhaseUse = errors.New("install plan has no action for this phase")

// beginInstallPhase asks the current policy and then journals a phase as starting.
//
// The policy question comes first and is answered for every phase, because that is
// the last moment before a remote command: a job whose unattended setup was turned
// off while this attempt was working must not issue the next one. The journal write
// is skipped entirely on a refusal, so the row records the disabled step rather than
// an in-flight phase that never ran.
func (h *Handlers) beginInstallPhase(
	ctx context.Context, intent models.GigahostSetupIntent, journal *gigahostsetup.InstallJournal,
	phase, step, boundary string,
) (bool, error) {
	if pause := h.refuseAutomaticEffect(ctx, intent, boundary); pause != nil {
		journal.Pause(ctx, pause.step, errors.New(pause.detail))
		return false, nil
	}
	return journal.BeginPhase(ctx, phase, step)
}

// installServer brings the panel server row for this order into existence and
// proves its protocol installation, without replaying any completed effect.
func (h *Handlers) installServer(
	ctx context.Context, req GigahostDeployRequest, plan installPlan,
	journal *gigahostsetup.InstallJournal,
) (*models.Server, error) {
	server, err := h.installVerifyAndRegister(ctx, req, plan, journal)
	if err != nil {
		return nil, err
	}
	if err := h.installProtocolStep(ctx, req, server, plan, journal); err != nil {
		return nil, err
	}
	return server, nil
}

// installVerifyAndRegister performs the SSH verification and registration steps.
//
// Verification is not journalled as a separate decision: it is read-only on the
// host (its only write is re-binding the same proven fingerprint locally), so
// re-running it after a crash repeats no remote effect. Registration is
// journalled because creating a server row is a real effect, and the store's
// provider-server-id dedup is what makes a repeated attempt reuse the row instead
// of creating a second one.
//
// The journal is authoritative about what happened; the server table is
// authoritative about what exists. A proven registration whose row is missing is a
// contradiction between durable records, and it pauses for a human rather than
// registering the server a second time.
func (h *Handlers) installVerifyAndRegister(
	ctx context.Context, req GigahostDeployRequest, plan installPlan,
	journal *gigahostsetup.InstallJournal,
) (*models.Server, error) {
	plan.setStep("ssh_verifying")
	server, alreadyRegistered, err := h.findRegisteredDeployServer(ctx, req)
	if err != nil {
		return nil, err
	}
	if server == nil {
		if plan.action(models.SetupPhaseRegistered) == actionSkip {
			return nil, fmt.Errorf("the setup journal records a registered server for order %s, "+
				"but no server row claims provider server %d", req.OrderID, req.ProviderServerID)
		}
		server, err = h.registerServerForInstall(ctx, req, plan, journal)
		if err != nil {
			return nil, err
		}
	}
	if server != nil && !alreadyRegistered {
		return server, nil
	}
	// A proven registration does not prove the host identity; verify it before the
	// install runs against the host.
	if err := h.verifyInstallSSHAccess(ctx, req); err != nil {
		return nil, err
	}
	return server, nil
}

// registerServerForInstall performs the SSH verification that precedes
// registration and then registers the server, journalled around the effect.
func (h *Handlers) registerServerForInstall(
	ctx context.Context, req GigahostDeployRequest, plan installPlan,
	journal *gigahostsetup.InstallJournal,
) (*models.Server, error) {
	fingerprint, err := h.verifyDeploySSHAccess(ctx, req.AssignedIP, req)
	if err != nil {
		return nil, fmt.Errorf("SSH verification failed: %w", err)
	}
	if ok, beginErr := h.beginInstallPhase(ctx, journal.Intent(), journal,
		models.SetupPhaseRegistered, "server_registration", boundaryAuthentication); beginErr != nil || !ok {
		return nil, beginErr
	}
	plan.setStep("server_registration")
	order, _, _, _, orderErr := h.getDeployOrderByID(ctx, req.OrderID)
	if orderErr != nil {
		return nil, fmt.Errorf("failed to load order %s: %w", req.OrderID, orderErr)
	}
	server, err := h.registerDeployServer(ctx, req, order, 0, req.ProviderServerID, req.AssignedIP, fingerprint)
	if err != nil {
		return nil, err
	}
	if _, err := journal.CompletePhase(ctx, models.SetupPhaseRegistered, "server_registered", server.ID); err != nil {
		return nil, err
	}
	return server, nil
}

// verifyInstallSSHAccess proves the host identity for an already registered server.
// It is read-only on the host and idempotent locally.
func (h *Handlers) verifyInstallSSHAccess(ctx context.Context, req GigahostDeployRequest) error {
	if _, err := h.verifyDeploySSHAccess(ctx, req.AssignedIP, req); err != nil {
		return fmt.Errorf("SSH verification failed: %w", err)
	}
	return nil
}

// findRegisteredDeployServer returns the existing panel server for this provider
// server id, if any. It is the restart-safe alternative to creating one.
func (h *Handlers) findRegisteredDeployServer(
	ctx context.Context, req GigahostDeployRequest,
) (*models.Server, bool, error) {
	server, registered, err := h.isProviderServerRegistered(ctx, "gigahost", req.ProviderServerID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to resolve the registered server: %w", err)
	}
	if !registered || server == nil {
		return nil, false, nil
	}
	return server, true, nil
}

// installProtocolStep installs the approved protocol, or proves a previously
// recorded installation for a resumed attempt.
func (h *Handlers) installProtocolStep(
	ctx context.Context, req GigahostDeployRequest, server *models.Server,
	plan installPlan, journal *gigahostsetup.InstallJournal,
) error {
	switch plan.action(models.SetupPhaseInstalled) {
	case actionSkip:
		return nil
	case actionVerify:
		if err := h.verifyRecordedProtocol(server, req); err != nil {
			return &unknownOutcomeError{phase: models.SetupPhaseInstalled, err: err}
		}
		return h.markPhaseDone(ctx, journal, models.SetupPhaseInstalled)
	case actionRun:
		// fallthrough below
	default:
		return errPhaseUse
	}

	if ok, err := h.beginInstallPhase(ctx, journal.Intent(), journal,
		models.SetupPhaseInstalled, "installing_protocol", boundaryProtocolInstall); err != nil || !ok {
		return err
	}
	plan.setStep("installing_protocol")
	if _, err := h.installDeployProtocol(ctx, server, req); err != nil {
		return fmt.Errorf("protocol %s installation failed: %w", req.GetEffectiveProtocol(), err)
	}
	_, err := journal.CompletePhase(ctx, models.SetupPhaseInstalled, "protocol_installed", server.ID)
	return err
}

// verifyRecordedProtocol proves the durable server row records the approved
// protocol as installed.
//
// It reads the same record the install wrote, and it is deliberately strict: a
// missing or differently-ported record cannot prove that the interrupted install
// finished, so it stops the job. Reading the remote host instead would be a new
// verification surface this checkpoint cannot honestly guarantee.
func (h *Handlers) verifyRecordedProtocol(server *models.Server, req GigahostDeployRequest) error {
	if h.db == nil {
		return errors.New("database not available")
	}
	protocol := req.GetEffectiveProtocol()
	meta, ok := server.Protocols[protocol].(map[string]any)
	if !ok || meta == nil {
		return fmt.Errorf("the server row records no %s installation", protocol)
	}
	if installed, _ := meta["installed"].(bool); !installed {
		return fmt.Errorf("the server row does not record %s as installed", protocol)
	}
	recordedPort, ok := protocolPortString(meta["port"])
	if !ok || recordedPort == "" {
		return fmt.Errorf("the server row records no %s port", protocol)
	}
	if want := req.GetEffectivePort(); want != "" && recordedPort != want {
		return fmt.Errorf("the server row records %s on port %s, but the approval asked for %s",
			protocol, recordedPort, want)
	}
	return nil
}

// protocolPortString normalises the port shapes the server row may hold.
func protocolPortString(v any) (string, bool) {
	switch p := v.(type) {
	case string:
		return strings.TrimSpace(p), true
	case int:
		return fmt.Sprintf("%d", p), true
	case int64:
		return fmt.Sprintf("%d", p), true
	case float64:
		return fmt.Sprintf("%d", int(p)), true
	default:
		return "", false
	}
}

// markPhaseDone records a phase as proven without performing its effect.
func (h *Handlers) markPhaseDone(
	ctx context.Context, journal *gigahostsetup.InstallJournal, phase string,
) error {
	_, err := journal.CompletePhase(ctx, phase, phase, journal.Intent().NexusServerID)
	return err
}
