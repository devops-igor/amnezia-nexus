package handlers

// Recovery of an automatic job whose admission already committed.
//
// Backend promotion and the job's terminal journal write are separate commits. A process
// that stops between them leaves the job installing while its backend is enabled and
// selectable. The installer takes that row over after a restart, and without this file
// the takeover goes through the install precheck first: with unattended setup now off,
// the precheck refuses and pauses the job, and the pause cannot withhold an admission
// that already happened. The job then says it never finished while the pool selects its
// backend, and paused rows are not retried, so nothing corrects it.
//
// The admission is not new work and needs no new permission. The policy gates effects
// that have not happened yet: authentication, installation, enablement and promotion.
// So a takeover first asks whether the durable records prove the admission completed,
// and if they do it records that and stops, with no credential reload, no SSH, no policy
// question and no backend change. Anything less than proof falls through to the
// unchanged path, where the policy and the phase journal decide as before.
//
// Proof is a conjunction of authoritative records, never the phase flag alone:
//
//	journal   the job reached enablement (in flight or proven)
//	ownership the server registered for this provider server is the one the job recorded
//	identity  the host identity bound to that server is the job's pin
//	install   the server row records the approved protocol and port as installed
//	admission the backend row is administratively enabled for that protocol, and its
//	          durable enrollment quarantine is released
//
// The quarantine marker is the deciding fact. Enablement sets it before the backend is
// registered, a refused or failed qualification keeps or restores it, and only the
// promotion transaction releases it, atomically with the status commit. The backend's
// runtime status is deliberately not part of the proof: startup resets every enabled
// backend to connecting and health probing moves it afterwards, so status describes the
// backend's current health, not whether it was admitted.
//
// This is limited to jobs with automatic provenance. A manual job has no policy refusal
// in front of its phase journal, so it reaches the existing enablement verification.
// An explicit cancellation still wins: it makes the row non-installing, so the terminal
// write below is refused by its generation fence, and cancellation withdraws the backend
// itself.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/gigahostsetup"
)

// finalizeRecoveredAdmission records the terminal success of a job whose admission the
// durable records prove, without performing any effect.
//
// It reports whether it handled the attempt. false with a nil error means the admission
// is not proven and the caller continues with the ordinary attempt.
func (h *Handlers) finalizeRecoveredAdmission(
	ctx context.Context, intent models.GigahostSetupIntent, journal *gigahostsetup.InstallJournal,
) (bool, error) {
	server, err := h.recoveredAdmissionServer(ctx, intent)
	if err != nil || server == nil {
		return err != nil, err
	}
	if err := journal.Admit(ctx, "ready", server.ID); err != nil {
		return true, err
	}
	slog.Info("Gigahost setup install recovered a completed admission",
		"order_id", intent.OrderID, "server_id", server.ID, "generation", journal.Generation())
	h.completeOrderDeployStatus(ctx,
		GigahostDeployRequest{OrderID: intent.OrderID, ProviderServerID: intent.ProviderServerID}, server)
	return true, nil
}

// isRecoveryCandidate reports whether a claimed row could hold a completed admission:
// an automatic job whose journal reached enablement and recorded its server.
func isRecoveryCandidate(intent models.GigahostSetupIntent) bool {
	return intent.HostTrustPolicy == models.SetupTrustPolicyFirstContact &&
		intentReachedEnablement(&intent) && intent.NexusServerID > 0
}

// recoveredAdmissionServer returns the job's server when the durable records prove its
// admission completed, and nil when they do not.
//
// A read failure is returned rather than treated as absence: "could not ask" is not
// evidence that the admission did not happen.
func (h *Handlers) recoveredAdmissionServer(
	ctx context.Context, intent models.GigahostSetupIntent,
) (*models.Server, error) {
	if h.db == nil || !isRecoveryCandidate(intent) {
		return nil, nil
	}
	server, err := h.ownedRecoveryServer(ctx, intent)
	if err != nil || server == nil {
		return nil, err
	}
	proven, err := h.admissionRecordsAgree(ctx, intent, server)
	if err != nil || !proven {
		return nil, err
	}
	return server, nil
}

// ownedRecoveryServer returns the server registered for the job's provider server, only
// when it is the server the job's journal recorded. A different or missing server means
// the job cannot be shown to own any admitted backend.
func (h *Handlers) ownedRecoveryServer(
	ctx context.Context, intent models.GigahostSetupIntent,
) (*models.Server, error) {
	server, registered, err := h.isProviderServerRegistered(ctx, "gigahost", intent.ProviderServerID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve the server for a completed admission: %w", err)
	}
	if !registered || server == nil || server.ID != intent.NexusServerID {
		return nil, nil
	}
	return server, nil
}

// admissionRecordsAgree checks identity, installation and admission for the job's server.
func (h *Handlers) admissionRecordsAgree(
	ctx context.Context, intent models.GigahostSetupIntent, server *models.Server,
) (bool, error) {
	bound, err := h.db.GetKnownHostFingerprint(ctx, server.ID)
	if err != nil {
		return false, fmt.Errorf("failed to read the bound host identity for a completed admission: %w", err)
	}
	pin := strings.TrimSpace(intent.HostFingerprint)
	if pin == "" || strings.TrimSpace(bound) != pin {
		return false, nil
	}
	req := GigahostDeployRequest{Protocol: intent.EffectiveProtocol(), Port: intent.Port}
	if h.verifyRecordedProtocol(server, req) != nil {
		return false, nil
	}
	return h.backendDurablyAdmitted(ctx, server.ID, req.GetEffectiveProtocol())
}

// backendDurablyAdmitted reports whether the stored backend is enabled for the protocol
// and its enrollment quarantine was released by promotion.
func (h *Handlers) backendDurablyAdmitted(ctx context.Context, serverID int64, protocol string) (bool, error) {
	tun, err := h.db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil {
		return false, fmt.Errorf("failed to read the backend for a completed admission: %w", err)
	}
	if tun == nil || !tun.Enabled ||
		models.NormalizeTunnelProtocol(tun.Protocol) != models.NormalizeTunnelProtocol(protocol) {
		return false, nil
	}
	pending, err := h.db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to read the enrollment quarantine for a completed admission: %w", err)
	}
	return !pending[serverID], nil
}
