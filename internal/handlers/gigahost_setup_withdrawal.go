package handlers

// Withdrawal of the backend a canceled setup job owns.
//
// A revocation that commits before admission is refused inside the promotion
// transaction, and the refusal itself withdraws the backend. The opposite ordering
// had no such path: a promotion that committed first, followed by a successful
// cancellation, left the approval canceled while its backend stayed enabled and
// selectable. A refused journal write afterwards is a correct fence, not
// compensation, so the success path needs the withdrawal.
//
// The withdrawal reuses the single existing lifecycle path (`quarantineEnrollment`)
// rather than introducing a second way to disable a backend: durable enrollment
// quarantine kept, backend administratively disabled, forwarder device detached.
//
// Truthfulness is part of the contract. `DisableBackend` is the effect that makes
// the backend unselectable, so a failure there is reported to the caller instead of
// being swallowed behind the successful intent write. The durable quarantine marker
// is set before the disable, so even a failed disable leaves the stronger state
// (quarantined and enabled) rather than the weaker one, and a repeated revocation
// retries the same withdrawal.

import (
	"context"
	"errors"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// setupWithdrawalError reports that a revocation was recorded but the owned
// backend could not be withdrawn. It exists so the HTTP layer can answer a
// truthful failure instead of reporting the revocation as fully applied.
type setupWithdrawalError struct {
	orderID  string
	serverID int64
	err      error
}

func (e *setupWithdrawalError) Error() string {
	return fmt.Sprintf(
		"the setup approval for order %s was revoked, but its backend %d was not withdrawn: %v; "+
			"the backend remains quarantined, and repeating the revocation retries the withdrawal",
		e.orderID, e.serverID, e.err)
}

func (e *setupWithdrawalError) Unwrap() error { return e.err }

// intentReachedEnablement reports whether this job ever started admitting its
// backend. It is the only condition under which a cancellation has a backend to
// withdraw: a job that stopped before enablement owns no admission.
//
// The in-flight phase counts. Enablement records the phase BEFORE the effect, so a
// process that died inside it leaves the phase set with no proof of completion -
// exactly the persisted interrupted-finalization state that must still be
// withdrawn if the admission did commit.
func intentReachedEnablement(intent *models.GigahostSetupIntent) bool {
	if intent == nil {
		return false
	}
	return intent.InstallPhase == models.SetupPhaseEnabled ||
		intent.InstallPhaseDone == models.SetupPhaseEnabled
}

// withdrawCanceledSetupEnrollment withdraws the backend a canceled job owns, and
// reports a truthful error when that effect could not be completed.
//
// Ownership is resolved from the identity this job recorded when it registered its
// server, falling back to the panel's provider-server lookup so a job whose
// registration completed without the intent column being written is still found.
// A job with no enablement history owns nothing and returns nil.
func (h *Handlers) withdrawCanceledSetupEnrollment(
	ctx context.Context, intent *models.GigahostSetupIntent,
) error {
	if h.vpnSvc == nil || intent == nil {
		return nil
	}
	if !intentReachedEnablement(intent) {
		return nil
	}
	serverID, err := h.ownedSetupServerID(ctx, intent)
	if err != nil {
		return &setupWithdrawalError{orderID: intent.OrderID, serverID: 0, err: err}
	}
	if serverID <= 0 {
		// Enablement was recorded but no server claims this job any more. There is
		// no identity to withdraw, and guessing one would withdraw somebody else's
		// backend.
		return nil
	}
	if err := h.withdrawEnrollment(ctx, serverID); err != nil {
		return &setupWithdrawalError{orderID: intent.OrderID, serverID: serverID, err: err}
	}
	return nil
}

// ownedSetupServerID resolves the panel server this approval owns.
func (h *Handlers) ownedSetupServerID(
	ctx context.Context, intent *models.GigahostSetupIntent,
) (int64, error) {
	if intent.NexusServerID > 0 {
		return intent.NexusServerID, nil
	}
	if intent.ProviderServerID <= 0 {
		return 0, nil
	}
	server, registered, err := h.isProviderServerRegistered(ctx, "gigahost", intent.ProviderServerID)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve the server this approval owns: %w", err)
	}
	if !registered || server == nil {
		return 0, nil
	}
	return server.ID, nil
}

// withdrawEnrollment disables the owned backend and reports whether the effect
// completed.
//
// An already-absent backend is not a failure: the job owns no admission, so there
// is nothing to withdraw. Every other error is returned, because a backend that is
// still selectable is exactly what must not be reported as withdrawn.
func (h *Handlers) withdrawEnrollment(ctx context.Context, serverID int64) error {
	if h.vpnSvc == nil || serverID <= 0 {
		return nil
	}
	// The durable quarantine marker must be set before the disable so a crash
	// between the two leaves the backend excluded from healthy selection.
	h.vpnSvc.SetPendingEnrollment(serverID, true)
	err := h.vpnSvc.DisableBackend(ctx, serverID)
	if err == nil {
		return nil
	}
	if errors.Is(err, vpn.ErrBackendTunnelNotFound) {
		// Nothing was enrolled for this server: there is no admission to remove.
		h.vpnSvc.SetPendingEnrollment(serverID, false)
		return nil
	}
	return err
}
