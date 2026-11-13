package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// proxyQualifyTimeout bounds the authenticated proxy traffic qualification run at
// the end of Gigahost proxy enrollment.
const proxyQualifyTimeout = 15 * time.Second

// qualifyProxyBackendTraffic proves that a newly onboarded VLESS/Naive backend
// actually forwards application traffic, then and only then admits it, and
// releases its durable enrollment quarantine atomically with that admission.
//
// Finding F10 + the original work item 9 ("validating data-plane reachability
// before adding it to the load balancer pool"): proxies used to return straight
// from EnableBackendWithConfig, so the deployment answered HTTP200/ready while the
// durable marker stayed set. Nothing ever cleared it, so after a restart startup
// quarantine forced every subsequent successful probe back to connecting and the
// backend was permanently unselectable.
//
// The qualification is a real authenticated application request/reply for the
// selected protocol. A REALITY/TLS handshake is NOT accepted as proof: it shows
// the engine is listening, not that payloads traverse the tunnel. On failure the
// backend stays durably quarantined, is administratively disabled, and the real
// error is returned so the route reports a truthful failure instead of ready.
//
// The observed backend `tun` is passed to the qualifier and to every terminal
// effect, so a result that returns after the operator deleted or re-enrolled that
// backend cannot admit — or withdraw — whatever owns the server slot now.
func (h *Handlers) qualifyProxyBackendTraffic(ctx context.Context, server *models.Server, observed *models.BackendTunnel, protocol string) error {
	if h.vpnSvc == nil {
		return nil
	}
	if observed == nil {
		// The backend never became enrolled: it is not qualified.
		return fmt.Errorf("backend tunnel not found for server %d", server.ID)
	}

	probeCtx, cancel := context.WithTimeout(ctx, proxyQualifyTimeout)
	defer cancel()

	latencyMS, err := h.vpnSvc.QualifyProxyTraffic(probeCtx, observed)
	if err != nil {
		// Keep the durable quarantine: an unproven payload path must not be
		// admitted, and reporting ready here was the defect.
		h.quarantineEnrollment(ctx, observed)
		return fmt.Errorf("%s application traffic qualification failed: %w", protocol, err)
	}

	if err := h.refuseAutomaticAdmissionOrQuarantine(ctx, observed); err != nil {
		return err
	}
	if err := h.vpnSvc.PromoteQualifiedTunnel(probeCtx, observed, latencyMS); err != nil {
		// A retired generation is inert by construction: the replacement owns its
		// own admission and must not be withdrawn for this observation's verdict.
		if errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
			return fmt.Errorf("%s traffic qualification completed for a backend that was replaced meanwhile; its result does not apply to the current backend: %w", protocol, err)
		}
		// A revoked approval is one of the two reasons promotion is refused, and
		// the backend must not be left enabled behind a canceled job either way.
		h.quarantineEnrollment(ctx, observed)
		return fmt.Errorf("failed to commit healthy status after %s traffic qualification: %w", protocol, err)
	}
	return nil
}

// refuseAutomaticAdmissionOrQuarantine applies the automation-policy gate on the proxy
// qualification path and quarantines the backend when it refuses.
//
// It mirrors the AWG path: the policy is asked after qualification succeeded and before the
// promotion commit, and a refusal keeps the durable enrollment quarantine so the backend
// stays out of the pool. Returning nil leaves the caller to promote normally.
func (h *Handlers) refuseAutomaticAdmissionOrQuarantine(ctx context.Context, observed *models.BackendTunnel) error {
	pause := h.refuseAutomaticAdmission(ctx)
	if pause == nil {
		return nil
	}
	h.quarantineEnrollment(ctx, observed)
	return fmt.Errorf("%s", pause.detail)
}

// quarantineEnrollment withdraws a backend that failed or was refused admission:
// enrollment stays durably quarantined, the backend is administratively disabled
// and its forwarder device detaches, so it cannot receive client traffic.
//
// The withdrawal is scoped to the generation the caller OBSERVED. A backend that
// was deleted or re-enrolled while the qualification was in flight is inert: the
// operator's replacement may not be disabled, detached or newly quarantined by a
// verdict about credentials it never had. The service decides that under its own
// service lock at the mutation, so the check cannot be outrun here.
//
// It runs on a context detached from the caller's, because the refusal is exactly
// what happens when the caller's own deadline expires; a cleanup that inherits
// that deadline would never run. The withdrawal is bounded on its own.
func (h *Handlers) quarantineEnrollment(ctx context.Context, observed *models.BackendTunnel) {
	if h.vpnSvc == nil || observed == nil || observed.ServerID <= 0 {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	// The service sets the generation-owned marker before the disable so a crash
	// between the two leaves the stronger state (quarantined and enabled) rather
	// than the weaker one.
	err := h.vpnSvc.WithdrawObservedEnrollment(cleanupCtx, observed)
	if err != nil && !errors.Is(err, tunnel.ErrTunnelGenerationRetired) {
		// Not returned: the caller is already reporting the qualification failure,
		// and this cleanup runs on a detached context. It must still be visible.
		log.Printf("[handlers] withdraw backend %d (tunnel %d) after failed qualification: %v",
			observed.ServerID, observed.ID, err)
	}
}
