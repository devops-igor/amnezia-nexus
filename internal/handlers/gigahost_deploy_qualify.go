package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
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
func (h *Handlers) qualifyProxyBackendTraffic(ctx context.Context, server *models.Server, protocol string) error {
	if h.vpnSvc == nil {
		return nil
	}
	tun, err := h.vpnSvc.GetTunnel(server.ID)
	if err != nil || tun == nil {
		// The backend never became enrolled: it is not qualified.
		return fmt.Errorf("backend tunnel not found for server %d", server.ID)
	}

	probeCtx, cancel := context.WithTimeout(ctx, proxyQualifyTimeout)
	defer cancel()

	latencyMS, err := h.vpnSvc.QualifyProxyTraffic(probeCtx, tun)
	if err != nil {
		// Keep the durable quarantine: an unproven payload path must not be
		// admitted, and reporting ready here was the defect.
		h.quarantineEnrollment(ctx, server.ID)
		return fmt.Errorf("%s application traffic qualification failed: %w", protocol, err)
	}

	if err := h.refuseAutomaticAdmissionOrQuarantine(ctx, server.ID); err != nil {
		return err
	}
	if err := h.vpnSvc.PromoteQualifiedTunnel(probeCtx, server.ID, latencyMS); err != nil {
		// A revoked approval is one of the two reasons promotion is refused, and
		// the backend must not be left enabled behind a canceled job either way.
		h.quarantineEnrollment(ctx, server.ID)
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
func (h *Handlers) refuseAutomaticAdmissionOrQuarantine(ctx context.Context, serverID int64) error {
	pause := h.refuseAutomaticAdmission(ctx)
	if pause == nil {
		return nil
	}
	h.quarantineEnrollment(ctx, serverID)
	return fmt.Errorf("%s", pause.detail)
}

// quarantineEnrollment withdraws a backend that failed or was refused admission:
// enrollment stays durably quarantined, the backend is administratively disabled
// and its forwarder device detaches, so it cannot receive client traffic.
//
// It runs on a context detached from the caller's, because the refusal is exactly
// what happens when the caller's own deadline expires; a cleanup that inherits
// that deadline would never run. The withdrawal is bounded on its own.
func (h *Handlers) quarantineEnrollment(ctx context.Context, serverID int64) {
	if h.vpnSvc == nil || serverID <= 0 {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	// The marker is set before the disable so a crash between the two leaves the
	// stronger state (quarantined and enabled) rather than the weaker one.
	h.vpnSvc.SetPendingEnrollment(serverID, true)
	_ = h.vpnSvc.DisableBackend(cleanupCtx, serverID)
}
