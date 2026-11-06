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
		_ = h.vpnSvc.DisableBackend(ctx, server.ID)
		return fmt.Errorf("%s application traffic qualification failed: %w", protocol, err)
	}

	if err := h.vpnSvc.PromoteQualifiedTunnel(ctx, server.ID, latencyMS); err != nil {
		_ = h.vpnSvc.DisableBackend(ctx, server.ID)
		return fmt.Errorf("failed to commit healthy status after %s traffic qualification: %w", protocol, err)
	}
	return nil
}
