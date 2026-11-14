package orchestrator

import (
	"context"
	"errors"
	"log/slog"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func obsoleteCanary(err error) bool {
	return errors.Is(err, tunnel.ErrTunnelNotFound) || errors.Is(err, tunnel.ErrStaleStateVersion) ||
		errors.Is(err, tunnel.ErrTunnelDisabled) || errors.Is(err, context.Canceled)
}

// blockedBackendHoldsSessions reports whether a backend currently serves live
// sessions, counting both the probe snapshot and the live pool snapshot.
func blockedBackendHoldsSessions(t, poolTun *models.BackendTunnel) bool {
	return t.ActiveConnections > 0 || (poolTun != nil && poolTun.ActiveConnections > 0)
}

// confirmOuterFailure classifies outer failure using the same consecutive inner
// confirmation rule below and above the outer threshold. A missing prober keeps
// the legacy outer policy, but cannot evict an already blocked backend.
func (o *Orchestrator) confirmOuterFailure(ctx context.Context, t, poolTun *models.BackendTunnel, outerFailures, threshold int, blocked bool) (string, error) {
	cp := o.getCanaryProber()
	if cp == nil {
		if blocked {
			return models.TunnelStatusHandshakeBlocked, nil
		}
		if outerFailures >= threshold {
			return models.TunnelStatusDegraded, nil
		}
		return "", nil
	}
	err := cp.ProbeCanary(ctx, t)
	if obsoleteCanary(err) {
		return "", err
	}
	if err == nil {
		o.ResetCanaryFailCount(t.ID)
		return models.TunnelStatusHandshakeBlocked, nil
	}
	failures := o.recordCanaryFailure(t.ID)
	if failures >= threshold {
		return models.TunnelStatusDegraded, nil
	}
	if blockedBackendHoldsSessions(t, poolTun) {
		return models.TunnelStatusHandshakeBlocked, nil
	}
	return models.TunnelStatusDegraded, nil
}

// innerPlaneVerdict is the usable answer about a backend's inner data plane.
type innerPlaneVerdict int

const (
	// innerPlaneUnobserved means no observation describes the current backend
	// generation, so no status may be written from it.
	innerPlaneUnobserved innerPlaneVerdict = iota
	// innerPlaneUnavailable means there is no inner prober to ask at all.
	innerPlaneUnavailable
	innerPlaneHealthy
	innerPlaneLost
)

// probeInnerPlane asks the configured inner canary prober about one backend.
// Stale, superseded or disabled observations are reported as unobserved rather
// than as loss, because they say nothing about the backend that exists now.
func (o *Orchestrator) probeInnerPlane(ctx context.Context, t *models.BackendTunnel) innerPlaneVerdict {
	cp := o.getCanaryProber()
	if cp == nil {
		return innerPlaneUnavailable
	}
	err := cp.ProbeCanary(ctx, t)
	switch {
	case obsoleteCanary(err):
		return innerPlaneUnobserved
	case err == nil:
		return innerPlaneHealthy
	default:
		return innerPlaneLost
	}
}

// preserveBlockedSlowOuterSuccess classifies a handshake_blocked backend whose
// outer probe SUCCEEDED above the latency threshold. Latency is not evidence
// about the inner data plane, and the degraded status migrates established
// sessions and moves their live forwarder routes, so a slow success must not
// evict a backend that is still serving sessions over a working inner path.
//
// A blocked backend that holds sessions applies the same dual-tier rule as the
// below-threshold path: only sustained consecutive inner canary failures
// reaching the failure threshold degrade it. A healthy inner plane, or no inner
// prober to ask, preserves handshake_blocked and only refreshes the latency
// diagnostic; unobserved inner evidence writes no status at all. Backends with
// no sessions keep the pre-existing latency policy.
//
// Returns true when the caller must treat the backend as degraded.
func (o *Orchestrator) preserveBlockedSlowOuterSuccess(ctx context.Context, t, poolTun *models.BackendTunnel, latencyMS int64, threshold int) bool {
	if !blockedBackendHoldsSessions(t, poolTun) {
		return o.updateTunnelStatus(ctx, t, models.TunnelStatusDegraded, latencyMS)
	}

	preserve := func(err error) {
		slog.Warn("Blocked backend tunnel outer probe succeeded above the latency threshold but its inner plane is not known to be lost; preserving handshake_blocked and established sessions",
			"tunnel_id", t.ID, "endpoint", t.Endpoint, "latency_ms", latencyMS,
			"active_connections", t.ActiveConnections, "err", err)
		if o.updateTunnelStatus(ctx, t, models.TunnelStatusHandshakeBlocked, latencyMS) {
			t.Status = models.TunnelStatusHandshakeBlocked
		}
	}

	switch o.probeInnerPlane(ctx, t) {
	case innerPlaneUnobserved:
		return false
	case innerPlaneUnavailable:
		preserve(nil)
		return false
	case innerPlaneHealthy:
		o.ResetCanaryFailCount(t.ID)
		preserve(nil)
		return false
	}

	fails := o.recordCanaryFailure(t.ID)
	if fails < threshold {
		preserve(errors.New("inner canary failed below the failure threshold"))
		return false
	}

	// Sustained inner failure on a session-carrying backend: the established
	// migration contract applies unchanged.
	slog.Warn("Blocked backend tunnel inner canary sustained failures reached threshold after a slow outer success; marking degraded",
		"tunnel_id", t.ID, "endpoint", t.Endpoint, "failures", fails, "threshold", threshold)
	if o.updateTunnelStatus(ctx, t, models.TunnelStatusDegraded, latencyMS) {
		t.Status = models.TunnelStatusDegraded
		o.recordProbeFailVersion(t.ID, t.StateVersion)
		o.ResetCanaryFailCount(t.ID)
		return true
	}
	return false
}
