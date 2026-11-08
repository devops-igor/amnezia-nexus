package orchestrator

import (
	"context"
	"errors"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func obsoleteCanary(err error) bool {
	return errors.Is(err, tunnel.ErrTunnelNotFound) || errors.Is(err, tunnel.ErrStaleStateVersion) ||
		errors.Is(err, tunnel.ErrTunnelDisabled) || errors.Is(err, context.Canceled)
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
	if t.ActiveConnections > 0 || (poolTun != nil && poolTun.ActiveConnections > 0) {
		return models.TunnelStatusHandshakeBlocked, nil
	}
	return models.TunnelStatusDegraded, nil
}
