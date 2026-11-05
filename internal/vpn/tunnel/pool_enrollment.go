package tunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// persistTunnelEnrollment replaces the existing identity write with one atomic
// identity/health reset. AddTunnelWithConfig already serializes identity updates
// under p.mu (legacy I/O debt); this adds no I/O call or lock scope there.
func (p *Pool) persistTunnelEnrollment(ctx context.Context, existing *models.BackendTunnel, updates map[string]any) error {
	reset := ctx != nil && ctx.Value(DeployEnrollmentKey) != nil
	if !reset {
		return p.db.UpdateBackendTunnel(ctx, existing.ID, updates)
	}
	delete(updates, "state_version")
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	swapped, err := p.db.ResetBackendTunnelForEnrollment(writeCtx, existing.ID, existing.StateVersion, updates)
	if err != nil {
		return err
	}
	if !swapped {
		return fmt.Errorf("backend enrollment changed concurrently or row is missing: %w", ErrStaleStateVersion)
	}
	return nil
}

func resetTunnelEnrollmentHealth(ctx context.Context, tunnel *models.BackendTunnel) {
	if ctx == nil || ctx.Value(DeployEnrollmentKey) == nil {
		return
	}
	tunnel.Status = models.TunnelStatusConnecting
	tunnel.DisableReason = models.DisableReasonNone
	tunnel.LatencyMS = 0
	tunnel.LastHealthCheck = nil
}
