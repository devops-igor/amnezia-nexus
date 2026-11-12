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
//
// For a deploy re-enrollment the durable quarantine commits in the reset's own
// transaction, so the new unqualified identity is never persisted without it and
// a failure to record it fails the enrollment.
func (p *Pool) persistTunnelEnrollment(ctx context.Context, existing *models.BackendTunnel, updates map[string]any) error {
	if !isDeployEnrollment(ctx) {
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

// resetTunnelEnrollmentLocked applies a committed deploy re-enrollment to the
// in-memory tunnel: health becomes unknown and the generation is quarantined
// until its own qualification. The caller must hold p.mu.
func (p *Pool) resetTunnelEnrollmentLocked(ctx context.Context, tunnel *models.BackendTunnel) {
	if !isDeployEnrollment(ctx) {
		return
	}
	tunnel.Status = models.TunnelStatusConnecting
	tunnel.DisableReason = models.DisableReasonNone
	tunnel.LatencyMS = 0
	tunnel.LastHealthCheck = nil
	p.setEnrollmentPendingLocked(tunnel.ID)
}

func isDeployEnrollment(ctx context.Context) bool {
	return ctx != nil && ctx.Value(DeployEnrollmentKey) != nil
}

// setEnrollmentPendingLocked quarantines one tunnel generation. The caller must
// hold p.mu for writing.
func (p *Pool) setEnrollmentPendingLocked(tunnelID int64) {
	if p.enrollmentPending == nil {
		p.enrollmentPending = make(map[int64]bool)
	}
	p.enrollmentPending[tunnelID] = true
}

// EnrollmentPending reports whether the tunnel generation currently registered
// for serverID is a deploy enrollment that has not yet qualified.
func (p *Pool) EnrollmentPending(serverID int64) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	t, ok := p.tunnelsByServerID[serverID]
	return ok && p.enrollmentPending[t.ID]
}
