package tunnel

import (
	"context"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// promotionTargetLocked resolves the tunnel a promotion may act on. It enforces
// the same identity/generation/administrative guards as setTunnelStatus so a
// stale probe or a concurrently disabled backend can never be admitted.
// The caller must hold p.mu.
func (p *Pool) promotionTargetLocked(serverID, expectedTunnelID, expectedVersion int64) (*models.BackendTunnel, error) {
	tunnel, ok := p.tunnelsByServerID[serverID]
	if !ok || (expectedTunnelID != 0 && tunnel.ID != expectedTunnelID) {
		return nil, ErrTunnelNotFound
	}
	if expectedVersion > 0 && tunnel.StateVersion != expectedVersion {
		return nil, ErrStaleStateVersion
	}
	if !tunnel.Enabled {
		return nil, ErrTunnelDisabled
	}
	return tunnel, nil
}

// PromoteTunnelWithEnrollmentRelease commits a qualified backend's runtime health
// and releases its durable enrollment quarantine in one transaction.
//
// Finding F10: promotion and quarantine release used to be two independent
// statements, so a process exit between them left a genuinely qualified backend
// still marked unqualified — startup then reset it to connecting and it was
// permanently unselectable. The marker is cleared only when the status transition
// actually commits, so a refused promotion (disabled, stale, deleted) leaves the
// backend safely enrolled as unqualified.
//
// This is reached only from PromoteQualifiedTunnel, i.e. after the caller has
// earned qualification with protocol-appropriate evidence. It is not a
// general-purpose quarantine bypass.
func (p *Pool) PromoteTunnelWithEnrollmentRelease(
	ctx context.Context,
	serverID, expectedTunnelID, expectedVersion int64,
	status string,
	latencyMS int64,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, err := p.promotionTargetLocked(serverID, expectedTunnelID, expectedVersion)
	if err != nil {
		return err
	}

	newReason := tunnel.DisableReason
	switch status {
	case models.TunnelStatusActive, models.TunnelStatusDegraded:
		newReason = models.DisableReasonNone
	}

	if p.db != nil {
		swapped, dbErr := p.db.PromoteTunnelAndClearEnrollment(
			ctx, tunnel.ID, tunnel.Status, tunnel.DisableReason, expectedVersion,
			status, newReason, latencyMS, serverID,
		)
		if dbErr != nil {
			return dbErr
		}
		if !swapped {
			return ErrStaleStateVersion
		}
	}

	tunnel.Status = status
	tunnel.DisableReason = newReason
	tunnel.LatencyMS = latencyMS
	tunnel.StateVersion++
	now := time.Now().UTC()
	tunnel.LastHealthCheck = &now

	return nil
}
