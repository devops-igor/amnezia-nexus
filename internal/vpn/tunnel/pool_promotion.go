package tunnel

import (
	"context"
	"errors"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ErrTunnelGenerationRetired reports that the backend generation an observation
// was made against no longer owns the server slot. A qualification result that
// carries it describes a backend that was deleted, replaced or re-enrolled
// while the observation was in flight, so it is inert: it may neither admit nor
// withdraw whatever backend owns the slot now.
var ErrTunnelGenerationRetired = errors.New("observed backend generation no longer owns the server slot")

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

// observedGenerationLocked resolves the backend a qualification observed, and
// refuses when the server slot is now owned by a different generation.
//
// Identity equality, not the row id alone, is the fence: a deployment re-enrolls
// an existing row with fresh credentials (same id, different endpoint or
// protocol parameters), so an id-only check would let a retired observation
// admit the replacement credentials it never proved. The whole decision runs
// under p.mu, the lock every generation change and every promotion takes, so
// the validated generation is the one the commit acts on.
// The caller must hold p.mu.
func (p *Pool) observedGenerationLocked(observed *models.BackendTunnel) (*models.BackendTunnel, error) {
	if observed == nil || observed.ID <= 0 || observed.ServerID <= 0 {
		return nil, ErrTunnelGenerationRetired
	}
	live, ok := p.tunnelsByServerID[observed.ServerID]
	if !ok {
		return nil, ErrTunnelNotFound
	}
	if !models.SameTunnelIdentity(live, observed) {
		return nil, ErrTunnelGenerationRetired
	}
	if !live.Enabled {
		return nil, ErrTunnelDisabled
	}
	return live, nil
}

// ErrSetupApprovalRevoked reports that the setup approval owning a backend was
// revoked before the backend could be admitted. It is re-exported here so the
// tunnel layer and its callers can distinguish "the authority was withdrawn" from
// "the tunnel state moved".
var ErrSetupApprovalRevoked = database.ErrSetupApprovalRevoked

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
//
// The caller supplies the expected generation explicitly. PromoteObservedTunnel-
// WithEnrollmentRelease is the caller-facing form used by a qualification, which
// observed its backend rather than selecting an expected one.
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
	return p.promoteLocked(ctx, tunnel, status, latencyMS)
}

// PromoteObservedTunnelWithEnrollmentRelease promotes the backend generation a
// qualification actually observed, and refuses when that generation no longer
// owns the server slot.
//
// The state version comes from the live row read in the same critical section,
// not from the caller's snapshot: a probe legitimately advances the version
// while the observation is in flight, and the CAS must fence the row's current
// state rather than an older copy of it. Identity, by contrast, may not drift —
// that is what decides whose qualification this is.
func (p *Pool) PromoteObservedTunnelWithEnrollmentRelease(
	ctx context.Context,
	observed *models.BackendTunnel,
	status string,
	latencyMS int64,
) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tunnel, err := p.observedGenerationLocked(observed)
	if err != nil {
		return err
	}
	return p.promoteLocked(ctx, tunnel, status, latencyMS)
}

// promoteLocked applies the admission verdict to the resolved generation. The
// caller must hold p.mu and must already have decided which generation this is.
func (p *Pool) promoteLocked(ctx context.Context, tunnel *models.BackendTunnel, status string, latencyMS int64) error {
	serverID := tunnel.ServerID
	newReason := tunnel.DisableReason
	switch status {
	case models.TunnelStatusActive, models.TunnelStatusDegraded:
		newReason = models.DisableReasonNone
	}

	if p.db != nil {
		swapped, dbErr := p.db.PromoteTunnelAndClearEnrollment(
			ctx, tunnel.ID, tunnel.Status, tunnel.DisableReason, tunnel.StateVersion,
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
	// The qualified generation's runtime quarantine is released in the same
	// critical section as its durable release.
	delete(p.enrollmentPending, tunnel.ID)

	return nil
}
