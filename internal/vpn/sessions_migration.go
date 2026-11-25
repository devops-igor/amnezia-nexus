package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
)

// SetPreCommitMigrationHookForTest sets a test hook called under s.mu in MigrateSession
// immediately before committing connection counters to the target tunnel (issue #289 rework).
func (s *Service) SetPreCommitMigrationHookForTest(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preCommitMigrationHookForTest = fn
}

// validateMigrationTarget checks that targetTunnelID exists and is eligible for
// migration and returns its StateVersion. The eligibility preflight must run before
// any migration mutation so an ineligible target is rejected without touching the
// forwarder route, SessionManager state, or the DB session row.
//
// The optimistic preflight is shared by health failover, its retry worker and
// rebalancing. Final acceptance is serialized with inventory in the connected-row
// commit; this read alone cannot authorize publication.
func (s *Service) validateMigrationTarget(targetTunnelID int64, providerAbsent models.AbsentServerSet) (int64, error) {
	if s.pool == nil {
		return 0, nil
	}
	targetTun, err := s.pool.GetTunnelByID(targetTunnelID)
	if err != nil {
		return 0, fmt.Errorf("target backend tunnel %d not found in pool: %w", targetTunnelID, err)
	}
	if !targetTun.Enabled || !strings.EqualFold(targetTun.Status, models.TunnelStatusActive) {
		return 0, fmt.Errorf("target backend tunnel %d is not eligible (enabled=%t status=%s)",
			targetTunnelID, targetTun.Enabled, targetTun.Status)
	}
	if providerAbsent.Contains(targetTun.ServerID) {
		// The provider's inventory has contradicted this server: moving a working session
		// onto it would strand the peer, and its "active" status is only the last health
		// sample. The mark is not converted into a status - nothing is disabled here.
		return 0, fmt.Errorf("%w: target backend tunnel %d (server %d) is confirmed absent by the provider",
			database.ErrDestinationProviderAbsent, targetTunnelID, targetTun.ServerID)
	}
	return targetTun.StateVersion, nil
}

// rollbackMigration reverts mutations across DB, SessionManager, and Forwarder during a failed migration.
// The DB compensation executes under a non-cancelable bounded context derived from ctx to guarantee
// completion even if the request context was canceled (issue #289 rework round 3).
func (s *Service) rollbackMigration(ctx context.Context, sessionID, peerKey string, oldTunnelID int64, oldStatus string, forwarderMigrated, rollbackSessionMgr, rollbackDB bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	var rollbackErrs []error

	if rollbackDB && s.db != nil {
		if err := s.db.MigrateVPNSessionBackend(rollbackCtx, sessionID, oldTunnelID); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback db session %s to backend %d: %w", sessionID, oldTunnelID, err))
		}
	}
	if rollbackSessionMgr && s.sessionMgr != nil {
		if err := s.sessionMgr.RollbackSessionBackend(sessionID, oldTunnelID, oldStatus); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback session mgr %s to backend %d: %w", sessionID, oldTunnelID, err))
		}
	}
	if forwarderMigrated && s.forwarder != nil {
		if err := s.forwarder.UpdateSessionBackend(peerKey, oldTunnelID); err != nil {
			rollbackErrs = append(rollbackErrs, fmt.Errorf("rollback forwarder peer %s to backend %d: %w", peerKey, oldTunnelID, err))
		}
	}

	return errors.Join(rollbackErrs...)
}

// MigrateSession migrates an active session to a target backend tunnel, updating
// the live forwarder route, in-memory session, database state, and pool counters atomically
// with full rollback across all subsystems if any step fails (issue #289, rework).
//
// Invariant (issue #86, #289): caller must not hold s.mu (it is acquired internally
// by MigrateSession), maintaining the lock ordering s.mu -> SessionManager.mu (never reversed),
// and preserving serialization for pool connection counters and route transitions.
//
//nolint:gocyclo // transactional validation, protocol check, and multi-phase rollback are centralized.
func (s *Service) MigrateSession(ctx context.Context, sessionID string, targetTunnelID int64) error {
	if s == nil {
		return errors.New("vpn service is nil")
	}
	if sessionID == "" {
		return errors.New("empty session id")
	}
	if targetTunnelID <= 0 {
		return errors.New("invalid target tunnel id")
	}

	// Optimistic filtering stays outside the topology lock. Final connected-row
	// acceptance rechecks inventory under its writer lock before any publication.
	providerAbsent := s.providerAbsentServerIDs(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	expectedVersion, err := s.validateMigrationTarget(targetTunnelID, providerAbsent)
	if err != nil {
		return err
	}

	if s.sessionMgr == nil {
		return errors.New("session manager is not initialized")
	}

	sess, ok := s.sessionMgr.GetSessionSnapshotByID(sessionID)
	if !ok {
		return session.ErrSessionNotFound
	}

	peerKey := sess.PeerPublicKey
	oldTunnelID := sess.BackendTunnelID
	if oldTunnelID == targetTunnelID {
		return nil
	}

	// Cross-protocol migration rejection (Epic #631, Issue #637):
	// Both source and target tunnels must belong to the same effective protocol family.
	if s.pool != nil {
		sourceTun, err := s.pool.GetTunnelByID(oldTunnelID)
		if err != nil {
			return fmt.Errorf("source backend tunnel %d not found: %w", oldTunnelID, err)
		}
		targetTun, err := s.pool.GetTunnelByID(targetTunnelID)
		if err != nil {
			return fmt.Errorf("target backend tunnel %d not found: %w", targetTunnelID, err)
		}
		sourceProto := models.NormalizeTunnelProtocol(sourceTun.Protocol)
		targetProto := models.NormalizeTunnelProtocol(targetTun.Protocol)
		if sourceProto != targetProto {
			return fmt.Errorf("cross-protocol migration rejected: source=%s target=%s", sourceProto, targetProto)
		}
	}

	// The test seam may mutate pool state or cancel the request; run it before
	// pinning the owners, then validate the captured target generation at commit.
	if s.preCommitMigrationHookForTest != nil {
		s.preCommitMigrationHookForTest()
	}
	if err := s.commitSessionMigration(ctx, sess, targetTunnelID, expectedVersion); err != nil {
		return err
	}

	log.Printf("[vpn] migrated session %s (peer %s) from backend %d to backend %d (connected)",
		sessionID, peerKey, oldTunnelID, targetTunnelID)
	slog.Info("Migrated VPN session backend route",
		"session_id", sessionID,
		"peer_key", peerKey,
		"source_tunnel_id", oldTunnelID,
		"target_tunnel_id", targetTunnelID,
		"status", "connected",
	)

	return nil
}

// MigrateVPNSession is an alias for MigrateSession.
func (s *Service) MigrateVPNSession(ctx context.Context, sessionID string, targetTunnelID int64) error {
	return s.MigrateSession(ctx, sessionID, targetTunnelID)
}

func (s *Service) selectTunnelForPeer(ctx context.Context, req *loadbalancer.RoutingRequest) (*models.BackendTunnel, error) {
	if req == nil || len(req.AvailableTunnels) == 0 {
		return nil, loadbalancer.ErrNoActiveBackends
	}
	if s.stickyMgr != nil {
		b, _, err := s.stickyMgr.GetOrAssignBackend(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("backend selection failed: %w", err)
		}
		return b, nil
	}
	if s.balancer != nil {
		b, err := s.balancer.SelectBackend(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("backend selection failed: %w", err)
		}
		return b, nil
	}
	return nil, loadbalancer.ErrNoActiveBackends
}

// SelectTunnel selects a backend tunnel using the configured load balancing algorithm.
// Optional protoFamily filters candidates by protocol (defaults to AWG for backward compatibility).
func (s *Service) SelectTunnel(ctx context.Context, tunnels []*models.BackendTunnel, protoFamily ...string) (*models.BackendTunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.balancer == nil {
		return nil, fmt.Errorf("load balancer not initialized")
	}

	family := models.ProtocolAWG
	if len(protoFamily) > 0 && protoFamily[0] != "" {
		family = models.NormalizeTunnelProtocol(protoFamily[0])
	}

	filtered := models.FilterTunnelsByProtocol(tunnels, family)
	if len(filtered) == 0 {
		return nil, loadbalancer.ErrNoActiveBackends
	}

	req := &loadbalancer.RoutingRequest{
		AvailableTunnels: filtered,
	}
	return s.balancer.SelectBackend(ctx, req)
}
