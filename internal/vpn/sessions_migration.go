package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
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
// migration - administratively enabled AND runtime-active (issue #90) -
// returning its StateVersion. The eligibility preflight must run before any
// migration mutation so a disabled target is rejected without touching the
// forwarder route, SessionManager state, or the DB session row.
func (s *Service) validateMigrationTarget(targetTunnelID int64) (int64, error) {
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
// Invariant (issue #86, #289): caller executes under s.mu.Lock(), maintaining the
// lock ordering s.mu -> SessionManager.mu (never reversed), and preserving serialization
// for pool connection counters and route transitions.
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

	s.mu.Lock()
	defer s.mu.Unlock()

	expectedVersion, err := s.validateMigrationTarget(targetTunnelID)
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
	oldStatus := sess.Status
	if oldStatus == "" {
		oldStatus = "connected"
	}

	if oldTunnelID == targetTunnelID {
		return nil
	}

	// Step 1: Live Forwarder Route Migration
	var forwarderMigrated bool
	if s.forwarder != nil {
		if err := s.forwarder.UpdateSessionBackend(peerKey, targetTunnelID); err != nil {
			if !errors.Is(err, forwarder.ErrSessionNotRegistered) {
				return fmt.Errorf("failed to update live forwarder route for session %s: %w", sessionID, err)
			}
		} else {
			forwarderMigrated = true
		}
	}

	// Step 2: In-Memory Session Update
	if _, _, _, err := s.sessionMgr.UpdateSessionBackend(sessionID, targetTunnelID, "connected"); err != nil {
		rbErr := s.rollbackMigration(ctx, sessionID, peerKey, oldTunnelID, oldStatus, forwarderMigrated, false, false)
		return errors.Join(fmt.Errorf("failed to update in-memory session %s: %w", sessionID, err), rbErr)
	}

	// Step 3: Database Persistence
	if s.db != nil {
		if err := s.db.MigrateVPNSessionBackend(ctx, sessionID, targetTunnelID); err != nil {
			rbErr := s.rollbackMigration(ctx, sessionID, peerKey, oldTunnelID, oldStatus, forwarderMigrated, true, false)
			return errors.Join(fmt.Errorf("failed to persist vpn session %s backend migration: %w", sessionID, err), rbErr)
		}
	}

	// Step 4.5: Pre-commit hook for testing check-to-commit races
	if s.preCommitMigrationHookForTest != nil {
		s.preCommitMigrationHookForTest()
	}

	// Step 5: Transfer Connection Counters
	if s.pool != nil {
		if err := s.pool.TransferConnectionsIfActive(oldTunnelID, targetTunnelID, expectedVersion); err != nil {
			rbErr := s.rollbackMigration(ctx, sessionID, peerKey, oldTunnelID, oldStatus, forwarderMigrated, true, true)
			return errors.Join(fmt.Errorf("failed to commit connection transfer to target tunnel %d: %w", targetTunnelID, err), rbErr)
		}
	}

	if s.stickyMgr != nil {
		s.stickyMgr.AssignPeerAffinity(peerKey, targetTunnelID)
	}
	s.sessionMgr.BumpLifecycleVersion()

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
func (s *Service) SelectTunnel(ctx context.Context, tunnels []*models.BackendTunnel) (*models.BackendTunnel, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.balancer == nil {
		return nil, fmt.Errorf("load balancer not initialized")
	}

	req := &loadbalancer.RoutingRequest{
		AvailableTunnels: tunnels,
	}
	return s.balancer.SelectBackend(ctx, req)
}
