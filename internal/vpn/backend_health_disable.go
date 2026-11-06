package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// healthDisableFailoverTimeout bounds the session-migration work a single
// automatic health disable may perform, so a dead backend cannot hold the probe
// cycle or the admission lock indefinitely.
const healthDisableFailoverTimeout = 10 * time.Second

// SetHealthDisabledNotifier registers (or clears, with nil) the automatic
// health-disable session failover callback on the service's health prober.
// Production wiring happens through SetDeviceProvider's optional
// HealthDisabledNotifier discovery; this setter exists for explicit wiring and
// for tests that need to reproduce the pre-round21 composition.
func (s *Service) SetHealthDisabledNotifier(fn func(ctx context.Context, tunnel *models.BackendTunnel) error) {
	if s == nil || s.prober == nil {
		return
	}
	s.prober.SetHealthDisabledNotifier(fn)
}

// BackendHealthDisabled implements tunnel.HealthDisabledNotifier.
//
// It is the missing terminal step of the dual-tier health machine: when the
// prober commits `disabled` with reason `health`, the backend stops being
// eligible for routing, and every session still pinned to it must move to a
// healthy alternative — the same terminal effect an administrative disable
// has, minus the administrative mutations.
//
// Deliberately NOT done here, because they belong to administrative intent:
//   - SetTunnelEnabled(false) and the adminDisableEpoch bump (the backend keeps
//     Enabled=true so self-healing may recover it),
//   - MarkAdminDisabled,
//   - device detach/close (the data plane stays attached for recovery, and the
//     canary needs it to prove the backend came back),
//   - clearing autoDisabled/DisableReasonHealth.
//
// The move itself reuses MigrateSession — the existing transactional primitive
// used by rebalancing and the scheduler's degraded-tunnel migration. It moves
// the live forwarder route, the in-memory session, the durable vpn_sessions row
// and the pool connection counters together, with rollback. This matters here
// because the client is still connected: unlike an administrative disable
// (whose clients are expected to reconnect) a health disable must not strand a
// working session.
func (s *Service) BackendHealthDisabled(ctx context.Context, disabled *models.BackendTunnel) error {
	if s == nil || s.pool == nil {
		return errors.New("tunnel pool not initialized")
	}
	if disabled == nil || disabled.ID == 0 {
		return errors.New("health-disable notification without tunnel identity")
	}
	// Bounded and detached from the probe cycle's cancellation: a probe
	// deadline must not tear a partially applied migration in half.
	opCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), healthDisableFailoverTimeout)
	defer cancel()

	live, err := s.healthDisabledBackend(disabled)
	if err != nil {
		return err
	}
	if live == nil {
		return nil
	}

	targets := s.healthDisableTargets(live)
	if len(targets) == 0 {
		log.Printf("[vpn] backend %d (tunnel %d) disabled by health probing; no healthy alternative for its established sessions", live.ServerID, live.ID)
		return nil
	}
	sessions, err := s.healthDisableSessions(opCtx, live.ID)
	if err != nil {
		return fmt.Errorf("list established sessions on health-disabled backend %d: %w", live.ID, err)
	}
	if len(sessions) == 0 {
		return nil
	}
	log.Printf("[vpn] backend %d (tunnel %d) disabled by health probing; migrating %d established session(s)",
		live.ServerID, live.ID, len(sessions))
	s.migrateSessionsToHealthy(opCtx, live, sessions, targets)
	return nil
}

// healthDisableEligible reports whether a committed health disable is still the
// backend's live state, so the failover it asks for is still the right action.
//
// Every administrative or recovery decision that landed after the prober's CAS
// makes this false: the backend was re-enabled, re-decided to another status,
// recovered by self-healing, or replaced by a newer state version. Those paths
// own their ordering and intent, and migrating here could move sessions off a
// backend the administrator just put back in service.
func healthDisableEligible(live, committed *models.BackendTunnel) bool {
	if live == nil || committed == nil {
		return false
	}
	if !live.Enabled ||
		live.DisableReason != models.DisableReasonHealth ||
		!strings.EqualFold(live.Status, models.TunnelStatusDisabled) {
		return false
	}
	return committed.StateVersion == 0 || live.StateVersion == committed.StateVersion
}

// healthDisabledBackend returns the live tunnel when the notification still
// describes the backend's current terminal state, and nil when it is stale or
// superseded. A non-nil error is a real read failure worth surfacing.
func (s *Service) healthDisabledBackend(disabled *models.BackendTunnel) (*models.BackendTunnel, error) {
	live, err := s.pool.GetTunnelByID(disabled.ID)
	if err != nil {
		if errors.Is(err, tunnel.ErrTunnelNotFound) {
			// Deleted between the status write and this notification; the
			// delete path owns its own failover.
			return nil, nil
		}
		return nil, fmt.Errorf("re-read health-disabled tunnel %d: %w", disabled.ID, err)
	}
	if !healthDisableEligible(live, disabled) {
		return nil, nil
	}
	return live, nil
}

// migrateSessionsToHealthy moves each session onto a healthy target, spreading
// the assignments round-robin over the least-loaded candidates.
func (s *Service) migrateSessionsToHealthy(ctx context.Context, source *models.BackendTunnel, sessions []models.VPNSession, targets []*models.BackendTunnel) {
	if source == nil || len(targets) == 0 {
		return
	}
	migrated := 0
	for i, sess := range sessions {
		// MigrateSession revalidates the target (exists, enabled, active,
		// version-pinned) under s.mu, so a target that went bad meanwhile is
		// rejected instead of receiving traffic.
		target := targets[i%len(targets)]
		if mErr := s.MigrateSession(ctx, sess.ID, target.ID); mErr != nil {
			// One failed session must not strand the rest; the peer is left on
			// the disabled backend and stays visible through the log.
			log.Printf("[vpn] health-disable failover: session %s (peer %s) NOT migrated off backend %d to %d: %v",
				sess.ID, sess.PeerPublicKey, source.ID, target.ID, mErr)
			continue
		}
		migrated++
	}
	if migrated > 0 {
		log.Printf("[vpn] health-disable failover: migrated %d/%d session(s) off backend %d",
			migrated, len(sessions), source.ID)
	}
}

// healthDisableTargets returns the still-eligible active tunnels of the same
// protocol family, least-loaded first, so a bulk migration spreads across
// healthy backends instead of piling onto one. The disabled backend itself is
// never a candidate: it is no longer in the active set, but the identity check
// keeps that guarantee explicit.
func (s *Service) healthDisableTargets(disabled *models.BackendTunnel) []*models.BackendTunnel {
	if s == nil || s.pool == nil || disabled == nil {
		return nil
	}
	family := models.NormalizeTunnelProtocol(disabled.Protocol)
	var targets []*models.BackendTunnel
	for _, candidate := range s.pool.GetActiveTunnels() {
		if candidate == nil || candidate.ID == disabled.ID {
			continue
		}
		if models.NormalizeTunnelProtocol(candidate.Protocol) == family {
			targets = append(targets, candidate)
		}
	}
	sortTunnelsByLoadThenID(targets)
	return targets
}

// sortTunnelsByLoadThenID orders candidates least-loaded first, then by ID.
// GetActiveTunnels returns map-ordered copies, so this is what makes the
// round-robin assignment for a bulk health-disable migration deterministic in
// tests and in logs.
func sortTunnelsByLoadThenID(tunnels []*models.BackendTunnel) {
	sort.Slice(tunnels, func(i, j int) bool {
		if tunnels[i].ActiveConnections != tunnels[j].ActiveConnections {
			return tunnels[i].ActiveConnections < tunnels[j].ActiveConnections
		}
		return tunnels[i].ID < tunnels[j].ID
	})
}

// healthDisableSessions returns the connected sessions still pinned to the
// disabled backend, preferring the live session manager and falling back to the
// durable rows so a session whose in-memory record is missing is still moved.
func (s *Service) healthDisableSessions(ctx context.Context, tunnelID int64) ([]models.VPNSession, error) {
	live := s.healthDisableLiveSessions(tunnelID)
	if s.db == nil {
		return live, nil
	}
	rows, err := s.db.GetActiveVPNSessions(ctx)
	if err != nil {
		if len(live) == 0 {
			return nil, err
		}
		// Live records are enough to act; report the durable-read gap without
		// abandoning the sessions we can see.
		log.Printf("[vpn] health-disable failover: durable session read failed, using %d live session(s): %v", len(live), err)
		return live, nil
	}
	return mergeHealthDisableSessions(live, rows, tunnelID), nil
}

// healthDisableLiveSessions returns the session manager's connected sessions on
// the disabled backend. Its rows are authoritative for live traffic.
func (s *Service) healthDisableLiveSessions(tunnelID int64) []models.VPNSession {
	if s.sessionMgr == nil {
		return nil
	}
	var sessions []models.VPNSession
	for _, sess := range s.sessionMgr.ListActiveSessionsSnapshot() {
		if sess.BackendTunnelID == tunnelID && strings.EqualFold(sess.Status, "connected") {
			sessions = append(sessions, sess)
		}
	}
	return sessions
}

// mergeHealthDisableSessions appends the durable rows pinned to the disabled
// backend that the live set did not already cover, so a connected row whose
// in-memory record is missing is still attempted (and then reported if it
// cannot move) instead of being silently ignored.
func mergeHealthDisableSessions(live, rows []models.VPNSession, tunnelID int64) []models.VPNSession {
	seen := make(map[string]bool, len(live))
	for _, sess := range live {
		seen[sess.ID] = true
	}
	merged := live
	for _, row := range rows {
		if row.BackendTunnelID != tunnelID || seen[row.ID] {
			continue
		}
		seen[row.ID] = true
		merged = append(merged, row)
	}
	return merged
}
