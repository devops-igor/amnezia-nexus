package vpn

import (
	"context"
	"log"
	"sync"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// F16 — retrying an unfinished automatic health-disable failover.
//
// When a health disable commits but no eligible alternative exists (or a
// per-session migration fails), the sessions pinned to that backend are NOT
// moved. Treating that as completed work strands live clients on a dead backend
// for as long as it stays dead, even after an alternative recovers: ProbeAll,
// the reconnect manager and the scheduler all skip a disabled backend, and the
// self-healing sweep only tries to recover that backend itself. Nothing revisits
// the source, so the established session and its live route stay on the dead
// backend forever.
//
// The unpaid obligation is therefore recorded per source-tunnel identity and
// settled by the existing bounded self-healing sweep (see
// RetryPendingHealthFailovers) — the timer-driven worker that already runs when
// a backend becomes recoverable, which is exactly when an alternative can
// become eligible again.
//
// The registry is package-level keyed by *Service, mirroring the existing
// canarySuccessCallbacks registry in health_canary.go. That keeps the
// Service-owned state attachable without adding a field to the fenced Service
// struct in vpn.go, and it cannot leak: entries are only added for a live
// Service that received a health-disable notification, and the sweep clears
// them when the debt is settled or superseded.

// healthFailoverDebt is one outstanding automatic failover, keyed by the source
// tunnel identity so a deleted-and-recreated tunnel is never mistaken for the
// original.
type healthFailoverDebt struct {
	tunnelID int64
	serverID int64
}

// healthFailoverRegistry holds per-Service outstanding debts.
type healthFailoverRegistry struct {
	mu      sync.RWMutex
	entries map[*Service]map[int64]healthFailoverDebt
}

var pendingHealthFailovers = &healthFailoverRegistry{
	entries: make(map[*Service]map[int64]healthFailoverDebt),
}

func (r *healthFailoverRegistry) record(s *Service, tun *models.BackendTunnel) {
	if r == nil || s == nil || tun == nil || tun.ID == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	perService := r.entries[s]
	if perService == nil {
		perService = make(map[int64]healthFailoverDebt)
		r.entries[s] = perService
	}
	perService[tun.ID] = healthFailoverDebt{tunnelID: tun.ID, serverID: tun.ServerID}
}

func (r *healthFailoverRegistry) clear(s *Service, tunnelID int64) {
	if r == nil || s == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	perService := r.entries[s]
	if perService == nil {
		return
	}
	delete(perService, tunnelID)
	if len(perService) == 0 {
		delete(r.entries, s)
	}
}

func (r *healthFailoverRegistry) snapshot(s *Service) []healthFailoverDebt {
	if r == nil || s == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	perService := r.entries[s]
	if len(perService) == 0 {
		return nil
	}
	out := make([]healthFailoverDebt, 0, len(perService))
	for _, e := range perService {
		out = append(out, e)
	}
	return out
}

func (r *healthFailoverRegistry) has(s *Service, tunnelID int64) bool {
	if r == nil || s == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.entries[s][tunnelID]
	return ok
}

// recordHealthFailoverDebt notes that the source still owes a migration.
// Caller must not hold Service.mu.
func (s *Service) recordHealthFailoverDebt(tun *models.BackendTunnel) {
	pendingHealthFailovers.record(s, tun)
}

// clearHealthFailoverDebt retires a debt that was settled or superseded.
func (s *Service) clearHealthFailoverDebt(tunnelID int64) {
	pendingHealthFailovers.clear(s, tunnelID)
}

// hasPendingHealthFailover reports whether an automatic failover is still owed
// for the given source tunnel.
func (s *Service) hasPendingHealthFailover(tunnelID int64) bool {
	return pendingHealthFailovers.has(s, tunnelID)
}

// RetryPendingHealthFailovers settles every recorded debt that has become
// completable. This is the bounded-worker entry point F16 requires.
//
// It re-reads CURRENT state and re-applies the guards the original notification
// used — same tunnel identity, still administratively enabled, still
// health-disabled, and an eligible healthy alternative now present — then
// delegates to the unchanged BackendHealthDisabled primitive, so the move keeps
// its transactional rollback, session identity and exactly-once accounting.
//
// It performs no I/O when no debt is outstanding, so calling it from a periodic
// loop is free in the normal case.
func (s *Service) RetryPendingHealthFailovers(ctx context.Context) int {
	if s == nil || s.pool == nil {
		return 0
	}
	pending := pendingHealthFailovers.snapshot(s)
	settled := 0
	for _, debt := range pending {
		if s.retryOneHealthFailover(ctx, debt) {
			settled++
		}
	}
	return settled
}

// retryOneHealthFailover attempts a single recorded debt and reports whether it
// was settled. Any guard that fails clears or keeps the debt without migrating,
// so this function's only success path is a real, completed move.
func (s *Service) retryOneHealthFailover(ctx context.Context, debt healthFailoverDebt) bool {
	live, err := s.pool.GetTunnelByID(debt.tunnelID)
	if err != nil || live == nil || live.ServerID != debt.serverID {
		// Source deleted or replaced: its own delete path owns the sessions,
		// and this debt is no longer about that backend.
		s.clearHealthFailoverDebt(debt.tunnelID)
		return false
	}
	if !healthFailoverStillOwed(live) {
		// An administrative or recovery decision landed after the disable.
		// Abandon the debt instead of fighting the operator or duplicating a
		// move another owner already performed.
		s.clearHealthFailoverDebt(debt.tunnelID)
		return false
	}
	if len(s.healthDisableTargets(live)) == 0 {
		// Still no alternative: keep the debt for the next sweep.
		return false
	}
	if err := s.BackendHealthDisabled(ctx, live); err != nil {
		log.Printf("[vpn] retrying pending health failover for backend %d: %v", live.ServerID, err)
		return false
	}
	if !s.healthFailoverSettled(ctx, live) {
		// Still stranded (e.g. a target degraded mid-move); keep the debt.
		return false
	}
	s.clearHealthFailoverDebt(debt.tunnelID)
	return true
}

// healthFailoverStillOwed reports whether the debt is still the right
// obligation: the source must still be administratively enabled and still
// runtime-disabled for health. Any other state means another owner already
// decided this backend's fate.
func healthFailoverStillOwed(live *models.BackendTunnel) bool {
	if live == nil || !live.Enabled {
		return false
	}
	return live.Status == models.TunnelStatusDisabled &&
		live.DisableReason == models.DisableReasonHealth
}

// healthFailoverSettled reports whether no established session remains pinned to
// the health-disabled source. A read error means "cannot verify", which keeps
// the debt rather than claiming false completion.
func (s *Service) healthFailoverSettled(ctx context.Context, live *models.BackendTunnel) bool {
	sessions, err := s.healthDisableSessions(ctx, live.ID)
	if err != nil {
		return false
	}
	return len(sessions) == 0
}
