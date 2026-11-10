package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// reconcileThresholdAutoDisable reconciles a missed threshold auto-disable CAS update
// caused by reverse failure ordering or concurrent state updates.
func (hp *HealthProber) reconcileThresholdAutoDisable(ctx context.Context, serverID, expectedTunnelID int64) (bool, error) {
	if hp.pool == nil {
		return false, nil
	}

	currentTunnel, err := hp.pool.GetTunnel(serverID)
	if err != nil {
		return false, err
	}
	if currentTunnel == nil || currentTunnel.ID != expectedTunnelID {
		return false, ErrTunnelNotFound
	}

	if !currentTunnel.Enabled {
		slog.Info("threshold auto-disable CAS missed due to concurrent admin disable", "server_id", serverID)
		return false, hp.updateHealthIfCurrent(currentTunnel, func() {
			delete(hp.autoDisabled, serverID)
			hp.failCounts[serverID] = 0
		})
	}

	if currentTunnel.Status == models.TunnelStatusHandshakeBlocked {
		return true, nil
	}

	if currentTunnel.Status == models.TunnelStatusDisabled && currentTunnel.DisableReason == models.DisableReasonHealth {
		if err := hp.updateHealthIfCurrent(currentTunnel, func() {
			hp.autoDisabled[serverID] = true
			hp.successCounts[serverID] = 0
		}); err != nil {
			return false, err
		}
		return true, nil
	}

	hp.mu.Lock()
	if err := hp.checkHealthGenerationLocked(currentTunnel); err != nil {
		hp.mu.Unlock()
		return false, err
	}
	count := hp.failCounts[serverID]
	threshold := hp.cfg.FailureThreshold
	hp.mu.Unlock()

	if count < threshold {
		return false, nil
	}

	swapped, casErr := hp.pool.CompareAndSwapTunnelStatusForTunnel(
		ctx,
		serverID,
		expectedTunnelID,
		currentTunnel.Status,
		currentTunnel.DisableReason,
		currentTunnel.StateVersion,
		models.TunnelStatusDisabled,
		models.DisableReasonHealth,
		0,
	)
	if casErr != nil {
		return false, casErr
	}
	if swapped {
		currentTunnel.StateVersion++
		// This reconciliation IS the terminal health-disable commit for a
		// sibling probe whose own CAS missed, so it owns the failover
		// notification. The "already disabled/health" branch below does not:
		// whoever committed that transition already notified.
		if err := hp.commitThresholdDisable(ctx, currentTunnel); err != nil {
			return false, err
		}
		return true, nil
	}

	cur, err := hp.pool.GetTunnel(serverID)
	if err != nil {
		return false, err
	}
	if cur == nil || cur.ID != expectedTunnelID {
		return false, ErrTunnelNotFound
	}
	if !cur.Enabled {
		slog.Info("threshold auto-disable reconciliation CAS missed due to concurrent admin disable", "server_id", serverID)
		return false, hp.updateHealthIfCurrent(cur, func() {
			delete(hp.autoDisabled, serverID)
			hp.failCounts[serverID] = 0
		})
	}

	if cur.Status == models.TunnelStatusDisabled && cur.DisableReason == models.DisableReasonHealth {
		if err := hp.updateHealthIfCurrent(cur, func() {
			hp.autoDisabled[serverID] = true
			hp.successCounts[serverID] = 0
		}); err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func (hp *HealthProber) handleProbeFailure(ctx context.Context, snapshot *models.BackendTunnel, probeErr error) (int64, error) {
	if hp.isTunnelAdminDisabled(snapshot.ServerID) {
		hp.mu.Lock()
		hp.failCounts[snapshot.ServerID] = 0
		delete(hp.autoDisabled, snapshot.ServerID)
		hp.mu.Unlock()
		slog.Info("probe failed but tunnel was administratively disabled; ignoring failure", "server_id", snapshot.ServerID)
		return 0, probeErr
	}
	hp.mu.Lock()
	if err := hp.checkHealthGenerationLocked(snapshot); err != nil {
		hp.mu.Unlock()
		return 0, err
	}
	hp.failCounts[snapshot.ServerID]++
	failures := hp.failCounts[snapshot.ServerID]
	hp.mu.Unlock()

	if err := hp.confirmOuterFailure(ctx, snapshot, failures); err != nil {
		return 0, err
	}
	if err := hp.checkTunnelAvailable(snapshot); errors.Is(err, ErrTunnelNotFound) {
		return 0, err
	}

	return 0, probeErr
}

func (hp *HealthProber) transitionToHandshakeBlocked(ctx context.Context, snapshot *models.BackendTunnel) error {
	if hp.pool != nil {
		swapped, casErr := hp.pool.CompareAndSwapTunnelStatusForTunnel(
			ctx,
			snapshot.ServerID,
			snapshot.ID,
			snapshot.Status,
			snapshot.DisableReason,
			snapshot.StateVersion,
			models.TunnelStatusHandshakeBlocked,
			models.DisableReasonNone,
			0,
		)
		if casErr != nil {
			return casErr
		}
		if swapped {
			snapshot.StateVersion++
			snapshot.Status = models.TunnelStatusHandshakeBlocked
			snapshot.DisableReason = models.DisableReasonNone
			return hp.updateHealthIfCurrent(snapshot, func() {
				delete(hp.autoDisabled, snapshot.ServerID)
				hp.successCounts[snapshot.ServerID] = 0
			})
		}
		cur, err := hp.pool.GetTunnel(snapshot.ServerID)
		if err == nil && cur != nil && cur.Status == models.TunnelStatusHandshakeBlocked {
			snapshot.StateVersion = cur.StateVersion
			snapshot.Status = cur.Status
			snapshot.DisableReason = cur.DisableReason
		}
		return nil
	}
	snapshot.Status = models.TunnelStatusHandshakeBlocked
	snapshot.DisableReason = models.DisableReasonNone
	return hp.updateHealthIfCurrent(snapshot, func() {
		delete(hp.autoDisabled, snapshot.ServerID)
		hp.successCounts[snapshot.ServerID] = 0
	})
}

// commitThresholdDisable records the consecutive-failure bookkeeping for a
// committed health auto-disable and, only when that write is accepted for the
// current tunnel generation, reports the disable to the data plane owner so it
// can migrate the sessions still pinned to the backend. A rejected write means
// a newer generation owns this backend, so there is nothing to report.
func (hp *HealthProber) commitThresholdDisable(ctx context.Context, snapshot *models.BackendTunnel) error {
	if err := hp.updateHealthIfCurrent(snapshot, func() {
		hp.autoDisabled[snapshot.ServerID] = true
		hp.successCounts[snapshot.ServerID] = 0
	}); err != nil {
		return err
	}
	hp.notifyHealthDisabled(ctx, snapshot.ServerID, snapshot.ID)
	return nil
}

func (hp *HealthProber) transitionToThresholdDisabled(ctx context.Context, snapshot *models.BackendTunnel) error {
	if hp.pool != nil {
		swapped, casErr := hp.pool.CompareAndSwapTunnelStatusForTunnel(
			ctx,
			snapshot.ServerID,
			snapshot.ID,
			snapshot.Status,
			snapshot.DisableReason,
			snapshot.StateVersion,
			models.TunnelStatusDisabled,
			models.DisableReasonHealth,
			0,
		)
		if casErr != nil {
			return casErr
		}
		if swapped {
			snapshot.StateVersion++
			snapshot.Status = models.TunnelStatusDisabled
			snapshot.DisableReason = models.DisableReasonHealth
			// Terminal health disable committed: hand the established sessions
			// pinned to this backend to the data plane owner so it can migrate
			// them. Runs outside hp.mu/pool.mu and is idempotent.
			return hp.commitThresholdDisable(ctx, snapshot)
		}
		reconciled, recErr := hp.reconcileThresholdAutoDisable(ctx, snapshot.ServerID, snapshot.ID)
		if recErr != nil {
			return recErr
		}
		if !reconciled {
			hp.mu.Lock()
			if hp.failCounts[snapshot.ServerID] > 0 {
				hp.failCounts[snapshot.ServerID]--
			}
			hp.mu.Unlock()
		}
		return nil
	}
	snapshot.Status = models.TunnelStatusDisabled
	snapshot.DisableReason = models.DisableReasonHealth
	return hp.updateHealthIfCurrent(snapshot, func() {
		hp.autoDisabled[snapshot.ServerID] = true
		hp.successCounts[snapshot.ServerID] = 0
	})
}

func (hp *HealthProber) transitionToDegraded(ctx context.Context, snapshot *models.BackendTunnel) error {
	if snapshot.Status == "degraded" {
		return nil
	}
	if hp.pool != nil {
		swapped, casErr := hp.pool.CompareAndSwapTunnelStatusForTunnel(
			ctx, snapshot.ServerID, snapshot.ID, snapshot.Status, snapshot.DisableReason, snapshot.StateVersion, "degraded", snapshot.DisableReason, 0)
		if casErr != nil {
			return casErr
		}
		if !swapped {
			slog.Debug("probe degraded CAS missed due to concurrent tunnel update",
				"server_id", snapshot.ServerID, "expected_status", snapshot.Status, "expected_version", snapshot.StateVersion)
			hp.mu.Lock()
			if hp.failCounts[snapshot.ServerID] > 0 {
				hp.failCounts[snapshot.ServerID]--
			}
			hp.mu.Unlock()
			if hp.isTunnelAdminDisabled(snapshot.ServerID) {
				return hp.updateHealthIfCurrent(snapshot, func() {
					hp.failCounts[snapshot.ServerID] = 0
					delete(hp.autoDisabled, snapshot.ServerID)
				})
			}
			return nil
		}
		snapshot.StateVersion++
	}
	snapshot.Status = "degraded"
	return hp.updateHealthIfCurrent(snapshot, func() {
		hp.successCounts[snapshot.ServerID] = 0
	})
}

func (hp *HealthProber) handleHookFailure(ctx context.Context, snapshot *models.BackendTunnel, hookErr error) (int64, error) {
	if errors.Is(hookErr, ErrTunnelDisabled) || errors.Is(hp.checkTunnelAvailable(snapshot), ErrTunnelDisabled) || hp.isTunnelAdminDisabled(snapshot.ServerID) {
		hp.mu.Lock()
		hp.failCounts[snapshot.ServerID] = 0
		delete(hp.autoDisabled, snapshot.ServerID)
		hp.mu.Unlock()
		slog.Info("data-plane hook failed because tunnel was administratively disabled", "server_id", snapshot.ServerID)
		return 0, ErrTunnelDisabled
	}
	hp.mu.Lock()
	if err := hp.checkHealthGenerationLocked(snapshot); err != nil {
		hp.mu.Unlock()
		return 0, err
	}
	hp.failCounts[snapshot.ServerID]++
	failures := hp.failCounts[snapshot.ServerID]
	hp.mu.Unlock()

	if failures >= hp.cfg.FailureThreshold {
		if hp.pool != nil {
			swapped, casErr := hp.pool.CompareAndSwapTunnelStatusForTunnel(
				ctx,
				snapshot.ServerID,
				snapshot.ID,
				snapshot.Status,
				snapshot.DisableReason,
				snapshot.StateVersion,
				"disabled",
				models.DisableReasonHealth,
				0,
			)
			if casErr != nil {
				return 0, casErr
			}
			if swapped {
				snapshot.StateVersion++
				if err := hp.commitThresholdDisable(ctx, snapshot); err != nil {
					return 0, err
				}
			} else {
				reconciled, recErr := hp.reconcileThresholdAutoDisable(ctx, snapshot.ServerID, snapshot.ID)
				if recErr != nil {
					return 0, recErr
				}
				if !reconciled {
					hp.mu.Lock()
					if hp.failCounts[snapshot.ServerID] > 0 {
						hp.failCounts[snapshot.ServerID]--
					}
					hp.mu.Unlock()
				}
			}
		} else {
			if err := hp.updateHealthIfCurrent(snapshot, func() {
				hp.autoDisabled[snapshot.ServerID] = true
				hp.successCounts[snapshot.ServerID] = 0
			}); err != nil {
				return 0, err
			}
		}
	} else if hp.pool != nil {
		swapped, casErr := hp.pool.CompareAndSwapTunnelStatusForTunnel(
			ctx,
			snapshot.ServerID,
			snapshot.ID,
			snapshot.Status,
			snapshot.DisableReason,
			snapshot.StateVersion,
			"degraded",
			snapshot.DisableReason,
			0,
		)
		if casErr != nil {
			return 0, casErr
		}
		if !swapped {
			slog.Debug("hook failure degraded CAS missed due to concurrent tunnel update",
				"server_id", snapshot.ServerID,
				"expected_status", snapshot.Status,
				"expected_version", snapshot.StateVersion,
			)
			hp.mu.Lock()
			if hp.failCounts[snapshot.ServerID] > 0 {
				hp.failCounts[snapshot.ServerID]--
			}
			hp.mu.Unlock()
			if hp.isTunnelAdminDisabled(snapshot.ServerID) {
				if err := hp.updateHealthIfCurrent(snapshot, func() {
					hp.failCounts[snapshot.ServerID] = 0
					delete(hp.autoDisabled, snapshot.ServerID)
				}); err != nil {
					return 0, err
				}
			}
		} else {
			snapshot.StateVersion++
		}
	}
	if err := hp.checkTunnelAvailable(snapshot); errors.Is(err, ErrTunnelNotFound) {
		return 0, err
	}

	return 0, fmt.Errorf("data-plane readiness check failed: %w", hookErr)
}
