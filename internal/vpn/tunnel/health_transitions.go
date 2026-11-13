package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// failureCategory identifies which consecutive-failure streak a decision is
// based on. Outer handshake failures and data-plane attachment failures are
// different observations, so a transition may only be completed by the streak
// that actually produced it.
type failureCategory int

const (
	// failureOuter is a failed outer handshake probe.
	failureOuter failureCategory = iota
	// failureAttachment is a failed data-plane attachment (active hook) run.
	failureAttachment
)

// failureCount returns the consecutive count for one category. Callers hold
// hp.mu.
func (hp *HealthProber) failureCount(serverID int64, category failureCategory) int {
	if category == failureAttachment {
		return hp.hookFailCounts[serverID]
	}
	return hp.failCounts[serverID]
}

// reconcileThresholdAutoDisable reconciles a missed threshold auto-disable CAS update
// caused by reverse failure ordering or concurrent state updates. category selects
// the streak the caller's threshold decision was based on, so a reconciliation
// cannot complete a threshold from unrelated failures.
func (hp *HealthProber) reconcileThresholdAutoDisable(ctx context.Context, serverID, expectedTunnelID int64, category failureCategory) (bool, error) {
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
			hp.resetFailureCountsLocked(serverID)
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
	count := hp.failureCount(serverID, category)
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
			hp.resetFailureCountsLocked(serverID)
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
		hp.resetFailureCountsLocked(snapshot.ServerID)
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
	threshold := hp.cfg.FailureThreshold
	hp.mu.Unlock()

	// Sanitized evidence for the last attempt: the outer exchange failed and the
	// inner data path was never reached on this attempt, so it contributes no
	// inner observation either way.
	hp.recordProbeAttempt(snapshot, OutcomeFailure, OutcomeNotRun)
	hp.recordFailureStreak(snapshot, FailureOuter, failures, threshold)

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
			hp.recordGateAtVersion(snapshot, GateOuterUnproven, time.Time{}, 0)
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
			hp.recordGateAtVersion(snapshot, GateHealthDisable, time.Time{}, 0)
			// Terminal health disable committed: hand the established sessions
			// pinned to this backend to the data plane owner so it can migrate
			// them. Runs outside hp.mu/pool.mu and is idempotent.
			return hp.commitThresholdDisable(ctx, snapshot)
		}
		reconciled, recErr := hp.reconcileThresholdAutoDisable(ctx, snapshot.ServerID, snapshot.ID, failureOuter)
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
					hp.resetFailureCountsLocked(snapshot.ServerID)
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

// preservableTunnelIdentity reports whether the caller's snapshot still
// describes an enabled, current tunnel, so a preservation verdict cannot be
// reached for a canceled probe, a deleted backend or an administrative disable.
func (hp *HealthProber) preservableTunnelIdentity(snapshot *models.BackendTunnel) bool {
	if snapshot == nil || hp.pool == nil {
		return false
	}
	cur, err := hp.pool.GetTunnel(snapshot.ServerID)
	return err == nil && cur != nil && cur.ID == snapshot.ID && cur.Enabled
}

// hookFailurePreservedByInnerEvidence reports whether a backend that has reached
// its attachment-failure threshold must nevertheless be kept routable because its
// existing attached device answers fresh matched in-tunnel replies.
//
// The deciding evidence is the same recorded-evidence oracle the blocked-backend
// admission path uses (probeCanary + CanaryAdmissible), so a fresh probe is taken
// and then required to be admissible for THIS tunnel generation and the device
// attached at that moment. That is what makes the refusal cases safe: no device
// yields no evidence, a failed canary withdraws rather than records success, a
// stale or previous-device record fails the freshness/identity check, and a
// concurrent device replacement invalidates the result.
//
// It is deliberately not a "preserve anyway" flag: when it returns false the
// caller executes the ordinary threshold withdrawal unchanged.
func (hp *HealthProber) hookFailurePreservedByInnerEvidence(ctx context.Context, snapshot *models.BackendTunnel) bool {
	if !hp.preservableTunnelIdentity(snapshot) {
		return false
	}
	cur, err := hp.pool.GetTunnel(snapshot.ServerID)
	if err != nil || cur == nil {
		return false
	}
	dev := hp.GetDevice(cur.ID)
	if dev == nil {
		// Without a usable attached device there is nothing to preserve and no
		// in-tunnel evidence can exist. (This also covers hasCanaryProber: a
		// non-nil device is itself the canary prober capability.)
		return false
	}
	if closer, ok := dev.(interface{ IsClosed() bool }); ok && closer.IsClosed() {
		// A closed device cannot answer the canary, so a preserved verdict here
		// would be unsupported.
		return false
	}
	if canaryErr := hp.probeCanary(ctx, cur); canaryErr != nil {
		slog.Warn("data-plane attach failed and the inner canary did not confirm; allowing the attachment threshold to withdraw the backend",
			"server_id", cur.ServerID, "tunnel_id", cur.ID, "error", canaryErr)
		return false
	}
	// Bind the verdict to the device attached NOW, not merely the one that
	// answered: a swap during the probe must not lend its result onward.
	if !hp.CanaryAdmissible(cur, canaryDeviceGeneration(hp.GetDevice(cur.ID))) {
		return false
	}
	slog.Warn("data-plane attach failed but the attached device answered fresh matched in-tunnel replies; preserving the backend and its established sessions",
		"server_id", cur.ServerID, "tunnel_id", cur.ID, "status", cur.Status)
	return true
}

func (hp *HealthProber) handleHookFailure(ctx context.Context, snapshot *models.BackendTunnel, hookErr error) (int64, error) {
	if errors.Is(hookErr, ErrTunnelDisabled) || errors.Is(hp.checkTunnelAvailable(snapshot), ErrTunnelDisabled) || hp.isTunnelAdminDisabled(snapshot.ServerID) {
		hp.mu.Lock()
		hp.resetFailureCountsLocked(snapshot.ServerID)
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
	// Attachment failures advance their own streak. Sharing the outer
	// handshake counter here would let one unattachable device complete a
	// threshold built from unrelated outer failures (and vice versa), which
	// withdraws a backend whose established data path was never shown to be
	// broken.
	failures := hp.recordHookFailureLocked(snapshot.ServerID)
	threshold := hp.cfg.FailureThreshold
	hp.mu.Unlock()

	hp.recordProbeAttempt(snapshot, OutcomeUnknown, OutcomeFailure)
	hp.recordFailureStreak(snapshot, FailureAttachment, failures, threshold)

	if failures >= hp.cfg.FailureThreshold {
		// An attachment failure is evidence that the attach ATTEMPT failed, not
		// evidence that the backend's established data path is gone. When the
		// device still attached to this backend answers fresh matched in-tunnel
		// replies, the owner's requirement is to keep that device and its routing
		// eligibility: withdrawal here would migrate sessions off a backend that
		// is demonstrably forwarding payload. The preserved label is
		// handshake_blocked, never active, so the backend stays truthful about a
		// failing attachment while remaining eligible exactly as the existing
		// preservation contract requires. Otherwise the ordinary withdrawal runs.
		if hp.hookFailurePreservedByInnerEvidence(ctx, snapshot) {
			_ = hp.transitionToHandshakeBlocked(ctx, snapshot)
			return 0, fmt.Errorf("data-plane readiness check failed (inner path still healthy): %w", hookErr)
		}
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
				reconciled, recErr := hp.reconcileThresholdAutoDisable(ctx, snapshot.ServerID, snapshot.ID, failureAttachment)
				if recErr != nil {
					return 0, recErr
				}
				if !reconciled {
					hp.mu.Lock()
					if hp.hookFailCounts[snapshot.ServerID] > 0 {
						hp.hookFailCounts[snapshot.ServerID]--
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
			if hp.hookFailCounts[snapshot.ServerID] > 0 {
				hp.hookFailCounts[snapshot.ServerID]--
			}
			hp.mu.Unlock()
			if hp.isTunnelAdminDisabled(snapshot.ServerID) {
				if err := hp.updateHealthIfCurrent(snapshot, func() {
					hp.resetFailureCountsLocked(snapshot.ServerID)
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
