package tunnel

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// MarkAutoDisabled marks a backend server as auto-disabled due to health probe failures.
func (hp *HealthProber) MarkAutoDisabled(serverID int64) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.recordCurrentGenerationLocked(serverID)
	hp.autoDisabled[serverID] = true
	hp.successCounts[serverID] = 0
}

// MarkAdminDisabled clears auto-disabled tracking and failure counters for a backend server when administratively disabled.
func (hp *HealthProber) MarkAdminDisabled(serverID int64) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.resetFailureCountsLocked(serverID)
	delete(hp.autoDisabled, serverID)
	delete(hp.successCounts, serverID)
	// An administrative disable withdraws admission authority immediately: the
	// backend must earn fresh evidence after it is re-enabled.
	delete(hp.canarySuccesses, serverID)
	hp.recordCurrentGenerationLocked(serverID)
}

// IsAutoDisabled reports whether a backend server is currently auto-disabled.
func (hp *HealthProber) IsAutoDisabled(serverID int64) bool {
	if hp == nil {
		return false
	}
	var currentID int64
	if hp.pool != nil {
		tun, err := hp.pool.GetTunnel(serverID)
		if err != nil || tun == nil || !tun.Enabled {
			return false
		}
		if tun.Status == "disabled" && tun.DisableReason == models.DisableReasonHealth {
			return true
		}
		currentID = tun.ID
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if gen := hp.healthGenerations[serverID]; hp.pool != nil && gen != 0 && gen != currentID {
		return false
	}
	return hp.autoDisabled[serverID]
}

// GetSelfHealingState returns the auto-disabled flag and consecutive probe successes for a server.
func (hp *HealthProber) GetSelfHealingState(serverID int64) (autoDisabled bool, consecutiveSuccesses int) {
	if hp == nil {
		return false, 0
	}
	var currentID int64
	if hp.pool != nil {
		current, err := hp.pool.GetTunnel(serverID)
		if err != nil || current == nil {
			return false, 0
		}
		currentID = current.ID
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if gen := hp.healthGenerations[serverID]; hp.pool != nil && gen != 0 && gen != currentID {
		return false, 0
	}
	return hp.autoDisabled[serverID], hp.successCounts[serverID]
}

// SetOnSelfHealHook registers a hook called to recover an auto-disabled backend tunnel.
func (hp *HealthProber) SetOnSelfHealHook(fn func(ctx context.Context, tunnel *models.BackendTunnel) error) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.onSelfHealHook = fn
}

// SetSelfHealingEnabled enables or disables the self-healing sweep.
func (hp *HealthProber) SetSelfHealingEnabled(enabled bool) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.cfg.DisableSelfHealing = !enabled
}

// SelfHealSweep sweeps auto-disabled tunnels and attempts to recover them with flap damping.
func (hp *HealthProber) SelfHealSweep(ctx context.Context) int {
	if hp == nil || hp.pool == nil {
		return 0
	}

	hp.mu.RLock()
	if hp.cfg.DisableSelfHealing {
		hp.mu.RUnlock()
		return 0
	}
	threshold := hp.cfg.SelfHealingThreshold
	latencyThreshold := hp.cfg.LatencyThresholdMS
	hp.mu.RUnlock()

	targets := hp.collectSelfHealTargets()
	if len(targets) == 0 {
		// Even with nothing to recover, an automatic failover that previously
		// found no target may now be completable (F16), so still let the data
		// plane owner settle its outstanding debt.
		hp.retryPendingFailovers(ctx)
		return 0
	}

	var wg sync.WaitGroup
	var reconnectedCount atomic.Int64

	for _, t := range targets {
		tun := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			if hp.reconcileTunnel(ctx, tun, threshold, latencyThreshold) {
				reconnectedCount.Add(1)
			}
		}()
	}

	wg.Wait()
	// A backend that just recovered may be exactly the alternative an earlier
	// health failover was waiting for, so settle that debt in the same sweep.
	hp.retryPendingFailovers(ctx)
	return int(reconnectedCount.Load())
}

// retryPendingFailovers invokes the data plane owner's unfinished-failover
// settlement, if one was registered. It runs outside hp.mu/pool.mu and never
// panics the sweep because of a nil/absent owner.
func (hp *HealthProber) retryPendingFailovers(ctx context.Context) {
	hp.mu.RLock()
	retry := hp.selfHealFailoverRetrier
	hp.mu.RUnlock()
	if retry == nil {
		return
	}
	retry(ctx)
}

func (hp *HealthProber) collectSelfHealTargets() []*models.BackendTunnel {
	tunnels := hp.pool.ListTunnels()
	var targets []*models.BackendTunnel
	hp.mu.RLock()
	multiProto := hp.multiProtocolEnabled
	hp.mu.RUnlock()

	for _, t := range tunnels {
		if !t.Enabled || t.Status != "disabled" {
			continue
		}
		if !multiProto && models.NormalizeTunnelProtocol(t.Protocol) != models.ProtocolAWG {
			continue
		}
		if t.DisableReason == models.DisableReasonHealth || hp.IsAutoDisabled(t.ServerID) {
			targets = append(targets, t)
		}
	}
	return targets
}

func (hp *HealthProber) reconcileTunnel(
	ctx context.Context,
	tun *models.BackendTunnel,
	threshold int,
	latencyThreshold int64,
) bool {
	if ctx.Err() != nil {
		return false
	}

	latencyMS, ready, outerFailed := hp.probeAndFlapDamp(ctx, tun, threshold)
	if outerFailed {
		// A failed outer handshake is not evidence that the established data
		// path is gone. The inner canary still decides, so a health-disabled
		// backend whose existing attached device answers fresh matched replies
		// can return to routing eligibility without waiting for outer success.
		return hp.recoverThroughInnerCanary(ctx, tun)
	}
	if !ready {
		return false
	}

	tunNow, ok := hp.verifyPreHookState(tun)
	if !ok {
		return false
	}

	if !hp.invokeSelfHealHook(ctx, tunNow) {
		return false
	}

	return hp.finalizeSelfHealRecovery(ctx, tun, tunNow, latencyMS, latencyThreshold)
}

// probeAndFlapDamp runs the outer handshake probe and the existing consecutive
// -success damping. outerFailed reports that the probe itself failed, which
// tells the caller the inner path still has to be consulted; it is distinct from
// the damping case where the outer path is healthy but has not yet confirmed.
func (hp *HealthProber) probeAndFlapDamp(
	ctx context.Context,
	tun *models.BackendTunnel,
	threshold int,
) (latencyMS int64, ready bool, outerFailed bool) {
	latencyMS, err := hp.probeEndpoint(ctx, tun)
	if err != nil {
		if hp.updateHealthIfCurrent(tun, func() { hp.successCounts[tun.ServerID] = 0 }) != nil {
			return 0, false, false
		}
		slog.Debug("self-healing probe failed", "server_id", tun.ServerID, "error", err)
		return 0, false, true
	}

	hp.mu.Lock()
	if hp.checkHealthGenerationLocked(tun) != nil {
		hp.mu.Unlock()
		return 0, false, false
	}
	hp.successCounts[tun.ServerID]++
	successes := hp.successCounts[tun.ServerID]
	hp.mu.Unlock()

	if successes < threshold {
		slog.Info("self-healing flap damping active",
			"server_id", tun.ServerID,
			"consecutive_successes", successes,
			"threshold", threshold,
		)
		return 0, false, false
	}
	return latencyMS, true, false
}

func (hp *HealthProber) verifyPreHookState(tun *models.BackendTunnel) (*models.BackendTunnel, bool) {
	tunNow, err := hp.pool.GetTunnel(tun.ServerID)
	if err != nil || tunNow == nil {
		return nil, false
	}
	if tunNow.ID != tun.ID ||
		!tunNow.Enabled ||
		tunNow.Status != "disabled" ||
		(tunNow.DisableReason != models.DisableReasonHealth && !hp.IsAutoDisabled(tun.ServerID)) ||
		tunNow.StateVersion != tun.StateVersion {
		slog.Info("self-healing aborted: tunnel state changed before hook",
			"server_id", tun.ServerID,
			"current_status", tunNow.Status,
			"current_reason", tunNow.DisableReason,
			"current_version", tunNow.StateVersion,
			"expected_version", tun.StateVersion,
		)
		return nil, false
	}
	return tunNow, true
}

func (hp *HealthProber) invokeSelfHealHook(ctx context.Context, tunNow *models.BackendTunnel) bool {
	hp.mu.RLock()
	hook := hp.onSelfHealHook
	if hook == nil {
		hook = hp.onActiveHook
	}
	hp.mu.RUnlock()

	if hook != nil {
		if hookErr := hook(ContextWithSelfHealing(ctx), tunNow); hookErr != nil {
			slog.Warn("self-healing hook failed", "server_id", tunNow.ServerID, "error", hookErr)
			if err := hp.updateHealthIfCurrent(tunNow, func() { hp.successCounts[tunNow.ServerID] = 0 }); err != nil {
				slog.Debug("self-healing hook result belongs to a retired tunnel", "server_id", tunNow.ServerID, "error", err)
			}
			return false
		}
	}
	return true
}

func (hp *HealthProber) determineSelfHealStatus(
	ctx context.Context,
	tun *models.BackendTunnel,
	latencyMS int64,
	latencyThreshold int64,
) string {
	if hp.hasCanaryProber(tun) {
		if canaryErr := hp.probeCanary(ctx, tun); canaryErr != nil {
			slog.Warn("self-healing outer probe succeeded but inner canary failed; denying self-healing recovery",
				"server_id", tun.ServerID,
				"tunnel_id", tun.ID,
				"error", canaryErr,
			)
			return ""
		}
	}
	if latencyMS > latencyThreshold {
		return "degraded"
	}
	return "active"
}

func (hp *HealthProber) finalizeSelfHealRecovery(
	ctx context.Context,
	tun *models.BackendTunnel,
	tunNow *models.BackendTunnel,
	latencyMS int64,
	latencyThreshold int64,
) bool {
	tunAfterHook, err := hp.pool.GetTunnel(tun.ServerID)
	if err != nil || tunAfterHook == nil || tunAfterHook.ID != tun.ID {
		return false
	}
	if !tunAfterHook.Enabled {
		slog.Warn("self-healing aborted: tunnel administratively disabled during hook execution",
			"server_id", tun.ServerID,
		)
		if err := hp.updateHealthIfCurrent(tun, func() {
			delete(hp.autoDisabled, tun.ServerID)
			delete(hp.successCounts, tun.ServerID)
		}); err != nil {
			return false
		}
		return false
	}

	newStatus := hp.determineSelfHealStatus(ctx, tunAfterHook, latencyMS, latencyThreshold)
	if newStatus == "" {
		slog.Warn("self-healing recovery denied: inner canary verification failed",
			"server_id", tun.ServerID,
			"tunnel_id", tun.ID,
		)
		return false
	}
	if hp.IsPendingEnrollment(tun.ServerID) {
		newStatus = models.TunnelStatusConnecting
	}

	return hp.commitSelfHealStatus(ctx, tun, tunNow, newStatus, latencyMS)
}

// recoverThroughInnerCanary restores routing eligibility for a health-disabled
// backend whose EXISTING attached device still answers matched in-tunnel
// replies while the outer handshake keeps failing.
//
// The status it establishes is handshake_blocked, never active: the outer
// handshake did not succeed, so claiming active (or a latency sample derived
// from a failed handshake) would be a false health report. handshake_blocked is
// exactly the truthful label for "outer path unproven, inner path fresh".
//
// It deliberately reuses the recorded canary evidence oracle instead of
// inventing a second verdict, which is what makes missing, stale, failed,
// late and previous-device evidence harmless: the sweep's own observation must
// be admissible for THIS tunnel generation and THIS attached device. A device
// replacement, detach, concurrent status write or administrative disable
// between the probe and the commit invalidates it.
//
// The attach hook is NOT run here. The device is already attached and just
// proved it forwards payload, so re-attaching would replace the very identity
// whose evidence authorized the recovery and would add remote I/O to a data
// path that is currently working.
func (hp *HealthProber) recoverThroughInnerCanary(ctx context.Context, tun *models.BackendTunnel) bool {
	if ctx.Err() != nil {
		return false
	}
	cur, ok := hp.verifyPreHookState(tun)
	if !ok {
		return false
	}
	// Enrollment quarantine is an independent authority, not a consequence of
	// canary evidence. Automatic recovery must not release it, and nothing
	// routable is lost by declining: disabled and connecting are both
	// non-routable, and only an explicit qualification/promotion transaction
	// releases the quarantine.
	if hp.IsPendingEnrollment(cur.ServerID) {
		return false
	}
	// No attached device means no in-tunnel evidence can exist for this backend.
	if !hp.hasCanaryProber(cur) {
		return false
	}
	if err := hp.probeCanary(ctx, cur); err != nil {
		// Obsolete evidence (tunnel replaced, version advanced, administrative
		// disable, cancellation) and genuine inner loss both keep the backend
		// withdrawn; only a fresh matched reply authorizes recovery.
		slog.Warn("self-healing inner-path recovery denied: canary did not confirm",
			"server_id", cur.ServerID,
			"tunnel_id", cur.ID,
			"error", err,
		)
		return false
	}
	// Bind the commit to the device attached NOW, not merely the one that
	// answered: a swap during the probe must not lend its verdict onward.
	// canaryDeviceGeneration yields the zero stamp for a replacement the probe
	// cannot verify, which CanaryAdmissible refuses.
	if !hp.CanaryAdmissible(cur, canaryDeviceGeneration(hp.GetDevice(cur.ID))) {
		return false
	}
	return hp.commitSelfHealStatus(ctx, tun, cur, models.TunnelStatusHandshakeBlocked, 0)
}

// commitSelfHealStatus performs the compare-and-swap that ends a self-healing
// recovery and the matching in-memory bookkeeping. It is shared by the
// outer-success and inner-canary recovery paths so both commit through one
// place with the same guards.
func (hp *HealthProber) commitSelfHealStatus(
	ctx context.Context,
	tun *models.BackendTunnel,
	tunNow *models.BackendTunnel,
	newStatus string,
	latencyMS int64,
) bool {
	swapped, err := hp.pool.CompareAndSwapTunnelStatusForTunnel(
		ctx,
		tun.ServerID,
		tun.ID,
		models.TunnelStatusDisabled,
		tunNow.DisableReason,
		tunNow.StateVersion,
		newStatus,
		models.DisableReasonNone,
		latencyMS,
	)
	if err != nil {
		slog.Error("self-healing CAS status update failed",
			"server_id", tun.ServerID,
			"error", err,
		)
		return false
	}
	if !swapped {
		slog.Info("self-healing CAS status update missed: state changed concurrently",
			"server_id", tun.ServerID,
		)
		return false
	}

	tun.StateVersion = tunNow.StateVersion + 1
	if err := hp.updateHealthIfCurrent(tun, func() {
		hp.resetFailureCountsLocked(tun.ServerID)
		delete(hp.autoDisabled, tun.ServerID)
		delete(hp.successCounts, tun.ServerID)
	}); err != nil {
		return false
	}

	slog.Info("self-healing successfully restored backend tunnel",
		"server_id", tun.ServerID,
		"tunnel_id", tun.ID,
		"status", newStatus,
		"latency_ms", latencyMS,
	)
	return true
}

type selfHealingContextKey struct{}

// ContextWithSelfHealing marks a context as originating from the self-healing sweep.
func ContextWithSelfHealing(ctx context.Context) context.Context {
	return context.WithValue(ctx, selfHealingContextKey{}, true)
}

// IsSelfHealingContext reports whether a context originated from the self-healing sweep.
func IsSelfHealingContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	val, ok := ctx.Value(selfHealingContextKey{}).(bool)
	return ok && val
}
