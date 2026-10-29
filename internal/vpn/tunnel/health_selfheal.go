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
	hp.failCounts[serverID] = 0
	delete(hp.autoDisabled, serverID)
	delete(hp.successCounts, serverID)
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
	return int(reconnectedCount.Load())
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

	latencyMS, ok := hp.probeAndFlapDamp(ctx, tun, threshold)
	if !ok {
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

func (hp *HealthProber) probeAndFlapDamp(
	ctx context.Context,
	tun *models.BackendTunnel,
	threshold int,
) (int64, bool) {
	latencyMS, err := hp.probeEndpoint(ctx, tun)
	if err != nil {
		if hp.updateHealthIfCurrent(tun, func() { hp.successCounts[tun.ServerID] = 0 }) != nil {
			return 0, false
		}
		slog.Debug("self-healing probe failed", "server_id", tun.ServerID, "error", err)
		return 0, false
	}

	hp.mu.Lock()
	if hp.checkHealthGenerationLocked(tun) != nil {
		hp.mu.Unlock()
		return 0, false
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
		return 0, false
	}
	return latencyMS, true
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

	newStatus := "active"
	if latencyMS > latencyThreshold {
		newStatus = "degraded"
	}

	swapped, err := hp.pool.CompareAndSwapTunnelStatusForTunnel(
		ctx,
		tun.ServerID,
		tun.ID,
		"disabled",
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
		hp.failCounts[tun.ServerID] = 0
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
