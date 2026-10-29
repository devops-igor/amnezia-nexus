package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
)

// ErrTunnelDisabled is returned when an operation is refused because the
// tunnel is administratively disabled.
var ErrTunnelDisabled = errors.New("tunnel is administratively disabled")

// ProbeFunc is a function type for executing Noise IK handshake probes to a UDP endpoint.
// h1 and h2 accept models.HeaderRange (AWG 3.1 header ranges, issue #49) or
// uint32 (legacy single-value headers); ProbeAWGEndpointRange handles both.
type ProbeFunc func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error)

// HealthConfig defines tuning parameters for the backend health prober.
type HealthConfig struct {
	Interval             time.Duration
	Timeout              time.Duration
	LatencyThresholdMS   int64
	FailureThreshold     int
	H1                   uint32
	H2                   uint32
	S1                   int
	S2                   int
	SelfHealingInterval  time.Duration
	SelfHealingThreshold int
	DisableSelfHealing   bool
}

// DefaultHealthConfig returns standard default prober settings.
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		Interval:             10 * time.Second,
		Timeout:              3 * time.Second,
		LatencyThresholdMS:   500,
		FailureThreshold:     3,
		H1:                   health.DefaultH1,
		H2:                   health.DefaultH2,
		S1:                   health.DefaultS1,
		S2:                   health.DefaultS2,
		SelfHealingInterval:  1 * time.Minute,
		SelfHealingThreshold: 2,
		DisableSelfHealing:   false,
	}
}

// HealthProber periodically performs Noise IK handshake probes against backend tunnels.
type HealthProber struct {
	mu                   sync.RWMutex
	pool                 *Pool
	db                   *database.DB
	cfg                  HealthConfig
	probeFn              ProbeFunc
	probeVLESSFn         VLESSProbeFunc
	probeNaiveFn         NaiveProbeFunc
	multiProtocolEnabled bool
	onActiveHook         func(ctx context.Context, tunnel *models.BackendTunnel) error
	onSelfHealHook       func(ctx context.Context, tunnel *models.BackendTunnel) error
	failCounts           map[int64]int
	autoDisabled         map[int64]bool
	successCounts        map[int64]int
	// Counter maps use server IDs for the public diagnostics API. This fence
	// records which tunnel generation owns each server's counters.
	healthGenerations    map[int64]int64
	preStatusCommitHook  func() // test synchronization, after the identity check
	preFailureCommitHook func() // test synchronization, after the identity check
	preActiveHookHook    func() // test synchronization, before executeActiveHook
	stopCh               chan struct{}
	wg                   sync.WaitGroup
	running              bool
}

// NewHealthProber initializes a new HealthProber instance.
func NewHealthProber(pool *Pool, db *database.DB, cfg HealthConfig, probeFn ...ProbeFunc) *HealthProber {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.LatencyThresholdMS <= 0 {
		cfg.LatencyThresholdMS = 500
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if cfg.H1 == 0 {
		cfg.H1 = health.DefaultH1
	}
	if cfg.H2 == 0 {
		cfg.H2 = health.DefaultH2
	}
	if cfg.S1 < 0 {
		cfg.S1 = health.DefaultS1
	}
	if cfg.S2 < 0 {
		cfg.S2 = health.DefaultS2
	}
	if cfg.SelfHealingInterval <= 0 {
		cfg.SelfHealingInterval = 1 * time.Minute
	}
	if cfg.SelfHealingThreshold <= 0 {
		cfg.SelfHealingThreshold = 2
	}

	pFn := health.ProbeAWGEndpointRange
	if len(probeFn) > 0 && probeFn[0] != nil {
		pFn = probeFn[0]
	}

	return &HealthProber{
		pool:              pool,
		db:                db,
		cfg:               cfg,
		probeFn:           pFn,
		probeVLESSFn:      vless.ProbeVLESSReality,
		probeNaiveFn:      naive.ProbeNaiveProxy,
		failCounts:        make(map[int64]int),
		autoDisabled:      make(map[int64]bool),
		successCounts:     make(map[int64]int),
		healthGenerations: make(map[int64]int64),
		stopCh:            make(chan struct{}),
	}
}

// SetMultiProtocolEnabled configures whether the prober inspects proxy tunnels.
func (hp *HealthProber) SetMultiProtocolEnabled(enabled bool) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.multiProtocolEnabled = enabled
}

// MultiProtocolEnabled reports whether the prober inspects proxy tunnels.
func (hp *HealthProber) MultiProtocolEnabled() bool {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.multiProtocolEnabled
}

// SetOnActiveHook registers a hook called before transitioning a tunnel to active status.
// If the hook returns an error, the tunnel status remains degraded.
func (hp *HealthProber) SetOnActiveHook(fn func(ctx context.Context, tunnel *models.BackendTunnel) error) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.onActiveHook = fn
}

// SetPreActiveHookHook registers a test hook called immediately before executeActiveHook.
func (hp *HealthProber) SetPreActiveHookHook(fn func()) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.preActiveHookHook = fn
}

// ResetFailCount clears the consecutive-failure counter, auto-disabled state,
// and consecutive-success counter for a backend server (issues #50, #279).
// EnableBackend calls it when an administrator manually re-enables a
// health-auto-disabled tunnel: without the reset the counter stays at or
// above FailureThreshold, so the first failed probe after re-enable would
// instantly re-disable the backend instead of granting the full grace period.
// Nil-receiver safe, matching SetProbeFunc's guard style.
func (hp *HealthProber) ResetFailCount(serverID int64) {
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

// GetFailCount returns the consecutive failure count for the given server ID.
// Nil-receiver safe.
func (hp *HealthProber) GetFailCount(serverID int64) int {
	if hp == nil {
		return 0
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.failCounts[serverID]
}

// recordCurrentGenerationLocked associates server-level state with the pool's
// current tunnel after an explicit health reset or administrative change.
func (hp *HealthProber) recordCurrentGenerationLocked(serverID int64) {
	if hp.pool == nil {
		return
	}
	current, err := hp.pool.GetTunnel(serverID)
	if err != nil || current == nil {
		delete(hp.healthGenerations, serverID)
		return
	}
	if previous := hp.healthGenerations[serverID]; previous != 0 && previous != current.ID {
		hp.failCounts[serverID] = 0
		delete(hp.autoDisabled, serverID)
		delete(hp.successCounts, serverID)
	}
	hp.healthGenerations[serverID] = current.ID
}

// checkHealthGenerationLocked prevents a stale probe from changing even the
// server-keyed health counters after a backend is deleted and recreated.
func (hp *HealthProber) checkHealthGenerationLocked(t *models.BackendTunnel) error {
	if hp.pool != nil {
		current, err := hp.pool.GetTunnel(t.ServerID)
		if err != nil {
			return err
		}
		if current == nil || current.ID != t.ID {
			return ErrTunnelNotFound
		}
		if t.StateVersion > 0 && current.StateVersion != t.StateVersion {
			return ErrStaleStateVersion
		}
	}
	if previous := hp.healthGenerations[t.ServerID]; previous != 0 && previous != t.ID {
		hp.failCounts[t.ServerID] = 0
		delete(hp.autoDisabled, t.ServerID)
		delete(hp.successCounts, t.ServerID)
	}
	hp.healthGenerations[t.ServerID] = t.ID
	return nil
}

func (hp *HealthProber) updateHealthIfCurrent(t *models.BackendTunnel, update func()) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if err := hp.checkHealthGenerationLocked(t); err != nil {
		return err
	}
	update()
	return nil
}

// Config returns a copy of the prober configuration.
func (hp *HealthProber) Config() HealthConfig {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.cfg
}

// probeEndpoint dispatches the probe according to the backend tunnel's protocol.
func (hp *HealthProber) probeEndpoint(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}

	proto := models.NormalizeTunnelProtocol(tunnel.Protocol)
	switch proto {
	case models.ProtocolAWG:
		return hp.probeAWG(ctx, tunnel)
	case models.ProtocolVLESS:
		return hp.probeVLESS(ctx, tunnel)
	case models.ProtocolNaive:
		return hp.probeNaive(ctx, tunnel)
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", tunnel.Protocol)
	}
}

// checkTunnelAvailable rejects a stale probe if its pool entry was deleted or
// replaced, as well as tunnels that were disabled while the probe was running.
func (hp *HealthProber) checkTunnelAvailable(tunnel *models.BackendTunnel) error {
	if hp.pool == nil {
		return nil
	}
	curTun, err := hp.pool.GetTunnel(tunnel.ServerID)
	if err != nil {
		return err
	}
	if curTun == nil || curTun.ID != tunnel.ID {
		return ErrTunnelNotFound
	}
	if !curTun.Enabled || curTun.Status == models.TunnelStatusDisabled {
		return ErrTunnelDisabled
	}
	if tunnel.StateVersion > 0 && curTun.StateVersion != tunnel.StateVersion {
		return ErrStaleStateVersion
	}
	return nil
}

func (hp *HealthProber) isTunnelAdminDisabled(serverID int64) bool {
	if hp.pool == nil {
		return false
	}
	curTun, err := hp.pool.GetTunnel(serverID)
	if err != nil || curTun == nil {
		return false
	}
	return !curTun.Enabled
}

func (hp *HealthProber) getInitialSnapshot(tunnel *models.BackendTunnel) *models.BackendTunnel {
	if hp.pool != nil {
		if cur, err := hp.pool.GetTunnel(tunnel.ServerID); err == nil && cur != nil {
			return cur
		}
	}
	return tunnel
}

// ProbeTunnel executes a single handshake or proxy probe against a backend tunnel and returns measured RTT.
// Administratively disabled tunnels are never probed and never have their status written:
// a healthy handshake would otherwise resurrect the tunnel (status write + onActiveHook
// device re-attach) and steer live sessions onto a blackhole, which is the root cause of
// issues #28/#43.
func (hp *HealthProber) ProbeTunnel(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}

	snapshot := hp.getInitialSnapshot(tunnel)
	if err := hp.checkTunnelAvailable(snapshot); err != nil {
		return 0, err
	}
	if !snapshot.Enabled {
		slog.Info("skipping probe of administratively disabled tunnel", "tunnel_id", snapshot.ID, "server_id", snapshot.ServerID)
		return 0, ErrTunnelDisabled
	}
	probeTarget := *tunnel
	probeTarget.StateVersion = snapshot.StateVersion
	probeTarget.Endpoint = snapshot.Endpoint

	latencyMS, err := hp.probeEndpoint(ctx, &probeTarget)
	if err != nil {
		if stateErr := hp.checkTunnelAvailable(&probeTarget); stateErr != nil {
			return 0, stateErr
		}
		if hp.preFailureCommitHook != nil {
			hp.preFailureCommitHook()
		}
		return hp.handleProbeFailure(ctx, snapshot, err)
	}

	// Probe succeeded
	if err := hp.checkTunnelAvailable(&probeTarget); err != nil {
		return 0, err
	}

	status := "active"
	if latencyMS > hp.cfg.LatencyThresholdMS {
		status = "degraded"
	}

	// If transitioning to active, verify data-plane readiness via hook
	if status == "active" {
		hp.mu.RLock()
		preActiveHook := hp.preActiveHookHook
		hp.mu.RUnlock()
		if preActiveHook != nil {
			preActiveHook()
		}
		if _, hookErr := hp.executeActiveHook(ctx, snapshot, &probeTarget); hookErr != nil {
			return 0, hookErr
		}
	}

	// Re-check status before final status write
	if err := hp.checkTunnelAvailable(&probeTarget); err != nil {
		return 0, err
	}
	if hp.preStatusCommitHook != nil {
		hp.preStatusCommitHook()
	}

	if hp.pool != nil {
		expectedVersion := probeTarget.StateVersion
		if snapshot != nil && snapshot.StateVersion > 0 {
			expectedVersion = snapshot.StateVersion
		}
		if err := hp.pool.SetTunnelStatusIfCurrentWithVersion(ctx, probeTarget.ServerID, probeTarget.ID, expectedVersion, status, latencyMS); err != nil {
			return 0, err
		}
		probeTarget.StateVersion = expectedVersion + 1
	}
	if err := hp.checkTunnelAvailable(&probeTarget); err != nil {
		return 0, err
	}
	hp.mu.Lock()
	if err := hp.checkHealthGenerationLocked(&probeTarget); err != nil {
		hp.mu.Unlock()
		return 0, err
	}
	hp.failCounts[probeTarget.ServerID] = 0
	delete(hp.autoDisabled, probeTarget.ServerID)
	delete(hp.successCounts, probeTarget.ServerID)
	hp.mu.Unlock()

	return latencyMS, nil
}

func (hp *HealthProber) executeActiveHook(ctx context.Context, snapshot, tunnel *models.BackendTunnel) (int64, error) {
	if err := hp.checkTunnelAvailable(tunnel); err != nil {
		return 0, err
	}
	if snapshot != nil {
		if err := hp.checkTunnelAvailable(snapshot); err != nil {
			return 0, err
		}
	}

	hp.mu.RLock()
	hook := hp.onActiveHook
	hp.mu.RUnlock()
	if hook != nil {
		if err := hp.checkTunnelAvailable(tunnel); err != nil {
			return 0, err
		}
		if snapshot != nil {
			if err := hp.checkTunnelAvailable(snapshot); err != nil {
				return 0, err
			}
		}
		if hookErr := hook(ctx, tunnel); hookErr != nil {
			if errors.Is(hookErr, ErrTunnelNotFound) || errors.Is(hookErr, ErrStaleStateVersion) {
				return 0, hookErr
			}
			if err := hp.checkTunnelAvailable(tunnel); errors.Is(err, ErrTunnelNotFound) || errors.Is(err, ErrStaleStateVersion) {
				return 0, err
			}
			return hp.handleHookFailure(ctx, snapshot, hookErr)
		}
	}
	return 0, nil
}

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
		if err := hp.updateHealthIfCurrent(currentTunnel, func() {
			hp.autoDisabled[serverID] = true
			hp.successCounts[serverID] = 0
		}); err != nil {
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
				if err := hp.updateHealthIfCurrent(snapshot, func() {
					hp.autoDisabled[snapshot.ServerID] = true
					hp.successCounts[snapshot.ServerID] = 0
				}); err != nil {
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
		if snapshot.Status != "degraded" {
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
				slog.Debug("probe degraded CAS missed due to concurrent tunnel update",
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
	}
	if err := hp.checkTunnelAvailable(snapshot); errors.Is(err, ErrTunnelNotFound) {
		return 0, err
	}

	return 0, probeErr
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
				if err := hp.updateHealthIfCurrent(snapshot, func() {
					hp.autoDisabled[snapshot.ServerID] = true
					hp.successCounts[snapshot.ServerID] = 0
				}); err != nil {
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
