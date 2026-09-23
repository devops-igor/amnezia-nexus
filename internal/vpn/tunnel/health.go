package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
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
	mu             sync.RWMutex
	pool           *Pool
	db             *database.DB
	cfg            HealthConfig
	probeFn        ProbeFunc
	onActiveHook   func(ctx context.Context, tunnel *models.BackendTunnel) error
	onSelfHealHook func(ctx context.Context, tunnel *models.BackendTunnel) error
	failCounts     map[int64]int
	autoDisabled   map[int64]bool
	successCounts  map[int64]int
	stopCh         chan struct{}
	wg             sync.WaitGroup
	running        bool
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
		pool:          pool,
		db:            db,
		cfg:           cfg,
		probeFn:       pFn,
		failCounts:    make(map[int64]int),
		autoDisabled:  make(map[int64]bool),
		successCounts: make(map[int64]int),
		stopCh:        make(chan struct{}),
	}
}

// SetProbeFunc updates the probe function used by the health prober.
func (hp *HealthProber) SetProbeFunc(fn ProbeFunc) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if fn != nil {
		hp.probeFn = fn
	}
}

// SetOnActiveHook registers a hook called before transitioning a tunnel to active status.
// If the hook returns an error, the tunnel status remains degraded.
func (hp *HealthProber) SetOnActiveHook(fn func(ctx context.Context, tunnel *models.BackendTunnel) error) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.onActiveHook = fn
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
}

// Config returns a copy of the prober configuration.
func (hp *HealthProber) Config() HealthConfig {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.cfg
}

func paramsFromBackendServer(ctx context.Context, db *database.DB, serverID int64) (h1, h2 models.HeaderRange, s1, s2 int, hpKey string, found bool) {
	server, err := db.GetServer(ctx, serverID)
	if err != nil || server == nil || server.Protocols == nil {
		return models.HeaderRange{}, models.HeaderRange{}, -1, -1, "", false
	}
	awgInfo, ok := server.Protocols["awg"].(map[string]any)
	if !ok || awgInfo == nil {
		return models.HeaderRange{}, models.HeaderRange{}, -1, -1, "", false
	}
	var paramsObj any
	if p, ok := awgInfo["awg_params"]; ok && p != nil {
		paramsObj = p
	} else if p, ok := awgInfo["params"]; ok && p != nil {
		paramsObj = p
	} else {
		paramsObj = awgInfo
	}
	// Issue #49: extract H1/H2 as full HeaderRanges (AWG 3.1). The previous
	// ExtractAWGExplicitParams path truncated ranges to their lowest bound,
	// so range-configured backends failed response verification ~99.998% of
	// the time and were degraded then disabled after 3 cycles.
	rH1, rH2, rS1, rS2 := health.ExtractAWGHeaderRanges(paramsObj, health.DefaultH1, health.DefaultH2, health.DefaultS1, health.DefaultS2)
	_, _, _, _, explicit := health.ExtractAWGExplicitParams(paramsObj)
	if explicit {
		return rH1, rH2, rS1, rS2, health.ExtractHeaderProtectionKey(paramsObj), true
	}
	return models.HeaderRange{}, models.HeaderRange{}, -1, -1, "", false
}

func paramsFromVPNConfig(ctx context.Context, db *database.DB) (h1, h2 models.HeaderRange, s1, s2 int, found bool) {
	vpnCfg, err := db.GetVPNConfig(ctx)
	if err != nil || vpnCfg == nil {
		return models.HeaderRange{}, models.HeaderRange{}, -1, -1, false
	}
	// Issue #49: forward the stored ranges verbatim (PickOne belongs to the
	// prober's initiation builder, not to resolution).
	if !vpnCfg.H1.IsZero() || !vpnCfg.H2.IsZero() || vpnCfg.S1 >= 0 || vpnCfg.S2 >= 0 {
		return vpnCfg.H1, vpnCfg.H2, vpnCfg.S1, vpnCfg.S2, true
	}
	return models.HeaderRange{}, models.HeaderRange{}, -1, -1, false
}

// resolveTunnelParams returns H1, H2, S1, S2 for probing the specific backend tunnel,
// checking the backend's installed params first, then stored VPNConfig, then prober defaults.
// h1 and h2 carry models.HeaderRange (full AWG 3.1 ranges, issue #49); they are typed
// `any` to match ProbeFunc, which ProbeAWGEndpointRange accepts alongside uint32.
func (hp *HealthProber) resolveTunnelParams(ctx context.Context, serverID int64) (h1, h2 any, s1, s2 int, hpKey string) {
	h1, h2, s1, s2 = hp.cfg.H1, hp.cfg.H2, hp.cfg.S1, hp.cfg.S2
	if hp.db == nil {
		return h1, h2, s1, s2, ""
	}

	if bH1, bH2, bS1, bS2, bHPKey, ok := paramsFromBackendServer(ctx, hp.db, serverID); ok {
		if !bH1.IsZero() {
			h1 = bH1
		}
		if !bH2.IsZero() {
			h2 = bH2
		}
		if bS1 >= 0 {
			s1 = bS1
		}
		if bS2 >= 0 {
			s2 = bS2
		}
		return h1, h2, s1, s2, bHPKey
	}

	if vH1, vH2, vS1, vS2, ok := paramsFromVPNConfig(ctx, hp.db); ok {
		if !vH1.IsZero() {
			h1 = vH1
		}
		if !vH2.IsZero() {
			h2 = vH2
		}
		if vS1 >= 0 {
			s1 = vS1
		}
		if vS2 >= 0 {
			s2 = vS2
		}
		return h1, h2, s1, s2, ""
	}

	return h1, h2, s1, s2, ""
}

// probeEndpoint executes a single Noise IK handshake probe against a backend tunnel
// using its dedicated probe key without checking whether the tunnel is disabled.
func (hp *HealthProber) probeEndpoint(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}

	h1, h2, s1, s2, hpKey := hp.resolveTunnelParams(ctx, tunnel.ServerID)

	// Issue #43: probe from the tunnel's DEDICATED probe key, not the data
	// device key. The backend roams a peer's return endpoint to whichever
	// socket sent last; a probe sharing the data identity would redirect all
	// return traffic to the ephemeral prober socket, starving the data device.
	probePrivKey := tunnel.ProbePrivateKey
	if probePrivKey == "" {
		// Legacy tunnel not yet upgraded by EnsureBackendProbeKeys.
		probePrivKey = tunnel.PrivateKey
	}

	hp.mu.RLock()
	probeFn := hp.probeFn
	timeout := hp.cfg.Timeout
	hp.mu.RUnlock()

	rtt, err := probeFn(
		ctx,
		tunnel.Endpoint,
		tunnel.PublicKey,
		probePrivKey,
		"",
		hpKey,
		h1,
		h2,
		s1,
		s2,
		timeout,
	)

	latencyMS := int64(rtt.Milliseconds())
	if latencyMS <= 0 && err == nil {
		latencyMS = 1
	}

	if err != nil {
		return 0, err
	}
	return latencyMS, nil
}

func (hp *HealthProber) isTunnelDisabled(serverID int64) bool {
	if hp.pool == nil {
		return false
	}
	curTun, err := hp.pool.GetTunnel(serverID)
	if err != nil || curTun == nil {
		return false
	}
	return curTun.Status == "disabled" || curTun.DisableReason == models.DisableReasonAdmin
}

func (hp *HealthProber) isTunnelAdminDisabled(serverID int64) bool {
	if hp.pool == nil {
		return false
	}
	curTun, err := hp.pool.GetTunnel(serverID)
	if err != nil || curTun == nil {
		return false
	}
	return curTun.DisableReason == models.DisableReasonAdmin
}

func (hp *HealthProber) getInitialSnapshot(tunnel *models.BackendTunnel) *models.BackendTunnel {
	if hp.pool != nil {
		if cur, err := hp.pool.GetTunnel(tunnel.ServerID); err == nil && cur != nil {
			return cur
		}
	}
	return tunnel
}

// ProbeTunnel executes a single Noise IK handshake probe against a backend tunnel and returns measured RTT.
// Administratively disabled tunnels are never probed and never have their status written:
// a healthy handshake would otherwise resurrect the tunnel (status write + onActiveHook
// device re-attach) and steer live sessions onto a blackhole, which is the root cause of
// issues #28/#43.
func (hp *HealthProber) ProbeTunnel(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}

	snapshot := hp.getInitialSnapshot(tunnel)
	if snapshot.Status == "disabled" || snapshot.DisableReason == models.DisableReasonAdmin {
		slog.Info("skipping probe of administratively disabled tunnel", "tunnel_id", snapshot.ID, "server_id", snapshot.ServerID)
		return 0, ErrTunnelDisabled
	}

	latencyMS, err := hp.probeEndpoint(ctx, tunnel)
	if err != nil {
		return hp.handleProbeFailure(ctx, snapshot, err)
	}

	// Probe succeeded
	if hp.isTunnelDisabled(tunnel.ServerID) {
		slog.Info("probe succeeded but tunnel is disabled; skipping activation", "server_id", tunnel.ServerID)
		return 0, ErrTunnelDisabled
	}

	status := "active"
	if latencyMS > hp.cfg.LatencyThresholdMS {
		status = "degraded"
	}

	// If transitioning to active, verify data-plane readiness via hook
	if status == "active" {
		if _, hookErr := hp.executeActiveHook(ctx, snapshot, tunnel); hookErr != nil {
			return 0, hookErr
		}
	}

	// Re-check status before final status write
	if hp.isTunnelDisabled(tunnel.ServerID) {
		slog.Info("tunnel was disabled before status write; skipping", "server_id", tunnel.ServerID)
		return 0, ErrTunnelDisabled
	}

	hp.mu.Lock()
	hp.failCounts[tunnel.ServerID] = 0
	delete(hp.autoDisabled, tunnel.ServerID)
	delete(hp.successCounts, tunnel.ServerID)
	hp.mu.Unlock()

	if hp.pool != nil {
		if err := hp.pool.SetTunnelStatus(ctx, tunnel.ServerID, status, latencyMS); err != nil {
			return 0, err
		}
	}

	return latencyMS, nil
}

func (hp *HealthProber) executeActiveHook(ctx context.Context, snapshot, tunnel *models.BackendTunnel) (int64, error) {
	if hp.isTunnelDisabled(tunnel.ServerID) {
		slog.Info("aborting onActiveHook: tunnel is disabled", "server_id", tunnel.ServerID)
		return 0, ErrTunnelDisabled
	}

	hp.mu.RLock()
	hook := hp.onActiveHook
	hp.mu.RUnlock()
	if hook != nil {
		if hookErr := hook(ctx, tunnel); hookErr != nil {
			return hp.handleHookFailure(ctx, snapshot, hookErr)
		}
	}
	return 0, nil
}

func (hp *HealthProber) handleProbeFailure(ctx context.Context, snapshot *models.BackendTunnel, probeErr error) (int64, error) {
	hp.mu.Lock()
	if hp.isTunnelAdminDisabled(snapshot.ServerID) {
		hp.failCounts[snapshot.ServerID] = 0
		delete(hp.autoDisabled, snapshot.ServerID)
		hp.mu.Unlock()
		slog.Info("probe failed but tunnel was administratively disabled; ignoring failure", "server_id", snapshot.ServerID)
		return 0, probeErr
	}
	hp.failCounts[snapshot.ServerID]++
	failures := hp.failCounts[snapshot.ServerID]
	hp.mu.Unlock()

	if failures >= hp.cfg.FailureThreshold {
		if hp.pool != nil {
			swapped, casErr := hp.pool.CompareAndSwapTunnelStatus(
				ctx,
				snapshot.ServerID,
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
				hp.mu.Lock()
				hp.autoDisabled[snapshot.ServerID] = true
				hp.successCounts[snapshot.ServerID] = 0
				hp.mu.Unlock()
			} else if hp.isTunnelAdminDisabled(snapshot.ServerID) {
				slog.Info("probe auto-disable CAS missed due to concurrent admin disable", "server_id", snapshot.ServerID)
				hp.mu.Lock()
				delete(hp.autoDisabled, snapshot.ServerID)
				hp.failCounts[snapshot.ServerID] = 0
				hp.mu.Unlock()
			}
		} else {
			hp.mu.Lock()
			hp.autoDisabled[snapshot.ServerID] = true
			hp.successCounts[snapshot.ServerID] = 0
			hp.mu.Unlock()
		}
	} else if hp.pool != nil {
		if err := hp.pool.SetTunnelStatus(ctx, snapshot.ServerID, "degraded", 0); err != nil {
			return 0, err
		}
		if hp.isTunnelAdminDisabled(snapshot.ServerID) {
			hp.mu.Lock()
			hp.failCounts[snapshot.ServerID] = 0
			delete(hp.autoDisabled, snapshot.ServerID)
			hp.mu.Unlock()
		}
	}

	return 0, probeErr
}

func (hp *HealthProber) handleHookFailure(ctx context.Context, snapshot *models.BackendTunnel, hookErr error) (int64, error) {
	hp.mu.Lock()
	if errors.Is(hookErr, ErrTunnelDisabled) || hp.isTunnelDisabled(snapshot.ServerID) {
		hp.failCounts[snapshot.ServerID] = 0
		delete(hp.autoDisabled, snapshot.ServerID)
		hp.mu.Unlock()
		slog.Info("data-plane hook failed because tunnel was administratively disabled", "server_id", snapshot.ServerID)
		return 0, ErrTunnelDisabled
	}
	hp.failCounts[snapshot.ServerID]++
	failures := hp.failCounts[snapshot.ServerID]
	hp.mu.Unlock()

	if failures >= hp.cfg.FailureThreshold {
		if hp.pool != nil {
			swapped, casErr := hp.pool.CompareAndSwapTunnelStatus(
				ctx,
				snapshot.ServerID,
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
				hp.mu.Lock()
				hp.autoDisabled[snapshot.ServerID] = true
				hp.successCounts[snapshot.ServerID] = 0
				hp.mu.Unlock()
			} else if hp.isTunnelAdminDisabled(snapshot.ServerID) {
				slog.Info("hook failure auto-disable CAS missed due to concurrent admin disable", "server_id", snapshot.ServerID)
				hp.mu.Lock()
				delete(hp.autoDisabled, snapshot.ServerID)
				hp.failCounts[snapshot.ServerID] = 0
				hp.mu.Unlock()
			}
		} else {
			hp.mu.Lock()
			hp.autoDisabled[snapshot.ServerID] = true
			hp.successCounts[snapshot.ServerID] = 0
			hp.mu.Unlock()
		}
	} else if hp.pool != nil {
		if err := hp.pool.SetTunnelStatus(ctx, snapshot.ServerID, "degraded", 0); err != nil {
			return 0, err
		}
		if hp.isTunnelAdminDisabled(snapshot.ServerID) {
			hp.mu.Lock()
			hp.failCounts[snapshot.ServerID] = 0
			delete(hp.autoDisabled, snapshot.ServerID)
			hp.mu.Unlock()
		}
	}

	return 0, fmt.Errorf("data-plane readiness check failed: %w", hookErr)
}

// MarkAutoDisabled marks a backend server as auto-disabled due to health probe failures.
func (hp *HealthProber) MarkAutoDisabled(serverID int64) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
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
}

// IsAutoDisabled reports whether a backend server is currently auto-disabled.
func (hp *HealthProber) IsAutoDisabled(serverID int64) bool {
	if hp == nil {
		return false
	}
	if hp.pool != nil {
		if tun, err := hp.pool.GetTunnel(serverID); err == nil && tun != nil {
			if tun.DisableReason == models.DisableReasonAdmin {
				return false
			}
			if tun.Status == "disabled" && tun.DisableReason == models.DisableReasonHealth {
				return true
			}
		}
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.autoDisabled[serverID]
}

// GetSelfHealingState returns the auto-disabled flag and consecutive probe successes for a server.
func (hp *HealthProber) GetSelfHealingState(serverID int64) (autoDisabled bool, consecutiveSuccesses int) {
	if hp == nil {
		return false, 0
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
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
	for _, t := range tunnels {
		if t.Status != "disabled" || t.DisableReason == models.DisableReasonAdmin {
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
		hp.mu.Lock()
		hp.successCounts[tun.ServerID] = 0
		hp.mu.Unlock()
		slog.Debug("self-healing probe failed", "server_id", tun.ServerID, "error", err)
		return 0, false
	}

	hp.mu.Lock()
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
	if tunNow.Status != "disabled" ||
		tunNow.DisableReason == models.DisableReasonAdmin ||
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
			hp.mu.Lock()
			hp.successCounts[tunNow.ServerID] = 0
			hp.mu.Unlock()
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
	if err != nil || tunAfterHook == nil {
		return false
	}
	if tunAfterHook.DisableReason == models.DisableReasonAdmin {
		slog.Warn("self-healing aborted: tunnel administratively disabled during hook execution",
			"server_id", tun.ServerID,
		)
		hp.mu.Lock()
		delete(hp.autoDisabled, tun.ServerID)
		delete(hp.successCounts, tun.ServerID)
		hp.mu.Unlock()
		return false
	}

	newStatus := "active"
	if latencyMS > latencyThreshold {
		newStatus = "degraded"
	}

	swapped, err := hp.pool.CompareAndSwapTunnelStatus(
		ctx,
		tun.ServerID,
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

	hp.mu.Lock()
	hp.failCounts[tun.ServerID] = 0
	delete(hp.autoDisabled, tun.ServerID)
	delete(hp.successCounts, tun.ServerID)
	hp.mu.Unlock()

	slog.Info("self-healing successfully restored backend tunnel",
		"server_id", tun.ServerID,
		"tunnel_id", tun.ID,
		"status", newStatus,
		"latency_ms", latencyMS,
	)
	return true
}

// ProbeAll probes all backend tunnels concurrently and updates their statuses.
func (hp *HealthProber) ProbeAll(ctx context.Context) map[int64]error {
	if hp.pool == nil {
		return nil
	}

	tunnels := hp.pool.ListTunnels()
	results := make(map[int64]error)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range tunnels {
		if t.Status == "disabled" {
			// Administratively disabled tunnels are excluded from health
			// probing entirely: probing them can only resurrect them.
			continue
		}
		tunnel := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := hp.ProbeTunnel(ctx, tunnel)
			mu.Lock()
			results[tunnel.ServerID] = err
			mu.Unlock()
		}()
	}

	wg.Wait()
	return results
}

// Start launches the periodic background probing loop and self-healing sweep loop.
func (hp *HealthProber) Start(ctx context.Context) {
	hp.mu.Lock()
	if hp.running {
		hp.mu.Unlock()
		return
	}
	hp.running = true
	hp.stopCh = make(chan struct{})
	hp.mu.Unlock()

	hp.wg.Add(2)
	go hp.probingLoop(ctx)
	go hp.selfHealingLoop(ctx)
}

// Stop terminates the background prober.
func (hp *HealthProber) Stop() {
	hp.mu.Lock()
	if !hp.running {
		hp.mu.Unlock()
		return
	}
	hp.running = false
	close(hp.stopCh)
	hp.mu.Unlock()

	hp.wg.Wait()
}

// IsRunning returns true if the prober is running.
func (hp *HealthProber) IsRunning() bool {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.running
}

func (hp *HealthProber) probingLoop(ctx context.Context) {
	defer hp.wg.Done()
	ticker := time.NewTicker(hp.cfg.Interval)
	defer ticker.Stop()

	// Initial probe sweep
	_ = hp.ProbeAll(ctx)

	for {
		select {
		case <-hp.stopCh:
			return
		case <-ticker.C:
			_ = hp.ProbeAll(ctx)
		}
	}
}

func (hp *HealthProber) selfHealingLoop(ctx context.Context) {
	defer hp.wg.Done()

	hp.mu.RLock()
	interval := hp.cfg.SelfHealingInterval
	hp.mu.RUnlock()

	if interval <= 0 {
		interval = 1 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-hp.stopCh:
			return
		case <-ticker.C:
			_ = hp.SelfHealSweep(ctx)
		}
	}
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
