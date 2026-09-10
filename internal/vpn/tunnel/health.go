package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
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
	Interval           time.Duration
	Timeout            time.Duration
	LatencyThresholdMS int64
	FailureThreshold   int
	H1                 uint32
	H2                 uint32
	S1                 int
	S2                 int
}

// DefaultHealthConfig returns standard default prober settings.
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		Interval:           10 * time.Second,
		Timeout:            3 * time.Second,
		LatencyThresholdMS: 500,
		FailureThreshold:   3,
		H1:                 health.DefaultH1,
		H2:                 health.DefaultH2,
		S1:                 health.DefaultS1,
		S2:                 health.DefaultS2,
	}
}

// HealthProber periodically performs Noise IK handshake probes against backend tunnels.
type HealthProber struct {
	mu           sync.RWMutex
	pool         *Pool
	db           *database.DB
	cfg          HealthConfig
	probeFn      ProbeFunc
	onActiveHook func(ctx context.Context, tunnel *models.BackendTunnel) error
	failCounts   map[int64]int
	stopCh       chan struct{}
	wg           sync.WaitGroup
	running      bool
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

	pFn := health.ProbeAWGEndpointRange
	if len(probeFn) > 0 && probeFn[0] != nil {
		pFn = probeFn[0]
	}

	return &HealthProber{
		pool:       pool,
		db:         db,
		cfg:        cfg,
		probeFn:    pFn,
		failCounts: make(map[int64]int),
		stopCh:     make(chan struct{}),
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

// ResetFailCount clears the consecutive-failure counter for a backend server
// (issue #50). EnableBackend calls it when an administrator manually re-enables
// a health-auto-disabled tunnel: without the reset the counter stays at or
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

// ProbeTunnel executes a single Noise IK handshake probe against a backend tunnel and returns measured RTT.
// Administratively disabled tunnels are never probed and never have their status written:
// a healthy handshake would otherwise resurrect the tunnel (status write + onActiveHook
// device re-attach) and steer live sessions onto a blackhole, which is the root cause of
// issues #28/#43.
func (hp *HealthProber) ProbeTunnel(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}
	if tunnel.Status == "disabled" {
		slog.Info("skipping probe of administratively disabled tunnel", "tunnel_id", tunnel.ID, "server_id", tunnel.ServerID)
		return 0, ErrTunnelDisabled
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

	rtt, err := hp.probeFn(
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
		hp.cfg.Timeout,
	)

	latencyMS := int64(rtt.Milliseconds())
	if latencyMS <= 0 && err == nil {
		latencyMS = 1
	}

	if err != nil {
		hp.mu.Lock()
		defer hp.mu.Unlock()
		hp.failCounts[tunnel.ServerID]++
		failures := hp.failCounts[tunnel.ServerID]

		status := "degraded"
		if failures >= hp.cfg.FailureThreshold {
			status = "disabled"
		}

		if hp.pool != nil {
			_ = hp.pool.SetTunnelStatus(ctx, tunnel.ServerID, status, 0)
		}
		return 0, err
	}

	// Probe succeeded
	status := "active"
	if latencyMS > hp.cfg.LatencyThresholdMS {
		status = "degraded"
	}

	// If transitioning to active, verify data-plane readiness via hook
	if status == "active" {
		hp.mu.RLock()
		hook := hp.onActiveHook
		hp.mu.RUnlock()
		if hook != nil {
			if hookErr := hook(ctx, tunnel); hookErr != nil {
				hp.mu.Lock()
				defer hp.mu.Unlock()
				hp.failCounts[tunnel.ServerID]++
				failures := hp.failCounts[tunnel.ServerID]

				hookStatus := "degraded"
				if failures >= hp.cfg.FailureThreshold {
					hookStatus = "disabled"
				}

				if hp.pool != nil {
					_ = hp.pool.SetTunnelStatus(ctx, tunnel.ServerID, hookStatus, 0)
				}
				return 0, fmt.Errorf("data-plane readiness check failed: %w", hookErr)
			}
		}
	}

	hp.mu.Lock()
	defer hp.mu.Unlock()

	hp.failCounts[tunnel.ServerID] = 0
	if hp.pool != nil {
		_ = hp.pool.SetTunnelStatus(ctx, tunnel.ServerID, status, latencyMS)
	}

	return latencyMS, nil
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

// Start launches the periodic background probing loop.
func (hp *HealthProber) Start(ctx context.Context) {
	hp.mu.Lock()
	if hp.running {
		hp.mu.Unlock()
		return
	}
	hp.running = true
	hp.stopCh = make(chan struct{})
	hp.mu.Unlock()

	hp.wg.Add(1)
	go hp.probingLoop(ctx)
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
