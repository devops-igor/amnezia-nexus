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
	SubnetCIDR           string
}

// HealthProberConfig is an alias for HealthConfig.
type HealthProberConfig = HealthConfig

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
		SubnetCIDR:           "10.100.0.0/16",
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
	probeCanaryFn        CanaryProbeFunc
	deviceProvider       func(tunnelID int64) PacketDevice
	devices              map[int64]PacketDevice
	multiProtocolEnabled bool
	onActiveHook         func(ctx context.Context, tunnel *models.BackendTunnel) error
	onSelfHealHook       func(ctx context.Context, tunnel *models.BackendTunnel) error
	failCounts           map[int64]int
	// hookFailCounts counts consecutive data-plane ATTACHMENT failures for a
	// backend, independently of failCounts (outer handshake failures). The two
	// observations are about different things, so neither may complete the
	// other's consecutive threshold: one attachment failure after a long outer
	// outage used to reach FailureThreshold immediately and withdraw a backend
	// whose established data path had never been shown to be broken.
	hookFailCounts   map[int64]int
	canaryFailCounts map[int64]int
	canarySequence   uint64
	canaryResults    map[int64]canaryResult
	// canarySuccesses records the last accepted inner success per server, bound
	// to the tunnel generation and the backend device that produced it. It is
	// the evidence a NEW admission onto a handshake-blocked backend needs; the
	// status label is not.
	canarySuccesses map[int64]canarySuccess
	// nowFn is the injectable time source for evidence freshness. Nil means the
	// wall clock. Swapped only by SetNowFuncForTest before a fixture reads it.
	nowFn         func() time.Time
	autoDisabled  map[int64]bool
	successCounts map[int64]int
	// Counter maps use server IDs for the public diagnostics API. This fence
	// records which tunnel generation owns each server's counters.
	healthGenerations    map[int64]int64
	preStatusCommitHook  func() // test synchronization, after the identity check
	preFailureCommitHook func() // test synchronization, after the identity check
	preActiveHookHook    func() // test synchronization, before executeActiveHook
	// healthDisabledNotifier carries the terminal health auto-disable to the
	// data plane owner so established sessions pinned to the backend move off
	// it. Nil means "status only", the historical behavior.
	healthDisabledNotifier func(ctx context.Context, tunnel *models.BackendTunnel) error
	// selfHealFailoverRetrier settles an automatic failover that could not
	// complete when it was first attempted (F16). Invoked by the bounded
	// self-healing sweep, never by the probe hot path.
	selfHealFailoverRetrier func(ctx context.Context) int
	// proxyTrafficProbeFn performs the protocol-appropriate authenticated
	// application exchange required before a proxy backend is admitted
	// (finding F10). Nil falls back to the real VLESS/Naive traffic probes.
	proxyTrafficProbeFn ProxyTrafficProbeFunc
	// proxyCanaryDestination overrides the proxy payload canary destination for
	// local fixtures only (SetProxyCanaryDestinationForTest). Empty in production,
	// where the destination comes from the tunnel's own protocol parameters.
	proxyCanaryDestination string
	// pendingEnrollment marks backends still inside initial enrollment
	// qualification. While set, handshake-only probe success must not promote
	// the backend out of connecting.
	pendingEnrollment map[int64]bool
	// pendingEnrollmentGeneration records which TUNNEL GENERATION established each
	// runtime quarantine. A removal identifies its own generation, so a release
	// scheduled for a retired backend cannot clear the quarantine a replacement
	// established in the same server slot after matcher.
	pendingEnrollmentGeneration map[int64]int64
	stopCh                      chan struct{}
	wg                          sync.WaitGroup
	running                     bool
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
	if cfg.SubnetCIDR == "" {
		cfg.SubnetCIDR = "10.100.0.0/16"
	}

	pFn := health.ProbeAWGEndpointRange
	if len(probeFn) > 0 && probeFn[0] != nil {
		pFn = probeFn[0]
	}

	hp := &HealthProber{
		pool:                        pool,
		db:                          db,
		cfg:                         cfg,
		probeFn:                     pFn,
		probeVLESSFn:                vless.ProbeVLESSReality,
		probeNaiveFn:                naive.ProbeNaiveProxy,
		devices:                     make(map[int64]PacketDevice),
		failCounts:                  make(map[int64]int),
		hookFailCounts:              make(map[int64]int),
		canaryFailCounts:            make(map[int64]int),
		autoDisabled:                make(map[int64]bool),
		successCounts:               make(map[int64]int),
		healthGenerations:           make(map[int64]int64),
		pendingEnrollment:           make(map[int64]bool),
		pendingEnrollmentGeneration: make(map[int64]int64),
		stopCh:                      make(chan struct{}),
	}
	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if pendingMap, err := db.GetBackendPendingEnrollments(ctx); err == nil {
			for sid, isPending := range pendingMap {
				if isPending {
					hp.pendingEnrollment[sid] = true
				}
			}
		}
	}
	hp.ownPoolEnrollmentLifecycle()
	return hp
}

// ownPoolEnrollmentLifecycle registers this prober as the runtime enrollment
// owner for its pool, so a tunnel removal releases both markers. Split out of
// NewHealthProber to keep that constructor's branching from growing.
func (hp *HealthProber) ownPoolEnrollmentLifecycle() {
	if hp == nil || hp.pool == nil {
		return
	}
	hp.pool.SetEnrollmentReleaseHook(func(_ context.Context, serverID, retiredTunnelID int64) {
		hp.releaseRuntimeEnrollmentIfGeneration(serverID, retiredTunnelID)
	})
}

// releaseRuntimeEnrollment clears the in-memory enrollment marker for a server
// whose tunnel was just removed. It never writes the durable setting: the pool
// removal owns that row, and this callback exists so the two owners cannot drift
// apart. Nil-receiver and lock-order safe: it takes only hp.mu and does no I/O.
// releaseRuntimeEnrollmentIfGeneration clears the runtime marker only when it was
// established by the SAME tunnel generation being retired.
//
// A release is scheduled from a removal, and the pool lock is not held while it
// runs, so a replacement can be added and quarantined in that window. Without the
// generation check the retired release would clear the replacement's gate and the
// new backend would be admitted without qualification. retiredTunnelID is the
// identity RemoveTunnel actually deleted; a marker owned by any other generation
// is left untouched.
func (hp *HealthProber) releaseRuntimeEnrollmentIfGeneration(serverID, retiredTunnelID int64) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.pendingEnrollment == nil || !hp.pendingEnrollment[serverID] {
		return
	}
	// Zero means the marker predates generation tracking (constructed from durable
	// state at startup): it cannot be attributed to a replacement, so the retired
	// release still owns it.
	owner := hp.pendingEnrollmentGeneration[serverID]
	if owner != 0 && retiredTunnelID != 0 && owner != retiredTunnelID {
		return
	}
	delete(hp.pendingEnrollment, serverID)
	delete(hp.pendingEnrollmentGeneration, serverID)
}

// SetPendingEnrollment sets whether a backend server is currently undergoing initial enrollment qualification.
// While guarded, outer handshake-only probes will not commit active status, keeping the backend quarantined as connecting.
func (hp *HealthProber) SetPendingEnrollment(serverID int64, pending bool) {
	if hp == nil {
		return
	}
	hp.mu.Lock()
	if hp.pendingEnrollment == nil {
		hp.pendingEnrollment = make(map[int64]bool)
	}
	if pending {
		hp.pendingEnrollment[serverID] = true
		// Bind the marker to the tunnel generation that now owns this server slot.
		// Without it a retired removal cannot tell its own marker from a
		// replacement's and would clear the wrong one.
		if hp.pool != nil {
			if cur, err := hp.pool.GetTunnel(serverID); err == nil && cur != nil {
				if hp.pendingEnrollmentGeneration == nil {
					hp.pendingEnrollmentGeneration = make(map[int64]int64)
				}
				hp.pendingEnrollmentGeneration[serverID] = cur.ID
			}
		}
	} else {
		delete(hp.pendingEnrollment, serverID)
		delete(hp.pendingEnrollmentGeneration, serverID)
	}
	db := hp.db
	hp.mu.Unlock()

	if db != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = db.SetBackendPendingEnrollment(ctx, serverID, pending)
	}
}

// IsPendingEnrollment reports whether a backend server is currently undergoing initial enrollment qualification.
func (hp *HealthProber) IsPendingEnrollment(serverID int64) bool {
	if hp == nil {
		return false
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.pendingEnrollment != nil && hp.pendingEnrollment[serverID]
}

// LatencyThresholdMS returns the configured latency threshold in milliseconds.
func (hp *HealthProber) LatencyThresholdMS() int64 {
	if hp == nil {
		return 500
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if hp.cfg.LatencyThresholdMS <= 0 {
		return 500
	}
	return hp.cfg.LatencyThresholdMS
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
	hp.resetFailureCountsLocked(serverID)
	delete(hp.canaryFailCounts, serverID)
	delete(hp.canaryResults, serverID)
	delete(hp.canarySuccesses, serverID)
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

// resetFailureCountsLocked clears every consecutive-failure category for a
// backend. Callers hold hp.mu.
//
// Both categories are cleared together on purpose: a successful observation of
// either kind (a completed outer handshake or a successful attachment) ends the
// streak for the backend as a whole, and keeping the two in step here means no
// future reset site can silently leave one category primed to combine with the
// other later.
func (hp *HealthProber) resetFailureCountsLocked(serverID int64) {
	hp.failCounts[serverID] = 0
	hp.hookFailCounts[serverID] = 0
}

// recordHookFailureLocked increments the consecutive data-plane attachment
// failure count and returns it. This is a separate category from
// failCounts (outer handshake failures), so it can only ever be completed by
// further attachment failures. Callers hold hp.mu.
func (hp *HealthProber) recordHookFailureLocked(serverID int64) int {
	if hp.hookFailCounts == nil {
		hp.hookFailCounts = make(map[int64]int)
	}
	hp.hookFailCounts[serverID]++
	return hp.hookFailCounts[serverID]
}

// hookFailures returns the consecutive attachment-failure count for a server.
func (hp *HealthProber) hookFailures(serverID int64) int {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.hookFailCounts[serverID]
}

// GetCanaryFailCount returns the consecutive data-plane canary failure count for the given server ID.
// Nil-receiver safe.
func (hp *HealthProber) GetCanaryFailCount(serverID int64) int {
	if hp == nil {
		return 0
	}
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	if hp.canaryFailCounts == nil {
		return 0
	}
	return hp.canaryFailCounts[serverID]
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
		hp.resetFailureCountsLocked(serverID)
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
		hp.resetFailureCountsLocked(t.ServerID)
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

	// Issue #713: Before promoting ANY backend to active (whether recovering from
	// handshake_blocked, connecting, or degraded), verify real data-plane transit via inner canary.
	isBlocked := (snapshot != nil && snapshot.Status == models.TunnelStatusHandshakeBlocked) ||
		probeTarget.Status == models.TunnelStatusHandshakeBlocked

	status := "active"
	if latencyMS > hp.cfg.LatencyThresholdMS {
		status = "degraded"
	}
	isPending := hp.checkAndRecordPendingEnrollment(ctx, probeTarget.ServerID)
	if isPending {
		status = models.TunnelStatusConnecting
	}

	if status == "active" {
		if err := hp.runActiveHookIfActive(ctx, snapshot, &probeTarget, status); err != nil {
			return 0, err
		}
	}

	if status == "active" || isBlocked {
		eligible, elErr := hp.verifyActiveEligibility(ctx, snapshot, &probeTarget, isBlocked)
		if elErr != nil {
			return 0, elErr
		}
		if !eligible {
			return latencyMS, nil
		}
	}

	// A slow successful outer sample is not evidence that the inner plane was
	// lost. Degraded status is exactly what makes established sessions
	// migration-eligible, so an already-blocked backend that still serves
	// sessions keeps its preservation status and only refreshes the latency
	// diagnostic. Inner loss still reaches degraded above through the
	// threshold path in verifyActiveEligibility, and fast recovery is unaffected
	// because it computes "active", not "degraded".
	status = hp.preservedProbeStatus(snapshot, &probeTarget, isBlocked, status)

	// Re-check status before final status write
	if err := hp.checkTunnelAvailable(&probeTarget); err != nil {
		return 0, err
	}
	if hp.preStatusCommitHook != nil {
		hp.preStatusCommitHook()
	}

	if err := hp.commitActiveProbeSuccess(ctx, snapshot, &probeTarget, status, latencyMS); err != nil {
		return 0, err
	}

	return latencyMS, nil
}

func (hp *HealthProber) commitActiveProbeSuccess(ctx context.Context, snapshot, probeTarget *models.BackendTunnel, status string, latencyMS int64) error {
	// A backend still inside initial enrollment qualification must stay
	// connecting even when the outer probe succeeded: handshake-only evidence is
	// not admission evidence (finding F10).
	isPending := hp.checkAndRecordPendingEnrollment(ctx, probeTarget.ServerID)
	targetStatus := status
	if isPending {
		targetStatus = models.TunnelStatusConnecting
	}
	if hp.pool != nil {
		expectedVersion := probeTarget.StateVersion
		if snapshot != nil && snapshot.StateVersion > 0 {
			expectedVersion = snapshot.StateVersion
		}
		if err := hp.pool.SetTunnelStatusIfCurrentWithVersion(ctx, probeTarget.ServerID, probeTarget.ID, expectedVersion, targetStatus, latencyMS); err != nil {
			return err
		}
		probeTarget.StateVersion = expectedVersion + 1
	}
	if err := hp.checkTunnelAvailable(probeTarget); err != nil {
		return err
	}
	hp.mu.Lock()
	if err := hp.checkHealthGenerationLocked(probeTarget); err != nil {
		hp.mu.Unlock()
		return err
	}
	// A completed outer handshake (and, above, a successful attachment) ends the
	// failure streak for this backend in every category.
	hp.resetFailureCountsLocked(probeTarget.ServerID)

	delete(hp.autoDisabled, probeTarget.ServerID)
	delete(hp.successCounts, probeTarget.ServerID)
	hp.mu.Unlock()
	return nil
}

// verifyActiveEligibility verifies that the inner data plane is functional before promoting
// or restoring a tunnel to active status.
func (hp *HealthProber) verifyActiveEligibility(ctx context.Context, snapshot, probeTarget *models.BackendTunnel, isBlocked bool) (bool, error) {
	if hp.hasCanaryProber(probeTarget) {
		if canaryErr := hp.probeCanary(ctx, probeTarget); canaryErr != nil {
			if isObsoleteCanary(canaryErr) {
				return false, canaryErr
			}
			slog.Warn("Backend tunnel outer probe succeeded but inner canary failed; denying active promotion",
				"tunnel_id", probeTarget.ID, "server_id", probeTarget.ServerID, "status", probeTarget.Status, "err", canaryErr)
			failures := hp.GetCanaryFailCount(probeTarget.ServerID)

			if failures >= hp.cfg.FailureThreshold {
				return false, hp.transitionToThresholdDisabled(ctx, snapshot)
			}
			if hp.hasEstablishedSessions(snapshot, probeTarget) {
				return false, hp.transitionToHandshakeBlocked(ctx, snapshot)
			}
			return false, hp.transitionToDegraded(ctx, snapshot)
		}
		return true, nil
	}

	if isBlocked {
		return false, nil
	}

	return true, nil
}

// hasEstablishedSessions reports whether a backend currently serves live
// sessions, consulting the probe snapshots first and the pool when available.
// Established sessions are the resource that blocked-backend preservation
// protects, so every decision on this path asks the same question.
func (hp *HealthProber) hasEstablishedSessions(snapshot, probeTarget *models.BackendTunnel) bool {
	if snapshot != nil && snapshot.ActiveConnections > 0 {
		return true
	}
	if probeTarget != nil && probeTarget.ActiveConnections > 0 {
		return true
	}
	if hp.pool == nil || probeTarget == nil {
		return false
	}
	cur, err := hp.pool.GetTunnel(probeTarget.ServerID)
	return err == nil && cur != nil && cur.ActiveConnections > 0
}

// preservedProbeStatus keeps the blocked-backend preservation status when a slow
// outer success carries no inner-loss evidence. It returns the final status the
// caller should commit.
func (hp *HealthProber) preservedProbeStatus(snapshot, probeTarget *models.BackendTunnel, isBlocked bool, status string) string {
	if !isBlocked || status != models.TunnelStatusDegraded {
		return status
	}
	if !hp.hasEstablishedSessions(snapshot, probeTarget) {
		return status
	}
	return models.TunnelStatusHandshakeBlocked
}

func (hp *HealthProber) runActiveHookIfActive(ctx context.Context, snapshot, probeTarget *models.BackendTunnel, status string) error {
	if status != "active" {
		return nil
	}
	hp.mu.RLock()
	preActiveHook := hp.preActiveHookHook
	hp.mu.RUnlock()
	if preActiveHook != nil {
		preActiveHook()
	}
	_, err := hp.executeActiveHook(ctx, snapshot, probeTarget)
	return err
}

func (hp *HealthProber) checkAndRecordPendingEnrollment(ctx context.Context, serverID int64) bool {
	hp.mu.Lock()
	if ctx != nil && ctx.Value(DeployEnrollmentKey) != nil {
		if hp.pendingEnrollment == nil {
			hp.pendingEnrollment = make(map[int64]bool)
		}
		hp.pendingEnrollment[serverID] = true
	}
	isPending := hp.pendingEnrollment != nil && hp.pendingEnrollment[serverID]
	db := hp.db
	hp.mu.Unlock()

	if isPending && ctx != nil && ctx.Value(DeployEnrollmentKey) != nil && db != nil {
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = db.SetBackendPendingEnrollment(writeCtx, serverID, true)
	}
	return isPending
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
