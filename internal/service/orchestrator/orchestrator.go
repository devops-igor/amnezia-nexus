package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/service/userops"
)

// ProtocolResolver resolves a ProtocolManager by protocol name.
type ProtocolResolver interface {
	Get(proto string) (manager.ProtocolManager, bool)
}

// UserOpsService defines the interface for mass user operations.
type UserOpsService interface {
	PerformMassOperations(ctx context.Context, req userops.MassOperationRequest) error
}

// TunnelStatusUpdater defines the interface for synchronizing backend tunnel health status with the VPN subsystem.
type TunnelStatusUpdater interface {
	SetTunnelStatus(ctx context.Context, serverID int64, status string, latencyMS int64) error
}

// SessionMigrator defines the interface for coordinated live VPN session migration across backend tunnels (issue #289).
type SessionMigrator interface {
	MigrateSession(ctx context.Context, sessionID string, targetTunnelID int64) error
}

type healthProbeKey struct {
	clientPriv string
	serverPub  string
	psk        string
}

// DefaultProbeFailureThreshold is the default consecutive health probe failure count
// before marking a backend tunnel degraded (matching tunnel.HealthProber.FailureThreshold).
const DefaultProbeFailureThreshold = 3

// ProbeFunc defines the signature for Noise IK handshake UDP probes.
// h1 and h2 accept models.HeaderRange (AWG 3.1 header ranges, issue #49) or
// uint32 (legacy single-value headers); ProbeAWGEndpointRange handles both.
type ProbeFunc func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error)

// Orchestrator coordinates scheduled background maintenance and telemetry tasks.
type Orchestrator struct {
	db                    *database.DB
	registry              ProtocolResolver
	userOps               UserOpsService
	statusUpdater         TunnelStatusUpdater
	sessionMigrator       SessionMigrator
	probeFn               ProbeFunc
	bootDelay             time.Duration
	interval              time.Duration
	maxConcurrency        int
	probeFailureThreshold int

	mu                sync.RWMutex
	reachabilityCache map[int64]map[string]any
	healthProbeKeys   map[int64]healthProbeKey
	probeFailCounts   map[int64]int

	running     bool
	cancel      context.CancelFunc
	stopCh      chan struct{}
	lastRun     *time.Time
	lastSuccess *time.Time
	lastError   error
}

// Option configures Orchestrator options.
type Option func(*Orchestrator)

// WithProbeFunc configures a custom handshake probe function for testing or simulation.
func WithProbeFunc(fn ProbeFunc) Option {
	return func(o *Orchestrator) {
		if fn != nil {
			o.probeFn = fn
		}
	}
}

// WithBootDelay configures initial delay before first background run.
func WithBootDelay(delay time.Duration) Option {
	return func(o *Orchestrator) {
		if delay >= 0 {
			o.bootDelay = delay
		}
	}
}

// WithInterval configures the recurring background ticker interval.
func WithInterval(interval time.Duration) Option {
	return func(o *Orchestrator) {
		if interval > 0 {
			o.interval = interval
		}
	}
}

// WithMaxConcurrency configures max parallel SSH workers across servers.
func WithMaxConcurrency(maxConcurrency int) Option {
	return func(o *Orchestrator) {
		if maxConcurrency > 0 {
			o.maxConcurrency = maxConcurrency
		}
	}
}

// WithUserOps configures custom UserOpsService.
func WithUserOps(ops UserOpsService) Option {
	return func(o *Orchestrator) {
		o.userOps = ops
	}
}

// WithProbeFailureThreshold configures the consecutive probe failure threshold
// before marking a backend tunnel as degraded.
func WithProbeFailureThreshold(threshold int) Option {
	return func(o *Orchestrator) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if threshold > 0 {
			o.probeFailureThreshold = threshold
		}
	}
}

// WithTunnelStatusUpdater configures a tunnel status updater on Orchestrator initialization.
func WithTunnelStatusUpdater(u TunnelStatusUpdater) Option {
	return func(o *Orchestrator) {
		o.statusUpdater = u
	}
}

// WithSessionMigrator configures the session migrator on Orchestrator initialization (issue #289).
func WithSessionMigrator(m SessionMigrator) Option {
	return func(o *Orchestrator) {
		o.sessionMigrator = m
	}
}

// New creates a new BackgroundTaskOrchestrator.
func New(db *database.DB, registry ProtocolResolver, opts ...Option) *Orchestrator {
	var defaultUserOps UserOpsService
	if db != nil {
		defaultUserOps = userops.NewUserOpsService(db, registry)
	}

	o := &Orchestrator{
		db:                    db,
		registry:              registry,
		userOps:               defaultUserOps,
		probeFn:               health.ProbeAWGEndpointRange,
		bootDelay:             60 * time.Second,
		interval:              600 * time.Second,
		maxConcurrency:        10,
		probeFailureThreshold: DefaultProbeFailureThreshold,
		reachabilityCache:     make(map[int64]map[string]any),
		healthProbeKeys:       make(map[int64]healthProbeKey),
		probeFailCounts:       make(map[int64]int),
		stopCh:                make(chan struct{}),
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// SetTunnelStatusUpdater configures the tunnel status updater (e.g. VPN service).
func (o *Orchestrator) SetTunnelStatusUpdater(u TunnelStatusUpdater) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.statusUpdater = u
}

// SetSessionMigrator configures the session migrator (e.g. VPN service) for live rebalancing (issue #289).
func (o *Orchestrator) SetSessionMigrator(m SessionMigrator) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sessionMigrator = m
}

// Name returns the service identifier for supervisor registration.
func (o *Orchestrator) Name() string {
	return "background-orchestrator"
}

// Start launches the periodic orchestrator loop with boot delay.
func (o *Orchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return errors.New("orchestrator is already running")
	}
	subCtx, cancel := context.WithCancel(ctx)
	o.cancel = cancel
	o.running = true
	o.stopCh = make(chan struct{})
	bootDelay := o.bootDelay
	interval := o.interval
	o.mu.Unlock()

	slog.Info("Background orchestrator started", "boot_delay", bootDelay, "interval", interval)

	// 1. Initial boot delay
	if bootDelay > 0 {
		select {
		case <-subCtx.Done():
			o.setStopped()
			return subCtx.Err()
		case <-o.stopCh:
			o.setStopped()
			return nil
		case <-time.After(bootDelay):
		}
	}

	// 2. Main periodic loop
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// First run after boot delay
	if err := o.RunAll(subCtx); err != nil && subCtx.Err() == nil {
		slog.Warn("Orchestrator initial RunAll encountered error", "err", err)
	}

	for {
		select {
		case <-subCtx.Done():
			o.setStopped()
			return subCtx.Err()
		case <-o.stopCh:
			o.setStopped()
			return nil
		case <-ticker.C:
			if err := o.RunAll(subCtx); err != nil && subCtx.Err() == nil {
				slog.Warn("Orchestrator periodic RunAll encountered error", "err", err)
			}
		}
	}
}

// Stop signals the orchestrator loop to terminate gracefully.
func (o *Orchestrator) Stop(ctx context.Context) error {
	o.mu.Lock()
	if !o.running {
		o.mu.Unlock()
		return nil
	}
	if o.cancel != nil {
		o.cancel()
	}
	select {
	case <-o.stopCh:
	default:
		close(o.stopCh)
	}
	o.running = false
	o.mu.Unlock()

	slog.Info("Background orchestrator stopped cleanly")
	return nil
}

func (o *Orchestrator) setStopped() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.running = false
}

// RunAll executes all periodic background operations with error isolation.
func (o *Orchestrator) RunAll(ctx context.Context) error {
	now := time.Now().UTC()
	o.mu.Lock()
	o.lastRun = &now
	o.mu.Unlock()

	operations := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"sync_traffic", o.SyncTraffic},
		{"check_server_reachability", func(c context.Context) error {
			_, err := o.CheckServerReachability(c)
			return err
		}},
		{"check_auto_trial_handshakes", o.CheckAutoTrialHandshakes},
		{"check_backend_tunnel_health", o.CheckBackendTunnelHealth},
		{"rebalance_vpn_sessions", o.RebalanceVPNSessions},
	}

	var combinedErrors []error

	for _, op := range operations {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := op.fn(ctx); err != nil {
			slog.Error("Background task operation failed", "operation", op.name, "err", err)
			combinedErrors = append(combinedErrors, fmt.Errorf("%s: %w", op.name, err))
		}
	}

	if len(combinedErrors) > 0 {
		joinErr := errors.Join(combinedErrors...)
		o.mu.Lock()
		o.lastError = joinErr
		o.mu.Unlock()
		return joinErr
	}

	o.mu.Lock()
	o.lastSuccess = &now
	o.lastError = nil
	o.mu.Unlock()
	return nil
}

// LastRun returns the timestamp of the last RunAll execution attempt.
func (o *Orchestrator) LastRun() *time.Time {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.lastRun
}

// LastSuccess returns the timestamp of the last successful RunAll execution.
func (o *Orchestrator) LastSuccess() *time.Time {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.lastSuccess
}

// LastError returns the error from the last RunAll execution, if any.
func (o *Orchestrator) LastError() error {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.lastError
}

// GetCachedServerReachability returns a snapshot of cached reachability test results.
func (o *Orchestrator) GetCachedServerReachability() map[int64]map[string]any {
	o.mu.RLock()
	defer o.mu.RUnlock()

	copyMap := make(map[int64]map[string]any, len(o.reachabilityCache))
	for k, v := range o.reachabilityCache {
		copyInner := make(map[string]any, len(v))
		for ik, iv := range v {
			copyInner[ik] = iv
		}
		copyMap[k] = copyInner
	}
	return copyMap
}

// ProbeFailureThreshold returns the configured consecutive probe failure threshold.
func (o *Orchestrator) ProbeFailureThreshold() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.probeFailureThreshold <= 0 {
		return DefaultProbeFailureThreshold
	}
	return o.probeFailureThreshold
}

// ResetProbeFailCount clears the consecutive failure count for a backend tunnel.
func (o *Orchestrator) ResetProbeFailCount(tunnelID int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.probeFailCounts != nil {
		delete(o.probeFailCounts, tunnelID)
	}
}

// GetProbeFailCount returns the current consecutive failure count for a backend tunnel.
func (o *Orchestrator) GetProbeFailCount(tunnelID int64) int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.probeFailCounts == nil {
		return 0
	}
	return o.probeFailCounts[tunnelID]
}

// recordProbeFailure increments and returns the consecutive failure count for a backend tunnel.
func (o *Orchestrator) recordProbeFailure(tunnelID int64) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.probeFailCounts == nil {
		o.probeFailCounts = make(map[int64]int)
	}
	o.probeFailCounts[tunnelID]++
	return o.probeFailCounts[tunnelID]
}
