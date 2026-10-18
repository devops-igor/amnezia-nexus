package vpn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Start launches the complete VPN subsystem.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.startedAt = time.Time{}
	s.retiredIngressLosses = ingressLossTotals{}
	s.retiredBackendDeviceDrops = backendDeviceDropStats{}
	s.mu.Unlock()

	// No client transport keys, endpoints, or forwarder routes survive a process
	// restart. Atomically discard persisted sessions and their pool gauges
	// before any backend device or packet pump can receive traffic. If cleanup
	// fails, do not start with a falsely connected data plane.
	if s.db != nil {
		s.assignmentMu.Lock()
		err := reservePersistedClientIPs(ctx, s.db, s.ipam)
		var invalidated int64
		if err == nil {
			invalidated, err = s.db.InvalidateVPNSessionsForRestart(ctx)
		}
		s.assignmentMu.Unlock()
		if err != nil {
			s.mu.Lock()
			s.running = false
			s.startedAt = time.Time{}
			s.mu.Unlock()
			return fmt.Errorf("failed to invalidate VPN sessions on restart: %w", err)
		}
		s.restartInvalidatedSessions.Store(invalidated)
		log.Printf("[vpn] restart reconciliation invalidated %d persisted connected session(s); awaiting fresh client handshakes", invalidated)
	}

	// 1. Sync tunnels from DB
	if s.pool != nil {
		if err := s.pool.SyncFromDB(ctx); err != nil {
			s.mu.Lock()
			s.running = false
			s.startedAt = time.Time{}
			s.mu.Unlock()
			return fmt.Errorf("failed to sync tunnels from DB: %w", err)
		}
		if err := s.pool.ResetEnabledHealthForStartup(ctx); err != nil {
			s.mu.Lock()
			s.running = false
			s.startedAt = time.Time{}
			s.mu.Unlock()
			return fmt.Errorf("failed to reset backend health for startup: %w", err)
		}

		// Issue #43 startup migration: backfill dedicated probe keys for
		// legacy tunnels and (re-)register both portal peers on each backend
		// BEFORE data planes are restored, so devices and probes come up
		// with their correct identities. Best-effort; logs on failure.
		s.EnsureBackendProbeKeys(ctx)

		// Enabled backends are intentionally "connecting" here, so no stale
		// data-plane device is restored. The health prober's initial sweep
		// establishes fresh health and attaches devices for successful probes.
		s.restoreBackendDevices(ctx)
	}

	// 2. Reconcile the active_connections gauge from the authoritative
	// session table (issue #54): the persisted counter drifts when older
	// deploys kill sessions without decrementing it, and the drift survives
	// restarts, distorting least-conn routing. Best-effort: startup must
	// not fail if reconciliation errors.
	s.reconcileConnectionCounts(ctx)

	// 3. Start forwarder & accountant
	if s.forwarder != nil {
		s.forwarder.Start(ctx)
		s.forwarder.StartPumps(ctx)
	}

	// 4. Establish fresh backend health before accepting client traffic.
	// ResetEnabledHealthForStartup intentionally made every enabled backend
	// unroutable ("connecting"). Run one synchronous sweep here so the endpoint
	// cannot accept a handshake in the window before the prober goroutine's
	// initial sweep has completed.
	if s.prober != nil {
		_ = s.prober.ProbeAll(ctx)
		s.prober.StartAfterInitialProbe(ctx)
	}
	if s.reconnectMgr != nil {
		s.reconnectMgr.Start(ctx)
	}

	// 5. Start active client AWG engine (upstream-only)
	if err := s.startUpstreamClientEngine(ctx); err != nil {
		return err
	}

	listenPort := s.resolveActiveListenPort(ctx)
	log.Printf("[vpn] active client AWG engine=%s listen_port=%d", ClientAWGEngineUpstream, listenPort)

	// Issue #78: hourly periodic reconcile of the active_connections gauge.
	// Safety net for residual counter drift; gauge-only semantics - it never
	// touches sessions, so it cannot fight the idle-timeout reaper.
	s.StartGaugeReconciler(ctx)

	// Issue #429 review blocker 1: every Start after Stop is an explicit new
	// diagnostics generation. Bump the generation and re-prime every
	// cumulative diagnostics tracker under diagRatesMu BEFORE
	// startRollingHistory() primes the history baselines, so all sampling
	// after this point is tagged with the new generation and computed only
	// from post-start observations — a restart can never be inferred from
	// counters that moved backwards. (The forwarder's trackers are already
	// reset inside Forwarder.Start above.)
	s.resetDiagnosticsGeneration()

	s.startRollingHistory()

	s.mu.Lock()
	s.startedAt = time.Now().UTC()
	s.mu.Unlock()

	return nil
}

// resetDiagnosticsGeneration starts a new diagnostics generation and re-primes
// every cumulative diagnostics tracker for it (issue #429 review blocker 1).
// Called from Service.Start after the forwarder has started; startRollingHistory
// then primes the history baselines into the new generation.
func (s *Service) resetDiagnosticsGeneration() {
	s.diagRatesMu.Lock()
	defer s.diagRatesMu.Unlock()
	gen := diagGeneration(s.diagGeneration.Add(1))
	if s.diagRates != nil {
		s.diagRates.reset(gen)
	}
	if s.historyDiagRates != nil {
		s.historyDiagRates.reset(gen)
	}
	s.diagDeltas.reset(gen)
	// historyPrimed is keyed to the generation (historyPrimedGen): bumping
	// diagGeneration invalidates it by itself, so the next history read
	// re-primes into the new generation. The prime call here captures the
	// FIRST post-start observation as the new baseline.
	s.primeHistoryRatesLocked(gen, time.Now(), func() *DropCategoryBreakdown {
		drops := s.captureDiagnosticsInputs().collectDropCategories()
		return &drops
	}())
}

func (s *Service) cleanupEngineStartupFailure() {
	if s.prober != nil {
		s.prober.Stop()
	}
	if s.reconnectMgr != nil {
		s.reconnectMgr.Stop()
	}
	if s.forwarder != nil {
		_ = s.forwarder.Stop()
	}
	s.mu.Lock()
	s.running = false
	s.startedAt = time.Time{}
	s.mu.Unlock()
}

func (s *Service) startUpstreamClientEngine(ctx context.Context) error {
	s.mu.Lock()
	ingressEng := s.ingressEngine
	s.mu.Unlock()

	if ingressEng == nil {
		var err error
		ingressEng, err = s.NewIngressEngine(ctx, "nexus-portal", nil)
		if err != nil {
			s.cleanupEngineStartupFailure()
			return fmt.Errorf("failed to construct upstream ingress engine: %w", err)
		}
		s.mu.Lock()
		s.ingressEngine = ingressEng
		s.mu.Unlock()
	}

	if err := ingressEng.Start(); err != nil {
		_ = ingressEng.Stop()
		s.mu.Lock()
		s.ingressEngine = nil
		s.mu.Unlock()
		s.cleanupEngineStartupFailure()
		return fmt.Errorf("failed to start upstream ingress engine: %w", err)
	}
	return nil
}

func (s *Service) resolveActiveListenPort(ctx context.Context) int {
	if s.cfg != nil && s.cfg.ListenPort > 0 {
		return s.cfg.ListenPort
	}
	if s.db != nil {
		if dbCfg, err := s.db.GetVPNConfig(ctx); err == nil && dbCfg != nil && dbCfg.ListenPort > 0 {
			return dbCfg.ListenPort
		}
	}
	return 51820
}

// isLifecycleMutated returns true if the session manager exists and its
// lifecycle version has advanced beyond versionBefore.
func (s *Service) isLifecycleMutated(versionBefore uint64) bool {
	return s.sessionMgr != nil && s.sessionMgr.LifecycleVersion() != versionBefore
}

// reconcileConnectionCounts recomputes the active_connections gauge of every
// tunnel in the pool from the authoritative vpn_sessions table (issue #54).
// The gauge is a LIVE count of status='connected' sessions per backend
// tunnel; it drifts when historical deploys kill sessions without
// decrementing it, and since it is persisted in backend_tunnels the drift
// survives restarts and distorts least-conn balancing. It runs once during
// Start after restart cleanup and pool sync but BEFORE the forwarder and
// endpoint accept traffic, so this read-modify-write over pool snapshots is
// safe: no live IncrementConnections/DecrementConnections traffic can race
// it at that point. On any error it logs and returns so the panel still
// comes up.
func (s *Service) reconcileConnectionCounts(ctx context.Context) {
	if s.pool == nil || s.db == nil {
		return
	}

	var versionBefore uint64
	if s.sessionMgr != nil {
		versionBefore = s.sessionMgr.LifecycleVersion()
	}

	sessions, err := s.db.GetActiveVPNSessions(ctx)
	dbReadTime := time.Now().UTC()
	if err != nil {
		log.Printf("[vpn] warning: connection gauge reconciliation skipped, cannot read active sessions: %v", err)
		return
	}

	var postHook func()
	s.mu.RLock()
	postHook = s.reconcilePostSnapshotHook
	s.mu.RUnlock()
	if postHook != nil {
		postHook()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sessionMgr != nil {
		s.sessionMgr.LockLifecycle()
		defer s.sessionMgr.UnlockLifecycle()
	}

	if s.isLifecycleMutated(versionBefore) {
		log.Printf("[vpn] warning: connection gauge reconciliation skipped: session lifecycle mutated during DB snapshot (version %d -> %d)",
			versionBefore, s.sessionMgr.LifecycleVersion())
		return
	}

	if s.reconcilePreApplyHook != nil {
		s.reconcilePreApplyHook()
	}

	if s.isLifecycleMutated(versionBefore) {
		log.Printf("[vpn] warning: connection gauge reconciliation skipped: session lifecycle mutated during pre-apply hook (version %d -> %d)",
			versionBefore, s.sessionMgr.LifecycleVersion())
		return
	}

	desired := make(map[int64]int)
	for i := range sessions {
		desired[sessions[i].BackendTunnelID]++
	}

	tunnels := s.pool.ListTunnels()
	tunnelChanges := make(map[int64]int)
	stagedReconcile := make(map[int64]time.Time)
	for _, tun := range tunnels {
		want := desired[tun.ID]
		if tun.ActiveConnections == want {
			stagedReconcile[tun.ID] = dbReadTime
			continue
		}
		tunnelChanges[tun.ID] = want
		stagedReconcile[tun.ID] = dbReadTime
	}

	if s.reconcilePreCommitHook != nil {
		s.reconcilePreCommitHook()
	}

	if s.isLifecycleMutated(versionBefore) {
		log.Printf("[vpn] warning: connection gauge reconciliation aborted: session lifecycle mutated before commit (version %d -> %d)",
			versionBefore, s.sessionMgr.LifecycleVersion())
		return
	}

	anyDrift := len(tunnelChanges) > 0
	allSucceeded := true
	for _, tun := range tunnels {
		want, changed := tunnelChanges[tun.ID]
		if !changed {
			continue
		}
		if err := s.pool.SetConnectionCount(ctx, tun.ID, want); err != nil {
			allSucceeded = false
			delete(stagedReconcile, tun.ID)
			log.Printf("[vpn] warning: failed to reconcile active_connections for tunnel %d (server %d): %v", tun.ID, tun.ServerID, err)
			continue
		}
		log.Printf("[vpn] reconciled active_connections for tunnel %d (server %d): %d -> %d", tun.ID, tun.ServerID, tun.ActiveConnections, want)
	}

	if s.lastReconcileByTunnel == nil {
		s.lastReconcileByTunnel = make(map[int64]time.Time)
	}
	for tunID, ts := range stagedReconcile {
		s.lastReconcileByTunnel[tunID] = ts
	}

	if allSucceeded {
		s.lastReconcileTime = dbReadTime
	}

	// Sessions whose BackendTunnelID is not in the pool: count them as the
	// total minus everything accounted for by known tunnels.
	knownCount := 0
	for _, tun := range tunnels {
		knownCount += desired[tun.ID]
	}
	unknown := len(sessions) - knownCount
	if unknown > 0 {
		log.Printf("[vpn] warning: %d connected session(s) reference backend tunnels outside the pool; left for existing failover/sweeper logic", unknown)
	}

	if !anyDrift && unknown == 0 {
		log.Printf("[vpn] connection gauge reconciliation: no drift detected across %d tunnel(s)", len(tunnels))
	}
}

// ConnectionGaugeReconcileInterval is the cadence of the periodic gauge
// reconciliation (issue #78 decision: hourly - short enough that drift never
// lives longer than one interval, cheap enough to be a single indexed DB
// read over the vpn_sessions table per hour).
const ConnectionGaugeReconcileInterval = time.Hour

// StartGaugeReconciler launches the hourly periodic reconcile of the
// active_connections gauge (issue #78 short-term safety net). It reuses the
// existing, tested reconcileConnectionCounts primitive unchanged - no new
// counting logic - so the gauge is the ONLY thing it corrects: it never
// creates, closes, or resurrects sessions, and therefore cannot fight the
// session reaper. Reaper interaction: the reaper's teardown closes real
// session rows synchronously via DisconnectSession before the gauge can be
// stale; the reconcile simply recomputes the gauge FROM the (now-correct)
// session table, so ordering against reaper passes is irrelevant. The only
// race window is a session lifecycle event landing mid-reconcile, which is
// the same read-modify-write over pool snapshots Start already relies on and
// self-corrects on the next pass. Drift (before -> after per backend) is
// logged inside reconcileConnectionCounts, making the residual leak rate
// observable in production.
func (s *Service) StartGaugeReconciler(ctx context.Context) {
	if s.pool == nil || s.db == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(ConnectionGaugeReconcileInterval)
		defer ticker.Stop()
		log.Printf("[vpn] periodic connection-gauge reconciler started (interval %s)", ConnectionGaugeReconcileInterval)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reconcileConnectionCounts(ctx)
				s.PruneExpiredAffinity()
			}
		}
	}()
}

// Stop gracefully shuts down the VPN subsystem.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.startedAt = time.Time{}
	ingressEng := s.ingressEngine
	initialLosses := engineLossTotals(ingressEng)
	s.retiredIngressLosses = addIngressLosses(s.retiredIngressLosses, initialLosses)
	s.ingressEngine = nil
	s.mu.Unlock()

	var firstErr error
	recordErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if ingressEng != nil {
		if err := ingressEng.Stop(); err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
			recordErr(err)
		}
		s.mu.Lock()
		s.retiredIngressLosses = addIngressLosses(s.retiredIngressLosses, ingressLossDelta(engineLossTotals(ingressEng), initialLosses))
		s.mu.Unlock()
	}
	if s.prober != nil {
		s.prober.Stop()
	}
	if s.reconnectMgr != nil {
		s.reconnectMgr.Stop()
	}
	if s.forwarder != nil {
		recordErr(s.forwarder.Stop())
	}
	s.stopRollingHistory()
	if s.pool != nil {
		_ = s.pool.Close()
	}

	s.mu.Lock()
	if s.backendDevices != nil {
		for id, dev := range s.backendDevices {
			if dev != nil {
				_ = dev.Close()
			}
			if dev != nil {
				// Snapshot AFTER Close so the shutdown drains it just
				// accounted are transferred too.
				s.retiredBackendDeviceDrops.addInto(snapshotBackendDeviceDrops(dev))
			}
			delete(s.backendDevices, id)
		}
	}
	if s.backendDeviceEndpoints != nil {
		for id := range s.backendDeviceEndpoints {
			delete(s.backendDeviceEndpoints, id)
		}
	}
	s.mu.Unlock()

	return firstErr
}
