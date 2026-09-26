package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// CheckBackendTunnelHealth probes active backend AWG tunnels via pure-Go Noise IK handshakes.
func (o *Orchestrator) CheckBackendTunnelHealth(ctx context.Context) error {
	if o.db == nil {
		return errors.New("database is not configured")
	}

	tunnels, err := o.db.GetBackendTunnels(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch backend tunnels: %w", err)
	}

	if len(tunnels) == 0 {
		return nil
	}

	vpnCfg, _ := o.db.GetVPNConfig(ctx)
	latencyThreshold := int64(500)
	if vpnCfg != nil && vpnCfg.HealthThresholdMS > 0 {
		latencyThreshold = int64(vpnCfg.HealthThresholdMS)
	}

	probeFn := o.probeFn
	if probeFn == nil {
		probeFn = health.ProbeAWGEndpointRange
	}

	tunnelParams := o.resolveTunnelProbeParams(ctx, tunnels)

	var degradedTunnels []int64
	var healthyTunnels []*models.BackendTunnel

	threshold := o.ProbeFailureThreshold()

	for _, t := range tunnels {
		if !t.Enabled {
			continue
		}

		// Resolve the server's actual obfuscation params (stored snake_case
		// awg_params, canonical format) so the raw UDP probe matches what the
		// backend expects. Falling back to defaults here was the root cause of
		// healthy custom-obfuscation backends being marked degraded.
		params, ok := tunnelParams[t.ID]
		if !ok {
			params = resolvedProbeParams{
				h1: models.DegenerateHeaderRange(health.DefaultH1),
				h2: models.DegenerateHeaderRange(health.DefaultH2),
				s1: health.DefaultS1,
				s2: health.DefaultS2,
			}
		}

		tCopy := t
		rtt, err := probeFn(
			ctx,
			t.Endpoint,
			t.PublicKey,
			t.PrivateKey,
			"",
			params.hpKey,
			params.h1,
			params.h2,
			params.s1,
			params.s2,
			3*time.Second,
		)

		if err != nil {
			isStale, staleErr := o.isTunnelVersionStale(ctx, &t)
			if staleErr != nil {
				slog.Warn("Failed to verify tunnel state version from DB during probe failure handling, dropping failure count to avoid contamination",
					"tunnel_id", t.ID,
					"err", staleErr,
				)
				continue
			}
			if isStale {
				slog.Debug("Backend tunnel state version is stale in DB, ignoring probe failure",
					"tunnel_id", t.ID,
					"stale_version", t.StateVersion,
				)
				continue
			}

			failures := o.recordProbeFailure(t.ID, t.StateVersion)
			if failures < threshold {
				slog.Warn("Backend tunnel health probe failed (below failure threshold)",
					"tunnel_id", t.ID,
					"endpoint", t.Endpoint,
					"failures", failures,
					"threshold", threshold,
					"err", err,
				)
				if !strings.EqualFold(t.Status, "degraded") {
					healthyTunnels = append(healthyTunnels, &tCopy)
				}
				continue
			}

			slog.Warn("Backend tunnel health probe failed",
				"tunnel_id", t.ID,
				"endpoint", t.Endpoint,
				"failures", failures,
				"threshold", threshold,
				"err", err,
			)
			if o.updateTunnelStatus(ctx, &t, "degraded", 0) {
				degradedTunnels = append(degradedTunnels, t.ID)
				o.mu.Lock()
				if o.probeFailVersions != nil && t.StateVersion > 0 {
					o.probeFailVersions[t.ID] = t.StateVersion + 1
				}
				o.mu.Unlock()
			} else {
				o.revertProbeFailure(t.ID, t.StateVersion)
			}
			continue
		}

		o.ResetProbeFailCount(t.ID)

		latencyMS := int64(rtt.Milliseconds())
		if latencyMS <= 0 {
			latencyMS = 1
		}

		status := "active"
		if latencyMS > latencyThreshold {
			status = "degraded"
		}

		if o.updateTunnelStatus(ctx, &t, status, latencyMS) {
			if status == "degraded" {
				degradedTunnels = append(degradedTunnels, t.ID)
			} else {
				healthyTunnels = append(healthyTunnels, &tCopy)
			}
		}
	}

	// Trigger failover / migration for sessions on degraded tunnels
	o.migrateDegradedTunnelSessions(ctx, degradedTunnels, healthyTunnels)

	return nil
}

// migrateDegradedTunnelSessions migrates active sessions off degraded tunnels onto healthy ones.
// When a SessionMigrator is configured (issue #289), it coordinates live forwarder routes,
// in-memory session updates, DB persistence, and connection counters. When nil, it falls back
// to direct DB-only updates.
func (o *Orchestrator) migrateDegradedTunnelSessions(ctx context.Context, degradedTunnels []int64, healthyTunnels []*models.BackendTunnel) {
	if len(degradedTunnels) == 0 || len(healthyTunnels) == 0 || o.db == nil {
		return
	}
	sessions, err := o.db.GetActiveVPNSessions(ctx)
	if err != nil || len(sessions) == 0 {
		return
	}

	o.mu.RLock()
	migrator := o.sessionMigrator
	o.mu.RUnlock()

	degradedMap := make(map[int64]bool, len(degradedTunnels))
	for _, tid := range degradedTunnels {
		degradedMap[tid] = true
	}

	migrated := 0
	hIdx := 0
	for _, s := range sessions {
		if degradedMap[s.BackendTunnelID] {
			// The probe result is only a snapshot. An administrator can disable a
			// target after it was classified as healthy, even before this loop.
			var target *models.BackendTunnel
			for checked := 0; checked < len(healthyTunnels); checked++ {
				idx := (hIdx + checked) % len(healthyTunnels)
				candidate := healthyTunnels[idx]
				if candidate == nil {
					continue
				}
				current, err := o.db.GetBackendTunnel(ctx, candidate.ID)
				if err != nil {
					slog.Warn("Failed to recheck migration target", "tunnel_id", candidate.ID, "err", err)
					continue
				}
				if current != nil && current.Enabled && strings.EqualFold(current.Status, "active") {
					target = current
					hIdx = (idx + 1) % len(healthyTunnels)
					break
				}
			}
			if target == nil {
				break
			}
			if migrator != nil {
				if err := migrator.MigrateSession(ctx, s.ID, target.ID); err != nil {
					slog.Warn("Degraded tunnel session migration failed, skipping session",
						"session_id", s.ID,
						"source_tunnel_id", s.BackendTunnelID,
						"target_tunnel_id", target.ID,
						"err", err,
					)
					continue
				}
				migrated++
			} else {
				// The predicate in this update closes the gap between the DB
				// recheck above and the actual session assignment.
				if err := o.db.MigrateVPNSessionToActiveTunnel(ctx, s.ID, s.BackendTunnelID, target.ID); err != nil {
					slog.Warn("Direct DB update for degraded tunnel session failed, skipping session",
						"session_id", s.ID,
						"source_tunnel_id", s.BackendTunnelID,
						"target_tunnel_id", target.ID,
						"err", err,
					)
					continue
				}
				migrated++
			}
		}
	}
	if migrated > 0 {
		slog.Info("Migrated VPN sessions from degraded backend tunnels", "count", migrated)
	}
}

// isTunnelVersionStale checks whether a tunnel's state version in the database has advanced
// past the snapshot version used for a probe.
func (o *Orchestrator) isTunnelVersionStale(ctx context.Context, t *models.BackendTunnel) (bool, error) {
	if o.db == nil || t == nil || t.StateVersion <= 0 {
		return false, nil
	}
	curTun, err := o.db.GetBackendTunnel(ctx, t.ID)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve tunnel %d from database: %w", t.ID, err)
	}
	if curTun == nil {
		return false, errors.New("tunnel not found in database")
	}
	return curTun.StateVersion != t.StateVersion, nil
}

// updateTunnelStatus updates a backend tunnel's status and latency using the configured
// TunnelStatusUpdater (e.g. VPN service pool) or falls back to an atomic CAS DB update.
// Returns true if the update was applied, false if dropped or missed due to stale state version.
func (o *Orchestrator) updateTunnelStatus(ctx context.Context, t *models.BackendTunnel, status string, latencyMS int64) bool {
	o.mu.RLock()
	updater := o.statusUpdater
	o.mu.RUnlock()

	if updater != nil {
		err := updater.SetTunnelStatusWithVersion(ctx, t.ServerID, t.ID, t.StateVersion, status, latencyMS)
		if err == nil {
			return true
		}
		if errors.Is(err, tunnel.ErrStaleStateVersion) {
			slog.Debug("Tunnel state version is stale in updater pool, dropping update",
				"server_id", t.ServerID,
				"tunnel_id", t.ID,
				"expected_version", t.StateVersion,
				"err", err,
			)
			return false
		}
		if !errors.Is(err, tunnel.ErrTunnelNotFound) {
			slog.Error("Tunnel status updater failed with operational error, skipping fallback to preserve state consistency",
				"server_id", t.ServerID,
				"tunnel_id", t.ID,
				"err", err,
			)
			return false
		}
		slog.Debug("Tunnel not found in updater pool, falling back to direct DB CAS",
			"server_id", t.ServerID,
			"tunnel_id", t.ID,
			"err", err,
		)
	}

	if o.db != nil {
		swapped, err := o.db.CompareAndSwapTunnelStatus(ctx, t.ID, t.Status, t.DisableReason, t.StateVersion, status, t.DisableReason, latencyMS)
		if err != nil {
			slog.Error("Direct DB CAS failed to update tunnel status",
				"server_id", t.ServerID,
				"tunnel_id", t.ID,
				"err", err,
			)
			return false
		}
		if !swapped {
			slog.Debug("Direct DB CAS missed during tunnel status update",
				"server_id", t.ServerID,
				"tunnel_id", t.ID,
				"expected_version", t.StateVersion,
			)
			return false
		}
		return true
	}

	return false
}

// resolvedProbeParams carries the obfuscation parameters used for a raw UDP
// Noise IK probe against a backend tunnel. h1/h2 carry models.HeaderRange
// (full AWG 3.1 ranges, issue #49); they are typed `any` to match ProbeFunc,
// which ProbeAWGEndpointRange accepts alongside uint32.
type resolvedProbeParams struct {
	h1, h2 any
	s1, s2 int
	hpKey  string
}

// resolveTunnelProbeParams resolves per-tunnel obfuscation params from each
// tunnel's backend server stored awg_params (snake_case canonical format),
// so the orchestrator probe matches what the backend actually expects.
// Tunnels whose params cannot be resolved are omitted; callers fall back to
// the probe defaults. Mirrors the in-process prober's resolveTunnelParams.
func (o *Orchestrator) resolveTunnelProbeParams(ctx context.Context, tunnels []models.BackendTunnel) map[int64]resolvedProbeParams {
	out := make(map[int64]resolvedProbeParams, len(tunnels))
	if o.db == nil {
		return out
	}

	byServer := make(map[int64][]int64)
	for _, t := range tunnels {
		if t.ServerID > 0 {
			byServer[t.ServerID] = append(byServer[t.ServerID], t.ID)
		}
	}
	if len(byServer) == 0 {
		return out
	}

	for serverID, tunnelIDs := range byServer {
		server, err := o.db.GetServer(ctx, serverID)
		if err != nil || server == nil || server.Protocols == nil {
			if err != nil {
				slog.Debug("Orchestrator probe param resolution: server read failed", "server_id", serverID, "err", err)
			}
			continue
		}
		awgInfo, ok := server.Protocols["awg"].(map[string]any)
		if !ok || awgInfo == nil {
			continue
		}
		var paramsObj any
		if p, ok := awgInfo["awg_params"]; ok && p != nil {
			paramsObj = p
		} else if p, ok := awgInfo["params"]; ok && p != nil {
			paramsObj = p
		} else {
			paramsObj = awgInfo
		}

		// Issue #49: extract H1/H2 as full HeaderRanges (AWG 3.1). The
		// previous ExtractAWGExplicitParams path truncated ranges to their
		// lowest bound, so range-configured backends failed response
		// verification almost always.
		rH1, rH2, rS1, rS2 := health.ExtractAWGHeaderRanges(paramsObj, health.DefaultH1, health.DefaultH2, health.DefaultS1, health.DefaultS2)
		_, _, _, _, found := health.ExtractAWGExplicitParams(paramsObj)
		if !found {
			slog.Debug("Orchestrator probe param resolution: no explicit awg_params on server, using probe defaults", "server_id", serverID)
			continue
		}
		res := resolvedProbeParams{h1: rH1, h2: rH2, s1: rS1, s2: rS2, hpKey: health.ExtractHeaderProtectionKey(paramsObj)}
		if rH1.IsZero() {
			res.h1 = models.DegenerateHeaderRange(health.DefaultH1)
		}
		if rH2.IsZero() {
			res.h2 = models.DegenerateHeaderRange(health.DefaultH2)
		}
		if rS1 < 0 {
			res.s1 = health.DefaultS1
		}
		if rS2 < 0 {
			res.s2 = health.DefaultS2
		}
		for _, tid := range tunnelIDs {
			out[tid] = res
		}
	}
	return out
}

// RebalanceVPNSessions detects load imbalance across backend tunnels and reassigns sessions to lighter backends.
//
// Guards against meaningless churn at low load: below the minimum-load gate
// (MinRebalanceSessions sessions AND average >= 1.0 per active tunnel) no
// rebalancing happens at all. Only sessions whose count exceeds the corrected
// overflow threshold are drained, and moves are in-place UPDATEs that preserve
// the session ID (UpdateVPNSessionBackendTunnel).
//
// Live migration with DB fallback (issue #44, #289): when SessionMigrator is
// configured, live forwarder routes, in-memory sessions, and database rows are
// migrated atomically with full rollback. In DB-only mode, the update remains
// persisted directly to the database. A moved session is recorded as "draining",
// which keeps it out of GetActiveVPNSessions so the next cycle cannot ping-pong it back.
func (o *Orchestrator) RebalanceVPNSessions(ctx context.Context) error {
	if o.db == nil {
		return errors.New("database is not configured")
	}

	tunnels, err := o.db.GetBackendTunnels(ctx)
	if err != nil {
		return fmt.Errorf("failed to query backend tunnels for rebalance: %w", err)
	}

	var activeTunnels []models.BackendTunnel
	for _, t := range tunnels {
		if strings.EqualFold(t.Status, "active") {
			activeTunnels = append(activeTunnels, t)
		}
	}

	if len(activeTunnels) < 2 {
		return nil
	}

	sessions, err := o.db.GetActiveVPNSessions(ctx)
	if err != nil {
		return fmt.Errorf("failed to query active sessions for rebalance: %w", err)
	}

	if len(sessions) == 0 {
		return nil
	}

	// R3: only connected sessions are eligible. GetActiveVPNSessions already
	// filters status='connected'; skip defensively on iteration anyway.
	eligible := make([]models.VPNSession, 0, len(sessions))
	for _, s := range sessions {
		if s.Status == "connected" {
			eligible = append(eligible, s)
		}
	}

	// R1 minimum-load gate: below it, rebalancing is pure churn and misleading
	// "overloaded" logs (with 1 session / 2 tunnels the legacy code drained the
	// only session). No log here on purpose — this is the normal quiet path.
	vpnCfg, err := o.db.GetVPNConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load VPN config for rebalance gate: %w", err)
	}
	avg := float64(len(eligible)) / float64(len(activeTunnels))
	if len(eligible) < vpnCfg.MinRebalanceSessions || avg < 1.0 {
		return nil
	}

	counts := make(map[int64]int)
	sessionsByTunnel := make(map[int64][]models.VPNSession)
	for _, s := range eligible {
		if s.BackendTunnelID > 0 {
			counts[s.BackendTunnelID]++
			sessionsByTunnel[s.BackendTunnelID] = append(sessionsByTunnel[s.BackendTunnelID], s)
		}
	}

	// R2 corrected threshold: max(1, int(avg*1.4)) instead of the legacy
	// int(avg*1.4), which collapsed to 0 whenever avg < 1 and made any tunnel
	// with a single session look "overloaded". A tunnel drains only when its
	// count exceeds BOTH the 40%-above-average threshold and avg+1.
	threshold := int(avg * 1.4)
	if threshold < 1 {
		threshold = 1
	}

	for _, t := range activeTunnels {
		count := counts[t.ID]
		if count <= threshold || count <= int(avg)+1 {
			continue
		}
		excess := count - threshold
		drained := o.drainTunnelExcess(ctx, sessionsByTunnel[t.ID], activeTunnels, t.ID, counts, excess)

		slog.Info("Rebalanced overloaded backend tunnel",
			"tunnel_id", t.ID,
			"session_count", count,
			"average", avg,
			"drained_sessions", drained,
		)
	}

	return nil
}

// drainTunnelExcess moves up to `excess` sessions from the overloaded tunnel
// (sourceID) to the currently lightest other active tunnel, using coordinated
// live migration when a SessionMigrator is present (issue #289) or in-place DB
// UPDATEs that mark rows "draining" (R5) when in DB-only mode. Returns the number moved.
// counts is updated in place so successive callers see consistent numbers.
func (o *Orchestrator) drainTunnelExcess(ctx context.Context, sessList []models.VPNSession, activeTunnels []models.BackendTunnel, sourceID int64, counts map[int64]int, excess int) int {
	o.mu.RLock()
	migrator := o.sessionMigrator
	o.mu.RUnlock()

	drained := 0
	for i := 0; i < len(sessList) && drained < excess; i++ {
		// Find lighter active backend tunnel
		var targetTunnelID int64
		minCount := 999999
		for _, cand := range activeTunnels {
			if cand.ID != sourceID && counts[cand.ID] < minCount {
				minCount = counts[cand.ID]
				targetTunnelID = cand.ID
			}
		}

		s := sessList[i]
		if targetTunnelID > 0 {
			var err error
			if migrator != nil {
				err = migrator.MigrateSession(ctx, s.ID, targetTunnelID)
			} else {
				err = o.db.UpdateVPNSessionBackendTunnel(ctx, s.ID, targetTunnelID)
			}
			if err == nil {
				counts[targetTunnelID]++
				counts[sourceID]--
				drained++
			} else {
				slog.Warn("Rebalance skipped session migration failed or no longer connected",
					"session_id", s.ID,
					"source_tunnel_id", sourceID,
					"target_tunnel_id", targetTunnelID,
					"err", err,
				)
			}
		}
	}
	return drained
}
