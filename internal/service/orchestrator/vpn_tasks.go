package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
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
		probeFn = health.ProbeAWGEndpoint
	}

	tunnelParams := o.resolveTunnelProbeParams(ctx, tunnels)

	var degradedTunnels []int64
	var healthyTunnels []*models.BackendTunnel

	for _, t := range tunnels {
		if strings.EqualFold(t.Status, "disabled") {
			continue
		}

		// Resolve the server's actual obfuscation params (stored snake_case
		// awg_params, canonical format) so the raw UDP probe matches what the
		// backend expects. Falling back to defaults here was the root cause of
		// healthy custom-obfuscation backends being marked degraded.
		params, ok := tunnelParams[t.ID]
		if !ok {
			params = resolvedProbeParams{h1: health.DefaultH1, h2: health.DefaultH2, s1: health.DefaultS1, s2: health.DefaultS2}
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
			slog.Warn("Backend tunnel health probe failed", "tunnel_id", t.ID, "endpoint", t.Endpoint, "err", err)
			_ = o.db.UpdateBackendTunnelStatus(ctx, t.ID, "degraded", 0)
			degradedTunnels = append(degradedTunnels, t.ID)
			continue
		}

		latencyMS := int64(rtt.Milliseconds())
		if latencyMS <= 0 {
			latencyMS = 1
		}

		status := "active"
		if latencyMS > latencyThreshold {
			status = "degraded"
			degradedTunnels = append(degradedTunnels, t.ID)
		} else {
			healthyTunnels = append(healthyTunnels, &tCopy)
		}

		_ = o.db.UpdateBackendTunnelStatus(ctx, t.ID, status, latencyMS)
	}

	// Trigger failover / migration for sessions on degraded tunnels
	if len(degradedTunnels) > 0 && len(healthyTunnels) > 0 {
		sessions, err := o.db.GetActiveVPNSessions(ctx)
		if err == nil && len(sessions) > 0 {
			degradedMap := make(map[int64]bool)
			for _, tid := range degradedTunnels {
				degradedMap[tid] = true
			}

			migrated := 0
			hIdx := 0
			for _, s := range sessions {
				if degradedMap[s.BackendTunnelID] {
					target := healthyTunnels[hIdx%len(healthyTunnels)]
					hIdx++
					s.BackendTunnelID = target.ID
					s.Status = "connected"
					if err := o.db.CreateVPNSession(ctx, &s); err == nil {
						migrated++
					}
				}
			}
			if migrated > 0 {
				slog.Info("Migrated VPN sessions from degraded backend tunnels", "count", migrated)
			}
		}
	}

	return nil
}

// resolvedProbeParams carries the obfuscation parameters used for a raw UDP
// Noise IK probe against a backend tunnel.
type resolvedProbeParams struct {
	h1, h2 uint32
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

		h1, h2, s1, s2, found := health.ExtractAWGExplicitParams(paramsObj)
		if !found {
			slog.Debug("Orchestrator probe param resolution: no explicit awg_params on server, using probe defaults", "server_id", serverID)
			continue
		}
		res := resolvedProbeParams{h1: h1, h2: h2, s1: s1, s2: s2, hpKey: health.ExtractHeaderProtectionKey(paramsObj)}
		if res.h1 == 0 {
			res.h1 = health.DefaultH1
		}
		if res.h2 == 0 {
			res.h2 = health.DefaultH2
		}
		if res.s1 < 0 {
			res.s1 = health.DefaultS1
		}
		if res.s2 < 0 {
			res.s2 = health.DefaultS2
		}
		for _, tid := range tunnelIDs {
			out[tid] = res
		}
	}
	return out
}

// RebalanceVPNSessions detects load imbalance across backend tunnels and reassigns sessions to lighter backends.
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

	counts := make(map[int64]int)
	sessionsByTunnel := make(map[int64][]models.VPNSession)
	for _, s := range sessions {
		if s.BackendTunnelID > 0 {
			counts[s.BackendTunnelID]++
			sessionsByTunnel[s.BackendTunnelID] = append(sessionsByTunnel[s.BackendTunnelID], s)
		}
	}

	avg := float64(len(sessions)) / float64(len(activeTunnels))
	threshold := int(avg * 1.4) // >40% above average

	for _, t := range activeTunnels {
		count := counts[t.ID]
		if count > threshold && count > int(avg) {
			excess := count - int(avg)
			sessList := sessionsByTunnel[t.ID]
			drained := 0

			for i := 0; i < len(sessList) && drained < excess; i++ {
				// Find lighter active backend tunnel
				var targetTunnelID int64
				minCount := 999999
				for _, cand := range activeTunnels {
					if cand.ID != t.ID && counts[cand.ID] < minCount {
						minCount = counts[cand.ID]
						targetTunnelID = cand.ID
					}
				}

				s := sessList[i]
				s.Status = "draining"
				if targetTunnelID > 0 {
					s.BackendTunnelID = targetTunnelID
					counts[targetTunnelID]++
					counts[t.ID]--
				}
				if err := o.db.CreateVPNSession(ctx, &s); err == nil {
					drained++
				}
			}

			slog.Info("Rebalanced overloaded backend tunnel",
				"tunnel_id", t.ID,
				"session_count", count,
				"average", avg,
				"drained_sessions", drained,
			)
		}
	}

	return nil
}

// SyncRemnaWave delegates to the configured RemnaWave syncer.
func (o *Orchestrator) SyncRemnaWave(ctx context.Context) error {
	if o.remnawaveSyncer == nil {
		return nil
	}

	count, msg, err := o.remnawaveSyncer.Sync(ctx)
	if err != nil {
		slog.Warn("RemnaWave periodic sync encountered error", "err", err)
		return err
	}

	slog.Info("RemnaWave periodic sync completed", "synced_users", count, "msg", msg)
	return nil
}
