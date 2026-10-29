package tunnel

import (
	"context"
	"errors"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/manager/awg/health"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// SetProbeFunc updates the probe function used by the health prober for AWG endpoints.
func (hp *HealthProber) SetProbeFunc(fn ProbeFunc) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if fn != nil {
		hp.probeFn = fn
	}
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
	// Issue #49: extract H1/H2 as full HeaderRanges (AWG 3.1).
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
	if !vpnCfg.H1.IsZero() || !vpnCfg.H2.IsZero() || vpnCfg.S1 >= 0 || vpnCfg.S2 >= 0 {
		return vpnCfg.H1, vpnCfg.H2, vpnCfg.S1, vpnCfg.S2, true
	}
	return models.HeaderRange{}, models.HeaderRange{}, -1, -1, false
}

// resolveTunnelParams returns H1, H2, S1, S2 for probing the specific backend tunnel,
// checking the backend's installed params first, then stored VPNConfig, then prober defaults.
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

// probeAWG executes a single Noise IK handshake probe against an AWG backend tunnel.
func (hp *HealthProber) probeAWG(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}

	h1, h2, s1, s2, hpKey := hp.resolveTunnelParams(ctx, tunnel.ServerID)

	// Issue #43: probe from the tunnel's DEDICATED probe key, not the data device key.
	probePrivKey := tunnel.ProbePrivateKey
	if probePrivKey == "" {
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
	if err != nil {
		return 0, err
	}

	latencyMS := int64(rtt.Milliseconds())
	if latencyMS <= 0 {
		latencyMS = 1
	}
	return latencyMS, nil
}
