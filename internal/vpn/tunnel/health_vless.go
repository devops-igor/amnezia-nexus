package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// VLESSProbeFunc is the signature for probing a VLESS+REALITY endpoint.
type VLESSProbeFunc func(ctx context.Context, endpoint string, params models.VLESSRealityParams, timeout time.Duration) (int64, error)

// SetVLESSProbeFunc overrides the VLESS probe function (useful for testing).
func (hp *HealthProber) SetVLESSProbeFunc(fn VLESSProbeFunc) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if fn != nil {
		hp.probeVLESSFn = fn
	}
}

func (hp *HealthProber) probeVLESS(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}
	if len(tunnel.ProtocolParams) == 0 {
		return 0, errors.New("vless protocol params cannot be empty")
	}
	var params models.VLESSRealityParams
	if err := json.Unmarshal(tunnel.ProtocolParams, &params); err != nil {
		return 0, fmt.Errorf("failed to decode vless params: %w", err)
	}

	hp.mu.RLock()
	probeFn := hp.probeVLESSFn
	timeout := hp.cfg.Timeout
	hp.mu.RUnlock()

	if probeFn == nil {
		return 0, errors.New("vless probe function not configured")
	}

	rttMS, err := probeFn(ctx, tunnel.Endpoint, params, timeout)
	if err != nil {
		return 0, err
	}
	if rttMS <= 0 {
		rttMS = 1
	}
	return rttMS, nil
}
