package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// NaiveProbeFunc is the signature for probing a NaiveProxy endpoint.
type NaiveProbeFunc func(ctx context.Context, endpoint string, params models.NaiveProxyParams, timeout time.Duration) (int64, error)

// SetNaiveProbeFunc overrides the Naive probe function (useful for testing).
func (hp *HealthProber) SetNaiveProbeFunc(fn NaiveProbeFunc) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if fn != nil {
		hp.probeNaiveFn = fn
	}
}

func (hp *HealthProber) probeNaive(ctx context.Context, tunnel *models.BackendTunnel) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("tunnel is nil")
	}
	if len(tunnel.ProtocolParams) == 0 {
		return 0, errors.New("naive protocol params cannot be empty")
	}
	var params models.NaiveProxyParams
	if err := json.Unmarshal(tunnel.ProtocolParams, &params); err != nil {
		return 0, fmt.Errorf("failed to decode naive params: %w", err)
	}

	hp.mu.RLock()
	probeFn := hp.probeNaiveFn
	timeout := hp.cfg.Timeout
	hp.mu.RUnlock()

	if probeFn == nil {
		return 0, errors.New("naive probe function not configured")
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
