//go:build with_utls

package vless

import (
	"context"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ProbeVLESSReality executes a lightweight REALITY TLS handshake against the target,
// measures latency in milliseconds, and closes the connection without sending any VLESS payload.
// Returns latencyMS (clamped to at least 1ms on success) and error.
func ProbeVLESSReality(ctx context.Context, target string, p models.VLESSRealityParams, timeout time.Duration) (int64, error) {
	return probeVLESSReality(ctx, target, p, timeout)
}

func probeVLESSReality(ctx context.Context, target string, p models.VLESSRealityParams, timeout time.Duration) (int64, error) {
	d, err := New(target, p)
	if err != nil {
		return 0, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tc, rtt, err := d.handshake(timeoutCtx)
	if err != nil {
		return 0, err
	}
	_ = tc.Close()

	latencyMS := rtt.Milliseconds()
	if latencyMS <= 0 {
		latencyMS = 1
	}
	return latencyMS, nil
}
