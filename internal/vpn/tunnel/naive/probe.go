package naive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ProbeNaiveProxy issues an authenticated CONNECT request to the server's own
// camouflage domain (p.Domain:443) through the specified NaiveProxy endpoint.
// It measures connection and handshake latency in milliseconds, clamping the
// result to at least 1ms on success, and closes the connection without transmitting
// any tunneled payload bytes.
func ProbeNaiveProxy(ctx context.Context, target string, p models.NaiveProxyParams, timeout time.Duration) (int64, error) {
	return probeNaiveProxy(ctx, target, p, timeout)
}

// ProbeNaiveProxyTunnel unwraps models.NaiveProxyParams from tunnel.ProtocolParams
// and executes ProbeNaiveProxy against tunnel.Endpoint.
func ProbeNaiveProxyTunnel(ctx context.Context, tunnel *models.BackendTunnel, timeout time.Duration) (int64, error) {
	if tunnel == nil {
		return 0, errors.New("naive: nil tunnel")
	}
	var params models.NaiveProxyParams
	if err := json.Unmarshal(tunnel.ProtocolParams, &params); err != nil {
		return 0, fmt.Errorf("naive: invalid protocol params: %w", err)
	}
	return probeNaiveProxy(ctx, tunnel.Endpoint, params, timeout)
}

func probeNaiveProxy(ctx context.Context, target string, p models.NaiveProxyParams, timeout time.Duration) (int64, error) {
	// Construct dialer outside the timed window so parameter validation
	// and pool structure allocations do not skew latency metrics.
	d, err := New(target, p)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = d.Close()
	}()

	timeoutCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		timeoutCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	camTarget := net.JoinHostPort(p.Domain, "443")

	if p.EnableH3 {
		h3Ctx := timeoutCtx
		if deadline, ok := timeoutCtx.Deadline(); ok {
			dur := time.Until(deadline) / 2
			if dur > 2*time.Second {
				dur = 2 * time.Second
			}
			if dur > 0 {
				var cancel context.CancelFunc
				h3Ctx, cancel = context.WithTimeout(timeoutCtx, dur)
				defer cancel()
			}
		} else {
			var cancel context.CancelFunc
			h3Ctx, cancel = context.WithTimeout(timeoutCtx, 2*time.Second)
			defer cancel()
		}

		elapsed, status, errH3 := d.probeH3(h3Ctx, camTarget)
		if errH3 == nil {
			return handleProbeStatus(status, elapsed)
		}
		// If the context timed out or was canceled during H3 probe, abort immediately.
		if timeoutCtx.Err() != nil {
			return 0, timeoutCtx.Err()
		}
		// On any transport-level H3 failure (UDP blocked, handshake timeout),
		// gracefully fall back to H2 probe.
	}

	elapsed, status, err := d.probeH2(timeoutCtx, camTarget)
	if err != nil {
		if timeoutCtx.Err() != nil {
			return 0, timeoutCtx.Err()
		}
		return 0, fmt.Errorf("naive: probe failed: %w", err)
	}

	return handleProbeStatus(status, elapsed)
}

func handleProbeStatus(status int, elapsed int64) (int64, error) {
	if elapsed < 1 {
		elapsed = 1
	}

	switch status {
	case http.StatusOK:
		return elapsed, nil
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect: // 307 / 308
		return 0, errors.New("naive: probe rejected — unauthenticated redirect")
	case http.StatusProxyAuthRequired: // 407
		return 0, errors.New("naive: probe failed — proxy authentication rejected")
	default:
		return 0, fmt.Errorf("naive: probe failed — unexpected status %d", status)
	}
}
