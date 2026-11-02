package naive

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ProbeNaiveProxy issues an authenticated probe request through the specified NaiveProxy endpoint.
// In production, it ensures the native daemon is running, establishes a tunnel via SOCKS5,
// and verifies authenticated remote egress by completing an application exchange.
// It measures connection and handshake latency in milliseconds, clamping the
// result to at least 1ms on success.
// In-process pure-Go probing is only permitted when testRootCAs != nil or WithInProcessFallback() is active.
func ProbeNaiveProxy(ctx context.Context, target string, p models.NaiveProxyParams, timeout time.Duration) (int64, error) {
	return probeNaiveProxy(ctx, target, p, timeout)
}

// ProbeNaiveProxyWithOptions executes ProbeNaiveProxy with optional dialer configuration.
func ProbeNaiveProxyWithOptions(ctx context.Context, target string, p models.NaiveProxyParams, timeout time.Duration, opts ...Option) (int64, error) {
	return probeNaiveProxy(ctx, target, p, timeout, opts...)
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

func probeNaiveProxy(ctx context.Context, target string, p models.NaiveProxyParams, timeout time.Duration, opts ...Option) (int64, error) {
	// Construct dialer outside the timed window so parameter validation
	// and pool structure allocations do not skew latency metrics.
	d, err := New(target, p, opts...)
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

	// 1. Production policy: If in-process Go transport is not allowed,
	// native daemon is strictly mandatory. Fail closed on acquisition or startup failure (H2).
	if !d.allowsInProcess() {
		sd, err := d.getOrStartDaemon(timeoutCtx)
		if err != nil {
			return 0, fmt.Errorf("naive: probe native daemon required: %w", err)
		}
		return d.probeViaDaemon(timeoutCtx, camTarget, p, sd)
	}

	// 2. Test / fallback policy: allowsInProcess() is true (testRootCAs != nil or WithInProcessFallback())
	d.daemonMu.Lock()
	sd := d.socks5Dialer
	d.daemonMu.Unlock()
	if sd == nil && isExecutable(GetNaiveBinPath()) {
		sd, _ = d.getOrStartDaemon(timeoutCtx)
	}
	if sd != nil {
		return d.probeViaDaemon(timeoutCtx, camTarget, p, sd)
	}

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

		start := time.Now()
		status, errH3 := d.probeH3(h3Ctx, camTarget)
		if errH3 == nil {
			elapsed := time.Since(start).Milliseconds()
			return handleProbeStatus(status, elapsed)
		}
		// If the context timed out or was canceled during H3 probe, abort immediately.
		if timeoutCtx.Err() != nil {
			return 0, timeoutCtx.Err()
		}
		// On any transport-level H3 failure (UDP blocked, handshake timeout),
		// gracefully fall back to H2 probe.
	}

	start := time.Now()
	status, err := d.probeH2(timeoutCtx, camTarget)
	if err != nil {
		if timeoutCtx.Err() != nil {
			return 0, timeoutCtx.Err()
		}
		return 0, fmt.Errorf("naive: probe failed: %w", err)
	}
	elapsed := time.Since(start).Milliseconds()

	return handleProbeStatus(status, elapsed)
}

func (d *Dialer) probeViaDaemon(ctx context.Context, camTarget string, p models.NaiveProxyParams, sd StreamDialer) (int64, error) {
	if sd == nil {
		return 0, errors.New("naive: daemon dialer not available")
	}

	start := time.Now()
	conn, err := sd.DialContext(ctx, "tcp", camTarget)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("naive: probe failed via daemon: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// SOCKS5 connects locally before upstream handshake completes.
	// Verify authenticated remote egress by completing an application exchange through the tunnel (H3).
	tlsCfg := d.tlsCfg.Clone()
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: p.Domain,
			RootCAs:    testRootCAs,
		}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("naive: remote probe tls handshake failed: %w", err)
	}
	defer tlsConn.Close()

	// Send minimal HTTP request through the authenticated TLS stream
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", p.Domain)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("naive: remote probe write failed: %w", err)
	}

	buf := make([]byte, 16)
	if _, err := io.ReadAtLeast(tlsConn, buf, 4); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("naive: remote probe read failed: %w", err)
	}

	if !strings.HasPrefix(string(buf), "HTTP/") {
		return 0, fmt.Errorf("naive: probe rejected — invalid remote response %q", string(buf))
	}

	elapsed := time.Since(start).Milliseconds()
	if elapsed < 1 {
		elapsed = 1
	}
	return elapsed, nil
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
