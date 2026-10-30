//go:build with_utls

package vless

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// ProbeVLESSReality executes a lightweight REALITY TLS handshake against the target,
// measures latency in milliseconds, and closes the connection without sending any VLESS payload.
// Returns latencyMS (clamped to at least 1ms on success) and error.
//
// Documented usage: Fresh installations without existing clients (len(clients) == 0) cannot perform
// client-authenticated VLESS proxying because no user UUIDs exist in the server configuration yet.
// ProbeVLESSReality verifies that the Xray engine is running, listening, and correctly completing
// the authenticated REALITY TLS key exchange with the configured private key, short ID, and engine profile.
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

// ProbeVLESSTraffic connects to the VLESS+REALITY endpoint, performs the handshake, establishes
// an authenticated VLESS session with the client UUID, transmits a lightweight probe request
// (HTTP HEAD) to the destination target, and verifies an application-level response.
// Returns roundtrip latency in milliseconds and error.
func ProbeVLESSTraffic(ctx context.Context, target string, p models.VLESSRealityParams, timeout time.Duration) (int64, error) {
	dest := p.ServerName
	if _, _, err := net.SplitHostPort(dest); err != nil {
		dest = net.JoinHostPort(dest, "443")
	}
	return ProbeVLESSTrafficWithTarget(ctx, target, p, dest, timeout)
}

// ProbeVLESSTrafficWithTarget connects to the VLESS+REALITY endpoint and routes to an explicit destination target.
func ProbeVLESSTrafficWithTarget(ctx context.Context, target string, p models.VLESSRealityParams, destination string, timeout time.Duration) (int64, error) {
	d, err := New(target, p)
	if err != nil {
		return 0, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	conn, err := d.DialContext(timeoutCtx, "tcp", destination)
	if err != nil {
		return 0, fmt.Errorf("vless: dial traffic target %s: %w", destination, err)
	}
	defer conn.Close()

	host := p.ServerName
	if h, _, err := net.SplitHostPort(destination); err == nil && h != "" {
		host = h
	}

	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: amnezia-nexus-readiness-probe\r\nConnection: close\r\n\r\n", host)

	if deadline, ok := timeoutCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, fmt.Errorf("vless: write probe request: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("vless: read probe response: %w", err)
	}
	if n == 0 {
		return 0, errors.New("vless: empty response from target through tunnel")
	}

	latencyMS := time.Since(start).Milliseconds()
	if latencyMS <= 0 {
		latencyMS = 1
	}
	return latencyMS, nil
}
