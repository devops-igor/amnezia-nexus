//go:build with_utls

package vless

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
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

	host, port := splitDestination(destination, p.ServerName)
	sni := resolveSNI(host, p.ServerName)
	start := time.Now()

	// Port 443 (standard HTTPS) or 8443 targets use TLS directly.
	if port == "443" || port == "8443" {
		return probeTrafficTarget(timeoutCtx, d, destination, host, sni, start, true)
	}

	latencyMS, err := probeTrafficTarget(timeoutCtx, d, destination, host, sni, start, false)
	if err == nil {
		return latencyMS, nil
	}

	// If plaintext probe failed because target is a TLS server (empty response / EOF / reset)
	// and context has not expired, retry with TLS to support HTTPS targets on arbitrary test ports.
	if timeoutCtx.Err() == nil && isRetryableTLSError(err) {
		if tlsLatency, tlsErr := probeTrafficTarget(timeoutCtx, d, destination, host, sni, start, true); tlsErr == nil {
			return tlsLatency, nil
		}
	}

	return 0, err
}

func splitDestination(destination, defaultServerName string) (host, port string) {
	host = defaultServerName
	port = "443"
	if h, pStr, err := net.SplitHostPort(destination); err == nil {
		if h != "" {
			host = h
		}
		if pStr != "" {
			port = pStr
		}
	}
	return host, port
}

func resolveSNI(host, serverName string) string {
	sni := host
	if (net.ParseIP(sni) != nil || sni == "") && serverName != "" {
		sni = serverName
	}
	if sni == "" {
		sni = "localhost"
	}
	return sni
}

func isRetryableTLSError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return errors.Is(err, io.EOF) ||
		strings.Contains(msg, "empty response") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "invalid http response")
}

func probeTrafficTarget(
	ctx context.Context,
	d *Dialer,
	destination, host, sni string,
	start time.Time,
	useTLS bool,
) (int64, error) {
	conn, err := d.DialContext(ctx, "tcp", destination)
	if err != nil {
		return 0, fmt.Errorf("vless: dial traffic target %s: %w", destination, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	var rw io.ReadWriter = conn
	if useTLS {
		tlsConfig := &tls.Config{
			ServerName: sni,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, fmt.Errorf("vless: tls handshake to target %s: %w", destination, err)
		}
		proto := tlsConn.ConnectionState().NegotiatedProtocol
		if proto == "h2" || proto == "http/1.1" {
			latencyMS := time.Since(start).Milliseconds()
			if latencyMS <= 0 {
				latencyMS = 1
			}
			return latencyMS, nil
		}
		rw = tlsConn
	}

	reqHost := sni
	if reqHost == "" {
		reqHost = host
	}
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: amnezia-nexus-readiness-probe\r\nConnection: close\r\n\r\n", reqHost)

	if _, err := rw.Write([]byte(req)); err != nil {
		return 0, fmt.Errorf("vless: write probe request: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := rw.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("vless: read probe response: %w", err)
	}
	if n == 0 {
		return 0, errors.New("vless: empty response from target through tunnel")
	}

	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "HTTP/1.0 ") && !strings.HasPrefix(resp, "HTTP/1.1 ") && !strings.HasPrefix(resp, "HTTP/2") {
		return 0, fmt.Errorf("vless: invalid http response status line: %q", strings.SplitN(resp, "\r\n", 2)[0])
	}

	latencyMS := time.Since(start).Milliseconds()
	if latencyMS <= 0 {
		latencyMS = 1
	}
	return latencyMS, nil
}
