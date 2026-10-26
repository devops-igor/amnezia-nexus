package naive

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestProbeNaiveProxy_Success_H2(t *testing.T) {
	proxyAddr, cleanup := setupTestH2Server(t, "userA", "passA", true)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "userA",
		Password: "passA",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy H2 failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}
}

func TestProbeNaiveProxy_Success_H3(t *testing.T) {
	proxyAddr, cleanup := setupTestH3Server(t, "userA", "passA", true)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "userA",
		Password: "passA",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy H3 failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}
}

func TestProbeNaiveProxy_H3FallbackToH2(t *testing.T) {
	// Only start H2 server, UDP/QUIC listener does not exist
	proxyAddr, cleanup := setupTestH2Server(t, "userA", "passA", true)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "userA",
		Password: "passA",
		Domain:   testCamouflageDomain,
		EnableH3: true, // H3 requested, should gracefully fall back to H2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy H3 fallback to H2 failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}
}

func TestProbeNaiveProxy_UnauthenticatedRedirect308(t *testing.T) {
	// Server returns 308 redirect for unauthenticated requests
	proxyAddr, cleanup := setupTestH2Server(t, "correctUser", "correctPass", true)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "wrongUser",
		Password: "wrongPass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err == nil {
		t.Fatalf("expected error for 308 redirect, got success with %d ms", latencyMS)
	}

	if !strings.Contains(err.Error(), "unauthenticated redirect") {
		t.Fatalf("expected 'unauthenticated redirect' error, got: %v", err)
	}
}

func TestProbeNaiveProxy_ProxyAuthRequired407(t *testing.T) {
	// Server returns 407 Proxy Authentication Required
	proxyAddr, cleanup := setupTestH2Server(t, "correctUser", "correctPass", false)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "wrongUser",
		Password: "wrongPass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err == nil {
		t.Fatalf("expected error for 407 status, got success with %d ms", latencyMS)
	}

	if !strings.Contains(err.Error(), "proxy authentication rejected") {
		t.Fatalf("expected 'proxy authentication rejected' error, got: %v", err)
	}
}

func TestProbeNaiveProxy_Timeout(t *testing.T) {
	blackholeAddr, cleanup := startBlackholeListener(t)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx := context.Background()
	start := time.Now()
	_, err := ProbeNaiveProxy(ctx, blackholeAddr, p, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) &&
		!strings.Contains(err.Error(), "context deadline exceeded") &&
		!strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("expected deadline exceeded, got: %v", err)
	}

	if elapsed > 1*time.Second {
		t.Fatalf("probe did not respect timeout: elapsed %v", elapsed)
	}
}

func TestProbeNaiveProxy_Cancellation(t *testing.T) {
	blackholeAddr, cleanup := startBlackholeListener(t)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := ProbeNaiveProxy(ctx, blackholeAddr, p, 5*time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected cancellation error, got nil")
	}

	if !errors.Is(err, context.Canceled) &&
		!strings.Contains(err.Error(), "context canceled") &&
		!strings.Contains(err.Error(), "use of closed network connection") {
		t.Fatalf("expected context canceled, got: %v", err)
	}

	if elapsed > 1*time.Second {
		t.Fatalf("probe did not respect cancellation: elapsed %v", elapsed)
	}
}

func TestProbeNaiveProxyTunnel(t *testing.T) {
	proxyAddr, cleanup := setupTestH2Server(t, "userA", "passA", true)
	defer cleanup()

	p := models.NaiveProxyParams{
		Username: "userA",
		Password: "passA",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	rawParams, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	tunnel := &models.BackendTunnel{
		ID:             1,
		Endpoint:       proxyAddr,
		Protocol:       models.ProtocolNaive,
		ProtocolParams: rawParams,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeNaiveProxyTunnel(ctx, tunnel, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxyTunnel failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}

	// Negative test: nil tunnel
	_, err = ProbeNaiveProxyTunnel(ctx, nil, 3*time.Second)
	if err == nil {
		t.Fatal("expected error for nil tunnel, got nil")
	}

	// Negative test: invalid json
	invalidTunnel := &models.BackendTunnel{
		Endpoint:       proxyAddr,
		ProtocolParams: []byte("not-json"),
	}
	_, err = ProbeNaiveProxyTunnel(ctx, invalidTunnel, 3*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid json params, got nil")
	}
}

func TestProbeNaiveProxy_ClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()

	p := models.NaiveProxyParams{
		Username: "u",
		Password: "p",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = ProbeNaiveProxy(ctx, closedAddr, p, 1*time.Second)
	if err == nil {
		t.Fatal("expected error for closed port, got nil")
	}
}
