//go:build with_utls

package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProbeVLESSReality_Success(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeVLESSReality(ctx, fixture.Endpoint, fixture.Params, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeVLESSReality failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}
}

func TestProbeVLESSReality_DestDelayTracking(t *testing.T) {
	// Baseline fixture with 0 delay
	fastFixture := setupTestServer(t, "", 0)
	defer fastFixture.ServerClose()

	ctx := context.Background()
	fastLatency, err := ProbeVLESSReality(ctx, fastFixture.Endpoint, fastFixture.Params, 3*time.Second)
	if err != nil {
		t.Fatalf("fast probe failed: %v", err)
	}

	// Delayed fixture with 60ms artificial delay on decoy server
	const delay = 60 * time.Millisecond
	delayedFixture := setupTestServer(t, "", delay)
	defer delayedFixture.ServerClose()

	delayedLatency, err := ProbeVLESSReality(ctx, delayedFixture.Endpoint, delayedFixture.Params, 3*time.Second)
	if err != nil {
		t.Fatalf("delayed probe failed: %v", err)
	}

	// Verify that latency reflects the dest delay and is not a constant
	if delayedLatency < fastLatency+40 {
		t.Fatalf("dest delay not tracked: fast=%d ms, delayed=%d ms (expected >= %d ms)",
			fastLatency, delayedLatency, fastLatency+40)
	}
}

func TestProbeVLESSReality_Failures(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	t.Run("wrong public key", func(t *testing.T) {
		wrongParams := fixture.Params
		wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate wrong key: %v", err)
		}
		wrongParams.PublicKey = base64.RawURLEncoding.EncodeToString(wrongKey.PublicKey().Bytes())
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err = ProbeVLESSReality(ctx, fixture.Endpoint, wrongParams, 2*time.Second)
		if err == nil {
			t.Fatalf("expected error for wrong public key, got nil")
		}
		if !strings.Contains(err.Error(), "reality verification failed") {
			t.Fatalf("expected 'reality verification failed', got: %v", err)
		}
	})

	t.Run("wrong short_id", func(t *testing.T) {
		wrongParams := fixture.Params
		wrongParams.ShortID = "ffffffffffffffff"
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := ProbeVLESSReality(ctx, fixture.Endpoint, wrongParams, 2*time.Second)
		if err == nil {
			t.Fatalf("expected error for wrong short_id, got nil")
		}
		if !strings.Contains(err.Error(), "reality verification failed") {
			t.Fatalf("expected 'reality verification failed', got: %v", err)
		}
	})

	t.Run("plain non-REALITY decoy site", func(t *testing.T) {
		// Probe the decoy server directly instead of the REALITY server
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err := ProbeVLESSReality(ctx, fixture.DecoyAddr, fixture.Params, 2*time.Second)
		if err == nil {
			t.Fatalf("expected error when probing plain TLS site, got nil")
		}
		// Decoy site possesses valid TLS certificate for example.com, but lacks REALITY signature
		if !strings.Contains(err.Error(), "reality verification failed") {
			t.Fatalf("expected 'reality verification failed', got: %v", err)
		}
	})

	t.Run("dest unreachable / connection refused", func(t *testing.T) {
		// Choose a free port that is closed
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		closedAddr := ln.Addr().String()
		_ = ln.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_, err = ProbeVLESSReality(ctx, closedAddr, fixture.Params, 1*time.Second)
		if err == nil {
			t.Fatalf("expected error for closed port, got nil")
		}
	})

	t.Run("timeout exceeded", func(t *testing.T) {
		blackholeAddr, cleanup := startBlackholeListener(t)
		defer cleanup()

		ctx := context.Background()
		start := time.Now()
		_, err := ProbeVLESSReality(ctx, blackholeAddr, fixture.Params, 100*time.Millisecond)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatalf("expected timeout error, got nil")
		}
		if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "i/o timeout") {
			t.Fatalf("expected deadline exceeded, got: %v", err)
		}
		if elapsed > 1*time.Second {
			t.Fatalf("probe did not respect timeout: elapsed %v", elapsed)
		}
	})

	t.Run("parent context cancellation", func(t *testing.T) {
		blackholeAddr, cleanup := startBlackholeListener(t)
		defer cleanup()

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		_, err := ProbeVLESSReality(ctx, blackholeAddr, fixture.Params, 5*time.Second)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatalf("expected context cancellation error, got nil")
		}
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Fatalf("expected context canceled, got: %v", err)
		}
		if elapsed > 1*time.Second {
			t.Fatalf("probe did not respect cancellation: elapsed %v", elapsed)
		}
	})
}

func TestProbeVLESSTraffic_Success(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, fixture.Params, echoAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeVLESSTrafficWithTarget failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}
}

func TestProbeVLESSTraffic_UnauthorizedClient(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wrongParams := fixture.Params
	wrongParams.UUID = "00000000-0000-0000-0000-000000000000"

	_, err := ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, wrongParams, echoAddr, 2*time.Second)
	if err == nil {
		t.Fatal("expected error for unauthorized client UUID, got nil")
	}
}

func TestProbeVLESSTraffic_UnreachableDestination(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	// Allocate and close local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedDest := ln.Addr().String()
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, fixture.Params, closedDest, 2*time.Second)
	if err == nil {
		t.Fatal("expected error for unreachable destination through tunnel, got nil")
	}
}
