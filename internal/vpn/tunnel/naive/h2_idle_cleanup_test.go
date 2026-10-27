package naive

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Retired (saturated, then drained) HTTP/2 connections must be closed by the idle
// timeout and dropped from the pool, without disturbing a stream still active on
// a sibling connection or closing the dialer.
//
//nolint:staticcheck // SA1019: x/net/http2.ClientConn required for low-level H2 CONNECT pooling
func TestDialer_H2_RetiredIdleConnectionsCleanedUp(t *testing.T) {
	prev := h2IdleConnTimeout
	h2IdleConnTimeout = 300 * time.Millisecond
	t.Cleanup(func() { h2IdleConnTimeout = prev })

	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()
	// MaxConcurrentStreams = 1: each concurrent CONNECT rotates to a new ClientConn.
	proxyAddr, cleanupH2 := setupTestH2ServerWithMaxStreams(t, "testuser", "testpass", 1)
	defer cleanupH2()

	d, err := New(proxyAddr, models.NaiveProxyParams{
		Username: "testuser", Password: "testpass", Domain: testCamouflageDomain,
	})
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn1, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 1: %v", err)
	}
	conn2, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 2: %v", err)
	}
	conn3, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 3: %v", err)
	}
	defer conn3.Close()

	tracked := d.h2Pool.trackedConns()
	if len(tracked) != 3 {
		t.Fatalf("expected 3 tracked connections, got %d", len(tracked))
	}

	// Drain the two retired connections; conn3 keeps its stream open.
	retired := map[any]bool{}
	for _, cc := range tracked {
		if cc != d.h2Pool.cc {
			retired[cc] = true
		}
	}
	_ = conn1.Close()
	_ = conn2.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		closed := 0
		for _, cc := range tracked {
			if retired[cc] && cc.State().Closed {
				closed++
			}
		}
		if closed == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("retired idle connections not closed by idle timeout (closed %d/2)", closed)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Next pool access prunes the closed retired connections.
	conn4, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext 4 (dialer must remain usable): %v", err)
	}
	defer conn4.Close()
	for _, cc := range d.h2Pool.trackedConns() {
		if retired[cc] {
			t.Fatalf("closed retired connection %p still tracked", cc)
		}
	}

	// The still-active stream on the busy connection is undisturbed.
	msg := []byte("still alive")
	if _, err := conn3.Write(msg); err != nil {
		t.Fatalf("conn3 write: %v", err)
	}
	recv := make([]byte, len(msg))
	if _, err := io.ReadFull(conn3, recv); err != nil || !bytes.Equal(recv, msg) {
		t.Fatalf("conn3 echo: got %q, err %v", recv, err)
	}
}
