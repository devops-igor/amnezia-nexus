//go:build with_utls && !race

package vless

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

func TestVision_TCPRoundTrip(t *testing.T) {
	fixture := setupTestServer(t, "xtls-rprx-vision", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New dialer with vision flow: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext tcp (vision): %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 256*1024)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errChan <- err
	}()

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("io.ReadFull (vision): %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("conn.Write error: %v", err)
	}

	if !bytes.Equal(payload, received) {
		t.Fatalf("TCP vision roundtrip mismatch: 256 KiB payload did not match byte-exact")
	}
}

func TestVision_UDPRoundTrip(t *testing.T) {
	fixture := setupTestServer(t, "xtls-rprx-vision", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startUDPEchoServer(t)
	defer cleanupEcho()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New dialer with vision flow: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext udp (vision): %v", err)
	}
	defer conn.Close()

	packets := [][]byte{
		[]byte("vision xudp packet 1"),
		bytes.Repeat([]byte("V"), 512),
		bytes.Repeat([]byte("W"), 1200),
	}

	recvBuf := make([]byte, 2048)
	for i, pkt := range packets {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(pkt); err != nil {
			t.Fatalf("vision pkt %d write error: %v", i, err)
		}

		n, err := conn.Read(recvBuf)
		if err != nil {
			t.Fatalf("vision pkt %d read error: %v", i, err)
		}
		if !bytes.Equal(recvBuf[:n], pkt) {
			t.Fatalf("vision pkt %d mismatch: got %d bytes, want %d bytes", i, n, len(pkt))
		}
	}
}

func TestVision_ProbeSuccess(t *testing.T) {
	fixture := setupTestServer(t, "xtls-rprx-vision", 0)
	defer fixture.ServerClose()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latencyMS, err := ProbeVLESSReality(ctx, fixture.Endpoint, fixture.Params, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeVLESSReality with vision params failed: %v", err)
	}

	if latencyMS < 1 {
		t.Fatalf("expected latencyMS >= 1, got %d", latencyMS)
	}
}
