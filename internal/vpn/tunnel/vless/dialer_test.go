//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDialer_ConstructionValidation(t *testing.T) {
	validEndpoint := "127.0.0.1:443"
	validParams := models.VLESSRealityParams{
		UUID:        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		Flow:        "",
		PublicKey:   "e-JgU2X7X8aH1pQ1pZqUuWbWw5K2s6J8f8gH9jK1lM4",
		ShortID:     "0123456789abcdef",
		ServerName:  "example.com",
		Fingerprint: "chrome",
	}

	tests := []struct {
		name     string
		endpoint string
		modify   func(p *models.VLESSRealityParams)
		wantErr  string
	}{
		{
			name:     "invalid endpoint format",
			endpoint: "not-an-endpoint",
			modify:   nil,
			wantErr:  "invalid endpoint",
		},
		{
			name:     "endpoint empty host",
			endpoint: ":443",
			modify:   nil,
			wantErr:  "endpoint host cannot be empty",
		},
		{
			name:     "endpoint invalid port",
			endpoint: "127.0.0.1:99999",
			modify:   nil,
			wantErr:  "invalid endpoint port",
		},
		{
			name:     "endpoint non-numeric port",
			endpoint: "127.0.0.1:xyz",
			modify:   nil,
			wantErr:  "invalid endpoint port",
		},
		{
			name:     "invalid non-RFC4122 UUID",
			endpoint: validEndpoint,
			modify: func(p *models.VLESSRealityParams) {
				p.UUID = "not-a-canonical-uuid-string"
			},
			wantErr: "invalid uuid",
		},
		{
			name:     "short_id exceeds 16 hex chars",
			endpoint: validEndpoint,
			modify: func(p *models.VLESSRealityParams) {
				p.ShortID = "0123456789abcdef01"
			},
			wantErr: "short_id exceeds 16 hex characters",
		},
		{
			name:     "short_id invalid hex characters",
			endpoint: validEndpoint,
			modify: func(p *models.VLESSRealityParams) {
				p.ShortID = "not-hex-chars!!"
			},
			wantErr: "invalid short_id",
		},
		{
			name:     "invalid base64 public key",
			endpoint: validEndpoint,
			modify: func(p *models.VLESSRealityParams) {
				p.PublicKey = "!!!not-valid-base64!!!"
			},
			wantErr: "invalid public_key",
		},
		{
			name:     "public key wrong length (not 32 bytes)",
			endpoint: validEndpoint,
			modify: func(p *models.VLESSRealityParams) {
				p.PublicKey = "AAAA" // only 3 bytes
			},
			wantErr: "public_key must be 32 bytes",
		},
		{
			name:     "unsupported flow",
			endpoint: validEndpoint,
			modify: func(p *models.VLESSRealityParams) {
				p.Flow = "unsupported-flow-xyz"
			},
			wantErr: "unsupported flow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := validParams
			if tc.modify != nil {
				tc.modify(&p)
			}
			dialer, err := New(tc.endpoint, p)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil dialer: %v", tc.wantErr, dialer)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.wantErr)) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestDialer_TCPRoundTrip(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext tcp: %v", err)
	}
	defer conn.Close()

	// 256 KiB payload byte-exact round-trip
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
		t.Fatalf("io.ReadFull: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("conn.Write error: %v", err)
	}

	if !bytes.Equal(payload, received) {
		t.Fatalf("TCP roundtrip mismatch: 256 KiB payload did not match byte-exact")
	}
}

func TestDialer_UDPRoundTrip(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startUDPEchoServer(t)
	defer cleanupEcho()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "udp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext udp: %v", err)
	}
	defer conn.Close()

	packets := [][]byte{
		[]byte("hello vless udp packet 1"),
		bytes.Repeat([]byte("B"), 512),
		bytes.Repeat([]byte("C"), 1400),
	}

	recvBuf := make([]byte, 2048)
	for i, pkt := range packets {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(pkt); err != nil {
			t.Fatalf("pkt %d write error: %v", i, err)
		}

		n, err := conn.Read(recvBuf)
		if err != nil {
			t.Fatalf("pkt %d read error: %v", i, err)
		}
		if !bytes.Equal(recvBuf[:n], pkt) {
			t.Fatalf("pkt %d mismatch: got %d bytes, want %d bytes", i, n, len(pkt))
		}
	}
}

func TestDialer_ReadDeadlineTimeout(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	t.Run("TCP read deadline", func(t *testing.T) {
		blackholeAddr, cleanup := startBlackholeListener(t)
		defer cleanup()

		d, err := New(fixture.Endpoint, fixture.Params)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := d.DialContext(ctx, "tcp", blackholeAddr)
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("expected timeout error on read, got nil")
		}

		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected net.Error timeout, got: %v", err)
		}
	})

	t.Run("UDP read deadline and recovery", func(t *testing.T) {
		echoAddr, cleanupEcho := startUDPEchoServer(t)
		defer cleanupEcho()

		d, err := New(fixture.Endpoint, fixture.Params)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := d.DialContext(ctx, "udp", echoAddr)
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		defer conn.Close()

		// Set tight read deadline with no write sent
		_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		buf := make([]byte, 64)
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("expected timeout error on unwritten UDP read")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected net.Error timeout, got: %v", err)
		}

		// Verify UDP connection is still usable after timeout
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		pkt := []byte("recovery packet after timeout")
		if _, err := conn.Write(pkt); err != nil {
			t.Fatalf("write after timeout error: %v", err)
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read after timeout error: %v", err)
		}
		if !bytes.Equal(buf[:n], pkt) {
			t.Fatalf("packet mismatch after timeout recovery")
		}
	})
}

func TestDialer_WrongUUIDBehavior(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	wrongParams := fixture.Params
	wrongParams.UUID = "00000000-0000-0000-0000-000000000001" // Different UUID from server's registered client

	d, err := New(fixture.Endpoint, wrongParams)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Dial MUST succeed at the REALITY TLS layer
	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("expected dial to succeed despite wrong UUID, got: %v", err)
	}
	defer conn.Close()

	// Writing payload
	_, err = conn.Write([]byte("ping with wrong uuid"))
	if err != nil {
		t.Logf("conn.Write error: %v", err)
	}

	// First read must time out or fail because the server drops unknown UUIDs silently
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("expected read error/timeout for wrong UUID, got nil")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && !netErr.Timeout() && !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected error type for wrong UUID: %v", err)
	}
}

func TestDialer_GoroutineLeak(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanupEcho := startTCPEchoServer(t)
	defer cleanupEcho()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Warmup cycle
	ctx := context.Background()
	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("warmup dial: %v", err)
	}
	_, _ = conn.Write([]byte("warmup"))
	_ = conn.Close()

	// Allow runtime to settle
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	const iterations = 50
	for i := 0; i < iterations; i++ {
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := d.DialContext(dialCtx, "tcp", echoAddr)
		dialCancel()
		if err != nil {
			t.Fatalf("cycle %d dial error: %v", i, err)
		}
		_, _ = c.Write([]byte("cycle ping"))
		buf := make([]byte, 10)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = c.Read(buf)
		_ = c.Close()
	}

	// Settle check
	settled := false
	var finalCount int
	for attempt := 0; attempt < 20; attempt++ {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		finalCount = runtime.NumGoroutine()
		if finalCount <= baseline+3 {
			settled = true
			break
		}
	}

	if !settled {
		t.Fatalf("goroutine leak detected: baseline=%d, final=%d (+%d)", baseline, finalCount, finalCount-baseline)
	}
}

func startServerFirstTCPServer(t *testing.T, banner string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen server-first tcp: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
	}
}

func TestDialer_ServerFirstTCP(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	const banner = "SSH-2.0-OpenSSH_9.0\r\n"
	serverAddr, cleanup := startServerFirstTCPServer(t, banner)
	defer cleanup()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		t.Fatalf("DialContext tcp: %v", err)
	}
	defer conn.Close()

	// Assert server-first protocol: read banner immediately without writing first
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(banner))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read server-first banner without writing: %v", err)
	}

	if string(buf) != banner {
		t.Fatalf("unexpected banner: got %q, want %q", string(buf), banner)
	}
}

func TestDialer_ModernPQFingerprintFallback(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	chReceived := make(chan []byte, 1)
	go func() {
		c, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		chReceived <- buf[:n]
	}()

	params := fixture.Params
	params.EngineProfile = "modern_pq"
	params.Fingerprint = "ios" // iOS fingerprint does not have X25519MLKEM768 shares

	d, err := New(ln.Addr().String(), params)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_, _ = d.DialContext(ctx, "tcp", "127.0.0.1:80")
	}()

	var rawHello []byte
	select {
	case rawHello = <-chReceived:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for ClientHello")
	}

	groups, _, _, err := parseClientHelloKeyShares(rawHello)
	if err != nil {
		t.Fatalf("parse ClientHello: %v", err)
	}

	// Verify that X25519MLKEM768 (4588) key share is present despite requesting "ios" fingerprint
	hasPQShare := false
	for _, g := range groups {
		if g == 4588 {
			hasPQShare = true
			break
		}
	}
	if !hasPQShare {
		t.Errorf("expected modern_pq fallback to include group 4588 (X25519MLKEM768), got groups: %v", groups)
	}
}
