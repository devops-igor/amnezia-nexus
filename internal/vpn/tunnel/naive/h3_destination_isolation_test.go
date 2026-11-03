package naive

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// destinationAwareSOCKS5Server is an RFC 1928 SOCKS5 test listener that can simulate
// both successful proxied streams and destination-level rejections (e.g. 0x05 Connection Refused).
func destinationAwareSOCKS5Server(t *testing.T, replyCodeForDest func(dst string) byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock SOCKS5 listen: %v", err)
	}

	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read greeting [VER, NMETHODS, METHODS...]
				buf := make([]byte, 258)
				n, err := io.ReadAtLeast(c, buf, 2)
				if err != nil || n < 2 || buf[0] != 0x05 {
					return
				}
				nMethods := int(buf[1])
				if n < 2+nMethods {
					if _, err := io.ReadFull(c, buf[n:2+nMethods]); err != nil {
						return
					}
				}
				// Reply: Version 5, NO_AUTH (0x00)
				if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
					return
				}

				// Read request [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if req[0] != 0x05 || req[1] != 0x01 { // CMD 0x01 = CONNECT
					return
				}

				var destHost string
				atyp := req[3]
				switch atyp {
				case 0x01: // IPv4 (4 bytes)
					ipBuf := make([]byte, 4)
					if _, err := io.ReadFull(c, ipBuf); err != nil {
						return
					}
					destHost = net.IP(ipBuf).String()
				case 0x03: // FQDN (1 byte length + domain)
					lenBuf := make([]byte, 1)
					if _, err := io.ReadFull(c, lenBuf); err != nil {
						return
					}
					nameBuf := make([]byte, int(lenBuf[0]))
					if _, err := io.ReadFull(c, nameBuf); err != nil {
						return
					}
					destHost = string(nameBuf)
				case 0x04: // IPv6 (16 bytes)
					ipBuf := make([]byte, 16)
					if _, err := io.ReadFull(c, ipBuf); err != nil {
						return
					}
					destHost = net.IP(ipBuf).String()
				default:
					return
				}

				portBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, portBuf); err != nil {
					return
				}
				port := int(portBuf[0])<<8 | int(portBuf[1])
				dest := net.JoinHostPort(destHost, strconv.Itoa(port))

				replyCode := byte(0x00) // Succeeded
				if replyCodeForDest != nil {
					replyCode = replyCodeForDest(dest)
				}

				if replyCode != 0x00 {
					// Return SOCKS5 error reply
					_, _ = c.Write([]byte{0x05, replyCode, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
					return
				}

				// Reply: Success
				resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port & 0xff)}
				if _, err := c.Write(resp); err != nil {
					return
				}

				// Echo back payload until client closes
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String(), func() {
		close(stopCh)
		_ = ln.Close()
	}
}

// TestH3DestinationIsolation_ActiveStreamSurvivesRefusedDestination verifies Finding F1:
// When Client A has an active healthy H3 stream, and Client B encounters a remote destination
// connection refusal (e.g. SOCKS5 status 0x05), the dialer must NOT trigger fallbackToH2()
// or terminate Client A's stream.
func TestH3DestinationIsolation_ActiveStreamSurvivesRefusedDestination(t *testing.T) {
	workingDest := "working-destination.example.com:80"
	refusedDest := "refused-destination.example.com:80"

	socksAddr, cleanupSocks := destinationAwareSOCKS5Server(t, func(dst string) byte {
		if strings.HasPrefix(dst, "refused-destination") {
			return 0x05 // Connection Refused
		}
		return 0x00 // Succeeded
	})
	defer cleanupSocks()

	socksDialer, err := NewSocks5Dialer(socksAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}

	p := models.NaiveProxyParams{
		Username:    "testuser",
		Password:    "testpass",
		Domain:      "camouflage.example.com",
		EnableH3:    true,
		H3Supported: true,
	}

	d, err := New("198.51.100.1:443", p, WithSocks5Dialer(socksDialer))
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer func() { _ = d.Close() }()

	ctx := context.Background()

	// 1. Client A establishes a healthy TCP stream
	connA, err := d.DialContext(ctx, "tcp", workingDest)
	if err != nil {
		t.Fatalf("Client A dial failed: %v", err)
	}
	defer connA.Close()

	payload1 := []byte("ping-client-a-initial")
	if _, err := connA.Write(payload1); err != nil {
		t.Fatalf("Client A write payload 1: %v", err)
	}
	buf1 := make([]byte, len(payload1))
	if _, err := io.ReadFull(connA, buf1); err != nil {
		t.Fatalf("Client A read payload 1: %v", err)
	}
	if !bytes.Equal(buf1, payload1) {
		t.Fatalf("Client A payload mismatch: got %q, want %q", buf1, payload1)
	}

	// 2. Client B connects to a destination that refuses the connection
	connB, errB := d.DialContext(ctx, "tcp", refusedDest)
	if errB == nil {
		_ = connB.Close()
		t.Fatal("expected Client B dial to fail on refused destination, but got nil")
	}

	// 3. Verify dialer state: H3 capability and dialer must remain active
	d.daemonMu.Lock()
	h3Supported := d.params.H3Supported
	sdAfterB := d.socks5Dialer
	lastErr := d.lastErr
	d.daemonMu.Unlock()

	if !h3Supported {
		t.Error("Finding F1 regression: H3 capability was disabled (fallbackToH2 triggered) on destination error!")
	}
	if sdAfterB == nil {
		t.Error("Finding F1 regression: socks5Dialer was cleared by fallbackToH2 on destination error!")
	}
	if !d.IsHealthy() {
		t.Errorf("expected dialer to remain healthy after destination refusal, got IsHealthy=false, lastErr=%v", lastErr)
	}

	// 4. Verify Client A's connection is STILL alive and usable
	payload2 := []byte("ping-client-a-after-client-b-refusal")
	if _, err := connA.Write(payload2); err != nil {
		t.Fatalf("Finding F1 regression: Client A stream was terminated after Client B failure: write failed: %v", err)
	}
	buf2 := make([]byte, len(payload2))
	if _, err := io.ReadFull(connA, buf2); err != nil {
		t.Fatalf("Finding F1 regression: Client A stream was terminated after Client B failure: read failed: %v", err)
	}
	if !bytes.Equal(buf2, payload2) {
		t.Fatalf("Client A payload mismatch after refusal: got %q, want %q", buf2, payload2)
	}

	// 5. Subsequent new dial (Client C) continues to work over H3 transport
	connC, errC := d.DialContext(ctx, "tcp", workingDest)
	if errC != nil {
		t.Fatalf("Client C dial failed: %v", errC)
	}
	defer connC.Close()

	payloadC := []byte("ping-client-c")
	if _, err := connC.Write(payloadC); err != nil {
		t.Fatalf("Client C write failed: %v", err)
	}
	bufC := make([]byte, len(payloadC))
	if _, err := io.ReadFull(connC, bufC); err != nil {
		t.Fatalf("Client C read failed: %v", err)
	}
	if !bytes.Equal(bufC, payloadC) {
		t.Fatalf("Client C payload mismatch: got %q, want %q", bufC, payloadC)
	}
}

// TestH3DestinationIsolation_MultipleSocksRejectionCodes verifies that none of the
// remote SOCKS5 destination error codes cause a transport fallback.
func TestH3DestinationIsolation_MultipleSocksRejectionCodes(t *testing.T) {
	testCases := []struct {
		name      string
		replyCode byte
	}{
		{"ConnectionNotAllowed", 0x02},
		{"NetworkUnreachable", 0x03},
		{"HostUnreachable", 0x04},
		{"ConnectionRefused", 0x05},
		{"TTLExpired", 0x06},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var currentReply atomic.Uint32
			currentReply.Store(0x00)

			socksAddr, cleanupSocks := destinationAwareSOCKS5Server(t, func(dst string) byte {
				if strings.Contains(dst, "failing") {
					return byte(currentReply.Load())
				}
				return 0x00
			})
			defer cleanupSocks()

			socksDialer, err := NewSocks5Dialer(socksAddr)
			if err != nil {
				t.Fatalf("NewSocks5Dialer: %v", err)
			}

			p := models.NaiveProxyParams{
				Username:    "alice",
				Password:    "secret",
				Domain:      "camouflage.example.com",
				EnableH3:    true,
				H3Supported: true,
			}

			d, err := New("198.51.100.1:443", p, WithSocks5Dialer(socksDialer))
			if err != nil {
				t.Fatalf("New dialer: %v", err)
			}
			defer func() { _ = d.Close() }()

			ctx := context.Background()

			// Active stream
			connA, err := d.DialContext(ctx, "tcp", "working.example.com:80")
			if err != nil {
				t.Fatalf("dial working stream: %v", err)
			}
			defer connA.Close()

			// Trigger destination rejection
			currentReply.Store(uint32(tc.replyCode))
			_, errB := d.DialContext(ctx, "tcp", "failing.example.com:80")
			if errB == nil {
				t.Fatalf("expected dial to failing destination with code 0x%02x to return error", tc.replyCode)
			}

			// Verify H3 not downgraded
			d.daemonMu.Lock()
			h3Supported := d.params.H3Supported
			d.daemonMu.Unlock()
			if !h3Supported {
				t.Errorf("code 0x%02x triggered H3 downgrade!", tc.replyCode)
			}

			// Stream A still functional
			testData := []byte("active-payload")
			if _, err := connA.Write(testData); err != nil {
				t.Fatalf("stream A write failed after code 0x%02x: %v", tc.replyCode, err)
			}
			recv := make([]byte, len(testData))
			if _, err := io.ReadFull(connA, recv); err != nil {
				t.Fatalf("stream A read failed after code 0x%02x: %v", tc.replyCode, err)
			}
		})
	}
}

// TestH3DestinationIsolation_UpstreamFailureTriggersFallback verifies that authentic
// upstream transport failures (like local proxy disconnection) STILL trigger fallback to H2.
func TestH3DestinationIsolation_UpstreamFailureTriggersFallback(t *testing.T) {
	// A server that closes connections immediately on request (simulating upstream crash/EOF)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Close immediately without SOCKS response -> EOF on client
			_ = c.Close()
		}
	}()

	socksDialer, err := NewSocks5Dialer(ln.Addr().String())
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}

	p := models.NaiveProxyParams{
		Username:    "alice",
		Password:    "secret",
		Domain:      "camouflage.example.com",
		EnableH3:    true,
		H3Supported: true,
	}

	d, err := New("198.51.100.1:443", p, WithSocks5Dialer(socksDialer), WithInProcessFallback())
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer func() { _ = d.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _ = d.DialContext(ctx, "tcp", "target.example.com:80")

	d.daemonMu.Lock()
	h3Supported := d.params.H3Supported
	d.daemonMu.Unlock()

	if h3Supported {
		t.Error("expected upstream EOF to trigger fallbackToH2 (H3Supported should become false)")
	}
}

// TestH3DestinationIsolation_ProbeDestinationRefusal_NoFallback verifies that
// a destination connection refusal during a probe does NOT cause fallback to H2.
func TestH3DestinationIsolation_ProbeDestinationRefusal_NoFallback(t *testing.T) {
	socksAddr, cleanupSocks := destinationAwareSOCKS5Server(t, func(dst string) byte {
		return 0x05 // Connection Refused
	})
	defer cleanupSocks()

	socksDialer, err := NewSocks5Dialer(socksAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}

	p := models.NaiveProxyParams{
		Username:    "alice",
		Password:    "secret",
		Domain:      "camouflage.example.com",
		EnableH3:    true,
		H3Supported: true,
	}

	d, err := New("198.51.100.1:443", p, WithSocks5Dialer(socksDialer))
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer func() { _ = d.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	camTarget := "camouflage.example.com:443"
	_, probeErr := d.probeViaDaemonWithFallback(ctx, camTarget, p, socksDialer)
	if probeErr == nil {
		t.Fatal("expected probe to fail on refused destination, got nil")
	}

	d.daemonMu.Lock()
	h3Supported := d.params.H3Supported
	d.daemonMu.Unlock()

	if !h3Supported {
		t.Error("Finding F1 regression: probe destination refusal triggered fallbackToH2 (H3Supported became false)!")
	}
}
