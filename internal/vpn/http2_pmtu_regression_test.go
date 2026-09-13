package vpn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/database"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
	"github.com/devops-igor/amnezia-web-ui-go/internal/vpn/tunnel"
)

// generateTestTLSCert creates an in-memory self-signed ECDSA certificate for testing.
func generateTestTLSCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}

	certPool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}
	certPool.AddCert(parsed)

	return cert, certPool
}

// TestClientConfig_MTU_DefaultsTo1280 verifies that client configuration generation
// sets MTU to 1280 (matching the backend container MTU and AmneziaWG defaults),
// eliminating the previous MTU 1420 mismatch that caused PMTU black hole drops.
func TestClientConfig_MTU_DefaultsTo1280(t *testing.T) {
	ctx := context.Background()
	db, err := database.New(":memory:", "test-secret")
	if err != nil {
		t.Fatalf("database.New failed: %v", err)
	}
	defer db.Close()

	uID, err := db.CreateUser(ctx, &models.User{Username: "http2_user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	user, err := db.GetUser(ctx, uID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateClientConfig(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateClientConfig failed: %v", err)
	}

	if filename != "amnezia-portal-http2_user.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	// Must contain MTU = 1280
	if !strings.Contains(cfgStr, "MTU = 1280") {
		t.Errorf("expected client config to have 'MTU = 1280', got:\n%s", cfgStr)
	}

	// Must NOT contain the old oversized MTU = 1420
	if strings.Contains(cfgStr, "MTU = 1420") {
		t.Errorf("client config still contains broken 'MTU = 1420':\n%s", cfgStr)
	}
}

// TestClientConfig_MTU_CustomClientParams verifies that an explicitly configured MTU
// in connection ClientParams is honored during client configuration rendering.
func TestClientConfig_MTU_CustomClientParams(t *testing.T) {
	ctx := context.Background()
	db, err := database.New(":memory:", "test-secret")
	if err != nil {
		t.Fatalf("database.New failed: %v", err)
	}
	defer db.Close()

	uID, err := db.CreateUser(ctx, &models.User{Username: "custom_mtu_user", Enabled: true})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	user, err := db.GetUser(ctx, uID)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	// Pre-create connection with explicit custom MTU = 1360
	connID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:     user.ID,
		ServerID:   0,
		Protocol:   "awg",
		ClientID:   "custom-pubkey-123456789012345678901234567890=",
		Name:       "custom-mtu-conn",
		AWGMimicry: models.AWGMimicryAuto,
		ClientParams: map[string]any{
			"mtu":                "1360",
			"client_private_key": "custom-privkey-123456789012345678901234567890=",
		},
	})
	if err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	cfgStr, filename, err := svc.GenerateClientConfigForConnection(ctx, user.ID, connID)
	if err != nil {
		t.Fatalf("GenerateClientConfigForConnection failed: %v", err)
	}

	if filename != "custom-mtu-conn.conf" {
		t.Errorf("unexpected filename: %s", filename)
	}

	if !strings.Contains(cfgStr, "MTU = 1360") {
		t.Errorf("expected client config to respect custom 'MTU = 1360', got:\n%s", cfgStr)
	}
}

// TestAttachBackendForwarder_MTU_MatchesBackendContainer verifies that attachBackendForwarder
// configures the backend AWGClientDevice with MTU = 1280 (matching the backend container's awg0 MTU)
// instead of the hardcoded 1340.
func TestAttachBackendForwarder_MTU_MatchesBackendContainer(t *testing.T) {
	ctx := context.Background()
	db, err := database.New(":memory:", "test-secret")
	if err != nil {
		t.Fatalf("database.New failed: %v", err)
	}
	defer db.Close()

	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	sID, pub, _ := createTestServerAndKey(t, db, "MTU Backend Server", "127.0.0.1")
	tun, err := svc.pool.AddTunnel(ctx, sID, "127.0.0.1:51820", pub)
	if err != nil {
		t.Fatalf("AddTunnel failed: %v", err)
	}

	svc.mu.Lock()
	err = svc.attachBackendForwarder(tun, nil)
	svc.mu.Unlock()
	if err != nil {
		t.Fatalf("attachBackendForwarder failed: %v", err)
	}

	dev := svc.GetBackendDeviceForTest(tun.ID)
	if dev == nil {
		t.Fatal("expected backend device attached, got nil")
	}
	defer dev.Close()

	awgDev, ok := dev.(*tunnel.AWGClientDevice)
	if !ok {
		t.Fatalf("expected *tunnel.AWGClientDevice, got %T", dev)
	}

	if awgDev.MTU() != 1280 {
		t.Errorf("expected backend device MTU = 1280, got %d", awgDev.MTU())
	}
}

// pmtuConstrainedConn models a TCP connection routed through a Path MTU constrained link.
// The TCP sender segments application stream writes into segments of at most mss bytes.
// If a segment's IP packet size (segment length + 40 bytes IP/TCP header) exceeds routerMTU,
// the router drops the packet (simulating DF=1 packet loss and a PMTU black hole).
type pmtuConstrainedConn struct {
	net.Conn
	mss       int
	routerMTU int
	dropCount *int
	mu        sync.Mutex
}

func (c *pmtuConstrainedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	total := len(b)
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > c.mss {
			chunkSize = c.mss
		}
		chunk := b[:chunkSize]
		b = b[chunkSize:]

		// IP packet length = TCP payload + 20 bytes IP + 20 bytes TCP
		ipPacketLen := len(chunk) + 40
		if ipPacketLen > c.routerMTU {
			// Dropped by intermediate router (e.g. awg0 with MTU 1280)
			*c.dropCount++
			continue
		}

		if _, err := c.Conn.Write(chunk); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// pmtuConstrainedListener wraps a net.Listener to produce pmtuConstrainedConn connections.
type pmtuConstrainedListener struct {
	net.Listener
	mss       int
	routerMTU int
	dropCount *int
}

func (l *pmtuConstrainedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &pmtuConstrainedConn{
		Conn:      c,
		mss:       l.mss,
		routerMTU: l.routerMTU,
		dropCount: l.dropCount,
	}, nil
}

// TestHTTP2_ProtocolAndMTU_Comparison demonstrates:
// 1. In the failure state (unclamped MSS 1380 from client MTU 1420 routed through backend MTU 1280):
//   - Small HTTP/1.1 requests succeed because segments are <= 1280 bytes.
//   - Large HTTP/2 data frames (> 1280 bytes) are segmented into 1380-byte packets that exceed
//     the 1280-byte MTU and are dropped by the router, causing connection stall and timeout.
//
// 2. In the fixed state (clamped MSS 1240 or client MTU 1280):
//   - All segments are <= 1240 bytes (IP packet <= 1280 bytes).
//   - Both HTTP/1.1 and HTTP/2 succeed completely with zero dropped packets, verifying
//     ALPN negotiation, TLS handshake, HTTP/2 SETTINGS exchange, HEADERS, and DATA frames.
func TestHTTP2_ProtocolAndMTU_Comparison(t *testing.T) {
	cert, certPool := generateTestTLSCert(t)

	largeResponseBody := strings.Repeat("A", 4096)
	smallResponseBody := "OK"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/small" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(smallResponseBody))
		} else {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(largeResponseBody))
		}
	})

	t.Run("FailureCase_UnclampedMSS_HTTP1WorksSmall_HTTP2FailsOnOversizedSegments", func(t *testing.T) {
		// Plain HTTP listener for small HTTP/1.1 requests (demonstrating why HTTP/1.1 appeared to work)
		rawHTTPLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer rawHTTPLn.Close()

		dropCountHTTP := 0
		// Unclamped MSS 1380 (from client MTU 1420), but router MTU is 1280
		constrainedHTTPLn := &pmtuConstrainedListener{
			Listener:  rawHTTPLn,
			mss:       1380,
			routerMTU: 1280,
			dropCount: &dropCountHTTP,
		}

		httpSrv := &http.Server{Handler: handler}
		go func() { _ = httpSrv.Serve(constrainedHTTPLn) }()
		defer func() { _ = httpSrv.Close() }()

		httpAddr := rawHTTPLn.Addr().String()

		// Small HTTP/1.1 request (status + headers + "OK" < 500 bytes)
		// 500 + 40 = 540 <= 1280: passes cleanly!
		h1Client := &http.Client{Timeout: 2 * time.Second}
		respH1, err := h1Client.Get(fmt.Sprintf("http://%s/small", httpAddr))
		if err != nil {
			t.Fatalf("HTTP/1.1 small request failed: %v", err)
		}
		bodyH1, _ := io.ReadAll(respH1.Body)
		_ = respH1.Body.Close()
		if string(bodyH1) != smallResponseBody {
			t.Errorf("HTTP/1.1 body mismatch: %s", string(bodyH1))
		}

		// Now test HTTP/2 over TLS on the same constrained link:
		rawTLSLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer rawTLSLn.Close()

		dropCountTLS := 0
		constrainedTLSLn := &pmtuConstrainedListener{
			Listener:  rawTLSLn,
			mss:       1380, // Unclamped MSS: packets are 1380 + 40 = 1420 bytes
			routerMTU: 1280, // Backend router MTU: drops any packet > 1280
			dropCount: &dropCountTLS,
		}

		serverTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		}
		tlsLn := tls.NewListener(constrainedTLSLn, serverTLSConfig)
		defer tlsLn.Close()

		tlsSrv := &http.Server{Handler: handler}
		go func() { _ = tlsSrv.Serve(tlsLn) }()
		defer func() { _ = tlsSrv.Close() }()

		tlsAddr := rawTLSLn.Addr().String()

		// HTTP/2 client requesting large response (4 KB):
		// Server writes 4 KB -> TCP segments into 1380-byte chunks -> IP packet 1420 bytes > 1280 -> DROPPED!
		h2Client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					NextProtos: []string{"h2"},
				},
				ForceAttemptHTTP2: true,
			},
			Timeout: 500 * time.Millisecond,
		}

		_, err = h2Client.Get(fmt.Sprintf("https://%s/large", tlsAddr))
		if err == nil {
			t.Fatal("expected HTTP/2 request to fail/timeout when segments exceed router MTU, got nil error")
		}

		if dropCountTLS == 0 {
			t.Error("expected oversized HTTP/2 segments to be dropped by the router")
		}
	})

	t.Run("SuccessCase_ClampedMSSOrAlignedMTU_BothHTTP1AndHTTP2Succeed", func(t *testing.T) {
		rawLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen failed: %v", err)
		}
		defer rawLn.Close()

		dropCount := 0
		// Clamped MSS: 1240 bytes (1280 MTU - 40 bytes IP/TCP header)
		// All packets are <= 1240 + 40 = 1280 bytes -> PASSES cleanly through router MTU 1280!
		properLn := &pmtuConstrainedListener{
			Listener:  rawLn,
			mss:       1240,
			routerMTU: 1280,
			dropCount: &dropCount,
		}

		serverTLSConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		}
		tlsLn := tls.NewListener(properLn, serverTLSConfig)
		defer tlsLn.Close()

		srv := &http.Server{Handler: handler}
		go func() { _ = srv.Serve(tlsLn) }()
		defer func() { _ = srv.Close() }()

		addr := rawLn.Addr().String()

		// 1. HTTP/1.1 request succeeds
		h1Client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					NextProtos: []string{"http/1.1"},
				},
			},
			Timeout: 2 * time.Second,
		}
		respH1, err := h1Client.Get(fmt.Sprintf("https://%s/large", addr))
		if err != nil {
			t.Fatalf("HTTP/1.1 request failed: %v", err)
		}
		bodyH1, _ := io.ReadAll(respH1.Body)
		_ = respH1.Body.Close()
		if len(bodyH1) != len(largeResponseBody) {
			t.Errorf("HTTP/1.1 body size mismatch: got %d, want %d", len(bodyH1), len(largeResponseBody))
		}

		// 2. HTTP/2 request succeeds cleanly with ALPN "h2"
		h2Client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    certPool,
					NextProtos: []string{"h2", "http/1.1"},
				},
				ForceAttemptHTTP2: true,
			},
			Timeout: 2 * time.Second,
		}

		respH2, err := h2Client.Get(fmt.Sprintf("https://%s/large", addr))
		if err != nil {
			t.Fatalf("HTTP/2 request failed: %v", err)
		}
		bodyH2, _ := io.ReadAll(respH2.Body)
		_ = respH2.Body.Close()

		if respH2.Proto != "HTTP/2.0" {
			t.Errorf("expected HTTP/2.0 protocol negotiation, got: %s", respH2.Proto)
		}
		if len(bodyH2) != len(largeResponseBody) {
			t.Errorf("HTTP/2 body size mismatch: got %d, want %d", len(bodyH2), len(largeResponseBody))
		}
		if dropCount != 0 {
			t.Errorf("expected 0 packet drops with clamped MSS, got %d", dropCount)
		}
	})
}
