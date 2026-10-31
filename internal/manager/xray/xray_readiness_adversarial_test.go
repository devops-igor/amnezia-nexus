//go:build with_utls

package xray

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/google/uuid"
	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"

	"github.com/devops-igor/amnezia-nexus/internal/manager/awg"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	realvless "github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
)

var (
	testCertOnce  sync.Once
	testCACertPEM []byte
	testLeafCert  tls.Certificate
)

func initTestCAs(t *testing.T) {
	t.Helper()
	var initErr error
	testCertOnce.Do(func() {
		caCert, caKey, caPEM, err := generateTestCA()
		if err != nil {
			initErr = fmt.Errorf("generateTestCA: %w", err)
			return
		}
		testCACertPEM = caPEM

		leafCert, err := generateLeafCert(caCert, caKey, "example.com")
		if err != nil {
			initErr = fmt.Errorf("generateLeafCert: %w", err)
			return
		}
		testLeafCert = leafCert

		tmpDir, err := os.MkdirTemp("", "vless-test-*")
		if err == nil {
			bundlePath := filepath.Join(tmpDir, "ca-bundle.crt")
			var bundleData []byte
			if sysCerts, errRead := os.ReadFile("/etc/ssl/certs/ca-certificates.crt"); errRead == nil {
				bundleData = append(bundleData, sysCerts...)
			}
			bundleData = append(bundleData, testCACertPEM...)
			if errWrite := os.WriteFile(bundlePath, bundleData, 0o644); errWrite == nil {
				_ = os.Setenv("SSL_CERT_FILE", bundlePath)
			}
		}
	})
	if initErr != nil {
		t.Fatalf("initTestCAs failed: %v", initErr)
	}
}

func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"VLESS Test CA"},
			CommonName:   "VLESS Decoy Test CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return parsed, priv, pemBytes, nil
}

func generateLeafCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  priv,
	}, nil
}

type fixtureHandler struct {
	dialer net.Dialer
}

func (h *fixtureHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	target, err := h.dialer.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		return
	}
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, conn)
		_ = target.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		_ = conn.Close()
	}()
	wg.Wait()
}

func (h *fixtureHandler) NewPacketConnectionEx(ctx context.Context, conn network.PacketConn, source metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}

	udpTarget, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	defer udpTarget.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			buffer := buf.New()
			dest, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			targetAddr := dest.String()
			if targetAddr == "" {
				targetAddr = destination.String()
			}
			udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				buffer.Release()
				continue
			}
			_, _ = udpTarget.WriteTo(buffer.Bytes(), udpAddr)
			buffer.Release()
		}
	}()

	go func() {
		defer wg.Done()
		rawBuf := make([]byte, 65536)
		for {
			n, raddr, err := udpTarget.ReadFrom(rawBuf)
			if err != nil {
				return
			}
			buffer := buf.New()
			buffer.Resize(network.DefaultHeadroom, 0)
			_, _ = buffer.Write(rawBuf[:n])
			fromAddr := metadata.SocksaddrFromNet(raddr)
			if err = conn.WritePacket(buffer, fromAddr); err != nil {
				buffer.Release()
				return
			}
		}
	}()

	<-ctx.Done()
	_ = udpTarget.Close()
	wg.Wait()
}

func startDecoyServer(t *testing.T, delay time.Duration) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for decoy: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{testLeafCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsLn := tls.NewListener(ln, tlsConfig)

	closeChan := make(chan struct{})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if delay > 0 {
					time.Sleep(delay)
				}
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return
					}
					if tc.ConnectionState().NegotiatedProtocol == "h2" {
						//nolint:staticcheck // SA1019: http2.Server test fixture helper
						h2s := &http2.Server{}
						//nolint:staticcheck // SA1019: http2.Server test fixture helper
						h2s.ServeConn(tc, &http2.ServeConnOpts{
							Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("Hello Decoy!"))
							}),
						})
						return
					}
				}
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = c.Read(buf)
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHello Decoy!"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	cleanup := func() {
		close(closeChan)
		_ = tlsLn.Close()
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

type testFixture struct {
	Endpoint    string
	Params      models.VLESSRealityParams
	DecoyAddr   string
	ServerClose func()
}

func setupTestServer(t *testing.T, flow string, decoyDelay time.Duration, rejectDelay time.Duration) *testFixture {
	t.Helper()
	initTestCAs(t)

	decoyAddr, cleanupDecoy := startDecoyServer(t, decoyDelay)
	decoyHost, decoyPortStr, _ := net.SplitHostPort(decoyAddr)
	var decoyPort uint16
	_, _ = fmt.Sscanf(decoyPortStr, "%d", &decoyPort)

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519: %v", err)
	}
	pubKey := privKey.PublicKey()
	privB64 := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(pubKey.Bytes())
	shortID := "0123456789abcdef"
	serverName := "example.com"
	clientUUID := uuid.New().String()

	inboundTLSOpts := option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: privB64,
			ShortID:    badoption.Listable[string]{shortID},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     decoyHost,
					ServerPort: decoyPort,
				},
			},
		},
	}

	serverCfg, err := sTLS.NewRealityServer(context.Background(), nil, inboundTLSOpts)
	if err != nil {
		t.Fatalf("NewRealityServer: %v", err)
	}

	handler := &fixtureHandler{dialer: net.Dialer{Timeout: 5 * time.Second}}
	vlessService := vless.NewService[int](logger.NOP(), handler)
	vlessService.UpdateUsers([]int{1}, []string{clientUUID}, []string{flow})

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen reality server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tlsConn, err := sTLS.ServerHandshake(ctx, c, serverCfg)
				if err != nil {
					_ = c.Close()
					return
				}
				serviceErr := vlessService.NewConnection(ctx, tlsConn, metadata.SocksaddrFromNet(tlsConn.RemoteAddr()), nil)
				if serviceErr != nil && rejectDelay > 0 && (strings.Contains(serviceErr.Error(), "unknown UUID") || strings.Contains(serviceErr.Error(), "flow mismatch")) {
					t.Logf("server confirmed VLESS rejection before any response; delaying close delivery: %v", serviceErr)
					select {
					case <-ctx.Done():
					case <-time.After(rejectDelay):
					}
				}
				_ = tlsConn.Close()
			}(conn)
		}
	}()

	params := models.VLESSRealityParams{
		UUID:        clientUUID,
		Flow:        flow,
		PublicKey:   pubB64,
		ShortID:     shortID,
		ServerName:  serverName,
		Fingerprint: "chrome",
	}

	return &testFixture{
		Endpoint:  serverLn.Addr().String(),
		Params:    params,
		DecoyAddr: decoyAddr,
		ServerClose: func() {
			cancel()
			_ = serverLn.Close()
			cleanupDecoy()
			wg.Wait()
		},
	}
}

func auditR14Launch(t *testing.T, traffic VLESSProbeFunc, handshake VLESSProbeFunc) (error, *mockXraySSHClient, *models.Server) {
	t.Helper()
	remote := newMockXraySSHClient()
	mgr := NewXrayManagerWithServerLocks(&mockXrayPool{client: remote}, awg.NewServerLockRegistry())
	key, _, err := GenerateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clients := []XrayClient{{ID: "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e", Flow: "", Email: "audit@example.com"}}
	cfg, err := RenderXrayConfig(8443, 54321, "example.com", "example.com:443", key, []string{"0123456789abcdef"}, clients)
	if err != nil {
		t.Fatal(err)
	}
	remote.files[XrayConfigPath] = append([]byte(nil), cfg...)
	// Configure handshake first: the setter clears traffic.
	mgr.SetVLESSProbeFunc(handshake)
	mgr.SetVLESSTrafficProbeFunc(traffic)
	server := &models.Server{ID: 946, Host: "192.0.2.146", Protocols: map[string]any{models.ProtocolVLESS: map[string]any{"installed": true, "port": 8443, "engine_profile": "legacy"}}}
	err = mgr.Install(context.Background(), server, map[string]any{"engine_profile": "modern_pq", "port": 8443})
	return err, remote, server
}

func TestIsExternalDestinationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"reality verification failed", fmt.Errorf("vless: dial traffic target example.com:443: vless: reality verification failed"), false},
		{"dial connect refused", fmt.Errorf("vless: dial: connect: connection refused"), false},
		{"dial target timeout", fmt.Errorf("vless: dial traffic target example.com:443: i/o timeout"), false},
		{"tls target deadline exceeded", fmt.Errorf("vless: tls handshake to target example.com:443: context deadline exceeded"), false},
		{"tls target io timeout", fmt.Errorf("vless: tls handshake to target example.com:443: i/o timeout"), false},
		{"tls target eof", fmt.Errorf("vless: tls handshake to target example.com:443: EOF"), false},
		{"tls target reset", fmt.Errorf("vless: tls handshake to target example.com:443: connection reset by peer"), false},
		{"tls target broken pipe", fmt.Errorf("vless: tls handshake to target example.com:443: broken pipe"), false},
		{"unauthorized client", fmt.Errorf("vless: unauthorized client"), false},
		{"read probe response timeout", fmt.Errorf("vless: read probe response: i/o timeout"), false},
		{"empty response from target", fmt.Errorf("vless: empty response from target through tunnel"), false},
		{"write probe request broken pipe", fmt.Errorf("vless: write probe request: broken pipe"), false},
		{"remote tls alert handshake failure", fmt.Errorf("vless: tls handshake to target example.com:443: remote error: tls: handshake failure"), true},
		{"tls handshake failure alert", fmt.Errorf("vless: tls handshake to target external-target.com:443: tls: handshake failure"), true},
		{"remote tls alert unrecognized name", fmt.Errorf("vless: tls handshake to target example.com:443: remote error: tls: unrecognized name"), true},
		{"tls failed to verify certificate", fmt.Errorf("vless: tls handshake to target example.com:443: tls: failed to verify certificate: x509: certificate signed by unknown authority"), true},
		{"x509 cert expired", fmt.Errorf("vless: tls handshake to target example.com:443: x509: certificate has expired or is not yet valid"), true},
		{"invalid http response empty", fmt.Errorf("vless: invalid http response status line: \"\""), true},
		{"invalid http response ssh banner", fmt.Errorf("vless: invalid http response status line: \"SSH-2.0-OpenSSH_8.9p1\""), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExternalDestinationError(tt.err)
			if got != tt.expected {
				t.Errorf("isExternalDestinationError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestAuditR14ActualFallbackBranches(t *testing.T) {
	for _, tc := range []struct {
		name, msg      string
		handshakeFails bool
		wantFail       bool
	}{
		{"external TLS alert", "vless: tls handshake to target example.com:443: remote error: tls: handshake failure", false, false},
		{"destination cert untrusted", "vless: tls handshake to target example.com:443: tls: failed to verify certificate: x509: certificate signed by unknown authority", false, false},
		{"destination invalid http", "vless: invalid http response status line: \"502 Bad Gateway\"", false, false},
		{"generic timeout deadline", "vless: tls handshake to target example.com:443: context deadline exceeded", false, true},
		{"generic timeout io", "vless: tls handshake to target example.com:443: i/o timeout", false, true},
		{"dial target timeout", "vless: dial traffic target example.com:443: i/o timeout", false, true},
		{"internal REALITY rejection", "vless: dial traffic target example.com:443: vless: reality verification failed", false, true},
		{"endpoint refused", "vless: dial traffic target example.com:443: vless: dial: connect: connection refused", false, true},
		{"failed fallback", "vless: tls handshake to target example.com:443: remote error: tls: handshake failure", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trafficCalls, handshakeCalls := 0, 0
			err, _, _ := auditR14Launch(t, func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
				trafficCalls++
				if _, ok := ctx.Deadline(); !ok || d != 5*time.Second {
					t.Error("missing 5s traffic bound")
				}
				return 0, fmt.Errorf("%s", tc.msg)
			}, func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
				handshakeCalls++
				if _, ok := ctx.Deadline(); !ok || d != 5*time.Second {
					t.Error("missing 5s fallback bound")
				}
				if tc.handshakeFails {
					return 0, fmt.Errorf("reality verification failed")
				}
				return 1, nil
			})
			if trafficCalls != 1 {
				t.Fatalf("traffic calls=%d", trafficCalls)
			}
			if (err != nil) != tc.wantFail {
				t.Fatalf("error=%v wantFail=%v", err, tc.wantFail)
			}
			expectedFallback := 0
			if isExternalDestinationError(fmt.Errorf("%s", tc.msg)) {
				expectedFallback = 1
			}
			if handshakeCalls != expectedFallback {
				t.Fatalf("fallback calls=%d want=%d", handshakeCalls, expectedFallback)
			}
			if tc.wantFail && !strings.Contains(err.Error(), "rolled back to previous container") {
				t.Fatalf("missing rollback: %v", err)
			}
		})
	}
}

func TestAuditR14RejectedVLESSUUIDMustNotCommitUpgrade(t *testing.T) {
	fixture := setupTestServer(t, "", 0, 0)
	defer fixture.ServerClose()
	// The REALITY identity is valid but this VLESS account is not accepted.
	bad := fixture.Params
	bad.UUID = "00000000-0000-0000-0000-000000000000"
	trafficCalls, handshakeCalls := 0, 0
	traffic := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		trafficCalls++
		// A rejected UUID cannot reach this destination, so no external I/O occurs.
		n, e := realvless.ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, bad, "example.com:443", d)
		t.Logf("actual rejected UUID traffic result: %v; external classification=%v", e, isExternalDestinationError(e))
		if e == nil {
			t.Fatal("invalid UUID unexpectedly authenticated")
		}
		return n, e
	}
	handshake := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		handshakeCalls++
		return realvless.ProbeVLESSReality(ctx, fixture.Endpoint, bad, d)
	}
	err, remote, server := auditR14Launch(t, traffic, handshake)
	meta := server.Protocols[models.ProtocolVLESS].(map[string]any)
	t.Logf("Install error=%v; traffic calls=%d; fallback calls=%d; published profile=%v; backup retained=%v; replacement alive=%v", err, trafficCalls, handshakeCalls, meta["engine_profile"], remote.backupContainerAlive, remote.dockerAlive)
	if err == nil {
		t.Fatal("upgrade committed despite real VLESS authentication failure; expected rollback, not REALITY-only acceptance")
	}
	if handshakeCalls != 0 {
		t.Fatalf("expected 0 fallback handshake calls, got %d", handshakeCalls)
	}
}

func TestAuditR14RejectedVLESSFlowMustNotCommitUpgrade(t *testing.T) {
	fixture := setupTestServer(t, "xtls-rprx-vision", 0, 0)
	defer fixture.ServerClose()
	// The REALITY identity is valid but this VLESS account is not accepted.
	bad := fixture.Params
	bad.Flow = ""
	trafficCalls, handshakeCalls := 0, 0
	traffic := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		trafficCalls++
		// A rejected flow cannot reach this destination, so no external I/O occurs.
		n, e := realvless.ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, bad, "example.com:443", d)
		t.Logf("actual rejected flow traffic result: %v; external classification=%v", e, isExternalDestinationError(e))
		if e == nil {
			t.Fatal("mismatched flow unexpectedly authenticated")
		}
		return n, e
	}
	handshake := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		handshakeCalls++
		return realvless.ProbeVLESSReality(ctx, fixture.Endpoint, bad, d)
	}
	err, remote, server := auditR14Launch(t, traffic, handshake)
	meta := server.Protocols[models.ProtocolVLESS].(map[string]any)
	t.Logf("Install error=%v; traffic calls=%d; fallback calls=%d; published profile=%v; backup retained=%v; replacement alive=%v", err, trafficCalls, handshakeCalls, meta["engine_profile"], remote.backupContainerAlive, remote.dockerAlive)
	if err == nil {
		t.Fatal("upgrade committed despite real VLESS authentication failure; expected rollback, not REALITY-only acceptance")
	}
	if handshakeCalls != 0 {
		t.Fatalf("expected 0 fallback handshake calls, got %d", handshakeCalls)
	}
}

func TestAuditR15DelayedRejectedVLESSUUIDMustNotCommitUpgrade(t *testing.T) {
	fixture := setupTestServer(t, "", 0, 6*time.Second)
	defer fixture.ServerClose()
	bad := fixture.Params
	bad.UUID = "00000000-0000-0000-0000-000000000000"
	trafficCalls, handshakeCalls := 0, 0
	traffic := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		trafficCalls++
		n, e := realvless.ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, bad, "example.com:443", d)
		t.Logf("actual delayed rejected UUID traffic result: %v; external classification=%v", e, isExternalDestinationError(e))
		if e == nil {
			t.Fatal("invalid UUID unexpectedly authenticated")
		}
		if isExternalDestinationError(e) {
			t.Fatalf("delayed rejected UUID must not be classified as external destination error: %v", e)
		}
		return n, e
	}
	handshake := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		handshakeCalls++
		return realvless.ProbeVLESSReality(ctx, fixture.Endpoint, bad, d)
	}
	err, remote, server := auditR14Launch(t, traffic, handshake)
	meta := server.Protocols[models.ProtocolVLESS].(map[string]any)
	t.Logf("Install error=%v; traffic calls=%d; fallback calls=%d; published profile=%v; backup retained=%v; replacement alive=%v", err, trafficCalls, handshakeCalls, meta["engine_profile"], remote.backupContainerAlive, remote.dockerAlive)
	if err == nil {
		t.Fatal("upgrade committed despite delayed VLESS rejection; expected rollback, not REALITY-only acceptance")
	}
	if handshakeCalls != 0 {
		t.Fatalf("expected 0 fallback handshake calls for delayed rejected UUID, got %d", handshakeCalls)
	}
	if meta["engine_profile"] != "legacy" {
		t.Fatalf("engine profile unexpectedly upgraded to %v", meta["engine_profile"])
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected rollback error message, got: %v", err)
	}
}

func TestAuditR15DelayedRejectedVLESSFlowMustNotCommitUpgrade(t *testing.T) {
	fixture := setupTestServer(t, "xtls-rprx-vision", 0, 6*time.Second)
	defer fixture.ServerClose()
	bad := fixture.Params
	bad.Flow = ""
	trafficCalls, handshakeCalls := 0, 0
	traffic := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		trafficCalls++
		n, e := realvless.ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, bad, "example.com:443", d)
		t.Logf("actual delayed rejected flow traffic result: %v; external classification=%v", e, isExternalDestinationError(e))
		if e == nil {
			t.Fatal("mismatched flow unexpectedly authenticated")
		}
		if isExternalDestinationError(e) {
			t.Fatalf("delayed rejected flow must not be classified as external destination error: %v", e)
		}
		return n, e
	}
	handshake := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
		handshakeCalls++
		return realvless.ProbeVLESSReality(ctx, fixture.Endpoint, bad, d)
	}
	err, remote, server := auditR14Launch(t, traffic, handshake)
	meta := server.Protocols[models.ProtocolVLESS].(map[string]any)
	t.Logf("Install error=%v; traffic calls=%d; fallback calls=%d; published profile=%v; backup retained=%v; replacement alive=%v", err, trafficCalls, handshakeCalls, meta["engine_profile"], remote.backupContainerAlive, remote.dockerAlive)
	if err == nil {
		t.Fatal("upgrade committed despite delayed VLESS rejection; expected rollback, not REALITY-only acceptance")
	}
	if handshakeCalls != 0 {
		t.Fatalf("expected 0 fallback handshake calls for delayed rejected flow, got %d", handshakeCalls)
	}
	if meta["engine_profile"] != "legacy" {
		t.Fatalf("engine profile unexpectedly upgraded to %v", meta["engine_profile"])
	}
	if !strings.Contains(err.Error(), "rolled back to previous container") {
		t.Fatalf("expected rollback error message, got: %v", err)
	}
}

func TestAuditR16ApplicationTrafficFailureTriggersRollback(t *testing.T) {
	fixture := setupTestServer(t, "", 0, 0)
	defer fixture.ServerClose()

	tests := []struct {
		name      string
		alpnProto string
	}{
		{
			name:      "h2 TLS succeeds but application stream stalls",
			alpnProto: "h2",
		},
		{
			name:      "http1.1 TLS succeeds but application stream stalls",
			alpnProto: "http/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{testLeafCert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{tt.alpnProto},
			}
			tlsLn := tls.NewListener(ln, tlsConfig)
			defer tlsLn.Close()

			go func() {
				for {
					conn, err := tlsLn.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if tc, ok := c.(*tls.Conn); ok {
							_ = tc.Handshake()
						}
						// Intentionally stall application data stream
						time.Sleep(5 * time.Second)
					}(conn)
				}
			}()

			trafficCalls, handshakeCalls := 0, 0
			targetAddr := ln.Addr().String()
			traffic := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
				trafficCalls++
				n, e := realvless.ProbeVLESSTrafficWithTarget(ctx, fixture.Endpoint, fixture.Params, targetAddr, 300*time.Millisecond)
				t.Logf("actual stalled application traffic result: %v; external classification=%v", e, isExternalDestinationError(e))
				if e == nil {
					t.Fatal("stalled application traffic unexpectedly succeeded")
				}
				if isExternalDestinationError(e) {
					t.Fatalf("stalled application traffic must not be classified as external destination error: %v", e)
				}
				return n, e
			}
			handshake := func(ctx context.Context, _ string, _ models.VLESSRealityParams, d time.Duration) (int64, error) {
				handshakeCalls++
				return realvless.ProbeVLESSReality(ctx, fixture.Endpoint, fixture.Params, d)
			}

			err, remote, server := auditR14Launch(t, traffic, handshake)
			meta := server.Protocols[models.ProtocolVLESS].(map[string]any)
			t.Logf("Install error=%v; traffic calls=%d; fallback calls=%d; published profile=%v; backup retained=%v; replacement alive=%v",
				err, trafficCalls, handshakeCalls, meta["engine_profile"], remote.backupContainerAlive, remote.dockerAlive)

			if err == nil {
				t.Fatal("upgrade committed despite application traffic stall; expected rollback, not acceptance")
			}
			if handshakeCalls != 0 {
				t.Fatalf("expected 0 fallback handshake calls for application stall, got %d", handshakeCalls)
			}
			if meta["engine_profile"] != "legacy" {
				t.Fatalf("engine profile unexpectedly upgraded to %v", meta["engine_profile"])
			}
			if !strings.Contains(err.Error(), "rolled back to previous container") {
				t.Fatalf("expected rollback error message, got: %v", err)
			}
		})
	}
}
