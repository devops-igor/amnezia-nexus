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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func setupTestServer(t *testing.T, flow string, decoyDelay time.Duration) *testFixture {
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
				_ = vlessService.NewConnection(ctx, tlsConn, metadata.SocksaddrFromNet(tlsConn.RemoteAddr()), nil)
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

func TestAuditR14ActualFallbackBranches(t *testing.T) {
	for _, tc := range []struct {
		name, msg      string
		handshakeFails bool
		wantFail       bool
	}{
		{"external TLS alert", "vless: tls handshake to target example.com:443: remote error: tls: handshake failure", false, false},
		{"external timeout", "vless: tls handshake to target example.com:443: context deadline exceeded", false, false},
		{"internal REALITY rejection", "vless: dial traffic target example.com:443: vless: reality verification failed", false, true},
		{"endpoint refused", "vless: dial traffic target example.com:443: vless: dial: connect: connection refused", false, true},
		{"failed fallback", "vless: tls handshake to target example.com:443: EOF", true, true},
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
	fixture := setupTestServer(t, "", 0)
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
}

func TestAuditR14RejectedVLESSFlowMustNotCommitUpgrade(t *testing.T) {
	fixture := setupTestServer(t, "xtls-rprx-vision", 0)
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
}
