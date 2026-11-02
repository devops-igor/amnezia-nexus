package naive

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

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

func TestProbeNaiveProxy_H3_TimeoutDuringResponse(t *testing.T) {
	cert, err := generateLeafCert(testCACert, testCAKey, testCamouflageDomain)
	if err != nil {
		t.Fatalf("generate leaf cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	server := &http3.Server{
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Intentionally delay responding to verify client timeout cancels ReadResponse
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
		}),
	}

	go func() {
		_ = server.Serve(udpConn)
	}()
	defer func() {
		_ = server.Close()
		_ = udpConn.Close()
	}()

	p := models.NaiveProxyParams{
		Username: "userA",
		Password: "passA",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	ctx := context.Background()
	start := time.Now()
	_, err = ProbeNaiveProxy(ctx, udpConn.LocalAddr().String(), p, 300*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	if elapsed > 1500*time.Millisecond {
		t.Fatalf("probe did not respect 300ms timeout on slow H3 response: took %v", elapsed)
	}
}

func auditProductionCAs(t *testing.T) {
	t.Helper()
	old := testRootCAs
	testRootCAs = nil
	t.Cleanup(func() { testRootCAs = old })
}

func TestAuditProbeDownloadFailureMustNotUseGoTransport(t *testing.T) {
	auditProductionCAs(t)
	t.Setenv(NaiveBinPathEnv, filepath.Join(t.TempDir(), "missing"))
	t.Setenv("NAIVE_DISABLE_DOWNLOAD", "1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			calls.Add(1)
			_ = c.Close()
		}
	}()
	p := models.NaiveProxyParams{Username: "audit-user", Password: "audit-password", Domain: "naive.example.com"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = ProbeNaiveProxy(ctx, ln.Addr().String(), p, time.Second)
	_ = ln.Close()
	<-done
	t.Logf("missing native binary: remote Go TCP attempts=%d err=%v", calls.Load(), err)
	if calls.Load() != 0 {
		t.Fatal("health probe leaked Go transport traffic after native failure")
	}
}

func TestAuditProbeMustRejectUnreachableUpstream(t *testing.T) {
	auditProductionCAs(t)
	t.Setenv(NaiveBinPathEnv, buildMockNaiveBinary(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := ln.Addr().String()
	_ = ln.Close() // deterministic refused remote endpoint
	p := models.NaiveProxyParams{Username: "audit-user", Password: "invalid-audit-credential", Domain: "naive.example.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ms, err := ProbeNaiveProxy(ctx, endpoint, p, time.Second)
	t.Logf("refused remote endpoint: latency=%d err=%v", ms, err)
	if err == nil {
		t.Fatal("health probe accepted local SOCKS success without any authenticated remote roundtrip")
	}
}

func TestAuditDownloadFailureMustNotUseGoTransport(t *testing.T) {
	auditProductionCAs(t)
	t.Setenv(NaiveBinPathEnv, filepath.Join(t.TempDir(), "missing-naive"))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()
	t.Setenv(NaiveDownloadBaseURLEnv, ts.URL)
	t.Setenv("NAIVE_DISABLE_DOWNLOAD", "0")
	var calls atomic.Int32
	sentinel := errors.New("audit: in-process Go transport reached")
	d, err := New("198.51.100.1:443", models.NaiveProxyParams{Username: "audit-user", Password: "audit-password", Domain: "naive.example.com"},
		WithDialContext(func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, sentinel
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = d.DialContext(ctx, "tcp", "target.example.com:443")
	t.Logf("download HTTP 503: Go transport calls=%d returned=%v", calls.Load(), err)
	if calls.Load() != 0 {
		t.Fatal("download failure silently downgraded to fingerprintable Go transport instead of failing closed")
	}
}

type mockStreamDialer struct {
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockStreamDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.dialContext(ctx, network, address)
}

func TestProbeNaiveProxy_CustomPortBackend(t *testing.T) {
	cert, err := generateLeafCert(testCACert, testCAKey, "camouflage.example.com")
	if err != nil {
		t.Fatalf("generate leaf cert: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	ts.StartTLS()
	defer ts.Close()

	customPort := ts.Listener.Addr().(*net.TCPAddr).Port
	if customPort == 443 {
		t.Fatal("expected ephemeral test port != 443")
	}

	var dialedTarget string
	sd := &mockStreamDialer{
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialedTarget = address
			var d net.Dialer
			return d.DialContext(ctx, network, ts.Listener.Addr().String())
		},
	}

	p := models.NaiveProxyParams{
		Username: "alice",
		Password: "secret-password",
		Domain:   "camouflage.example.com",
		Port:     customPort,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	latency, err := ProbeNaiveProxyWithOptions(ctx, "198.51.100.1:"+strconv.Itoa(customPort), p, 3*time.Second, WithSocks5Dialer(sd))
	if err != nil {
		t.Fatalf("ProbeNaiveProxy custom port failed: %v", err)
	}
	if latency < 1 {
		t.Errorf("expected latency >= 1ms, got %d", latency)
	}

	expectedTarget := net.JoinHostPort("camouflage.example.com", strconv.Itoa(customPort))
	if dialedTarget != expectedTarget {
		t.Fatalf("expected probe to dial %q, got %q", expectedTarget, dialedTarget)
	}

	// Verify that dialing with hardcoded 443 against a mock that rejects 443 fails
	sdReject443 := &mockStreamDialer{
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if strings.HasSuffix(address, ":443") {
				return nil, errors.New("connection refused: not listening on port 443")
			}
			var d net.Dialer
			return d.DialContext(ctx, network, ts.Listener.Addr().String())
		},
	}
	// With custom port: should succeed
	latency, err = ProbeNaiveProxyWithOptions(ctx, "198.51.100.1:"+strconv.Itoa(customPort), p, 3*time.Second, WithSocks5Dialer(sdReject443))
	if err != nil || latency < 1 {
		t.Fatalf("expected custom port probe to succeed on non-443 server: %v (latency=%d)", err, latency)
	}

	// Without custom port (defaults to 443): should fail against sdReject443
	pDefaultPort := p
	pDefaultPort.Port = 0
	_, err = ProbeNaiveProxyWithOptions(ctx, "198.51.100.1:"+strconv.Itoa(customPort), pDefaultPort, 3*time.Second, WithSocks5Dialer(sdReject443))
	if err == nil {
		t.Fatal("expected probe without custom port to fail against server not listening on 443")
	}

	// Verify ProbeNaiveProxyTunnel with custom port
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	tun := &models.BackendTunnel{
		ID:             42,
		Endpoint:       "198.51.100.1:" + strconv.Itoa(customPort),
		Protocol:       models.ProtocolNaive,
		ProtocolParams: raw,
	}
	tunLatency, err := ProbeNaiveProxyWithOptions(ctx, tun.Endpoint, p, 3*time.Second, WithSocks5Dialer(sd))
	if err != nil || tunLatency < 1 {
		t.Fatalf("ProbeNaiveProxy with unmarshaled params failed: %v", err)
	}
}
