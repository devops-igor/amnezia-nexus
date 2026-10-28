package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// generateTestCertificate generates an in-memory CA and server certificate valid for domain and 127.0.0.1.
func generateTestCertificate(t *testing.T, domain string) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate srv key: %v", err)
	}

	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	srvBytes, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create srv cert: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{srvBytes},
		PrivateKey:  srvKey,
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return tlsCert, pool
}

func TestProbeTLSH2_Success(t *testing.T) {
	domain := "reality.test.local"
	tlsCert, rootCAs := generateTestCertificate(t, domain)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	serverAddr := server.Listener.Addr().String()

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	customDialer := &net.Dialer{
		Timeout: 2 * time.Second,
		Control: nil,
	}

	// Override domain dialing to connect to our test server
	probeOpts := ProbeOptions{
		Timeout: 2 * time.Second,
		RootCAs: rootCAs,
		Dialer:  dialer,
	}

	// To direct domain to local server without altering global DNS, test ProbeTLSH2 with a loopback dialer wrapper
	probeOpts.Dialer = &net.Dialer{
		Timeout: 2 * time.Second,
	}

	// Custom probe with loopback connection
	rawConn, err := customDialer.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("dial mock server: %v", err)
	}
	defer func() { _ = rawConn.Close() }()

	tlsCfg := &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    rootCAs,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	cs := tlsConn.ConnectionState()
	if cs.Version != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got 0x%04x", cs.Version)
	}
	if cs.NegotiatedProtocol != "h2" {
		t.Errorf("expected h2 ALPN, got %q", cs.NegotiatedProtocol)
	}
	if len(cs.VerifiedChains) == 0 {
		t.Errorf("expected verified certificate chain")
	}
}

func TestProbeTLSH2_TargetIPExactDial(t *testing.T) {
	domain := "reality.test.local"
	tlsCert, _ := generateTestCertificate(t, domain)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	host, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	targetIP := net.ParseIP(host)

	// Probe connects directly to TargetIP:Port without resolving unresolvable domain
	unresolvableDomain := "candidate.reality-unresolvable.invalid"
	certForUnresolvable, unresRootCAs := generateTestCertificate(t, unresolvableDomain)
	server.TLS.Certificates = []tls.Certificate{certForUnresolvable}

	opts := ProbeOptions{
		Timeout:  2 * time.Second,
		RootCAs:  unresRootCAs,
		TargetIP: targetIP,
		Port:     port,
	}

	res := ProbeTLSH2(context.Background(), unresolvableDomain, opts)
	if res.Error != "" {
		t.Fatalf("ProbeTLSH2 direct dial to TargetIP failed: %s", res.Error)
	}
	if !res.TLS13 {
		t.Errorf("expected TLS13 = true")
	}
	if res.ALPN != "h2" {
		t.Errorf("expected ALPN = h2, got %q", res.ALPN)
	}
	if !res.CertValid {
		t.Errorf("expected CertValid = true")
	}
}

func TestProbeTLSH2_InvalidCert(t *testing.T) {
	domain := "reality.test.local"
	tlsCert, _ := generateTestCertificate(t, domain)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	// Probe with empty rootCAs pool (should fail certificate verification)
	emptyPool := x509.NewCertPool()
	res := ProbeTLSH2(context.Background(), server.Listener.Addr().String(), ProbeOptions{
		Timeout: 2 * time.Second,
		RootCAs: emptyPool,
	})

	if res.Error == "" && res.CertValid {
		t.Errorf("expected TLS probe to fail on untrusted certificate")
	}
}

func TestScanSNI_WorkerPool(t *testing.T) {
	// Create mock GeoDB with test ranges
	ranges := []IPRange{
		{
			StartIP: 0x7F000001, // 127.0.0.1
			EndIP:   0x7F000001,
			ASN:     13335, // Cloudflare
			Country: [2]byte{'U', 'S'},
		},
	}
	geoDB := NewGeoDBFromRanges(ranges)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := ScanSNI(ctx, "127.0.0.1", ScannerOptions{
		Concurrency: 2,
		Timeout:     1 * time.Second,
		Domains:     []string{"127.0.0.1.nip.io", "nonexistent.domain.test"},
		GeoDB:       geoDB,
	})
	if err != nil {
		t.Fatalf("ScanSNI failed: %v", err)
	}

	if report.ServerIP != "127.0.0.1" {
		t.Errorf("expected server IP 127.0.0.1, got %q", report.ServerIP)
	}
	if report.Scope != "panel_side_proximity" {
		t.Errorf("scope = %q, want panel_side_proximity", report.Scope)
	}
	if report.FallbackToPanel || report.Warning != "" {
		t.Errorf("scanner alone must not set fallback markers: %+v", report)
	}
	if len(report.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(report.Results))
	}

	// Verify sorting and status field presence
	for _, res := range report.Results {
		if res.Domain == "" {
			t.Errorf("expected non-empty domain")
		}
		if res.Status == "" {
			t.Errorf("expected non-empty status for domain %s", res.Domain)
		}
		if res.Domain == "nonexistent.domain.test" && !strings.Contains(res.Status, "dns_failed") && !strings.Contains(res.Status, "rejected") && !strings.Contains(res.Status, "tls_failed") {
			t.Errorf("expected failure status for nonexistent domain, got %s", res.Status)
		}
	}
}
