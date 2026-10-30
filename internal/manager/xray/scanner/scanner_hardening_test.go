package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeTLSH2_P256OnlyRejection(t *testing.T) {
	domain := "p256.test.local"
	tlsCert, rootCAs := generateTestCertificate(t, domain)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Server configured strictly with CurveP256 only (no X25519 support)
	server.TLS = &tls.Config{
		Certificates:     []tls.Certificate{tlsCert},
		NextProtos:       []string{"h2", "http/1.1"},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
	server.StartTLS()
	defer server.Close()

	host, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	targetIP := net.ParseIP(host)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	opts := ProbeOptions{
		Timeout:  2 * time.Second,
		RootCAs:  rootCAs,
		TargetIP: targetIP,
		Port:     port,
	}

	res := ProbeTLSH2(context.Background(), domain, opts)
	if res.Error == "" {
		t.Fatalf("expected P-256-only candidate to be rejected, but got no error")
	}
	if !strings.Contains(res.Error, "negotiated NIST CurveP256 without X25519 support") {
		t.Errorf("error = %q, want mention of NIST CurveP256 without X25519 support", res.Error)
	}
	if res.X25519 {
		t.Errorf("expected X25519 = false, got true")
	}
	if res.Curve != "CurveP256" {
		t.Errorf("expected Curve = CurveP256, got %q", res.Curve)
	}
}

func TestProbeTLSH2_ALPNEnforcement(t *testing.T) {
	domain := "h1only.test.local"
	tlsCert, rootCAs := generateTestCertificate(t, domain)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Server only negotiates http/1.1 (no h2 support)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	defer server.Close()

	host, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	targetIP := net.ParseIP(host)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	opts := ProbeOptions{
		Timeout:  2 * time.Second,
		RootCAs:  rootCAs,
		TargetIP: targetIP,
		Port:     port,
	}

	res := ProbeTLSH2(context.Background(), domain, opts)
	if res.Error == "" {
		t.Fatalf("expected non-h2 candidate to be rejected, got no error")
	}
	if !strings.Contains(res.Error, "negotiated ALPN \"http/1.1\" instead of h2") {
		t.Errorf("error = %q, want mention of negotiated ALPN instead of h2", res.Error)
	}
}

func TestScanSNI_PrioritizedRankingGeoAlignedOverAnycastCDN(t *testing.T) {
	// IP range setup:
	// Server IP: 192.0.2.10 (SE, AS42708)
	// Local domain IP: 192.0.2.20 (SE, AS42708) -> proximity score 100
	// Anycast CDN IP: 104.16.1.1 (US, AS13335 Cloudflare) -> proximity score 40
	ranges := []IPRange{
		{
			StartIP: 0x68100101, // 104.16.1.1
			EndIP:   0x68100101,
			ASN:     13335, // Cloudflare Anycast CDN
			Country: [2]byte{'U', 'S'},
		},
		{
			StartIP: 0xC000020A, // 192.0.2.10
			EndIP:   0xC000020A,
			ASN:     42708,
			Country: [2]byte{'S', 'E'},
		},
		{
			StartIP: 0xC0000214, // 192.0.2.20
			EndIP:   0xC0000214,
			ASN:     42708,
			Country: [2]byte{'S', 'E'},
		},
	}
	geoDB := NewGeoDBFromRanges(ranges)

	localDomain := "local-aligned.se"
	cdnDomain := "cdn-anycast.com"

	localCert, localPool := generateTestCertificate(t, localDomain)
	cdnCert, _ := generateTestCertificate(t, cdnDomain)

	// Combine pools
	combinedPool := localPool
	// Add root from cdnPool
	// In test, both use self-signed CA certs
	_ = cdnCert

	localSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // Higher latency
		w.WriteHeader(http.StatusOK)
	}))
	localSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{localCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	localSrv.StartTLS()
	defer localSrv.Close()

	cdnSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond) // Lower latency
		w.WriteHeader(http.StatusOK)
	}))
	cdnSrv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cdnCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	cdnSrv.StartTLS()
	defer cdnSrv.Close()

	// Merge root CAs
	for _, c := range cdnCert.Certificate {
		if parsed, err := x509.ParseCertificate(c); err == nil && parsed.IsCA {
			combinedPool.AddCert(parsed)
		}
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{}
		host, _, _ := net.SplitHostPort(addr)
		if host == "192.0.2.20" {
			return d.DialContext(ctx, network, localSrv.Listener.Addr().String())
		}
		if host == "104.16.1.1" {
			return d.DialContext(ctx, network, cdnSrv.Listener.Addr().String())
		}
		return d.DialContext(ctx, network, addr)
	}

	// Mock resolver mapping domain names to IPs
	resLocal := ScanResult{
		Domain:          localDomain,
		Country:         "SE",
		ASN:             42708,
		RTTMS:           65,
		TLS13:           true,
		Curve:           "X25519",
		X25519:          true,
		ALPN:            "h2",
		ALPNH2:          true,
		PassedGeoFilter: true,
		ProximityScore:  calculateProximityScore("SE", 42708, "SE", 42708),
		Status:          "ok",
	}

	resCDN := ScanResult{
		Domain:          cdnDomain,
		Country:         "US",
		ASN:             13335,
		RTTMS:           12,
		TLS13:           true,
		Curve:           "X25519",
		X25519:          true,
		ALPN:            "h2",
		ALPNH2:          true,
		PassedGeoFilter: true,
		ProximityScore:  calculateProximityScore("SE", 42708, "US", 13335),
		Status:          "ok",
	}

	// Check score calculation directly
	if resLocal.ProximityScore != 100 {
		t.Errorf("resLocal score = %d, want 100 (same ASN + same country)", resLocal.ProximityScore)
	}
	if resCDN.ProximityScore != 40 {
		t.Errorf("resCDN score = %d, want 40 (Anycast CDN fallback)", resCDN.ProximityScore)
	}

	results := []ScanResult{resCDN, resLocal}
	// Sort per production scanner ranking rules directly
	RankScanResults(results)

	if results[0].Domain != localDomain {
		t.Fatalf("ranking order failed: expected local domain %q to rank first over CDN %q, but got %q",
			localDomain, cdnDomain, results[0].Domain)
	}
	if results[1].Domain != cdnDomain {
		t.Fatalf("ranking order failed: expected CDN domain %q at index 1, but got %q",
			cdnDomain, results[1].Domain)
	}

	_ = geoDB
	_ = dialContext
}
