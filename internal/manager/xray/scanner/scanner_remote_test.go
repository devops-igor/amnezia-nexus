package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func startScannerTLSServer(t *testing.T, domain string) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	certificate, rootCAs := generateTestCertificate(t, domain)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, rootCAs
}

func TestProbeTLSH2UsesDialContext(t *testing.T) {
	const domain = "remote-probe.test"
	server, rootCAs := startScannerTLSServer(t, domain)
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	dialedAddr := make(chan string, 1)
	result := ProbeTLSH2(context.Background(), domain, ProbeOptions{
		Timeout:  2 * time.Second,
		RootCAs:  rootCAs,
		TargetIP: net.ParseIP(host),
		Port:     port,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialedAddr <- addr
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	if result.Error != "" {
		t.Fatalf("ProbeTLSH2: %s", result.Error)
	}
	select {
	case addr := <-dialedAddr:
		if addr != server.Listener.Addr().String() {
			t.Fatalf("dialed address = %q, want %q", addr, server.Listener.Addr())
		}
	default:
		t.Fatal("custom DialContext was not used")
	}
}

func TestScanSNIRemoteDialContextScope(t *testing.T) {
	server, rootCAs := startScannerTLSServer(t, "127.0.0.1")
	geoDB := NewGeoDBFromRanges([]IPRange{{
		StartIP: 0x7F000001,
		EndIP:   0x7F000001,
		ASN:     13335,
		Country: [2]byte{'U', 'S'},
	}})
	dialedAddr := make(chan string, 1)
	report, err := ScanSNI(context.Background(), "127.0.0.1", ScannerOptions{
		Concurrency: 1,
		Timeout:     2 * time.Second,
		Domains:     []string{"127.0.0.1"},
		GeoDB:       geoDB,
		RootCAs:     rootCAs,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialedAddr <- addr
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatalf("ScanSNI: %v", err)
	}
	if report.Scope != "remote_server_rtt" {
		t.Fatalf("scope = %q, want remote_server_rtt", report.Scope)
	}
	if len(report.Results) != 1 || report.Results[0].Status != "ok" {
		t.Fatalf("results = %+v, want one successful probe", report.Results)
	}
	select {
	case addr := <-dialedAddr:
		if addr != "127.0.0.1:443" {
			t.Fatalf("candidate dial address = %q, want 127.0.0.1:443", addr)
		}
	default:
		t.Fatal("remote DialContext was not used")
	}
}
