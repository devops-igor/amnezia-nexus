package naive

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDialer_IPv6_EndpointParsing(t *testing.T) {
	validCases := []struct {
		name     string
		endpoint string
		wantHost string
		wantPort int
	}{
		{
			name:     "bracketed ipv6 standard port",
			endpoint: "[2001:db8::10]:443",
			wantHost: "2001:db8::10",
			wantPort: 443,
		},
		{
			name:     "bracketed ipv6 custom port",
			endpoint: "[2001:db8::10]:8443",
			wantHost: "2001:db8::10",
			wantPort: 8443,
		},
		{
			name:     "bracketed ipv6 loopback",
			endpoint: "[::1]:443",
			wantHost: "::1",
			wantPort: 443,
		},
		{
			name:     "bracketed ipv6 with spaces",
			endpoint: "  [2001:db8::10]:443  ",
			wantHost: "2001:db8::10",
			wantPort: 443,
		},
		{
			name:     "hostname with aaaa",
			endpoint: "ipv6-backend.example.com:443",
			wantHost: "ipv6-backend.example.com",
			wantPort: 443,
		},
	}

	p := models.NaiveProxyParams{
		Username: "user",
		Password: "pass",
		Domain:   testCamouflageDomain,
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := New(tc.endpoint, p)
			if err != nil {
				t.Fatalf("New(%q) unexpected error: %v", tc.endpoint, err)
			}
			defer d.Close()

			host, portStr, err := net.SplitHostPort(d.endpoint)
			if err != nil {
				t.Fatalf("SplitHostPort(%q) failed: %v", d.endpoint, err)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
			if portStr != strings.TrimSpace(portStr) {
				t.Errorf("portStr has unexpected spaces: %q", portStr)
			}
			// Verify TLS ServerName strictly matches camouflage domain, never the transport IP
			if d.tlsCfg.ServerName != testCamouflageDomain {
				t.Errorf("ServerName = %q, want %q", d.tlsCfg.ServerName, testCamouflageDomain)
			}
			if d.tlsCfg.InsecureSkipVerify {
				t.Error("InsecureSkipVerify must be false")
			}
		})
	}

	invalidCases := []struct {
		name     string
		endpoint string
	}{
		{
			name:     "unbracketed ipv6 with port",
			endpoint: "2001:db8::10:443",
		},
		{
			name:     "bracketed ipv6 missing port",
			endpoint: "[2001:db8::10]",
		},
		{
			name:     "unbracketed ipv6 missing port",
			endpoint: "2001:db8::10",
		},
		{
			name:     "bracketed ipv6 port out of range",
			endpoint: "[2001:db8::10]:70000",
		},
		{
			name:     "empty endpoint",
			endpoint: "",
		},
		{
			name:     "missing host",
			endpoint: ":443",
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.endpoint, p)
			if err == nil {
				t.Fatalf("New(%q) expected error, got nil", tc.endpoint)
			}
		})
	}
}

func TestDialer_IPv6_H2_DialIPv4CONNECT(t *testing.T) {
	// 1. IPv4 TCP echo target (simulating client payload destination)
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// 2. IPv6 Naive H2 backend listening on [::1]:port
	proxyAddr, cleanupH2 := setupTestH2ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Dial IPv4 address through IPv6 NaiveProxy backend
	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext IPv6 -> IPv4 target failed: %v", err)
	}
	defer conn.Close()

	// Verify transport address family is IPv6
	remoteAddr := conn.RemoteAddr().String()
	if !strings.HasPrefix(remoteAddr, "[::1]:") {
		t.Errorf("expected remote transport address to be IPv6 [::1]:..., got %q", remoteAddr)
	}

	// Verify 64 KiB payload round-trip through the IPv6 tunnel to IPv4 target
	const payloadSize = 64 * 1024
	verifyEchoPayload(t, conn, payloadSize, "H2-IPv6")
}

func TestDialer_IPv6_H3_DialIPv4CONNECT(t *testing.T) {
	// 1. IPv4 TCP echo target
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	// 2. IPv6 Naive H3 backend listening on [::1]:port (UDP)
	proxyAddr, cleanupH3 := setupTestH3ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH3()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: true,
	}

	d, err := New(proxyAddr, p)
	if err != nil {
		t.Fatalf("New dialer: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext H3 IPv6 -> IPv4 target failed: %v", err)
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	if !strings.HasPrefix(remoteAddr, "[::1]:") {
		t.Errorf("expected remote transport address to be IPv6 [::1]:..., got %q", remoteAddr)
	}

	const payloadSize = 64 * 1024
	verifyEchoPayload(t, conn, payloadSize, "H3-IPv6")
}

func TestDialer_IPv6_AAAA_HostnameResolution(t *testing.T) {
	echoAddr, cleanupEcho := setupTCPEchoServer(t)
	defer cleanupEcho()

	proxyAddr, cleanupH2 := setupTestH2ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH2()

	_, portStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	const aaaaDomain = "aaaa-backend.example.com"
	customResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// In-process mock resolver returning only IPv6 loopback
			return nil, &net.DNSError{Err: "not implemented"}
		},
	}
	_ = customResolver

	// Use testDialContext to emulate pure AAAA resolution to [::1]:port
	resolvedTarget := net.JoinHostPort("::1", portStr)
	SetTestDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if host == aaaaDomain {
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort("::1", port))
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, network, addr)
	})
	defer SetTestDialContext(nil)

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	d, err := New(net.JoinHostPort(aaaaDomain, portStr), p)
	if err != nil {
		t.Fatalf("New dialer with AAAA hostname: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext through AAAA hostname: %v", err)
	}
	defer conn.Close()

	if !strings.HasPrefix(conn.RemoteAddr().String(), "[::1]:") && conn.RemoteAddr().String() != resolvedTarget {
		t.Errorf("expected remote address IPv6 loopback, got %q", conn.RemoteAddr().String())
	}

	const payloadSize = 32 * 1024
	verifyEchoPayload(t, conn, payloadSize, "AAAA-H2")
}

func TestProbeNaiveProxy_IPv6_SuccessAndFailure(t *testing.T) {
	proxyAddr, cleanupH2 := setupTestH2ServerIPv6(t, "testuser", "testpass", true)
	defer cleanupH2()

	p := models.NaiveProxyParams{
		Username: "testuser",
		Password: "testpass",
		Domain:   testCamouflageDomain,
		EnableH3: false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Success probe against IPv6 backend
	latencyMS, err := ProbeNaiveProxy(ctx, proxyAddr, p, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxy against IPv6 backend failed: %v", err)
	}
	if latencyMS <= 0 {
		t.Errorf("expected positive latencyMS, got %d", latencyMS)
	}

	// 2. ProbeNaiveProxyTunnel wrapper
	rawParams, _ := json.Marshal(p)
	tun := &models.BackendTunnel{
		ID:             99,
		Endpoint:       proxyAddr,
		Protocol:       models.ProtocolNaive,
		ProtocolParams: rawParams,
	}
	latencyTunnel, err := ProbeNaiveProxyTunnel(ctx, tun, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeNaiveProxyTunnel failed: %v", err)
	}
	if latencyTunnel <= 0 {
		t.Errorf("expected positive latencyMS from tunnel probe, got %d", latencyTunnel)
	}

	// 3. Simulated failure: unreachable IPv6 blackhole
	blackholeIPv6 := "[2001:db8::1]:54321"
	_, err = ProbeNaiveProxy(ctx, blackholeIPv6, p, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected probe to fail on unreachable IPv6 address, got nil")
	}
}
