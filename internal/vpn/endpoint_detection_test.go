package vpn

// Issue #71: public-endpoint detection must never trust (or trust-and-cache)
// non-public IPs. The live incident: the UDP-dial fallback returned the
// container's local IP (172.19.0.3) inside Docker, which was cached for the
// process lifetime and handed to clients as the portal endpoint.

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

// fakeUDPConn satisfies net.Conn for the outboundDial seam; only
// LocalAddr and Close are exercised by detectOutboundInterfaceIP.
type fakeUDPConn struct {
	net.Conn
	addr *net.UDPAddr
}

func (c *fakeUDPConn) LocalAddr() net.Addr { return c.addr }
func (c *fakeUDPConn) Close() error        { return nil }

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"public v4", "203.0.113.7", true},
		{"public v6", "2001:db8::1", true},
		{"loopback", "127.0.0.1", false},
		{"unspecified", "0.0.0.0", false},
		{"private rfc1918 10/8", "10.1.2.3", false},
		{"private rfc1918 172.16/12", "172.19.0.3", false},
		{"private rfc1918 192.168/16", "192.168.1.50", false},
		{"cgnat low edge", "100.64.0.1", false},
		{"cgnat high edge", "100.127.255.254", false},
		{"above cgnat block", "100.128.0.1", true},
		{"link-local v4", "169.254.1.1", false},
		{"link-local v6", "fe80::1", false},
		{"ula v6", "fd00::1", false},
		{"multicast", "224.0.0.1", false},
		{"nil", "", false},
		{"garbage", "not-an-ip", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPublicIP(net.ParseIP(tc.ip)); got != tc.want {
				t.Errorf("isPublicIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestDetectOutboundInterfaceIP_RejectsNonPublic(t *testing.T) {
	origDial := outboundDial
	defer func() { outboundDial = origDial }()

	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &fakeUDPConn{addr: &net.UDPAddr{IP: net.IPv4(172, 19, 0, 3), Port: 51820}}, nil
	}
	if got := detectOutboundInterfaceIP(); got != "" {
		t.Fatalf("UDP-dial fallback yielded private IP %q; want detection failure (\"\")", got)
	}

	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("no route to host")
	}
	if got := detectOutboundInterfaceIP(); got != "" {
		t.Fatalf("dial failure must yield \"\", got %q", got)
	}

	// Control: a public address still passes through.
	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &fakeUDPConn{addr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51820}}, nil
	}
	if got := detectOutboundInterfaceIP(); got != "203.0.113.7" {
		t.Fatalf("public outbound IP must be returned verbatim, got %q", got)
	}
}

func TestDetectExternalPublicIP_RetriesUntilSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("203.0.113.7\n"))
	}))
	defer srv.Close()

	origEndpoints := ipServiceEndpoints
	defer func() { ipServiceEndpoints = origEndpoints }()
	ipServiceEndpoints = []string{srv.URL}

	if got := detectExternalPublicIP(context.Background()); got != "203.0.113.7" {
		t.Fatalf("retry path must return public IP on 2nd attempt, got %q", got)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("expected exactly 2 endpoint calls (1 fail + 1 success), got %d", n)
	}
}

func TestDetectExternalPublicIP_AllAttemptsFail(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	origEndpoints := ipServiceEndpoints
	defer func() { ipServiceEndpoints = origEndpoints }()
	ipServiceEndpoints = []string{srv.URL}

	if got := detectExternalPublicIP(context.Background()); got != "" {
		t.Fatalf("expected \"\" after all attempts fail, got %q", got)
	}
	if n := calls.Load(); n != ipServiceAttempts {
		t.Fatalf("expected %d attempts, got %d", ipServiceAttempts, n)
	}
}

func TestDetectPortalHostIP_NonPublicNotCached(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	var calls atomic.Int32
	origDetector := externalIPDetector
	origDial := outboundDial
	defer func() {
		externalIPDetector = origDetector
		outboundDial = origDial
	}()
	externalIPDetector = func(ctx context.Context) string {
		calls.Add(1)
		return "192.168.1.50" // private: must never be trusted
	}
	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("no route")
	}

	ctx := context.Background()
	for i := 1; i <= 2; i++ {
		got, src := svc.detectPortalHostIP(ctx)
		if got != "" {
			t.Fatalf("call %d: non-public detection must return \"\", got %q", i, got)
		}
		if src != endpointSourceFallback {
			t.Fatalf("call %d: private ip-service result must be rejected, not surface as %q", i, src)
		}
	}

	svc.publicIPMu.RLock()
	cached := svc.detectedPublicIP
	svc.publicIPMu.RUnlock()
	if cached != "" {
		t.Fatalf("non-public detection result must NOT be cached, cache holds %q", cached)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("second call must retry detection (cache stayed empty), detector called %d times", n)
	}
}

func TestDetectPortalHostIP_PublicResultCached(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	var calls atomic.Int32
	origDetector := externalIPDetector
	defer func() { externalIPDetector = origDetector }()
	externalIPDetector = func(ctx context.Context) string {
		calls.Add(1)
		return "203.0.113.7"
	}

	ctx := context.Background()
	if got, _ := svc.detectPortalHostIP(ctx); got != "203.0.113.7" {
		t.Fatalf("first call: want detected public IP, got %q", got)
	}
	if got, _ := svc.detectPortalHostIP(ctx); got != "203.0.113.7" {
		t.Fatalf("second call: want cached public IP, got %q", got)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("public result must be cached (no extra network calls), detector called %d times", n)
	}
	svc.publicIPMu.RLock()
	cached := svc.detectedPublicIP
	svc.publicIPMu.RUnlock()
	if cached != "203.0.113.7" {
		t.Fatalf("expected validated public IP cached, got %q", cached)
	}
}

func TestResolveClientEndpointInternal_ConfigWinsOverDetection(t *testing.T) {
	var calls atomic.Int32
	origDetector := externalIPDetector
	defer func() { externalIPDetector = origDetector }()
	externalIPDetector = func(ctx context.Context) string {
		calls.Add(1)
		return "203.0.113.9"
	}

	cfg := &models.VPNConfig{PublicEndpoint: "vpn.example.com:51820"}
	got := resolveClientEndpointInternal(context.Background(), nil, cfg, 51820)
	if got != "vpn.example.com:51820" {
		t.Fatalf("configured endpoint must win unchanged, got %q", got)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("detection must not run when cfg.PublicEndpoint is set, ran %d times", n)
	}
}

func TestResolveClientEndpoint_LoggingSourceOncePerChange(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")
	t.Setenv("VPN_DEBUG", "")

	origDetector := externalIPDetector
	defer func() { externalIPDetector = origDetector }()
	externalIPDetector = func(ctx context.Context) string {
		return "198.51.100.7"
	}

	var buf strings.Builder
	origW := logWriter()
	log.SetOutput(&buf)
	defer log.SetOutput(origW)

	ctx := context.Background()
	cfg := &models.VPNConfig{ListenPort: 51820}
	ep1 := svc.resolveClientEndpoint(ctx, cfg, 51820)
	ep2 := svc.resolveClientEndpoint(ctx, cfg, 51820)
	if ep1 != "198.51.100.7:51820" || ep2 != ep1 {
		t.Fatalf("endpoint resolution changed across calls: %q vs %q", ep1, ep2)
	}

	logs := buf.String()
	if n := strings.Count(logs, "detected(ip-service)"); n != 1 {
		t.Fatalf("source change must log INFO exactly once (cache hit stays quiet), got %d in:\n%s", n, logs)
	}
	if strings.Contains(logs, "fallback(127.0.0.1)") {
		t.Fatalf("unexpected fallback source logged:\n%s", logs)
	}
}

func TestResolveClientEndpoint_FallbackSourceLoggedWhenDetectionFails(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}

	t.Setenv("VPN_PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_ENDPOINT", "")
	t.Setenv("PUBLIC_IP", "")
	t.Setenv("VPN_DEBUG", "")

	origDetector := externalIPDetector
	origDial := outboundDial
	defer func() {
		externalIPDetector = origDetector
		outboundDial = origDial
	}()
	externalIPDetector = func(ctx context.Context) string { return "" }
	outboundDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &fakeUDPConn{addr: &net.UDPAddr{IP: net.IPv4(172, 19, 0, 3), Port: 51820}}, nil
	}

	var buf strings.Builder
	origW := logWriter()
	log.SetOutput(&buf)
	defer log.SetOutput(origW)

	ctx := context.Background()
	cfg := &models.VPNConfig{ListenPort: 51820}
	for i := 1; i <= 2; i++ {
		if got := svc.resolveClientEndpoint(ctx, cfg, 51820); got != "127.0.0.1:51820" {
			t.Fatalf("call %d: private-only environment must fall back to 127.0.0.1, got %q", i, got)
		}
	}

	logs := buf.String()
	if n := strings.Count(logs, "fallback(127.0.0.1)"); n != 1 {
		t.Fatalf("fallback source must log INFO once (not per resolve), got %d in:\n%s", n, logs)
	}
	if strings.Contains(logs, "172.19.0.3") {
		t.Fatalf("private container IP must never appear as endpoint:\n%s", logs)
	}
}
