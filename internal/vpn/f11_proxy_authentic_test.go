//go:build with_utls

package vpn

// F11 — authentic positive/negative oracle over the ACTUAL production health
// consumer and the ACTUAL production proxy device type.
//
// Unlike the capability test (which proves the health path reaches a real payload
// exchange and that a failure still fails), this fixture delivers REAL
// authenticated application request/replies for BOTH proxy transports:
//
//	real protocol endpoint (VLESS+REALITY / Naive H2 CONNECT) + real origin
//	  -> EnableBackendWithConfig                 (production attach path)
//	  -> real *ProxyBackendDevice                (production device type)
//	  -> prober.ProbeTunnel                      (production sweep, real outer probe)
//	  -> defaultCanaryProbe -> payload canary    (production inner probe)
//	  -> real authenticated request/reply through the device's own egress
//	  -> active, enabled and selectable, repeatedly
//
// and then proves the negative: once the payload path breaks, the same production
// path stops treating the backend as healthy, so the repair is not unconditional
// success.
//
// DESTINATION SEAM (disclosed): production derives the health destination from the
// tunnel's own protocol parameters, which in a local fixture is a public name that
// cannot resolve to loopback. The fixture supplies the loopback destination through
// a narrow seam that changes only the address — the exchange, the authentication and
// the pass/fail decision remain the real production ones. This is the same
// explicit-destination arrangement the existing R12 test uses.

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
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/naive"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/streambridge"
	vlesspkg "github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
)

// f11OriginHandler forwards an accepted VLESS stream to a real TCP destination.
type f11OriginHandler struct {
	dialer net.Dialer
}

func (h *f11OriginHandler) NewConnectionEx(ctx context.Context, conn net.Conn, _ metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
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
		if cw, ok := target.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, target)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

func (h *f11OriginHandler) NewPacketConnectionEx(ctx context.Context, conn network.PacketConn, _ metadata.Socksaddr, _ metadata.Socksaddr, onClose network.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
}

// f11PlainHTTPOrigin is a real plain HTTP/1.1 origin answering a HEAD request. The
// production VLESS probe addresses a non-443 destination over plain HTTP first, so
// this is the origin shape a real plaintext upstream presents.
func f11PlainHTTPOrigin(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}(c)
		}
	}()
	var once sync.Once
	return ln.Addr().String(), func() { once.Do(func() { _ = ln.Close(); <-done }) }
}

// startF11RealityServer runs a real VLESS+REALITY server over a real decoy TLS
// server and returns its endpoint and client parameters.
func startF11RealityServer(t *testing.T) (endpoint string, params models.VLESSRealityParams, stop func()) {
	t.Helper()

	decoyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	decoyTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "decoy"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	decoyDER, err := x509.CreateCertificate(rand.Reader, decoyTmpl, decoyTmpl, &decoyKey.PublicKey, decoyKey)
	if err != nil {
		t.Fatal(err)
	}
	decoyCert := tls.Certificate{Certificate: [][]byte{decoyDER}, PrivateKey: decoyKey}

	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	decoyTLS := tls.NewListener(decoyLn, &tls.Config{
		Certificates: []tls.Certificate{decoyCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	decoyHost, decoyPortStr, _ := net.SplitHostPort(decoyLn.Addr().String())
	var decoyPort uint16
	_, _ = fmt.Sscanf(decoyPortStr, "%d", &decoyPort)
	go func() {
		for {
			c, err := decoyTLS.Accept()
			if err != nil {
				return
			}
			go func(cc net.Conn) {
				defer cc.Close()
				_ = cc.(*tls.Conn).Handshake()
				buf := make([]byte, 64)
				_, _ = cc.Read(buf)
			}(c)
		}
	}()

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
	const shortID = "0123456789abcdef"
	const serverName = "example.com"
	clientUUID := uuid.New().String()

	serverCfg, err := sTLS.NewRealityServer(context.Background(), nil, option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Reality: &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: privB64,
			ShortID:    badoption.Listable[string]{shortID},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{Server: decoyHost, ServerPort: decoyPort},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewRealityServer: %v", err)
	}

	handler := &f11OriginHandler{dialer: net.Dialer{Timeout: 5 * time.Second}}
	vlessSvc := vless.NewService[int](logger.NOP(), handler)
	vlessSvc.UpdateUsers([]int{1}, []string{clientUUID}, []string{""})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn, err := sTLS.ServerHandshake(ctx, conn, serverCfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				_ = vlessSvc.NewConnection(ctx, tlsConn, metadata.SocksaddrFromNet(tlsConn.RemoteAddr()), nil)
				_ = tlsConn.Close()
			}(c)
		}
	}()

	var once sync.Once
	return ln.Addr().String(),
		models.VLESSRealityParams{
			UUID:        clientUUID,
			PublicKey:   pubB64,
			ShortID:     shortID,
			ServerName:  serverName,
			Fingerprint: "chrome",
			Transport:   "tcp",
		},
		func() {
			once.Do(func() {
				cancel()
				_ = ln.Close()
				_ = decoyLn.Close()
				wg.Wait()
			})
		}
}

// f11TLSOrigin is a real TLS HTTP/1.1 origin answering a HEAD request, signed by
// the caller's CA so an authenticating client verifies it normally (no
// InsecureSkipVerify anywhere).
func f11TLSOrigin(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serverName string) (addr string, stop func()) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName, "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert := tls.Certificate{Certificate: [][]byte{leafDER, caCert.Raw}, PrivateKey: leafKey}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{leafCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			}(c)
		}
	}()
	var once sync.Once
	return ln.Addr().String(), func() { once.Do(func() { _ = tlsLn.Close(); <-done }) }
}

func f11MustPort(t *testing.T, addr string) (host string, port int) {
	t.Helper()
	h, pStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	p, err := strconv.Atoi(pStr)
	if err != nil {
		t.Fatalf("atoi %q: %v", pStr, err)
	}
	return h, p
}

// f11AssertSweepsKeepHealthy runs production ProbeTunnel with NO inner-probe
// override and asserts the qualified backend stays active, enabled, durable-active
// and selectable across repeated ordinary sweeps.
func f11AssertSweepsKeepHealthy(t *testing.T, svc *Service, db *database.DB, sid, tunnelID int64, sweeps int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < sweeps; i++ {
		live, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.prober.ProbeTunnel(ctx, live); err != nil {
			t.Fatalf("sweep %d failed on a genuinely healthy backend: %v", i+1, err)
		}
		after, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		if after.Status != models.TunnelStatusActive {
			t.Fatalf("sweep %d took a healthy proxy backend to %q", i+1, after.Status)
		}
		if n := len(svc.pool.GetActiveTunnels()); n != 1 {
			t.Fatalf("sweep %d left %d selectable backends, want 1", i+1, n)
		}
		if !after.Enabled {
			t.Fatalf("sweep %d administratively disabled a healthy backend", i+1)
		}
		durable, err := db.GetBackendTunnel(ctx, tunnelID)
		if err != nil {
			t.Fatal(err)
		}
		if durable.Status != models.TunnelStatusActive || !durable.Enabled {
			t.Fatalf("sweep %d durable state = %s enabled=%v", i+1, durable.Status, durable.Enabled)
		}
		if svc.prober.IsPendingEnrollment(sid) {
			t.Fatalf("sweep %d left the enrollment marker set on a qualified backend", i+1)
		}
		t.Logf("sweep=%d status=%s selectable=%d", i+1, after.Status, len(svc.pool.GetActiveTunnels()))
	}
}

// f11AssertBrokenPayloadDenied removes the payload path and asserts the same
// production health path stops treating the backend as healthy and selectable.
func f11AssertBrokenPayloadDenied(t *testing.T, svc *Service, sid int64) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		live, err := svc.pool.GetTunnel(sid)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = svc.prober.ProbeTunnel(ctx, live)
	}
	final, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status == models.TunnelStatusActive && len(svc.pool.GetActiveTunnels()) == 1 {
		t.Fatalf("a proxy backend whose payload path is broken stayed active and selectable (status=%s)", final.Status)
	}
	t.Logf("broken payload: status=%s enabled=%v selectable=%d innerFailures=%d",
		final.Status, final.Enabled, len(svc.pool.GetActiveTunnels()), svc.CanaryFailureCount(final.ID))
}

// TestF11_AuthenticVLESSProxyHealthKeepsQualifiedBackendAvailable drives the
// production attach path and production health consumer over a real authenticated
// VLESS request/reply, asserts it stays healthy, then asserts a broken payload is
// still denied.
func TestF11_AuthenticVLESSProxyHealthKeepsQualifiedBackendAvailable(t *testing.T) {
	ctx := context.Background()

	originAddr, stopOrigin := f11PlainHTTPOrigin(t)
	var originOnce sync.Once
	stopOriginOnce := func() { originOnce.Do(stopOrigin) }
	defer stopOriginOnce()

	realityEndpoint, params, stopReality := startF11RealityServer(t)
	defer stopReality()

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tun := range svc.pool.ListTunnels() {
			if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})

	realityHost, realityPort := f11MustPort(t, realityEndpoint)
	sid, err := db.CreateServer(ctx, &models.Server{
		Name: "f11 authentic vless",
		Host: realityHost,
		Protocols: map[string]any{
			"vless": map[string]any{"installed": true, "port": realityPort, "server_name": "example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableBackendWithConfig(ctx, sid, tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: raw,
	}); err != nil {
		t.Fatalf("EnableBackendWithConfig: %v", err)
	}
	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("GetTunnel: tun=%v err=%v", tun, err)
	}
	attached := svc.GetBackendDeviceForTest(tun.ID)
	if _, ok := attached.(*ProxyBackendDevice); !ok {
		t.Fatalf("production attach path produced %T, want *ProxyBackendDevice", attached)
	}

	svc.SetProxyTrafficProbeFuncForTest(func(c context.Context, tn *models.BackendTunnel) (int64, error) {
		var p models.VLESSRealityParams
		if err := json.Unmarshal(tn.ProtocolParams, &p); err != nil {
			return 0, err
		}
		return vlesspkg.ProbeVLESSTrafficWithTarget(c, tn.Endpoint, p, originAddr, 8*time.Second)
	})
	svc.prober.SetProxyCanaryDestinationForTest(originAddr)

	latencyMS, err := svc.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("authentic qualification failed: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, sid, latencyMS); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if svc.prober.GetCanaryProbeFunc() != nil {
		t.Fatal("health must use the production inner probe, not a canary override")
	}
	if !svc.prober.HasCanaryProber(tun) {
		t.Fatal("production device is not visible to the health consumer")
	}

	f11AssertSweepsKeepHealthy(t, svc, db, sid, tun.ID, 3)

	stopOriginOnce()
	f11AssertBrokenPayloadDenied(t, svc, sid)
}

// TestF11_AuthenticNaiveProxyHealthKeepsQualifiedBackendAvailable does the same for
// NaiveProxy: a real H2 CONNECT proxy fronting a real echo origin, reached through
// the naive dialer that is the device's actual egress.
func TestF11_AuthenticNaiveProxyHealthKeepsQualifiedBackendAvailable(t *testing.T) {
	ctx := context.Background()

	caCert, caKey := setupE2ETestCA(t)
	proxyAddr, stopProxy := setupE2ETestH2Server(t, "127.0.0.1:0", "f11-user", "f11-pass", caCert, caKey, "")
	var proxyOnce sync.Once
	stopProxyOnce := func() { proxyOnce.Do(stopProxy) }
	defer stopProxyOnce()

	// Real TLS origin: the authenticated naive exchange speaks TLS + HTTP through
	// the CONNECT tunnel, so the origin must genuinely terminate TLS under the
	// proxy's camouflage DNS name.
	originAddr, stopOrigin := f11TLSOrigin(t, caCert, caKey, "localhost")
	var originOnce sync.Once
	stopOriginOnce := func() { originOnce.Do(stopOrigin) }
	defer stopOriginOnce()

	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tun := range svc.pool.ListTunnels() {
			if d := svc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})

	proxyHost, proxyPort := f11MustPort(t, proxyAddr)
	sid, err := db.CreateServer(ctx, &models.Server{
		Name: "f11 authentic naive",
		Host: proxyHost,
		Protocols: map[string]any{
			"naive": map[string]any{"installed": true, "port": proxyPort, "domain": "localhost"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	naiveParams := models.NaiveProxyParams{
		Username: "f11-user",
		Password: "f11-pass",
		Domain:   "localhost",
	}
	raw, err := json.Marshal(naiveParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableBackendWithConfig(ctx, sid, tunnel.BackendTunnelOptions{
		Protocol:       models.ProtocolNaive,
		ProtocolParams: raw,
	}); err != nil {
		t.Fatalf("EnableBackendWithConfig: %v", err)
	}
	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("GetTunnel: tun=%v err=%v", tun, err)
	}

	// Same production device type, built over a real naive dialer against the real
	// H2 CONNECT proxy. The in-process H2 transport is the documented test-mode
	// transport, so this fixture needs no external daemon binary.
	naiveDialer, err := naive.New(proxyAddr, naiveParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = naiveDialer.Close() })
	bridge, err := streambridge.New(streambridge.Config{MTU: 1280}, naiveDialer)
	if err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyBackendDevice(bridge, nil)
	t.Cleanup(func() { _ = proxy.Close() })
	svc.SetBackendDeviceForTest(tun.ID, proxy)

	svc.SetProxyTrafficProbeFuncForTest(func(c context.Context, tn *models.BackendTunnel) (int64, error) {
		var p models.NaiveProxyParams
		if err := json.Unmarshal(tn.ProtocolParams, &p); err != nil {
			return 0, err
		}
		return naive.ProbeNaiveTrafficViaDialerTo(c, naiveDialer, p, originAddr, 8*time.Second)
	})
	svc.prober.SetProxyCanaryDestinationForTest(originAddr)

	latencyMS, err := svc.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("authentic naive qualification failed: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, sid, latencyMS); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if svc.prober.GetCanaryProbeFunc() != nil {
		t.Fatal("health must use the production inner probe, not a canary override")
	}

	f11AssertSweepsKeepHealthy(t, svc, db, sid, tun.ID, 3)

	stopProxyOnce()
	f11AssertBrokenPayloadDenied(t, svc, sid)
}
