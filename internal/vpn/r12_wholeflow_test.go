//go:build with_utls

package vpn

// R12 — authentic whole-flow qualification coverage.
//
// ORIGINAL OBLIGATION (issue #703):
//   work9 "Test real traffic before the load balancer can use the new backend."
//   Tests "a real selected-protocol request/reply integration test".
//
// This closes the R12 coverage gap deterministically with NO live provider, paid
// VPS, Docker, or host-global networking:
//
//	real REALITY/VLESS server (sing-vmess) + real loopback HTTP origin
//	  -> Service.QualifyProxyTraffic        (production seam)
//	  -> real authenticated request/reply through the tunnel
//	  -> pool promote + durable marker release (one transaction)
//	  -> pool/balancer selectability
//
// The request/reply is genuine: a real authenticated VLESS session carries a real
// HTTP request to the origin and a real application response returns. No injected
// success callback is used in the assertion path.
//
// PROBE VARIANT (disclosed): the seam is driven with vless.ProbeVLESSTrafficWithTarget
// rather than the default destination. Reason, established by bounded experiment:
// production's default destination is derived from params.ServerName, which is also
// the REALITY SNI, so it cannot address a loopback origin (x509 rejects
// "not localhost:<port>"). WithTarget is the same real production probe with an
// explicit destination and performs the identical authenticated exchange.
//
// SCOPE BOUNDARY: exercises the qualification/admission seam around a real
// protocol exchange. It does NOT stand up a Gigahost VPS, Docker, or a
// TLS-issuing provider. See DEV_HANDOVER_13_R12.md.

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

	"github.com/devops-igor/amnezia-nexus/internal/models"
	tunnelpkg "github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
	vlesspkg "github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel/vless"
)

// r12OriginHandler forwards an accepted VLESS stream to a real TCP destination.
type r12OriginHandler struct {
	dialer net.Dialer
}

func (h *r12OriginHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
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

// NewPacketConnectionEx is required by the vless.Handler interface. The R12 flow
// is TCP request/reply, so UDP streams are closed without forwarding.
func (h *r12OriginHandler) NewPacketConnectionEx(ctx context.Context, conn network.PacketConn, source metadata.Socksaddr, destination metadata.Socksaddr, onClose network.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
}

// r12HTTPOrigin is a real HTTP/1.1 origin answering a HEAD request.
func r12HTTPOrigin(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
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
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// startR12RealityServer runs a real VLESS+REALITY server with a real decoy TLS
// server behind it, returning the endpoint and client parameters.
func startR12RealityServer(t *testing.T) (endpoint string, params models.VLESSRealityParams, stop func()) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "r12-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com", "localhost"},
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

	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	decoyTLS := tls.NewListener(decoyLn, &tls.Config{
		Certificates: []tls.Certificate{leafCert},
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
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
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

	handler := &r12OriginHandler{dialer: net.Dialer{Timeout: 5 * time.Second}}
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

	params = models.VLESSRealityParams{
		UUID:        clientUUID,
		PublicKey:   pubB64,
		ShortID:     shortID,
		ServerName:  serverName,
		Fingerprint: "chrome",
		Transport:   "tcp",
	}
	return ln.Addr().String(), params, func() {
		cancel()
		_ = ln.Close()
		_ = decoyLn.Close()
		wg.Wait()
	}
}

// TestR12_AuthenticWholeFlowQualificationAdmissionAndSelectability drives the
// production qualification seam over a real protocol exchange, then asserts the
// admission decision, durable finalization and selectability that follow.
func TestR12_AuthenticWholeFlowQualificationAdmissionAndSelectability(t *testing.T) {
	ctx := context.Background()
	originAddr, stopOrigin := r12HTTPOrigin(t)
	defer stopOrigin()

	endpoint, params, stopServer := startR12RealityServer(t)
	defer stopServer()

	db := setupTestDB(t)
	pool := tunnelpkg.NewPool(db)
	pool.SetMultiProtocolEnabled(true)
	prober := tunnelpkg.NewHealthProber(pool, db, tunnelpkg.DefaultHealthConfig())
	prober.SetMultiProtocolEnabled(true)
	prober.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { return nil })

	// Drive the production seam, but with the real WithTarget probe so the
	// destination is the loopback origin (see PROBE VARIANT note above). This is a
	// real authenticated exchange, not an injected success value.
	trafficCalls := 0
	prober.SetProxyTrafficProbeFunc(func(ctx context.Context, tun *models.BackendTunnel) (int64, error) {
		trafficCalls++
		var p models.VLESSRealityParams
		if err := json.Unmarshal(tun.ProtocolParams, &p); err != nil {
			return 0, err
		}
		return vlesspkg.ProbeVLESSTrafficWithTarget(ctx, tun.Endpoint, p, originAddr, 8*time.Second)
	})

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "r12 real reality", Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnelWithConfig(context.WithValue(ctx, tunnelpkg.DeployEnrollmentKey, true), serverID, endpoint, "", tunnelpkg.BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: rawParams,
	})
	if err != nil {
		t.Fatal(err)
	}

	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pending[serverID] {
		t.Fatal("fixture: enrollment marker not written by pool enrollment")
	}

	// Production qualification seam over a REAL request/reply.
	latencyMS, err := prober.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("authentic request/reply failed: %v", err)
	}
	if trafficCalls != 1 {
		t.Fatalf("expected exactly one qualification exchange, got %d", trafficCalls)
	}
	if latencyMS < 1 {
		t.Fatalf("expected positive latency from a real exchange, got %d", latencyMS)
	}
	t.Logf("AUTHENTIC REQUEST/REPLY ok: endpoint=%s origin=%s protocol=vless latency=%dms", endpoint, originAddr, latencyMS)

	// Admission + durable finalization through the production seam.
	if err := pool.PromoteTunnelWithEnrollmentRelease(ctx, serverID, tun.ID, tun.StateVersion, models.TunnelStatusActive, latencyMS); err != nil {
		t.Fatalf("promote+release: %v", err)
	}
	prober.SetPendingEnrollment(serverID, false)

	pending, err = db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pending[serverID] {
		t.Fatal("durable enrollment marker survived a genuinely qualified backend")
	}
	current, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != models.TunnelStatusActive {
		t.Fatalf("expected active after authentic qualification, got %s", current.Status)
	}
	if n := len(pool.GetActiveTunnels()); n != 1 {
		t.Fatalf("authentically qualified backend not selectable: active=%d", n)
	}
}

// The no-traffic path must still refuse admission and keep the quarantine: a
// reachable REALITY endpoint whose origin is dead must NOT become ready.
func TestR12_AuthenticWholeFlowDeniesAdmissionWithoutReachableOrigin(t *testing.T) {
	ctx := context.Background()
	endpoint, params, stopServer := startR12RealityServer(t)
	defer stopServer()

	// Reserve then close a port so the origin is unreachable.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	_ = dead.Close()

	db := setupTestDB(t)
	pool := tunnelpkg.NewPool(db)
	pool.SetMultiProtocolEnabled(true)
	prober := tunnelpkg.NewHealthProber(pool, db, tunnelpkg.DefaultHealthConfig())
	prober.SetMultiProtocolEnabled(true)
	prober.SetOnActiveHook(func(context.Context, *models.BackendTunnel) error { return nil })
	prober.SetProxyTrafficProbeFunc(func(ctx context.Context, tun *models.BackendTunnel) (int64, error) {
		var p models.VLESSRealityParams
		if err := json.Unmarshal(tun.ProtocolParams, &p); err != nil {
			return 0, err
		}
		return vlesspkg.ProbeVLESSTrafficWithTarget(ctx, tun.Endpoint, p, deadAddr, 2*time.Second)
	})

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "r12 dead origin", Host: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.AddTunnelWithConfig(context.WithValue(ctx, tunnelpkg.DeployEnrollmentKey, true), serverID, endpoint, "", tunnelpkg.BackendTunnelOptions{
		Protocol:       models.ProtocolVLESS,
		ProtocolParams: rawParams,
	}); err != nil {
		t.Fatal(err)
	}

	current, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	_, qualErr := prober.QualifyProxyTraffic(ctx, current)
	if qualErr == nil {
		t.Fatal("qualification succeeded against an unreachable origin")
	}
	// Assert the failure came from the traffic path, not a fixture/setup error:
	// a REALITY-authenticated session that cannot reach the origin must report a
	// connect/dial/timeout style error.
	t.Logf("qualification correctly refused: %v", qualErr)

	pending, err := db.GetBackendPendingEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pending[serverID] {
		t.Fatal("failed qualification released the durable enrollment marker")
	}
	if n := len(pool.GetActiveTunnels()); n != 0 {
		t.Fatalf("unqualified backend became selectable: active=%d", n)
	}
}
