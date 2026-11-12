package handlers

// Authentic automatic traffic qualification over a real VLESS+REALITY endpoint.
//
// Every earlier checkpoint injected the qualification outcome: a callback returned success or
// an error, and the tests asserted what the installer did with that verdict. This file removes
// the injection for the supported VLESS path and lets the PRODUCTION qualification decide.
//
// The chain under test is the whole one a deployment uses:
//
//	production entry -> tracker (provider discovery, association, grant, pin)
//	  -> installer (register, install, enable)
//	  -> vpnSvc.QualifyProxyTraffic      production, no override
//	       -> qualifyVLESS                 production
//	            -> vless.ProbeVLESSTraffic production: authenticated VLESS session,
//	                 a real HTTP request, and a VERIFIED application reply
//	  -> promotion / durable quarantine release
//
// Two facts are counted at the endpoints rather than inferred:
//
//   - how many authenticated sessions the VLESS endpoint accepted;
//   - how many requests the origin received and how many replies it sent.
//
// Fixture boundaries, stated plainly: the provider answer, the SSH transport to the "host" and
// the protocol installation are controlled outcomes, exactly as in every earlier checkpoint.
// What is NOT controlled is qualification: there is no success callback, no error callback and
// no destination override. Production derives the destination from the parameters on the
// server row, which the fixture seeds with the loopback origin address - so the production
// derivation itself points at loopback. That is why no seam is needed here.
//
// Scope: this proves the VLESS+REALITY automatic path. It says nothing about AWG or other
// protocols, and nothing about Linux/kernel routing.

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
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/json/badoption"
	slogger "github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"

	"github.com/devops-igor/amnezia-nexus/internal/manager/ssh"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// authenticTrafficEndpoint is a real VLESS+REALITY endpoint relaying to a counted origin.
type authenticTrafficEndpoint struct {
	// endpoint is the host:port a client dials, which is also what the server row records.
	endpoint string
	params   models.VLESSRealityParams
	// originAddr is the address the endpoint forwards to. It is seeded into the tunnel's
	// ServerName, so production derivation yields it with no override.
	originAddr string
	// authenticated counts accepted VLESS sessions carrying the client's identity.
	authenticated *atomic.Int64
	// originRequests counts requests the origin actually received.
	originRequests *atomic.Int64
	// originReplies counts replies the origin actually sent.
	originReplies *atomic.Int64
	stop          func()
}

// authenticOriginHandler forwards an accepted VLESS stream to the real origin address.
//
// It exists because the VLESS service needs a destination router; the routing decision is
// "wherever the client asked", which is the origin the fixture counted.
type authenticOriginHandler struct {
	dialer   net.Dialer
	requests *atomic.Int64
	replies  *atomic.Int64
	// authenticated counts connections the VLESS service accepted for a KNOWN user. The
	// service calls this only after it has matched the client's UUID, so it is the
	// authentication evidence - unlike the REALITY handshake, which completes for any client
	// because the camouflage certificate is presented before user validation.
	authenticated *atomic.Int64
}

// NewPacketConnectionEx is required by the VLESS Handler interface. The fixture runs a TCP
// HTTP exchange, so a packet connection is refused rather than silently accepted: a UDP
// "success" here would be evidence of nothing.
func (h *authenticOriginHandler) NewPacketConnectionEx(
	context.Context, network.PacketConn, metadata.Socksaddr, metadata.Socksaddr,
	network.CloseHandlerFunc,
) {
}

func (h *authenticOriginHandler) NewConnectionEx(
	ctx context.Context, conn net.Conn, _ metadata.Socksaddr, destination metadata.Socksaddr,
	onClose network.CloseHandlerFunc,
) {
	defer func() { _ = conn.Close() }()
	if onClose != nil {
		defer onClose(nil)
	}
	// Reaching here means the VLESS service matched the client's UUID: the session is
	// authenticated, not merely handshaked.
	h.authenticated.Add(1)
	target, err := h.dialer.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		return
	}
	defer func() { _ = target.Close() }()
	h.requests.Add(1)
	// Relay in both directions until either side closes. The reply count is incremented
	// only when the origin actually wrote bytes back, so a half-open connection cannot be
	// mistaken for a delivered response.
	buf := make([]byte, 4096)
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			if _, writeErr := target.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
		reply := make([]byte, 4096)
		rn, recvErr := target.Read(reply)
		if rn > 0 {
			if _, writeErr := conn.Write(reply[:rn]); writeErr != nil {
				return
			}
			h.replies.Add(1)
		}
		if recvErr != nil {
			return
		}
	}
}

// startAuthenticTrafficFixture builds a real VLESS+REALITY endpoint plus a counted origin.
//
// `acceptRequests` controls whether the origin answers at all: with it false, the endpoint and
// its authentication still work, the origin still receives the request, and no reply is ever
// delivered. That is the A2 negative shape "handshake and authentication succeeded but the
// application reply is missing".
func startAuthenticTrafficFixture(t *testing.T, acceptRequests bool) *authenticTrafficEndpoint {
	t.Helper()

	// --- counted origin -------------------------------------------------------------
	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	var originRequests, originReplies atomic.Int64
	originDone := make(chan struct{})
	go func() {
		defer close(originDone)
		for {
			c, acceptErr := originLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 2048)
				n, readErr := conn.Read(buf)
				if n > 0 {
					originRequests.Add(1)
				}
				if readErr != nil || !acceptRequests {
					// Accepted the connection and read the request, then never reply. The
					// caller's qualification must not be able to call that a success.
					return
				}
				body := "authentic-origin-ok"
				_, _ = fmt.Fprintf(conn,
					"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					len(body), body)
				originReplies.Add(1)
			}(c)
		}
	}()
	originAddr := originLn.Addr().String()

	// --- REALITY decoy ------------------------------------------------------------------
	decoyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("decoy key: %v", err)
	}
	now := time.Now()
	decoyTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
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
		t.Fatalf("decoy cert: %v", err)
	}
	decoyCert := tls.Certificate{Certificate: [][]byte{decoyDER}, PrivateKey: decoyKey}
	decoyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("decoy listen: %v", err)
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
			c, acceptErr := decoyTLS.Accept()
			if acceptErr != nil {
				return
			}
			go func(cc net.Conn) {
				defer func() { _ = cc.Close() }()
				if tlsConn, ok := cc.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				buf := make([]byte, 64)
				_, _ = cc.Read(buf)
			}(c)
		}
	}()

	// --- VLESS+REALITY endpoint ---------------------------------------------------------
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("reality key: %v", err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
	const shortID = "0123456789abcdef"
	// REALITY validates that the client's SNI equals the server's configured ServerName, and
	// production sends `p.ServerName` verbatim while ALSO using it as the forwarding
	// destination. So the camouflage name here must be the origin address itself - one value
	// serving both roles, which is how the production path is designed.
	camouflageServerName := originAddr
	clientUUID := uuid.New().String()

	serverCfg, err := sTLS.NewRealityServer(context.Background(), nil, option.InboundTLSOptions{
		Enabled:    true,
		ServerName: camouflageServerName,
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

	var authenticated atomic.Int64
	handler := &authenticOriginHandler{
		dialer:        net.Dialer{Timeout: 5 * time.Second},
		requests:      &originRequests,
		replies:       &originReplies,
		authenticated: &authenticated,
	}
	vlessSvc := vless.NewService[int](slogger.NOP(), handler)
	vlessSvc.UpdateUsers([]int{1}, []string{clientUUID}, []string{""})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("vless listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn, handshakeErr := sTLS.ServerHandshake(ctx, conn, serverCfg)
				if handshakeErr != nil {
					_ = conn.Close()
					return
				}
				// The REALITY handshake completing is NOT authentication: it presents the
				// camouflage certificate before the client's UUID is checked. The counter is
				// incremented by the handler, which the service only reaches for a known user.
				_ = vlessSvc.NewConnection(ctx, tlsConn, metadata.SocksaddrFromNet(tlsConn.RemoteAddr()), nil)
				_ = tlsConn.Close()
			}(c)
		}
	}()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = ln.Close()
			_ = decoyLn.Close()
			_ = originLn.Close()
			wg.Wait()
			<-originDone
		})
	}

	return &authenticTrafficEndpoint{
		endpoint:       ln.Addr().String(),
		originAddr:     originAddr,
		authenticated:  &authenticated,
		originRequests: &originRequests,
		originReplies:  &originReplies,
		stop:           stop,
		params: models.VLESSRealityParams{
			UUID:      clientUUID,
			Flow:      "",
			PublicKey: pubB64,
			ShortID:   shortID,
			// ServerName is the FORWARDING destination the production probe derives, so the
			// fixture sets it to the loopback origin. No override, no seam: production reads
			// this value from the server row and dials it.
			ServerName:  originAddr,
			Fingerprint: "chrome",
			Transport:   "tcp",
		},
	}
}

// provisionVLESSIdentity makes the fixture's protocol manager hand out these VLESS
// credentials, which is the production provisioning contract.
//
// `resolveInstalledProxyParamsForProto` asks the protocol manager's AddClient for the client
// credentials when the server row carries none yet, so whatever AddClient returns becomes the
// tunnel's real parameters. That is how production derivation ends up pointing at this
// fixture's endpoint and origin WITHOUT any qualification override and WITHOUT rewriting a
// stored row.
func (e *installEnv) provisionVLESSIdentity(
	t *testing.T, host string, port int, params models.VLESSRealityParams,
) {
	t.Helper()
	mgr, ok := e.h.registry.Get(models.ProtocolVLESS)
	if !ok {
		t.Fatalf("no VLESS protocol manager is registered")
	}
	fixture, ok := mgr.(*mockProtocolManager)
	if !ok {
		t.Fatalf("VLESS manager is %T, want the fixture manager", mgr)
	}
	_ = host
	_ = port
	fixture.addClientFn = func(context.Context, *models.Server, map[string]any) (map[string]any, error) {
		return map[string]any{
			"client_id":   params.UUID,
			"uuid":        params.UUID,
			"flow":        params.Flow,
			"public_key":  params.PublicKey,
			"short_id":    params.ShortID,
			"server_name": params.ServerName,
			"port":        port,
		}, nil
	}
}

// splitEndpointHostPort splits a host:port, failing the test on a malformed value.
func splitEndpointHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

// authenticPoolContains reports whether a server is selectable by the production path.
func authenticPoolContains(t *testing.T, env *installEnv, serverID int64) bool {
	t.Helper()
	all, err := env.h.vpnSvc.GetTunnels(context.Background())
	if err != nil {
		t.Fatalf("read tunnels: %v", err)
	}
	for _, tun := range loadbalancer.FilterHealthy(all, 0) {
		if tun.ServerID == serverID {
			return true
		}
	}
	return false
}

// authenticDurableQuarantine reports whether the durable enrollment marker is still set.
func authenticDurableQuarantine(t *testing.T, env *installEnv, serverID int64) bool {
	t.Helper()
	marks, err := env.db.GetBackendPendingEnrollments(context.Background())
	if err != nil {
		t.Fatalf("read durable enrollment markers: %v", err)
	}
	return marks[serverID]
}

// authenticSSHClientFactory is the SSH boundary every automatic install needs.
//
// It is the command-capable mock client, because the VLESS install bootstraps containers over
// SSH. It is installed BEFORE the tracking pass so the first-contact challenge and the install
// observe the SAME identity - which is how one durable pin is preserved without ever rewriting
// the stored fingerprint.
func (e *installEnv) useAuthenticSSHBoundary() {
	e.t.Helper()
	e.h.SetSSHDialerForTest(func(context.Context, ssh.Config) (ssh.SSHClient, error) {
		return &mockDeploySSHClient{fingerprint: installFixtureFingerprint}, nil
	})
}

// useAuthenticQualification REMOVES the shared fixture's qualification override.
//
// `newInstallEnv` installs a proxy-traffic callback that returns success, which is right for
// tests that are about something other than qualification. This checkpoint is about
// qualification, so the override must be cleared or the production probe would never run and
// every assertion here would be vacuous. Clearing a fixture seam is not a production change.
func (e *installEnv) useAuthenticQualification() {
	e.t.Helper()
	e.h.vpnSvc.SetProxyTrafficProbeFuncForTest(nil)
}

// requireNoFingerprintRewrite fails if the stored pin differs from what the peer presented,
// which would mean a fixture "aligned" the pin instead of preserving it.
func requireNoFingerprintRewrite(t *testing.T, got, want, what string) {
	t.Helper()
	if strings.TrimSpace(got) != strings.TrimSpace(want) {
		t.Fatalf("%s: stored fingerprint is %q but the peer presented %q "+
			"(the pin must never be rewritten to match a fixture)", what, got, want)
	}
}
