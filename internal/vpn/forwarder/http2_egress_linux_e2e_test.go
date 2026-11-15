//go:build linux

package forwarder

// HTTP/2-only end-to-end qualification for policy routing (issue #833).
//
// The forwarder is L3/L4: it never parses, terminates or classifies HTTP, so an
// HTTP/2-only site is ordinary TLS over TCP and routing cannot break it by
// protocol handling. The realistic failure mode is MTU/MSS, and it hides well:
// a client that advertises an MSS larger than the path MTU makes the far end
// emit segments the client tunnel cannot carry, and HTTP/2 fails while a small
// HTTP/1.1 request appeared to work.
//
// These cases extend the namespace fixture of TestLinuxE2E_DirectEgress. The
// origin runs inside the same isolated network namespace (a re-exec of this
// test binary), the client is a real TCP stack (gvisor netstack) whose packets
// enter the production dispatcher exactly as a peer's packets do, and the
// proxied case uses a real packet device (netstack) as the proxy backend
// tunnel. Nothing here resolves a name, reaches the internet or binds a fixed
// public address.
//
// Modeled boundaries, stated explicitly so the proof cannot over-claim:
//   - The direct origin is reached over the fixture TUN with the kernel's own
//     TCP stack, so the exchange crosses a real kernel.
//   - The MSS clamp is the semantic action of the AWG install rule
//     `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
//     -j TCPMSS --clamp-mss-to-pmtu`: outbound SYN segments have their MSS
//     option rewritten to the path MTU. It is applied at the WAN device
//     boundary by mssClampDevice because a user-mode packet path cannot execute
//     the kernel rule, and the TUN's own MTU would otherwise mask the defect.
//   - The client tunnel's 1280-byte MTU is enforced where the forwarder hands a
//     packet back to the peer (the return path), which is the boundary that
//     cannot carry an oversized inner packet in production.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"golang.org/x/net/http2"
)

// h2Fixture is the shared namespace fixture: one TUN + namespace with the
// direct origin, one netstack proxy backend with the proxied origin, and one
// forwarder with policy routing enabled.
type h2Fixture struct {
	t        *testing.T
	fwd      *Forwarder
	dem      *DirectEgressManager
	rc       *testRouteCache
	wan      *mssClampDevice
	cert     tls.Certificate
	pool     *x509.CertPool
	body     []byte
	proxyID  int64
	proxyDev *h2CountingDevice
	proxySrv *http.Server
}

func newH2EgressFixture(t *testing.T) *h2Fixture {
	t.Helper()
	fx := &h2Fixture{t: t, rc: newTestRouteCache(), body: h2OriginBody(), proxyID: 401}

	cert, pool, certPEM, keyPEM := newH2OriginCertificate(t)
	fx.cert, fx.pool = cert, pool

	tunName := fmt.Sprintf("tun%d", time.Now().UnixNano()%10000)
	tunDev, err := createLinuxTUN(tunName)
	if err != nil {
		t.Fatalf("createLinuxTUN failed: %v", err)
	}
	t.Cleanup(func() { _ = tunDev.Close() })

	fx.startDirectOrigin(t, tunName, certPEM, keyPEM)

	fx.wan = &mssClampDevice{PacketDevice: tunDev}
	fx.fwd = NewForwarder(nil, "10.100.0.0/16", 100)
	fx.fwd.SetPBREnabled(true)
	fx.dem = NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  netip.MustParseAddr("198.51.200.1"),
		WANDevice:  fx.wan,
		UDPTimeout: 5 * time.Second,
		TCPTimeout: 30 * time.Second,
	}, fx.fwd)
	t.Cleanup(func() { _ = fx.dem.Close() })
	fx.fwd.SetDirectEgress(fx.dem)
	fx.fwd.SetRouteCache(fx.rc)
	fx.fwd.StartPumps(t.Context())

	// The proxied origin needs the forwarder, and its teardown must close its
	// device before the pumps stop writing to it.
	fx.startProxyOrigin(t)
	t.Cleanup(fx.fwd.StopPumps)
	return fx
}

// startDirectOrigin creates the isolated namespace, moves the TUN into it and
// runs the h2-only origin there as a re-exec of this test binary.
func (fx *h2Fixture) startDirectOrigin(t *testing.T, tunName string, certPEM, keyPEM []byte) {
	t.Helper()
	netnsName := fmt.Sprintf("h2ns%d", time.Now().UnixNano()%100000)
	if err := exec.Command("ip", "netns", "add", netnsName).Run(); err != nil {
		t.Fatalf("ip netns add failed: %v", err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", netnsName).Run() })

	if err := exec.Command("ip", "link", "set", tunName, "netns", netnsName).Run(); err != nil {
		t.Fatalf("ip link set netns failed: %v", err)
	}
	_ = exec.Command("ip", "netns", "exec", netnsName, "sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6=1", tunName)).Run()
	_ = exec.Command("ip", "-n", netnsName, "link", "set", "lo", "up").Run()
	if err := exec.Command("ip", "-n", netnsName, "addr", "add", "198.51.200.2/24", "dev", tunName).Run(); err != nil {
		t.Fatalf("ip addr add failed: %v", err)
	}
	if err := exec.Command("ip", "-n", netnsName, "link", "set", tunName, "up").Run(); err != nil {
		t.Fatalf("ip link set up failed: %v", err)
	}

	cmd := exec.Command("ip", "netns", "exec", netnsName, os.Args[0], "-test.run=TestHelperPlaceholder")
	cmd.Env = append(os.Environ(),
		h2OriginHelperEnv+"=1",
		h2OriginTargetEnv+"="+h2DirectOriginAddr,
		h2OriginCertEnv+"="+string(certPEM),
		h2OriginKeyEnv+"="+string(keyPEM),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("origin stdin pipe failed: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("origin stdout pipe failed: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start HTTP/2 origin failed: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ready := make([]byte, 6)
	if _, err := io.ReadFull(stdout, ready); err != nil || string(ready) != "READY\n" {
		t.Fatalf("HTTP/2 origin not ready: %q, err: %v", string(ready), err)
	}
}

// startProxyOrigin runs the proxied origin inside a netstack packet device that
// is attached as the proxy backend tunnel, and pumps its replies into the
// production return path exactly as a real backend device does.
func (fx *h2Fixture) startProxyOrigin(t *testing.T) {
	t.Helper()
	originIP := netip.MustParseAddr(h2ProxyOriginIP)
	vt, ns, err := netstack.CreateNetTUN([]netip.Addr{originIP}, nil, 1500)
	if err != nil {
		t.Fatalf("create proxy backend netstack failed: %v", err)
	}
	ln, err := ns.ListenTCPAddrPort(netip.AddrPortFrom(originIP, h2ProxyOriginPort))
	if err != nil {
		_ = vt.Close()
		t.Fatalf("proxy backend listen failed: %v", err)
	}
	fx.proxySrv = newHTTP2OnlyOrigin(fx.cert, fx.body)
	go func() { _ = fx.proxySrv.Serve(tls.NewListener(ln, fx.proxySrv.TLSConfig)) }()

	fx.proxyDev = &h2CountingDevice{PacketDevice: &h2BatchDevice{dev: vt}}
	fx.fwd.AttachBackendDevice(fx.proxyID, fx.proxyDev)

	done := make(chan struct{})
	// Registered first, so it runs after the device is closed and the reader
	// goroutine has exited.
	t.Cleanup(func() { <-done })
	t.Cleanup(func() {
		fx.fwd.DetachBackendDevice(fx.proxyID)
		_ = fx.proxySrv.Close()
		_ = fx.proxyDev.Close()
	})

	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, err := fx.proxyDev.Read(buf)
			if err != nil {
				return
			}
			if n < 20 || buf[0]>>4 != 4 {
				continue
			}
			dstIP := netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]}).String()
			_ = fx.fwd.RouteBackendToClient(fx.proxyID, buf[:n], dstIP)
		}
	}()
}

// h2Session is one peer session driven over the fixture.
type h2Session struct {
	fx        *h2Fixture
	client    *h2ClientStack
	returns   *h2MTUReturnPath
	peerKey   string
	sessionID string
	clientIP  string
	path      *ReturnPath
}

// startSession registers a peer whose packets enter the production dispatcher
// and whose returns are bounded by the client tunnel MTU.
func (fx *h2Fixture) startSession(t *testing.T, peerKey, sessionID, clientIP string, clientMTU uint32, dst netip.Addr, decision policy.Decision) *h2Session {
	t.Helper()
	client := newH2ClientStack(t, netip.MustParseAddr(clientIP), clientMTU)
	returns := newH2MTUReturnPath(h2PathMTU, client.inject)
	path := NewReturnPath(returns.write)
	fx.fwd.RegisterSessionWithReturnPath(sessionID, "conn-"+peerKey, peerKey, clientIP, fx.proxyID, path)
	fx.rc.Set(sessionID, dst, decision)
	client.setSubmit(func(packet []byte) error { return fx.fwd.RouteClientToBackend(peerKey, packet) })

	s := &h2Session{fx: fx, client: client, returns: returns, peerKey: peerKey, sessionID: sessionID, clientIP: clientIP, path: path}
	t.Cleanup(s.end)
	return s
}

func (s *h2Session) end() {
	// Retire the route first: UnregisterSession joins the client pump, so no
	// queued reply can still be handed to a return path this is about to close.
	s.fx.fwd.UnregisterSession(s.peerKey)
	s.fx.dem.PurgeSession(s.sessionID)
	s.path.Close()
	s.client.close()
}

// h2ExchangeResult is what one HTTP/2 exchange observed.
type h2ExchangeResult struct {
	body  []byte
	proto string
	alpn  string
	err   error
}

// exchange drives one HTTP/2-only request from the session's client stack to
// dst. The transport speaks HTTP/2 exclusively and its dialer never resolves a
// name, so the request cannot escape the fixture or fall back to HTTP/1.1.
func (s *h2Session) exchange(ctx context.Context, dst netip.AddrPort, timeout time.Duration) h2ExchangeResult {
	//nolint:staticcheck // SA1019: an HTTP/2-only client that cannot fall back is the case under test.
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    s.fx.pool,
			ServerName: h2OriginServerName,
			NextProtos: []string{http2.NextProtoTLS},
			MinVersion: tls.VersionTLS12,
		},
		DialTLSContext: func(ctx context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
			return s.client.dialTLS(ctx, dst, cfg)
		},
	}
	//nolint:staticcheck // SA1019: closes the HTTP/2 transport declared above.
	defer tr.CloseIdleConnections()

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+h2OriginServerName+h2OriginPath, nil)
	if err != nil {
		return h2ExchangeResult{err: err}
	}
	//nolint:staticcheck // SA1019: requests go through the HTTP/2 transport above.
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return h2ExchangeResult{err: err}
	}
	res := h2ExchangeResult{proto: resp.Proto, err: nil}
	if resp.TLS != nil {
		res.alpn = resp.TLS.NegotiatedProtocol
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	res.body = body
	res.err = readErr
	return res
}

// assertBodyEquality fails unless the exchange delivered the origin's body
// byte-for-byte over a negotiated HTTP/2 connection.
func assertBodyEquality(t *testing.T, res h2ExchangeResult, want []byte, label string) {
	t.Helper()
	if res.err != nil {
		t.Fatalf("%s: HTTP/2 exchange failed: %v", label, res.err)
	}
	if res.proto != "HTTP/2.0" {
		t.Fatalf("%s: expected HTTP/2.0, got %q", label, res.proto)
	}
	if res.alpn != http2.NextProtoTLS {
		t.Fatalf("%s: expected ALPN %q, got %q", label, http2.NextProtoTLS, res.alpn)
	}
	if !bytes.Equal(res.body, want) {
		gotSum := sha256.Sum256(res.body)
		wantSum := sha256.Sum256(want)
		t.Fatalf("%s: body mismatch: got %d bytes sha256=%x, want %d bytes sha256=%x",
			label, len(res.body), gotSum[:8], len(want), wantSum[:8])
	}
	sum := sha256.Sum256(res.body)
	t.Logf("h2 body verified over %s: %d bytes sha256=%x alpn=%s proto=%s", label, len(res.body), sum[:8], res.alpn, res.proto)
}

// flowChoice reports the egress decision the direct egress manager recorded for
// a peer's flow to dst. Reading the recorded decision instead of a byte counter
// keeps the check exact: an unrelated packet arriving late cannot satisfy or
// break it.
func (fx *h2Fixture) flowChoice(peerKey string, dst netip.AddrPort) (EgressChoice, bool) {
	fx.dem.mu.RLock()
	defer fx.dem.mu.RUnlock()
	for key, entry := range fx.dem.flows {
		if key.PeerKey != peerKey || key.DstPort != dst.Port() {
			continue
		}
		if netip.AddrFrom4(key.DstIP) != dst.Addr() {
			continue
		}
		return entry.choice, true
	}
	return EgressChoiceNone, false
}

// TestLinuxE2E_HTTP2OnlyEgress proves an HTTP/2-only origin stays reachable
// through the DIRECT and PROXY paths with policy routing enabled, and that the
// constrained path succeeds only when the MSS clamp is applied.
func TestLinuxE2E_HTTP2OnlyEgress(t *testing.T) {
	if !checkLinuxCapabilities(t) {
		return
	}
	fx := newH2EgressFixture(t)
	directDst := netip.MustParseAddrPort(h2DirectOriginAddr)
	proxyDst := netip.AddrPortFrom(netip.MustParseAddr(h2ProxyOriginIP), h2ProxyOriginPort)

	t.Run("DirectPath_ServesHTTP2OnlyOriginBody", func(t *testing.T) { fx.caseDirect(t, directDst) })
	t.Run("ProxiedPath_ServesHTTP2OnlyOriginBody", func(t *testing.T) { fx.caseProxied(t, proxyDst) })
	t.Run("HTTP11OnlyClient_RefusedByHTTP2OnlyOrigin", func(t *testing.T) { fx.caseHTTP11Refused(t, directDst) })
	t.Run("ConstrainedMTU_WithMSSClamp_ServesBody", func(t *testing.T) { fx.caseConstrainedClamped(t, directDst) })
	t.Run("ConstrainedMTU_WithoutMSSClamp_Fails", func(t *testing.T) { fx.caseConstrainedUnclamped(t, directDst) })
}

// caseDirect proves the HTTP/2-only origin is reachable over DIRECT egress and
// the whole body arrives. This is the behaviour the owner asked to keep.
func (fx *h2Fixture) caseDirect(t *testing.T, dst netip.AddrPort) {
	fx.wan.setClamp(0)
	directBefore := fx.dem.DirectBytes()
	proxyBefore := fx.proxyDev.packets.Load()
	s := fx.startSession(t, "peer-h2-direct", "sess-h2-direct", "10.100.0.30", h2CorrectClientMTU, dst.Addr(), policy.Direct)

	res := s.exchange(t.Context(), dst, h2PositiveTimeout)
	assertBodyEquality(t, res, fx.body, "DIRECT")

	if delta := fx.dem.DirectBytes() - directBefore; delta <= 0 {
		t.Fatalf("expected direct egress to carry the exchange, directBytes delta = %d", delta)
	}
	if choice, ok := fx.flowChoice(s.peerKey, dst); !ok || choice != EgressChoiceDirect {
		t.Fatalf("expected a recorded DIRECT flow decision for %v, got %v (recorded=%t)", dst, choice, ok)
	}
	if delta := fx.proxyDev.packets.Load() - proxyBefore; delta != 0 {
		t.Fatalf("expected no proxy backend packet for a DIRECT flow, got %d", delta)
	}
	if fx.fwd.ProxyDrops() != 0 {
		t.Fatalf("expected no proxy drops, got %d", fx.fwd.ProxyDrops())
	}
	delivered, oversized, maxPacket, _ := s.returns.stats()
	t.Logf("DIRECT: %d return packets delivered to the peer, %d oversized, largest %d bytes (session send errors %d)",
		delivered, oversized, maxPacket, s.client.sendErrs.Load())
}

// caseProxied proves the same exchange succeeds over PROXY egress. The proxied
// destination exists only inside the proxy backend's packet stack, so a
// delivered body proves the traversal; the recorded flow decision must be PROXY.
func (fx *h2Fixture) caseProxied(t *testing.T, dst netip.AddrPort) {
	fx.wan.setClamp(0)
	proxyBefore := fx.proxyDev.packets.Load()
	s := fx.startSession(t, "peer-h2-proxy", "sess-h2-proxy", "10.100.0.31", h2CorrectClientMTU, dst.Addr(), policy.Proxy)

	res := s.exchange(t.Context(), dst, h2PositiveTimeout)
	assertBodyEquality(t, res, fx.body, "PROXY")

	if delta := fx.proxyDev.packets.Load() - proxyBefore; delta <= 0 {
		t.Fatalf("expected the proxy backend to carry the exchange, packet delta = %d", delta)
	}
	if choice, ok := fx.flowChoice(s.peerKey, dst); !ok || choice != EgressChoiceProxy {
		t.Fatalf("expected a recorded PROXY flow decision for %v, got %v (recorded=%t)", dst, choice, ok)
	}
	if fx.fwd.ProxyDrops() != 0 {
		t.Fatalf("expected no proxy drops, got %d", fx.fwd.ProxyDrops())
	}
	t.Logf("PROXY: %d backend packets carried the exchange", fx.proxyDev.packets.Load()-proxyBefore)
}

// caseHTTP11Refused is the negative control for the origin's own protocol
// restriction: an http/1.1-only client cannot be served, so cases 1 and 2 really
// exercise HTTP/2. Go's TLS server deliberately lets an http/1.1-only client
// connect to an h2-only server with no negotiated protocol (Go issue 46310), so
// the refusal is observed at the HTTP layer when the handshake completes.
func (fx *h2Fixture) caseHTTP11Refused(t *testing.T, dst netip.AddrPort) {
	fx.wan.setClamp(0)
	s := fx.startSession(t, "peer-h2-h1", "sess-h2-h1", "10.100.0.32", h2CorrectClientMTU, dst.Addr(), policy.Direct)

	ctx, cancel := context.WithTimeout(t.Context(), h2NegativeTimeout)
	defer cancel()
	conn, err := s.client.dialTLS(ctx, dst, &tls.Config{
		RootCAs:    fx.pool,
		ServerName: h2OriginServerName,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Logf("red-before: http/1.1-only ALPN offer refused by the h2-only origin during the handshake: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("expected a TLS connection, got %T", conn)
	}
	if negotiated := tlsConn.ConnectionState().NegotiatedProtocol; negotiated == http2.NextProtoTLS {
		t.Fatalf("expected no h2 negotiation for an http/1.1-only client, got %q", negotiated)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", h2OriginPath, h2OriginServerName); err != nil {
		t.Logf("red-before: http/1.1 request refused by the h2-only origin: %v", err)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Logf("red-before: http/1.1 request refused by the h2-only origin: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusHTTPVersionNotSupported {
		t.Fatalf("expected the h2-only origin to refuse an http/1.1 request with status %d, got %d (%q)",
			http.StatusHTTPVersionNotSupported, resp.StatusCode, string(body))
	}
	t.Logf("red-before: http/1.1 request refused by the h2-only origin: status %d, ALPN %q", resp.StatusCode, tlsConn.ConnectionState().NegotiatedProtocol)
}

// caseConstrainedClamped is the production configuration: a 1420 client would
// advertise MSS 1380, and the clamp rewrites it to 1240 so every segment fits
// the 1280 path and the full body arrives.
func (fx *h2Fixture) caseConstrainedClamped(t *testing.T, dst netip.AddrPort) {
	fx.wan.setClamp(h2ClampedMSS)
	s := fx.startSession(t, "peer-h2-clamped", "sess-h2-clamped", "10.100.0.33", h2LegacyClientMTU, dst.Addr(), policy.Direct)

	res := s.exchange(t.Context(), dst, h2PositiveTimeout)
	assertBodyEquality(t, res, fx.body, "DIRECT+MSS clamp")

	observed, rewrites := fx.wan.stats()
	if observed != h2LegacyClientMTU-40 {
		t.Fatalf("expected the client to announce MSS %d from its %d-byte MTU, got %d",
			h2LegacyClientMTU-40, h2LegacyClientMTU, observed)
	}
	if rewrites == 0 {
		t.Fatalf("expected the MSS clamp to rewrite the client SYN, got 0 rewrites")
	}
	_, oversized, _, _ := s.returns.stats()
	if oversized != 0 {
		t.Fatalf("expected no oversized return packet with the clamp applied, got %d", oversized)
	}
	t.Logf("DIRECT+MSS clamp: announced MSS %d clamped to %d (%d rewrite(s)), %d oversized returns",
		observed, h2ClampedMSS, rewrites, oversized)
}

// caseConstrainedUnclamped is the negative control for the clamp: the same
// constrained exchange must fail, and the failure must be the oversized segments
// the path cannot carry. This is the regression the clamp prevents.
func (fx *h2Fixture) caseConstrainedUnclamped(t *testing.T, dst netip.AddrPort) {
	fx.wan.setClamp(0)
	s := fx.startSession(t, "peer-h2-unclamped", "sess-h2-unclamped", "10.100.0.34", h2LegacyClientMTU, dst.Addr(), policy.Direct)

	res := s.exchange(t.Context(), dst, h2NegativeTimeout)
	if res.err == nil && bytes.Equal(res.body, fx.body) {
		t.Fatalf("expected the HTTP/2 exchange to fail without the MSS clamp on a %d-byte path, but the whole body arrived", h2PathMTU)
	}
	observed, rewrites := fx.wan.stats()
	if observed != h2LegacyClientMTU-40 {
		t.Fatalf("expected the client to announce MSS %d from its %d-byte MTU, got %d",
			h2LegacyClientMTU-40, h2LegacyClientMTU, observed)
	}
	if rewrites != 0 {
		t.Fatalf("expected no MSS rewrite without the clamp, got %d", rewrites)
	}
	_, oversized, _, oversizedMax := s.returns.stats()
	if oversized == 0 {
		t.Fatalf("expected oversized return segments to be undeliverable on the %d-byte path, got none", h2PathMTU)
	}
	t.Logf("red-before: HTTP/2 exchange failed without the MSS clamp (client MSS %d, path MTU %d): %v; %d oversized return segments (largest %d bytes) could not be delivered",
		observed, h2PathMTU, res.err, oversized, oversizedMax)
}
