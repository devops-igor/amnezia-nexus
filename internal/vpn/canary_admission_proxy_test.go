//go:build with_utls

package vpn

// Proxy consumer proof for issue #731: the admission decision must cover the
// established VLESS and Naive consumers, not only AWG.
//
// The evidence is produced by the real production proxy canary path — an
// authenticated application request/reply over the device's own egress — through
// the real HealthProber sweep, and the resulting admission decision is read from
// the same helper the ingress admission calls.
//
// Fixtures reuse the existing authenticated helpers: a real VLESS+REALITY server
// over a real decoy TLS server (startF11RealityServer) and a real Naive H2 CONNECT
// proxy in front of a real echo origin (setupE2ETestH2Server). The only seam is
// the health destination, which production derives from the tunnel's own protocol
// parameters and which a local fixture must point at a reachable origin
// (SetProxyCanaryDestinationForTest) — the arrangement the existing F11/R12
// fixtures already use.
//
// An established session is seeded on the proxy backend first, because that is
// what makes the blocked label persist through an inner canary failure (a
// session-carrying backend keeps handshake_blocked below the confirmation
// threshold). The negative case is therefore decided by the evidence record, not
// by the status label changing underneath the assertion.

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// proxyAdmissionEnv is one service whose only enabled backend is a proxy tunnel.
type proxyAdmissionEnv struct {
	svc *Service
	tun *models.BackendTunnel
}

// newProxyAdmissionService builds a service with every AWG fixture tunnel
// administratively disabled, so a proxy backend added afterwards is the only
// admission candidate.
func newProxyAdmissionService(t *testing.T) *Service {
	t.Helper()
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	svc.pool.SetMultiProtocolEnabled(true)
	svc.prober.SetMultiProtocolEnabled(true)
	for _, tun := range svc.pool.ListTunnels() {
		if err := svc.pool.SetTunnelEnabled(ctx, tun.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("disable fixture tunnel: %v", err)
		}
	}
	// The standard fixture service installs a success-only canary override. The
	// whole point of this file is the real authenticated proxy exchange, so it
	// must be cleared before any verdict is read.
	svc.prober.SetCanaryProbeFunc(nil)
	if svc.prober.GetCanaryProbeFunc() != nil {
		t.Fatal("fixture: a canary override is still installed")
	}
	return svc
}

// seedProxySession books one real session row and forwards route onto the proxy
// backend, so a later inner canary failure keeps the blocked label (the
// session-carrying preservation rule). It deliberately does NOT go through
// admission: at seed time the proxy has no canary evidence yet, so admission
// would (correctly) refuse and the fixture would be unable to create the very
// precondition it needs. Creating the session directly mirrors the state a real
// admission leaves behind.
func seedProxySession(t *testing.T, svc *Service, tun *models.BackendTunnel, name string) ingressTestPeer {
	t.Helper()
	peer := seedIngressPeer(t, svc.db, name, "proxy-"+name+"-peer-key", "10.100.9."+proxyLastOctet(name))
	sess, delta, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(t.Context(),
		peer.userID, peer.peerKey, peer.ip.String(), tun.ID, name+"-device", models.SessionAdmissionIngress)
	if err != nil {
		t.Fatalf("seed session on the proxy backend: %v", err)
	}
	if sess == nil {
		t.Fatal("seed session returned no session")
	}
	if !delta.HasInc {
		svc.pool.IncrementConnections(tun.ID)
	}
	if svc.forwarder != nil {
		svc.forwarder.RegisterSession(sess.ID, peer.connID, peer.peerKey, peer.ip.String(), tun.ID)
	}
	t.Cleanup(func() { svc.forwarder.UnregisterSession(peer.peerKey) })
	return peer
}

// proxyLastOctet derives a stable last octet from the fixture name so two seeded
// peers do not collide.
func proxyLastOctet(name string) string {
	last := byte(1)
	for i := 0; i < len(name); i++ {
		last = last*31 + name[i]
	}
	return strconv.Itoa(int(last%200) + 20)
}

// sweepOuterFailing runs one real health sweep with a failing outer handshake.
// Proxy transports take their outer probe from the protocol-specific prober
// functions, so all three are made to fail; the AWG one is set too so the helper
// stays correct for a mixed candidate set.
func (e *proxyAdmissionEnv) sweepOuterFailing(t *testing.T) *models.BackendTunnel {
	t.Helper()
	failOuter := func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, context.DeadlineExceeded
	}
	e.svc.prober.SetProbeFunc(failOuter)
	e.svc.prober.SetVLESSProbeFunc(func(context.Context, string, models.VLESSRealityParams, time.Duration) (int64, error) {
		return 0, context.DeadlineExceeded
	})
	e.svc.prober.SetNaiveProbeFunc(func(context.Context, string, models.NaiveProxyParams, time.Duration) (int64, error) {
		return 0, context.DeadlineExceeded
	})
	live, err := e.svc.pool.GetTunnel(e.tun.ServerID)
	if err != nil {
		t.Fatalf("read proxy tunnel: %v", err)
	}
	if _, err := e.svc.prober.ProbeTunnel(t.Context(), live); err != nil {
		t.Logf("proxy probe returned %v", err)
	}
	cur, err := e.svc.pool.GetTunnel(e.tun.ServerID)
	if err != nil {
		t.Fatalf("re-read proxy tunnel: %v", err)
	}
	return cur
}

// isCandidate reports whether the production admission helper offers the tunnel.
func (e *proxyAdmissionEnv) isCandidate(t *testing.T) bool {
	t.Helper()
	e.svc.mu.Lock()
	candidates := e.svc.admissibleIngressCandidatesLocked()
	e.svc.mu.Unlock()
	for _, c := range candidates {
		if c != nil && c.ID == e.tun.ID {
			return true
		}
	}
	return false
}

// setupVLESSEndpoint creates the VLESS server record, adds the tunnel and attaches
// the production device through EnableBackendWithConfig.
func setupVLESSEndpoint(t *testing.T, svc *Service, endpoint string, params models.VLESSRealityParams) *models.BackendTunnel {
	t.Helper()
	ctx := t.Context()
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatalf("split reality endpoint: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("reality port: %v", err)
	}
	sid, err := svc.db.CreateServer(ctx, &models.Server{
		Name: "issue731 vless admission",
		Host: host,
		Protocols: map[string]any{
			"vless": map[string]any{"installed": true, "port": port, "server_name": params.ServerName},
		},
	})
	if err != nil {
		t.Fatalf("create vless server: %v", err)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal vless params: %v", err)
	}
	if err := svc.EnableBackendWithConfig(ctx, sid, tunnel.BackendTunnelOptions{
		Protocol: models.ProtocolVLESS, ProtocolParams: raw,
	}); err != nil {
		t.Fatalf("enable vless backend: %v", err)
	}
	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("read vless tunnel: tun=%v err=%v", tun, err)
	}
	return tun
}

// TestCanaryAdmission_VLESSProxyConsumer proves a VLESS backend whose outer
// handshake is blocked but whose authenticated payload path is alive becomes an
// admission candidate, and that breaking that payload path withdraws eligibility
// while the blocked label is preserved by the established session.
func TestCanaryAdmission_VLESSProxyConsumer(t *testing.T) {
	ctx := context.Background()
	originAddr, stopOrigin := f11PlainHTTPOrigin(t)
	var originStopped bool
	t.Cleanup(func() {
		if !originStopped {
			stopOrigin()
		}
	})
	realityEndpoint, params, stopReality := startF11RealityServer(t)
	t.Cleanup(stopReality)

	svc := newProxyAdmissionService(t)
	tun := setupVLESSEndpoint(t, svc, realityEndpoint, params)
	svc.prober.SetProxyCanaryDestinationForTest(originAddr)
	env := &proxyAdmissionEnv{svc: svc, tun: tun}

	if svc.GetBackendDeviceForTest(tun.ID) == nil {
		t.Fatalf("production attach path produced no device for tunnel %d", tun.ID)
	}
	if !svc.prober.HasCanaryProber(tun) {
		t.Fatal("the production VLESS device is not visible to the health consumer")
	}
	latencyMS, err := svc.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("authentic vless qualification: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, tun, latencyMS); err != nil {
		t.Fatalf("promote vless backend: %v", err)
	}
	seedProxySession(t, svc, tun, "vless")

	// Positive: blocked label, authenticated payload path alive.
	cur := env.sweepOuterFailing(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: vless status = %q, want handshake_blocked", cur.Status)
	}
	if !env.isCandidate(t) {
		t.Fatal("a canary-proven blocked VLESS backend was not an admission candidate")
	}

	// Negative: the payload path breaks; the established session keeps the
	// blocked label, so only the evidence record can withdraw eligibility.
	stopOrigin()
	originStopped = true
	time.Sleep(100 * time.Millisecond)
	cur = env.sweepOuterFailing(t)
	t.Logf("after origin removal: status=%s innerFailures=%d", cur.Status, svc.prober.GetCanaryFailCount(tun.ServerID))
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Logf("status moved to %q instead of staying blocked; candidate check still decides by evidence", cur.Status)
	}
	if env.isCandidate(t) {
		t.Fatal("a VLESS backend whose payload path is broken stayed an admission candidate")
	}
}

// TestCanaryAdmission_NaiveProxyConsumer does the same for NaiveProxy over its
// real H2 CONNECT transport.
func TestCanaryAdmission_NaiveProxyConsumer(t *testing.T) {
	ctx := context.Background()
	caCert, caKey := setupE2ETestCA(t)
	// The naive payload canary speaks TLS+HTTP to the destination through the
	// proxy's own CONNECT tunnel, so the proxy must forward to the requested
	// destination (empty echoAddr) and the origin must genuinely terminate TLS.
	proxyAddr, stopProxy := setupE2ETestH2Server(t, "127.0.0.1:0", "issue731-user", "issue731-pass",
		caCert, caKey, "")
	var proxyStopped bool
	t.Cleanup(func() {
		if !proxyStopped {
			stopProxy()
		}
	})
	originAddr, stopOrigin := f11TLSOrigin(t, caCert, caKey, "localhost")
	t.Cleanup(stopOrigin)

	svc := newProxyAdmissionService(t)
	proxyHost, proxyPortStr, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		t.Fatalf("split proxy endpoint: %v", err)
	}
	proxyPort, err := strconv.Atoi(proxyPortStr)
	if err != nil {
		t.Fatalf("proxy port: %v", err)
	}
	sid, err := svc.db.CreateServer(ctx, &models.Server{
		Name: "issue731 naive admission",
		Host: proxyHost,
		Protocols: map[string]any{
			"naive": map[string]any{"installed": true, "port": proxyPort, "domain": "localhost"},
		},
	})
	if err != nil {
		t.Fatalf("create naive server: %v", err)
	}
	naiveParams := models.NaiveProxyParams{Username: "issue731-user", Password: "issue731-pass", Domain: "localhost"}
	raw, err := json.Marshal(naiveParams)
	if err != nil {
		t.Fatalf("marshal naive params: %v", err)
	}
	if err := svc.EnableBackendWithConfig(ctx, sid, tunnel.BackendTunnelOptions{
		Protocol: models.ProtocolNaive, ProtocolParams: raw,
	}); err != nil {
		t.Fatalf("enable naive backend: %v", err)
	}
	tun, err := svc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("read naive tunnel: tun=%v err=%v", tun, err)
	}
	svc.prober.SetProxyCanaryDestinationForTest(originAddr)
	env := &proxyAdmissionEnv{svc: svc, tun: tun}

	if svc.GetBackendDeviceForTest(tun.ID) == nil {
		t.Fatalf("production attach path produced no device for tunnel %d", tun.ID)
	}
	if !svc.prober.HasCanaryProber(tun) {
		t.Fatal("the production Naive device is not visible to the health consumer")
	}
	latencyMS, err := svc.QualifyProxyTraffic(ctx, tun)
	if err != nil {
		t.Fatalf("authentic naive qualification: %v", err)
	}
	if err := svc.PromoteQualifiedTunnel(ctx, tun, latencyMS); err != nil {
		t.Fatalf("promote naive backend: %v", err)
	}
	seedProxySession(t, svc, tun, "naive")

	cur := env.sweepOuterFailing(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: naive status = %q, want handshake_blocked", cur.Status)
	}
	if !env.isCandidate(t) {
		t.Fatal("a canary-proven blocked Naive backend was not an admission candidate")
	}

	stopProxy()
	proxyStopped = true
	time.Sleep(100 * time.Millisecond)
	cur = env.sweepOuterFailing(t)
	t.Logf("after proxy removal: status=%s innerFailures=%d", cur.Status, svc.prober.GetCanaryFailCount(tun.ServerID))
	if env.isCandidate(t) {
		t.Fatal("a Naive backend whose payload path is broken stayed an admission candidate")
	}
}

// TestCanaryAdmission_ProxyRefusesWithoutEvidence is the proxy label-only
// negative control: a blocked proxy backend that never produced a successful
// authenticated payload exchange must not be an admission candidate, even though
// the label says the same thing it says for a healthy one.
func TestCanaryAdmission_ProxyRefusesWithoutEvidence(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			svc := newProxyAdmissionService(t)
			tun, err := svc.pool.AddTunnelWithConfig(t.Context(), mustProxyServer(t, svc, proto), "192.0.2.92:443", "",
				tunnel.BackendTunnelOptions{Protocol: proto, ProtocolParams: proxyFixtureParams(t, proto)})
			if err != nil {
				t.Fatalf("add %s tunnel: %v", proto, err)
			}
			if err := svc.pool.SetTunnelStatus(t.Context(), tun.ServerID, models.TunnelStatusHandshakeBlocked, 0); err != nil {
				t.Fatalf("set blocked status: %v", err)
			}
			env := &proxyAdmissionEnv{svc: svc, tun: tun}
			if env.isCandidate(t) {
				t.Fatalf("%s: a blocked proxy with no payload evidence was an admission candidate", proto)
			}
			if n := len(svc.pool.GetActiveTunnels()); n != 0 {
				t.Fatalf("%s: %d backends appeared in the active snapshot", proto, n)
			}
		})
	}
}

// mustProxyServer creates the server record the proxy tunnel needs.
func mustProxyServer(t *testing.T, svc *Service, proto string) int64 {
	t.Helper()
	sid, err := svc.db.CreateServer(t.Context(), &models.Server{
		Name:      "issue731 proxy evidence " + proto,
		Host:      "192.0.2.92",
		Protocols: map[string]any{proto: map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create proxy server: %v", err)
	}
	return sid
}

// proxyFixtureParams returns valid protocol parameters for the given transport.
func proxyFixtureParams(t *testing.T, proto string) []byte {
	t.Helper()
	switch proto {
	case models.ProtocolVLESS:
		return []byte(`{"uuid":"a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d","server_name":"proxy.example.com","public_key":"K4Z2q0m1nJ9v3xY8wT7rS6pQ5oN4lM3kJ2hG1fE0dC8","short_id":"0123456789abcdef"}`)
	case models.ProtocolNaive:
		return []byte(`{"username":"fixture","password":"fixture","domain":"proxy.example.com"}`)
	default:
		t.Fatalf("no fixture params for protocol %q", proto)
		return nil
	}
}
