package vpn

// Issue #390 part 2 lifecycle E2E: the issue's acceptance proof, built on
// the engine_return_e2e_test.go pattern (real engine, real clientawg portal
// device, real upstream clients, bidirectional application flows).
//
// TestUpstreamPeerLifecycleReapAndReadmissionE2E drives the FULL cycle
// through the REAL reap loop ticker (short cadence via the engine's
// reapIdleTimeoutFn and reapInterval test seams — never a 3-minute wait):
// configured peer → traffic → backend session → busy session survives the
// threshold → idle reap → peer STILL configured → same running client's
// traffic re-admits it. The engine is built MANUALLY instead of via
// startEngine: startEngine starts the engine, and both reap seams are read
// once when the reap loop launches (never written after Start), so the
// assignments must sit between construction and Start.
//
// TestUpstreamPeerSurvivesServiceRestart proves restart reconstruction: with
// stale vpn_sessions rows (simulating a previous process) a fresh
// Service + IngressEngine built from the same DB invalidates the old rows,
// reconstructs the configured peer from durable state, and serves traffic —
// peer availability is independent of vpn_sessions. The fresh service pins
// the SAME ListenPort/PublicEndpoint identity through the reload path
// (UpdateConfig -> SaveVPNConfig -> GetVPNConfig) and never runs the legacy
// listener: the started portal owns that UDP port and a second bind
// (StdNetBind.Open) would fail EADDRINUSE.
//
// Spec-scoped assertions (do not over-extend): peer identity = public key +
// durable assigned_ip lease + portal peer state + resolver record; config
// non-regeneration = the same rendered client config reconnects unchanged,
// the portal never drops or re-adds the peer, and exactly one new session
// registration happens across the reap → re-admit cycle.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// engineLifecyclePeer bundles one configured upstream peer's identity
// surfaces the lifecycle assertions compare across reap/re-admit/restart.
type engineLifecyclePeer struct {
	enginePeer         // private/public key + durable assigned_ip
	savedConfig string // the rendered client config (identity witness)
}

// startLifecycleEchoBackend attaches a real netstack TUN to one backend as
// its backend device (the returnStreamClient shape), pumps its returns
// through the production backend-return path, and serves TCP+UDP echo
// servers on port 40001. Returns the destination address the client dials.
func startLifecycleEchoBackend(t *testing.T, svc *Service, backend *models.BackendTunnel, marker byte) netip.Addr {
	t.Helper()
	destination := netip.MustParseAddr("198.51.100.77")
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{destination}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &returnStackDevice{tun: vt}
	done := make(chan struct{})
	svc.forwarder.AttachBackendDevice(backend.ID, adapter)
	go func() { defer close(done); svc.pumpBackendReturns(backend.ID, backend.ServerID, adapter) }()
	t.Cleanup(func() { _ = adapter.Close(); <-done })
	returnEchoServers(t, stack, destination, marker)
	return destination
}

// lifecycleClient is one running upstream client device with live TCP and
// UDP connections to the echo backend; the SAME instance must survive the
// reap (spec: "same running client sends traffic again").
type lifecycleClient struct {
	uc       *returnStreamClient
	dest     netip.Addr
	marker   byte
	sequence uint32
}

// startLifecycleClient builds the real upstream engine from the rendered
// config and dials the echo backend's TCP+UDP endpoints through the tunnel.
// The dial's admission is NOT awaited here — callers drive it explicitly.
func startLifecycleClient(t *testing.T, peer engineLifecyclePeer, dest netip.Addr, marker byte) *lifecycleClient {
	t.Helper()
	client := newReturnStreamClient(t, peer.enginePeer, peer.savedConfig, dest, marker)
	return &lifecycleClient{uc: client, dest: dest, marker: marker}
}

// sendAwait pushes one marked application exchange through the SAME running
// client: a TCP write/read round trip plus one UDP echo, both byte-checked.
func (c *lifecycleClient) sendAwait(t *testing.T, seq uint32) {
	t.Helper()
	c.sequence = seq
	payload := []byte(fmt.Sprintf("lifecycle-seq-%08d", seq))
	returnExchange(t, c.uc.tcp, payload, false, c.marker)
	returnExchange(t, c.uc.udp, payload, true, c.marker)
}

// startDatagramOnlyClient builds a second real upstream engine from the same
// rendered config WITHOUT dialing TCP — the lifecycle echo backend serves
// exactly one TCP connection, which the still-running original client holds,
// so a second TCP dial would deadlock until the dial deadline. Returns the
// fresh engine's UDP connection into the tunnel (the reconnect proof surface).
func startDatagramOnlyClient(t *testing.T, peer enginePeer, saved string, destination netip.Addr) net.Conn {
	t.Helper()
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(peer.assignedIP)}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "datagram-client"))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(configToUAPI(t, saved)); err != nil {
		t.Fatal("client configuration rejected")
	}
	if err := dev.IpcSet("rekey_after_time=2\nrekey_timeout=1\n"); err != nil {
		t.Fatal("test timing configuration rejected")
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	udpConn, err := stack.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(destination, 40001))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })
	return udpConn
}

// verifySameConfigStillValid proves config non-regeneration at the protocol
// level: a SECOND real engine configured from the ORIGINAL rendered config
// string completes a fresh handshake and completes a UDP echo exchange
// through the echo backend — the config was never regenerated or invalidated
// (identity is key-based, lease-stable, not session-bound). UDP has no
// single-accept limit, unlike the echo backend's one TCP connection.
func (c *lifecycleClient) verifySameConfigStillValid(t *testing.T, peer engineLifecyclePeer) {
	t.Helper()
	udp := startDatagramOnlyClient(t, peer.enginePeer, peer.savedConfig, c.dest)
	deadline := time.Now().Add(10 * time.Second)
	payload := []byte("same-config-probe")
	want := append([]byte{c.marker}, payload...)
	buf := make([]byte, len(want))
	for {
		_ = udp.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := udp.Write(payload); err != nil {
			t.Fatalf("application write: %v", err)
		}
		n, err := udp.Read(buf)
		if err == nil && n == len(want) && bytes.Equal(buf, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("verifySameConfigStillValid failed within 10s: n=%d err=%v match=%v", n, err, bytes.Equal(buf, want))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitBackendGaugeEqual polls until the backend's active-connection gauge
// reaches want (the gauge moves under s.mu; the test thread can observe it
// slightly late).
func waitBackendGaugeEqual(t *testing.T, svc *Service, backendID int64, want int, why string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		tun, err := svc.pool.GetTunnelByID(backendID)
		if err != nil {
			t.Fatal(err)
		}
		if tun.ActiveConnections == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: backend %d gauge = %d, want %d", why, backendID, tun.ActiveConnections, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// portalPeerStatus returns the portal's PeerStatus for the peer key, failing
// if the peer is absent — the "STILL configured" surface.
func portalPeerStatus(t *testing.T, engine *IngressEngine, peerKey string) clientawg.PeerStatus {
	t.Helper()
	status, err := engine.Portal().Status()
	if err != nil {
		t.Fatalf("portal status: %v", err)
	}
	for _, p := range status.Peers {
		if p.PublicKey == peerKey {
			return p
		}
	}
	t.Fatalf("portal no longer has peer %s configured (peers=%d)", peerKey, len(status.Peers))
	return clientawg.PeerStatus{}
}

// portalPeerStatusPeers returns the portal's full configured peer list.
func portalPeerStatusPeers(t *testing.T, engine *IngressEngine) []clientawg.PeerStatus {
	t.Helper()
	status, err := engine.Portal().Status()
	if err != nil {
		t.Fatalf("portal status: %v", err)
	}
	return status.Peers
}

// portalGuardDevice is a no-op stand-in that occupies one slot of the
// service's backendDevices map. With the slot filled,
// ensureBackendDeviceAttached — reachable through the health prober's
// on-active hook and the startup device restore — returns early instead of
// building a real backend AWG device, which would hijack the forwarder slot
// a test's echo adapter owns. The forwarder-side slot stays untouched; this
// guard only covers the service-side map. It carries no data plane: reads
// return EOF and writes succeed discarding.
type portalGuardDevice struct{}

func (portalGuardDevice) Read(p []byte) (int, error)   { return 0, io.EOF }
func (portalGuardDevice) Write(p []byte) (int, error)  { return len(p), nil }
func (portalGuardDevice) Close() error                 { return nil }
func (portalGuardDevice) LastHandshakeTime() time.Time { return time.Time{} }
func (portalGuardDevice) CreatedAt() time.Time         { return time.Time{} }
func (portalGuardDevice) DroppedPackets() uint64       { return 0 }
func (portalGuardDevice) IsClosed() bool               { return false }

// TestUpstreamIdleReapDefaultThreshold pins the production default: an
// engine with the seam unset sweeps at the 3-minute constant — the default
// behavior MUST stay exactly 3m (spec required-work item 1).
func TestUpstreamIdleReapDefaultThreshold(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	engine, err := svc.NewIngressEngine(t.Context(), "reap-default-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	if got := engine.reapIdleTimeout(); got != 3*time.Minute {
		t.Fatalf("default reap idle threshold = %s, want exactly 3m", got)
	}
	if got := reapLoopIdleTimeout(svc); got != 3*time.Minute {
		t.Fatalf("reapLoopIdleTimeout = %s, want exactly 3m", got)
	}
}

// TestUpstreamIdleReapShortenedThresholdSeam pins the seam itself: an engine
// with reapIdleTimeoutFn assigned sweeps at the override, per engine, while
// the production constant stays untouched.
func TestUpstreamIdleReapShortenedThresholdSeam(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	engine, err := svc.NewIngressEngine(t.Context(), "reap-seam-portal", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	engine.reapIdleTimeoutFn = func(*Service) time.Duration { return 50 * time.Millisecond }
	if got := engine.reapIdleTimeout(); got != 50*time.Millisecond {
		t.Fatalf("overridden reap idle threshold = %s, want 50ms", got)
	}
	if got := reapLoopIdleTimeout(svc); got != 3*time.Minute {
		t.Fatalf("production constant changed by the override: %s, want 3m", got)
	}
}

// TestUpstreamPeerLifecycleReapAndReadmissionE2E is the issue #390
// acceptance proof. Chain: durable connection → configured upstream peer →
// real engine + real client device with matching identity. Traffic admits a
// backend session; the REAL reap loop retires it idle; the SAME running
// client's next packet lazily re-admits it — with the peer's identity
// (public key, durable lease, portal state, resolver record) unchanged
// throughout, no config regeneration, and the backend gauge decremented
// exactly once by the reap.
func TestUpstreamPeerLifecycleReapAndReadmissionE2E(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	lcPeer, saved := newEnginePeer(t, svc, db, "lifecycle-alice")
	lc := engineLifecyclePeer{enginePeer: lcPeer, savedConfig: saved}
	ip := netip.MustParseAddr(lc.assignedIP)

	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	sort.Slice(backends, func(i, j int) bool { return backends[i].ID < backends[j].ID })
	if len(backends) == 0 {
		t.Fatal("no active backends")
	}
	destination := startLifecycleEchoBackend(t, svc, backends[0], 0x3A)
	// The client->backend queue path needs the forwarder pumps running for
	// delivery (same shape as the return E2E and queue-observability tests).
	svc.forwarder.StartPumps(t.Context())
	t.Cleanup(svc.forwarder.StopPumps)

	// Build the engine MANUALLY instead of via startEngine: startEngine
	// starts the engine, and both reap seams are read once when the reap
	// loop launches — they are never written after Start. Same wiring as
	// startEngine, with the seam assignments inserted before Start.
	engine, err := svc.NewIngressEngine(t.Context(), "lifecycle-portal", []clientawg.Peer{
		{PublicKey: lc.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	// Issue the REAL reap loop its short idle threshold and 50ms cadence:
	// the ticker must be the component that performs the reap (spec: at
	// least one test drives the actual reapLoop, not a direct sweepOnce).
	var currentReapTimeout atomic.Int64
	currentReapTimeout.Store(int64(3 * time.Minute))
	engine.reapIdleTimeoutFn = func(*Service) time.Duration { return time.Duration(currentReapTimeout.Load()) }
	engine.reapInterval = 50 * time.Millisecond
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}

	client := startLifecycleClient(t, lc, destination, 0x3A)

	// ---- Phase 1: first traffic admits a backend session ----
	client.sendAwait(t, 1)
	sess1, ok := waitForSession(t, svc, lc.publicKey)
	if !ok {
		t.Fatal("first traffic never admitted a backend session")
	}
	if sess1.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("session AdmittedVia = %q, want ingress", sess1.AdmittedVia)
	}
	if sess1.AssignedIP != lc.assignedIP {
		t.Fatalf("session IP %q, want durable lease %q", sess1.AssignedIP, lc.assignedIP)
	}
	if route1 := svc.forwarder.RouteSessionID(lc.publicKey); route1 != sess1.ID {
		t.Fatalf("route %q, want admitted session %q", route1, sess1.ID)
	}
	backendID := sess1.BackendTunnelID
	waitBackendGaugeEqual(t, svc, backendID, 1, "after first admission")
	resolverBefore, ok := engine.Resolver().Lookup(ip)
	if !ok || resolverBefore.PeerPublicKey != lc.publicKey || resolverBefore.ConnectionID == "" {
		t.Fatalf("resolver record before reap: %+v ok=%v", resolverBefore, ok)
	}
	registrationsAfterAdmission := svc.freshSessionRegistrations.Load()

	// Keep application traffic flowing past the idle threshold to prove
	// liveness refresh keeps a busy session out of the reaper, then go
	// idle. Traffic-driven liveness is throttled to one refresh per
	// TouchSessionThrottleSeconds (2s) — coarser than this test's 150ms
	// threshold — so the busy phase drives SessionManager.TouchSession
	// directly, the way a real sub-2s traffic cadence reaches it.
	currentReapTimeout.Store(int64(150 * time.Millisecond))
	busyDeadline := time.Now().Add(300 * time.Millisecond) // > idle threshold + margin
	for time.Now().Before(busyDeadline) {
		svc.sessionMgr.TouchSession(lc.publicKey)
		time.Sleep(25 * time.Millisecond)
	}
	if live, ok := svc.sessionMgr.GetSessionSnapshotByPeer(lc.publicKey); !ok || live.ID != sess1.ID {
		t.Fatalf("idle threshold elapsed while touching the busy session, yet session changed: %+v ok=%v", live, ok)
	}

	// ---- Phase 2: go idle; the REAL reap loop retires the session ----
	reapDeadline := time.Now().Add(15 * time.Second)
	for {
		if _, exists := svc.sessionMgr.GetSessionSnapshotByPeer(lc.publicKey); !exists {
			break
		}
		if time.Now().After(reapDeadline) {
			t.Fatalf("reap loop never retired the idle session (session=%s route=%q)", sess1.ID, svc.forwarder.RouteSessionID(lc.publicKey))
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := svc.forwarder.RouteSessionID(lc.publicKey); got != "" {
		t.Fatalf("forwarder route survived the reap: %q", got)
	}
	waitBackendGaugeEqual(t, svc, backendID, 0, "after reap")
	if row, err := db.GetVPNSessionByPeerKey(t.Context(), lc.publicKey); err != nil || row != nil {
		t.Fatalf("persisted session row survived the reap: row=%+v err=%v", row, err)
	}

	// Peer STILL configured: portal state (public key + /32) unchanged, the
	// durable connection unchanged, the resolver record unchanged.
	peerStatus := portalPeerStatus(t, engine, lc.publicKey)
	if peerStatus.AllowedIP != netip.PrefixFrom(ip, 32) {
		t.Fatalf("portal peer AllowedIP changed: %v", peerStatus.AllowedIP)
	}
	connAfterReap, err := db.GetConnectionByClientID(t.Context(), lc.publicKey, 0)
	if err != nil || connAfterReap == nil {
		t.Fatalf("durable connection vanished at reap: %v", err)
	}
	if got := connAfterReap.ClientParams["assigned_ip"]; got != lc.assignedIP {
		t.Fatalf("durable lease changed at reap: %v, want %q", got, lc.assignedIP)
	}
	resolverAfterReap, ok := engine.Resolver().Lookup(ip)
	if !ok || resolverAfterReap != resolverBefore {
		t.Fatalf("resolver record changed at reap: %+v -> %+v", resolverBefore, resolverAfterReap)
	}
	if gen := svc.PeerGeneration(lc.publicKey); gen != 0 {
		t.Fatalf("reap advanced peerGenerations to %d, want 0", gen)
	}

	// Reset reap timeout to default before Phase 3 so the re-admitted session
	// is not prematurely reaped while assertions and probe exchange run.
	currentReapTimeout.Store(int64(3 * time.Minute))

	// ---- Phase 3: the SAME running client sends traffic again ----
	if peers := portalPeerStatusPeers(t, engine); len(peers) != 1 {
		t.Fatalf("portal peer count changed across the cycle: %d", len(peers))
	}
	client.sendAwait(t, 3)
	sess2, ok := waitForSession(t, svc, lc.publicKey)
	if !ok {
		t.Fatal("post-reap traffic never re-admitted the peer")
	}
	if sess2.ID == sess1.ID {
		t.Fatal("re-admission reused the reaped session ID — the reap did not run")
	}
	if got := svc.forwarder.RouteSessionID(lc.publicKey); got != sess2.ID {
		t.Fatalf("post-reap route %q, want the new session %q", got, sess2.ID)
	}
	waitBackendGaugeEqual(t, svc, backendID, 1, "after re-admission")

	// NO peer re-creation, NO config regeneration: the same rendered config
	// still authenticates a fresh engine; the portal never dropped or
	// re-added the peer; the durable connection row is identical; the
	// resolver record is identical; exactly ONE new session registration
	// happened across the whole reap → re-admit cycle.
	if regDelta := svc.freshSessionRegistrations.Load() - registrationsAfterAdmission; regDelta != 1 {
		t.Fatalf("fresh registrations delta across reap/re-admit = %d, want exactly 1", regDelta)
	}
	connAfterReadmit, err := db.GetConnectionByClientID(t.Context(), lc.publicKey, 0)
	if err != nil || connAfterReadmit == nil || connAfterReadmit.ID != connAfterReap.ID ||
		connAfterReadmit.ClientParams["assigned_ip"] != lc.assignedIP {
		t.Fatalf("durable identity changed across re-admission: %+v vs %+v err=%v", connAfterReadmit, connAfterReap, err)
	}
	finalStatus := portalPeerStatus(t, engine, lc.publicKey)
	if finalStatus.AllowedIP != netip.PrefixFrom(ip, 32) || finalStatus.PublicKey != lc.publicKey {
		t.Fatalf("portal peer identity changed across re-admission: %+v", finalStatus)
	}
	resolverFinal, ok := engine.Resolver().Lookup(ip)
	if !ok || resolverFinal != resolverBefore {
		t.Fatalf("resolver record changed across re-admission: %+v -> %+v", resolverBefore, resolverFinal)
	}
	client.verifySameConfigStillValid(t, lc)
}

// TestUpstreamPeerSurvivesServiceRestart is the restart-reconstruction
// proof: stale vpn_sessions rows from a previous process must not affect
// peer availability. A fresh Service + fresh IngressEngine from the same DB
// (a) invalidates the old rows at Service.Start, (b) reconstructs the
// configured peer from durable state (clientawg.LoadConfig + LoadResolver —
// both DB-durable, independent of vpn_sessions), and (c) admits and serves
// the SAME client identity (unchanged rendered config) end to end.
//
// Port discipline: the fresh service pins the SAME ListenPort/PublicEndpoint
// the first service persisted (the reload path keeps them), and the legacy
// listener is shut down and detached BEFORE Start — the started portal owns
// that UDP port, and Listener.Start's StdNetBind.Open would fail EADDRINUSE
// against it. Prober discipline: the health prober is stopped before Start
// (Stop is idempotent; Service.Stop tolerates the double stop) — its
// on-active hook builds real backend devices into the forwarder slot this
// test attaches its echo adapter to, and the restore pass would mark the
// backend degraded; the test re-marks it active and guards the service-side
// device slot with portalGuardDevice.
func TestUpstreamPeerSurvivesServiceRestart(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)

	peer, saved := newEnginePeer(t, svc, db, "restart-bob")
	ip := netip.MustParseAddr(peer.assignedIP)

	// The in-memory pool starts empty; sync the durable tunnels exactly like
	// the lifecycle E2E does before touching pool state.
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	prevBackends := svc.pool.GetActiveTunnels()
	if len(prevBackends) == 0 {
		t.Fatal("no active backends")
	}
	prevBackend := prevBackends[0]
	prevBackendID := prevBackend.ID

	// Stale rows from the "previous process": one for the real peer, one
	// ghost row for a peer that exists nowhere else. The previous process
	// also leaves stale pool gauges in backend_tunnels.
	ghostPeer := "restart-ghost-peer-not-configured"
	// vpn_sessions.user_id is a users(id) FK: seed both stale rows under the
	// real peer's durable user (the ghost row's user identity is irrelevant —
	// restart invalidation removes both).
	peerConn, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0)
	if err != nil || peerConn == nil {
		t.Fatalf("durable connection for restart peer: %v", err)
	}
	for _, seed := range []struct {
		id     string
		key    string
		ip     string
		userID string
	}{
		{"stale-session-real", peer.publicKey, peer.assignedIP, peerConn.UserID},
		{"stale-session-ghost", ghostPeer, "10.100.6.199", peerConn.UserID},
	} {
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID: seed.id, BackendTunnelID: prevBackendID, UserID: seed.userID,
			PeerPublicKey: seed.key, AssignedIP: seed.ip, Status: "connected",
		}); err != nil {
			t.Fatalf("seed stale session %s: %v", seed.id, err)
		}
	}
	if err := db.UpdateBackendTunnel(ctx, prevBackendID, map[string]any{"active_connections": 3}); err != nil {
		t.Fatalf("seed stale gauge: %v", err)
	}
	staleBefore, err := db.GetActiveVPNSessions(ctx)
	if err != nil || len(staleBefore) != 2 {
		t.Fatalf("stale rows not seeded: %d rows, %v", len(staleBefore), err)
	}

	// ---- Fresh process: new Service + new engine from the SAME DB ----
	// Pin the SAME portal identity via the config-reload path (UpdateConfig
	// -> SaveVPNConfig -> GetVPNConfig): the fresh service (and the engine
	// it later builds) must serve the SAME endpoint the rendered client
	// config targets. NOTE: the pin must happen AFTER construction —
	// newIngressEngineService assigns its own fresh free ListenPort and
	// persists it after any cfgMutator runs, so a mutator pin would be
	// clobbered. The first service never started anything on the port; the
	// fresh service is its only binder in-process.
	started := newIngressEngineService(t, db)
	startedCfg, err := started.GetConfig(ctx)
	if err != nil {
		t.Fatalf("load restarted config: %v", err)
	}
	startedCfg.ListenPort = svc.cfg.ListenPort
	startedCfg.PublicEndpoint = svc.cfg.PublicEndpoint
	if err := started.UpdateConfig(ctx, startedCfg); err != nil {
		t.Fatalf("pin restarted portal identity: %v", err)
	}
	started.mu.RLock()
	legacyListener := started.endpoint
	started.mu.RUnlock()
	if legacyListener != nil {
		_ = legacyListener.Stop()
	}
	started.mu.Lock()
	started.endpoint = nil // never Start the legacy listener over the portal port
	started.mu.Unlock()
	// Suppress probing at the SOURCE, not by stopping the instance: Start
	// runs ProbeAll + StartAfterInitialProbe on whatever s.prober points to
	// (vpn.go: "if s.prober != nil"), and a Stop() before Start does not
	// prevent that sweep — its on-active ensure path then fights the echo
	// adapter mid-test. SetHealthProber(nil) makes Start skip the whole
	// probe path (the same knob the SetHealthProber(nil) unit tests use).
	started.SetHealthProber(nil)
	if err := started.Start(ctx); err != nil {
		t.Fatalf("fresh service start: %v", err)
	}
	t.Cleanup(func() { _ = started.Stop() })

	// The startup health sweep never ran (prober suppressed) and the
	// restore pass could not build a data plane for the synthetic backend:
	// re-mark the tunnel active so the admission path can route to it.
	if err := started.pool.SetTunnelStatus(ctx, prevBackend.ServerID, TunnelStatusActive, 50); err != nil {
		t.Fatalf("re-mark restarted backend active: %v", err)
	}
	// Occupy the service-side device slot so any late ensure-active path
	// (hook or restore) cannot attach a real device over the test's echo
	// adapter once it is attached below.
	started.mu.Lock()
	if started.backendDevices == nil {
		started.backendDevices = make(map[int64]BackendDevice)
	}
	started.backendDevices[prevBackendID] = portalGuardDevice{}
	started.mu.Unlock()
	// Pin admission to the echo backend: Service.Start also launched the
	// reconnect manager, whose activate pass marks BOTH tunnels active on
	// the restarted pool — but only prevBackendID carries the echo adapter.
	// Unpinned LB selection can route the fresh admission to the adapter-less
	// tunnel, black-holing the return path. Sticky affinity is consulted
	// first by admission selection (same primitive production reconnects use).
	if started.stickyMgr != nil {
		started.stickyMgr.AssignPeerAffinity(peer.publicKey, prevBackendID)
	}

	// (a) Restart reconciliation invalidated the old rows and reset gauges.
	if got := started.restartInvalidatedSessions.Load(); got != 2 {
		t.Fatalf("restart invalidated %d sessions, want 2", got)
	}
	rowsAfter, err := db.GetActiveVPNSessions(ctx)
	if err != nil || len(rowsAfter) != 0 {
		t.Fatalf("stale connected rows survived restart: %d rows, %v", len(rowsAfter), err)
	}
	freshTunnel, err := db.GetBackendTunnel(ctx, prevBackendID)
	if err != nil || freshTunnel == nil || freshTunnel.ActiveConnections != 0 {
		t.Fatalf("stale gauge survived restart: %+v err=%v", freshTunnel, err)
	}

	// (b) The configured peer is reconstructed from durable state, not from
	// any vpn_sessions row: resolver lease + portal identity, both durable.
	freshEngine, err := started.NewIngressEngine(ctx, "restart-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatalf("engine reconstruction from restarted service: %v", err)
	}
	t.Cleanup(func() { _ = freshEngine.Stop() })
	if err := freshEngine.Start(); err != nil {
		t.Fatal(err)
	}
	ownership, ok := freshEngine.Resolver().Lookup(ip)
	if !ok || ownership.PeerPublicKey != peer.publicKey {
		t.Fatalf("resolver did not reconstruct the peer from durable state: %+v ok=%v", ownership, ok)
	}
	if ownership.ConnectionID == "" || ownership.UserID == "" {
		t.Fatalf("reconstructed ownership incomplete: %+v", ownership)
	}
	if st := portalPeerStatus(t, freshEngine, peer.publicKey); st.AllowedIP != netip.PrefixFrom(ip, 32) {
		t.Fatalf("reconstructed portal peer wrong: %+v", st)
	}
	// The ghost peer — present only in the (deleted) stale session rows —
	// must NOT be configured anywhere: it was never a durable peer.
	for _, p := range portalPeerStatusPeers(t, freshEngine) {
		if p.PublicKey == ghostPeer {
			t.Fatal("the ghost stale-session peer was reconstructed into the portal")
		}
	}

	// (c) The SAME client identity (unchanged rendered config) connects and
	// flows end to end against the fresh process.
	restartedTunnels := started.pool.ListTunnels()
	var freshBackend *models.BackendTunnel
	for _, tun := range restartedTunnels {
		if tun.ID == prevBackendID {
			freshBackend = tun
			break
		}
	}
	if freshBackend == nil {
		t.Fatalf("restarted pool lost backend %d", prevBackendID)
	}
	destination := startLifecycleEchoBackend(t, started, freshBackend, 0x3B)
	started.forwarder.StartPumps(ctx)
	t.Cleanup(started.forwarder.StopPumps)
	client := startLifecycleClient(t, engineLifecyclePeer{enginePeer: peer, savedConfig: saved}, destination, 0x3B)
	client.sendAwait(t, 1)
	sess, ok := waitForSession(t, started, peer.publicKey)
	if !ok {
		t.Fatal("traffic after restart never admitted a session")
	}
	if sess.AssignedIP != peer.assignedIP || sess.PeerPublicKey != peer.publicKey {
		t.Fatalf("post-restart admission wrong identity: %+v", sess)
	}
	if got := started.forwarder.RouteSessionID(peer.publicKey); got != sess.ID {
		t.Fatalf("post-restart route %q, want %q", got, sess.ID)
	}
	if got := started.freshSessionRegistrations.Load(); got != 1 {
		t.Fatalf("post-restart registrations = %d, want 1 (reconstruction must not pre-create sessions)", got)
	}
	// The reconnected client kept its untouched identity: the rendered
	// config's key still pairs with the portal (the handshake succeeded)
	// and the durable lease is unchanged.
	if row, err := db.GetConnectionByClientID(ctx, peer.publicKey, 0); err != nil || row == nil ||
		row.ClientParams["assigned_ip"] != peer.assignedIP {
		t.Fatalf("durable lease changed across restart: %+v err=%v", row, err)
	}
}
