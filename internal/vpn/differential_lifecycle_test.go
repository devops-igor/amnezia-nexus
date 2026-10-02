package vpn

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// startConcurrentEchoBackend starts a multi-client echo server supporting multiple concurrent
// TCP streams and UDP datagrams to a specific destination IP on the given backend tunnel.
func startConcurrentEchoBackend(t *testing.T, svc *Service, backend *models.BackendTunnel, dest netip.Addr, marker byte) {
	t.Helper()
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{dest}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &returnStackDevice{tun: vt}
	done := make(chan struct{})
	svc.forwarder.AttachBackendDevice(backend.ID, adapter)
	go func() {
		defer close(done)
		svc.pumpBackendReturns(backend.ID, backend.ServerID, adapter)
	}()
	t.Cleanup(func() { _ = adapter.Close(); <-done })

	tcpListener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(dest, 40001))
	if err != nil {
		t.Fatal(err)
	}
	udpListener, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(dest, 40001))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tcpListener.Close()
		_ = udpListener.Close()
	})

	go func() {
		for {
			c, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				if _, err := conn.Write([]byte{marker}); err != nil {
					return
				}
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := udpListener.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpListener.WriteTo(append([]byte{marker}, buf[:n]...), remote)
		}
	}()
}

// TestLifecycle_TransparentBackendMigration verifies live session migration between backends
// while the client's AWG device and connection stay actively open, asserting traffic transitions
// smoothly to the target backend, counters update accurately, and client identity is preserved.
func TestLifecycle_TransparentBackendMigration(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db, fullAmneziaWGOpts())

	peer, saved := newEnginePeer(t, svc, db, "lifecycle-migrate-peer")
	ip := netip.MustParseAddr(peer.assignedIP)

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	if len(backends) < 2 {
		t.Fatalf("need at least 2 backends for migration test, got %d", len(backends))
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].ID < backends[j].ID })
	b1, b2 := backends[0], backends[1]

	dest := netip.MustParseAddr("198.51.100.71")
	startConcurrentEchoBackend(t, svc, b1, dest, 0x11)
	startConcurrentEchoBackend(t, svc, b2, dest, 0x22)

	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	svc.stickyMgr.AssignPeerAffinity(peer.publicKey, b1.ID)

	engine, err := svc.NewIngressEngine(ctx, "migrate-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	// Connect client to dest through b1 with standard timing (rekey after 120s)
	// so the 2-second test rekey timer does not trigger during migration.
	c1 := newReturnStreamClientWithTiming(t, peer, saved, dest, 0x11, "rekey_after_time=120\nrekey_timeout=5\n")
	defer func() { c1.dev.Close() }()

	// Send initial application traffic through Backend 1
	payload1 := []byte("pre-migration-traffic-be1")
	returnExchange(t, c1.tcp, payload1, false, 0x11)
	returnExchange(t, c1.udp, payload1, true, 0x11)

	hsBefore := c1.LastHandshakeTime()

	sess, ok := waitForSession(t, svc, peer.publicKey)
	if !ok {
		t.Fatal("session never admitted")
	}
	if sess.BackendTunnelID != b1.ID {
		t.Fatalf("session on backend %d, want initial %d", sess.BackendTunnelID, b1.ID)
	}
	waitBackendGaugeEqual(t, svc, b1.ID, 1, "initial b1 gauge")
	waitBackendGaugeEqual(t, svc, b2.ID, 0, "initial b2 gauge")

	// Perform live migration to Backend 2
	if err := svc.MigrateSession(ctx, sess.ID, b2.ID); err != nil {
		t.Fatalf("MigrateSession: %v", err)
	}

	// Verify session snapshot updated
	migratedSess, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey)
	if !ok {
		t.Fatal("session snapshot missing after migration")
	}
	if migratedSess.BackendTunnelID != b2.ID {
		t.Fatalf("migrated session on backend %d, want target %d", migratedSess.BackendTunnelID, b2.ID)
	}
	waitBackendGaugeEqual(t, svc, b1.ID, 0, "b1 gauge after migration")
	waitBackendGaugeEqual(t, svc, b2.ID, 1, "b2 gauge after migration")

	// Continue traffic on the SAME client c1, verifying seamless transition to b2 marker 0x22
	payload2 := []byte("post-migration-traffic-be2")
	returnExchange(t, c1.udp, payload2, true, 0x22)

	tcpPost, err := c1.stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(dest, 40001))
	if err != nil {
		t.Fatalf("TCP post-migration dial: %v", err)
	}
	defer tcpPost.Close()
	_ = tcpPost.SetReadDeadline(time.Now().Add(3 * time.Second))
	initMarker := make([]byte, 1)
	if _, err := io.ReadFull(tcpPost, initMarker); err != nil || initMarker[0] != 0x22 {
		t.Fatalf("TCP post-migration reached wrong backend: marker=%v err=%v", initMarker, err)
	}
	returnExchange(t, tcpPost, payload2, false, 0x22)

	// Verify c1 device remained continuously up with zero re-handshakes caused by migration
	if hsAfter := c1.LastHandshakeTime(); !hsAfter.Equal(hsBefore) {
		t.Fatalf("migration caused unexpected client re-handshake: before=%v after=%v", hsBefore, hsAfter)
	}

	// Verify forwarder drop statistics remain 0
	qFull, noRoute, _ := svc.forwarder.DropStats()
	if qFull != 0 || noRoute != 0 {
		t.Errorf("forwarder drops after migration: queueFull=%d noRoute=%d", qFull, noRoute)
	}

	// Assert client identity is unchanged
	peerStatus := portalPeerStatus(t, engine, peer.publicKey)
	if peerStatus.AllowedIP != netip.PrefixFrom(ip, 32) {
		t.Errorf("portal AllowedIP mutated: got %v", peerStatus.AllowedIP)
	}
}

// TestLifecycle_IdleSessionReapAndRecreation verifies that an idle session is retired by the
// real reap loop, and that new traffic from the same unchanged client admits a fresh backend
// session without regenerating configuration or removing the upstream peer.
func TestLifecycle_IdleSessionReapAndRecreation(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db, fullAmneziaWGOpts())

	peer, saved := newEnginePeer(t, svc, db, "lifecycle-reap-peer")
	lc := engineLifecyclePeer{enginePeer: peer, savedConfig: saved}
	ip := netip.MustParseAddr(lc.assignedIP)

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	if len(backends) == 0 {
		t.Fatal("no active backends")
	}
	backend := backends[0]
	dest := netip.MustParseAddr("198.51.100.73")
	for _, b := range backends {
		startConcurrentEchoBackend(t, svc, b, dest, 0x33)
	}
	svc.stickyMgr.AssignPeerAffinity(lc.publicKey, backend.ID)

	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	engine, err := svc.NewIngressEngine(ctx, "reap-portal", []clientawg.Peer{
		{PublicKey: lc.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	var currentReapTimeout atomic.Int64
	currentReapTimeout.Store(int64(3 * time.Minute))
	engine.reapIdleTimeoutFn = func(*Service) time.Duration { return time.Duration(currentReapTimeout.Load()) }
	engine.reapInterval = 50 * time.Millisecond
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}

	client := startLifecycleClient(t, lc, dest, 0x33)
	defer func() { client.uc.dev.Close() }()

	// 1. Initial traffic admits session
	client.sendAwait(t, 1)
	sess1, ok := waitForSession(t, svc, lc.publicKey)
	if !ok {
		t.Fatal("initial session not admitted")
	}
	waitBackendGaugeEqual(t, svc, backend.ID, 1, "gauge after first admission")

	// 2. Shorten reap timeout and wait for idle retirement
	currentReapTimeout.Store(int64(100 * time.Millisecond))
	reapDeadline := time.Now().Add(10 * time.Second)
	for {
		_, exists := svc.sessionMgr.GetSessionSnapshotByPeer(lc.publicKey)
		route := svc.forwarder.RouteSessionID(lc.publicKey)
		tun, err := svc.pool.GetTunnelByID(backend.ID)
		if !exists && route == "" && err == nil && tun.ActiveConnections == 0 {
			break
		}
		if time.Now().After(reapDeadline) {
			t.Fatalf("reap loop never retired idle session (route=%q)", route)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Assert peer is STILL configured in portal
	peerStatus := portalPeerStatus(t, engine, lc.publicKey)
	if peerStatus.AllowedIP != netip.PrefixFrom(ip, 32) {
		t.Fatalf("portal peer AllowedIP mutated: %v", peerStatus.AllowedIP)
	}

	// 3. Same running client sends traffic again to transparently recreate session
	currentReapTimeout.Store(int64(3 * time.Minute))
	client.sendAwait(t, 2)

	sess2, ok := waitForSession(t, svc, lc.publicKey)
	if !ok {
		t.Fatal("post-reap traffic never re-admitted session")
	}
	if sess2.ID == sess1.ID {
		t.Fatal("session ID reused across reap")
	}
	waitBackendGaugeEqual(t, svc, backend.ID, 1, "gauge after re-admission")
}

// TestLifecycle_EngineRestartWithStatePreservation verifies that restarting the IngressEngine
// service using the same database, portal identity, client config, and assigned IP cleanly
// reconstructs the runtime peer table and allows the client to resume traffic without re-issuance.
func TestLifecycle_EngineRestartWithStatePreservation(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc1 := newIngressEngineService(t, db, fullAmneziaWGOpts())

	peer, saved := newEnginePeer(t, svc1, db, "lifecycle-restart-peer")
	ip := netip.MustParseAddr(peer.assignedIP)

	if err := svc1.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backends := svc1.pool.ListTunnels()
	if len(backends) == 0 {
		t.Fatal("no backends")
	}
	backend := backends[0]
	dest := netip.MustParseAddr("198.51.100.74")
	startConcurrentEchoBackend(t, svc1, backend, dest, 0x44)
	svc1.stickyMgr.AssignPeerAffinity(peer.publicKey, backend.ID)

	svc1.forwarder.StartPumps(ctx)

	engine1, err := svc1.NewIngressEngine(ctx, "restart-portal-1", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine1.Start(); err != nil {
		t.Fatal(err)
	}

	c1 := newReturnStreamClient(t, peer, saved, dest, 0x44)
	returnExchange(t, c1.tcp, []byte("pre-restart-tcp"), false, 0x44)
	returnExchange(t, c1.udp, []byte("pre-restart-udp"), true, 0x44)

	// Stop Engine 1 and Service 1
	c1.dev.Close()
	_ = engine1.Stop()
	svc1.forwarder.StopPumps()
	svc1.Stop()

	// Build Service 2 from SAME database
	svc2 := newIngressEngineService(t, db, fullAmneziaWGOpts())
	startedCfg := svc2.cfg
	startedCfg.ListenPort = svc1.cfg.ListenPort
	startedCfg.PublicEndpoint = svc1.cfg.PublicEndpoint
	if err := svc2.UpdateConfig(ctx, startedCfg); err != nil {
		t.Fatalf("pin restarted portal identity: %v", err)
	}
	svc2.mu.Lock()
	if svc2.backendDevices == nil {
		svc2.backendDevices = make(map[int64]BackendDevice)
	}
	svc2.backendDevices[backend.ID] = portalGuardDevice{}
	svc2.mu.Unlock()
	svc2.SetHealthProber(nil)

	if err := svc2.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	dest2 := netip.MustParseAddr("198.51.100.74")
	startConcurrentEchoBackend(t, svc2, backend, dest2, 0x44)
	svc2.forwarder.StartPumps(ctx)
	t.Cleanup(svc2.forwarder.StopPumps)

	if svc2.stickyMgr != nil {
		svc2.stickyMgr.AssignPeerAffinity(peer.publicKey, backend.ID)
	}

	// IngressEngine 2 reconstructs configured peer from durable state
	engine2, err := svc2.NewIngressEngine(ctx, "restart-portal-2", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine2.Stop() })

	// Connect client using the EXACT SAME unchanged configuration
	c2 := newReturnStreamClient(t, peer, saved, dest2, 0x44)
	defer func() { c2.dev.Close() }()

	returnExchange(t, c2.tcp, []byte("post-restart-tcp"), false, 0x44)
	returnExchange(t, c2.udp, []byte("post-restart-udp"), true, 0x44)

	// Assert session successfully recreated on Service 2
	sessAfter, ok := waitForSession(t, svc2, peer.publicKey)
	if !ok {
		t.Fatal("session not found on restarted service")
	}
	if sessAfter.AssignedIP != peer.assignedIP {
		t.Errorf("session IP after restart = %s, want %s", sessAfter.AssignedIP, peer.assignedIP)
	}
}

// TestLifecycle_MultiPeerConcurrencyAndLoad scales to multiple distinct concurrent peers
// sending mixed TCP and UDP traffic through distinct backends, asserting peer isolation,
// zero crosstalk, bounded drops, and clean teardown.
func TestLifecycle_MultiPeerConcurrencyAndLoad(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db, fullAmneziaWGOpts())

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	if len(backends) < 2 {
		t.Fatalf("need >= 2 backends, got %d", len(backends))
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].ID < backends[j].ID })

	b1, b2 := backends[0], backends[1]
	dest1 := netip.MustParseAddr("198.51.100.81")
	startConcurrentEchoBackend(t, svc, b1, dest1, 0x51)
	dest2 := netip.MustParseAddr("198.51.100.82")
	startConcurrentEchoBackend(t, svc, b2, dest2, 0x52)

	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	// Create 4 distinct peers
	numPeers := 4
	peers := make([]enginePeer, numPeers)
	configs := make([]string, numPeers)
	clientPeers := make([]clientawg.Peer, numPeers)

	for i := 0; i < numPeers; i++ {
		p, saved := newEnginePeer(t, svc, db, fmt.Sprintf("multipeer-%d", i))
		peers[i] = p
		configs[i] = saved
		ip := netip.MustParseAddr(p.assignedIP)
		clientPeers[i] = clientawg.Peer{
			PublicKey: p.publicKey,
			AllowedIP: netip.PrefixFrom(ip, 32),
		}
		// Distribute affinity across backends
		targetBackend := b1.ID
		if i%2 == 1 {
			targetBackend = b2.ID
		}
		svc.stickyMgr.AssignPeerAffinity(p.publicKey, targetBackend)
	}

	engine, err := svc.NewIngressEngine(ctx, "multipeer-portal", clientPeers)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	// Launch concurrent streaming clients
	var wg sync.WaitGroup
	wg.Add(numPeers)

	clients := make([]*returnStreamClient, numPeers)
	for i := 0; i < numPeers; i++ {
		dest := dest1
		marker := byte(0x51)
		if i%2 == 1 {
			dest = dest2
			marker = 0x52
		}
		clients[i] = newReturnStreamClient(t, peers[i], configs[i], dest, marker)
	}
	defer func() {
		for _, c := range clients {
			if c != nil && c.dev != nil {
				c.dev.Close()
			}
		}
	}()

	for i := 0; i < numPeers; i++ {
		go func(idx int) {
			defer wg.Done()
			c := clients[idx]
			marker := byte(0x51)
			if idx%2 == 1 {
				marker = 0x52
			}
			for round := 0; round < 5; round++ {
				payload := []byte(fmt.Sprintf("peer-%d-round-%d", idx, round))
				returnExchange(t, c.tcp, payload, false, marker)
				returnExchange(t, c.udp, payload, true, marker)
			}
		}(i)
	}

	wg.Wait()

	// Assert strict isolation: each peer has a distinct session and no cross-routed packets
	qFull, noRoute, _ := svc.forwarder.DropStats()
	if qFull != 0 || noRoute != 0 {
		t.Errorf("forwarder drops under multi-peer load: queueFull=%d noRoute=%d", qFull, noRoute)
	}

	for i := 0; i < numPeers; i++ {
		snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peers[i].publicKey)
		if !ok {
			t.Errorf("missing session snapshot for peer %d", i)
			continue
		}
		expectedBackend := b1.ID
		if i%2 == 1 {
			expectedBackend = b2.ID
		}
		if snap.BackendTunnelID != expectedBackend {
			t.Errorf("peer %d routed to backend %d, want %d", i, snap.BackendTunnelID, expectedBackend)
		}
	}
}

// TestLifecycle_ConcurrentRevokeTrafficRace exercises concurrent application traffic streaming
// and peer revocation, asserting that the revoked peer is immediately rejected while unrevoked
// peers continue traffic unaffected with zero data races.
func TestLifecycle_ConcurrentRevokeTrafficRace(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db, fullAmneziaWGOpts())

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	backends := svc.pool.ListTunnels()
	if len(backends) == 0 {
		t.Fatal("no backends")
	}
	backend := backends[0]
	dest := netip.MustParseAddr("198.51.100.91")
	for _, b := range backends {
		startConcurrentEchoBackend(t, svc, b, dest, 0x66)
	}

	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	// Issue 2 peers
	peer1, saved1 := newEnginePeer(t, svc, db, "race-peer-1")
	peer2, saved2 := newEnginePeer(t, svc, db, "race-peer-2")

	svc.stickyMgr.AssignPeerAffinity(peer1.publicKey, backend.ID)
	svc.stickyMgr.AssignPeerAffinity(peer2.publicKey, backend.ID)

	ip1 := netip.MustParseAddr(peer1.assignedIP)
	ip2 := netip.MustParseAddr(peer2.assignedIP)

	engine, err := svc.NewIngressEngine(ctx, "race-portal", []clientawg.Peer{
		{PublicKey: peer1.publicKey, AllowedIP: netip.PrefixFrom(ip1, 32)},
		{PublicKey: peer2.publicKey, AllowedIP: netip.PrefixFrom(ip2, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	c1 := newReturnStreamClient(t, peer1, saved1, dest, 0x66)
	c2 := newReturnStreamClient(t, peer2, saved2, dest, 0x66)
	defer func() {
		c1.dev.Close()
		c2.dev.Close()
	}()

	// Establish initial sessions
	returnExchange(t, c1.tcp, []byte("init-peer1"), false, 0x66)
	returnExchange(t, c2.tcp, []byte("init-peer2"), false, 0x66)

	// Stream concurrently on both peers while revoking Peer 1
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)

	// Peer 2 worker: unrevoked stream continues
	go func() {
		defer wg.Done()
		seq := 0
		for {
			select {
			case <-stopCh:
				return
			default:
				seq++
				payload := []byte(fmt.Sprintf("peer2-seq-%04d", seq))
				returnExchange(t, c2.udp, payload, true, 0x66)
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	// Peer 1 worker: actively sending
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			payload := []byte(fmt.Sprintf("peer1-probe-%04d", i))
			_ = c1.udp.SetDeadline(time.Now().Add(50 * time.Millisecond))
			_, _ = c1.udp.Write(payload)
			buf := make([]byte, 64)
			_, _ = c1.udp.Read(buf)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Revoke Peer 1 mid-traffic
	conn1, err := db.GetConnectionByClientID(ctx, peer1.publicKey, 0)
	if err != nil || conn1 == nil {
		t.Fatalf("missing conn for peer1: %v", err)
	}

	revokedCh := make(chan struct{})
	svc.SetPostCommitRevokeHookForTest(func(kind database.PeerRevokeKind, userID, clientID string) {
		if kind == database.PeerRevokeConnection && clientID == peer1.publicKey {
			close(revokedCh)
		}
	})
	t.Cleanup(func() { svc.SetPostCommitRevokeHookForTest(nil) })

	if ok, err := db.ToggleConnection(ctx, conn1.ID, false); !ok || err != nil {
		t.Fatalf("ToggleConnection peer 1 failed: %v", err)
	}

	select {
	case <-revokedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("revocation hook not called within 3s")
	}

	// Verify Peer 1 session and route removed
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer1.publicKey); ok {
		t.Errorf("revoked peer 1 session still exists: %+v", snap)
	}
	if route := svc.forwarder.RouteSessionID(peer1.publicKey); route != "" {
		t.Errorf("revoked peer 1 forwarder route still exists: %q", route)
	}

	close(stopCh)
	wg.Wait()

	// Verify Peer 2 remains fully functional
	returnExchange(t, c2.tcp, []byte("peer2-final-check"), false, 0x66)
	returnExchange(t, c2.udp, []byte("peer2-final-check"), true, 0x66)
}
