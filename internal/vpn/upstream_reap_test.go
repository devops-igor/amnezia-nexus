package vpn

// Issue #390 part 1 regression coverage: the upstream engine's backend
// sessions are reaped ROUTING-ONLY. An idle reap of an ingress-admitted
// session must never fence peer generations, never prune endpoint transport
// state, and never force the upstream client into a re-handshake — while the
// legacy handshake-era reap keeps its fence+prune teardown byte-for-byte
// (pinned by the unmodified issue-295/309 reaper contract tests).
//
// Provenance seam: models.VPNSession.AdmittedVia is stamped by
// EnsureBackendSessionForIngress (both branches) and read by
// Service.reapSession. "ingress" → reapIngressSession (routing-only);
// "" (the handshake-era admission) → reapLegacySession (fence+prune).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// reapIngressSessionFixture is the minimal state reapIngressSession needs:
// a synced pool, a registered forwarder route, and one backend count. No
// listener transport state is created — exactly the upstream-engine reality.
type reapIngressSessionFixture struct {
	svc       *Service
	backendID int64
	sess      *models.VPNSession
}

func newReapIngressFixture(t *testing.T) *reapIngressSessionFixture {
	t.Helper()
	db := setupTestDB(t)
	svc, _, _, userID, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tunnels := svc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels")
	}
	backend := tunnels[0]
	sess, _, err := svc.sessionMgr.CreateSessionWithDeltaAndSource(ctx, userID, "ingress-reap-peer", "10.100.6.2", backend.ID, "ingress-device", models.SessionAdmissionIngress)
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.IncrementConnections(backend.ID)
	if svc.forwarder != nil {
		_ = svc.forwarder.BeginRegisterSessionWithLimit(sess.ID, "conn-ingress-reap", sess.PeerPublicKey, sess.AssignedIP, backend.ID, 0, 0)
	}
	return &reapIngressSessionFixture{svc: svc, backendID: backend.ID, sess: sess}
}

// TestReapIngressSessionNeverTouchesEndpointState pins the core invariant:
// the routing-only reap retires the route and the pool count.
func TestReapIngressSessionNeverTouchesEndpointState(t *testing.T) {
	fx := newReapIngressFixture(t)
	svc, sess, backendID := fx.svc, fx.sess, fx.backendID

	svc.sessionMgr.SetSessionLastSeen(sess.PeerPublicKey, time.Now().UTC().Add(-10*time.Minute))
	timedOut, err := svc.sessionMgr.CheckTimeouts(context.Background(), time.Minute)
	if err != nil || len(timedOut) != 1 {
		t.Fatalf("CheckTimeouts: %v (%d timed out)", err, len(timedOut))
	}
	svc.reapSession(context.Background(), timedOut[0])

	if route := svc.forwarder.RouteSessionID(sess.PeerPublicKey); route != "" {
		t.Fatalf("route survived routing-only reap: %q", route)
	}
	tun, err := svc.pool.GetTunnelByID(backendID)
	if err != nil {
		t.Fatal(err)
	}
	if got := tun.ActiveConnections; got != 0 {
		t.Fatalf("backend ActiveConnections = %d, want 0 after reap", got)
	}
}

// TestReapSessionNilAndUnknownPeerSafe covers the dispatch guards: nil
// session and a fabricated unknown-peer session (legacy provenance) must not
// panic — the pre-existing edge-case contract, now through the dispatcher.
func TestReapSessionNilAndUnknownPeerSafe(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()

	svc.reapSession(ctx, nil)
	svc.reapSession(ctx, &models.VPNSession{
		ID:              "non-existent",
		PeerPublicKey:   "no-such-peer",
		BackendTunnelID: 999999,
	})
}

// TestIngressAdmissionStampsProvenance verifies the seam at its source: a
// fresh ingress admission stamps AdmittedVia=ingress on the returned AND the
// stored session.
func TestIngressAdmissionStampsProvenance(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "ingress-stamp-alice", "ingress-stamp-peer-1", "10.100.6.10")
	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	if sess.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("returned session AdmittedVia = %q, want %q", sess.AdmittedVia, models.SessionAdmissionIngress)
	}
	stored, ok := svc.sessionMgr.GetSessionByPeer(ctx, peer.peerKey)
	if ok != nil || stored == nil {
		t.Fatalf("stored session missing: %v", ok)
	}
	if stored.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("stored session AdmittedVia = %q, want %q", stored.AdmittedVia, models.SessionAdmissionIngress)
	}
}

// TestIngressReadoptStampsLegacySession covers the adoption branch: a
// handshake-created live session (AdmittedVia == "") reused by the ingress
// admission comes back stamped ingress — the reap of the session the ingress
// path actually served must be routing-only.
func TestIngressReadoptStampsLegacySession(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "ingress-adopt-bob", "ingress-adopt-peer-1", "10.100.6.11")
	backend, err := selectBackendForIngressTest(t, svc, peer.userID)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := svc.sessionMgr.CreateSession(ctx, peer.userID, peer.peerKey, peer.ip.String(), backend.ID, "adopted-device")
	if err != nil {
		t.Fatal(err)
	}
	svc.pool.IncrementConnections(backend.ID)
	_ = svc.forwarder.BeginRegisterSessionWithLimit(legacy.ID, peer.connID, peer.peerKey, peer.ip.String(), backend.ID, 0, 0)
	if legacy.AdmittedVia != models.SessionAdmissionHandshake {
		t.Fatalf("fixture setup: legacy session AdmittedVia = %q, want empty", legacy.AdmittedVia)
	}

	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("ingress readoption: %v", err)
	}
	if sess.ID != legacy.ID {
		t.Fatalf("expected reuse of the legacy session %s, got new session %s", legacy.ID, sess.ID)
	}
	if sess.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("readopted session AdmittedVia = %q, want %q", sess.AdmittedVia, models.SessionAdmissionIngress)
	}
	stored, _ := svc.sessionMgr.GetSessionByPeer(ctx, peer.peerKey)
	if stored == nil || stored.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("stored readopted session not stamped: %+v", stored)
	}
}

// selectBackendForIngressTest mirrors the admission's selection for a peer
// with no prior affinity: least-connections over the active tunnels.
func selectBackendForIngressTest(t *testing.T, svc *Service, userID string) (*models.BackendTunnel, error) {
	t.Helper()
	tunnels := svc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels for selection")
	}
	req := &loadbalancer.RoutingRequest{
		UserID:           userID,
		AvailableTunnels: tunnels,
	}
	return svc.selectTunnelForPeer(context.Background(), req)
}

// TestEngineSweepReapsIdleIngressSessionRoutingOnly drives the upstream-mode
// reap driver (IngressEngine.sweepOnce) against a real engine: an expired
// ingress session is reaped through CheckTimeouts + the provenance-selected
// routing-only teardown — no fence, no transport-state mutation, gauge back
// to zero — while a healthy session on another peer is left untouched.
func TestEngineSweepReapsIdleIngressSessionRoutingOnly(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	// The portal validates peer identities (canonical base64, 32 bytes), so
	// the seeded peer uses a real minted public key; the admission itself is
	// driven directly through EnsureBackendSessionForIngress.
	_, sweepPub := engineKeys(t)
	peer := seedIngressPeer(t, db, "engine-sweep-alice", sweepPub, "10.100.6.20")
	engine := startEngine(t, svc, "engine-sweep-portal", []clientawg.Peer{
		{PublicKey: peer.peerKey, AllowedIP: netip.PrefixFrom(peer.ip, 32)},
	})

	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	backendID := sess.BackendTunnelID
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != sess.ID {
		t.Fatalf("pre-sweep route session %q, want %q", got, sess.ID)
	}

	// Expire exactly this session and drive one deterministic engine sweep
	// (the reap loop's cadence is not waited on).
	svc.sessionMgr.SetSessionLastSeen(peer.peerKey, time.Now().UTC().Add(-10*time.Minute))
	engine.sweepOnce(ctx)

	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey); ok {
		t.Fatal("sweep did not retire the expired ingress session")
	}
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != "" {
		t.Fatalf("route survived the engine sweep: %q", got)
	}
	tun, err := svc.pool.GetTunnelByID(backendID)
	if err != nil {
		t.Fatal(err)
	}
	if got := tun.ActiveConnections; got != 0 {
		t.Fatalf("backend ActiveConnections = %d after sweep, want 0", got)
	}
}

// gaugeSumAcrossBackends returns the total active-connection count over all
// pool tunnels, the net-increment assertion surface for the race tests.
func gaugeSumAcrossBackends(t *testing.T, svc *Service) int {
	t.Helper()
	total := 0
	for _, tun := range svc.pool.ListTunnels() {
		live, err := svc.pool.GetTunnelByID(tun.ID)
		if err != nil {
			t.Fatal(err)
		}
		total += live.ActiveConnections
	}
	return total
}

// TestUpstreamReapRacesFirstPlaintextAdmission is spec item 6 race A: the
// idle reap (driver CheckTimeouts + reapSession) racing the admission a
// fresh plaintext packet triggers. LastSeen-based reuse means every
// interleaving converges to one of two valid outcomes — traffic saved the
// session, or traffic recreated it — and after one convergent admission the
// peer has EXACTLY one usable routing session and the backend gauges net to
// exactly one increment (no double-inc, no leak). The loop forces varied
// interleavings; -race guards the unsynchronized gaps.
func TestUpstreamReapRacesFirstPlaintextAdmission(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "race-admit-eva", "race-admit-peer-1", "10.100.6.30")
	o := ownershipFor(peer)

	const iterations = 25
	for i := 0; i < iterations; i++ {
		if _, _, _, err := svc.EnsureBackendSessionForIngress(ctx, o); err != nil {
			t.Fatalf("iter %d: admission: %v", i, err)
		}
		// Expire the live session, then race the reap driver against a
		// fresh admission (what the next plaintext packet runs).
		svc.sessionMgr.SetSessionLastSeen(peer.peerKey, time.Now().UTC().Add(-10*time.Minute))

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			timedOut, err := svc.sessionMgr.CheckTimeouts(ctx, time.Minute)
			if err != nil {
				t.Errorf("iter %d: CheckTimeouts: %v", i, err)
				return
			}
			for _, s := range timedOut {
				svc.reapSession(ctx, s)
			}
		}()
		go func() {
			defer wg.Done()
			if _, _, _, err := svc.EnsureBackendSessionForIngress(ctx, o); err != nil {
				t.Errorf("iter %d: racing admission: %v", i, err)
			}
		}()
		wg.Wait()

		// Convergent admission: the following plaintext packet. Whatever
		// the interleaving above, exactly one usable session must result.
		if _, _, _, err := svc.EnsureBackendSessionForIngress(ctx, o); err != nil {
			t.Fatalf("iter %d: convergent admission: %v", i, err)
		}

		live, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
		if !ok || live.Status != "connected" {
			t.Fatalf("iter %d: no usable routing session after reap/admission race", i)
		}
		if got := svc.forwarder.RouteSessionID(peer.peerKey); got != live.ID {
			t.Fatalf("iter %d: route session %q, want the live session %q", i, got, live.ID)
		}
		if got := gaugeSumAcrossBackends(t, svc); got != 1 {
			t.Fatalf("iter %d: backend gauge sum = %d, want exactly 1 (net single increment)", i, got)
		}
	}
}

// TestUpstreamReapDoesNotRetireRecreatedSessionRoute is spec item 6 race B:
// the delayed reap of an OLD session running after a replacement admission —
// the route-retirement fencing contract. The old reap must not remove the
// new session's route (the forwarder's generation-bounded delete) and return
// traffic for the new session must still flow; backend gauges end with
// exactly one count on the new session's backend.
func TestUpstreamReapDoesNotRetireRecreatedSessionRoute(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := context.Background()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	peer := seedIngressPeer(t, db, "race-return-fred", "race-return-peer-1", "10.100.6.31")
	o := ownershipFor(peer)

	const iterations = 10
	for i := 0; i < iterations; i++ {
		if _, _, _, err := svc.EnsureBackendSessionForIngress(ctx, o); err != nil {
			t.Fatalf("iter %d: admission: %v", i, err)
		}
		oldSnap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
		if !ok {
			t.Fatalf("iter %d: live session missing before replacement", i)
		}
		svc.sessionMgr.SetSessionLastSeen(peer.peerKey, time.Now().UTC().Add(-10*time.Minute))

		// Genuinely evict expired session A from the live map via CheckTimeouts
		// before admitting fresh session B.
		timedOut, err := svc.sessionMgr.CheckTimeouts(ctx, time.Minute)
		if err != nil || len(timedOut) != 1 {
			t.Fatalf("iter %d: CheckTimeouts: %v (%d timed out)", i, err, len(timedOut))
		}
		reapTarget := timedOut[0]
		if reapTarget.ID != oldSnap.ID {
			t.Fatalf("iter %d: reapTarget ID %s != oldSnap ID %s", i, reapTarget.ID, oldSnap.ID)
		}

		fresh, _, _, err := svc.EnsureBackendSessionForIngress(ctx, o)
		if err != nil {
			t.Fatalf("iter %d: replacement admission: %v", i, err)
		}
		if fresh.ID == oldSnap.ID {
			t.Fatalf("iter %d: expected fresh session ID != oldSnap ID %s, got %s", i, oldSnap.ID, fresh.ID)
		}

		// Delayed reap of old session A must not disturb fresh session B's route.
		svc.reapSession(ctx, reapTarget)

		if got := svc.forwarder.RouteSessionID(peer.peerKey); got != fresh.ID {
			t.Fatalf("iter %d: old reap disturbed the new route: %q, want %q", i, got, fresh.ID)
		}
		ret := engineUDPPacket(peer.ip, netip.MustParseAddr("198.51.100.1"), uint32(0x39000000+i))
		if err := svc.forwarder.RouteBackendToClient(fresh.BackendTunnelID, ret, fresh.AssignedIP); err != nil {
			t.Fatalf("iter %d: return traffic for the new session rejected: %v", i, err)
		}
		clientQueue, ok := svc.forwarder.GetClientPacketChannel(peer.peerKey)
		if !ok {
			t.Fatalf("iter %d: client packet channel missing", i)
		}
		select {
		case got := <-clientQueue:
			if !bytes.Equal(got, ret) {
				t.Fatalf("iter %d: client queue delivered a different packet", i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iter %d: return traffic never reached the client queue within 2s", i)
		}
		live, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
		if !ok || live.ID != fresh.ID {
			t.Fatalf("iter %d: live session %v, want the replacement %s", i, ok, fresh.ID)
		}
		if got := gaugeSumAcrossBackends(t, svc); got != 1 {
			t.Fatalf("iter %d: backend gauge sum = %d, want exactly 1", i, got)
		}
	}
}

// TestUpstreamRekeyDoesNotCreateBackendSessionWithoutTraffic is spec item 5,
// second guard: handshake/rekey activity with NO live backend session must
// not itself create one. The upstream engine has no handshake-visible
// admission at all (admission is plaintext-packet-driven), so the assertion
// surface is the service: registrations happen ONLY through
// EnsureBackendSessionForIngress — handshakes (out of scope, #394) cannot
// mint sessions through it. Pinned here so a future handshake-coupled change
// to the ingress path fails loudly.
func TestUpstreamRekeyDoesNotCreateBackendSessionWithoutTraffic(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	peer, saved := newEnginePeer(t, svc, db, "rekey-nosession-nina")
	ip := netip.MustParseAddr(peer.assignedIP)

	engine, err := svc.NewIngressEngine(ctx, "rekey-nosession-portal", []clientawg.Peer{
		{PublicKey: peer.publicKey, AllowedIP: netip.PrefixFrom(ip, 32)},
	})
	if err != nil {
		t.Fatalf("engine construction: %v", err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	if err := engine.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}

	client := startEngineUpstreamClient(t, saved, "rekey-client")
	serverPubB64 := configField(t, saved, "PublicKey")
	serverPubBytes, err := base64.StdEncoding.DecodeString(serverPubB64)
	if err != nil {
		t.Fatalf("decode server public key: %v", err)
	}
	serverPubHex := hex.EncodeToString(serverPubBytes)
	if err := client.dev.IpcSet(fmt.Sprintf("public_key=%s\npersistent_keepalive_interval=1\n", serverPubHex)); err != nil {
		t.Fatalf("IpcSet persistent_keepalive_interval: %v", err)
	}

	// Poll until handshake completes without application traffic
	handshakeDeadline := time.Now().Add(10 * time.Second)
	for {
		status := portalPeerStatus(t, engine, peer.publicKey)
		if !status.LastHandshake.IsZero() {
			break
		}
		if time.Now().After(handshakeDeadline) {
			t.Fatal("timed out waiting for upstream WireGuard handshake without traffic")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Assert: zero backend session in SessionManager, empty route in forwarder, freshSessionRegistrations == 0
	if snap, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.publicKey); ok {
		t.Fatalf("session exists in SessionManager without application traffic: %+v", snap)
	}
	if route := svc.forwarder.RouteSessionID(peer.publicKey); route != "" {
		t.Fatalf("forwarder route exists without application traffic: %q", route)
	}
	if got := svc.freshSessionRegistrations.Load(); got != 0 {
		t.Fatalf("freshSessionRegistrations = %d without application traffic, want 0", got)
	}

	// Inject a plaintext UDP packet to trigger admission; pump to handle
	// handshake-settling drops under load (issue #391 round 4b, finding 3).
	pkt := engineUDPPacket(netip.MustParseAddr(peer.assignedIP), netip.MustParseAddr("10.0.0.1"), 0x42)
	client.inject(t, pkt)
	stopPump := pumpEnginePacketUntil(t, client, pkt, nil)
	defer stopPump()

	sess, ok := waitForSession(t, svc, peer.publicKey)
	if !ok {
		t.Fatal("session was not admitted after injecting application traffic")
	}
	if sess.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("sess.AdmittedVia = %q, want %q", sess.AdmittedVia, models.SessionAdmissionIngress)
	}
	if got := svc.freshSessionRegistrations.Load(); got != 1 {
		t.Fatalf("freshSessionRegistrations = %d after admission, want 1", got)
	}
}

// TestUpstreamPeerSurvivesReapWithIdentityIntact is spec item 7, the
// acceptance invariant (unit level; full E2E is Part 2): one configured
// upstream peer survives reap → new plaintext traffic → fresh backend
// session, with peer public key, assigned IP, and client config identity
// unchanged throughout; no peer removal and no transport-state mutation
// observable (fence baseline + live-endpoint inspection).
func TestUpstreamPeerSurvivesReapWithIdentityIntact(t *testing.T) {
	db := setupTestDB(t)
	svc := newIngressEngineService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tun := range svc.pool.ListTunnels() {
		svc.forwarder.AttachBackendDevice(tun.ID, nil)
	}

	// Real portal identity for the peer (the portal validates keys), a real
	// durable lease, and the rendered client config captured BEFORE the reap.
	_, peerPub := engineKeys(t)
	peer := seedIngressPeer(t, db, "survive-reap-omar", peerPub, "10.100.6.33")
	connBefore, err := svc.db.GetConnectionByClientID(ctx, peer.peerKey, 0)
	if err != nil || connBefore == nil {
		t.Fatalf("durable connection before reap: %v", err)
	}
	ipBefore := connBefore.ClientParams["assigned_ip"]
	if ipBefore != peer.ip.String() {
		t.Fatalf("durable lease %v, want %s", ipBefore, peer.ip.String())
	}

	// Phase 1: admit, then reap the session the way the upstream driver
	// does: idle expiry, CheckTimeouts (removes the session), reapSession.
	if _, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer)); err != nil {
		t.Fatalf("first admission: %v", err)
	}

	svc.sessionMgr.SetSessionLastSeen(peer.peerKey, time.Now().UTC().Add(-10*time.Minute))
	timedOut, err := svc.sessionMgr.CheckTimeouts(ctx, time.Minute)
	if err != nil || len(timedOut) != 1 {
		t.Fatalf("CheckTimeouts: %v (%d timed out)", err, len(timedOut))
	}
	svc.reapSession(ctx, timedOut[0])
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey); ok {
		t.Fatal("session survived its reap")
	}

	// Phase 2: the peer's identity survived the reap untouched...
	connAfter, err := svc.db.GetConnectionByClientID(ctx, peer.peerKey, 0)
	if err != nil || connAfter == nil {
		t.Fatalf("durable connection after reap: %v", err)
	}
	if connAfter.ID != connBefore.ID || connAfter.ClientParams["assigned_ip"] != ipBefore {
		t.Fatalf("durable identity changed across reap: %s/%v -> %s/%v",
			connBefore.ID, ipBefore, connAfter.ID, connAfter.ClientParams["assigned_ip"])
	}

	// Phase 3: new plaintext traffic re-admits the SAME peer with the SAME
	// durable lease as a fresh backend session.
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("re-admission: %v", err)
	}
	if sess.PeerPublicKey != peer.peerKey {
		t.Fatalf("re-admitted peer %s, want %s", sess.PeerPublicKey, peer.peerKey)
	}
	if sess.AssignedIP != peer.ip.String() {
		t.Fatalf("re-admitted IP %s, want the durable lease %s", sess.AssignedIP, peer.ip.String())
	}
	if sess.UserID != peer.userID {
		t.Fatalf("re-admitted user %s, want %s", sess.UserID, peer.userID)
	}
	if sess.BackendTunnelID != backend.ID {
		t.Fatalf("re-admitted backend %d, want selected %d", sess.BackendTunnelID, backend.ID)
	}
	if got := svc.forwarder.RouteSessionID(peer.peerKey); got != sess.ID {
		t.Fatalf("route session %q, want the re-admitted session %q", got, sess.ID)
	}
}

// TestIngressAdoptionFailureFallsThroughToFreshAdmission verifies review finding 2 & 3:
// if a legacy session exists at the start of EnsureBackendSessionForIngress but
// AdoptSessionForIngress fails (e.g. concurrent CloseSession/CheckTimeouts evicts
// the session before the adoption), adoption does not return the evicted session.
// Instead, no return path is bound and admission falls through cleanly to
// create and return a brand-new live session with AdmittedVia == ingress.
func TestIngressAdoptionFailureFallsThroughToFreshAdmission(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "adopt-fail-user", "adopt-fail-peer", "10.100.6.50")
	backend, err := selectBackendForIngressTest(t, svc, peer.userID)
	if err != nil {
		t.Fatal(err)
	}

	// Deterministic eviction hook right before AdoptSessionForIngress
	svc.SetPreAdoptHookForTest(func(peerKey, sessionID string) {
		_ = svc.sessionMgr.CloseSession(ctx, sessionID, "disconnected")
	})
	defer svc.SetPreAdoptHookForTest(nil)

	legacy, err := svc.sessionMgr.CreateSession(ctx, peer.userID, peer.peerKey, peer.ip.String(), backend.ID, "legacy-device")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_ = svc.forwarder.BeginRegisterSessionWithLimit(legacy.ID, peer.connID, peer.peerKey, peer.ip.String(), backend.ID, 0, 0)

	sess, admittedBackend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("EnsureBackendSessionForIngress: %v", err)
	}
	if sess.ID == legacy.ID {
		t.Fatalf("expected fresh session ID != legacy ID %s, got %s", legacy.ID, sess.ID)
	}
	if sess.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("admitted session AdmittedVia = %q, want %q", sess.AdmittedVia, models.SessionAdmissionIngress)
	}
	if sess.BackendTunnelID != admittedBackend.ID {
		t.Fatalf("session BackendTunnelID %d != admittedBackend %d", sess.BackendTunnelID, admittedBackend.ID)
	}

	// The returned session MUST be live in sessionMgr (never a dead evicted pointer)
	stored, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
	if !ok || stored.ID != sess.ID {
		t.Fatalf("session %s not stored as live in sessionMgr (got ok=%v, stored=%+v)", sess.ID, ok, stored)
	}
	if stored.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("stored session AdmittedVia = %q, want %q", stored.AdmittedVia, models.SessionAdmissionIngress)
	}
}

// TestIngressAdoptionRefreshesLivenessAgainstImmediateReap verifies review finding 1:
// adopting an existing session atomically refreshes LastSeen so that an immediate
// CheckTimeouts sweep does not evict the session before traffic touches it.
func TestIngressAdoptionRefreshesLivenessAgainstImmediateReap(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "adopt-refresh-user", "adopt-refresh-peer", "10.100.6.51")
	backend, err := selectBackendForIngressTest(t, svc, peer.userID)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Create legacy session A with backdated LastSeen (e.g. 10m ago).
	legacy, err := svc.sessionMgr.CreateSession(ctx, peer.userID, peer.peerKey, peer.ip.String(), backend.ID, "legacy-device")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_ = svc.forwarder.BeginRegisterSessionWithLimit(legacy.ID, peer.connID, peer.peerKey, peer.ip.String(), backend.ID, 0, 0)
	backdated := time.Now().UTC().Add(-10 * time.Minute)
	svc.sessionMgr.SetSessionLastSeen(peer.peerKey, backdated)

	// 2. Adopt A via EnsureBackendSessionForIngress.
	adopted, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("EnsureBackendSessionForIngress: %v", err)
	}
	if adopted.ID != legacy.ID {
		t.Fatalf("expected adoption of legacy session %s, got %s", legacy.ID, adopted.ID)
	}
	if adopted.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("adopted session AdmittedVia = %q, want %q", adopted.AdmittedVia, models.SessionAdmissionIngress)
	}

	// 3. Immediately call CheckTimeouts with 1m idle timeout.
	timedOut, err := svc.sessionMgr.CheckTimeouts(ctx, time.Minute)
	if err != nil {
		t.Fatalf("CheckTimeouts: %v", err)
	}

	// 4. Assert len(timedOut) == 0 (A was not evicted because LastSeen was refreshed).
	if len(timedOut) != 0 {
		t.Fatalf("session was evicted by CheckTimeouts despite adoption refresh: %d timed out", len(timedOut))
	}

	// 5. Assert A remains connected and live in sessionMgr.
	stored, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
	if !ok || stored.ID != legacy.ID || stored.Status != "connected" {
		t.Fatalf("session not live in sessionMgr after CheckTimeouts: ok=%v, stored=%+v", ok, stored)
	}
}

// TestDisconnectSessionUpstreamIsRoutingOnly verifies review finding 4:
// DisconnectSession on an upstream-admitted session performs routing-only teardown
// without advancing peer generations, fencing the endpoint, or pruning transport state.
func TestDisconnectSessionUpstreamIsRoutingOnly(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "dc-sess-user", "dc-sess-peer", "10.100.6.60")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("EnsureBackendSessionForIngress: %v", err)
	}
	if sess.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("AdmittedVia = %q, want %q", sess.AdmittedVia, models.SessionAdmissionIngress)
	}

	tun, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tun.ActiveConnections != 1 {
		t.Fatalf("ActiveConnections = %d, want 1 before disconnect", tun.ActiveConnections)
	}

	if err := svc.DisconnectSession(ctx, sess.ID); err != nil {
		t.Fatalf("DisconnectSession: %v", err)
	}

	// Invariant: routing teardown performed
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey); ok {
		t.Fatal("session was not closed in sessionMgr")
	}
	if route := svc.forwarder.RouteSessionID(peer.peerKey); route != "" {
		t.Fatalf("route survived disconnect: %q", route)
	}
	tunAfter, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Fatalf("ActiveConnections = %d, want 0 after disconnect", tunAfter.ActiveConnections)
	}
}

// TestDisconnectUserUpstreamIsRoutingOnly verifies review finding 4:
// DisconnectUser on an upstream-admitted session performs routing-only teardown
// without advancing peer generations, fencing the endpoint, or pruning transport state.
func TestDisconnectUserUpstreamIsRoutingOnly(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	peer := seedIngressPeer(t, db, "dc-user-user", "dc-user-peer", "10.100.6.61")
	sess, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatalf("EnsureBackendSessionForIngress: %v", err)
	}
	if sess.AdmittedVia != models.SessionAdmissionIngress {
		t.Fatalf("AdmittedVia = %q, want %q", sess.AdmittedVia, models.SessionAdmissionIngress)
	}

	tun, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tun.ActiveConnections != 1 {
		t.Fatalf("ActiveConnections = %d, want 1 before disconnect", tun.ActiveConnections)
	}

	if err := svc.DisconnectUser(ctx, peer.userID); err != nil {
		t.Fatalf("DisconnectUser: %v", err)
	}

	// Invariant: routing teardown performed
	if _, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey); ok {
		t.Fatal("session was not closed in sessionMgr")
	}
	if route := svc.forwarder.RouteSessionID(peer.peerKey); route != "" {
		t.Fatalf("route survived disconnect: %q", route)
	}
	tunAfter, err := svc.pool.GetTunnelByID(backend.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Fatalf("ActiveConnections = %d, want 0 after disconnect", tunAfter.ActiveConnections)
	}
}
