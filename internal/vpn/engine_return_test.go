package vpn

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

func ownedIngressPacket(source string) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], 28)
	ip := netip.MustParseAddr(source).As4()
	copy(packet[12:16], ip[:])
	copy(packet[16:20], []byte{192, 0, 2, 1})
	return packet
}

func TestEngineReturnOwnershipFreshReuseReplacementAndLegacyMemo(t *testing.T) {
	db := setupTestDB(t)
	svc, serverA, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	peer := seedIngressPeer(t, db, "return-owner", "return-peer-key-11111", "10.100.8.2")
	owner := ownershipFor(peer)
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	// Start with an existing legacy route to exercise healthy-session takeover.
	old, backend, _, err := svc.EnsureBackendSessionForIngress(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	resolver := ingress.NewResolver()
	if err := resolver.Update(owner); err != nil {
		t.Fatal(err)
	}
	router := ingress.NewRouterWithReturnPath(resolver, serviceIngressAdmission{svc: svc, returnPath: path}, svc.forwarder, nil, path)
	packet := ownedIngressPacket(peer.ip.String())
	if err := router.HandlePacket(packet); err != nil {
		t.Fatal(err)
	}
	if !svc.forwarder.HasSessionRouteWithReturnPath(peer.peerKey, old.ID, peer.connID, peer.ip.String(), backend.ID, path) {
		t.Fatal("reused legacy session missing owned return path")
	}
	for range 3 {
		if err := router.HandlePacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	if router.StatsSnapshot().AdmittedSessions != 1 {
		t.Fatal("healthy route churned admission")
	}
	// A rollback listener can replace an identical tuple: owner-sensitive memo
	// must detect that, rebind it, and still preserve the routing session.
	svc.forwarder.RegisterSession(old.ID, peer.connID, peer.peerKey, peer.ip.String(), backend.ID)
	if err := router.HandlePacket(packet); err != nil {
		t.Fatal(err)
	}
	if router.StatsSnapshot().AdmittedSessions != 2 {
		t.Fatal("legacy replacement escaped owner fence")
	}
	if !svc.forwarder.HasSessionRouteWithReturnPath(peer.peerKey, old.ID, peer.connID, peer.ip.String(), backend.ID, path) {
		t.Fatal("legacy route not rebound")
	}
	// Replacement onto another backend carries the same owner but retains the
	// existing exactly-once backend connection accounting.
	adminDisableBackend(t, svc, serverA)
	current, newBackend, _, err := svc.ensureBackendSessionForIngress(t.Context(), owner, path)
	if err != nil {
		t.Fatal(err)
	}
	if current.ID == old.ID || newBackend.ID == backend.ID {
		t.Fatal("backend replacement did not occur")
	}
	if !svc.forwarder.HasSessionRouteWithReturnPath(peer.peerKey, current.ID, peer.connID, peer.ip.String(), newBackend.ID, path) {
		t.Fatal("replacement omitted writer")
	}
	counts := backendCounts(t, svc)
	if counts[backend.ID] != 0 || counts[newBackend.ID] != 1 {
		t.Fatalf("replacement double accounted: %v", counts)
	}
	path.Close()
	if _, _, _, err := svc.ensureBackendSessionForIngress(t.Context(), owner, path); !errors.Is(err, forwarder.ErrReturnPathClosed) {
		t.Fatalf("stopped admission accepted: %v", err)
	}
	next := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	restored, _, _, err := svc.ensureBackendSessionForIngress(t.Context(), owner, next)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ID != current.ID || !svc.forwarder.HasSessionRouteWithReturnPath(peer.peerKey, current.ID, peer.connID, peer.ip.String(), newBackend.ID, next) {
		t.Fatal("new engine did not reuse session with fresh owner")
	}
	if err := router.HandlePacket(packet); err == nil {
		t.Fatal("old engine submitted after new owner took over")
	}
	if !svc.forwarder.HasSessionRouteWithReturnPath(peer.peerKey, current.ID, peer.connID, peer.ip.String(), newBackend.ID, next) {
		t.Fatal("old engine stole replacement owner")
	}
}

// TestEngineReturnWriteClassifiesDropsAndStats pins the engine seam's
// classification contract (issue #389 "queue pressure has explicit
// metrics"): every rejected plaintext shape lands in its own counter,
// accepted packets surface the portal TUN snapshot, and a stopped engine's
// closed return path rejects submissions.
func TestEngineReturnWriteClassifiesDropsAndStats(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	// NewIngressEngine fail-closed validates real upstream keys, so this test
	// mints an actual X25519 identity and seeds the matching durable lease.
	peerKey, _ := engineKeys(t)
	peer := seedIngressPeer(t, db, "return-classify", peerKey, "10.100.8.4")
	engine, err := svc.NewIngressEngine(t.Context(), "return-classify-portal", []clientawg.Peer{
		{PublicKey: peer.peerKey, AllowedIP: netip.PrefixFrom(peer.ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	returnPacket := func(dest netip.Addr) []byte {
		p := make([]byte, 28)
		p[0] = 0x45
		p[9] = 17 // UDP
		binary.BigEndian.PutUint16(p[2:4], 28)
		ip := dest.As4()
		copy(p[16:20], ip[:])
		return p
	}
	accepted := returnPacket(peer.ip)
	if _, err := engine.writeReturnPacket(peer.peerKey, peer.ip.String(), accepted); err != nil {
		t.Fatal(err)
	}

	stats := engine.ReturnStats()
	if stats.AcceptedPackets != 1 {
		t.Fatalf("accepted=%d, want 1", stats.AcceptedPackets)
	}
	if stats.TUN.InboundDepth != 1 {
		t.Fatalf("portal inbound depth=%d, want 1 (packet must reach the client-facing TUN)", stats.TUN.InboundDepth)
	}
	for name, got := range map[string]uint64{
		"malformed": stats.MalformedDrops, "unmapped": stats.UnmappedDrops,
		"mismatch": stats.OwnershipMismatchDrops, "injection": stats.InjectionErrors,
	} {
		if got != 0 {
			t.Fatalf("%s drops=%d after one accepted packet", name, got)
		}
	}

	// The shared reader's IPv4 floor: the engine seam must reject shapes the
	// production backend reader would otherwise forward unchecked.
	badVersion := returnPacket(peer.ip)
	badVersion[0] = 0x65
	badIHL := returnPacket(peer.ip)[:20]
	badIHL[0] = 0x46 // IHL=6: claimed 24-byte header exceeds the 20-byte packet
	shortTotal := returnPacket(peer.ip)
	binary.BigEndian.PutUint16(shortTotal[2:4], 12)
	for name, p := range map[string][]byte{"bad version": badVersion, "bad IHL": badIHL, "short total length": shortTotal} {
		if _, err := engine.writeReturnPacket(peer.peerKey, peer.ip.String(), p); !errors.Is(err, errReturnDestination) {
			t.Fatalf("%s packet accepted: %v", name, err)
		}
	}

	other := netip.MustParseAddr("192.0.2.53")
	if _, err := engine.writeReturnPacket(peer.peerKey, peer.ip.String(), returnPacket(other)); !errors.Is(err, errReturnDestination) {
		t.Fatal("unmapped destination accepted")
	}
	if _, err := engine.writeReturnPacket("not-"+peer.peerKey, peer.ip.String(), returnPacket(peer.ip)); !errors.Is(err, errReturnDestination) {
		t.Fatal("wrong peer key accepted")
	}
	if _, err := engine.writeReturnPacket(peer.peerKey, other.String(), returnPacket(peer.ip)); !errors.Is(err, errReturnDestination) {
		t.Fatal("assigned-IP divergence accepted")
	}

	stats = engine.ReturnStats()
	if stats.MalformedDrops != 3 || stats.UnmappedDrops != 1 || stats.OwnershipMismatchDrops != 2 {
		t.Fatalf("misclassified drops: malformed=%d unmapped=%d mismatch=%d", stats.MalformedDrops, stats.UnmappedDrops, stats.OwnershipMismatchDrops)
	}
	if stats.AcceptedPackets != 1 || stats.TUN.InboundDepth != 1 {
		t.Fatal("rejections corrupted accepted accounting")
	}
	if stats.TUN.DropsQueueFull != 0 {
		t.Fatalf("unexpected portal TUN drops: %+v", stats.TUN)
	}

	// Never started: Stop still closes the portal and the return path, but
	// reports ErrIngressEngineNotStarted by contract.
	if err := engine.Stop(); err != nil && !errors.Is(err, ErrIngressEngineNotStarted) {
		t.Fatal(err)
	}
	if _, err := engine.writeReturnPacket(peer.peerKey, peer.ip.String(), returnPacket(peer.ip)); !errors.Is(err, virtualtun.ErrClosed) {
		t.Fatalf("stopped engine accepted plaintext: %v", err)
	}
}

func TestEngineFreshAdmissionCarriesReturnOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	peer := seedIngressPeer(t, db, "return-fresh", "return-peer-key-22222", "10.100.8.3")
	path := forwarder.NewReturnPath(func(_, _ string, p []byte) (int, error) { return len(p), nil })
	sess, be, _, err := svc.ensureBackendSessionForIngress(t.Context(), ownershipFor(peer), path)
	if err != nil {
		t.Fatal(err)
	}
	if !svc.forwarder.HasSessionRouteWithReturnPath(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), be.ID, path) {
		t.Fatal("fresh admission omitted return owner")
	}
}
