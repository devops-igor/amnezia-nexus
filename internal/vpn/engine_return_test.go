package vpn

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
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
