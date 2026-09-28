package vpn

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
)

// replyPacket builds a backend→client IPv4 reply whose destination is dst.
func replyPacket(dst netip.Addr) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[9] = 17 // UDP
	binary.BigEndian.PutUint16(p[2:4], 28)
	ip := dst.As4()
	copy(p[16:20], ip[:])
	return p
}

// TestEngineReturnClassifiesViaProductionPath pins the production-path
// classification contract (issue #389 rework 2): the backend reader's entry
// point (Forwarder.RouteBackendToClient) rejects malformed and unrouted
// replies BEFORE the engine's write callback runs, so the forwarder
// classifies those rejections itself through the registered classifier and
// the engine counters move even though writeReturnPacket never sees those
// packets.
//
// Reviewer-probe parity: one malformed reply + one unrouted reply submitted
// through the production path must produce engine MalformedDrops==1 and
// UnmappedDrops==1 (the reviewer's probe previously showed 0/0 with the
// forwarder's no-route counter +2). The single-owner rule guarantees no
// double-counting: the write callback classifies ONLY the packets the
// filters passed to it.
func TestEngineReturnClassifiesViaProductionPath(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	// NewIngressEngine fail-closed validates real upstream keys, so this
	// test mints an actual X25519 identity and seeds the matching durable
	// lease — same fail-closed construction as the seam-level test.
	peerKey, _ := engineKeys(t)
	peer := seedIngressPeer(t, db, "return-classify-prod", peerKey, "10.100.8.4")
	engine, err := svc.NewIngressEngine(t.Context(), "return-classify-prod-portal", []clientawg.Peer{
		{PublicKey: peer.peerKey, AllowedIP: netip.PrefixFrom(peer.ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	// Bind the engine's return path to the route exactly as production
	// admission does, so route.returnPath is set and the forwarder's
	// return-path filter guards this route.
	if _, err := svc.forwarder.TryRegisterSessionWithReturnPath("sess-prod-classify", peer.connID, peer.peerKey, peer.ip.String(), 1, 0, 0, engine.returnPath); err != nil {
		t.Fatal(err)
	}
	svc.forwarder.StartPumps(t.Context())
	t.Cleanup(svc.forwarder.StopPumps)

	before := engine.ReturnStats()

	// Reviewer probe 1: one MALFORMED reply for the owned route. The shape
	// filter rejects it before the engine's write callback can classify it.
	malformed := replyPacket(peer.ip)
	malformed[0] = 0x65 // bad IP version
	if err := svc.forwarder.RouteBackendToClient(1, malformed, peer.ip.String()); err == nil {
		t.Fatal("malformed reply accepted by the production path")
	}

	// Reviewer probe 2: one UNROUTED reply — no route holds 192.0.2.53.
	if err := svc.forwarder.RouteBackendToClient(1, replyPacket(netip.MustParseAddr("192.0.2.53")), "192.0.2.53"); err == nil {
		t.Fatal("unrouted reply accepted by the production path")
	}

	after := engine.ReturnStats()
	if got := after.MalformedDrops - before.MalformedDrops; got != 1 {
		t.Fatalf("MalformedDrops delta = %d, want 1 (production-path classification broken)", got)
	}
	if got := after.UnmappedDrops - before.UnmappedDrops; got != 1 {
		t.Fatalf("UnmappedDrops delta = %d, want 1 (production-path classification broken)", got)
	}
	if got := after.AcceptedPackets - before.AcceptedPackets; got != 0 {
		t.Fatalf("AcceptedPackets delta = %d, want 0", got)
	}
	if got := after.OwnershipMismatchDrops - before.OwnershipMismatchDrops; got != 0 {
		t.Fatalf("OwnershipMismatchDrops delta = %d, want 0", got)
	}

	// Single-owner parity on the forwarder side: exactly the two filter
	// rejections are counted, and nothing was queued for the client.
	queueFull, noRoute, total := svc.forwarder.DropStats()
	if noRoute != 2 || total != 2 || queueFull != 0 {
		t.Fatalf("forwarder DropStats = (queueFull=%d, noRoute=%d, total=%d), want (0, 2, 2)", queueFull, noRoute, total)
	}

	// No double-count on the write path: the classifier and the write
	// callback own disjoint populations, so nothing queued for the client
	// may carry a drop classification. The delivery leg (write callback ->
	// portal TUN) is asynchronous — delivery itself is covered by the E2E
	// return-path suite, not asserted here on a timer.
	svc.forwarder.RouteBackendToClient(1, replyPacket(peer.ip), peer.ip.String()) //nolint:errcheck // queue admission is best-effort here; classified counters above are the contract
	final := engine.ReturnStats()
	if final.MalformedDrops != after.MalformedDrops || final.UnmappedDrops != after.UnmappedDrops ||
		final.OwnershipMismatchDrops != after.OwnershipMismatchDrops {
		t.Fatal("a queued reply was misclassified as a drop")
	}
}
