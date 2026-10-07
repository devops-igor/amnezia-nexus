package vpn

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
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
//
// These are DIRECT writeReturnPacket calls: they pin the callback's own
// fallback classification. The PRODUCTION-path classification contract —
// forwarder filters reject malformed/unrouted replies before this callback
// runs and classify them at the rejection sites — is pinned separately by
// TestEngineReturnClassifiesViaProductionPath (issue #389 rework 2).
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
	// No InboundDepth assertion: the upstream device.Device consumes the
	// client-facing TUN concurrently, so instantaneous depth proves nothing
	// (0 can mean already dequeued for encryption). Delivery is proven by
	// the E2E TestUpstreamReturnTCPUDPRekeysAndRoaming.
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
	// AcceptedPackets is monotonic: rejections must not have decremented it.
	// Depth is still not asserted here — same reason as above.
	if stats.AcceptedPackets != 1 {
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

// TestEngineReturnWriteConcurrent_Race verifies lockless writeReturnPacket
// scaling across multiple concurrent goroutines under -race (issue #424 round-8, Chunk 2).
func TestEngineReturnWriteConcurrent_Race(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(t.Context()); err != nil {
		t.Fatal(err)
	}
	peerKey, _ := engineKeys(t)
	peer := seedIngressPeer(t, db, "race-return", peerKey, "10.100.8.98")
	engine, err := svc.NewIngressEngine(t.Context(), "race-return-portal", []clientawg.Peer{
		{PublicKey: peer.peerKey, AllowedIP: netip.PrefixFrom(peer.ip, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], 28)
	ip := peer.ip.As4()
	copy(packet[16:20], ip[:])

	const workers = 8
	const perWorker = 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				_, _ = engine.writeReturnPacket(peer.peerKey, peer.ip.String(), packet)
			}
		}()
	}
	wg.Wait()

	stats := engine.ReturnStats()
	if stats.AcceptedPackets == 0 && stats.InjectionErrors == 0 {
		t.Fatalf("expected accounted return packets, got accepted=%d errors=%d", stats.AcceptedPackets, stats.InjectionErrors)
	}
}

func setupBenchReturnEngine(b *testing.B) (*IngressEngine, string, netip.Addr) {
	b.Helper()
	dir := b.TempDir()
	dbPath := filepath.Join(dir, "bench_vpn.db")
	db, err := database.Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		b.Fatalf("failed to open bench db: %v", err)
	}
	b.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	s1ID, _ := db.CreateServer(ctx, &models.Server{Name: "US East", Host: "198.51.100.1", Protocols: map[string]any{
		"awg": map[string]any{"public_key": "us-east-pubkey", "port": 51820},
	}})
	_, _ = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: s1ID, InterfaceName: "awg-be-1", PublicKey: "us-east-pubkey",
		PrivateKey: "us-east-privkey", Endpoint: "198.51.100.1:51820", Status: "active",
	})
	cfg := &models.VPNConfig{
		Algorithm: models.LBLeastConnections, SubnetCIDR: "10.100.0.0/16",
		Weights: map[int64]int{s1ID: 100},
	}
	vpnSvc, err := NewVPNService(db, cfg)
	if err != nil {
		b.Fatalf("NewVPNService: %v", err)
	}
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		b.Fatal(err)
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	peerKey := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	assignedIP := netip.MustParseAddr("10.100.8.99")

	uID, err := db.CreateUser(ctx, &models.User{Username: "bench", Role: "user", Enabled: true})
	if err != nil {
		b.Fatal(err)
	}
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		ID: "conn-bench", UserID: uID, ServerID: 0, Protocol: "awg", ClientID: peerKey,
		ClientParams: map[string]any{"assigned_ip": assignedIP.String()},
	})

	engine, err := vpnSvc.NewIngressEngine(b.Context(), "bench-return-portal", []clientawg.Peer{
		{PublicKey: peerKey, AllowedIP: netip.PrefixFrom(assignedIP, 32)},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = engine.Stop() })
	return engine, peerKey, assignedIP
}

// BenchmarkWriteReturnPacket_Concurrent verifies lockless throughput scaling
// of writeReturnPacket under concurrent submission from multiple goroutines
// (issue #424 round-8 remediation, Chunk 2).
func BenchmarkWriteReturnPacket_Concurrent(b *testing.B) {
	engine, peerKey, assignedIP := setupBenchReturnEngine(b)

	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], 28)
	ip := assignedIP.As4()
	copy(packet[16:20], ip[:])

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = engine.writeReturnPacket(peerKey, assignedIP.String(), packet)
		}
	})
}
