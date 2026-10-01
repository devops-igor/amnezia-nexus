package vpn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

// rollbackSinkDevice captures packets routed to a backend or peer device
// for deterministic verification.
type rollbackSinkDevice struct {
	mu      sync.Mutex
	packets [][]byte
}

func (d *rollbackSinkDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := make([]byte, len(p))
	copy(cp, p)
	d.packets = append(d.packets, cp)
	return len(p), nil
}

func (d *rollbackSinkDevice) Read(p []byte) (int, error)   { return 0, io.EOF }
func (d *rollbackSinkDevice) Close() error                 { return nil }
func (d *rollbackSinkDevice) LastHandshakeTime() time.Time { return time.Time{} }
func (d *rollbackSinkDevice) CreatedAt() time.Time         { return time.Time{} }
func (d *rollbackSinkDevice) DroppedPackets() uint64       { return 0 }
func (d *rollbackSinkDevice) IsClosed() bool               { return false }

func (d *rollbackSinkDevice) packetCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.packets)
}

func (d *rollbackSinkDevice) awaitPacketCount(target int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if d.packetCount() >= target {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return d.packetCount() >= target
}

func (d *rollbackSinkDevice) lastPacket() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.packets) == 0 {
		return nil
	}
	res := make([]byte, len(d.packets[len(d.packets)-1]))
	copy(res, d.packets[len(d.packets)-1])
	return res
}

// TestDualEngine_SameDBSamePortSameConfigRollback implements the end-to-end integration
// verification required by PR 393-C: proving that a service can transition from
// custom -> upstream -> custom across fresh Service instances backed by the EXACT SAME
// database, binding the EXACT SAME UDP port, and serving the EXACT SAME frozen client
// configuration without key rotation, IP reassignment, or database migrations.
func TestDualEngine_SameDBSamePortSameConfigRollback(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)

	// =========================================================================
	// Phase 0: Setup, Database Seeding, and Client Config Freezing
	// =========================================================================

	// Seed service with full AmneziaWG obfuscation options. This populates
	// servers, backends, and portal identity with an ephemeral localhost port.
	svc1 := newIngressEngineService(t, db, fullAmneziaWGOpts())

	initialListenPort := svc1.cfg.ListenPort
	if initialListenPort <= 0 {
		t.Fatalf("expected positive listen port, got %d", initialListenPort)
	}
	initialPublicEndpoint := svc1.cfg.PublicEndpoint
	initialPortalPubKey := svc1.portalPubKey
	initialPortalPrivKey := svc1.portalPrivKey
	if initialPortalPubKey == "" || initialPortalPrivKey == "" {
		t.Fatal("expected non-empty initial portal keypair")
	}

	// Register a test user and connection with pre-generated client AWG credentials
	peer, rawConfig := newEnginePeer(t, svc1, db, "rollback-user")
	initialAssignedIP := peer.assignedIP
	initialClientPubKey := peer.publicKey
	initialClientPrivKey := peer.privateKey

	if initialAssignedIP == "" || initialClientPubKey == "" || initialClientPrivKey == "" {
		t.Fatal("expected non-empty peer credentials and assigned IP")
	}

	var initialConnectionID string
	row := db.QueryRowContext(ctx, "SELECT id FROM user_connections WHERE client_id = ?", initialClientPubKey)
	if err := row.Scan(&initialConnectionID); err != nil {
		t.Fatalf("query user_connection id: %v", err)
	}

	// Freeze client configuration: calculate SHA-256 digest
	frozenConfigHash := sha256.Sum256([]byte(rawConfig))
	frozenHashHex := hex.EncodeToString(frozenConfigHash[:])

	// Validate config fields through FreezeAndRedactConfig manifest
	manifest, err := FreezeAndRedactConfig(rawConfig, initialClientPubKey, initialAssignedIP, initialListenPort)
	if err != nil {
		t.Fatalf("FreezeAndRedactConfig failed: %v", err)
	}
	if manifest.RenderedConfigHash != frozenHashHex {
		t.Fatalf("manifest hash mismatch: got %s, want %s", manifest.RenderedConfigHash, frozenHashHex)
	}
	if manifest.ClientPublicKey != initialClientPubKey {
		t.Fatalf("manifest client pubkey mismatch: got %s, want %s", manifest.ClientPublicKey, initialClientPubKey)
	}
	if manifest.AssignedIP != initialAssignedIP {
		t.Fatalf("manifest assigned IP mismatch: got %s, want %s", manifest.AssignedIP, initialAssignedIP)
	}
	if manifest.ServerPort != initialListenPort {
		t.Fatalf("manifest server port mismatch: got %d, want %d", manifest.ServerPort, initialListenPort)
	}

	// Verify exact config fields
	if priv := configField(t, rawConfig, "PrivateKey"); priv != initialClientPrivKey {
		t.Fatalf("config PrivateKey mismatch: got %s, want %s", priv, initialClientPrivKey)
	}
	if pub := configField(t, rawConfig, "PublicKey"); pub != initialPortalPubKey {
		t.Fatalf("config PublicKey mismatch: got %s, want %s", pub, initialPortalPubKey)
	}
	if addr := configField(t, rawConfig, "Address"); addr != initialAssignedIP+"/32" {
		t.Fatalf("config Address mismatch: got %s, want %s/32", addr, initialAssignedIP)
	}
	if ep := configField(t, rawConfig, "Endpoint"); ep != fmt.Sprintf("127.0.0.1:%d", initialListenPort) {
		t.Fatalf("config Endpoint mismatch: got %s, want 127.0.0.1:%d", ep, initialListenPort)
	}

	// Query available backends and sort deterministically
	if err := svc1.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("svc1 pool.SyncFromDB: %v", err)
	}
	backends := svc1.pool.ListTunnels()
	if len(backends) == 0 {
		t.Fatal("expected at least 1 backend tunnel")
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].ID < backends[j].ID })

	// Track ReturnRouteOwner transitions: must progress strictly:
	// none -> custom -> none -> upstream -> none -> custom -> none
	var ownerTransitions []string

	// Mock probe function for restarted services
	mockProbe := func(ctx context.Context, endpoint string, serverPubKey string, clientPrivKey string, psk string, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	}

	// Helper to verify database integrity
	assertDBIntegrity := func(stage string) {
		t.Helper()
		var integrityResult string
		row := db.QueryRowContext(ctx, "PRAGMA integrity_check;")
		if err := row.Scan(&integrityResult); err != nil {
			t.Fatalf("[%s] PRAGMA integrity_check query failed: %v", stage, err)
		}
		if integrityResult != "ok" {
			t.Fatalf("[%s] PRAGMA integrity_check reported corruption: %q", stage, integrityResult)
		}

		var count int
		row = db.QueryRowContext(ctx, "SELECT count(*) FROM user_connections WHERE client_id = ?", initialClientPubKey)
		if err := row.Scan(&count); err != nil {
			t.Fatalf("[%s] count user_connections: %v", stage, err)
		}
		if count != 1 {
			t.Fatalf("[%s] expected exactly 1 user_connection for peer, got %d", stage, count)
		}
	}

	assertDBIntegrity("pre-flight")

	// =========================================================================
	// Step 1: Custom Engine (Baseline)
	// =========================================================================
	t.Log("=== Step 1: Starting Service 1 in Custom Engine Mode ===")
	t.Setenv("VPN_CLIENT_AWG_ENGINE", ClientAWGEngineCustom)
	if err := svc1.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
		t.Fatalf("svc1.SetClientAWGEngine(custom): %v", err)
	}
	if err := svc1.Start(ctx); err != nil {
		t.Fatalf("svc1.Start failed: %v", err)
	}

	// Verify initial state before traffic
	ownerTransitions = append(ownerTransitions, svc1.forwarder.ReturnRouteOwner())
	if svc1.forwarder.ReturnRouteOwner() != "none" {
		t.Fatalf("svc1 before traffic: expected ReturnRouteOwner 'none', got %q", svc1.forwarder.ReturnRouteOwner())
	}
	stat1, err := svc1.GetStatus(ctx)
	if err != nil {
		t.Fatalf("svc1.GetStatus: %v", err)
	}
	if stat1.ConfiguredEngine != ClientAWGEngineCustom || stat1.ActiveEngine != ClientAWGEngineCustom {
		t.Fatalf("svc1 status engine mismatch: configured=%s, active=%s", stat1.ConfiguredEngine, stat1.ActiveEngine)
	}
	if stat1.ListenPort != initialListenPort {
		t.Fatalf("svc1 listen port changed: got %d, want %d", stat1.ListenPort, initialListenPort)
	}

	// Attach backend recording sink to all available tunnels
	sink1 := &rollbackSinkDevice{}
	for _, b := range backends {
		svc1.forwarder.AttachBackendDevice(b.ID, sink1)
	}

	// Attach client return sink
	clientSink1 := &rollbackSinkDevice{}
	svc1.forwarder.AttachPeerDevice(initialClientPubKey, clientSink1)

	// Client admission in custom mode
	sess1, be1, err := svc1.HandleIncomingPeer(ctx, initialClientPubKey)
	if err != nil {
		t.Fatalf("svc1.HandleIncomingPeer: %v", err)
	}
	if sess1.AssignedIP != initialAssignedIP {
		t.Fatalf("svc1 admitted IP %s != frozen %s", sess1.AssignedIP, initialAssignedIP)
	}
	if be1 == nil || be1.ID <= 0 {
		t.Fatalf("svc1 admitted invalid backend: %+v", be1)
	}
	if !svc1.forwarder.HasSessionRoute(initialClientPubKey, sess1.ID, initialConnectionID, initialAssignedIP, be1.ID) {
		t.Fatal("svc1 forwarder route not registered")
	}

	// Bidirectional Packet Flow (Client -> Backend)
	clientPkt1 := engineUDPPacket(netip.MustParseAddr(initialAssignedIP), netip.MustParseAddr("198.51.100.1"), 0x1101)
	if err := svc1.forwarder.RouteClientToBackend(initialClientPubKey, clientPkt1); err != nil {
		t.Fatalf("svc1 RouteClientToBackend: %v", err)
	}
	if !sink1.awaitPacketCount(1, 2*time.Second) {
		t.Fatalf("svc1 backend sink expected 1 packet, got %d", sink1.packetCount())
	}
	if !bytes.Equal(sink1.lastPacket(), clientPkt1) {
		t.Fatal("svc1 backend sink payload corrupted")
	}

	// Bidirectional Packet Flow (Backend -> Client)
	returnPkt1 := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr(initialAssignedIP), 0x1102)
	if err := svc1.forwarder.RouteBackendToClient(be1.ID, returnPkt1, initialAssignedIP); err != nil {
		t.Fatalf("svc1 RouteBackendToClient: %v", err)
	}

	// Verify owner transition to custom
	ownerTransitions = append(ownerTransitions, svc1.forwarder.ReturnRouteOwner())
	if svc1.forwarder.ReturnRouteOwner() != ClientAWGEngineCustom {
		t.Fatalf("svc1 expected ReturnRouteOwner custom, got %q", svc1.forwarder.ReturnRouteOwner())
	}
	stat1After, _ := svc1.GetStatus(ctx)
	if stat1After.ReturnRouteOwner != ClientAWGEngineCustom {
		t.Fatalf("svc1 status return route owner expected custom, got %q", stat1After.ReturnRouteOwner)
	}

	// Assert portal public/private keys and client assigned IP match frozen state
	if svc1.portalPubKey != initialPortalPubKey || svc1.portalPrivKey != initialPortalPrivKey {
		t.Fatal("svc1 portal keypair mutated during execution")
	}

	// Clean shutdown of Service 1
	if err := svc1.Stop(); err != nil {
		t.Fatalf("svc1.Stop: %v", err)
	}
	ownerTransitions = append(ownerTransitions, svc1.forwarder.ReturnRouteOwner())

	_, _, active1 := svc1.forwarder.GetStats()
	if active1 != 0 {
		t.Fatalf("svc1 after stop: expected 0 active routes, got %d", active1)
	}
	occ1, _, _ := svc1.forwarder.AggregateQueueStats()
	if occ1 != 0 {
		t.Fatalf("svc1 after stop: expected 0 queue occupancy, got %d", occ1)
	}
	if svc1.forwarder.ReturnRouteOwner() != "none" {
		t.Fatalf("svc1 after stop: expected ReturnRouteOwner 'none', got %q", svc1.forwarder.ReturnRouteOwner())
	}
	stat1Stopped, _ := svc1.GetStatus(ctx)
	if stat1Stopped.ActiveEngine != "none" || stat1Stopped.EngineRunning {
		t.Fatalf("svc1 after stop: active_engine=%s, running=%v", stat1Stopped.ActiveEngine, stat1Stopped.EngineRunning)
	}

	assertDBIntegrity("post-step-1")

	// =========================================================================
	// Step 2: Custom -> Upstream Cutover
	// =========================================================================
	t.Log("=== Step 2: Starting Service 2 in Upstream Engine Mode (Cutover) ===")
	t.Setenv("VPN_CLIENT_AWG_ENGINE", ClientAWGEngineUpstream)

	// Create fresh Service against the EXACT SAME database
	svc2, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService for svc2 failed: %v", err)
	}
	svc2.SetProbeFunc(mockProbe)

	// Assert listen port, portal keys, and endpoint are 100% identical from DB
	if svc2.cfg.ListenPort != initialListenPort {
		t.Fatalf("svc2 listen port mismatch: got %d, want %d", svc2.cfg.ListenPort, initialListenPort)
	}
	if svc2.cfg.PublicEndpoint != initialPublicEndpoint {
		t.Fatalf("svc2 public endpoint mismatch: got %s, want %s", svc2.cfg.PublicEndpoint, initialPublicEndpoint)
	}
	if svc2.portalPubKey != initialPortalPubKey || svc2.portalPrivKey != initialPortalPrivKey {
		t.Fatalf("svc2 portal keys mismatch: pub=%s, priv=%s", svc2.portalPubKey, svc2.portalPrivKey)
	}

	// Verify frozen client configuration digest remains 100% identical
	if sum := sha256.Sum256([]byte(rawConfig)); sum != frozenConfigHash {
		t.Fatalf("client config digest mutated before cutover: got %x, want %x", sum, frozenConfigHash)
	}

	if err := svc2.SetClientAWGEngine(ClientAWGEngineUpstream); err != nil {
		t.Fatalf("svc2.SetClientAWGEngine(upstream): %v", err)
	}
	if err := svc2.Start(ctx); err != nil {
		t.Fatalf("svc2.Start failed: %v", err)
	}

	// Verify initial state before traffic
	ownerTransitions = append(ownerTransitions, svc2.forwarder.ReturnRouteOwner())
	if svc2.forwarder.ReturnRouteOwner() != "none" {
		t.Fatalf("svc2 before traffic: expected ReturnRouteOwner 'none', got %q", svc2.forwarder.ReturnRouteOwner())
	}
	stat2, err := svc2.GetStatus(ctx)
	if err != nil {
		t.Fatalf("svc2.GetStatus: %v", err)
	}
	if stat2.ConfiguredEngine != ClientAWGEngineUpstream || stat2.ActiveEngine != ClientAWGEngineUpstream {
		t.Fatalf("svc2 status engine mismatch: configured=%s, active=%s", stat2.ConfiguredEngine, stat2.ActiveEngine)
	}
	if stat2.ListenPort != initialListenPort {
		t.Fatalf("svc2 listen port changed: got %d, want %d", stat2.ListenPort, initialListenPort)
	}

	engine2 := svc2.IngressEngine()
	if engine2 == nil || !engine2.Running() {
		t.Fatal("svc2 expected running IngressEngine")
	}
	if engine2.returnPath == nil {
		t.Fatal("svc2 expected non-nil engine ReturnPath")
	}

	// Attach backend recording sink to all available tunnels
	sink2 := &rollbackSinkDevice{}
	for _, b := range backends {
		svc2.forwarder.AttachBackendDevice(b.ID, sink2)
	}

	// Ingress session admission and client packet routing via IngressEngine.Router
	clientPkt2 := engineUDPPacket(netip.MustParseAddr(initialAssignedIP), netip.MustParseAddr("198.51.100.1"), 0x2201)
	if err := engine2.Router().HandlePacket(clientPkt2); err != nil {
		t.Fatalf("svc2 engine.Router.HandlePacket failed: %v", err)
	}

	// Verify packet reached backend sink
	if !sink2.awaitPacketCount(1, 2*time.Second) {
		t.Fatalf("svc2 backend sink expected 1 packet, got %d", sink2.packetCount())
	}
	if !bytes.Equal(sink2.lastPacket(), clientPkt2) {
		t.Fatal("svc2 backend sink payload corrupted")
	}

	// Verify session and route were admitted under upstream ReturnPath
	sess2, ok := svc2.sessionMgr.GetSessionSnapshotByPeer(initialClientPubKey)
	if !ok {
		t.Fatal("svc2 expected active session for peer")
	}
	if sess2.AssignedIP != initialAssignedIP {
		t.Fatalf("svc2 session IP %s != frozen %s", sess2.AssignedIP, initialAssignedIP)
	}
	if !svc2.forwarder.HasSessionRouteWithReturnPath(initialClientPubKey, sess2.ID, initialConnectionID, initialAssignedIP, sess2.BackendTunnelID, engine2.returnPath) {
		t.Fatal("svc2 forwarder route with returnPath missing")
	}

	// Bidirectional Packet Flow (Backend -> Client via ReturnPath)
	returnPkt2 := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr(initialAssignedIP), 0x2202)
	if err := svc2.forwarder.RouteBackendToClient(sess2.BackendTunnelID, returnPkt2, initialAssignedIP); err != nil {
		t.Fatalf("svc2 RouteBackendToClient: %v", err)
	}

	// Verify owner transition to upstream
	ownerTransitions = append(ownerTransitions, svc2.forwarder.ReturnRouteOwner())
	if svc2.forwarder.ReturnRouteOwner() != ClientAWGEngineUpstream {
		t.Fatalf("svc2 expected ReturnRouteOwner upstream, got %q", svc2.forwarder.ReturnRouteOwner())
	}
	stat2After, _ := svc2.GetStatus(ctx)
	if stat2After.ReturnRouteOwner != ClientAWGEngineUpstream {
		t.Fatalf("svc2 status return route owner expected upstream, got %q", stat2After.ReturnRouteOwner)
	}

	// Assert portal public/private keys, client assigned IP, and config hash unchanged
	if svc2.portalPubKey != initialPortalPubKey || svc2.portalPrivKey != initialPortalPrivKey {
		t.Fatal("svc2 portal keypair mutated during upstream cutover")
	}
	if sum := sha256.Sum256([]byte(rawConfig)); sum != frozenConfigHash {
		t.Fatalf("client config digest mutated during upstream execution: got %x, want %x", sum, frozenConfigHash)
	}

	// Clean shutdown of Service 2
	if err := svc2.Stop(); err != nil {
		t.Fatalf("svc2.Stop: %v", err)
	}
	ownerTransitions = append(ownerTransitions, svc2.forwarder.ReturnRouteOwner())

	_, _, active2 := svc2.forwarder.GetStats()
	if active2 != 0 {
		t.Fatalf("svc2 after stop: expected 0 active routes, got %d", active2)
	}
	occ2, _, _ := svc2.forwarder.AggregateQueueStats()
	if occ2 != 0 {
		t.Fatalf("svc2 after stop: expected 0 queue occupancy, got %d", occ2)
	}
	if svc2.forwarder.ReturnRouteOwner() != "none" {
		t.Fatalf("svc2 after stop: expected ReturnRouteOwner 'none', got %q", svc2.forwarder.ReturnRouteOwner())
	}
	stat2Stopped, _ := svc2.GetStatus(ctx)
	if stat2Stopped.ActiveEngine != "none" || stat2Stopped.EngineRunning {
		t.Fatalf("svc2 after stop: active_engine=%s, running=%v", stat2Stopped.ActiveEngine, stat2Stopped.EngineRunning)
	}

	assertDBIntegrity("post-step-2")

	// =========================================================================
	// Step 3: Upstream -> Custom Rollback
	// =========================================================================
	t.Log("=== Step 3: Starting Service 3 in Custom Engine Mode (Rollback) ===")
	t.Setenv("VPN_CLIENT_AWG_ENGINE", ClientAWGEngineCustom)

	// Create fresh Service against the EXACT SAME database
	svc3, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService for svc3 failed: %v", err)
	}
	svc3.SetProbeFunc(mockProbe)

	// Assert listen port, portal keys, and endpoint remain 100% identical
	if svc3.cfg.ListenPort != initialListenPort {
		t.Fatalf("svc3 listen port mismatch: got %d, want %d", svc3.cfg.ListenPort, initialListenPort)
	}
	if svc3.cfg.PublicEndpoint != initialPublicEndpoint {
		t.Fatalf("svc3 public endpoint mismatch: got %s, want %s", svc3.cfg.PublicEndpoint, initialPublicEndpoint)
	}
	if svc3.portalPubKey != initialPortalPubKey || svc3.portalPrivKey != initialPortalPrivKey {
		t.Fatalf("svc3 portal keys mismatch: pub=%s, priv=%s", svc3.portalPubKey, svc3.portalPrivKey)
	}

	// Verify frozen client configuration digest remains 100% identical
	if sum := sha256.Sum256([]byte(rawConfig)); sum != frozenConfigHash {
		t.Fatalf("client config digest mutated before rollback: got %x, want %x", sum, frozenConfigHash)
	}

	if err := svc3.SetClientAWGEngine(ClientAWGEngineCustom); err != nil {
		t.Fatalf("svc3.SetClientAWGEngine(custom): %v", err)
	}
	if err := svc3.Start(ctx); err != nil {
		t.Fatalf("svc3.Start failed: %v", err)
	}

	// Verify initial state before traffic
	ownerTransitions = append(ownerTransitions, svc3.forwarder.ReturnRouteOwner())
	if svc3.forwarder.ReturnRouteOwner() != "none" {
		t.Fatalf("svc3 before traffic: expected ReturnRouteOwner 'none', got %q", svc3.forwarder.ReturnRouteOwner())
	}
	stat3, err := svc3.GetStatus(ctx)
	if err != nil {
		t.Fatalf("svc3.GetStatus: %v", err)
	}
	if stat3.ConfiguredEngine != ClientAWGEngineCustom || stat3.ActiveEngine != ClientAWGEngineCustom {
		t.Fatalf("svc3 status engine mismatch: configured=%s, active=%s", stat3.ConfiguredEngine, stat3.ActiveEngine)
	}
	if stat3.ListenPort != initialListenPort {
		t.Fatalf("svc3 listen port changed: got %d, want %d", stat3.ListenPort, initialListenPort)
	}

	// Attach backend recording sink to all available tunnels
	sink3 := &rollbackSinkDevice{}
	for _, b := range backends {
		svc3.forwarder.AttachBackendDevice(b.ID, sink3)
	}

	// Attach client return sink
	clientSink3 := &rollbackSinkDevice{}
	svc3.forwarder.AttachPeerDevice(initialClientPubKey, clientSink3)

	// Client admission in rolled-back custom mode (using EXACT SAME frozen credentials)
	sess3, be3, err := svc3.HandleIncomingPeer(ctx, initialClientPubKey)
	if err != nil {
		t.Fatalf("svc3.HandleIncomingPeer: %v", err)
	}
	if sess3.AssignedIP != initialAssignedIP {
		t.Fatalf("svc3 admitted IP %s != frozen %s", sess3.AssignedIP, initialAssignedIP)
	}
	if be3 == nil || be3.ID <= 0 {
		t.Fatalf("svc3 admitted invalid backend: %+v", be3)
	}
	if !svc3.forwarder.HasSessionRoute(initialClientPubKey, sess3.ID, initialConnectionID, initialAssignedIP, be3.ID) {
		t.Fatal("svc3 forwarder route not registered")
	}

	// Bidirectional Packet Flow (Client -> Backend)
	clientPkt3 := engineUDPPacket(netip.MustParseAddr(initialAssignedIP), netip.MustParseAddr("198.51.100.1"), 0x3301)
	if err := svc3.forwarder.RouteClientToBackend(initialClientPubKey, clientPkt3); err != nil {
		t.Fatalf("svc3 RouteClientToBackend: %v", err)
	}
	if !sink3.awaitPacketCount(1, 2*time.Second) {
		t.Fatalf("svc3 backend sink expected 1 packet, got %d", sink3.packetCount())
	}
	if !bytes.Equal(sink3.lastPacket(), clientPkt3) {
		t.Fatal("svc3 backend sink payload corrupted")
	}

	// Bidirectional Packet Flow (Backend -> Client)
	returnPkt3 := engineUDPPacket(netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr(initialAssignedIP), 0x3302)
	if err := svc3.forwarder.RouteBackendToClient(be3.ID, returnPkt3, initialAssignedIP); err != nil {
		t.Fatalf("svc3 RouteBackendToClient: %v", err)
	}

	// Verify owner transition to custom
	ownerTransitions = append(ownerTransitions, svc3.forwarder.ReturnRouteOwner())
	if svc3.forwarder.ReturnRouteOwner() != ClientAWGEngineCustom {
		t.Fatalf("svc3 expected ReturnRouteOwner custom, got %q", svc3.forwarder.ReturnRouteOwner())
	}
	stat3After, _ := svc3.GetStatus(ctx)
	if stat3After.ReturnRouteOwner != ClientAWGEngineCustom {
		t.Fatalf("svc3 status return route owner expected custom, got %q", stat3After.ReturnRouteOwner)
	}

	// Assert portal public/private keys and client assigned IP match frozen state
	if svc3.portalPubKey != initialPortalPubKey || svc3.portalPrivKey != initialPortalPrivKey {
		t.Fatal("svc3 portal keypair mutated during rollback")
	}
	if sum := sha256.Sum256([]byte(rawConfig)); sum != frozenConfigHash {
		t.Fatalf("client config digest mutated during rollback execution: got %x, want %x", sum, frozenConfigHash)
	}

	// Clean shutdown of Service 3
	if err := svc3.Stop(); err != nil {
		t.Fatalf("svc3.Stop: %v", err)
	}
	ownerTransitions = append(ownerTransitions, svc3.forwarder.ReturnRouteOwner())

	_, _, active3 := svc3.forwarder.GetStats()
	if active3 != 0 {
		t.Fatalf("svc3 after stop: expected 0 active routes, got %d", active3)
	}
	occ3, _, _ := svc3.forwarder.AggregateQueueStats()
	if occ3 != 0 {
		t.Fatalf("svc3 after stop: expected 0 queue occupancy, got %d", occ3)
	}
	if svc3.forwarder.ReturnRouteOwner() != "none" {
		t.Fatalf("svc3 after stop: expected ReturnRouteOwner 'none', got %q", svc3.forwarder.ReturnRouteOwner())
	}
	stat3Stopped, _ := svc3.GetStatus(ctx)
	if stat3Stopped.ActiveEngine != "none" || stat3Stopped.EngineRunning {
		t.Fatalf("svc3 after stop: active_engine=%s, running=%v", stat3Stopped.ActiveEngine, stat3Stopped.EngineRunning)
	}

	assertDBIntegrity("post-step-3")

	// =========================================================================
	// Invariants Verified Across All Transitions
	// =========================================================================
	t.Log("=== Verifying Global Lifecycle Invariants ===")

	// 1. ReturnRouteOwner Transition Progression:
	//    none -> custom -> none -> upstream -> none -> custom -> none
	wantTransitions := []string{
		"none",     // svc1 started, no traffic
		"custom",   // svc1 traffic routed
		"none",     // svc1 stopped
		"none",     // svc2 started, no traffic
		"upstream", // svc2 traffic routed
		"none",     // svc2 stopped
		"none",     // svc3 started, no traffic
		"custom",   // svc3 traffic routed
		"none",     // svc3 stopped
	}
	if len(ownerTransitions) != len(wantTransitions) {
		t.Fatalf("owner transitions count mismatch: got %d (%v), want %d (%v)",
			len(ownerTransitions), ownerTransitions, len(wantTransitions), wantTransitions)
	}
	for i, want := range wantTransitions {
		if ownerTransitions[i] != want {
			t.Errorf("transition step [%d] mismatch: got %q, want %q", i, ownerTransitions[i], want)
		}
	}

	// 2. Client config hash unchanged from start to finish
	finalHash := sha256.Sum256([]byte(rawConfig))
	if finalHash != frozenConfigHash {
		t.Fatalf("client config SHA-256 altered: got %x, want %x", finalHash, frozenConfigHash)
	}

	// 3. Zero orphaned or closed-path routes in forwarder
	_, _, activeRoutes := svc3.forwarder.GetStats()
	if activeRoutes != 0 {
		t.Fatalf("expected 0 active routes in forwarder, got %d", activeRoutes)
	}
	if svc3.forwarder.HasRoutesForReturnPath(nil) {
		t.Fatal("expected no custom routes remaining in forwarder")
	}

	// 4. Database session restart reconciliation invariant:
	// InvalidateVPNSessionsForRestart cleanly transitions any remaining connected sessions
	// to disconnected, ensuring zero stranded connected sessions survive restart.
	invalidated, err := db.InvalidateVPNSessionsForRestart(ctx)
	if err != nil {
		t.Fatalf("InvalidateVPNSessionsForRestart: %v", err)
	}
	if invalidated != 1 {
		t.Fatalf("expected exactly 1 session invalidated on restart, got %d", invalidated)
	}

	var activeSessions int
	row = db.QueryRowContext(ctx, "SELECT count(*) FROM vpn_sessions WHERE status = 'connected';")
	if err := row.Scan(&activeSessions); err != nil {
		t.Fatalf("count connected vpn_sessions: %v", err)
	}
	if activeSessions != 0 {
		t.Fatalf("expected 0 connected sessions in DB after restart invalidation, got %d", activeSessions)
	}
}
