package vpn

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// createDummyIPv4Packet creates a minimal valid IPv4 packet with the given src and dst IP.
func createDummyIPv4Packet(srcIP, dstIP string, payload []byte) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	totalLen := 20 + len(payload)

	hdr := make([]byte, totalLen)
	hdr[0] = 0x45 // Version 4, IHL 5
	hdr[1] = 0x00 // TOS
	hdr[2] = byte(totalLen >> 8)
	hdr[3] = byte(totalLen & 0xff)
	hdr[8] = 64   // TTL
	hdr[9] = 0x11 // Protocol UDP
	copy(hdr[12:16], src)
	copy(hdr[16:20], dst)
	copy(hdr[20:], payload)
	return hdr
}

// TestVPNRebalanceLiveMigration verifies that MigrateSession coordinates the live forwarder route,
// in-memory session, database row, tunnel pool counters, and sticky affinity (issue #289).
func TestVPNRebalanceLiveMigration(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel(s1ID) failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel(s2ID) failed: %v", err)
	}

	assignedIP := "10.100.0.15"

	// 1. Create active session on Backend 1
	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tun1.ID, "alice-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 2. Register live forwarder route pointing to Backend 1
	svc.forwarder.RegisterSession(sess.ID, "conn-alice", peerKeyAlice, assignedIP, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)
	svc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tun1.ID)

	q1, ok := svc.forwarder.GetBackendPacketChannel(tun1.ID)
	if !ok {
		t.Fatalf("failed to get backend packet channel for tun1 (%d)", tun1.ID)
	}

	// Send test packet 1 from client, verify it reaches Backend 1 queue
	pkt1 := createDummyIPv4Packet(assignedIP, "1.1.1.1", []byte("hello-be1"))
	if err := svc.forwarder.RouteClientToBackend(peerKeyAlice, pkt1); err != nil {
		t.Fatalf("RouteClientToBackend before migration failed: %v", err)
	}
	select {
	case received := <-q1:
		if !bytes.Equal(received, pkt1) {
			t.Errorf("packet mismatch on backend 1 queue")
		}
	default:
		t.Fatalf("expected packet on backend 1 queue, but channel was empty")
	}

	// 3. Migrate session from Backend 1 to Backend 2
	if err := svc.MigrateSession(ctx, sess.ID, tun2.ID); err != nil {
		t.Fatalf("MigrateSession failed: %v", err)
	}

	// 4. Verify live forwarder route migrated to Backend 2
	q2, ok := svc.forwarder.GetBackendPacketChannel(tun2.ID)
	if !ok {
		t.Fatalf("failed to get backend packet channel for tun2 (%d)", tun2.ID)
	}

	pkt2 := createDummyIPv4Packet(assignedIP, "1.1.1.1", []byte("hello-be2"))
	if err := svc.forwarder.RouteClientToBackend(peerKeyAlice, pkt2); err != nil {
		t.Fatalf("RouteClientToBackend after migration failed: %v", err)
	}

	// Verify Backend 2 queue received pkt2
	select {
	case received := <-q2:
		if !bytes.Equal(received, pkt2) {
			t.Errorf("packet mismatch on backend 2 queue")
		}
	default:
		t.Fatalf("expected packet on backend 2 queue after migration, but channel was empty")
	}

	// Verify Backend 1 queue has no unexpected packets
	select {
	case unexpected := <-q1:
		t.Fatalf("unexpected packet received on old backend 1 queue: %v", unexpected)
	default:
	}

	// 5. Verify in-memory session in SessionManager
	snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("session %s not found in SessionManager", sess.ID)
	}
	if snap.BackendTunnelID != tun2.ID {
		t.Errorf("SessionManager BackendTunnelID = %d, want %d", snap.BackendTunnelID, tun2.ID)
	}
	if snap.Status != "draining" {
		t.Errorf("SessionManager Status = %q, want 'draining'", snap.Status)
	}

	// 6. Verify DB persistence
	dbSessions, err := db.GetVPNSessionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetVPNSessionsByUserID failed: %v", err)
	}
	if len(dbSessions) == 0 {
		t.Fatalf("no session rows found in DB for user %s", uID)
	}
	if dbSessions[0].BackendTunnelID != tun2.ID {
		t.Errorf("DB session backend_tunnel_id = %d, want %d", dbSessions[0].BackendTunnelID, tun2.ID)
	}
	if dbSessions[0].Status != "draining" {
		t.Errorf("DB session status = %q, want 'draining'", dbSessions[0].Status)
	}

	// 7. Verify pool counters
	tun1Live, err := svc.pool.GetTunnelByID(tun1.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(tun1) failed: %v", err)
	}
	if tun1Live.ActiveConnections != 0 {
		t.Errorf("tun1 ActiveConnections = %d, want 0", tun1Live.ActiveConnections)
	}

	tun2Live, err := svc.pool.GetTunnelByID(tun2.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(tun2) failed: %v", err)
	}
	if tun2Live.ActiveConnections != 1 {
		t.Errorf("tun2 ActiveConnections = %d, want 1", tun2Live.ActiveConnections)
	}

	// 8. Verify sticky affinity
	selected, _, err := svc.stickyMgr.GetOrAssignBackend(ctx, &loadbalancer.RoutingRequest{
		PeerPublicKey:    peerKeyAlice,
		AvailableTunnels: []*models.BackendTunnel{tun1Live, tun2Live},
	})
	if err != nil {
		t.Fatalf("GetOrAssignBackend failed: %v", err)
	}
	if selected.ID != tun2.ID {
		t.Errorf("sticky peer affinity returned tunnel %d, want %d", selected.ID, tun2.ID)
	}
}

// TestVPNRebalanceRollbackOnDBFailure verifies that if the database write fails during migration,
// live forwarder route and in-memory session are restored to the old backend, and pool counters are untouched (issue #289).
func TestVPNRebalanceRollbackOnDBFailure(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel(s1ID) failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel(s2ID) failed: %v", err)
	}

	assignedIP := "10.100.0.16"

	// Create session on Backend 1
	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tun1.ID, "alice-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	svc.forwarder.RegisterSession(sess.ID, "conn-alice", peerKeyAlice, assignedIP, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	// Simulate DB failure by passing a canceled context
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel() // cancel immediately

	err = svc.MigrateSession(canceledCtx, sess.ID, tun2.ID)
	if err == nil {
		t.Fatal("expected MigrateSession to fail with canceled context")
	}

	// 1. Verify forwarder route rolled back to Backend 1
	q1, _ := svc.forwarder.GetBackendPacketChannel(tun1.ID)
	q2, _ := svc.forwarder.GetBackendPacketChannel(tun2.ID)

	pkt := createDummyIPv4Packet(assignedIP, "1.1.1.1", []byte("rollback-check"))
	if err := svc.forwarder.RouteClientToBackend(peerKeyAlice, pkt); err != nil {
		t.Fatalf("RouteClientToBackend after rollback failed: %v", err)
	}

	select {
	case received := <-q1:
		if !bytes.Equal(received, pkt) {
			t.Errorf("packet mismatch on backend 1 queue after rollback")
		}
	default:
		t.Fatalf("expected packet on backend 1 queue after rollback, but was empty")
	}

	select {
	case unexpected := <-q2:
		t.Fatalf("unexpected packet received on backend 2 queue after rollback: %v", unexpected)
	default:
	}

	// 2. Verify in-memory session restored in SessionManager
	snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("session %s not found in SessionManager", sess.ID)
	}
	if snap.BackendTunnelID != tun1.ID {
		t.Errorf("SessionManager BackendTunnelID after rollback = %d, want %d", snap.BackendTunnelID, tun1.ID)
	}
	if snap.Status != "connected" {
		t.Errorf("SessionManager Status after rollback = %q, want 'connected'", snap.Status)
	}

	// 3. Verify pool counters untouched
	tun1Live, _ := svc.pool.GetTunnelByID(tun1.ID)
	if tun1Live.ActiveConnections != 1 {
		t.Errorf("tun1 ActiveConnections after rollback = %d, want 1", tun1Live.ActiveConnections)
	}
	tun2Live, _ := svc.pool.GetTunnelByID(tun2.ID)
	if tun2Live.ActiveConnections != 0 {
		t.Errorf("tun2 ActiveConnections after rollback = %d, want 0", tun2Live.ActiveConnections)
	}
}

// TestVPNReturnTrafficSurvivabilityAfterRebalance verifies that after a session is migrated
// from Backend 1 to Backend 2, in-flight return packets arriving from Backend 1 continue to be
// delivered to the client queue without dropping or ErrSessionNotRegistered (issue #289).
func TestVPNReturnTrafficSurvivabilityAfterRebalance(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel(s1ID) failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel(s2ID) failed: %v", err)
	}

	assignedIP := "10.100.0.17"

	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tun1.ID, "alice-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	svc.forwarder.RegisterSession(sess.ID, "conn-alice", peerKeyAlice, assignedIP, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	clientCh, ok := svc.forwarder.GetClientPacketChannel(peerKeyAlice)
	if !ok {
		t.Fatalf("failed to get client packet channel for %s", peerKeyAlice)
	}

	// Migrate session to Backend 2
	if err := svc.MigrateSession(ctx, sess.ID, tun2.ID); err != nil {
		t.Fatalf("MigrateSession failed: %v", err)
	}

	// Inject return packet originating from OLD Backend 1 toward client's assigned IP
	returnPayload := []byte("return-from-backend-1-after-migration")
	returnPkt := createDummyIPv4Packet("1.1.1.1", assignedIP, returnPayload)

	err = svc.forwarder.RouteBackendToClient(tun1.ID, returnPkt, assignedIP)
	if err != nil {
		t.Fatalf("RouteBackendToClient from old backend failed: %v", err)
	}

	select {
	case delivered := <-clientCh:
		if !bytes.Equal(delivered, returnPkt) {
			t.Errorf("delivered packet mismatch, got %v, want %v", delivered, returnPkt)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for return packet from old backend to reach client channel")
	}
}

// TestOrchestratorRebalanceEndToEndWithVPNService verifies that running Orchestrator.RebalanceVPNSessions
// with a live VPN service migrates the live forwarder route, session manager, DB, and counters (issue #289).
func TestOrchestratorRebalanceEndToEndWithVPNService(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, err := svc.pool.GetTunnel(s1ID)
	if err != nil {
		t.Fatalf("GetTunnel(s1ID) failed: %v", err)
	}
	tun2, err := svc.pool.GetTunnel(s2ID)
	if err != nil {
		t.Fatalf("GetTunnel(s2ID) failed: %v", err)
	}

	// Configure Orchestrator with vpnSvc as SessionMigrator
	orch := orchestrator.New(db, nil, orchestrator.WithSessionMigrator(svc))

	// Seed 9 sessions on tun1 (including alice's live session) and 1 session on tun2
	// Total 10 sessions, avg 5.0, threshold 7, excess 2 on tun1.
	assignedIPAlice := "10.100.0.18"
	aliceSess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPAlice, tun1.ID, "alice-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	svc.forwarder.RegisterSession(aliceSess.ID, "conn-alice", peerKeyAlice, assignedIPAlice, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	// Seed 8 additional sessions on tun1 in DB + SessionManager
	for i := 2; i <= 9; i++ {
		peerKey := "peer-tun1-" + string(rune('0'+i))
		ip := "10.100.0." + string(rune('0'+i+20))
		s, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, ip, tun1.ID, "bulk-conn")
		if err != nil {
			t.Fatalf("CreateSession bulk %d failed: %v", i, err)
		}
		svc.forwarder.RegisterSession(s.ID, "conn-"+peerKey, peerKey, ip, tun1.ID)
		svc.pool.IncrementConnections(tun1.ID)
	}

	// Seed 1 session on tun2
	peerKeyBob := "peer-bob-tun2"
	sBob, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyBob, "10.100.0.50", tun2.ID, "bob-conn")
	if err != nil {
		t.Fatalf("CreateSession bob failed: %v", err)
	}
	svc.forwarder.RegisterSession(sBob.ID, "conn-bob", peerKeyBob, "10.100.0.50", tun2.ID)
	svc.pool.IncrementConnections(tun2.ID)

	// Run rebalancer
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	// 2 sessions should have migrated to tun2
	tun1After, _ := svc.pool.GetTunnelByID(tun1.ID)
	tun2After, _ := svc.pool.GetTunnelByID(tun2.ID)

	if tun1After.ActiveConnections != 7 {
		t.Errorf("tun1 ActiveConnections after rebalance = %d, want 7", tun1After.ActiveConnections)
	}
	if tun2After.ActiveConnections != 3 {
		t.Errorf("tun2 ActiveConnections after rebalance = %d, want 3", tun2After.ActiveConnections)
	}

	// Verify that alice's live forwarder route now directs packets to Backend 2 queue
	q2, ok := svc.forwarder.GetBackendPacketChannel(tun2.ID)
	if !ok {
		t.Fatalf("failed to get packet channel for tun2")
	}
	pktOut := createDummyIPv4Packet(assignedIPAlice, "8.8.8.8", []byte("e2e-outbound-test"))
	if err := svc.forwarder.RouteClientToBackend(peerKeyAlice, pktOut); err != nil {
		t.Fatalf("RouteClientToBackend after orchestrator rebalance failed: %v", err)
	}
	select {
	case rec := <-q2:
		if !bytes.Equal(rec, pktOut) {
			t.Errorf("packet mismatch on backend 2 queue")
		}
	default:
		t.Fatalf("expected packet on backend 2 queue after orchestrator rebalance")
	}

	// Verify that return packet from Backend 1 still reaches alice
	clientCh, ok := svc.forwarder.GetClientPacketChannel(peerKeyAlice)
	if !ok {
		t.Fatalf("failed to get client packet channel for alice")
	}
	pktReturn := createDummyIPv4Packet("8.8.8.8", assignedIPAlice, []byte("e2e-return-from-old-be"))
	if err := svc.forwarder.RouteBackendToClient(tun1.ID, pktReturn, assignedIPAlice); err != nil {
		t.Fatalf("RouteBackendToClient failed: %v", err)
	}
	select {
	case rec := <-clientCh:
		if !bytes.Equal(rec, pktReturn) {
			t.Errorf("return packet mismatch")
		}
	default:
		t.Fatalf("expected return packet to reach client channel")
	}
}

// TestRebalanceDivergenceWithoutSessionMigrator demonstrates the original defect (issue #289):
// when no SessionMigrator is wired to Orchestrator, RebalanceVPNSessions only updates the DB
// while the live forwarder route, SessionManager, and pool counters remain stuck on the old backend.
func TestRebalanceDivergenceWithoutSessionMigrator(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tun1, _ := svc.pool.GetTunnel(s1ID)
	tun2, _ := svc.pool.GetTunnel(s2ID)

	// Orchestrator WITHOUT SessionMigrator (simulating pre-fix / uncoordinated rebalance)
	orch := orchestrator.New(db, nil)

	assignedIPAlice := "10.100.0.19"
	aliceSess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPAlice, tun1.ID, "alice-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	svc.forwarder.RegisterSession(aliceSess.ID, "conn-alice", peerKeyAlice, assignedIPAlice, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	// Seed 8 additional sessions on tun1
	for i := 2; i <= 9; i++ {
		peerKey := "peer-div-" + string(rune('0'+i))
		ip := "10.100.0." + string(rune('0'+i+20))
		s, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, ip, tun1.ID, "bulk")
		if err != nil {
			t.Fatalf("CreateSession bulk %d failed: %v", i, err)
		}
		svc.forwarder.RegisterSession(s.ID, "conn-"+peerKey, peerKey, ip, tun1.ID)
		svc.pool.IncrementConnections(tun1.ID)
	}

	// Seed 1 session on tun2
	sBob, _ := svc.sessionMgr.CreateSession(ctx, uID, "peer-div-bob", "10.100.0.60", tun2.ID, "bob")
	svc.forwarder.RegisterSession(sBob.ID, "conn-bob", "peer-div-bob", "10.100.0.60", tun2.ID)
	svc.pool.IncrementConnections(tun2.ID)

	// Trigger DB-only rebalance
	if err := orch.RebalanceVPNSessions(ctx); err != nil {
		t.Fatalf("RebalanceVPNSessions failed: %v", err)
	}

	// In DB: alice's session row was updated to tun2 (draining)
	dbSessions, err := db.GetVPNSessionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("GetVPNSessionsByUserID failed: %v", err)
	}
	var aliceDB models.VPNSession
	for _, s := range dbSessions {
		if s.ID == aliceSess.ID {
			aliceDB = s
			break
		}
	}
	if aliceDB.BackendTunnelID != tun2.ID {
		t.Errorf("DB session backend = %d, want %d", aliceDB.BackendTunnelID, tun2.ID)
	}

	// BUT without SessionMigrator:
	// 1. Live forwarder route is STILL pointing to Backend 1 (the bug)
	q1, _ := svc.forwarder.GetBackendPacketChannel(tun1.ID)
	pkt := createDummyIPv4Packet(assignedIPAlice, "8.8.8.8", []byte("divergence-test"))
	if err := svc.forwarder.RouteClientToBackend(peerKeyAlice, pkt); err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}
	select {
	case <-q1:
		// Packet still went to Backend 1 because live forwarder route was not migrated!
	default:
		t.Errorf("expected packet to be routed to old backend 1 due to divergence")
	}

	// 2. In-memory session in SessionManager is STILL pointing to Backend 1
	snap, _ := svc.sessionMgr.GetSessionSnapshotByID(aliceSess.ID)
	if snap.BackendTunnelID != tun1.ID {
		t.Errorf("SessionManager BackendTunnelID = %d, want %d (unmigrated in DB-only mode)", snap.BackendTunnelID, tun1.ID)
	}

	// 3. Pool counters were NOT migrated
	tun1Live, _ := svc.pool.GetTunnelByID(tun1.ID)
	if tun1Live.ActiveConnections != 9 {
		t.Errorf("tun1 ActiveConnections = %d, want 9 (unmigrated in DB-only mode)", tun1Live.ActiveConnections)
	}
}
