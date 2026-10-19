package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
)

func TestDisconnectUser_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	var targetTunnel *models.BackendTunnel
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			targetTunnel = tun
			break
		}
	}
	if targetTunnel == nil {
		targetTunnel = tunnels[0]
	}
	tunID := targetTunnel.ID

	sessID := "sess-disc-user-lifecycle"
	assignedIP := "10.100.0.81"
	createdSess, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(createdSess.ID, "conn-user-1", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	if err := vpnSvc.DisconnectUser(ctx, uID); err != nil {
		t.Fatalf("DisconnectUser failed: %v", err)
	}

	if _, ok := vpnSvc.sessionMgr.GetSessionByID(createdSess.ID); ok {
		t.Errorf("expected session %s to be closed in sessionMgr", createdSess.ID)
	}
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); ok {
		t.Errorf("expected forwarder route for %s to be retired", peerKeyAlice)
	}
	if _, ok := vpnSvc.stickyMgr.GetAffinity(uID); ok {
		t.Errorf("expected user affinity for %s to be cleared", uID)
	}
	if _, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); ok {
		t.Errorf("expected peer affinity for %s to be cleared", peerKeyAlice)
	}
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool connections=0, got %d (err: %v)", tunAfter.ActiveConnections, err)
	}

	if err := vpnSvc.DisconnectUser(ctx, "non-existent-user"); err != nil {
		t.Errorf("DisconnectUser non-existent user failed: %v", err)
	}
}

func TestDisconnectSession_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID

	// 1. Unknown session returns session.ErrSessionNotFound
	err := vpnSvc.DisconnectSession(ctx, "unknown-sess-id")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for unknown session, got %v", err)
	}

	// 2. Successful disconnect of active session
	sessID := "sess-disc-session-lifecycle"
	assignedIP := "10.100.0.82"
	createdSess, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(createdSess.ID, "conn-sess-1", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	if err := vpnSvc.DisconnectSession(ctx, createdSess.ID); err != nil {
		t.Fatalf("DisconnectSession failed: %v", err)
	}

	if _, ok := vpnSvc.sessionMgr.GetSessionByID(createdSess.ID); ok {
		t.Errorf("expected session %s to be closed", createdSess.ID)
	}
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); ok {
		t.Errorf("expected forwarder route to be retired")
	}
	if _, ok := vpnSvc.stickyMgr.GetAffinity(uID); ok {
		t.Errorf("expected user affinity to be cleared")
	}
	if _, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); ok {
		t.Errorf("expected peer affinity to be cleared")
	}
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool connections=0, got %d", tunAfter.ActiveConnections)
	}
}

func TestRevokeUpstreamPeerSession_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID

	// 1. Unknown peer returns nil safely
	if err := vpnSvc.RevokeUpstreamPeerSession(ctx, "unknown-peer-key"); err != nil {
		t.Fatalf("expected nil error for unknown peer, got %v", err)
	}

	// 2. Active peer session revoked
	sessID := "sess-revoke-lifecycle"
	assignedIP := "10.100.0.83"
	createdSess, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(createdSess.ID, "conn-revoke-1", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	var hookPeerKey, hookSessID string
	vpnSvc.SetPreRevokeCloseHookForTest(func(pk, sid string) {
		hookPeerKey = pk
		hookSessID = sid
	})

	if err := vpnSvc.RevokeUpstreamPeerSession(ctx, peerKeyAlice); err != nil {
		t.Fatalf("RevokeUpstreamPeerSession failed: %v", err)
	}

	if hookPeerKey != peerKeyAlice || hookSessID != createdSess.ID {
		t.Errorf("preRevokeCloseHookForTest got (%q, %q), want (%q, %q)", hookPeerKey, hookSessID, peerKeyAlice, createdSess.ID)
	}
	if _, ok := vpnSvc.sessionMgr.GetSessionByID(createdSess.ID); ok {
		t.Errorf("expected session %s to be closed", createdSess.ID)
	}
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); ok {
		t.Errorf("expected forwarder route to be retired")
	}
	if _, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); ok {
		t.Errorf("expected peer affinity to be cleared")
	}
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool connections=0, got %d", tunAfter.ActiveConnections)
	}

	// 3. Race condition: session evicted between GetSession and CloseSession
	sessID2 := "sess-revoke-race"
	assignedIP2 := "10.100.0.84"
	_, err = vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP2, tunID, sessID2)
	if err != nil {
		t.Fatalf("CreateSession 2 failed: %v", err)
	}
	vpnSvc.SetPreRevokeCloseHookForTest(func(pk, sid string) {
		_ = vpnSvc.sessionMgr.CloseSession(ctx, sid, "evicted")
	})
	if err := vpnSvc.RevokeUpstreamPeerSession(ctx, peerKeyAlice); err != nil {
		t.Errorf("expected nil when session evicted under race, got: %v", err)
	}
}

func TestReleaseClient_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID

	allocatedIP, err := vpnSvc.ipam.Allocate(peerKeyAlice)
	if err != nil {
		t.Fatalf("IPAM Allocate failed: %v", err)
	}

	sessID := "sess-release-client-lifecycle"
	createdSess, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, allocatedIP.String(), tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(createdSess.ID, "conn-rel-1", peerKeyAlice, allocatedIP.String(), tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	if _, ok := vpnSvc.ipam.GetAssignedIP(peerKeyAlice); !ok {
		t.Fatalf("expected IP to be allocated in IPAM")
	}

	if err := vpnSvc.ReleaseClient(ctx, peerKeyAlice); err != nil {
		t.Fatalf("ReleaseClient failed: %v", err)
	}

	if _, ok := vpnSvc.sessionMgr.GetSessionByID(createdSess.ID); ok {
		t.Errorf("expected session to be closed")
	}
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); ok {
		t.Errorf("expected forwarder route to be retired")
	}
	if _, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); ok {
		t.Errorf("expected peer affinity to be cleared")
	}
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool connections=0, got %d", tunAfter.ActiveConnections)
	}
	if _, ok := vpnSvc.ipam.GetAssignedIP(peerKeyAlice); ok {
		t.Errorf("expected IPAM allocation to be released")
	}

	if err := vpnSvc.ReleaseClient(ctx, ""); err != nil {
		t.Errorf("ReleaseClient(\"\") returned error: %v", err)
	}
}

func TestSweepTimedOutSessions_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}
	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatalf("expected active tunnels in pool")
	}
	tunID := tunnels[0].ID

	// 1. Test with SetSessionReaperHookForTest
	sessID1 := "sess-sweep-hook"
	assignedIP1 := "10.100.0.85"
	sess1, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP1, tunID, sessID1)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	sess1.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	var hookCalled bool
	var reapedID string
	vpnSvc.SetSessionReaperHookForTest(func(c context.Context, s *models.VPNSession) {
		hookCalled = true
		reapedID = s.ID
	})

	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sess1.ID {
		t.Fatalf("expected 1 timed out session with ID %s, got %v", sess1.ID, timedOut)
	}
	if !hookCalled || reapedID != sess1.ID {
		t.Errorf("reaper hook not called properly: called=%v, reapedID=%s", hookCalled, reapedID)
	}

	// 2. Test default path (hook=nil) invoking reapSession / reapIngressSession
	vpnSvc.SetSessionReaperHookForTest(nil)

	peerKeyBob := "peer-key-bob-sweep"
	sessID2 := "sess-sweep-default"
	assignedIP2 := "10.100.0.86"
	sess2, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyBob, assignedIP2, tunID, sessID2)
	if err != nil {
		t.Fatalf("CreateSession 2 failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sess2.ID, "conn-sweep-2", peerKeyBob, assignedIP2, tunID)
	vpnSvc.pool.IncrementConnections(tunID)
	sess2.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	timedOut2, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions default failed: %v", err)
	}
	if len(timedOut2) != 1 || timedOut2[0].ID != sess2.ID {
		t.Fatalf("expected 1 timed out session with ID %s, got %v", sess2.ID, timedOut2)
	}
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyBob); ok {
		t.Errorf("expected route to be unregistered by default reap")
	}
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool connections=0 after default reap, got %d", tunAfter.ActiveConnections)
	}
}

func TestPruneExpiredAffinity_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	tunID := int64(42)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)

	pruned := vpnSvc.PruneExpiredAffinity()
	if pruned != 0 {
		t.Errorf("expected 0 pruned affinities before expiry, got %d", pruned)
	}

	vpnSvc.stickyMgr.SetNowFunc(func() time.Time {
		return time.Now().UTC().Add(35 * time.Minute)
	})

	pruned = vpnSvc.PruneExpiredAffinity()
	if pruned != 2 {
		t.Errorf("expected 2 pruned affinities after expiry, got %d", pruned)
	}

	if prunedAgain := vpnSvc.PruneExpiredAffinity(); prunedAgain != 0 {
		t.Errorf("expected 0 on second prune, got %d", prunedAgain)
	}
}

func TestReconcileTestHooks_Lifecycle(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, _, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	var order []string
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		order = append(order, "post_snapshot")
	})
	vpnSvc.SetReconcilePreApplyHook(func() {
		order = append(order, "pre_apply")
	})
	vpnSvc.SetReconcilePreCommitHook(func() {
		order = append(order, "pre_commit")
	})

	var adoptCalled, routeRegCalled bool
	vpnSvc.SetPreAdoptHookForTest(func(pk, sid string) {
		adoptCalled = true
	})
	vpnSvc.SetPreIngressRouteRegistrationHookForTest(func() {
		routeRegCalled = true
	})

	vpnSvc.mu.Lock()
	if vpnSvc.preAdoptHookForTest != nil {
		vpnSvc.preAdoptHookForTest("test-peer", "test-sid")
	}
	if vpnSvc.preIngressRouteRegistrationHookForTest != nil {
		vpnSvc.preIngressRouteRegistrationHookForTest()
	}
	vpnSvc.mu.Unlock()

	if !adoptCalled || !routeRegCalled {
		t.Errorf("expected pre-adopt and pre-route-reg hooks to be set and callable")
	}

	vpnSvc.reconcileConnectionCounts(ctx)

	expectedOrder := []string{"post_snapshot", "pre_apply", "pre_commit"}
	if len(order) != len(expectedOrder) {
		t.Fatalf("expected %d hooks called, got %d: %v", len(expectedOrder), len(order), order)
	}
	for i, name := range expectedOrder {
		if order[i] != name {
			t.Errorf("hook %d: want %s, got %s", i, name, order[i])
		}
	}
}
