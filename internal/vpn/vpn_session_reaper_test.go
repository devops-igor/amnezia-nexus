package vpn

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestSessionReaperHook_Teardown(t *testing.T) {
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

	// 1. Establish state simulating an active session:
	// - session in sessionMgr
	// - route registered in forwarder
	// - sticky affinities in stickyMgr
	// - incremented connection count in pool
	sessID := "sess-reaper-test-1"
	assignedIP := "10.100.0.88"
	createdSess, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIP, tunID, sessID)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	vpnSvc.forwarder.RegisterSession(createdSess.ID, "conn-1", peerKeyAlice, assignedIP, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// Verify pre-conditions
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); !ok {
		t.Fatalf("expected forwarder route to be registered")
	}
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Fatalf("expected user sticky affinity to be %d, got %d (ok=%v)", tunID, tid, ok)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Fatalf("expected peer sticky affinity to be %d, got %d (ok=%v)", tunID, tid, ok)
	}
	tunBefore, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunBefore.ActiveConnections != 1 {
		t.Fatalf("expected pool ActiveConnections=1, got %d (err=%v)", tunBefore.ActiveConnections, err)
	}

	// 2. Age session past IdleTimeout (default 3m, age by 10m)
	createdSess.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// 3. Trigger timeout sweep through service (which invokes the registered SessionReaperHook)
	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) == 0 {
		t.Fatalf("expected at least 1 timed out session, got 0")
	}
	if timedOut[0].ID != createdSess.ID {
		t.Fatalf("expected timed out session %s, got %s", createdSess.ID, timedOut[0].ID)
	}

	// 4. Verify post-conditions after reaper hook teardown:
	// a) Session is removed from sessionMgr
	if _, ok := vpnSvc.sessionMgr.GetSessionByID(createdSess.ID); ok {
		t.Errorf("session still found in sessionMgr after sweep")
	}

	// b) Forwarder route unregistered
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); ok {
		t.Errorf("forwarder route for %s still registered after reaper teardown", peerKeyAlice)
	}

	// c) Sticky affinities preserved within AffinityTTL (issue #294)
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Errorf("expected user sticky affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Errorf("expected peer sticky affinity to be preserved as %d, got %d (ok=%v)", tunID, tid, ok)
	}

	// Verify sticky affinity expires naturally once time advances past AffinityTTL (30m)
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time {
		return time.Now().UTC().Add(35 * time.Minute)
	})
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); ok {
		t.Errorf("expected user sticky affinity to expire after TTL, got %d", tid)
	}
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); ok {
		t.Errorf("expected peer sticky affinity to expire after TTL, got %d", tid)
	}

	// d) Pool connection count decremented to 0
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections=0 after reaper teardown, got %d (err=%v)", tunAfter.ActiveConnections, err)
	}
}

func TestService_ReapSession_EdgeCases(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, _, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	// Calling with nil session should not panic or error
	vpnSvc.reapSession(ctx, nil)

	// Calling with empty/non-existent session fields should not panic
	dummySess := &models.VPNSession{
		ID:              "non-existent",
		UserID:          "",
		PeerPublicKey:   "no-such-peer",
		BackendTunnelID: 999999,
	}
	vpnSvc.reapSession(ctx, dummySess)
}

func TestSessionReaperHook_ReconnectRace(t *testing.T) {
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
	tunID := tunnels[0].ID
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tunID = tun.ID
			break
		}
	}

	// 1. Session A is active
	sessIDA := "sess-reconnect-race-A"
	assignedIPA := "10.100.0.91"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPA, tunID, sessIDA)
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-1", peerKeyAlice, assignedIPA, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 2. Age session A past idle timeout
	sessA.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// 3. Intercept reaper hook execution to simulate delayed reaper execution
	reaperChan := make(chan *models.VPNSession, 1)
	vpnSvc.SetSessionReaperHookForTest(func(ctx context.Context, s *models.VPNSession) {
		reaperChan <- s
	})

	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected session A to time out, got %+v", timedOut)
	}

	var reapedSessA *models.VPNSession
	select {
	case reapedSessA = <-reaperChan:
	default:
		t.Fatalf("expected reaperChan to receive session A")
	}

	// 4. Client reconnects creating session B before session A's reaper hook executes
	assignedIPB := "10.100.0.92"
	sessB, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPB, tunID, "conn-b")
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-b", peerKeyAlice, assignedIPB, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tunMid, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunMid.ActiveConnections != 2 {
		t.Fatalf("expected pool ActiveConnections=2 before reaper A runs, got %d", tunMid.ActiveConnections)
	}

	// 5. Now execute the delayed reapSession for session A
	vpnSvc.reapSession(ctx, reapedSessA)

	// 6. Assertions for Session B:
	// a) Session B must still be active in sessionMgr
	if current, ok := vpnSvc.sessionMgr.GetSession(peerKeyAlice); !ok || current.ID != sessB.ID {
		t.Errorf("expected session B to still be active in sessionMgr, got ok=%v, sess=%+v", ok, current)
	}

	// b) Session B's forwarder route must remain intact
	if _, ok := vpnSvc.forwarder.GetClientPacketChannel(peerKeyAlice); !ok {
		t.Errorf("expected forwarder route for session B to remain intact")
	}

	// c) Session B's sticky peer affinity must remain intact
	if tid, ok := vpnSvc.stickyMgr.GetPeerAffinity(peerKeyAlice); !ok || tid != tunID {
		t.Errorf("expected peer sticky affinity to remain %d, got %d (ok=%v)", tunID, tid, ok)
	}

	// d) Session B's sticky user affinity must remain intact
	if tid, ok := vpnSvc.stickyMgr.GetAffinity(uID); !ok || tid != tunID {
		t.Errorf("expected user sticky affinity to remain %d, got %d (ok=%v)", tunID, tid, ok)
	}

	// e) Tunnel ActiveConnections must be exactly 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunAfter.ActiveConnections != 1 {
		t.Errorf("expected pool ActiveConnections=1 after reaper A runs, got %d", tunAfter.ActiveConnections)
	}
}

func TestSessionReaperHook_ReconcileRace(t *testing.T) {
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
	tunID := tunnels[0].ID
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tunID = tun.ID
			break
		}
	}

	// 1. Session A is active
	sessIDA := "sess-reconcile-race-A"
	assignedIPA := "10.100.0.93"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPA, tunID, sessIDA)
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-1", peerKeyAlice, assignedIPA, tunID)
	vpnSvc.stickyMgr.AssignAffinity(uID, tunID)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 2. Age session A past idle timeout
	sessA.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// Intercept reaper hook
	reaperChan := make(chan *models.VPNSession, 1)
	vpnSvc.SetSessionReaperHookForTest(func(ctx context.Context, s *models.VPNSession) {
		reaperChan <- s
	})

	// 3. Trigger SweepTimedOutSessions
	timedOut, err := vpnSvc.SweepTimedOutSessions(ctx)
	if err != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", err)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected session A to time out, got %+v", timedOut)
	}
	if timedOut[0].TimedOutAt.IsZero() {
		t.Fatalf("expected TimedOutAt to be set on timed-out session")
	}

	var reapedSessA *models.VPNSession
	select {
	case reapedSessA = <-reaperChan:
	default:
		t.Fatalf("expected reaperChan to receive session A")
	}

	// 4. Session B connects for another peer
	peerKeyBob := "peer-reconcile-bob"
	assignedIPB := "10.100.0.94"
	sessB, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyBob, assignedIPB, tunID, "conn-bob")
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-bob", peerKeyBob, assignedIPB, tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	// 5. Periodic reconciliation runs before session A's reaper hook runs
	vpnSvc.reconcileConnectionCounts(ctx)

	tunReconciled, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunReconciled.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1 after reconciliation, got %d", tunReconciled.ActiveConnections)
	}
	if vpnSvc.lastReconcileTime.IsZero() || !vpnSvc.lastReconcileTime.After(reapedSessA.TimedOutAt) {
		t.Fatalf("expected lastReconcileTime to be after TimedOutAt")
	}

	// 6. Now the delayed reapSession for session A runs
	vpnSvc.reapSession(ctx, reapedSessA)

	// 7. Verify pool counter was NOT decremented to 0
	tunFinal, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tunFinal.ActiveConnections != 1 {
		t.Errorf("expected pool ActiveConnections to remain 1 after stale reaper, got %d", tunFinal.ActiveConnections)
	}
}

func TestSessionReaperHook_ConcurrentDeadlock(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	peerKeyBob := "peer-deadlock-bob"
	_, _ = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: peerKeyBob,
		Name:     "bob-phone",
	})

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Worker 1: repeatedly creates sessions and ages them
	wg.Add(1)
	go func() {
		defer wg.Done()
		peers := []string{peerKeyAlice, peerKeyBob}
		for i := 0; i < 50; i++ {
			p := peers[i%len(peers)]
			sess, _, err := vpnSvc.HandleIncomingPeerForTest(ctx, p)
			if err == nil && sess != nil {
				vpnSvc.sessionMgr.SetSessionLastSeen(p, time.Now().UTC().Add(-10*time.Minute))
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 2: repeatedly triggers timeout sweeps
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = vpnSvc.SweepTimedOutSessions(ctx)
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Worker 3: runs periodic reconciliation
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			vpnSvc.reconcileConnectionCounts(ctx)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded without deadlock
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock detected: concurrent timeout sweep, HandleIncomingPeer, and reconciliation did not complete in 10s")
	}
}
