package vpn

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestReconcileConnectionCounts_StaleSnapshotRejected(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-stale-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.91", tunID, "conn-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-a", peerKeyA, "10.100.0.91", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// 2. Configure reconcilePostSnapshotHook:
	// While reconciliation is paused post-DB read, create a new Session B and increment live pool counter.
	// This mutates sessionMgr lifecycle version and moves live gauge to 2.
	// Because DB snapshot only contains Session A (count 1), if the snapshot were applied,
	// it would clobber the gauge back to 1.
	hookFired := false
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		hookFired = true
		peerKeyB := "peer-reconcile-stale-b"
		sessB, errCreate := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyB, "10.100.0.92", tunID, "conn-b")
		if errCreate != nil {
			t.Fatalf("hook: CreateSession B failed: %v", errCreate)
		}
		vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-b", peerKeyB, "10.100.0.92", tunID)
		vpnSvc.pool.IncrementConnections(tunID)
	})

	// 3. Run reconcileConnectionCounts:
	// Prior to DB read: lifecycleVersion is V1.
	// DB read returns 1 session (Session A).
	// Hook fires: Session B created, lifecycleVersion becomes V2, pool gauge is 2.
	// Reconciliation acquires lock: sees lifecycleVersion V2 != V1 -> aborts!
	vpnSvc.reconcileConnectionCounts(ctx)

	if !hookFired {
		t.Fatal("expected reconcilePostSnapshotHook to fire")
	}

	// 4. Verify pool gauge remains 2, not reset to 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 2 {
		t.Errorf("expected pool ActiveConnections to remain 2, got %d (stale snapshot was not rejected)", tunAfter.ActiveConnections)
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected_ReplacementFailure(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-replace-fail-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.91", tunID, "conn-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-a", peerKeyA, "10.100.0.91", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// 2. Configure reconcilePostSnapshotHook:
	// While reconciliation is paused post-DB read (which captured Session A with count 1),
	// trigger a replacement for Session A with a canceled context so persistence fails.
	// The replacement removes Session A from memory maps and advances lifecycleVersion.
	// We also adjust live pool gauge (decrement by 1 to 0) to represent Session A being torn down.
	// If the stale snapshot were applied, it would reset the live gauge back to 1.
	hookFired := false
	versionBeforeReconcile := vpnSvc.sessionMgr.LifecycleVersion()
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		hookFired = true
		cancCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, errReplace := vpnSvc.sessionMgr.CreateSession(cancCtx, uID, peerKeyA, "10.100.0.91", tunID, "conn-a-replacement")
		if errReplace == nil {
			t.Fatal("expected CreateSession replacement to fail due to canceled context")
		}

		// Verify that lifecycleVersion was advanced even though CreateSession returned an error
		if vpnSvc.sessionMgr.LifecycleVersion() <= versionBeforeReconcile {
			t.Fatalf("expected lifecycleVersion to advance on replacement removal, but got %d (was %d)",
				vpnSvc.sessionMgr.LifecycleVersion(), versionBeforeReconcile)
		}

		// Adjust live pool counter to 0
		vpnSvc.pool.DecrementConnections(tunID)
	})

	// 3. Run reconcileConnectionCounts:
	// DB read captured Session A (desired count 1).
	// Hook fired: replacement failed, but advanced lifecycleVersion. Live gauge is 0.
	// Reconcile acquires lock: detects lifecycleVersion mutated -> aborts!
	vpnSvc.reconcileConnectionCounts(ctx)

	if !hookFired {
		t.Fatal("expected reconcilePostSnapshotHook to fire")
	}

	// 4. Verify pool gauge remains 0, not reset to stale count 1
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to remain 0, got %d (stale snapshot was not rejected)", tunAfter.ActiveConnections)
	}
}

func TestSessionReaperHook_ReconcileFailureDoesNotSuppressReaper(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, s1ID, s2ID, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) < 2 {
		t.Fatalf("expected at least 2 active tunnels in pool, got %d", len(tunnels))
	}
	var tun1ID, tun2ID int64
	for _, tun := range tunnels {
		if tun.ServerID == s1ID {
			tun1ID = tun.ID
		} else if tun.ServerID == s2ID {
			tun2ID = tun.ID
		}
	}
	if tun1ID == 0 || tun2ID == 0 {
		t.Fatalf("failed to resolve tunnel IDs for servers %d and %d", s1ID, s2ID)
	}

	// 1. Session A is active on Tunnel 1
	sessIDA := "sess-reconcile-fail-A"
	assignedIPA := "10.100.0.95"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyAlice, assignedIPA, tun1ID, sessIDA)
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-1", peerKeyAlice, assignedIPA, tun1ID)
	vpnSvc.pool.IncrementConnections(tun1ID)

	// 2. Age session A past idle timeout
	sessA.LastSeen = time.Now().UTC().Add(-10 * time.Minute)

	// Intercept reaper hook so delayed reapSession execution can be controlled
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

	// 4. Session B connects on Tunnel 1, bringing live ActiveConnections to 2 (1 stale A + 1 live B)
	peerKeyBob := "peer-reconcile-bob-fail"
	assignedIPB := "10.100.0.96"
	sessB, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyBob, assignedIPB, tun1ID, "conn-bob")
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessB.ID, "conn-bob", peerKeyBob, assignedIPB, tun1ID)
	vpnSvc.pool.IncrementConnections(tun1ID)

	tun1Before, err := vpnSvc.pool.GetTunnelByID(tun1ID)
	if err != nil || tun1Before.ActiveConnections != 2 {
		t.Fatalf("expected Tunnel 1 ActiveConnections=2 before reconcile, got %d", tun1Before.ActiveConnections)
	}

	// 5. Run reconcileConnectionCounts with an injected failure during SetConnectionCount:
	// Reconciliation reads DB (desired count for Tunnel 1 is 1 for Session B).
	// Hook cancels context so SetConnectionCount DB persistence fails for Tunnel 1.
	ctxReconcile, cancelReconcile := context.WithCancel(context.Background())
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		cancelReconcile()
	})
	vpnSvc.reconcileConnectionCounts(ctxReconcile)

	// 6. Verify reconciliation state under lock:
	// Tunnel 1 failed persistence: lastReconcileByTunnel[tun1ID] must NOT be set!
	// Tunnel 2 had zero drift: lastReconcileByTunnel[tun2ID] was successfully set.
	// Because Tunnel 1 failed, global lastReconcileTime must NOT be updated.
	vpnSvc.mu.RLock()
	tun1ReconcileTime := vpnSvc.lastReconcileByTunnel[tun1ID]
	tun2ReconcileTime := vpnSvc.lastReconcileByTunnel[tun2ID]
	globalReconcileTime := vpnSvc.lastReconcileTime
	vpnSvc.mu.RUnlock()

	if !tun1ReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[tun1ID] to be zero after failure, got %v", tun1ReconcileTime)
	}
	if tun2ReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[tun2ID] to be non-zero for successful tunnel, got zero")
	}
	if !globalReconcileTime.IsZero() {
		t.Errorf("expected global lastReconcileTime to remain zero when any tunnel fails, got %v", globalReconcileTime)
	}

	// 7. Now execute delayed reapSession for session A.
	// Since Tunnel 1's reconciliation timestamp was not recorded, reaper must NOT skip decrement.
	vpnSvc.reapSession(ctx, reapedSessA)

	// 8. Verify Tunnel 1 ActiveConnections was decremented to 0
	tunFinal, err := vpnSvc.pool.GetTunnelByID(tun1ID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunFinal.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to be decremented to 0, got %d (reaper decrement was improperly suppressed)", tunFinal.ActiveConnections)
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected_TimeoutDuringApply(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-timeout-apply-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.95", tunID, "conn-apply-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-apply-a", peerKeyA, "10.100.0.95", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// Age session past IdleTimeout (default 3m, age by 10m)
	vpnSvc.sessionMgr.SetSessionLastSeen(peerKeyA, time.Now().UTC().Add(-10*time.Minute))

	versionBefore := vpnSvc.sessionMgr.LifecycleVersion()

	var wg sync.WaitGroup
	var hookFired atomic.Bool
	var sweepErr error
	var timedOut []*models.VPNSession

	vpnSvc.SetReconcilePreApplyHook(func() {
		hookFired.Store(true)

		vpnSvc.sessionMgr.UnlockLifecycle()
		defer vpnSvc.sessionMgr.LockLifecycle()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// SweepTimedOutSessions runs CheckTimeouts under SessionManager.mu,
			// increments lifecycleVersion, and then invokes registered reaperHook
			// which calls svc.reapSession(ctx, sess) blocking on Service.mu.
			timedOut, sweepErr = vpnSvc.SweepTimedOutSessions(ctx)
		}()

		// Wait until CheckTimeouts has removed session A and advanced lifecycleVersion
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_, found := vpnSvc.sessionMgr.GetSessionByID(sessA.ID)
			if !found && vpnSvc.sessionMgr.LifecycleVersion() > versionBefore {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}

		// Yield to allow the reaper goroutine to reach reapSession and block on Service.mu
		time.Sleep(50 * time.Millisecond)
	})

	// 2. Run reconcileConnectionCounts:
	// DB read captured Session A (desired count 1).
	// Passes initial version check under Service.mu.
	// Hook fires: Session A times out, lifecycleVersion advances, reaper blocks on Service.mu.
	// Reconcile resumes: detects lifecycleVersion mutated -> refuses to apply snapshot and aborts!
	// Reconcile releases Service.mu.
	vpnSvc.reconcileConnectionCounts(ctx)

	// Wait for the reaper goroutine to finish
	wg.Wait()

	if !hookFired.Load() {
		t.Fatal("expected reconcilePreApplyHook to fire")
	}
	if sweepErr != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", sweepErr)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected 1 timed out session %s, got %+v", sessA.ID, timedOut)
	}

	// 3. Verify reconciliation timestamps were NOT committed
	vpnSvc.mu.RLock()
	var tunReconcileTime time.Time
	if vpnSvc.lastReconcileByTunnel != nil {
		tunReconcileTime = vpnSvc.lastReconcileByTunnel[tunID]
	}
	globalReconcileTime := vpnSvc.lastReconcileTime
	vpnSvc.mu.RUnlock()

	if !tunReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[%d] to be zero after abort, got %v", tunID, tunReconcileTime)
	}
	if !globalReconcileTime.IsZero() {
		t.Errorf("expected global lastReconcileTime to remain zero after abort, got %v", globalReconcileTime)
	}

	// 4. Verify pool gauge is 0 (decremented by reaper, not restored to 1 by reconciliation)
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to be 0, got %d (stale snapshot restored count)", tunAfter.ActiveConnections)
	}
}

func TestReconcileConnectionCounts_StaleSnapshotRejected_TimeoutBeforeCommit(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	vpnSvc, _, _, uID, _ := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	tunnels := vpnSvc.pool.GetActiveTunnels()
	if len(tunnels) == 0 {
		t.Fatal("no active tunnels found")
	}
	tunID := tunnels[0].ID

	// 1. Create Session A: pool ActiveConnections is 1, DB has 1 active session.
	peerKeyA := "peer-reconcile-timeout-commit-a"
	sessA, err := vpnSvc.sessionMgr.CreateSession(ctx, uID, peerKeyA, "10.100.0.96", tunID, "conn-commit-a")
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}
	vpnSvc.forwarder.RegisterSession(sessA.ID, "conn-commit-a", peerKeyA, "10.100.0.96", tunID)
	vpnSvc.pool.IncrementConnections(tunID)

	tun1, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil || tun1.ActiveConnections != 1 {
		t.Fatalf("expected ActiveConnections=1, got %d", tun1.ActiveConnections)
	}

	// Age session past IdleTimeout (default 3m, age by 10m)
	vpnSvc.sessionMgr.SetSessionLastSeen(peerKeyA, time.Now().UTC().Add(-10*time.Minute))

	versionBefore := vpnSvc.sessionMgr.LifecycleVersion()

	var wg sync.WaitGroup
	var hookFired atomic.Bool
	var sweepErr error
	var timedOut []*models.VPNSession

	vpnSvc.SetReconcilePreCommitHook(func() {
		hookFired.Store(true)

		// Temporarily release session lifecycle lock so background sweep can proceed
		vpnSvc.sessionMgr.UnlockLifecycle()
		defer vpnSvc.sessionMgr.LockLifecycle()

		wg.Add(1)
		go func() {
			defer wg.Done()
			// SweepTimedOutSessions runs CheckTimeouts under SessionManager.mu,
			// increments lifecycleVersion, and then invokes registered reaperHook
			// which calls svc.reapSession(ctx, sess) blocking on Service.mu.
			timedOut, sweepErr = vpnSvc.SweepTimedOutSessions(ctx)
		}()

		// Wait until CheckTimeouts has removed session A and advanced lifecycleVersion
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_, found := vpnSvc.sessionMgr.GetSessionByID(sessA.ID)
			if !found && vpnSvc.sessionMgr.LifecycleVersion() > versionBefore {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}

		// Yield to allow the reaper goroutine to reach reapSession and block on Service.mu
		time.Sleep(50 * time.Millisecond)
	})

	// 2. Run reconcileConnectionCounts:
	// DB read captured Session A (desired count 1).
	// Passes initial version check under Service.mu and sm.LockLifecycle.
	// Drift evaluated in Phase 1 (no changes yet applied).
	// Pre-commit hook fires: temporarily releases sm.LockLifecycle,
	// Session A times out, lifecycleVersion advances, reaper blocks on Service.mu,
	// sm.LockLifecycle re-acquired.
	// Reconcile resumes from hook: detects lifecycleVersion mutated,
	// aborts Phase 2 commit immediately (SetConnectionCount never called, timestamps not committed).
	// Reconcile releases sm.UnlockLifecycle and Service.mu.
	vpnSvc.reconcileConnectionCounts(ctx)

	// Wait for the reaper goroutine to finish
	wg.Wait()

	if !hookFired.Load() {
		t.Fatal("expected reconcilePreCommitHook to fire")
	}
	if sweepErr != nil {
		t.Fatalf("SweepTimedOutSessions failed: %v", sweepErr)
	}
	if len(timedOut) != 1 || timedOut[0].ID != sessA.ID {
		t.Fatalf("expected 1 timed out session %s, got %+v", sessA.ID, timedOut)
	}

	// 3. Verify reconciliation timestamps were NOT committed
	vpnSvc.mu.RLock()
	var tunReconcileTime time.Time
	if vpnSvc.lastReconcileByTunnel != nil {
		tunReconcileTime = vpnSvc.lastReconcileByTunnel[tunID]
	}
	globalReconcileTime := vpnSvc.lastReconcileTime
	vpnSvc.mu.RUnlock()

	if !tunReconcileTime.IsZero() {
		t.Errorf("expected lastReconcileByTunnel[%d] to be zero after abort, got %v", tunID, tunReconcileTime)
	}
	if !globalReconcileTime.IsZero() {
		t.Errorf("expected global lastReconcileTime to remain zero after abort, got %v", globalReconcileTime)
	}

	// 4. Verify pool gauge is 0 (decremented by reaper, not restored to 1 by reconciliation)
	tunAfter, err := vpnSvc.pool.GetTunnelByID(tunID)
	if err != nil {
		t.Fatalf("GetTunnelByID failed: %v", err)
	}
	if tunAfter.ActiveConnections != 0 {
		t.Errorf("expected pool ActiveConnections to be 0, got %d (stale snapshot restored count)", tunAfter.ActiveConnections)
	}
}
