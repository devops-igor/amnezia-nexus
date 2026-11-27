package vpn

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestService_MaintenanceLoop_PrunesExpiredAffinity drives one iteration of the
// background maintenance loop that StartGaugeReconciler starts in production
// (issue #552). The direct-call affinity regression cannot observe whether the
// tick path that prunes affinity in production still does so, so this test feeds
// the loop a tick and asserts, in order: the loop does not prune without a tick,
// the tick reconciles the connection gauge while the expired records are still
// present, the tick then removes them, and a cancelled context ends the loop.
func TestService_MaintenanceLoop_PrunesExpiredAffinity(t *testing.T) {
	// The seam must not become a cadence knob: production still reconciles hourly.
	if ConnectionGaugeReconcileInterval != time.Hour {
		t.Fatalf("production reconcile cadence changed: ConnectionGaugeReconcileInterval = %s, want %s",
			ConnectionGaugeReconcileInterval, time.Hour)
	}

	db := setupTestDB(t)
	vpnSvc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	defer func() { _ = vpnSvc.Stop() }()

	ctx := context.Background()
	if err := vpnSvc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	now := time.Now().UTC()
	vpnSvc.stickyMgr.AssignAffinity(uID, 1)
	vpnSvc.stickyMgr.AssignPeerAffinity(peerKeyAlice, 1)
	// Every affinity record is now past its TTL from the loop's point of view.
	vpnSvc.stickyMgr.SetNowFunc(func() time.Time { return now.Add(1 * time.Hour) })

	if uCount, pCount := vpnSvc.stickyMgr.AffinityCount(); uCount != 1 || pCount != 1 {
		t.Fatalf("expected initial AffinityCount=(1, 1), got (%d, %d)", uCount, pCount)
	}

	// The post-snapshot hook runs inside reconcileConnectionCounts, after the
	// session snapshot and before the loop's prune call, so the affinity counts
	// sampled here are the ones the reconcile pass saw.
	var hookMu sync.Mutex
	reconcilePasses := 0
	affinityDuringReconcile := [2]int{}
	vpnSvc.SetReconcilePostSnapshotHook(func() {
		uCount, pCount := vpnSvc.stickyMgr.AffinityCount()
		hookMu.Lock()
		reconcilePasses++
		affinityDuringReconcile = [2]int{uCount, pCount}
		hookMu.Unlock()
	})

	loopCtx, cancelLoop := context.WithCancel(context.Background())
	defer cancelLoop()
	ticks := make(chan time.Time)
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		vpnSvc.runMaintenanceLoop(loopCtx, ticks)
	}()

	// Negative direction: a running loop that has received no tick must leave
	// affinity untouched, so the prune asserted below is attributable to the tick.
	noTickDeadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(noTickDeadline) {
		if uCount, pCount := vpnSvc.stickyMgr.AffinityCount(); uCount != 1 || pCount != 1 {
			t.Fatalf("affinity pruned before any tick arrived: AffinityCount=(%d, %d)", uCount, pCount)
		}
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case ticks <- now.Add(1 * time.Hour):
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance loop did not consume a tick within 5s")
	}

	pruneDeadline := time.Now().Add(5 * time.Second)
	for {
		uCount, pCount := vpnSvc.stickyMgr.AffinityCount()
		if uCount == 0 && pCount == 0 {
			break
		}
		if time.Now().After(pruneDeadline) {
			t.Fatalf("expected the maintenance tick to prune expired affinity, still (%d, %d)", uCount, pCount)
		}
		time.Sleep(5 * time.Millisecond)
	}

	hookMu.Lock()
	passes := reconcilePasses
	duringReconcile := affinityDuringReconcile
	hookMu.Unlock()
	if passes == 0 {
		t.Fatal("expected the maintenance tick to reconcile the connection gauge before pruning affinity")
	}
	if duringReconcile[0] != 1 || duringReconcile[1] != 1 {
		t.Fatalf("expected affinity to be present while the gauge reconciled (reconcile runs before prune), got (%d, %d)",
			duringReconcile[0], duringReconcile[1])
	}

	// The loop must not leak: cancelling its context ends it even with no tick.
	cancelLoop()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance loop did not return after its context was cancelled")
	}
}
