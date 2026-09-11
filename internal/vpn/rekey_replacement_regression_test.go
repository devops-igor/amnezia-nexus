package vpn

import (
	"testing"
)

// Regression tests for issue #78: the rekey/reconnect session-replacement
// path used to leak +1 on the old backend's ActiveConnections gauge — the
// original connect incremented it in HandleIncomingPeer, but CreateSession's
// replacement path never decremented and never closed the old DB row, so a
// later DisconnectSession(oldID) hit ErrSessionNotFound and its mirror
// decrement never ran either.

// TestRekeyReplacementReturnsGaugeToBaseline forces a rekey (session
// replacement for the same peer, same backend) through the real
// HandleIncomingPeer path — the same population as the issue's live evidence
// (mobile clients waking up rekey frequently) — and asserts the old backend's
// pool gauge returns to its baseline.
func TestRekeyReplacementReturnsGaugeToBaseline(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, peerKey := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 951, "awg951", "pub951", "priv951", "10.9.9.151:51820")
	svc.pool.IncrementConnections(tun.ID)
	baseline := tun.ActiveConnections
	if baseline != 1 {
		t.Fatalf("setup: baseline gauge = %d, want 1", baseline)
	}

	// Initial connect.
	if _, _, err := svc.HandleIncomingPeer(ctx, peerKey); err != nil {
		t.Fatalf("initial HandleIncomingPeer failed: %v", err)
	}
	if tun.ActiveConnections != 2 {
		t.Fatalf("after connect: gauge = %d, want 2", tun.ActiveConnections)
	}

	// Rekey: the same peer connects again (fresh session, same peer key).
	sess2, backend2, err := svc.HandleIncomingPeer(ctx, peerKey)
	if err != nil {
		t.Fatalf("rekey HandleIncomingPeer failed: %v", err)
	}
	if backend2.ID != tun.ID {
		t.Fatalf("rekey selected backend %d, want %d", backend2.ID, tun.ID)
	}

	// The gauge must be back to exactly 2 (baseline 1 + the one live
	// replacement session) — the old session's +1 must have been migrated.
	if tun.ActiveConnections != baseline+1 {
		t.Errorf("after rekey: old backend gauge = %d, want %d (leak: replacement did not decrement the old session)", tun.ActiveConnections, baseline+1)
	}

	// No orphan DB row for the replaced session may survive.
	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions: %v", err)
	}
	count := 0
	for _, s := range sessions {
		if s.PeerPublicKey == peerKey {
			count++
			if s.ID != sess2.ID {
				t.Errorf("stale session row %s for peer survived replacement", s.ID)
			}
		}
	}
	if count != 1 {
		t.Errorf("found %d active session rows for the rekeyed peer, want 1", count)
	}

	// Replacement metrics: exactly one replacement, one counter migration.
	metrics := svc.sessionMgr.MetricsSnapshot()
	if metrics["replacements_total"] != 1 {
		t.Errorf("replacements_total = %d, want 1", metrics["replacements_total"])
	}
	if metrics["replacement_counter_migrations_total"] != 1 {
		t.Errorf("replacement_counter_migrations_total = %d, want 1", metrics["replacement_counter_migrations_total"])
	}

	// Clean disconnect of the replacement must land at the true baseline.
	if err := svc.DisconnectSession(ctx, sess2.ID); err != nil {
		t.Fatalf("DisconnectSession: %v", err)
	}
	if tun.ActiveConnections != baseline {
		t.Errorf("after disconnect: gauge = %d, want baseline %d", tun.ActiveConnections, baseline)
	}
}

// TestRekeyReplacementAcrossBackends moves the counter: a rekey that lands on
// a DIFFERENT backend must decrement the old backend and increment the new.
func TestRekeyReplacementAcrossBackends(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	oldTun := lbTunnel(t, svc, db, 961, "awg961", "pub961", "priv961", "10.9.9.161:51820")
	newTun := lbTunnel(t, svc, db, 962, "awg962", "pub962", "priv962", "10.9.9.162:51820")

	// Connect on oldTun.
	svc.pool.IncrementConnections(oldTun.ID)
	sess1, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-move-78", "10.202.0.61", oldTun.ID)
	if err != nil {
		t.Fatalf("CreateSession (initial): %v", err)
	}
	_ = sess1
	if oldTun.ActiveConnections != 1 {
		t.Fatalf("setup: oldTun gauge = %d, want 1", oldTun.ActiveConnections)
	}

	// Rekey onto newTun: the replacement hook performs BOTH sides of the
	// migration (decrement old, increment new) — exactly what
	// HandleIncomingPeer would drive when the balancer selects newTun.
	if _, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-move-78", "10.202.0.61", newTun.ID); err != nil {
		t.Fatalf("CreateSession (rekey): %v", err)
	}

	gotOld, err := svc.pool.GetTunnelByID(oldTun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(old): %v", err)
	}
	if gotOld.ActiveConnections != 0 {
		t.Errorf("old backend gauge = %d, want 0 after cross-backend replacement", gotOld.ActiveConnections)
	}
	gotNew, err := svc.pool.GetTunnelByID(newTun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(new): %v", err)
	}
	if gotNew.ActiveConnections != 1 {
		t.Errorf("new backend gauge = %d, want 1 after cross-backend replacement", gotNew.ActiveConnections)
	}

	// No orphan row pointing at the old backend.
	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions: %v", err)
	}
	for _, s := range sessions {
		if s.PeerPublicKey == "peer-move-78" && s.BackendTunnelID == oldTun.ID {
			t.Errorf("vpn_sessions row for peer-move-78 still references old backend %d", oldTun.ID)
		}
	}
}

// TestPeriodicGaugeReconcileCorrectsDrift pins the #78 safety net: the hourly
// reconcile must correct an artificially drifted gauge using the existing
// reconcileConnectionCounts primitive, and must be gauge-only (no session
// created or killed).
func TestPeriodicGaugeReconcileCorrectsDrift(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 971, "awg971", "pub971", "priv971", "10.9.9.171:51820")

	// One real connected session...
	svc.pool.IncrementConnections(tun.ID)
	if _, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-reconcile-78", "10.202.0.71", tun.ID); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// ...plus artificial drift (e.g. an unresolved residual leak).
	for i := 0; i < 7; i++ {
		svc.pool.IncrementConnections(tun.ID)
	}
	if tun.ActiveConnections != 8 {
		t.Fatalf("setup: gauge = %d, want 8", tun.ActiveConnections)
	}

	// The periodic reconcile (same entry point StartGaugeReconciler calls
	// hourly) must correct the gauge to the true count of 1.
	svc.reconcileConnectionCounts(ctx)

	got, err := svc.pool.GetTunnelByID(tun.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID: %v", err)
	}
	if got.ActiveConnections != 1 {
		t.Errorf("after reconcile: gauge = %d, want 1", got.ActiveConnections)
	}

	// Gauge-only semantics: the real session must still be connected.
	sessions, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions: %v", err)
	}
	count := 0
	for _, s := range sessions {
		if s.PeerPublicKey == "peer-reconcile-78" && s.Status == "connected" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("reconcile must not touch sessions: found %d connected rows for the peer, want 1", count)
	}
}
