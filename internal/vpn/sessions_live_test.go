package vpn

// Behavior tests for Service.SessionsLive — the memory-authoritative admin
// session table (issue #189 improvement round). The row set comes from the
// SessionManager's in-memory connected set (the same source as the
// active-sessions card), identity enrichment runs in one DB pass with the
// same fallbacks as the DB-enriched path, un-flushed accountant deltas are
// added on top of the persisted counters, and connection names are captured
// at CreateSession and carried through the rekey/replacement path.

import (
	"fmt"
	"testing"
)

// TestSessionsLiveMatchesActiveCount pins the core issue-#189 guarantee: the
// admin table row count and the active-sessions card count are derived from
// the same in-memory set, so they can never disagree — at connect time and
// after a disconnect.
func TestSessionsLiveMatchesActiveCount(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	ctx := t.Context()

	// One pool-registered active backend so the handshake path can select
	// it (the service is intentionally not started — no UDP listener, no
	// background flushers).
	lbTunnel(t, svc, db, 955, "awg955", "pub955", "priv955", "10.9.9.155:51820")

	// Session 1 through the real handshake path.
	sess1, _, err := svc.HandleIncomingPeer(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed: %v", err)
	}
	// Session 2 straight through the manager (auth/IPAM bypassed), on the
	// same backend as sess1.
	sess2, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-live-count", "10.201.0.21", sess1.BackendTunnelID, "")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	live, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("SessionsLive failed: %v", err)
	}
	status, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if len(live) != 2 || status.ConnectedSessions != 2 || svc.sessionMgr.ActiveCount() != 2 {
		t.Fatalf("setup: table rows = %d, card count = %d, manager count = %d, want 2/2/2",
			len(live), status.ConnectedSessions, svc.sessionMgr.ActiveCount())
	}

	// Disconnect exactly one; both sources must drop by the same amount.
	if err := svc.DisconnectSession(ctx, sess2.ID); err != nil {
		t.Fatalf("DisconnectSession failed: %v", err)
	}

	liveAfter, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("post-disconnect SessionsLive failed: %v", err)
	}
	statusAfter, err := svc.GetStatus(ctx)
	if err != nil {
		t.Fatalf("post-disconnect GetStatus failed: %v", err)
	}
	if len(liveAfter) != len(live)-1 {
		t.Errorf("table rows dropped %d -> %d, want exactly one row removed", len(live), len(liveAfter))
	}
	if len(liveAfter) != statusAfter.ConnectedSessions {
		t.Errorf("card and table disagree after disconnect: card = %d, table = %d",
			statusAfter.ConnectedSessions, len(liveAfter))
	}
	if len(liveAfter) == 1 && liveAfter[0].ID != sess1.ID {
		t.Errorf("surviving row = %s, want the still-connected session %s", liveAfter[0].ID, sess1.ID)
	}
}

// TestSessionsLiveDBMissFallback proves the memory-authoritative row set:
// when the user and tunnel rows behind a live session are deleted (the
// vpn_sessions row cascades away with them), SessionsLive still returns the
// in-memory session, keeping the same fallbacks as the DB-enriched path —
// 'unknown' username, 'Server #<tunnelID>' naming, server ID 0 — while the
// manager-known connection name survives.
func TestSessionsLiveDBMissFallback(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, peerKeyAlice := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 956, "awg956", "pub956", "priv956", "10.9.9.156:51820")
	sess, _, err := svc.HandleIncomingPeer(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed: %v", err)
	}

	// Remove the DB identity chain: the tunnel row (cascades the
	// vpn_sessions row) and the user row (the production DeleteUser
	// primitive removes vpn_sessions rows itself). The in-memory session
	// survives both — exactly the ghost-row scenario SessionsLive exists
	// to handle.
	if err := db.DeleteBackendTunnel(ctx, tun.ID); err != nil {
		t.Fatalf("DeleteBackendTunnel failed: %v", err)
	}
	if _, err := db.DeleteUser(ctx, uID); err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	// Precondition: the DB row is really gone, so the row below can only
	// come from the manager's memory.
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if row != nil {
		t.Fatalf("precondition: vpn_sessions row survived deletion: %+v", row)
	}

	live, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("SessionsLive failed: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("expected the live session to survive DB deletion, got %d rows: %+v", len(live), live)
	}
	got := live[0]
	if got.ID != sess.ID {
		t.Errorf("row ID = %s, want %s", got.ID, sess.ID)
	}
	if got.Username != "unknown" {
		t.Errorf("username fallback = %q, want %q", got.Username, "unknown")
	}
	wantServer := fmt.Sprintf("Server #%d", sess.BackendTunnelID)
	if got.ServerName != wantServer {
		t.Errorf("server name fallback = %q, want %q", got.ServerName, wantServer)
	}
	if got.ServerID != 0 {
		t.Errorf("server ID fallback = %d, want 0", got.ServerID)
	}
	if got.ConnectionName != "alice-phone" {
		t.Errorf("connection name must come from the manager, got %q, want %q", got.ConnectionName, "alice-phone")
	}
}

// TestSessionsLiveAccountantDeltas checks the telemetry path: SessionsLive
// adds the accountant's un-flushed buffered deltas on top of the session's
// persisted (DB) counters — the same values production traffic produces
// between periodic flushes.
func TestSessionsLiveAccountantDeltas(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, peerKeyAlice := setupTestVPNService(t, db)
	ctx := t.Context()

	lbTunnel(t, svc, db, 957, "awg957", "pub957", "priv957", "10.9.9.157:51820")
	sess, _, err := svc.HandleIncomingPeer(ctx, peerKeyAlice)
	if err != nil {
		t.Fatalf("HandleIncomingPeer failed: %v", err)
	}

	// Base counters as persisted (the service is never started, so no
	// periodic flush can race this read).
	dbRow, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if dbRow == nil {
		t.Fatalf("GetVPNSessionByID returned no row for %s", sess.ID)
	}

	// Buffered, un-flushed deltas recorded on the service's real
	// accountant (wired by NewVPNService; its flush loop only runs after
	// Start, so the deltas stay buffered — the exact state SessionsLive
	// must compensate for).
	svc.accountant.RecordRx(sess.ID, "", 500)
	svc.accountant.RecordTx(sess.ID, "", 300)

	live, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("SessionsLive failed: %v", err)
	}
	if len(live) != 1 {
		t.Fatalf("expected 1 row, got %d: %+v", len(live), live)
	}
	got := live[0]
	if want := dbRow.RxBytes + 500; got.RxBytes != want {
		t.Errorf("rx = %d, want persisted %d + buffered 500 = %d", got.RxBytes, dbRow.RxBytes, want)
	}
	if want := dbRow.TxBytes + 300; got.TxBytes != want {
		t.Errorf("tx = %d, want persisted %d + buffered 300 = %d", got.TxBytes, dbRow.TxBytes, want)
	}
}

// TestCreateSessionPersistsConnectionNameAndReplacement pins the
// connection_name contract: CreateSession stores the caller-supplied name on
// both the in-memory session and the persisted row, and the rekey/replacement
// path (same peer key) keeps the freshly authenticated connection name on the
// surviving row while the replaced row is fully torn down.
func TestCreateSessionPersistsConnectionNameAndReplacement(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, uID, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	tun := lbTunnel(t, svc, db, 958, "awg958", "pub958", "priv958", "10.9.9.158:51820")

	sess, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-cname-1", "10.201.2.10", tun.ID, "dave-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if sess.ConnectionName != "dave-phone" {
		t.Errorf("in-memory session connection name = %q, want %q", sess.ConnectionName, "dave-phone")
	}
	row, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if row == nil {
		t.Fatalf("GetVPNSessionByID returned no row for %s", sess.ID)
	}
	if row.ConnectionName != "dave-phone" {
		t.Errorf("persisted connection_name = %q, want %q", row.ConnectionName, "dave-phone")
	}

	// Replacement path: the same peer reconnects (rekey). The manager tears
	// the old session down (memory + DB row) and registers the replacement
	// built from the freshly passed-in fields — connection name included.
	replaced, err := svc.sessionMgr.CreateSession(ctx, uID, "peer-cname-1", "10.201.2.10", tun.ID, "dave-phone")
	if err != nil {
		t.Fatalf("replacement CreateSession failed: %v", err)
	}
	if replaced.ID == sess.ID {
		t.Fatalf("replacement must be a new session, got the same ID %s", replaced.ID)
	}
	if replaced.ConnectionName != "dave-phone" {
		t.Errorf("replacement in-memory connection name = %q, want %q", replaced.ConnectionName, "dave-phone")
	}

	// No orphan row for the replaced session may survive.
	oldRow, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID(old) failed: %v", err)
	}
	if oldRow != nil {
		t.Errorf("replaced session row %s survived (orphan)", sess.ID)
	}
	newRow, err := db.GetVPNSessionByID(ctx, replaced.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID(replacement) failed: %v", err)
	}
	if newRow == nil {
		t.Fatalf("GetVPNSessionByID returned no row for replacement %s", replaced.ID)
	}
	if newRow.ConnectionName != "dave-phone" {
		t.Errorf("replacement persisted connection_name = %q, want %q", newRow.ConnectionName, "dave-phone")
	}

	// The admin live table shows exactly the replacement, with its name.
	live, err := svc.SessionsLive(ctx)
	if err != nil {
		t.Fatalf("SessionsLive failed: %v", err)
	}
	if len(live) != 1 || live[0].ID != replaced.ID {
		t.Fatalf("live table = %+v, want exactly the replacement session %s", live, replaced.ID)
	}
	if live[0].ConnectionName != "dave-phone" {
		t.Errorf("live table connection name = %q, want %q", live[0].ConnectionName, "dave-phone")
	}
}
