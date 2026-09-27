package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/loadbalancer"
)

// Regression tests for issue #90 / PR #370: after splitting administrative
// intent (backend_tunnels.enabled) from runtime health (status), the state
// combination Enabled=false + Status=active is valid and expected. Both the
// HandleIncomingPeer existing-session/rekey fast path and the
// validateMigrationTarget preflight must require administrative eligibility
// (Enabled) in addition to runtime health (active status).

// TestRekeyFastPathRejectsAdminDisabledBackend is the stranded-session
// regression: a live session whose backend is administratively disabled while
// no healthy failover target exists (the session is stranded) must NOT be
// reused by the rekey fast path on the next HandleIncomingPeer call. The
// disabled backend's runtime health is still "active" after the split, so
// status alone is not sufficient — Enabled must gate the fast path.
func TestRekeyFastPathRejectsAdminDisabledBackend(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, _, peerKey := setupTestVPNService(t, db)
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("SyncFromDB failed: %v", err)
	}

	// 1. Create a live session through the real admission path.
	sess1, backend1, err := svc.HandleIncomingPeer(ctx, peerKey)
	if err != nil {
		t.Fatalf("initial HandleIncomingPeer failed: %v", err)
	}
	liveTunID := backend1.ID
	liveSrvID := backend1.ServerID
	otherSrvID := s1ID
	if liveSrvID == s1ID {
		otherSrvID = s2ID
	}

	// 2. Strand the session: first remove the healthy failover target, then
	// administratively disable the live backend. With no active tunnels left,
	// DisableBackend's failover finds no target and the session stays on the
	// now-disabled backend.
	if err := svc.DisableBackend(ctx, otherSrvID); err != nil {
		t.Fatalf("DisableBackend(failover target %d) failed: %v", otherSrvID, err)
	}
	if err := svc.DisableBackend(ctx, liveSrvID); err != nil {
		t.Fatalf("DisableBackend(live backend %d) failed: %v", liveSrvID, err)
	}

	// Precondition (issue #90 state split): administrative disable preserves
	// runtime health, so the stranded backend is Enabled=false, Status=active.
	got, err := svc.pool.GetTunnelByID(liveTunID)
	if err != nil {
		t.Fatalf("GetTunnelByID(live) failed: %v", err)
	}
	if got.Enabled {
		t.Fatal("precondition failed: live backend is still enabled after administrative disable")
	}
	if !strings.EqualFold(got.Status, models.TunnelStatusActive) {
		t.Fatalf("precondition failed: runtime health changed on admin disable: got %q, want %q", got.Status, models.TunnelStatusActive)
	}
	if got.ActiveConnections != 1 {
		t.Fatalf("precondition failed: stranded session not counted on live backend: gauge = %d, want 1", got.ActiveConnections)
	}

	// 3. Rekey: the same peer initiates a new handshake on the stranded
	// session. The fast path must NOT reuse the administratively disabled
	// backend; with no healthy alternative the call must fail with
	// ErrNoActiveBackends instead of advancing the live session.
	sess2, backend2, err := svc.HandleIncomingPeer(ctx, peerKey)
	if err == nil {
		t.Fatalf("expected HandleIncomingPeer to refuse reuse of admin-disabled backend %d, got session %s on backend %d", liveTunID, sess2.ID, backend2.ID)
	}
	if !errors.Is(err, loadbalancer.ErrNoActiveBackends) {
		t.Fatalf("expected ErrNoActiveBackends after fast path refusal, got: %v", err)
	}
	if sess2 != nil || backend2 != nil {
		t.Fatalf("expected nil session/backend on refusal, got session %v backend %v", sess2, backend2)
	}

	// 4. The live session must be untouched: same ID, same generation, still
	// pointing at the (disabled) backend it was stranded on.
	live, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peerKey)
	if !ok {
		t.Fatal("live session disappeared after refused rekey")
	}
	if live.ID != sess1.ID {
		t.Errorf("live session replaced: %s -> %s", sess1.ID, live.ID)
	}
	if live.Generation != sess1.Generation {
		t.Errorf("live session generation advanced by refused rekey: %d -> %d", sess1.Generation, live.Generation)
	}
	if live.BackendTunnelID != liveTunID {
		t.Errorf("live session moved to backend %d, want %d", live.BackendTunnelID, liveTunID)
	}
	if gen := svc.PeerGeneration(peerKey); gen != sess1.Generation {
		t.Errorf("peer generation advanced by refused rekey: got %d, want %d", gen, sess1.Generation)
	}

	// 5. No new DB session row; the single row still references the disabled
	// backend.
	rows, err := db.GetActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetActiveVPNSessions failed: %v", err)
	}
	count := 0
	for _, r := range rows {
		if r.PeerPublicKey == peerKey {
			count++
			if r.ID != sess1.ID {
				t.Errorf("unexpected session row %s for peer after refused rekey", r.ID)
			}
			if r.BackendTunnelID != liveTunID {
				t.Errorf("DB session row moved to backend %d, want %d", r.BackendTunnelID, liveTunID)
			}
		}
	}
	if count != 1 {
		t.Errorf("found %d active session rows for the peer, want 1", count)
	}

	// 6. The pool gauge on the disabled backend is unchanged (no counter
	// churn from the refused rekey).
	got, err = svc.pool.GetTunnelByID(liveTunID)
	if err != nil {
		t.Fatalf("GetTunnelByID(live) after refusal failed: %v", err)
	}
	if got.ActiveConnections != 1 {
		t.Errorf("live backend gauge = %d after refused rekey, want 1", got.ActiveConnections)
	}
}

// TestMigrateSessionRejectsAdminDisabledTargetBeforeMutation pins the
// preflight ordering: an admin-disabled/runtime-active migration target is
// rejected by validateMigrationTarget BEFORE the forwarder route,
// SessionManager state, or DB session row are mutated. Before this fix the
// preflight passed on status alone, the mutation steps ran, and the target was
// only rejected later by TransferConnectionsIfActive — after a rollback cycle.
func TestMigrateSessionRejectsAdminDisabledTargetBeforeMutation(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	svc, s1ID, s2ID, uID, peerKey := setupTestVPNService(t, db)
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

	// Live session on tun1 with a registered forwarder route.
	assignedIP := "10.100.0.90"
	sess, err := svc.sessionMgr.CreateSession(ctx, uID, peerKey, assignedIP, tun1.ID, "alice-phone")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	const connID = "conn-issue90"
	svc.forwarder.RegisterSession(sess.ID, connID, peerKey, assignedIP, tun1.ID)
	svc.pool.IncrementConnections(tun1.ID)

	// Administratively disable the TARGET backend. Per the issue #90 split
	// its runtime health must remain active — exactly the state the old
	// status-only preflight let through.
	if err := svc.DisableBackend(ctx, s2ID); err != nil {
		t.Fatalf("DisableBackend(target %d) failed: %v", s2ID, err)
	}
	got2, err := svc.pool.GetTunnelByID(tun2.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(target) failed: %v", err)
	}
	if got2.Enabled {
		t.Fatal("precondition failed: target backend is still enabled after administrative disable")
	}
	if !strings.EqualFold(got2.Status, models.TunnelStatusActive) {
		t.Fatalf("precondition failed: target runtime health changed on admin disable: got %q, want %q", got2.Status, models.TunnelStatusActive)
	}

	// Migration to the admin-disabled target must be rejected at preflight.
	err = svc.MigrateSession(ctx, sess.ID, tun2.ID)
	if err == nil {
		t.Fatal("expected MigrateSession to reject admin-disabled target, got nil")
	}
	if !strings.Contains(err.Error(), "not eligible") {
		t.Errorf("expected preflight eligibility error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "enabled=false") {
		t.Errorf("expected eligibility error to report enabled=false, got: %v", err)
	}
	// Ordering proof: the pure preflight error must surface. If the mutation
	// steps had run first, the error would be the late transfer-commit
	// failure (joined with rollback noise) instead.
	if strings.Contains(err.Error(), "connection transfer") {
		t.Errorf("target was rejected after mutation at transfer commit, not at preflight: %v", err)
	}

	// Forwarder route unchanged: still bound to tun1, never moved to tun2.
	if !svc.forwarder.HasSessionRoute(peerKey, sess.ID, connID, assignedIP, tun1.ID) {
		t.Error("forwarder route was mutated by rejected migration: route no longer bound to source backend")
	}
	if svc.forwarder.HasSessionRoute(peerKey, sess.ID, connID, assignedIP, tun2.ID) {
		t.Error("forwarder route was mutated by rejected migration: route points at disabled target")
	}

	// SessionManager state unchanged.
	snap, ok := svc.sessionMgr.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatal("session missing from SessionManager after rejected migration")
	}
	if snap.BackendTunnelID != tun1.ID {
		t.Errorf("SessionManager BackendTunnelID = %d, want %d (mutation without commit)", snap.BackendTunnelID, tun1.ID)
	}
	if snap.Status != "connected" {
		t.Errorf("SessionManager Status = %q, want connected", snap.Status)
	}

	// DB session row unchanged.
	dbSess, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if dbSess.BackendTunnelID != tun1.ID {
		t.Errorf("DB session backend_tunnel_id = %d, want %d", dbSess.BackendTunnelID, tun1.ID)
	}
	if dbSess.Status != "connected" {
		t.Errorf("DB session status = %q, want connected", dbSess.Status)
	}

	// Pool counters unchanged.
	got1, err := svc.pool.GetTunnelByID(tun1.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(source) failed: %v", err)
	}
	if got1.ActiveConnections != 1 {
		t.Errorf("source gauge = %d after rejected migration, want 1", got1.ActiveConnections)
	}
	got2, err = svc.pool.GetTunnelByID(tun2.ID)
	if err != nil {
		t.Fatalf("GetTunnelByID(target) failed: %v", err)
	}
	if got2.ActiveConnections != 0 {
		t.Errorf("target gauge = %d after rejected migration, want 0", got2.ActiveConnections)
	}
}
