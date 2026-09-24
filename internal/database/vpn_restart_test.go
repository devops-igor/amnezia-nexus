package database

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestInvalidateVPNSessionsForRestartAtomicAndIdempotent(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "restart-host", Host: "192.0.2.27"})
	if err != nil {
		t.Fatal(err)
	}
	tunnelID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: serverID, InterfaceName: "awg-restart", PublicKey: "restart-pub",
		Endpoint: "192.0.2.27:51820", ActiveConnections: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	userID, err := db.CreateUser(ctx, &models.User{Username: "restart-user"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ id, peer, ip, status string }{
		{"old-connected", "old-peer", "10.100.0.12", "connected"},
		{"old-draining", "draining-peer", "10.100.0.13", "draining"},
	} {
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID: test.id, UserID: userID, BackendTunnelID: tunnelID,
			PeerPublicKey: test.peer, AssignedIP: test.ip, Status: test.status,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A failed gauge update must roll back the session deletion too.
	if _, err := db.SQLDB().ExecContext(ctx, `CREATE TRIGGER block_restart_gauge
		BEFORE UPDATE OF active_connections ON backend_tunnels
		BEGIN SELECT RAISE(ABORT, 'blocked restart gauge'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InvalidateVPNSessionsForRestart(ctx); err == nil {
		t.Fatal("expected transaction to fail on gauge update")
	}
	if old, err := db.GetVPNSessionByPeerKey(ctx, "old-peer"); err != nil || old == nil {
		t.Fatalf("failed transaction deleted connected session: row=%+v err=%v", old, err)
	}
	if row, err := db.GetBackendTunnel(ctx, tunnelID); err != nil || row == nil || row.ActiveConnections != 4 {
		t.Fatalf("failed transaction changed gauge: row=%+v err=%v", row, err)
	}
	if _, err := db.SQLDB().ExecContext(ctx, "DROP TRIGGER block_restart_gauge"); err != nil {
		t.Fatal(err)
	}

	count, err := db.InvalidateVPNSessionsForRestart(ctx)
	if err != nil || count != 1 {
		t.Fatalf("invalidated=%d err=%v, want one connected session", count, err)
	}
	for _, peer := range []string{"old-peer", "draining-peer"} {
		if row, err := db.GetVPNSessionByPeerKey(ctx, peer); err != nil || row != nil {
			t.Fatalf("retired session %s survived: row=%+v err=%v", peer, row, err)
		}
	}
	if row, err := db.GetBackendTunnel(ctx, tunnelID); err != nil || row == nil || row.ActiveConnections != 0 {
		t.Fatalf("persisted gauge not reset: row=%+v err=%v", row, err)
	}
	if count, err := db.InvalidateVPNSessionsForRestart(ctx); err != nil || count != 0 {
		t.Fatalf("second restart invalidated=%d err=%v, want zero", count, err)
	}
}
