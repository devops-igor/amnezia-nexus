package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestGetEnrichedActiveVPNSessionsJoins verifies the read-path JOIN behind the
// admin session visibility feature (issue #190): usernames resolve from users,
// server names resolve via backend_tunnels -> servers, rows whose joins miss
// fall back to 'unknown'/'Server #N', and only connected rows are returned.
func TestGetEnrichedActiveVPNSessionsJoins(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "Edge Node 1", Host: "198.51.100.10"})
	if err != nil || sID <= 0 {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: "alice"})
	if err != nil || uID == "" {
		t.Fatalf("CreateUser failed: %v", err)
	}
	tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "pubkey-be-1",
		PrivateKey:    "privkey-be-1",
		Endpoint:      "198.51.100.10:51820",
	})
	if err != nil || tID <= 0 {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	connected := &models.VPNSession{
		ID:              "sess-joined",
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer-joined",
		AssignedIP:      "10.100.0.21",
		ConnectedAt:     time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC),
		LastSeen:        time.Date(2026, 9, 18, 9, 5, 0, 0, time.UTC),
		RxBytes:         1024,
		TxBytes:         2048,
		Status:          "connected",
	}
	if err := db.CreateVPNSession(ctx, connected); err != nil {
		t.Fatalf("CreateVPNSession connected failed: %v", err)
	}

	// Disconnected rows must be excluded from the enriched view.
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sess-disconnected",
		UserID:          uID,
		BackendTunnelID: tID,
		PeerPublicKey:   "peer-disconnected",
		AssignedIP:      "10.100.0.22",
		Status:          "disconnected",
	}); err != nil {
		t.Fatalf("CreateVPNSession disconnected failed: %v", err)
	}

	// Orphan row: user and backend tunnel lookups miss — fallbacks must kick
	// in. The schema enforces FKs, so a pre-FK legacy orphan can only exist
	// by seeding through a separate raw connection (same pattern as
	// migration_compat_test.go); the public API correctly refuses it.
	rawDB, err := sql.Open("sqlite", db.dbPath)
	if err != nil {
		t.Fatalf("failed to open raw sqlite db for legacy seed: %v", err)
	}
	defer rawDB.Close()
	rawDB.SetMaxOpenConns(1) // keep the FK pragma and the insert on one conn
	if _, err := rawDB.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatalf("failed to disable FKs on raw seed connection: %v", err)
	}
	if _, err := rawDB.Exec(`INSERT INTO vpn_sessions
		(id, user_id, backend_tunnel_id, peer_public_key, assigned_ip, connected_at, last_seen, rx_bytes, tx_bytes, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"sess-orphan", "ghost-user", 9999, "peer-orphan", "10.100.0.23",
		"2026-09-18T09:00:00Z", "2026-09-18T09:05:00Z", 5, 10, "connected"); err != nil {
		t.Fatalf("failed to seed legacy orphan vpn session: %v", err)
	}
	// Dangling-server variant: the tunnel row exists, but the server it
	// points to is gone — server_name must fall back to the tunnel's
	// server_id ('Server #<serverID>').
	if _, err := rawDB.Exec(`INSERT INTO backend_tunnels
		(id, server_id, interface_name, public_key, private_key, probe_private_key, endpoint, status, latency_ms, active_connections, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		777, 8888, "awg-be-dangling", "pubkey-dangling", "privkey-dangling", "",
		"198.51.100.99:51820", "active", 0, 0, "2026-09-18T08:00:00Z"); err != nil {
		t.Fatalf("failed to seed dangling-server tunnel: %v", err)
	}
	if err := db.CreateVPNSession(ctx, &models.VPNSession{
		ID:              "sess-dangling-server",
		UserID:          uID,
		BackendTunnelID: 777,
		PeerPublicKey:   "peer-dangling-server",
		AssignedIP:      "10.100.0.24",
		Status:          "connected",
	}); err != nil {
		t.Fatalf("CreateVPNSession dangling-server failed: %v", err)
	}

	sessions, err := db.GetEnrichedActiveVPNSessions(ctx)
	if err != nil {
		t.Fatalf("GetEnrichedActiveVPNSessions failed: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected 3 connected sessions, got %d: %+v", len(sessions), sessions)
	}

	var joined, orphan, dangling *models.EnrichedVPNSession
	for i := range sessions {
		switch sessions[i].ID {
		case "sess-joined":
			joined = &sessions[i]
		case "sess-orphan":
			orphan = &sessions[i]
		case "sess-dangling-server":
			dangling = &sessions[i]
		}
	}
	if joined == nil || orphan == nil || dangling == nil {
		t.Fatalf("expected sess-joined, sess-orphan and sess-dangling-server in results, got: %+v", sessions)
	}

	if joined.Username != "alice" {
		t.Errorf("username not resolved from users join: got %q, want %q", joined.Username, "alice")
	}
	if joined.ServerName != "Edge Node 1" {
		t.Errorf("server name not resolved from servers join: got %q, want %q", joined.ServerName, "Edge Node 1")
	}
	if joined.ServerID != sID {
		t.Errorf("server id mismatch: got %d, want %d", joined.ServerID, sID)
	}
	if joined.BackendTunnelID != tID {
		t.Errorf("backend tunnel id mismatch: got %d, want %d", joined.BackendTunnelID, tID)
	}
	if !joined.ConnectedAt.Equal(time.Date(2026, 9, 18, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("connected_at mismatch: got %v", joined.ConnectedAt)
	}
	if !joined.LastSeen.Equal(time.Date(2026, 9, 18, 9, 5, 0, 0, time.UTC)) {
		t.Errorf("last_seen mismatch: got %v", joined.LastSeen)
	}
	if joined.RxBytes != 1024 || joined.TxBytes != 2048 {
		t.Errorf("counters mismatch: rx=%d tx=%d, want 1024/2048", joined.RxBytes, joined.TxBytes)
	}
	if joined.Status != "connected" {
		t.Errorf("status mismatch: got %q", joined.Status)
	}

	if orphan.Username != "unknown" {
		t.Errorf("orphan username fallback: got %q, want %q", orphan.Username, "unknown")
	}
	if orphan.ServerName != "Server #9999" {
		t.Errorf("orphan server name fallback: got %q, want %q", orphan.ServerName, "Server #9999")
	}

	if dangling.Username != "alice" {
		t.Errorf("dangling-server username should resolve: got %q, want %q", dangling.Username, "alice")
	}
	if dangling.ServerID != 8888 {
		t.Errorf("dangling-server server id: got %d, want 8888", dangling.ServerID)
	}
	if dangling.ServerName != "Server #8888" {
		t.Errorf("dangling-server name fallback: got %q, want %q", dangling.ServerName, "Server #8888")
	}
}
