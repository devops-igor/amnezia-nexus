package database

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestVPNSessionsConnectionNameColumn covers the connection_name column on
// vpn_sessions (issue #189 improvement round): a fresh database gets the
// column from schema.sql, a legacy database created without it is extended
// in place by runMigrationsLocked, and CreateVPNSession persists the name
// through INSERT and upsert paths.
func TestVPNSessionsConnectionNameColumn(t *testing.T) {
	ctx := context.Background()

	t.Run("fresh schema has connection_name", func(t *testing.T) {
		db, _ := setupTestDB(t)

		has, err := dbHasColumn(t, db, "vpn_sessions", "connection_name")
		if err != nil {
			t.Fatalf("PRAGMA inspect failed: %v", err)
		}
		if !has {
			t.Fatal("expected fresh schema to have vpn_sessions.connection_name")
		}
	})

	t.Run("legacy database without column migrates in place", func(t *testing.T) {
		legacyPath := filepath.Join(t.TempDir(), "legacy.db")
		openLegacyDB(t, legacyPath, func(legacy *DB) {
			// Simulate the pre-migration schema: vpn_sessions without
			// connection_name, seeded with one connected row.
			legacySeed := []string{
				`INSERT INTO vpn_sessions (
					id, user_id, backend_tunnel_id, peer_public_key, assigned_ip,
					connected_at, last_seen, rx_bytes, tx_bytes, status
				) VALUES ('legacy-sess-1', 'u1', 0, 'legacy-peer-1', '10.100.5.1',
					'2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', 1, 2, 'connected')`,
			}
			for _, q := range legacySeed {
				if _, err := legacy.sqlDB.ExecContext(ctx, q); err != nil {
					t.Fatalf("legacy seed failed: %v", err)
				}
			}
		})

		// Reopen through the normal Open path: runMigrationsLocked must
		// add the missing column without touching existing rows.
		db, err := Open(legacyPath, testSecretKey)
		if err != nil {
			t.Fatalf("Open on legacy database failed: %v", err)
		}
		defer db.Close()

		has, err := dbHasColumn(t, db, "vpn_sessions", "connection_name")
		if err != nil {
			t.Fatalf("PRAGMA inspect after migration failed: %v", err)
		}
		if !has {
			t.Fatal("expected migration to add vpn_sessions.connection_name")
		}

		// The migrated row stays readable with '' as the connection name
		// (legacy rows: config resolved at handshake only, never known).
		sess, err := db.GetVPNSessionByID(ctx, "legacy-sess-1")
		if err != nil {
			t.Fatalf("GetVPNSessionByID after migration failed: %v", err)
		}
		if sess == nil {
			t.Fatal("legacy row lost during migration")
		}
		if sess.ConnectionName != "" {
			t.Errorf("legacy row connection_name = %q, want empty", sess.ConnectionName)
		}
	})

	t.Run("CreateVPNSession persists connection_name", func(t *testing.T) {
		db, _ := setupTestDB(t)

		// vpn_sessions carries an FK on users(id); seed the referenced row.
		if _, err := db.ExecContext(ctx,
			"INSERT INTO users (id, username, role, enabled) VALUES ('u1', 'connname-u1', 'user', 1)"); err != nil {
			t.Fatalf("seed user failed: %v", err)
		}

		// vpn_sessions carries FKs on users(id) and backend_tunnels(id);
		// seed the referenced rows.
		sID, err := db.CreateServer(ctx, &models.Server{Name: "Persist Node", Host: "198.51.100.8"})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: "awg-persist",
			PublicKey:     "pubkey-persist",
			PrivateKey:    "privkey-persist",
			Endpoint:      "198.51.100.8:51820",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel failed: %v", err)
		}

		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "conn-name-1",
			UserID:          "u1",
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-conn-name-1",
			AssignedIP:      "10.100.5.2",
			ConnectionName:  "Igor Phone (AWG)",
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		got, err := db.GetVPNSessionByID(ctx, "conn-name-1")
		if err != nil {
			t.Fatalf("GetVPNSessionByID failed: %v", err)
		}
		if got == nil {
			t.Fatal("session row missing after insert")
		}
		if got.ConnectionName != "Igor Phone (AWG)" {
			t.Errorf("connection_name = %q, want %q", got.ConnectionName, "Igor Phone (AWG)")
		}

		// Upsert path: same peer, new session ID and connection name.
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "conn-name-2",
			UserID:          "u1",
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-conn-name-1",
			AssignedIP:      "10.100.5.2",
			ConnectionName:  "Igor Laptop (AWG)",
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession upsert failed: %v", err)
		}
		got, err = db.GetVPNSessionByID(ctx, "conn-name-2")
		if err != nil {
			t.Fatalf("GetVPNSessionByID after upsert failed: %v", err)
		}
		if got == nil || got.ConnectionName != "Igor Laptop (AWG)" {
			t.Errorf("upsert did not persist new connection_name: %+v", got)
		}
	})

	t.Run("enriched query carries connection_name", func(t *testing.T) {
		db, _ := setupTestDB(t)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "Edge Node 5", Host: "198.51.100.5"})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		uID, err := db.CreateUser(ctx, &models.User{Username: "connname-user"})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: "awg-cn",
			PublicKey:     "pubkey-cn",
			PrivateKey:    "privkey-cn",
			Endpoint:      "198.51.100.5:51820",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel failed: %v", err)
		}
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "sess-cn-1",
			UserID:          uID,
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-cn-1",
			AssignedIP:      "10.100.5.3",
			ConnectionName:  "Tablet Config",
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		rows, err := db.GetEnrichedActiveVPNSessions(ctx)
		if err != nil {
			t.Fatalf("GetEnrichedActiveVPNSessions failed: %v", err)
		}
		var found bool
		for _, r := range rows {
			if r.ID == "sess-cn-1" {
				found = true
				if r.ConnectionName != "Tablet Config" {
					t.Errorf("enriched connection_name = %q, want %q", r.ConnectionName, "Tablet Config")
				}
			}
		}
		if !found {
			t.Fatal("seeded session missing from enriched rows")
		}
	})
}
