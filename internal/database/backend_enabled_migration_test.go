package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestBackendEnabledMigrationPreservesAdministrativeIntent(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy-enabled.db")

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.ExecContext(ctx, `
		CREATE TABLE backend_tunnels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			interface_name TEXT NOT NULL UNIQUE,
			public_key TEXT NOT NULL,
			private_key TEXT NOT NULL,
			probe_private_key TEXT NOT NULL DEFAULT '',
			endpoint TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'connecting',
			disable_reason TEXT NOT NULL DEFAULT '',
			state_version INTEGER NOT NULL DEFAULT 1,
			last_health_check TEXT,
			latency_ms INTEGER DEFAULT 0,
			active_connections INTEGER DEFAULT 0,
			created_at TEXT NOT NULL
		)
	`)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rows := []struct {
		iface, status, reason string
	}{
		{"admin", "active", "admin"},
		{"health", "disabled", "health"},
		{"ambiguous", "disabled", ""},
		{"active", "active", ""},
	}
	for i, row := range rows {
		if _, err := raw.ExecContext(ctx, `
			INSERT INTO backend_tunnels
				(server_id, interface_name, public_key, private_key, endpoint, status, disable_reason, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, i+1, row.iface, "pub", "priv", "192.0.2.1:51820", row.status, row.reason, now); err != nil {
			_ = raw.Close()
			t.Fatal(err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	tunnels, err := db.GetBackendTunnels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byInterface := make(map[string]bool, len(tunnels))
	for _, tun := range tunnels {
		byInterface[tun.InterfaceName] = tun.Enabled
	}

	if byInterface["admin"] {
		t.Fatal("explicit admin-disabled legacy row migrated as enabled")
	}
	if !byInterface["health"] {
		t.Fatal("health-disabled legacy row must remain administratively enabled")
	}
	if byInterface["ambiguous"] {
		t.Fatal("ambiguous legacy disabled row must migrate conservatively as disabled")
	}
	if !byInterface["active"] {
		t.Fatal("active legacy row migrated as administratively disabled")
	}
}
