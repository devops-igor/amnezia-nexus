package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
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
	byInterface := make(map[string]struct {
		enabled bool
		reason  string
	}, len(tunnels))
	for _, tun := range tunnels {
		byInterface[tun.InterfaceName] = struct {
			enabled bool
			reason  string
		}{enabled: tun.Enabled, reason: tun.DisableReason}
	}

	if byInterface["admin"].enabled {
		t.Fatal("explicit admin-disabled legacy row migrated as enabled")
	}
	if !byInterface["health"].enabled {
		t.Fatal("health-disabled legacy row must remain administratively enabled")
	}
	if byInterface["ambiguous"].enabled {
		t.Fatal("ambiguous legacy disabled row must migrate conservatively as disabled")
	}
	if byInterface["ambiguous"].reason != "admin" {
		t.Fatalf("ambiguous legacy disabled row reason = %q, want admin", byInterface["ambiguous"].reason)
	}
	if !byInterface["active"].enabled {
		t.Fatal("active legacy row migrated as administratively disabled")
	}

	// Simulate a valid post-migration intermediate state: administrative
	// intent is enabled, while runtime health is still disabled and its old
	// provenance has already been cleared. Reopening the DB must not reinterpret
	// this modern state as a legacy administrative disable.
	if _, err := db.SQLDB().ExecContext(ctx,
		`UPDATE backend_tunnels SET enabled = 1, status = 'disabled', disable_reason = '' WHERE interface_name = 'health'`,
	); err != nil {
		t.Fatalf("prepare post-migration state: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close migrated DB: %v", err)
	}

	reopened, err := Open(dbPath, "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatalf("reopen migrated DB: %v", err)
	}
	defer reopened.Close()

	reopenedTunnels, err := reopened.GetBackendTunnels(ctx)
	if err != nil {
		t.Fatalf("GetBackendTunnels after reopen: %v", err)
	}
	var health *models.BackendTunnel
	for i := range reopenedTunnels {
		if reopenedTunnels[i].InterfaceName == "health" {
			health = &reopenedTunnels[i]
			break
		}
	}
	if health == nil {
		t.Fatal("health tunnel missing after reopen")
	}
	if !health.Enabled || health.Status != "disabled" || health.DisableReason != "" {
		t.Fatalf("reopen reinterpreted modern state as legacy admin disable: enabled=%v status=%q reason=%q",
			health.Enabled, health.Status, health.DisableReason)
	}
}
