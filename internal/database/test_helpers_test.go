package database

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // register the "sqlite" driver for raw legacy opens
)

// testSecretKey is the master key used to open test databases in this
// package (same shape as the production key). Defined locally because the
// package's other test files use their own inline keys.
const testSecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// legacyVPNSessionsDDL is the minimal pre-#189-improvement schema shape: the
// original vpn_sessions table WITHOUT connection_name, plus its parent
// tables. Mirrors the raw-DDL legacy-database precedent from
// migration_compat_test.go, narrowed to the tables the vpn_sessions tests
// touch.
const legacyVPNSessionsDDL = `
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT,
    telegramId TEXT,
    description TEXT,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    enabled INTEGER NOT NULL DEFAULT 1,
    traffic_limit INTEGER,
    traffic_used INTEGER DEFAULT 0,
    traffic_total INTEGER DEFAULT 0,
    traffic_total_rx INTEGER DEFAULT 0,
    traffic_total_tx INTEGER DEFAULT 0,
    monthly_rx INTEGER DEFAULT 0,
    monthly_tx INTEGER DEFAULT 0,
    monthly_reset_at TEXT,
    traffic_reset_strategy TEXT DEFAULT 'never',
    share_enabled INTEGER DEFAULT 0,
    share_token TEXT,
    share_password_hash TEXT,
    remnawave_uuid TEXT,
    created_at TEXT,
    last_reset_at TEXT,
    expiration_date TEXT,
    expires_at TEXT,
    awg_mimicry TEXT DEFAULT 'auto',
    password_change_required INTEGER NOT NULL DEFAULT 0,
    limits TEXT
);

CREATE TABLE IF NOT EXISTS backend_tunnels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    interface_name TEXT,
    public_key TEXT,
    private_key TEXT,
    endpoint TEXT,
    status TEXT DEFAULT 'active',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS vpn_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    backend_tunnel_id INTEGER NOT NULL,
    peer_public_key TEXT NOT NULL UNIQUE,
    assigned_ip TEXT NOT NULL UNIQUE,
    connected_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    rx_bytes INTEGER DEFAULT 0,
    tx_bytes INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'connected',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (backend_tunnel_id) REFERENCES backend_tunnels(id) ON DELETE CASCADE
);
`

// dbHasColumn reports whether the given table currently has the named
// column, via PRAGMA table_info — the same introspection the runtime
// additive migrations use.
func dbHasColumn(t *testing.T, db *DB, table, column string) (bool, error) {
	t.Helper()

	rows, err := db.sqlDB.QueryContext(context.Background(), "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid, notNull, pk int
		var name, colType string
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// openLegacyDB creates a raw SQLite database at path using the pre-migration
// DDL, hands it to seed for row setup, and closes it. The caller then reopens
// the file through Open(), whose runMigrationsLocked must bring the legacy
// shape up to date in place.
func openLegacyDB(t *testing.T, path string, seed func(legacy *DB)) {
	t.Helper()

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("failed to open raw legacy database: %v", err)
	}

	legacy := &DB{sqlDB: raw}
	if _, err := raw.Exec(legacyVPNSessionsDDL); err != nil {
		_ = raw.Close()
		t.Fatalf("failed to execute legacy DDL: %v", err)
	}
	if seed != nil {
		seed(legacy)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("failed to close legacy database: %v", err)
	}
}
