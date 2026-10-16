package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

func (d *DB) runMigrationsLocked(ctx context.Context) error {
	if err := d.migratePlaintextCredentials(ctx); err != nil {
		return err
	}
	if err := d.migrateXraySensitiveKeys(ctx); err != nil {
		return err
	}
	if err := d.migratePlaintextSSLKeys(ctx); err != nil {
		return err
	}
	if err := d.migrateUniqueUsernameIndex(ctx); err != nil {
		return err
	}
	if err := d.migrateUserConnectionsClientParams(ctx); err != nil {
		return err
	}
	if err := d.migrateUserSessionVersion(ctx); err != nil {
		return err
	}
	if err := d.migrateBackendTunnelsProbePrivateKey(ctx); err != nil {
		return err
	}
	if err := d.migrateVPNSessionsConnectionName(ctx); err != nil {
		return err
	}
	if err := d.migrateBackendTunnelsDisableReason(ctx); err != nil {
		return err
	}
	if err := d.migrateBackendTunnelsEnabled(ctx); err != nil {
		return err
	}
	if err := d.migrateAWGIPAllocations(ctx); err != nil {
		return err
	}
	return d.migratePeerLifecycle(ctx)
}

func (d *DB) migratePeerLifecycle(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS peer_lifecycle (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			client_id TEXT NOT NULL,
			name TEXT DEFAULT '',
			user_id TEXT DEFAULT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(server_id, protocol, client_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_peer_lifecycle_server_proto ON peer_lifecycle(server_id, protocol)`,
		`CREATE INDEX IF NOT EXISTS idx_peer_lifecycle_status ON peer_lifecycle(status)`,
		`INSERT OR IGNORE INTO peer_lifecycle (server_id, protocol, client_id, name, user_id, status, created_at, updated_at)
		 SELECT server_id, protocol, client_id, COALESCE(name, ''), user_id, 'active',
		        COALESCE(NULLIF(created_at, ''), datetime('now')),
		        COALESCE(NULLIF(created_at, ''), datetime('now'))
		 FROM user_connections
		 WHERE client_id IS NOT NULL AND client_id != ''`,
	}
	for _, q := range queries {
		if _, err := d.sqlDB.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed to migrate peer_lifecycle: %w", err)
		}
	}
	return nil
}

func (d *DB) migrateAWGIPAllocations(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS awg_ip_allocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			server_id INTEGER NOT NULL,
			client_id TEXT NOT NULL,
			ip TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'allocated',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(server_id, ip)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_awg_ip_allocations_server ON awg_ip_allocations(server_id)`,
		`CREATE INDEX IF NOT EXISTS idx_awg_ip_allocations_server_client ON awg_ip_allocations(server_id, client_id)`,
	}
	for _, q := range queries {
		if _, err := d.sqlDB.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed to migrate awg_ip_allocations: %w", err)
		}
	}
	return d.reconcileLegacyDuplicateActiveAllocationsLocked(ctx)
}

func (d *DB) migrateUserSessionVersion(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(users)")
	if err != nil {
		return fmt.Errorf("failed to inspect users schema: %w", err)
	}
	defer rows.Close()

	hasSessionVersion := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "session_version") {
			hasSessionVersion = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasSessionVersion {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1"); err != nil {
			return fmt.Errorf("failed to add session_version column to users: %w", err)
		}
	}
	return nil
}

// migrateBackendTunnelsProbePrivateKey adds the probe_private_key column to
// backend_tunnels on databases created before the dedicated health-probe key
// existed (issue #43). Existing rows start empty and are backfilled by the
// VPN service at startup (EnsureBackendProbeKeys), which also re-registers
// the probe peer on the backend server.
func (d *DB) migrateBackendTunnelsProbePrivateKey(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(backend_tunnels)")
	if err != nil {
		return fmt.Errorf("failed to inspect backend_tunnels schema: %w", err)
	}
	defer rows.Close()

	hasProbeKey := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "probe_private_key") {
			hasProbeKey = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasProbeKey {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN probe_private_key TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add probe_private_key column: %w", err)
		}
	}
	return nil
}

// migrateVPNSessionsConnectionName adds the connection_name column to
// vpn_sessions on databases created before per-session connection config
// names were tracked (issue #189 improvement round). The name is resolved
// from the user_connection at handshake time and stored on the session row;
// legacy rows start empty and are never backfilled (the config that a
// historical session used is unknowable after the fact).
func (d *DB) migrateVPNSessionsConnectionName(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(vpn_sessions)")
	if err != nil {
		return fmt.Errorf("failed to inspect vpn_sessions schema: %w", err)
	}
	defer rows.Close()

	hasConnectionName := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "connection_name") {
			hasConnectionName = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasConnectionName {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE vpn_sessions ADD COLUMN connection_name TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add connection_name column: %w", err)
		}
	}
	return nil
}

// migrateBackendTunnelsDisableReason adds disable_reason and state_version columns
// to backend_tunnels on databases created before persistent disable provenance and
// state versioning existed (issue #279).
func (d *DB) migrateBackendTunnelsDisableReason(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(backend_tunnels)")
	if err != nil {
		return fmt.Errorf("failed to inspect backend_tunnels schema: %w", err)
	}
	defer rows.Close()

	hasDisableReason := false
	hasStateVersion := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "disable_reason") {
			hasDisableReason = true
		}
		if strings.EqualFold(name, "state_version") {
			hasStateVersion = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !hasDisableReason {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN disable_reason TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add disable_reason column: %w", err)
		}
	}
	if !hasStateVersion {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN state_version INTEGER NOT NULL DEFAULT 1"); err != nil {
			return fmt.Errorf("failed to add state_version column: %w", err)
		}
	}
	return nil
}

// migrateBackendTunnelsEnabled separates administrative intent from runtime
// health (issue #90). Legacy rows disabled by an administrator map to
// enabled=false; health-disabled rows remain enabled so self-healing can
// continue to own their runtime status.
func (d *DB) migrateBackendTunnelsEnabled(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(backend_tunnels)")
	if err != nil {
		return fmt.Errorf("failed to inspect backend_tunnels schema: %w", err)
	}

	hasEnabled := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			_ = rows.Close()
			return err
		}
		if strings.EqualFold(name, "enabled") {
			hasEnabled = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	// The presence of the column is the migration marker. Once it exists,
	// enabled is authoritative modern state and must never be re-inferred from
	// runtime health on later opens.
	if hasEnabled {
		return nil
	}

	// Add the marker column and translate legacy rows in one SQLite
	// transaction. SQLite DDL is transactional, so a crash cannot leave the
	// column present without the accompanying legacy-state translation.
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin backend enabled migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1"); err != nil {
		return fmt.Errorf("failed to add backend_tunnels enabled column: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE backend_tunnels
		 SET enabled = 0,
		     disable_reason = CASE
		         WHEN status = ? AND (disable_reason = '' OR disable_reason IS NULL) THEN ?
		         ELSE disable_reason
		     END
		 WHERE disable_reason = ?
		    OR (status = ? AND (disable_reason = '' OR disable_reason IS NULL))`,
		models.TunnelStatusDisabled,
		models.DisableReasonAdmin,
		models.DisableReasonAdmin,
		models.TunnelStatusDisabled,
	); err != nil {
		return fmt.Errorf("failed to migrate administrative backend state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit backend enabled migration: %w", err)
	}
	return nil
}

func (d *DB) migrateUserConnectionsClientParams(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(user_connections)")
	if err != nil {
		return fmt.Errorf("failed to inspect user_connections schema: %w", err)
	}
	defer rows.Close()

	hasClientParams := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "client_params") {
			hasClientParams = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasClientParams {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE user_connections ADD COLUMN client_params TEXT DEFAULT '{}'"); err != nil {
			return fmt.Errorf("failed to add client_params column: %w", err)
		}
	}
	return nil
}

func (d *DB) migrateUniqueUsernameIndex(ctx context.Context) error {
	_, _ = d.sqlDB.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)")
	return nil
}

func (d *DB) migratePlaintextCredentials(ctx context.Context) error {
	if d.secretKey == "" {
		return nil
	}

	var credsFlag string
	row := d.sqlDB.QueryRowContext(ctx, "SELECT value FROM migration_flags WHERE key = 'credentials_encrypted'")
	if err := row.Scan(&credsFlag); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if credsFlag != "" {
		return nil
	}

	rows, err := d.sqlDB.QueryContext(ctx, "SELECT id, ssh_pass, ssh_key FROM servers")
	if err == nil {
		defer rows.Close()
		type serverCred struct {
			id      int64
			sshPass string
			sshKey  string
		}
		var serversToEncrypt []serverCred
		for rows.Next() {
			var sc serverCred
			var p, k sql.NullString
			if err := rows.Scan(&sc.id, &p, &k); err == nil {
				sc.sshPass = p.String
				sc.sshKey = k.String
				serversToEncrypt = append(serversToEncrypt, sc)
			}
		}
		for _, sc := range serversToEncrypt {
			encPass := sc.sshPass
			encKey := sc.sshKey
			dirty := false
			if sc.sshPass != "" && !security.LooksLikeFernetToken(sc.sshPass) {
				if ep, err := security.EncryptCredential(sc.sshPass, d.secretKey); err == nil {
					encPass = ep
					dirty = true
				}
			}
			if sc.sshKey != "" && !security.LooksLikeFernetToken(sc.sshKey) {
				if ek, err := security.EncryptCredential(sc.sshKey, d.secretKey); err == nil {
					encKey = ek
					dirty = true
				}
			}
			if dirty {
				_, _ = d.sqlDB.ExecContext(ctx, "UPDATE servers SET ssh_pass = ?, ssh_key = ? WHERE id = ?", encPass, encKey, sc.id)
			}
		}
	}

	_, err = d.sqlDB.ExecContext(ctx, "INSERT INTO migration_flags (key, value) VALUES ('credentials_encrypted', '1') ON CONFLICT(key) DO UPDATE SET value = '1'")
	return err
}

func (d *DB) migrateXraySensitiveKeys(ctx context.Context) error {
	var xrayFlag string
	row := d.sqlDB.QueryRowContext(ctx, "SELECT value FROM migration_flags WHERE key = 'xray_private_keys_cleared'")
	if err := row.Scan(&xrayFlag); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if xrayFlag != "" {
		return nil
	}

	rows, err := d.sqlDB.QueryContext(ctx, "SELECT id, protocols FROM servers")
	if err == nil {
		defer rows.Close()
		type srvProto struct {
			id       int64
			cleanedB string
		}
		var toUpdate []srvProto
		for rows.Next() {
			var id int64
			var protoJSON sql.NullString
			if err := rows.Scan(&id, &protoJSON); err == nil && protoJSON.Valid && protoJSON.String != "" {
				var protoMap map[string]any
				if err := json.Unmarshal([]byte(protoJSON.String), &protoMap); err == nil {
					cleaned := security.StripSensitiveProtocolFields(protoMap)
					if cleanedBytes, err := json.Marshal(cleaned); err == nil {
						toUpdate = append(toUpdate, srvProto{id: id, cleanedB: string(cleanedBytes)})
					}
				}
			}
		}
		_ = rows.Close()
		for _, u := range toUpdate {
			_, _ = d.sqlDB.ExecContext(ctx, "UPDATE servers SET protocols = ? WHERE id = ?", u.cleanedB, u.id)
		}
	}

	_, err = d.sqlDB.ExecContext(ctx, "INSERT INTO migration_flags (key, value) VALUES ('xray_private_keys_cleared', '1') ON CONFLICT(key) DO UPDATE SET value = '1'")
	return err
}

func (d *DB) migratePlaintextSSLKeys(ctx context.Context) error {
	if d.secretKey == "" {
		return nil
	}

	var sslFlag string
	row := d.sqlDB.QueryRowContext(ctx, "SELECT value FROM migration_flags WHERE key = 'ssl_keys_encrypted'")
	if err := row.Scan(&sslFlag); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if sslFlag != "" {
		return nil
	}

	var sslVal sql.NullString
	row = d.sqlDB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'ssl'")
	if err := row.Scan(&sslVal); err == nil && sslVal.Valid && sslVal.String != "" {
		var sslMap map[string]any
		if err := json.Unmarshal([]byte(sslVal.String), &sslMap); err == nil {
			dirty := false
			if kt, ok := sslMap["key_text"].(string); ok && kt != "" && !security.LooksLikeFernetToken(kt) {
				if enc, err := security.EncryptCredential(kt, d.secretKey); err == nil {
					sslMap["key_text"] = enc
					dirty = true
				}
			}
			if ct, ok := sslMap["cert_text"].(string); ok && ct != "" && !security.LooksLikeFernetToken(ct) {
				if enc, err := security.EncryptCredential(ct, d.secretKey); err == nil {
					sslMap["cert_text"] = enc
					dirty = true
				}
			}
			if dirty {
				if sslBytes, err := json.Marshal(sslMap); err == nil {
					_, _ = d.sqlDB.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES ('ssl', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", string(sslBytes))
				}
			}
		}
	}

	_, err := d.sqlDB.ExecContext(ctx, "INSERT INTO migration_flags (key, value) VALUES ('ssl_keys_encrypted', '1') ON CONFLICT(key) DO UPDATE SET value = '1'")
	return err
}
