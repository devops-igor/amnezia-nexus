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
	if err := d.migrateBackendTunnelsProtocol(ctx); err != nil {
		return err
	}
	if err := d.migrateAWGIPAllocations(ctx); err != nil {
		return err
	}
	if err := d.migrateGigahostOrders(ctx); err != nil {
		return err
	}
	if err := d.migrateGigahostSetupIntents(ctx); err != nil {
		return err
	}
	if err := d.migrateNotificationProducerStateGeneration(ctx); err != nil {
		return err
	}
	if err := d.migrateServersProviderAbsence(ctx); err != nil {
		return err
	}
	if err := d.migrateServersProviderAccount(ctx); err != nil {
		return err
	}
	return d.migratePeerLifecycle(ctx)
}

// migrateServersProviderAbsence adds the provider_absent_at column to servers.
//
// Existing rows start empty, which is the correct value: no successful provider
// inventory read has judged them yet, so nothing may claim they are absent. The
// column's presence is the migration marker.
func (d *DB) migrateServersProviderAbsence(ctx context.Context) error {
	return d.ensureServerTextColumn(ctx, "provider_absent_at",
		`ALTER TABLE servers ADD COLUMN provider_absent_at TEXT NOT NULL DEFAULT ''`)
}

// migrateServersProviderAccount adds the provider_account_id column to servers.
//
// It records which provider account a server row was provisioned under, so an
// inventory read may only judge rows of the account that answered. Existing rows
// start empty, which is the fail-safe value: their association is unknown, so no
// read may mark them absent. The column's presence is the migration marker.
func (d *DB) migrateServersProviderAccount(ctx context.Context) error {
	return d.ensureServerTextColumn(ctx, "provider_account_id",
		`ALTER TABLE servers ADD COLUMN provider_account_id TEXT NOT NULL DEFAULT ''`)
}

// ensureServerTextColumn runs ddl when the servers table does not already carry
// the named column. Both callers add a NOT NULL TEXT column whose default is the
// empty string, and for both an empty value means "not recorded", which is the
// reading that never invents a fact.
func (d *DB) ensureServerTextColumn(ctx context.Context, column, ddl string) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(servers)")
	if err != nil {
		return fmt.Errorf("failed to inspect servers schema: %w", err)
	}
	defer rows.Close()

	hasColumn := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, column) {
			hasColumn = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if hasColumn {
		return nil
	}
	if _, err := d.sqlDB.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to add servers %s column: %w", column, err)
	}
	return nil
}

// migrateNotificationProducerStateGeneration adds the transition generation used
// to build a stable event key. Existing rows start at generation 0 and advance on
// their next observed change.
func (d *DB) migrateNotificationProducerStateGeneration(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(notification_producer_state)")
	if err != nil {
		return fmt.Errorf("inspect notification producer state schema: %w", err)
	}
	defer rows.Close()

	hasGeneration := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == "generation" {
			hasGeneration = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if hasGeneration {
		return nil
	}
	if _, err := d.sqlDB.ExecContext(ctx,
		`ALTER TABLE notification_producer_state ADD COLUMN generation INTEGER NOT NULL DEFAULT 0`,
	); err != nil {
		return fmt.Errorf("add notification producer generation: %w", err)
	}
	return nil
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
	if _, err := d.sqlDB.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)"); err != nil {
		return fmt.Errorf("failed to create idx_users_username: %w", err)
	}
	return nil
}

// runMigrationTx runs one migration's work inside a single transaction and
// commits it.
//
// Migrations that record their completion in migration_flags must write the data
// rewrite and the flag from the same transaction: otherwise a failed rewrite can
// be followed by a successful flag write and the migration is recorded as done
// while the data is untouched. fn must therefore perform the guard read, the
// rewrite and the flag write through tx.
//
// The caller must already hold writeMu (InitSchema does); WithTransaction is not
// used here because it takes that lock again.
func (d *DB) runMigrationTx(ctx context.Context, name string, fn func(tx *sql.Tx) error) error {
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin %s migration: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit %s migration: %w", name, err)
	}
	return nil
}

// migrationAlreadyApplied reports whether the named migration flag is set. A
// missing row means "not applied"; any other read error is returned. This is the
// guard every flag migration uses, unchanged in strictness: a non-empty flag
// skips the work, a read failure aborts initialization.
func migrationAlreadyApplied(ctx context.Context, tx *sql.Tx, key string) (bool, error) {
	var flag string
	err := tx.QueryRowContext(ctx, "SELECT value FROM migration_flags WHERE key = ?", key).Scan(&flag)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to read %s migration flag: %w", key, err)
	}
	return flag != "", nil
}

// markMigrationApplied records a migration's completion flag inside the
// migration's own transaction, so it commits together with the rewrite.
func markMigrationApplied(ctx context.Context, tx *sql.Tx, key string) error {
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO migration_flags (key, value) VALUES (?, '1') ON CONFLICT(key) DO UPDATE SET value = '1'", key); err != nil {
		return fmt.Errorf("failed to record %s migration: %w", key, err)
	}
	return nil
}

// serverCred is one servers row whose SSH credentials may need encryption.
type serverCred struct {
	id      int64
	sshPass string
	sshKey  string
}

// collectServerCredentials reads the credentials of every server.
func collectServerCredentials(ctx context.Context, tx *sql.Tx) ([]serverCred, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, ssh_pass, ssh_key FROM servers")
	if err != nil {
		return nil, fmt.Errorf("failed to read servers for credential encryption: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []serverCred
	for rows.Next() {
		var sc serverCred
		var p, k sql.NullString
		if err := rows.Scan(&sc.id, &p, &k); err != nil {
			return nil, fmt.Errorf("failed to scan server credentials: %w", err)
		}
		sc.sshPass = p.String
		sc.sshKey = k.String
		creds = append(creds, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed reading server credentials: %w", err)
	}
	return creds, nil
}

// encryptServerCredentials encrypts the plaintext parts of one server's
// credentials. dirty reports whether anything had to be rewritten.
func encryptServerCredentials(secretKey string, sc serverCred) (encPass, encKey string, dirty bool, err error) {
	encPass, encKey = sc.sshPass, sc.sshKey
	if sc.sshPass != "" && !security.LooksLikeFernetToken(sc.sshPass) {
		if encPass, err = security.EncryptCredential(sc.sshPass, secretKey); err != nil {
			return "", "", false, fmt.Errorf("failed to encrypt ssh_pass for server %d: %w", sc.id, err)
		}
		dirty = true
	}
	if sc.sshKey != "" && !security.LooksLikeFernetToken(sc.sshKey) {
		if encKey, err = security.EncryptCredential(sc.sshKey, secretKey); err != nil {
			return "", "", false, fmt.Errorf("failed to encrypt ssh_key for server %d: %w", sc.id, err)
		}
		dirty = true
	}
	return encPass, encKey, dirty, nil
}

// migratePlaintextCredentials encrypts legacy plaintext SSH credentials in place.
//
// The guard read, the rewrite and the 'credentials_encrypted' flag share one
// transaction: any failure (read, encryption, write, flag, commit) rolls the
// migration back, so the flag can never record encryption that did not happen and
// plaintext credentials cannot survive behind it.
func (d *DB) migratePlaintextCredentials(ctx context.Context) error {
	if d.secretKey == "" {
		return nil
	}

	return d.runMigrationTx(ctx, "credentials_encrypted", func(tx *sql.Tx) error {
		done, err := migrationAlreadyApplied(ctx, tx, "credentials_encrypted")
		if err != nil || done {
			return err
		}

		creds, err := collectServerCredentials(ctx, tx)
		if err != nil {
			return err
		}
		for _, sc := range creds {
			encPass, encKey, dirty, err := encryptServerCredentials(d.secretKey, sc)
			if err != nil {
				return err
			}
			if !dirty {
				continue
			}
			if _, err := tx.ExecContext(ctx, "UPDATE servers SET ssh_pass = ?, ssh_key = ? WHERE id = ?", encPass, encKey, sc.id); err != nil {
				return fmt.Errorf("failed to store encrypted credentials for server %d: %w", sc.id, err)
			}
		}

		return markMigrationApplied(ctx, tx, "credentials_encrypted")
	})
}

// protocolCleanup is one servers row whose stored protocols need sensitive
// fields removed.
type protocolCleanup struct {
	id       int64
	cleanedB string
}

// collectProtocolCleanups reads the servers table and returns the cleaned
// protocol JSON of every row that stores any. A value that is not valid JSON is
// skipped: no plaintext field can be identified in it, and failing startup would
// not remove a key from it either. A row that cannot be read is a failure.
func collectProtocolCleanups(ctx context.Context, tx *sql.Tx) ([]protocolCleanup, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id, protocols FROM servers")
	if err != nil {
		return nil, fmt.Errorf("failed to read servers for sensitive key cleanup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var updates []protocolCleanup
	for rows.Next() {
		var id int64
		var protoJSON sql.NullString
		if err := rows.Scan(&id, &protoJSON); err != nil {
			return nil, fmt.Errorf("failed to scan server protocols: %w", err)
		}
		if !protoJSON.Valid || protoJSON.String == "" {
			continue
		}
		var protoMap map[string]any
		if err := json.Unmarshal([]byte(protoJSON.String), &protoMap); err != nil {
			continue
		}
		cleanedBytes, err := json.Marshal(security.StripSensitiveProtocolFields(protoMap))
		if err != nil {
			return nil, fmt.Errorf("failed to encode cleaned protocols for server %d: %w", id, err)
		}
		updates = append(updates, protocolCleanup{id: id, cleanedB: string(cleanedBytes)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed reading server protocols: %w", err)
	}
	return updates, nil
}

// migrateXraySensitiveKeys removes private keys from stored protocol definitions.
//
// The guard read, the rewrite and the 'xray_private_keys_cleared' flag share one
// transaction (see runMigrationTx).
func (d *DB) migrateXraySensitiveKeys(ctx context.Context) error {
	return d.runMigrationTx(ctx, "xray_private_keys_cleared", func(tx *sql.Tx) error {
		done, err := migrationAlreadyApplied(ctx, tx, "xray_private_keys_cleared")
		if err != nil || done {
			return err
		}

		updates, err := collectProtocolCleanups(ctx, tx)
		if err != nil {
			return err
		}
		for _, u := range updates {
			if _, err := tx.ExecContext(ctx, "UPDATE servers SET protocols = ? WHERE id = ?", u.cleanedB, u.id); err != nil {
				return fmt.Errorf("failed to store cleaned protocols for server %d: %w", u.id, err)
			}
		}

		return markMigrationApplied(ctx, tx, "xray_private_keys_cleared")
	})
}

// readSSLSetting returns the raw ssl setting value, or "" when it is absent. A
// missing setting is not a failure: there is nothing to encrypt.
func readSSLSetting(ctx context.Context, tx *sql.Tx) (string, error) {
	var value sql.NullString
	err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = 'ssl'").Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to read ssl settings: %w", err)
	}
	if !value.Valid {
		return "", nil
	}
	return value.String, nil
}

// encryptSSLSetting encrypts the plaintext key material in one raw ssl setting
// value. dirty reports whether the value had to be rewritten; a value that is not
// valid JSON is returned unchanged, because no plaintext field can be identified
// in it.
func encryptSSLSetting(secretKey, raw string) (encrypted string, dirty bool, err error) {
	var sslMap map[string]any
	if err := json.Unmarshal([]byte(raw), &sslMap); err != nil {
		return raw, false, nil
	}
	for _, field := range []string{"key_text", "cert_text"} {
		value, ok := sslMap[field].(string)
		if !ok || value == "" || security.LooksLikeFernetToken(value) {
			continue
		}
		enc, err := security.EncryptCredential(value, secretKey)
		if err != nil {
			return "", false, fmt.Errorf("failed to encrypt ssl %s: %w", field, err)
		}
		sslMap[field] = enc
		dirty = true
	}
	if !dirty {
		return raw, false, nil
	}
	encoded, err := json.Marshal(sslMap)
	if err != nil {
		return "", false, fmt.Errorf("failed to encode ssl settings: %w", err)
	}
	return string(encoded), true, nil
}

// migratePlaintextSSLKeys encrypts legacy plaintext TLS key material in the ssl
// setting.
//
// The guard read, the rewrite and the 'ssl_keys_encrypted' flag share one
// transaction (see runMigrationTx).
func (d *DB) migratePlaintextSSLKeys(ctx context.Context) error {
	if d.secretKey == "" {
		return nil
	}

	return d.runMigrationTx(ctx, "ssl_keys_encrypted", func(tx *sql.Tx) error {
		done, err := migrationAlreadyApplied(ctx, tx, "ssl_keys_encrypted")
		if err != nil || done {
			return err
		}

		raw, err := readSSLSetting(ctx, tx)
		if err != nil {
			return err
		}
		if raw == "" {
			return markMigrationApplied(ctx, tx, "ssl_keys_encrypted")
		}

		encrypted, dirty, err := encryptSSLSetting(d.secretKey, raw)
		if err != nil {
			return err
		}
		if dirty {
			if _, err := tx.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES ('ssl', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", encrypted); err != nil {
				return fmt.Errorf("failed to store encrypted ssl settings: %w", err)
			}
		}

		return markMigrationApplied(ctx, tx, "ssl_keys_encrypted")
	})
}

// migrateBackendTunnelsProtocol adds protocol and protocol_params columns to
// backend_tunnels for multi-protocol egress backend support (issue #632).
// Existing rows default to protocol='awg' and empty encrypted protocol_params.
func (d *DB) migrateBackendTunnelsProtocol(ctx context.Context) error {
	rows, err := d.sqlDB.QueryContext(ctx, "PRAGMA table_info(backend_tunnels)")
	if err != nil {
		return fmt.Errorf("failed to inspect backend_tunnels schema: %w", err)
	}
	defer rows.Close()

	hasProtocol := false
	hasProtocolParams := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal sql.NullString
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "protocol") {
			hasProtocol = true
		}
		if strings.EqualFold(name, "protocol_params") {
			hasProtocolParams = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !hasProtocol {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN protocol TEXT NOT NULL DEFAULT 'awg'"); err != nil {
			return fmt.Errorf("failed to add protocol column: %w", err)
		}
	}
	if !hasProtocolParams {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN protocol_params TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("failed to add protocol_params column: %w", err)
		}
	}
	return nil
}
