package database

import (
	"context"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
	_ "modernc.org/sqlite" // Pure-Go SQLite database driver
)

//go:embed schema.sql
var SchemaSQL string

// DefaultSettings maps configuration keys to their default JSON values.
var DefaultSettings = map[string]string{
	"schema_version": `"1"`,
	"appearance":     `{"title":"Amnezia","logo":"🛡","subtitle":"Web Panel","language":"en"}`,
	"captcha":        `{"enabled":false}`,
	"telegram":       `{}`,
	"ssl":            `{"enabled":false,"domain":"","cert_path":"","key_path":"","cert_text":"","key_text":"","panel_port":5000}`,
	"limits":         `{"max_connections_per_user":10,"connection_rate_limit_count":5,"connection_rate_limit_window":60}`,
	"vpn_config":     `{"algorithm":"least_conn","weights":{},"health_threshold_ms":2000,"listen_port":51820,"subnet_cidr":"10.100.0.0/16","max_total_peers":1000,"max_peers_per_backend":200}`,
}

// Column allowlists for update methods to prevent SQL injection
var (
	allowedServerColumns = map[string]bool{
		"name":        true,
		"host":        true,
		"ssh_user":    true,
		"ssh_port":    true,
		"ssh_pass":    true,
		"ssh_key":     true,
		"protocols":   true,
		"server_info": true,
		"created_at":  true,
	}

	allowedUserColumns = map[string]bool{
		"username":                 true,
		"email":                    true,
		"telegramId":               true,
		"description":              true,
		"password_hash":            true,
		"role":                     true,
		"enabled":                  true,
		"traffic_limit":            true,
		"traffic_used":             true,
		"traffic_total":            true,
		"traffic_total_rx":         true,
		"traffic_total_tx":         true,
		"monthly_rx":               true,
		"monthly_tx":               true,
		"monthly_reset_at":         true,
		"traffic_reset_strategy":   true,
		"share_enabled":            true,
		"share_token":              true,
		"share_password_hash":      true,
		"created_at":               true,
		"last_reset_at":            true,
		"expiration_date":          true,
		"expires_at":               true,
		"awg_mimicry":              true,
		"password_change_required": true,
		"session_version":          true,
		"limits":                   true,
	}

	allowedConnectionColumns = map[string]bool{
		"user_id":          true,
		"server_id":        true,
		"protocol":         true,
		"client_id":        true,
		"name":             true,
		"awg_mimicry":      true,
		"client_params":    true,
		"last_rx":          true,
		"last_tx":          true,
		"traffic_delta_rx": true,
		"traffic_delta_tx": true,
		"traffic_total_rx": true,
		"traffic_total_tx": true,
		"traffic_total":    true,
		"created_at":       true,
	}

	allowedBackendTunnelColumns = map[string]bool{
		"server_id":          true,
		"interface_name":     true,
		"public_key":         true,
		"private_key":        true,
		"probe_private_key":  true,
		"endpoint":           true,
		"enabled":            true,
		"status":             true,
		"disable_reason":     true,
		"state_version":      true,
		"last_health_check":  true,
		"latency_ms":         true,
		"active_connections": true,
		"created_at":         true,
	}
)

// DB wraps an sql.DB handle and serializes write operations to ensure SQLite thread-safety.
type DB struct {
	dbPath            string
	secretKey         string
	sqlDB             *sql.DB
	writeMu           sync.Mutex
	mu                sync.RWMutex
	reachabilityMu    sync.RWMutex
	reachabilityCache map[int64]models.ReachabilityStatus
}

// Open opens a connection to the SQLite database with WAL mode, busy timeout, and foreign keys enabled.
func Open(dbPath, secretKey string) (*DB, error) {
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file::memory:") && !strings.Contains(dbPath, "mode=memory") {
		dir := filepath.Dir(dbPath)
		if dir != "" && dir != "." {
			if err := CheckDirWritable(dir); err != nil {
				return nil, err
			}
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", dbPath)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// SQLite single-writer connection pool bounds
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	db := &DB{
		dbPath:            dbPath,
		secretKey:         secretKey,
		sqlDB:             sqlDB,
		reachabilityCache: make(map[int64]models.ReachabilityStatus),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.InitSchema(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

// New is an alias for Open to support multiple calling conventions.
func New(dbPath string, secretKeys ...string) (*DB, error) {
	var secretKey string
	if len(secretKeys) > 0 {
		secretKey = secretKeys[0]
	}
	return Open(dbPath, secretKey)
}

// InitSchema executes DDL and applies default seed settings and migrations.
func (d *DB) InitSchema(ctx context.Context) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	// Reconcile legacy duplicate active AWG IP allocations before applying schema unique index
	if err := d.reconcileLegacyDuplicateActiveAllocationsLocked(ctx); err != nil {
		return fmt.Errorf("failed to reconcile legacy duplicate active allocations: %w", err)
	}

	if _, err := d.sqlDB.ExecContext(ctx, SchemaSQL); err != nil {
		return fmt.Errorf("failed to execute schema DDL: %w", err)
	}

	if err := d.ensureDefaultSettingsLocked(ctx); err != nil {
		return err
	}

	return d.runMigrationsLocked(ctx)
}

// EnsureDefaultSettings ensures all default keys exist in settings table.
func (d *DB) EnsureDefaultSettings(ctx context.Context) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.ensureDefaultSettingsLocked(ctx)
}

func (d *DB) ensureDefaultSettingsLocked(ctx context.Context) error {
	for key, val := range DefaultSettings {
		_, err := d.sqlDB.ExecContext(ctx, "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", key, val)
		if err != nil {
			return fmt.Errorf("failed to seed default setting %s: %w", key, err)
		}
	}
	return nil
}

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

	if !hasEnabled {
		if _, err := d.sqlDB.ExecContext(ctx, "ALTER TABLE backend_tunnels ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1"); err != nil {
			return fmt.Errorf("failed to add backend_tunnels enabled column: %w", err)
		}
	}

	if _, err := d.sqlDB.ExecContext(ctx,
		`UPDATE backend_tunnels SET enabled = 0
		 WHERE disable_reason = ?
		    OR (status = ? AND (disable_reason = '' OR disable_reason IS NULL))`,
		models.DisableReasonAdmin,
		models.TunnelStatusDisabled,
	); err != nil {
		return fmt.Errorf("failed to migrate administrative backend state: %w", err)
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

// WithTransaction executes fn within an exclusive SQLite transaction with write mutex serialization.
func (d *DB) WithTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ExecuteTransaction is an alias for WithTransaction.
func (d *DB) ExecuteTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	return d.WithTransaction(ctx, fn)
}

// Ping verifies database connectivity.
func (d *DB) Ping(ctx context.Context) error {
	return d.sqlDB.PingContext(ctx)
}

// Close gracefully closes the database connection handle.
func (d *DB) Close() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.sqlDB.Close()
}

// SQLDB returns the underlying *sql.DB handle.
func (d *DB) SQLDB() *sql.DB {
	return d.sqlDB
}

// ExecContext executes a direct query without returning rows.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.sqlDB.ExecContext(ctx, query, args...)
}

// QueryRowContext executes a direct query expected to return at most one row.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sqlDB.QueryRowContext(ctx, query, args...)
}

// QueryContext executes a direct query that returns rows.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sqlDB.QueryContext(ctx, query, args...)
}

// SecretKey returns the configured database credential secret key.
func (d *DB) SecretKey() string {
	return d.secretKey
}

// Helper functions for time and null conversions

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func formatTimePtr(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

func nullStringToPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	val := ns.String
	return &val
}

func constantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type legacyActiveAllocRow struct {
	id int64
	ip string
}

func (d *DB) reconcileLegacyDuplicateActiveAllocationsLocked(ctx context.Context) error {
	var tableExists int
	err := d.sqlDB.QueryRowContext(ctx, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='awg_ip_allocations'").Scan(&tableExists)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to check if awg_ip_allocations table exists: %w", err)
	}

	// a) Safely delete identical duplicate active rows (same server_id, client_id, and ip)
	_, err = d.sqlDB.ExecContext(ctx, `
		DELETE FROM awg_ip_allocations
		WHERE status = 'allocated'
		  AND id NOT IN (
		      SELECT MIN(id)
		      FROM awg_ip_allocations
		      WHERE status = 'allocated'
		      GROUP BY server_id, client_id, ip
		  )
	`)
	if err != nil {
		return fmt.Errorf("failed to delete identical duplicate active allocations: %w", err)
	}

	// b) For divergent active allocations (same server_id, client_id, but different IPs)
	type dupGroup struct {
		serverID int64
		clientID string
	}

	groupRows, err := d.sqlDB.QueryContext(ctx, `
		SELECT server_id, client_id
		FROM awg_ip_allocations
		WHERE status = 'allocated'
		GROUP BY server_id, client_id
		HAVING COUNT(*) > 1
	`)
	if err != nil {
		return fmt.Errorf("failed to query divergent active allocation groups: %w", err)
	}

	var groups []dupGroup
	for groupRows.Next() {
		var g dupGroup
		if err := groupRows.Scan(&g.serverID, &g.clientID); err != nil {
			_ = groupRows.Close()
			return fmt.Errorf("failed to scan divergent allocation group: %w", err)
		}
		groups = append(groups, g)
	}
	if err := groupRows.Err(); err != nil {
		_ = groupRows.Close()
		return fmt.Errorf("failed reading divergent allocation groups: %w", err)
	}
	_ = groupRows.Close()

	if len(groups) > 0 {
		var ucExists int
		err = d.sqlDB.QueryRowContext(ctx, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='user_connections'").Scan(&ucExists)
		hasUserConnections := (err == nil)

		now := time.Now().UTC().Format(time.RFC3339)
		for _, g := range groups {
			allocs, err := d.fetchActiveAllocationsForGroupLocked(ctx, g.serverID, g.clientID)
			if err != nil {
				return err
			}
			if len(allocs) <= 1 {
				continue
			}

			var retainID int64 = -1
			if hasUserConnections {
				retainID = d.findMatchingAllocIDFromUserConnectionsLocked(ctx, g.serverID, g.clientID, allocs)
			}
			if retainID == -1 {
				retainID = allocs[0].id
			}

			for _, a := range allocs {
				if a.id == retainID {
					continue
				}
				_, err = d.sqlDB.ExecContext(ctx,
					"UPDATE awg_ip_allocations SET status = 'superseded', updated_at = ? WHERE id = ?",
					now, a.id,
				)
				if err != nil {
					return fmt.Errorf("failed to mark divergent allocation %d as superseded: %w", a.id, err)
				}
			}
		}
	}

	// c) Then create the unique partial index
	_, err = d.sqlDB.ExecContext(ctx,
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_awg_ip_allocations_server_client_active ON awg_ip_allocations(server_id, client_id) WHERE status = 'allocated'",
	)
	if err != nil {
		return fmt.Errorf("failed to create uq_awg_ip_allocations_server_client_active index: %w", err)
	}

	return nil
}

func (d *DB) fetchActiveAllocationsForGroupLocked(ctx context.Context, serverID int64, clientID string) ([]legacyActiveAllocRow, error) {
	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT id, ip FROM awg_ip_allocations WHERE server_id = ? AND client_id = ? AND status = 'allocated' ORDER BY id ASC",
		serverID, clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch active allocations for group (%d, %s): %w", serverID, clientID, err)
	}
	defer rows.Close()

	var allocs []legacyActiveAllocRow
	for rows.Next() {
		var a legacyActiveAllocRow
		if err := rows.Scan(&a.id, &a.ip); err != nil {
			return nil, fmt.Errorf("failed to scan active allocation: %w", err)
		}
		allocs = append(allocs, a)
	}
	return allocs, rows.Err()
}

func (d *DB) findMatchingAllocIDFromUserConnectionsLocked(ctx context.Context, serverID int64, clientID string, allocs []legacyActiveAllocRow) int64 {
	rows, err := d.sqlDB.QueryContext(ctx,
		"SELECT client_params FROM user_connections WHERE server_id = ? AND (client_id = ? OR id = ?)",
		serverID, clientID, clientID,
	)
	if err != nil {
		return -1
	}
	defer rows.Close()

	var candidateIPs []string
	for rows.Next() {
		var raw sql.NullString
		if err := rows.Scan(&raw); err != nil || !raw.Valid || strings.TrimSpace(raw.String) == "" {
			continue
		}
		var params map[string]any
		if err := json.Unmarshal([]byte(raw.String), &params); err != nil {
			continue
		}
		if ip := extractIPFromClientParams(params["assigned_ip"]); ip != "" {
			candidateIPs = append(candidateIPs, ip)
		}
		if ip := extractIPFromClientParams(params["Address"]); ip != "" {
			candidateIPs = append(candidateIPs, ip)
		}
	}

	for _, cand := range candidateIPs {
		for _, a := range allocs {
			if matchAllocationIP(a.ip, cand) {
				return a.id
			}
		}
	}

	return -1
}

func extractIPFromClientParams(val any) string {
	if val == nil {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func matchAllocationIP(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA != nil && ipB != nil && ipA.Equal(ipB) {
		return true
	}
	return false
}
