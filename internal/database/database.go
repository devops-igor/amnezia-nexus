package database

import (
	"context"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
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
		"server_id":         true,
		"interface_name":    true,
		"public_key":        true,
		"private_key":       true,
		"probe_private_key": true,
		"endpoint":          true,
		"state_version":     true,
		// Administrative intent and runtime health have dedicated writers
		// (issue #90). Keep those fields out of this generic update path so
		// subsystem ownership cannot be bypassed.
		"active_connections": true,
		"created_at":         true,
		"protocol":           true,
		"protocol_params":    true,
	}
)

// DB wraps an sql.DB handle and serializes write operations to ensure SQLite thread-safety.
type DB struct {
	dbPath             string
	secretKey          string
	sqlDB              *sql.DB
	writeMu            sync.Mutex
	mu                 sync.RWMutex
	reachabilityMu     sync.RWMutex
	reachabilityCache  map[int64]models.ReachabilityStatus
	peerListener       peerListenerSlot
	peerRevokeListener peerRevokeSlot
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
