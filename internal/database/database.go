package database

import (
	"context"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	sqlite "modernc.org/sqlite"      // Pure-Go SQLite database driver
	sqlite3 "modernc.org/sqlite/lib" // SQLite result codes used to classify lock waits
)

//go:embed schema.sql
var SchemaSQL string

// DefaultSettings maps configuration keys to their default JSON values.
var DefaultSettings = map[string]string{
	"schema_version": `"1"`,
	"appearance":     `{"title":"Amnezia","logo":"🛡","subtitle":"Web Panel","language":"en"}`,
	"captcha":        `{"enabled":false}`,
	"telegram":       `{}`,
	"notifications":  `{"enabled":false,"url":"","app_token":"","min_severity":"info","categories":{"server_health":true,"backend_health":true,"provisioning":true,"updates":true,"failover":true},"cooldown_seconds":60,"max_attempts":6}`,
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

// SQLite lock-wait policy for opening and initializing the database.
//
// These values define a production startup budget, not a test bound: cmd/panel
// and cmd/server both open the database through Open, which runs InitSchema
// before serving. A fresh connection can block on a lock held by another process
// (a second instance, a checkpoint, or WAL index recovery), so the budget is
// expressed in multiples of the busy timeout rather than as an unrelated
// wall-clock constant.
//
// Measured behavior of the pinned driver (modernc.org/sqlite v1.62.0):
//
//   - A statement that is already executing honors context cancellation: a
//     300 ms context interrupts a multi-second query after 301 ms.
//   - Connection setup does not. The DSN pragmas (busy_timeout, journal_mode,
//     foreign_keys, synchronous) are applied on context.Background(), so the
//     first statement on a connection that still has to be established waits in
//     the busy handler for a full busy timeout and then surfaces SQLITE_BUSY; no
//     context can shorten that wait. That is the wait a startup timeout actually
//     expires on, and the repeated ~5 s attempts the schema-init tests observe.
//
// One attempt therefore gets schemaInitAttemptTimeout, which leaves room for
// more than one of those uncancellable windows plus the statements themselves,
// and a lock-wait expiry is retried schemaInitMaxAttempts times with no sleep:
// the wait already happens inside the driver, and retrying immediately re-enters
// it. With a lock that never clears, each attempt ends when its own busy window
// expires, so the policy exhausts in about
// sqliteBusyTimeout * schemaInitMaxAttempts (~15 s, measured), not after the
// summed attempt deadlines: schemaInitAttemptTimeout is a per-attempt upper
// bound, and the 60 s sum is neither a wall-clock guarantee nor a minimum.
const (
	sqliteBusyTimeout        = 5 * time.Second
	schemaInitAttemptTimeout = 4 * sqliteBusyTimeout
	schemaInitMaxAttempts    = 3
)

// schemaInitPolicy bounds how long one initialization waits for the SQLite lock
// before failing closed. Exposed as a value (rather than read from globals) so
// tests can exercise the same code path with a shorter total budget.
type schemaInitPolicy struct {
	attemptTimeout time.Duration
	maxAttempts    int
}

var defaultSchemaInitPolicy = schemaInitPolicy{
	attemptTimeout: schemaInitAttemptTimeout,
	maxAttempts:    schemaInitMaxAttempts,
}

// schemaInitLockError reports that a schema-initialization statement spent its
// whole allowance waiting for a SQLite lock. It names the statement so a startup
// failure can be told apart from a schema or I/O fault using the log line alone.
type schemaInitLockError struct {
	Statement string
	Err       error
}

func (e *schemaInitLockError) Error() string {
	return fmt.Sprintf("timed out waiting for a SQLite lock on statement %q: %v", e.Statement, e.Err)
}

func (e *schemaInitLockError) Unwrap() error { return e.Err }

// schemaInitStep names one statement executed during initialization.
type schemaInitStep struct {
	label string
	stmt  string
}

// wrap annotates a statement failure. A lock-wait expiry carries the statement
// text; any other failure keeps the plain step context.
func (s schemaInitStep) wrap(err error) error {
	if err == nil {
		return nil
	}
	if !isLockWaitExpiry(err) {
		return fmt.Errorf("%s: %w", s.label, err)
	}
	return fmt.Errorf("%s: %w", s.label, &schemaInitLockError{Statement: s.stmt, Err: err})
}

// isLockWaitExpiry reports whether err means the statement was blocked on a
// SQLite lock rather than doing work: either the driver's busy handler expired
// (SQLITE_BUSY / SQLITE_LOCKED) or the attempt deadline expired while the
// statement was still waiting. Only these errors are retried; DDL, schema,
// constraint and I/O failures are returned to the caller immediately.
func isLockWaitExpiry(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		code := sqliteErr.Code() & 0xff // primary result code; extended bits cleared
		return code == sqlite3.SQLITE_BUSY || code == sqlite3.SQLITE_LOCKED
	}
	return false
}

// OpenReadOnly opens an existing SQLite database without initializing or
// migrating its schema, for inspection tools that must not change the file.
//
// It does not create the database, does not run DDL, and does not set pragmas
// that write. Callers that need to write use Open.
func OpenReadOnly(dbPath string) (*DB, error) {
	if dbPath == ":memory:" || strings.Contains(dbPath, "mode=memory") {
		return nil, errors.New("read-only open requires a file database")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("database not found: %w", err)
	}
	dsn := fmt.Sprintf("%s?_pragma=query_only(ON)&_pragma=busy_timeout(%d)", dbPath, sqliteBusyTimeout.Milliseconds())
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	return &DB{
		dbPath:            dbPath,
		sqlDB:             sqlDB,
		reachabilityCache: make(map[int64]models.ReachabilityStatus),
	}, nil
}

// Open opens a connection to the SQLite database with WAL mode, busy timeout, and foreign keys enabled.
//
// Open is the production startup path (cmd/panel, cmd/server) as well as the
// path every test uses, so schema initialization here runs with
// defaultSchemaInitPolicy. openWithPolicy exposes the same sequence with an
// explicit lock-wait budget for tests.
func Open(dbPath, secretKey string) (*DB, error) {
	return openWithPolicy(dbPath, secretKey, defaultSchemaInitPolicy)
}

func openWithPolicy(dbPath, secretKey string, policy schemaInitPolicy) (*DB, error) {
	if !isMemoryDBPath(dbPath) {
		dir := filepath.Dir(dbPath)
		if dir != "" && dir != "." {
			if err := CheckDirWritable(dir); err != nil {
				return nil, err
			}
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)", dbPath, sqliteBusyTimeout.Milliseconds())
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

	// The lock-wait budget lives in the policy; the caller has no earlier
	// deadline to respect here.
	if err := db.initSchemaWithPolicy(context.Background(), policy); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	if !isMemoryDBPath(dbPath) {
		_ = os.Chmod(dbPath, 0600)
		_ = os.Chmod(dbPath+"-wal", 0600)
		_ = os.Chmod(dbPath+"-shm", 0600)
	}

	return db, nil
}

// isMemoryDBPath reports whether dbPath addresses an in-memory database, which
// needs neither a directory writability check nor file permission fixes.
func isMemoryDBPath(dbPath string) bool {
	return dbPath == ":memory:" || strings.HasPrefix(dbPath, "file::memory:") || strings.Contains(dbPath, "mode=memory")
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
//
// Initialization runs with the production lock-wait policy (see
// defaultSchemaInitPolicy): a lock held by another process is waited for and
// retried within a bounded, documented budget instead of aborting startup after
// a single busy-timeout window. That window is not cancellable - it is the DSN
// pragma application during connection setup - which is why the policy is
// expressed in multiples of it and why one attempt's deadline is an upper bound
// rather than the expected wait. Callers that need a different budget use
// openWithPolicy.
//
// Failure is fail-closed in the sense that matters for callers: the error names
// the statement that was waiting, and Open closes the handle instead of
// returning a half-initialized database. Initialization is not one transaction
// (migrations issue their own statements and commit per migration), but every
// step is idempotent, so the next Open resumes the remaining work; each
// data-rewriting migration commits its rewrite and its completion flag together,
// so a flag never claims work that was rolled back. The duplicate-allocation
// reconciliation keeps its existing per-statement semantics.
func (d *DB) InitSchema(ctx context.Context) error {
	return d.initSchemaWithPolicy(ctx, defaultSchemaInitPolicy)
}

func (d *DB) initSchemaWithPolicy(ctx context.Context, policy schemaInitPolicy) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	var lastErr error
	for attempt := 1; attempt <= policy.maxAttempts; attempt++ {
		lastErr = d.runSchemaInitAttempt(ctx, policy.attemptTimeout)
		if lastErr == nil {
			return nil
		}
		if ctx.Err() != nil {
			// The caller canceled or its own deadline expired: that is not a
			// lock budget to spend more of.
			return fmt.Errorf("schema initialization aborted: %w", lastErr)
		}
		if !isLockWaitExpiry(lastErr) {
			return lastErr
		}
	}

	return fmt.Errorf("schema initialization failed (attempts: %d, per-attempt deadline: %s): %w",
		policy.maxAttempts, policy.attemptTimeout, lastErr)
}

// runSchemaInitAttempt runs the full initialization sequence once under its own
// deadline. The sequence is idempotent, so a lock-wait retry re-enters it safely.
func (d *DB) runSchemaInitAttempt(ctx context.Context, timeout time.Duration) error {
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Reconcile legacy duplicate active AWG IP allocations before applying schema unique index
	if err := d.reconcileLegacyDuplicateActiveAllocationsLocked(attemptCtx); err != nil {
		return fmt.Errorf("failed to reconcile legacy duplicate active allocations: %w", err)
	}

	if _, err := d.sqlDB.ExecContext(attemptCtx, SchemaSQL); err != nil {
		return schemaInitStep{"failed to execute schema DDL", "schema DDL (schema.sql)"}.wrap(err)
	}

	if err := d.ensureDefaultSettingsLocked(attemptCtx); err != nil {
		return err
	}

	return d.runMigrationsLocked(attemptCtx)
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
