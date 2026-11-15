package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// holdExclusiveFileLock takes SQLite's exclusive lock on path from a second
// connection and keeps it until the returned release function is called.
//
// WAL mode lets readers ignore a writer's lock, so a writer-shaped hold would
// not block a trivial schema probe. locking_mode(EXCLUSIVE) makes this
// connection hold the file exclusively, which blocks every statement from any
// other connection - including the plain `SELECT ... FROM sqlite_master` that
// issue #832 reported waiting - and is verified here by a probe read.
func holdExclusiveFileLock(t *testing.T, path string) (release func()) {
	t.Helper()

	holder, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)&_pragma=locking_mode(EXCLUSIVE)")
	if err != nil {
		t.Fatalf("failed to open lock holder: %v", err)
	}
	holder.SetMaxOpenConns(1)
	holder.SetMaxIdleConns(1)

	var tables int
	if err := holder.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&tables); err != nil {
		_ = holder.Close()
		t.Fatalf("lock holder could not take the exclusive lock: %v", err)
	}

	released := false
	release = func() {
		if released {
			return
		}
		released = true
		if err := holder.Close(); err != nil {
			t.Errorf("failed to release exclusive lock: %v", err)
		}
	}
	t.Cleanup(release)
	return release
}

// seedDatabaseFile creates path with a complete schema and closes it, so that a
// later Open only has to re-run the idempotent initialization sequence.
func seedDatabaseFile(t *testing.T, path string) {
	t.Helper()

	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to seed database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close seeded database: %v", err)
	}
}

// TestOpenWaitsForExclusiveLockPastBusyTimeout is the regression for issue #832:
// initialization used to run under a single 10 second context and therefore
// failed as soon as the first statement exhausted the 5 second busy timeout.
//
// The test holds the file exclusively from another connection, asserts that Open
// is still waiting (not failing) after the busy-timeout window has passed, then
// releases the lock and requires Open to succeed with a usable, fully
// initialized database.
//
// It proves: a lock held longer than busy_timeout is waited out and retried
// instead of aborting startup, and initialization completes afterwards.
// It does not prove: how long a lock may be held in production (a lock that never
// clears exhausts the policy in about 15 s: three attempts, each ending at its
// own ~5 s connection-setup busy window), nor that the DEV runner's exact lock
// source is reproduced - the test uses a real SQLite exclusive lock, not a
// synthetic sleep.
func TestOpenWaitsForExclusiveLockPastBusyTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	seedDatabaseFile(t, path)

	release := holdExclusiveFileLock(t, path)

	type openResult struct {
		db      *DB
		err     error
		elapsed time.Duration
	}
	done := make(chan openResult, 1)
	start := time.Now()
	go func() {
		db, err := Open(path, testSecretKey)
		done <- openResult{db: db, err: err, elapsed: time.Since(start)}
	}()

	// Past this point the previous implementation had already given up: one busy
	// timeout window is the most a single attempt can wait.
	select {
	case r := <-done:
		release()
		if r.db != nil {
			_ = r.db.Close()
		}
		t.Fatalf("Open returned while the exclusive lock was still held (elapsed %s, err %v); "+
			"initialization must keep waiting within its lock-wait policy", r.elapsed, r.err)
	case <-time.After(sqliteBusyTimeout + 500*time.Millisecond):
	}

	release()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Open failed after the lock was released: %v (elapsed %s)", r.err, r.elapsed)
		}
		if r.db == nil {
			t.Fatal("Open returned no database and no error")
		}
		defer func() { _ = r.db.Close() }()

		if total := time.Duration(schemaInitMaxAttempts) * schemaInitAttemptTimeout; r.elapsed > total {
			t.Fatalf("Open took %s, beyond the documented startup budget %s", r.elapsed, total)
		}

		var version string
		if err := r.db.QueryRowContext(context.Background(),
			"SELECT value FROM settings WHERE key = 'schema_version'").Scan(&version); err != nil {
			t.Fatalf("opened database is not initialized: %v", err)
		}
		t.Logf("Open waited %s for the held lock and initialized schema_version=%s", r.elapsed, version)
	case <-time.After(schemaInitMaxAttempts*schemaInitAttemptTimeout + 30*time.Second):
		t.Fatal("Open did not complete after the exclusive lock was released")
	}
}

// TestOpenFailsClosedWhenLockOutlivesPolicy checks the other half of the
// contract: when the lock is still there after the policy's attempts are spent,
// Open fails with an error naming the statement that was waiting, returns no
// handle, and leaves nothing half-initialized behind (the next Open, after the
// lock is gone, initializes the database completely).
//
// It proves: fail-closed behavior and the diagnosable error for a lock that
// never clears. It does not prove: that a mid-sequence failure can never leave
// partially migrated state - initialization is a sequence of idempotent
// statements, not one transaction, so recovery is by resuming.
func TestOpenFailsClosedWhenLockOutlivesPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")

	release := holdExclusiveFileLock(t, path)

	policy := schemaInitPolicy{attemptTimeout: schemaInitAttemptTimeout, maxAttempts: 1}
	start := time.Now()
	db, err := openWithPolicy(path, testSecretKey, policy)
	elapsed := time.Since(start)

	if err == nil {
		if db != nil {
			_ = db.Close()
		}
		release()
		t.Fatal("openWithPolicy succeeded while the file was exclusively locked")
	}
	if db != nil {
		_ = db.Close()
		t.Fatal("openWithPolicy returned a handle together with an error")
	}
	if !strings.Contains(err.Error(), "failed to initialize schema") {
		t.Fatalf("error does not identify schema initialization: %v", err)
	}

	var lockErr *schemaInitLockError
	if !errors.As(err, &lockErr) {
		t.Fatalf("error is not a schemaInitLockError: %v", err)
	}
	if lockErr.Statement != awgAllocTableProbeSQL {
		t.Fatalf("error names statement %q, want %q", lockErr.Statement, awgAllocTableProbeSQL)
	}
	if !strings.Contains(err.Error(), `"`+awgAllocTableProbeSQL+`"`) {
		t.Fatalf("error text does not quote the blocked statement: %v", err)
	}
	if elapsed > policy.attemptTimeout+sqliteBusyTimeout {
		t.Fatalf("fail-closed took %s, expected about one busy-timeout window", elapsed)
	}
	t.Logf("fail-closed after %s: %v", elapsed, err)

	// No schema was left behind: the file holds no tables at all.
	raw, rawErr := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)")
	if rawErr != nil {
		t.Fatalf("failed to inspect database file: %v", rawErr)
	}
	release()
	defer func() { _ = raw.Close() }()
	var tables int
	if err := raw.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil {
		t.Fatalf("failed to count tables: %v", err)
	}
	if tables != 0 {
		t.Fatalf("failed initialization left %d tables behind", tables)
	}

	// Resuming after the lock is gone initializes the database completely.
	db, err = Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("re-open after a failed initialization failed: %v", err)
	}
	defer func() { _ = db.Close() }()
	var version string
	if err := db.QueryRowContext(context.Background(),
		"SELECT value FROM settings WHERE key = 'schema_version'").Scan(&version); err != nil {
		t.Fatalf("resumed database is not initialized: %v", err)
	}
}

// TestInitSchemaRespectsCallerCancellation checks that a caller context that is
// already done is not retried: the failure surfaces as an aborted initialization
// instead of spending the lock-wait budget.
func TestInitSchemaRespectsCallerCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")

	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err = db.InitSchema(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("InitSchema succeeded with a canceled context")
	}
	if !strings.Contains(err.Error(), "schema initialization aborted") {
		t.Fatalf("error does not report an aborted initialization: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("InitSchema spent %s on a canceled context", elapsed)
	}
}

// TestIsLockWaitExpiry pins the retry classification using real driver errors.
func TestIsLockWaitExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	seedDatabaseFile(t, path)

	release := holdExclusiveFileLock(t, path)
	defer release()

	locked, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatalf("failed to open probe connection: %v", err)
	}
	defer func() { _ = locked.Close() }()

	var one int
	busyErr := locked.QueryRow("SELECT 1 FROM sqlite_master LIMIT 1").Scan(&one)
	if !isLockWaitExpiry(busyErr) {
		t.Fatalf("SQLITE_BUSY from a held exclusive lock is not classified as a lock wait: %v", busyErr)
	}

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "typed busy error", err: busyErr, want: true},
		{name: "wrapped typed busy error", err: errors.Join(errors.New("context"), busyErr), want: true},
		{name: "attempt deadline", err: context.DeadlineExceeded, want: true},
		{name: "wrapped attempt deadline", err: errors.Join(errors.New("phase"), context.DeadlineExceeded), want: true},
		{name: "caller cancellation", err: context.Canceled, want: false},
		{name: "constraint violation", err: errors.New("constraint failed: UNIQUE constraint failed: settings.key"), want: false},
		{name: "plain error", err: errors.New("no such table: missing"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLockWaitExpiry(tt.err); got != tt.want {
				t.Fatalf("isLockWaitExpiry(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
