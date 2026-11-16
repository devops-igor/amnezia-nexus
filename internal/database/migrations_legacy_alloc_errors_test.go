package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

// Tests for how the legacy duplicate-allocation reconciliation treats a failed
// read of user_connections. A failed read is not evidence that no connection
// record names an allocation: it must reach the caller, and through it the
// schema-init retry policy, instead of selecting the fallback allocation.
//
// The failure is injected with a deterministic SQL function behind a generated
// column, so one specific row is unreadable while the table, the statement and
// every other row stay healthy. The driver applies a registration to
// connections opened afterwards, so it is registered before a fixture opens
// its database.

const (
	allocGuardFunc   = "test_alloc_read_guard"
	allocGuardMarker = "FAIL"
	allocGuardStall  = 900 * time.Millisecond
)

const (
	allocGuardOff   int32 = 0 // marker rows read normally
	allocGuardError int32 = 1 // reading a marker row fails
	allocGuardSlow  int32 = 2 // reading a marker row outlasts the attempt deadline
)

var (
	allocGuardMode  atomic.Int32
	allocGuardCalls atomic.Int32
	allocGuardOnce  sync.Once
)

// allocGuard returns its argument, except that a value carrying the marker
// fails or stalls according to allocGuardMode. A stall happens once and then
// disarms, so a retried attempt reads healthy.
func allocGuard(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
	s, _ := args[0].(string)
	if !strings.Contains(s, allocGuardMarker) {
		return args[0], nil
	}
	switch allocGuardMode.Load() {
	case allocGuardError:
		allocGuardCalls.Add(1)
		return nil, errors.New("injected read failure")
	case allocGuardSlow:
		if allocGuardMode.CompareAndSwap(allocGuardSlow, allocGuardOff) {
			allocGuardCalls.Add(1)
			time.Sleep(allocGuardStall)
		}
	}
	return args[0], nil
}

func registerAllocGuard(t *testing.T) {
	t.Helper()
	allocGuardOnce.Do(func() {
		if err := sqlite.RegisterDeterministicScalarFunction(allocGuardFunc, 1, allocGuard); err != nil {
			panic(err)
		}
	})
	allocGuardMode.Store(allocGuardOff)
	allocGuardCalls.Store(0)
	t.Cleanup(func() { allocGuardMode.Store(allocGuardOff) })
}

const (
	legacyServerID = 1
	legacyClientID = "c1"
	legacyFirstIP  = "10.8.0.2"
	legacySecondIP = "10.8.0.3"
	legacyIndexSQL = "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='uq_awg_ip_allocations_server_client_active'"
)

// legacyAllocIDs names the two active allocations of the fixture pair. The
// connection record always names the second one; the documented fallback
// retains the first.
type legacyAllocIDs struct{ first, second int64 }

func mustExec(t *testing.T, db *DB, query string, args ...any) {
	t.Helper()
	if _, err := db.sqlDB.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// seedLegacyAllocs puts db in the pre-index state the reconciliation repairs:
// two active allocations for one (server, client) pair and no unique index.
func seedLegacyAllocs(t *testing.T, db *DB) legacyAllocIDs {
	t.Helper()
	now := "2026-01-01T00:00:00Z"
	mustExec(t, db, `PRAGMA foreign_keys = OFF`)
	mustExec(t, db, `DROP INDEX IF EXISTS uq_awg_ip_allocations_server_client_active`)
	var ids []int64
	for _, ip := range []string{legacyFirstIP, legacySecondIP} {
		res, err := db.sqlDB.Exec(
			`INSERT INTO awg_ip_allocations (server_id, client_id, ip, status, created_at, updated_at)
			 VALUES (?, ?, ?, 'allocated', ?, ?)`, legacyServerID, legacyClientID, ip, now, now)
		if err != nil {
			t.Fatalf("insert allocation %s: %v", ip, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("last insert id: %v", err)
		}
		ids = append(ids, id)
	}
	return legacyAllocIDs{first: ids[0], second: ids[1]}
}

// Triggers that make the user_connections read fail while the table still
// exists, so the existence probe succeeds.
const (
	// The matching read fails on the second row, after a healthy first row
	// was already read: the result set is cut short mid-iteration.
	triggerRowRead = "row read fails mid-iteration"
	// The SELECT itself cannot run because the column it names is gone.
	triggerStatement = "statement fails to start"
)

// installUserConnections replaces user_connections with a fixture that names
// the second allocation as the live one, and arms the requested read failure.
func installUserConnections(t *testing.T, db *DB, trigger string) {
	t.Helper()
	mustExec(t, db, `DROP TABLE user_connections`)
	cols := `id TEXT PRIMARY KEY, user_id TEXT, server_id INTEGER, protocol TEXT, client_id TEXT`
	if trigger == triggerRowRead {
		cols += `, raw_params TEXT, client_params TEXT GENERATED ALWAYS AS (` + allocGuardFunc + `(raw_params)) VIRTUAL`
	}
	mustExec(t, db, `CREATE TABLE user_connections (`+cols+`)`)
	if trigger == triggerStatement {
		mustExec(t, db, `INSERT INTO user_connections (id, user_id, server_id, protocol, client_id)
			VALUES ('u1', 'user1', ?, 'awg', ?)`, legacyServerID, legacyClientID)
		return
	}
	rows := []struct{ id, raw string }{
		{"u0", `{"assigned_ip":"10.8.0.99"}`},
		{"u1", `{"assigned_ip":"` + legacySecondIP + `","note":"` + allocGuardMarker + `"}`},
	}
	for _, r := range rows {
		mustExec(t, db, `INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, raw_params)
			VALUES (?, 'user1', ?, 'awg', ?, ?)`, r.id, legacyServerID, legacyClientID, r.raw)
	}
}

func openLegacyAllocDB(t *testing.T) (*DB, legacyAllocIDs) {
	t.Helper()
	registerAllocGuard(t)
	db, err := Open(filepath.Join(t.TempDir(), "legacy.db"), testSecretKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, seedLegacyAllocs(t, db)
}

// allocStatuses reads back the status of the two fixture allocations and
// whether the unique partial index exists.
func allocStatuses(t *testing.T, db *DB, ids legacyAllocIDs) (first, second string, indexed bool) {
	t.Helper()
	for id, dst := range map[int64]*string{ids.first: &first, ids.second: &second} {
		if err := db.sqlDB.QueryRow(`SELECT status FROM awg_ip_allocations WHERE id = ?`, id).Scan(dst); err != nil {
			t.Fatalf("read status of allocation %d: %v", id, err)
		}
	}
	var n int
	if err := db.sqlDB.QueryRow(legacyIndexSQL).Scan(&n); err != nil {
		t.Fatalf("read index state: %v", err)
	}
	return first, second, n > 0
}

func requireStatuses(t *testing.T, db *DB, ids legacyAllocIDs, first, second string, indexed bool) {
	t.Helper()
	gotFirst, gotSecond, gotIndexed := allocStatuses(t, db, ids)
	if gotFirst != first || gotSecond != second || gotIndexed != indexed {
		t.Fatalf("allocation states: first=%s second=%s index=%v; want first=%s second=%s index=%v",
			gotFirst, gotSecond, gotIndexed, first, second, indexed)
	}
}

// requireInterrupted fails when the reconciliation reported success or
// superseded anything: an interrupted read must leave both allocations active
// and the unique index uncreated, so the next attempt decides with full evidence.
func requireInterrupted(t *testing.T, err error, db *DB, ids legacyAllocIDs) {
	t.Helper()
	if err == nil {
		first, second, indexed := allocStatuses(t, db, ids)
		t.Fatalf("reconciliation returned nil after a failed read; first=%s second=%s index=%v "+
			"(the connection record names the second allocation)", first, second, indexed)
	}
	requireStatuses(t, db, ids, "allocated", "allocated", false)
}

// A SELECT that cannot run is a database execution error, not absent evidence.
func TestReconcileLegacyAllocations_StatementFailureIsReturned(t *testing.T) {
	db, ids := openLegacyAllocDB(t)
	installUserConnections(t, db, triggerStatement)

	err := db.reconcileLegacyDuplicateActiveAllocationsLocked(context.Background())

	requireInterrupted(t, err, db, ids)
	if isLockWaitExpiry(err) {
		t.Fatalf("a missing column must not be classified as a lock wait: %v", err)
	}
}

// A read that fails after earlier rows were read must not leave the earlier
// rows standing as the whole of the evidence.
func TestReconcileLegacyAllocations_MidIterationFailureIsReturned(t *testing.T) {
	db, ids := openLegacyAllocDB(t)
	installUserConnections(t, db, triggerRowRead)
	allocGuardMode.Store(allocGuardError)

	err := db.reconcileLegacyDuplicateActiveAllocationsLocked(context.Background())

	requireInterrupted(t, err, db, ids)
	if !strings.Contains(err.Error(), "injected read failure") {
		t.Fatalf("the read failure is not reported to the caller: %v", err)
	}
	if allocGuardCalls.Load() == 0 {
		t.Fatal("the injected failure never fired, so the test did not exercise the read")
	}
}

// Control: the same fixture with no injected failure keeps the allocation the
// connection record names. Without it the failure tests could pass for a
// fixture that never produced a match.
func TestReconcileLegacyAllocations_HealthyReadKeepsNamedAllocation(t *testing.T) {
	db, ids := openLegacyAllocDB(t)
	installUserConnections(t, db, triggerRowRead)

	if err := db.reconcileLegacyDuplicateActiveAllocationsLocked(context.Background()); err != nil {
		t.Fatalf("healthy reconciliation failed: %v", err)
	}
	requireStatuses(t, db, ids, "superseded", "allocated", true)
}

// Genuine absence, established by an affirmative answer, takes the documented
// fallback: the earliest allocation is retained.
func TestReconcileLegacyAllocations_AbsentEvidenceTakesFallback(t *testing.T) {
	cases := map[string]func(t *testing.T, db *DB){
		"no user_connections table": func(t *testing.T, db *DB) {
			mustExec(t, db, `DROP TABLE user_connections`)
		},
		"table without a row for the pair": func(t *testing.T, db *DB) {
			mustExec(t, db, `INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, client_params)
				VALUES ('o1', 'user1', 2, 'awg', 'other', '{"assigned_ip":"`+legacySecondIP+`"}')`)
		},
		"row whose params name no active allocation": func(t *testing.T, db *DB) {
			mustExec(t, db, `INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, client_params)
				VALUES ('n1', 'user1', ?, 'awg', ?, '{"assigned_ip":"10.8.0.200"}')`, legacyServerID, legacyClientID)
		},
		"row with empty, null and malformed params": func(t *testing.T, db *DB) {
			for i, params := range []any{"", nil, "{not json"} {
				mustExec(t, db, `INSERT INTO user_connections (id, user_id, server_id, protocol, client_id, client_params)
					VALUES (?, 'user1', ?, 'awg', ?, ?)`, "e"+string(rune('0'+i)), legacyServerID, legacyClientID, params)
			}
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			db, ids := openLegacyAllocDB(t)
			arrange(t, db)

			if err := db.reconcileLegacyDuplicateActiveAllocationsLocked(context.Background()); err != nil {
				t.Fatalf("absent evidence must not be an error: %v", err)
			}
			requireStatuses(t, db, ids, "allocated", "superseded", true)
		})
	}
}

// A read that is still running when the attempt deadline expires must come
// back as the lock-wait class the retry policy re-enters on, with nothing
// superseded. The retry then reads healthy and keeps the allocation the
// connection record names.
func TestReconcileLegacyAllocations_DeadlineDuringReadIsRetryableThenConverges(t *testing.T) {
	db, ids := openLegacyAllocDB(t)
	installUserConnections(t, db, triggerRowRead)
	allocGuardMode.Store(allocGuardSlow)

	ctx, cancel := context.WithTimeout(context.Background(), allocGuardStall/3)
	defer cancel()
	err := db.reconcileLegacyDuplicateActiveAllocationsLocked(ctx)

	requireInterrupted(t, err, db, ids)
	if !isLockWaitExpiry(err) {
		t.Fatalf("a deadline during the read is not classified for retry: %v", err)
	}
	if allocGuardCalls.Load() == 0 {
		t.Fatal("the stall never fired, so the test did not exercise the read")
	}

	if err := db.reconcileLegacyDuplicateActiveAllocationsLocked(context.Background()); err != nil {
		t.Fatalf("retry after the interruption failed: %v", err)
	}
	requireStatuses(t, db, ids, "superseded", "allocated", true)
}

// A non-lock read failure leaves schema initialization through the policy's
// own entry point instead of being absorbed on the way: the error reaches the
// caller unchanged in kind and nothing is superseded.
func TestInitSchemaReturnsLegacyAllocationReadFailure(t *testing.T) {
	db, ids := openLegacyAllocDB(t)
	installUserConnections(t, db, triggerRowRead)
	allocGuardMode.Store(allocGuardError)

	policy := schemaInitPolicy{attemptTimeout: 5 * time.Second, maxAttempts: 3}
	err := db.initSchemaWithPolicy(context.Background(), policy)

	requireInterrupted(t, err, db, ids)
	if !strings.Contains(err.Error(), "injected read failure") {
		t.Fatalf("initialization lost the cause of the failed read: %v", err)
	}
	if isLockWaitExpiry(err) {
		t.Fatalf("an execution error was classified as a lock wait: %v", err)
	}
}

// The existence probe is part of the evidence: when it cannot run, that is an
// error, not a table that does not exist.
func TestUserConnectionsTableExistsDistinguishesFailureFromAbsence(t *testing.T) {
	db, _ := openLegacyAllocDB(t)

	exists, err := db.userConnectionsTableExistsLocked(context.Background())
	if err != nil || !exists {
		t.Fatalf("present table: exists=%v err=%v; want true, nil", exists, err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if exists, err := db.userConnectionsTableExistsLocked(canceled); err == nil || exists {
		t.Fatalf("failed probe: exists=%v err=%v; want false with an error", exists, err)
	}

	mustExec(t, db, `DROP TABLE user_connections`)
	exists, err = db.userConnectionsTableExistsLocked(context.Background())
	if err != nil || exists {
		t.Fatalf("absent table: exists=%v err=%v; want false, nil", exists, err)
	}
}
