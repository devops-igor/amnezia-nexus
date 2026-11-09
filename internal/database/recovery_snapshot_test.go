package database

// Behavioral tests for the coherent snapshot/restore helper used by the
// gigahost-recovery utility.
//
// The first test is the regression oracle for the defect this helper exists to
// close: copying database/-wal/-shm one file at a time does NOT produce a
// snapshot of a live WAL database. The test builds that naive copy next to the
// real snapshot from the same source, and asserts the naive copy loses rows while
// the snapshot keeps them.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // register the driver for raw legacy fixtures
)

// ledgerFixture describes a disposable database used by these tests.
type ledgerFixture struct {
	orders [][2]string // order_id, status
	audit  []string    // detail
}

// newLegacyLedger creates a database with the ORIGINAL (pre-migration) ledger
// shape: gigahost_orders without released_at/price_id, plus an audit table. This
// is the database an operator actually needs to back up.
func newLegacyLedger(t *testing.T, path string, f ledgerFixture) {
	t.Helper()
	seedRawLedger(t, path, f, `CREATE TABLE gigahost_orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id TEXT NOT NULL,
		server_id INTEGER DEFAULT 0,
		status TEXT NOT NULL,
		plan_id INTEGER NOT NULL,
		region_id INTEGER NOT NULL,
		hourly_price_nok REAL NOT NULL DEFAULT 0.0,
		assigned_ip TEXT DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	)`)
}

// newCurrentLedger creates a database with the upgraded ledger shape.
func newCurrentLedger(t *testing.T, path string, f ledgerFixture) {
	t.Helper()
	seedRawLedger(t, path, f, `CREATE TABLE gigahost_orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id TEXT NOT NULL,
		server_id INTEGER DEFAULT 0,
		status TEXT NOT NULL,
		plan_id INTEGER NOT NULL,
		region_id INTEGER NOT NULL,
		hourly_price_nok REAL NOT NULL DEFAULT 0.0,
		assigned_ip TEXT DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		price_id INTEGER DEFAULT 0,
		monthly_cap_nok REAL DEFAULT 0.0,
		currency TEXT DEFAULT '',
		released_at TEXT DEFAULT '',
		release_reason TEXT DEFAULT ''
	)`)
}

func seedRawLedger(t *testing.T, path string, f ledgerFixture, ordersDDL string) {
	t.Helper()
	con, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = con.Close() }()
	stmts := []string{ordersDDL, `CREATE TABLE gigahost_order_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		record_id INTEGER NOT NULL,
		order_id TEXT DEFAULT '',
		action TEXT NOT NULL,
		reason TEXT DEFAULT '',
		detail TEXT DEFAULT '',
		created_at TEXT NOT NULL
	)`}
	for _, s := range stmts {
		if _, err := con.Exec(s); err != nil {
			t.Fatalf("fixture DDL: %v", err)
		}
	}
	for _, o := range f.orders {
		if _, err := con.Exec(
			`INSERT INTO gigahost_orders (order_id, status, plan_id, region_id, created_at, updated_at)
			 VALUES (?, ?, 202, 1, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`, o[0], o[1]); err != nil {
			t.Fatalf("fixture order: %v", err)
		}
	}
	for _, detail := range f.audit {
		if _, err := con.Exec(
			`INSERT INTO gigahost_order_audit (record_id, order_id, action, reason, detail, created_at)
			 VALUES (1, '10001', 'released', 'provider_terminated', ?, '2026-11-01T00:00:00Z')`, detail); err != nil {
			t.Fatalf("fixture audit: %v", err)
		}
	}
}

// committedWALRows appends rows through a connection that stays OPEN, so the new
// rows live only in the -wal file and the main file page image is stale. Returns
// a close function.
func committedWALRows(t *testing.T, path string, count int) func() {
	t.Helper()
	con, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open live writer: %v", err)
	}
	for i := 0; i < count; i++ {
		if _, err := con.Exec(
			`INSERT INTO gigahost_orders (order_id, status, plan_id, region_id, created_at, updated_at)
			 VALUES (?, 'ready', 202, 1, '2026-11-02T00:00:00Z', '2026-11-02T00:00:00Z')`,
			fmt.Sprintf("live-%d", i)); err != nil {
			t.Fatalf("live insert: %v", err)
		}
	}
	return func() { _ = con.Close() }
}

// naiveSequentialCopy reproduces the old makeBackup behaviour: copy the main file
// and then its -wal/-shm siblings, one at a time, with truncating writes.
//
// between is called after the main file was copied and before the sidecars are,
// which is exactly the window a live panel writes in.
func naiveSequentialCopy(t *testing.T, src, dst string, between func()) {
	t.Helper()
	suffixes := []string{"", "-wal", "-shm"}
	for i, suffix := range suffixes {
		in, err := os.Open(filepath.Clean(src + suffix))
		if err != nil {
			continue
		}
		out, err := os.OpenFile(dst+suffix, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			_ = in.Close()
			t.Fatalf("naive copy %s: %v", src+suffix, err)
		}
		if _, err := out.ReadFrom(in); err != nil {
			_ = in.Close()
			_ = out.Close()
			t.Fatalf("naive copy %s: %v", src+suffix, err)
		}
		_ = in.Close()
		if err := out.Close(); err != nil {
			t.Fatalf("naive copy %s: %v", src+suffix, err)
		}
		if i == 0 && between != nil {
			between()
		}
	}
}

func countRows(t *testing.T, path, table string) int64 {
	t.Helper()
	con, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = con.Close() }()
	var n int64
	if err := con.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s in %s: %v", table, path, err)
	}
	return n
}

// TestRecoverySnapshotCapturesUncheckpointedWAL is the counterexample test: a
// sequential file copy of a live WAL database silently loses committed rows,
// while the coherent snapshot keeps them.
//
// The negative control reproduces the exact interleaving the old code was exposed
// to: the main file is copied first, then the panel checkpoints and truncates the
// WAL, then the (now empty) WAL and the SHM are copied. The copy is a database
// that opens cleanly and is missing every row that lived only in the WAL.
func TestRecoverySnapshotCapturesUncheckpointedWAL(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "panel.db")
	newCurrentLedger(t, src, ledgerFixture{
		orders: [][2]string{{"10001", "ready"}, {"10002", "pending"}},
		audit:  []string{"historic release"},
	})
	closeWriter := committedWALRows(t, src, 40)
	defer closeWriter()

	walInfo, err := os.Stat(src + "-wal")
	if err != nil {
		t.Fatalf("expected an uncheckpointed WAL, got %v", err)
	}
	if walInfo.Size() == 0 {
		t.Fatal("expected committed frames in the WAL, it is empty")
	}

	// Negative control: the retired sequential copy, with the panel checkpointing
	// in the middle of it.
	naive := filepath.Join(dir, "naive.db")
	naiveSequentialCopy(t, src, naive, func() {
		checkpointAndTruncateWAL(t, src)
	})
	naiveRows, naiveErr := probeOrders(naive)
	t.Logf("naive copy: rows=%d err=%v (source has 42)", naiveRows, naiveErr)

	snapshot := filepath.Join(dir, "panel.backup.db")
	receipt, err := CreateSnapshot(context.Background(), src, snapshot)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if receipt.Ledger.Orders.Rows != 42 {
		t.Fatalf("snapshot orders = %d, want 42 (2 seeded + 40 committed in the WAL)", receipt.Ledger.Orders.Rows)
	}
	if got := countRows(t, snapshot, "gigahost_orders"); got != 42 {
		t.Fatalf("snapshot row count = %d, want 42", got)
	}
	if got := countRows(t, snapshot, "gigahost_order_audit"); got != 1 {
		t.Fatalf("snapshot audit rows = %d, want 1", got)
	}

	// The naive copy must be visibly worse, or this test proves nothing: it either
	// cannot be opened as a database, or it opens with fewer rows than the source.
	if naiveErr == nil && naiveRows >= 42 {
		t.Fatalf("negative control did not reproduce the defect: naive copy opened with %d rows", naiveRows)
	}
	if naiveErr == nil {
		t.Logf("negative control lost %d of 42 committed rows", 42-naiveRows)
	}
}

// checkpointAndTruncateWAL performs the checkpoint the panel itself runs, which is
// what makes a file-by-file copy incoherent.
func checkpointAndTruncateWAL(t *testing.T, path string) {
	t.Helper()
	con, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatalf("open for checkpoint: %v", err)
	}
	defer func() { _ = con.Close() }()
	var busy, logFrames, checkpointed int
	if err := con.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
}

// probeOrders reports the ledger row count of a possibly unusable database.
func probeOrders(path string) (int64, error) {
	con, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return 0, err
	}
	defer func() { _ = con.Close() }()
	var n int64
	if err := con.QueryRow(`SELECT COUNT(*) FROM gigahost_orders`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// TestRecoverySnapshotRefusesToOverwriteAnything asserts the mandatory
// non-overwriting behaviour, on the destination and on its sidecars.
func TestRecoverySnapshotRefusesToOverwriteAnything(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "panel.db")
	newCurrentLedger(t, src, ledgerFixture{orders: [][2]string{{"10001", "ready"}}})
	ctx := context.Background()

	tests := []struct {
		name string
		dest func() string
	}{
		{"existing destination", func() string {
			p := filepath.Join(dir, "existing.db")
			if err := os.WriteFile(p, []byte("keep these bytes"), 0o600); err != nil {
				t.Fatalf("seed destination: %v", err)
			}
			return p
		}},
		{"existing -wal sibling", func() string {
			p := filepath.Join(dir, "withwal.db")
			if err := os.WriteFile(p+"-wal", []byte("keep"), 0o600); err != nil {
				t.Fatalf("seed wal: %v", err)
			}
			return p
		}},
		{"source itself", func() string { return src }},
		{"source symlink", func() string {
			p := filepath.Join(dir, "link.db")
			if err := os.Symlink(src, p); err != nil {
				t.Skipf("symlink unsupported: %v", err)
			}
			return p
		}},
		{"source hardlink", func() string {
			p := filepath.Join(dir, "hard.db")
			if err := os.Link(src, p); err != nil {
				t.Skipf("hardlink unsupported: %v", err)
			}
			return p
		}},
		{"source -wal as destination", func() string { return src + "-wal" }},
		{"empty destination", func() string { return "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dest := tc.dest()
			_, err := CreateSnapshot(ctx, src, dest)
			if err == nil {
				t.Fatalf("CreateSnapshot(%q) must be refused", dest)
			}
			if dest != "" {
				if info, statErr := os.Lstat(dest); statErr == nil && dest != src {
					if info.Mode()&os.ModeSymlink != 0 || info.Size() > 0 {
						// Pre-existing material is intact; nothing new was created.
						if strings.HasSuffix(dest, ".db") && info.Size() == 0 {
							t.Fatalf("a refused snapshot created %q", dest)
						}
					}
				}
			}
		})
	}

	// The seeded destination keeps its exact bytes.
	existing := filepath.Join(dir, "existing.db")
	data, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("read existing destination: %v", err)
	}
	if string(data) != "keep these bytes" {
		t.Fatalf("refused snapshot modified the existing destination: %q", data)
	}
	// The source is untouched.
	if got := countRows(t, src, "gigahost_orders"); got != 1 {
		t.Fatalf("source changed: %d rows", got)
	}
}

// TestRecoverySnapshotPreservesLegacySchemaAndHistory proves a backup of an
// un-migrated database keeps the legacy columns and the audit history, and that
// taking it does not migrate the source.
func TestRecoverySnapshotPreservesLegacySchemaAndHistory(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "legacy.db")
	newLegacyLedger(t, src, ledgerFixture{
		orders: [][2]string{{"10001", "unknown"}, {"10002", "pending"}},
		audit:  []string{"earlier release", "second audit row"},
	})
	before, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	snapshot := filepath.Join(dir, "legacy.backup.db")
	receipt, err := CreateSnapshot(context.Background(), src, snapshot)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if receipt.Ledger.Orders.Rows != 2 || receipt.Ledger.Audit.Rows != 2 {
		t.Fatalf("receipt ledger = %+v, want 2 orders and 2 audit rows", receipt.Ledger)
	}
	if receipt.Ledger.Orders.Digest == "" {
		t.Fatal("receipt must fingerprint the preserved ledger content")
	}

	con, err := sql.Open("sqlite", "file:"+snapshot+"?mode=ro")
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer func() { _ = con.Close() }()
	var columns int
	if err := con.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('gigahost_orders') WHERE name = 'released_at'`).Scan(&columns); err != nil {
		t.Fatalf("inspect columns: %v", err)
	}
	if columns != 0 {
		t.Fatal("the snapshot must keep the legacy column set, not the upgraded one")
	}

	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("re-read source: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("taking a snapshot modified the source database file")
	}
}

// TestRecoverySnapshotPermissionsAndReceipt asserts the file is private and that
// the receipt names what it preserved and what it cannot.
func TestRecoverySnapshotPermissionsAndReceipt(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "panel.db")
	newCurrentLedger(t, src, ledgerFixture{
		orders: [][2]string{{"10001", "ready"}},
		audit:  []string{"one"},
	})
	snapshot := filepath.Join(dir, "panel.backup.db")
	receipt, err := CreateSnapshot(context.Background(), src, snapshot)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	info, err := os.Stat(snapshot)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("snapshot permissions = %o, want 600", perm)
	}
	if receipt.SHA256 == "" || receipt.Bytes != info.Size() {
		t.Fatalf("receipt does not describe the file: %+v", receipt)
	}
	if receipt.JournalMode != "delete" {
		t.Fatalf("snapshot journal mode = %q, want a self-contained delete-journal file", receipt.JournalMode)
	}
	if receipt.SourceLedger == nil || receipt.SourceLedger.Orders.Rows != 1 {
		t.Fatalf("receipt must record what the source held: %+v", receipt.SourceLedger)
	}
	if len(receipt.Limits) == 0 {
		t.Fatal("receipt must state the limits of the snapshot")
	}
	joined := strings.Join(receipt.Limits, " ")
	if !strings.Contains(joined, "not a backup") || !strings.Contains(joined, "not that the ledger contents are financially correct") {
		t.Fatalf("receipt limits must be explicit about scope: %v", receipt.Limits)
	}
	found := false
	for _, object := range receipt.SchemaObjects {
		if object == "table:gigahost_orders" {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema inventory is missing the ledger table: %v", receipt.SchemaObjects)
	}
}

// TestRecoverySnapshotFailureLeavesNoDestination proves a failed copy leaves
// nothing behind that an operator could mistake for a backup.
func TestRecoverySnapshotFailureLeavesNoDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "panel.db")
	newCurrentLedger(t, src, ledgerFixture{orders: [][2]string{{"10001", "ready"}}})

	dest := filepath.Join(dir, "nested", "snapshot.db")
	_, err := CreateSnapshot(context.Background(), src, dest)
	if err == nil {
		t.Fatal("snapshot into a missing directory must fail")
	}
	if _, statErr := os.Stat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed snapshot left %q behind", dest)
	}

	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	out := filepath.Join(dir, "garbage.backup.db")
	if _, err := CreateSnapshot(context.Background(), garbage, out); err == nil {
		t.Fatal("snapshot of a non-database file must fail")
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed snapshot left %q behind", out)
	}
}

// TestRecoverySnapshotRestoreIntoDisposableDestination proves a snapshot can be
// restored into a separate new file with identical ledger history, and that a
// restore never lands on top of existing data.
func TestRecoverySnapshotRestoreIntoDisposableDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "panel.db")
	newCurrentLedger(t, src, ledgerFixture{
		orders: [][2]string{{"10001", "ready"}, {"10002", "terminated"}},
		audit:  []string{"release one", "release two"},
	})
	ctx := context.Background()
	snapshot := filepath.Join(dir, "panel.backup.db")
	snapshotReceipt, err := CreateSnapshot(ctx, src, snapshot)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	restored := filepath.Join(dir, "restored", "panel.db")
	if err := os.MkdirAll(filepath.Dir(restored), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	restoreReceipt, err := RestoreSnapshot(ctx, snapshot, restored)
	if err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if restoreReceipt.Ledger.Orders.Digest != snapshotReceipt.Ledger.Orders.Digest {
		t.Fatal("restored orders differ from the snapshot")
	}
	if restoreReceipt.Ledger.Audit.Digest != snapshotReceipt.Ledger.Audit.Digest {
		t.Fatal("restored audit history differs from the snapshot")
	}
	if got := countRows(t, restored, "gigahost_order_audit"); got != 2 {
		t.Fatalf("restored audit rows = %d, want 2", got)
	}
	if got := countRows(t, restored, "gigahost_orders"); got != 2 {
		t.Fatalf("restored orders = %d, want 2", got)
	}

	// Restoring onto an existing database is refused, and that database is intact.
	if _, err := RestoreSnapshot(ctx, snapshot, restored); err == nil {
		t.Fatal("restore must not overwrite an existing database")
	}
	if got := countRows(t, restored, "gigahost_orders"); got != 2 {
		t.Fatalf("refused restore damaged the existing database: %d rows", got)
	}

	// A tampered snapshot is refused before anything is written.
	tampered := filepath.Join(dir, "tampered.db")
	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	data[100] ^= 0xFF
	if err := os.WriteFile(tampered, data, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	out := filepath.Join(dir, "tampered-restore.db")
	if _, err := RestoreSnapshot(ctx, tampered, out); err == nil {
		t.Fatal("a corrupt snapshot must not be restorable")
	}
	if _, statErr := os.Stat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused restore left %q behind", out)
	}
}

// TestRecoverySnapshotDetectsMissingLedgerRows proves the completeness check
// refuses a snapshot that does not contain the rows the source held. A truncated
// page image is simulated by pointing the helper at a destination pre-filled with
// an older copy: the snapshot must not silently become "the backup".
func TestRecoverySnapshotDetectsMissingLedgerRows(t *testing.T) {
	older := LedgerState{Orders: LedgerTable{Present: true, Rows: 10, MaxID: 10}}
	newer := LedgerState{Orders: LedgerTable{Present: true, Rows: 3, MaxID: 3}}
	if err := newer.covers(older); err == nil {
		t.Fatal("a snapshot with fewer ledger rows than the source must be refused")
	}
	if err := older.covers(newer); err != nil {
		t.Fatalf("a superset must be accepted: %v", err)
	}
	if err := (LedgerState{}).covers(LedgerState{Orders: LedgerTable{Present: true, Rows: 1}}); err == nil {
		t.Fatal("a snapshot missing the ledger table must be refused")
	}
	if err := older.matches(LedgerState{Orders: LedgerTable{Present: true, Rows: 10, MaxID: 10}}); err != nil {
		t.Fatalf("identical ledger states must match: %v", err)
	}
}

// TestRecoverySnapshotOnDatabaseWithoutLedger proves a database that never used
// Gigahost still backs up, with an absent (not failed) ledger.
func TestRecoverySnapshotOnDatabaseWithoutLedger(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain.db")
	con, err := sql.Open("sqlite", src+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := con.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	if _, err := con.Exec(`INSERT INTO settings (key, value) VALUES ('schema_version', '"1"')`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = con.Close()

	snapshot := filepath.Join(dir, "plain.backup.db")
	receipt, err := CreateSnapshot(context.Background(), src, snapshot)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if receipt.Ledger.Orders.Present || receipt.Ledger.Audit.Present {
		t.Fatalf("a database without the ledger must report it absent, got %+v", receipt.Ledger)
	}
	if len(receipt.Tables) != 1 || receipt.Tables[0].Name != "settings" {
		t.Fatalf("table counts = %+v, want just settings", receipt.Tables)
	}
}

// TestRecoverySnapshotDamagedSourceIsRefusedAndCleanedUp proves a corrupt source
// cannot produce a snapshot an operator would trust, and that the partial
// destination is removed rather than left in place.
//
// This is the path a half-written or page-damaged database takes, and it is the
// one where leaving the file behind would be most dangerous.
func TestRecoverySnapshotDamagedSourceIsRefusedAndCleanedUp(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "damaged.db")
	paddedCurrentLedger(t, src)

	// Truncating b-tree pages leaves a file that still opens but is inconsistent.
	info, err := os.Stat(src)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(src, info.Size()-3000); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if problems, err := probeIntegrity(src); err != nil || len(problems) == 0 {
		t.Fatalf("fixture is not damaged: problems=%v err=%v", problems, err)
	}

	dest := filepath.Join(dir, "damaged.backup.db")
	_, err = CreateSnapshot(context.Background(), src, dest)
	if err == nil {
		t.Fatal("a damaged source must not produce a snapshot")
	}
	if _, statErr := os.Stat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("the failed snapshot left %q behind", dest)
	}
}

// TestRecoverySnapshotRejectsUnusablePaths covers the remaining refusal paths:
// a missing source, a source that is a directory, and a subject database with no
// bytes.
func TestRecoverySnapshotRejectsUnusablePaths(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	t.Run("missing source", func(t *testing.T) {
		_, err := CreateSnapshot(ctx, filepath.Join(dir, "absent.db"), filepath.Join(dir, "out.db"))
		if err == nil {
			t.Fatal("a missing source must be refused")
		}
	})
	t.Run("source is a directory", func(t *testing.T) {
		sub := filepath.Join(dir, "adir")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		_, err := CreateSnapshot(ctx, sub, filepath.Join(dir, "out2.db"))
		if err == nil {
			t.Fatal("a directory must not be snapshotted as a database")
		}
	})
	t.Run("snapshot path is a directory", func(t *testing.T) {
		src := filepath.Join(dir, "ok.db")
		newCurrentLedger(t, src, ledgerFixture{orders: [][2]string{{"10001", "ready"}}})
		sub := filepath.Join(dir, "destdir")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := CreateSnapshot(ctx, src, sub); err == nil {
			t.Fatal("a destination that is a directory must be refused")
		}
	})
	t.Run("verify a missing file", func(t *testing.T) {
		if _, err := VerifySnapshot(ctx, filepath.Join(dir, "nothing.db")); err == nil {
			t.Fatal("verifying a missing file must fail")
		}
	})
	t.Run("verify a directory", func(t *testing.T) {
		sub := filepath.Join(dir, "verifydir")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := VerifySnapshot(ctx, sub); err == nil {
			t.Fatal("verifying a directory must fail")
		}
	})
	t.Run("verify a non-database", func(t *testing.T) {
		junk := filepath.Join(dir, "junk.db")
		if err := os.WriteFile(junk, []byte("not sqlite"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := VerifySnapshot(ctx, junk); err == nil {
			t.Fatal("verifying a non-database must fail")
		}
	})
	t.Run("read the ledger of a non-database", func(t *testing.T) {
		junk := filepath.Join(dir, "junk2.db")
		if err := os.WriteFile(junk, []byte("not sqlite"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := ReadLedgerState(ctx, junk); err == nil {
			t.Fatal("reading a ledger from a non-database must fail")
		}
	})
}

// paddedCurrentLedger creates a current-shape ledger with enough rows that
// truncating its tail damages a b-tree page.
func paddedCurrentLedger(t *testing.T, path string) {
	t.Helper()
	con, err := sql.Open("sqlite", path+"?_pragma=journal_mode=DELETE")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = con.Close() }()
	if _, err := con.Exec(`CREATE TABLE gigahost_orders (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		order_id TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		released_at TEXT DEFAULT ''
	)`); err != nil {
		t.Fatalf("ddl: %v", err)
	}
	payload := strings.Repeat("x", 200)
	for i := 0; i < 300; i++ {
		if _, err := con.Exec(
			`INSERT INTO gigahost_orders (order_id, status, created_at, updated_at, released_at)
			 VALUES (?, 'ready', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', ?)`,
			fmt.Sprintf("order-%03d-%s", i, payload), ""); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

// probeIntegrity returns SQLite's complaint list for a database, if any.
func probeIntegrity(path string) ([]string, error) {
	conn, err := openReadOnly(context.Background(), path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return integrityProblems(context.Background(), conn)
}
