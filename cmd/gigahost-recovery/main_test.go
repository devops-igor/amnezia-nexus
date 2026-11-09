package main

// Behavioral tests for the recovery CLI's backup and restore wiring.
//
// These exercise the flag handling and the report the operator reads, on
// disposable databases. They are deliberately separate from
// internal/database's snapshot tests: those prove the helper, these prove the
// command actually uses it and refuses the unsafe combinations.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
)

// ledgerFixture writes a disposable database with a legacy-shaped ledger.
func ledgerFixture(t *testing.T, path string) {
	t.Helper()
	con, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = con.Close() }()
	stmts := []string{
		`CREATE TABLE gigahost_orders (
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
		)`,
		`CREATE TABLE gigahost_order_audit (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			record_id INTEGER NOT NULL,
			order_id TEXT DEFAULT '',
			action TEXT NOT NULL,
			reason TEXT DEFAULT '',
			detail TEXT DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`INSERT INTO gigahost_orders (order_id, status, plan_id, region_id, created_at, updated_at)
		 VALUES ('10001', 'ready', 202, 1, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z'),
		        ('intent_1700000000000000000', 'unknown', 202, 1, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`,
		`INSERT INTO gigahost_order_audit (record_id, order_id, action, reason, detail, created_at)
		 VALUES (1, '10001', 'released', 'provider_terminated', 'historic', '2026-11-01T00:00:00Z')`,
	}
	for _, s := range stmts {
		if _, err := con.Exec(s); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
}

// runCLI invokes run() as the binary would, capturing both streams.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestCLIApplyAlwaysTakesAVerifiedSnapshot asserts the mandatory backup: --apply
// produces a snapshot receipt even though nothing is released, and the snapshot is
// a real, verified file.
func TestCLIApplyAlwaysTakesAVerifiedSnapshot(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)

	code, stdout, stderr := runCLI(t, "--db", db, "--budget", "100", "--apply")
	if code != exitOK {
		t.Fatalf("apply exit = %d, want 0; stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "sha256:") || !strings.Contains(stdout, "integrity:      ok") {
		t.Fatalf("apply report must carry the snapshot receipt:\n%s", stdout)
	}
	if !strings.Contains(stdout, "limit:") {
		t.Fatalf("apply report must state the snapshot's limits:\n%s", stdout)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var snapshots []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".gigahost-backup-") {
			snapshots = append(snapshots, filepath.Join(dir, e.Name()))
		}
	}
	if len(snapshots) != 1 {
		t.Fatalf("expected exactly one snapshot file, got %v", snapshots)
	}
	info, err := os.Stat(snapshots[0])
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot permissions = %o, want 600", info.Mode().Perm())
	}
	if info.Size() == 0 {
		t.Fatal("snapshot is empty")
	}
}

// TestCLIRefusesNoBackup proves the bypass flag is refused instead of silently
// weakening the guarantee.
func TestCLIRefusesNoBackup(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)

	code, stdout, stderr := runCLI(t, "--db", db, "--budget", "100", "--apply", "--no-backup")
	if code != exitUsage {
		t.Fatalf("--apply --no-backup exit = %d, want %d (usage)", code, exitUsage)
	}
	if !strings.Contains(stderr, "--no-backup is not supported") {
		t.Fatalf("stderr must explain the refusal, got %q", stderr)
	}
	if stdout != "" {
		t.Fatalf("a refused run must not report a plan, got %q", stdout)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "gigahost-backup") {
			t.Fatalf("a refused run created a snapshot: %s", e.Name())
		}
	}
}

// TestCLIRefusesExistingBackupDestination proves the tool will not overwrite an
// earlier pre-change copy.
func TestCLIRefusesExistingBackupDestination(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)
	dest := filepath.Join(dir, "already-there.db")
	if err := os.WriteFile(dest, []byte("first copy must survive"), 0o600); err != nil {
		t.Fatalf("seed destination: %v", err)
	}

	code, _, stderr := runCLI(t, "--db", db, "--budget", "100", "--apply", "--backup", dest)
	if code != exitFailure {
		t.Fatalf("exit = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr, "nothing was written") {
		t.Fatalf("stderr must state that nothing was written, got %q", stderr)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if string(data) != "first copy must survive" {
		t.Fatalf("the existing destination was modified: %q", data)
	}
}

// TestCLIRestoreReportsVerifiedHistory proves --restore-to produces a separate
// database with the snapshot's ledger history and never touches the snapshot.
func TestCLIRestoreReportsVerifiedHistory(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)

	if code, _, stderr := runCLI(t, "--db", db, "--budget", "100", "--apply"); code != exitOK {
		t.Fatalf("apply failed: %d %q", code, stderr)
	}
	snapshot := findSnapshot(t, dir)

	restored := filepath.Join(dir, "restored", "panel.db")
	if err := os.MkdirAll(filepath.Dir(restored), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	code, stdout, stderr := runCLI(t, "--db", snapshot, "--restore-to", restored, "--json")
	if code != exitOK {
		t.Fatalf("restore exit = %d, want 0; stderr=%q", code, stderr)
	}
	var rep struct {
		Mode       string `json:"mode"`
		RestoredTo string `json:"restored_to"`
		Restore    *struct {
			Ledger struct {
				Orders struct {
					Rows int64 `json:"rows"`
				} `json:"orders"`
				Audit struct {
					Rows int64 `json:"rows"`
				} `json:"audit"`
			} `json:"ledger"`
		} `json:"restore"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("parse report: %v (stdout=%q)", err, stdout)
	}
	if rep.Mode != "restored" || rep.RestoredTo != restored {
		t.Fatalf("report mode/target = %q/%q", rep.Mode, rep.RestoredTo)
	}
	if rep.Restore == nil || rep.Restore.Ledger.Orders.Rows != 2 || rep.Restore.Ledger.Audit.Rows != 1 {
		t.Fatalf("restored ledger = %+v, want 2 orders and 1 audit row", rep.Restore)
	}

	restoredCon, err := sql.Open("sqlite", "file:"+restored+"?mode=ro")
	if err != nil {
		t.Fatalf("open restored: %v", err)
	}
	defer func() { _ = restoredCon.Close() }()
	var orders, audit int64
	if err := restoredCon.QueryRow(`SELECT COUNT(*) FROM gigahost_orders`).Scan(&orders); err != nil {
		t.Fatalf("count restored orders: %v", err)
	}
	if err := restoredCon.QueryRow(`SELECT COUNT(*) FROM gigahost_order_audit`).Scan(&audit); err != nil {
		t.Fatalf("count restored audit: %v", err)
	}
	if orders != 2 || audit != 1 {
		t.Fatalf("restored rows = %d/%d, want 2/1", orders, audit)
	}

	// Restoring again onto the same path is refused.
	if code, _, _ := runCLI(t, "--db", snapshot, "--restore-to", restored); code != exitFailure {
		t.Fatalf("restore onto an existing database exit = %d, want %d", code, exitFailure)
	}
	// The snapshot itself is untouched by the restore.
	receipt, err := verifySnapshotFile(snapshot)
	if err != nil {
		t.Fatalf("snapshot no longer verifies: %v", err)
	}
	if receipt.Orders != 2 {
		t.Fatalf("snapshot orders after restore = %d, want 2", receipt.Orders)
	}
}

// TestCLIRestoreRejectsTamperedSnapshot proves a corrupt snapshot never becomes a
// restored database.
func TestCLIRestoreRejectsTamperedSnapshot(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)
	if code, _, stderr := runCLI(t, "--db", db, "--budget", "100", "--apply"); code != exitOK {
		t.Fatalf("apply failed: %d %q", code, stderr)
	}
	snapshot := findSnapshot(t, dir)

	data, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(snapshot, data, 0o600); err != nil {
		t.Fatalf("tamper snapshot: %v", err)
	}
	out := filepath.Join(dir, "tampered-restore.db")
	code, _, stderr := runCLI(t, "--db", snapshot, "--restore-to", out)
	if code != exitFailure {
		t.Fatalf("tampered restore exit = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr, "not usable") && !strings.Contains(stderr, "integrity") {
		t.Fatalf("stderr must name the verification failure, got %q", stderr)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("a rejected restore left a destination file behind")
	}
}

// TestCLIDryRunStaysReadOnly proves the default mode writes nothing at all, not
// even a snapshot.
func TestCLIDryRunStaysReadOnly(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}

	code, stdout, stderr := runCLI(t, "--db", db, "--budget", "100")
	if code != exitUnresolved {
		t.Fatalf("dry run exit = %d, want %d (unresolved pending reservation); stderr=%q", code, exitUnresolved, stderr)
	}
	if !strings.Contains(stdout, "nothing was written") {
		t.Fatalf("dry run must say it wrote nothing:\n%s", stdout)
	}
	if strings.Contains(stdout, "sha256:") {
		t.Fatalf("a dry run must not take a snapshot:\n%s", stdout)
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("re-read db: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a dry run modified the database file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("a dry run created files: %v", entries)
	}
}

// TestCLIRefusesIncoherentFlagCombinations covers the usage-level refusals.
func TestCLIRefusesIncoherentFlagCombinations(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "panel.db")
	ledgerFixture(t, db)

	cases := [][]string{
		{"--db", db, "--apply", "--restore-to", filepath.Join(dir, "x.db")},
		{"--db", db, "--restore-to", filepath.Join(dir, "y.db"), "--backup", filepath.Join(dir, "z.db")},
	}
	for _, args := range cases {
		code, _, stderr := runCLI(t, args...)
		if code != exitUsage {
			t.Fatalf("%v exit = %d, want %d (%q)", args, code, exitUsage, stderr)
		}
	}
}

// findSnapshot returns the single snapshot file in dir.
func findSnapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".gigahost-backup-") {
			return filepath.Join(dir, e.Name())
		}
	}
	t.Fatal("no snapshot file found")
	return ""
}

// verifySnapshotFile re-verifies a snapshot with the same code the CLI uses.
func verifySnapshotFile(path string) (struct{ Orders, Audit int64 }, error) {
	var out struct{ Orders, Audit int64 }
	state, err := database.ReadLedgerState(context.Background(), path)
	if err != nil {
		return out, err
	}
	out.Orders = state.Orders.Rows
	out.Audit = state.Audit.Rows
	return out, nil
}
