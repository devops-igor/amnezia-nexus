package database

// Coherent SQLite snapshots for the operator recovery utility.
//
// Copying a database file and its -wal/-shm siblings one after another does not
// produce a snapshot. A writer can commit between two copies, or checkpoint and
// truncate the WAL between them, and the resulting set either refuses to open or
// - worse - opens cleanly while silently missing committed rows.
//
// VACUUM INTO reads the whole database inside ONE read transaction and writes a
// single self-contained file, so the copy is a consistent point-in-time image
// that needs no sidecar files. This file owns that operation, the refusal to
// overwrite anything, and the verification that must pass before a recovery run
// is allowed to write.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Ledger tables whose history a recovery backup must contain.
const (
	ledgerOrdersTable = "gigahost_orders"
	ledgerAuditTable  = "gigahost_order_audit"
)

// snapshotBusyTimeoutMS bounds how long a snapshot waits for the panel's locks.
const snapshotBusyTimeoutMS = 5000

// LedgerTable summarizes one ledger table so a backup or restore can be proven to
// contain the same history. Rows/MaxID/Released are cheap invariants; Digest is a
// content fingerprint over the whole table (used where an exact comparison is
// meaningful, such as a restore into a separate destination).
type LedgerTable struct {
	Present  bool   `json:"present"`
	Rows     int64  `json:"rows"`
	MaxID    int64  `json:"max_id"`
	Released int64  `json:"released"`
	Digest   string `json:"digest"`
}

// LedgerState is the recoverable Gigahost ledger history in one database.
type LedgerState struct {
	Orders LedgerTable `json:"orders"`
	Audit  LedgerTable `json:"audit"`
}

// TableRows is one table's row count in a snapshot.
type TableRows struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// SnapshotReceipt is what a snapshot preserved and what it cannot preserve.
//
// It is the operator-facing proof for a backup: the file digest, the SQLite
// integrity result, the schema inventory, per-table row counts, the ledger
// history fingerprint and an explicit list of limits.
type SnapshotReceipt struct {
	Path                 string       `json:"path"`
	Bytes                int64        `json:"bytes"`
	FileMode             string       `json:"file_mode"`
	SHA256               string       `json:"sha256"`
	JournalMode          string       `json:"journal_mode"`
	PageSize             int64        `json:"page_size"`
	UserVersion          int64        `json:"user_version"`
	ApplicationID        int64        `json:"application_id"`
	SchemaObjects        []string     `json:"schema_objects"`
	Tables               []TableRows  `json:"tables"`
	Ledger               LedgerState  `json:"ledger"`
	ForeignKeyViolations int          `json:"foreign_key_violations"`
	SourcePath           string       `json:"source,omitempty"`
	SourceLedger         *LedgerState `json:"source_ledger,omitempty"`
	Limits               []string     `json:"limits"`
}

// SnapshotLimits returns what a coherent database snapshot cannot preserve. The
// list is part of the receipt, not documentation: an operator reading a backup
// report has to know what it is not.
func SnapshotLimits() []string {
	return []string{
		"the snapshot is the database as of the moment it was taken; writes the panel commits afterwards are not in it",
		"only the database is copied: other files in the data directory (secret keys, certificates, generated configs) are not included",
		"the source is opened read-only, but SQLite may create empty -shm/-wal sidecars next to a WAL-mode database while it is read; those sidecars are not copied and are not needed",
		"the snapshot is one file in rollback-journal mode, so it must be copied or restored as a whole; a partially copied file is not a backup",
		"a snapshot proves the file was coherent and readable, not that the ledger contents are financially correct",
	}
}

// CreateSnapshot writes a coherent, verified snapshot of sourcePath to destPath.
//
// It refuses to overwrite anything: destPath (and any -wal/-shm/-journal sibling)
// must not exist, and destPath may not resolve to the source or one of its
// sidecars. The snapshot is created mode 0600. The source ledger is observed
// before the snapshot and compared afterwards; if the snapshot is missing rows
// the planner saw, or if SQLite reports any integrity problem, the snapshot is
// deleted and the error is returned, so a caller can never write while believing
// it holds a usable backup.
func CreateSnapshot(ctx context.Context, sourcePath, destPath string) (*SnapshotReceipt, error) {
	if err := checkSnapshotDestination(sourcePath, destPath); err != nil {
		return nil, err
	}
	observed, err := ReadLedgerState(ctx, sourcePath)
	if err != nil {
		return nil, fmt.Errorf("read source ledger: %w", err)
	}
	receipt, err := copyVerifiedSnapshot(ctx, sourcePath, destPath)
	if err != nil {
		return nil, err
	}
	if err := receipt.Ledger.covers(observed); err != nil {
		removeSnapshotFiles(destPath)
		return nil, err
	}
	receipt.SourcePath = sourcePath
	receipt.SourceLedger = &observed
	return receipt, nil
}

// RestoreSnapshot writes a verified copy of a snapshot into a separate, unused
// destination database. It never replaces a live database: anything at destPath
// is refused, so restoring always produces a new file that can be inspected
// before an operator swaps it in themselves.
func RestoreSnapshot(ctx context.Context, snapshotPath, destPath string) (*SnapshotReceipt, error) {
	if err := checkSnapshotDestination(snapshotPath, destPath); err != nil {
		return nil, err
	}
	source, err := VerifySnapshot(ctx, snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot is not usable: %w", err)
	}
	receipt, err := copyVerifiedSnapshot(ctx, snapshotPath, destPath)
	if err != nil {
		return nil, err
	}
	if err := receipt.Ledger.matches(source.Ledger); err != nil {
		removeSnapshotFiles(destPath)
		return nil, err
	}
	receipt.SourcePath = snapshotPath
	receipt.SourceLedger = &source.Ledger
	return receipt, nil
}

// VerifySnapshot inspects an existing snapshot without touching its source and
// returns its receipt. Any integrity problem is an error.
func VerifySnapshot(ctx context.Context, path string) (*SnapshotReceipt, error) {
	conn, err := openReadOnly(ctx, path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	problems, err := integrityProblems(ctx, conn)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("snapshot failed SQLite integrity check: %s", strings.Join(problems, "; "))
	}
	receipt, err := inspectSnapshot(ctx, conn, path)
	if err != nil {
		return nil, err
	}
	receipt.Limits = SnapshotLimits()
	return receipt, nil
}

// ReadLedgerState reads the Gigahost ledger history from a database without
// creating or migrating anything, so it also works on a legacy schema.
func ReadLedgerState(ctx context.Context, dbPath string) (LedgerState, error) {
	conn, err := openReadOnly(ctx, dbPath)
	if err != nil {
		return LedgerState{}, err
	}
	defer func() { _ = conn.Close() }()
	return readLedgerState(ctx, conn)
}

// copyVerifiedSnapshot creates destPath exclusively and fills it from src, then
// verifies the result. The destination is removed again on any failure so a
// half-written file is never left where an operator might trust it.
func copyVerifiedSnapshot(ctx context.Context, src, dest string) (*SnapshotReceipt, error) {
	placeholder, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- operator-supplied backup destination
	if err != nil {
		return nil, fmt.Errorf("create backup file %s: %w", dest, err)
	}
	if err := placeholder.Close(); err != nil {
		removeSnapshotFiles(dest)
		return nil, fmt.Errorf("close backup file %s: %w", dest, err)
	}
	receipt, err := fillAndVerifySnapshot(ctx, src, dest)
	if err != nil {
		removeSnapshotFiles(dest)
		return nil, err
	}
	return receipt, nil
}

// fillAndVerifySnapshot runs the copy and the verification for a destination that
// was already created exclusively.
func fillAndVerifySnapshot(ctx context.Context, src, dest string) (*SnapshotReceipt, error) {
	if err := writeSnapshot(ctx, src, dest); err != nil {
		return nil, err
	}
	return VerifySnapshot(ctx, dest)
}

// writeSnapshot performs the coherent copy itself.
func writeSnapshot(ctx context.Context, src, dest string) error {
	conn, err := openReadOnly(ctx, src)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `VACUUM INTO ?`, dest); err != nil {
		return fmt.Errorf("snapshot %s into %s: %w", src, dest, err)
	}
	return nil
}

// openReadOnly opens an existing database read-only, with a bounded busy
// timeout. mode=ro (not immutable=1) is deliberate: an immutable open ignores
// WAL frames, which is exactly how a "backup" loses recently committed rows.
func openReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", path, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("database not found: %w", err)
	}
	u := url.URL{Scheme: "file", Path: abs}
	dsn := fmt.Sprintf("%s?mode=ro&_pragma=busy_timeout(%d)", u.String(), snapshotBusyTimeoutMS)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s read-only: %w", path, err)
	}
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("open %s read-only: %w", path, err)
	}
	return conn, nil
}

// integrityProblems returns SQLite's report; an empty result means "ok".
func integrityProblems(ctx context.Context, conn *sql.DB) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return nil, fmt.Errorf("integrity check: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, fmt.Errorf("integrity check: %w", err)
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	return problems, rows.Err()
}

// inspectSnapshot reads everything a receipt records about one snapshot file.
func inspectSnapshot(ctx context.Context, conn *sql.DB, path string) (*SnapshotReceipt, error) {
	receipt := &SnapshotReceipt{Path: path}
	steps := []struct {
		what string
		run  func() error
	}{
		{"describe the file", func() error { return describeSnapshotFile(path, receipt) }},
		{"read storage pragmas", func() error { return readSnapshotPragmas(ctx, conn, receipt) }},
		{"read the schema", func() error {
			objects, err := schemaInventory(ctx, conn)
			receipt.SchemaObjects = objects
			return err
		}},
		{"count table rows", func() error {
			tables, err := tableRowCounts(ctx, conn)
			receipt.Tables = tables
			return err
		}},
		{"read the gigahost ledger", func() error {
			ledger, err := readLedgerState(ctx, conn)
			receipt.Ledger = ledger
			return err
		}},
		{"check foreign keys", func() error {
			violations, err := foreignKeyViolations(ctx, conn)
			receipt.ForeignKeyViolations = violations
			return err
		}},
	}
	for _, step := range steps {
		if err := step.run(); err != nil {
			return nil, fmt.Errorf("%s of %s: %w", step.what, path, err)
		}
	}
	return receipt, nil
}

// describeSnapshotFile records the size, permissions and digest of the snapshot.
func describeSnapshotFile(path string, receipt *SnapshotReceipt) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	receipt.Bytes = info.Size()
	receipt.FileMode = info.Mode().Perm().String()
	digest, err := fileSHA256(path)
	if err != nil {
		return err
	}
	receipt.SHA256 = digest
	return nil
}

// readSnapshotPragmas records the storage facts that decide whether the file is
// self-contained.
func readSnapshotPragmas(ctx context.Context, conn *sql.DB, receipt *SnapshotReceipt) error {
	var journalMode string
	if err := conn.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		return fmt.Errorf("read journal_mode: %w", err)
	}
	receipt.JournalMode = journalMode
	scalars := []struct {
		pragma string
		into   *int64
	}{
		{"PRAGMA page_size", &receipt.PageSize},
		{"PRAGMA user_version", &receipt.UserVersion},
		{"PRAGMA application_id", &receipt.ApplicationID},
	}
	for _, s := range scalars {
		if err := conn.QueryRowContext(ctx, s.pragma).Scan(s.into); err != nil {
			return fmt.Errorf("read %s: %w", s.pragma, err)
		}
	}
	return nil
}

// schemaInventory lists every non-internal schema object, so the receipt shows
// which tables, indexes, triggers and views were preserved.
func schemaInventory(ctx context.Context, conn *sql.DB) ([]string, error) {
	rows, err := conn.QueryContext(ctx,
		`SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY type, name`)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var kind, name string
		if err := rows.Scan(&kind, &name); err != nil {
			return nil, fmt.Errorf("read schema: %w", err)
		}
		out = append(out, kind+":"+name)
	}
	return out, rows.Err()
}

// tableRowCounts counts every table in the snapshot.
func tableRowCounts(ctx context.Context, conn *sql.DB) ([]TableRows, error) {
	rows, err := conn.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("list tables: %w", err)
		}
		names = append(names, name)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	out := make([]TableRows, 0, len(names))
	for _, name := range names {
		var count int64
		// #nosec G201 -- the identifier comes from sqlite_master of the file being
		// backed up, never from user input, and it is quoted by quoteIdent.
		q := fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(name))
		if err := conn.QueryRowContext(ctx, q).Scan(&count); err != nil {
			return nil, fmt.Errorf("count %s: %w", name, err)
		}
		out = append(out, TableRows{Name: name, Rows: count})
	}
	return out, nil
}

// foreignKeyViolations counts rows that break a declared foreign key. It is
// reported, not enforced: a legacy database can violate keys that a later schema
// added, and that is information for the operator rather than a reason to refuse
// a backup.
func foreignKeyViolations(ctx context.Context, conn *sql.DB) (int, error) {
	rows, err := conn.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return 0, fmt.Errorf("foreign key check: %w", err)
	}
	defer func() { _ = rows.Close() }()
	count := 0
	for rows.Next() {
		count++
	}
	return count, rows.Err()
}

// readLedgerState reads the ledger history from an open database connection.
func readLedgerState(ctx context.Context, conn *sql.DB) (LedgerState, error) {
	orders, err := readLedgerTable(ctx, conn, ledgerOrdersTable, "released_at")
	if err != nil {
		return LedgerState{}, err
	}
	audit, err := readLedgerTable(ctx, conn, ledgerAuditTable, "")
	if err != nil {
		return LedgerState{}, err
	}
	return LedgerState{Orders: orders, Audit: audit}, nil
}

// readLedgerTable summarizes one ledger table. A table that does not exist yet
// (a database that never used Gigahost, or an older schema) is reported as
// absent rather than as an error.
func readLedgerTable(ctx context.Context, conn *sql.DB, table, releaseColumn string) (LedgerTable, error) {
	columns, err := tableColumns(ctx, conn, table)
	if err != nil {
		return LedgerTable{}, err
	}
	if len(columns) == 0 {
		return LedgerTable{}, nil
	}
	state := LedgerTable{Present: true}
	counts := `SELECT COUNT(*), COALESCE(MAX(id), 0) FROM ` + quoteIdent(table)
	if err := conn.QueryRowContext(ctx, counts).Scan(&state.Rows, &state.MaxID); err != nil {
		return LedgerTable{}, fmt.Errorf("summarize %s: %w", table, err)
	}
	if releaseColumn != "" && columns[releaseColumn] {
		// #nosec G201 -- table and column names come from the database being backed
		// up and are quoted by quoteIdent; the compare value is a constant.
		q := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE COALESCE(%s, '') != ''`,
			quoteIdent(table), quoteIdent(releaseColumn))
		if err := conn.QueryRowContext(ctx, q).Scan(&state.Released); err != nil {
			return LedgerTable{}, fmt.Errorf("count released %s: %w", table, err)
		}
	}
	if state.Digest, err = digestTable(ctx, conn, table); err != nil {
		return LedgerTable{}, err
	}
	return state, nil
}

// tableColumns returns the column names of one table, empty when it is absent.
func tableColumns(ctx context.Context, conn *sql.DB, table string) (map[string]bool, error) {
	rows, err := conn.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("inspect %s: %w", table, err)
		}
		out[name] = true
	}
	return out, rows.Err()
}

// digestTable fingerprints the full content of one table in primary-key order.
// Scanning generically keeps it correct for the older column sets too.
func digestTable(ctx context.Context, conn *sql.DB, table string) (string, error) {
	// #nosec G202 -- the identifier comes from sqlite_master of the file being
	// fingerprinted and is quoted; nothing here is user input.
	rows, err := conn.QueryContext(ctx, "SELECT * FROM "+quoteIdent(table)+" ORDER BY 1")
	if err != nil {
		return "", fmt.Errorf("fingerprint %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		return "", fmt.Errorf("fingerprint %s: %w", table, err)
	}
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "table=%s columns=%s\n", table, strings.Join(columns, ","))
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return "", fmt.Errorf("fingerprint %s: %w", table, err)
		}
		_, _ = fmt.Fprintf(hash, "%v\n", values)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("fingerprint %s: %w", table, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// covers reports whether state contains every row already known from an earlier
// observation. The ledger is append-only and never deletes rows, so a snapshot
// taken later must contain at least the observed rows; anything less means the
// snapshot is not the pre-write state the caller is about to rely on.
func (state LedgerState) covers(observed LedgerState) error {
	if err := state.Orders.covers(observed.Orders, ledgerOrdersTable); err != nil {
		return err
	}
	return state.Audit.covers(observed.Audit, ledgerAuditTable)
}

// matches reports whether two ledger states are identical. Used where an exact
// comparison is meaningful: a restore is a static copy, not a later observation.
func (state LedgerState) matches(other LedgerState) error {
	if state.Orders.Rows != other.Orders.Rows || state.Audit.Rows != other.Audit.Rows {
		return fmt.Errorf("restored ledger has %d orders and %d audit rows, snapshot has %d and %d",
			state.Orders.Rows, state.Audit.Rows, other.Orders.Rows, other.Audit.Rows)
	}
	if state.Orders.Digest != other.Orders.Digest || state.Audit.Digest != other.Audit.Digest {
		return errors.New("restored ledger content differs from the snapshot")
	}
	return nil
}

// covers reports whether t is a superset of observed for one table.
func (t LedgerTable) covers(observed LedgerTable, table string) error {
	if !observed.Present {
		return nil
	}
	if !t.Present {
		return fmt.Errorf("snapshot is missing the %s table that the source has", table)
	}
	if t.Rows < observed.Rows || t.MaxID < observed.MaxID {
		return fmt.Errorf("snapshot %s has %d rows (max id %d) but the source had %d (max id %d): the snapshot is not a complete backup",
			table, t.Rows, t.MaxID, observed.Rows, observed.MaxID)
	}
	return nil
}

// checkSnapshotDestination refuses any destination that already exists, is an
// alias of the source, or is one of the source's sidecar files.
func checkSnapshotDestination(source, dest string) error {
	trimmed := strings.TrimSpace(dest)
	if trimmed == "" {
		return errors.New("no backup destination given")
	}
	resolvedSource, err := resolveExisting(source)
	if err != nil {
		return err
	}
	resolvedDest, err := resolveNew(trimmed)
	if err != nil {
		return err
	}
	if alias := matchingSourceAlias(resolvedSource, resolvedDest); alias != "" {
		return fmt.Errorf("refusing to write the snapshot to %s: it is the database (or one of its sidecar files)", dest)
	}
	if occupied := firstExistingPath(snapshotFiles(resolvedDest)); occupied != "" {
		return fmt.Errorf("refusing to write the snapshot to %s: %s already exists", dest, occupied)
	}
	return nil
}

// matchingSourceAlias returns the source alias that dest is, or "".
func matchingSourceAlias(resolvedSource, resolvedDest string) string {
	for _, alias := range sourceAliases(resolvedSource) {
		if resolvedDest == alias {
			return alias
		}
	}
	return ""
}

// firstExistingPath returns the first path in the list that exists, or "".
func firstExistingPath(paths []string) string {
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			return path
		}
	}
	return ""
}

// snapshotFiles lists every path a snapshot at dest would need to itself.
func snapshotFiles(dest string) []string {
	out := make([]string, 0, 4)
	for _, suffix := range snapshotSuffixes() {
		out = append(out, dest+suffix)
	}
	return out
}

// snapshotSuffixes are the files whose presence means the destination is already
// used by something.
func snapshotSuffixes() []string {
	return []string{"", "-wal", "-shm", "-journal"}
}

// sourceAliases lists the names that must never be used as a destination.
func sourceAliases(resolvedSource string) []string {
	aliases := []string{resolvedSource}
	for _, suffix := range snapshotSuffixes()[1:] {
		aliases = append(aliases, resolvedSource+suffix)
	}
	return aliases
}

// resolveExisting resolves every symlink in a path that must already exist.
func resolveExisting(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	return resolved, nil
}

// resolveNew resolves the directory part of a path that must not exist yet, so a
// symlinked destination directory cannot alias the source either.
func resolveNew(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// removeSnapshotFiles deletes a destination this process created, together with
// any sidecar SQLite may have made for it. Only call it for a path that was
// created exclusively by us.
func removeSnapshotFiles(path string) {
	for _, target := range snapshotFiles(path) {
		// #nosec G304 -- the path is the backup destination this process created
		_ = os.Remove(target)
	}
}

// fileSHA256 returns the hex digest of a file's bytes.
func fileSHA256(path string) (string, error) {
	// #nosec G304 -- operator-supplied snapshot path being fingerprinted
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// quoteIdent quotes a SQLite identifier. Table names come from sqlite_master here,
// never from user input, but quoting keeps unusual names readable to SQLite.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
