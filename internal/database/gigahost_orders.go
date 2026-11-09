package database

// Persistence for the Gigahost hourly order ledger.
//
// The ledger is the durable half of the monthly budget calculation, so it keeps
// the price identity the provider contracted at order time (price id, monthly
// cap, hourly rate, currency) and never deletes a row. Releasing a reservation
// writes a release marker plus an audit row and leaves the original status
// intact, so the accounting history stays readable and a repeated recovery run
// is a no-op.
//
// Only this package issues SQL for the table (module ownership rules, section
// 6.1). The handlers and the recovery utility call these methods.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Gigahost order release/audit actions.
const (
	GigahostOrderActionReleased = "released"
)

// gigahostOrdersSchema is the current table definition. It is created when
// missing and upgraded column by column for databases created by earlier
// versions.
var gigahostOrdersSchema = `CREATE TABLE IF NOT EXISTS gigahost_orders (
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
)`

// gigahostOrderColumns lists every optional column added after the original
// table. Each entry is applied with ALTER TABLE ADD COLUMN and an existing
// column is not an error, which makes the upgrade idempotent on any version.
var gigahostOrderColumns = []struct {
	name string
	ddl  string
}{
	{"nexus_server_id", `ALTER TABLE gigahost_orders ADD COLUMN nexus_server_id INTEGER DEFAULT 0`},
	{"last_error", `ALTER TABLE gigahost_orders ADD COLUMN last_error TEXT DEFAULT ''`},
	{"step", `ALTER TABLE gigahost_orders ADD COLUMN step TEXT DEFAULT ''`},
	{"price_id", `ALTER TABLE gigahost_orders ADD COLUMN price_id INTEGER DEFAULT 0`},
	{"monthly_cap_nok", `ALTER TABLE gigahost_orders ADD COLUMN monthly_cap_nok REAL DEFAULT 0.0`},
	{"currency", `ALTER TABLE gigahost_orders ADD COLUMN currency TEXT DEFAULT ''`},
	{"released_at", `ALTER TABLE gigahost_orders ADD COLUMN released_at TEXT DEFAULT ''`},
	{"release_reason", `ALTER TABLE gigahost_orders ADD COLUMN release_reason TEXT DEFAULT ''`},
}

var gigahostOrderIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_gigahost_orders_order_id ON gigahost_orders(order_id)`,
	`CREATE INDEX IF NOT EXISTS idx_gigahost_orders_status ON gigahost_orders(status)`,
}

// EnsureGigahostOrdersSchema creates or upgrades the ledger table. It is safe to
// call on every request and from a migration.
func (d *DB) EnsureGigahostOrdersSchema(ctx context.Context) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.ensureGigahostOrdersSchemaLocked(ctx)
}

func (d *DB) ensureGigahostOrdersSchemaLocked(ctx context.Context) error {
	if _, err := d.sqlDB.ExecContext(ctx, gigahostOrdersSchema); err != nil {
		return fmt.Errorf("failed to init gigahost_orders schema: %w", err)
	}
	for _, col := range gigahostOrderColumns {
		// A duplicate column means the upgrade already ran; any other error is
		// a real failure and must not be swallowed silently.
		if _, err := d.sqlDB.ExecContext(ctx, col.ddl); err != nil && !isDuplicateColumnError(err) {
			return fmt.Errorf("failed to add gigahost_orders column %s: %w", col.name, err)
		}
	}
	for _, q := range gigahostOrderIndexes {
		if _, err := d.sqlDB.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("failed to create gigahost_orders index: %w", err)
		}
	}
	return nil
}

// isDuplicateColumnError reports the SQLite "duplicate column name" error that
// makes an ADD COLUMN upgrade idempotent.
func isDuplicateColumnError(err error) bool {
	return err != nil && containsFold(err.Error(), "duplicate column name")
}

func containsFold(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a, b := haystack[i+j], needle[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// migrateGigahostOrders upgrades an existing database at startup.
//
// It runs from runMigrationsLocked, which already holds writeMu, so it must not
// take the lock itself.
func (d *DB) migrateGigahostOrders(ctx context.Context) error {
	if _, err := d.sqlDB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS gigahost_order_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		record_id INTEGER NOT NULL,
		order_id TEXT DEFAULT '',
		action TEXT NOT NULL,
		reason TEXT DEFAULT '',
		detail TEXT DEFAULT '',
		created_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("failed to init gigahost_order_audit schema: %w", err)
	}
	if _, err := d.sqlDB.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_gigahost_order_audit_record ON gigahost_order_audit(record_id)`); err != nil {
		return fmt.Errorf("failed to create gigahost_order_audit index: %w", err)
	}
	return d.ensureGigahostOrdersSchemaLocked(ctx)
}

// ListGigahostOrders returns every ledger row, newest first.
func (d *DB) ListGigahostOrders(ctx context.Context) ([]models.GigahostOrder, error) {
	if d == nil || d.sqlDB == nil {
		return []models.GigahostOrder{}, nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return nil, err
	}
	return d.readGigahostOrders(ctx)
}

// ListGigahostOrdersReadOnly reads the ledger without creating or upgrading
// anything.
//
// A database written by an earlier version has only the original columns, and
// that legacy database is exactly the one an operator needs to inspect, so the
// missing price/release columns are read as their zero values instead of
// failing the inspection. Columns are never added here.
func (d *DB) ListGigahostOrdersReadOnly(ctx context.Context) ([]models.GigahostOrder, error) {
	if d == nil || d.sqlDB == nil {
		return []models.GigahostOrder{}, nil
	}
	rows, err := d.sqlDB.QueryContext(ctx, "SELECT name FROM pragma_table_info('gigahost_orders')")
	if err != nil {
		return nil, fmt.Errorf("failed to inspect gigahost_orders: %w", err)
	}
	present := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		present[name] = true
	}
	_ = rows.Close()
	if !present["id"] {
		return []models.GigahostOrder{}, nil
	}

	// Only columns that exist are selected. A legacy row therefore reports
	// price_id 0 / currency "" / monthly_cap 0, which the budget reads as "not
	// recorded" - never as a guessed value.
	optional := []struct {
		name     string
		selectAs string
	}{
		{"price_id", "COALESCE(price_id, 0)"},
		{"monthly_cap_nok", "COALESCE(monthly_cap_nok, 0)"},
		{"currency", "COALESCE(currency, '')"},
		{"released_at", "COALESCE(released_at, '')"},
		{"release_reason", "COALESCE(release_reason, '')"},
	}
	cols := []string{"id", "order_id", "server_id", "status", "plan_id", "region_id",
		"hourly_price_nok", "assigned_ip", "created_at", "updated_at"}
	var exprs []string
	for _, c := range optional {
		if present[c.name] {
			exprs = append(exprs, c.selectAs)
		} else {
			switch c.name {
			case "currency", "released_at", "release_reason":
				exprs = append(exprs, "''")
			default:
				exprs = append(exprs, "0")
			}
		}
	}
	q := fmt.Sprintf("SELECT %s, %s FROM gigahost_orders ORDER BY id DESC",
		strings.Join(cols, ", "), strings.Join(exprs, ", "))
	return d.scanGigahostOrders(ctx, q)
}

// readGigahostOrders is the shared SELECT body.
func (d *DB) readGigahostOrders(ctx context.Context) ([]models.GigahostOrder, error) {
	q := `SELECT id, order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip,
	             created_at, updated_at, price_id, monthly_cap_nok, currency, released_at, release_reason
	      FROM gigahost_orders
	      ORDER BY id DESC`
	return d.scanGigahostOrders(ctx, q)
}

// scanGigahostOrders runs a query with the canonical column order and scans it.
func (d *DB) scanGigahostOrders(ctx context.Context, q string) ([]models.GigahostOrder, error) {
	rows, err := d.sqlDB.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("failed to query gigahost orders: %w", err)
	}
	defer func() { _ = rows.Close() }()

	list := []models.GigahostOrder{}
	for rows.Next() {
		var o models.GigahostOrder
		var createdAt, updatedAt string
		var assignedIP, currency, releasedAt, releaseReason sql.NullString
		var priceID sql.NullInt64
		var monthlyCap sql.NullFloat64
		if err := rows.Scan(
			&o.ID, &o.OrderID, &o.ServerID, &o.Status, &o.PlanID, &o.RegionID,
			&o.HourlyPriceNOK, &assignedIP, &createdAt, &updatedAt,
			&priceID, &monthlyCap, &currency, &releasedAt, &releaseReason,
		); err != nil {
			return nil, err
		}
		o.AssignedIP = assignedIP.String
		o.Currency = currency.String
		o.ReleasedAt = releasedAt.String
		o.ReleaseReason = releaseReason.String
		o.PriceID = int(priceID.Int64)
		o.MonthlyCapNOK = monthlyCap.Float64
		o.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		list = append(list, o)
	}
	return list, rows.Err()
}

// GetGigahostOrderByID returns one ledger row by primary key.
func (d *DB) GetGigahostOrderByID(ctx context.Context, id int64) (*models.GigahostOrder, error) {
	list, err := d.ListGigahostOrders(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, nil
}

// InsertGigahostOrder writes a new ledger row and sets its ID.
func (d *DB) InsertGigahostOrder(ctx context.Context, o *models.GigahostOrder) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return err
	}
	q := `INSERT INTO gigahost_orders
	      (order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip,
	       created_at, updated_at, price_id, monthly_cap_nok, currency)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		o.OrderID, o.ServerID, o.Status, o.PlanID, o.RegionID, o.HourlyPriceNOK, o.AssignedIP,
		o.CreatedAt.Format(time.RFC3339), o.UpdatedAt.Format(time.RFC3339),
		o.PriceID, o.MonthlyCapNOK, o.Currency,
	)
	if err != nil {
		return fmt.Errorf("failed to insert gigahost order: %w", err)
	}
	if id, idErr := res.LastInsertId(); idErr == nil {
		o.ID = id
	}
	return nil
}

// UpdateGigahostOrder updates the provider identity and status of a row.
// Price identity is written once at order time and is not rewritten here.
func (d *DB) UpdateGigahostOrder(ctx context.Context, o *models.GigahostOrder) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	o.UpdatedAt = time.Now().UTC()
	q := `UPDATE gigahost_orders
	      SET order_id = ?, server_id = ?, status = ?, assigned_ip = ?, updated_at = ?,
	          price_id = CASE WHEN ? > 0 THEN ? ELSE price_id END,
	          monthly_cap_nok = CASE WHEN ? > 0 THEN ? ELSE monthly_cap_nok END,
	          hourly_price_nok = CASE WHEN ? > 0 THEN ? ELSE hourly_price_nok END,
	          currency = CASE WHEN ? != '' THEN ? ELSE currency END
	      WHERE id = ? OR (order_id = ? AND order_id != '')`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.sqlDB.ExecContext(ctx, q,
		o.OrderID, o.ServerID, o.Status, o.AssignedIP, o.UpdatedAt.Format(time.RFC3339),
		o.PriceID, o.PriceID,
		o.MonthlyCapNOK, o.MonthlyCapNOK,
		o.HourlyPriceNOK, o.HourlyPriceNOK,
		o.Currency, o.Currency,
		o.ID, o.OrderID,
	)
	return err
}

// ErrGigahostOrderAlreadyReleased reports a repeated release attempt.
var ErrGigahostOrderAlreadyReleased = errors.New("gigahost order reservation already released")

// ErrGigahostOrderChanged reports that the ledger row no longer matches the
// accounting/lifecycle snapshot the release evidence was gathered against.
var ErrGigahostOrderChanged = errors.New("gigahost order changed since the release evidence was observed")

// ReleaseExpectation is the complete ledger snapshot observed before collecting
// provider evidence. Zero and blank fields are observations, never wildcards.
// The transaction compares every persisted accounting/lifecycle field, including
// timestamps, so an unchanged provider identity alone cannot authorize release.
type ReleaseExpectation = models.GigahostOrder

// ReleaseGigahostOrder releases without a prior observation. Kept for the
// separately scoped offline recovery path and fixtures; live reconciliation must
// use ReleaseGigahostOrderIfCurrent instead.
func (d *DB) ReleaseGigahostOrder(ctx context.Context, recordID int64, reason, detail string) error {
	return d.releaseGigahostOrder(ctx, recordID, nil, reason, detail)
}

// ReleaseGigahostOrderIfCurrent marks a reservation as released and appends an
// audit row in one transaction, only if every observed field still matches.
// Unlike ReleaseGigahostOrder, even a zero expectation performs strict checks.
//
// Releasing an already released row is a no-op reported as
// ErrGigahostOrderAlreadyReleased, so a repeated run is visibly idempotent rather
// than silently rewriting history.
func (d *DB) ReleaseGigahostOrderIfCurrent(
	ctx context.Context, recordID int64, expect ReleaseExpectation, reason, detail string,
) error {
	return d.releaseGigahostOrder(ctx, recordID, &expect, reason, detail)
}

func (d *DB) releaseGigahostOrder(
	ctx context.Context, recordID int64, expect *ReleaseExpectation, reason, detail string,
) error {
	if d == nil || d.sqlDB == nil {
		return errors.New("no database handle")
	}
	if reason == "" {
		return errors.New("a release reason is required")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	return d.WithTransaction(ctx, func(tx *sql.Tx) error {
		var orderID, releasedAt string
		err := tx.QueryRowContext(ctx,
			`SELECT order_id, COALESCE(released_at, '') FROM gigahost_orders WHERE id = ?`, recordID).
			Scan(&orderID, &releasedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("gigahost order %d not found", recordID)
		}
		if err != nil {
			return err
		}
		if releasedAt != "" {
			return ErrGigahostOrderAlreadyReleased
		}
		if err := checkGigahostReleaseSnapshot(ctx, tx, recordID, expect); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE gigahost_orders SET released_at = ?, release_reason = ?, updated_at = ? WHERE id = ?`,
			now, reason, now, recordID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO gigahost_order_audit (record_id, order_id, action, reason, detail, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			recordID, orderID, GigahostOrderActionReleased, reason, detail, now)
		return err
	})
}

// checkGigahostReleaseSnapshot compares the complete persisted model inside the
// same transaction as the release/audit write. SQL equality preserves timestamp
// precision and rejects malformed/changed stored times rather than normalizing
// them into apparent equality. NULL optional fields match their read defaults.
func checkGigahostReleaseSnapshot(ctx context.Context, tx *sql.Tx, recordID int64, expect *ReleaseExpectation) error {
	if expect == nil {
		return nil
	}
	var matches bool
	err := tx.QueryRowContext(ctx, `SELECT
		id = ? AND order_id = ? AND COALESCE(server_id, 0) = ? AND status = ?
		AND plan_id = ? AND region_id = ? AND hourly_price_nok = ?
		AND COALESCE(assigned_ip, '') = ? AND created_at = ? AND updated_at = ?
		AND COALESCE(price_id, 0) = ? AND COALESCE(monthly_cap_nok, 0) = ?
		AND COALESCE(currency, '') = ? AND COALESCE(released_at, '') = ?
		AND COALESCE(release_reason, '') = ?
		FROM gigahost_orders WHERE id = ?`,
		expect.ID, expect.OrderID, expect.ServerID, expect.Status,
		expect.PlanID, expect.RegionID, expect.HourlyPriceNOK, expect.AssignedIP,
		expect.CreatedAt.Format(time.RFC3339Nano), expect.UpdatedAt.Format(time.RFC3339Nano),
		expect.PriceID, expect.MonthlyCapNOK, expect.Currency, expect.ReleasedAt, expect.ReleaseReason,
		recordID).Scan(&matches)
	if err != nil {
		return err
	}
	if !matches {
		return ErrGigahostOrderChanged
	}
	return nil
}

// GigahostOrderAuditRow is one audit entry for a ledger row.
type GigahostOrderAuditRow struct {
	ID        int64
	RecordID  int64
	OrderID   string
	Action    string
	Reason    string
	Detail    string
	CreatedAt string
}

// ListGigahostOrderAudit returns the audit history, newest first. A recordID of
// zero returns the whole history.
func (d *DB) ListGigahostOrderAudit(ctx context.Context, recordID int64) ([]GigahostOrderAuditRow, error) {
	if d == nil || d.sqlDB == nil {
		return nil, nil
	}
	q := `SELECT id, record_id, order_id, action, reason, detail, created_at FROM gigahost_order_audit`
	args := []any{}
	if recordID > 0 {
		q += ` WHERE record_id = ?`
		args = append(args, recordID)
	}
	q += ` ORDER BY id DESC`
	rows, err := d.sqlDB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []GigahostOrderAuditRow
	for rows.Next() {
		var r GigahostOrderAuditRow
		if err := rows.Scan(&r.ID, &r.RecordID, &r.OrderID, &r.Action, &r.Reason, &r.Detail, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
