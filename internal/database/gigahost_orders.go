package database

// Persistence for the Gigahost hourly order ledger.
//
// The ledger is the durable record of what was ordered and what the provider
// answered, so it keeps the price identity the provider contracted at order time
// (price id, hourly rate, currency, provider monthly ceiling) and never deletes a
// row. Those price fields are recorded history: nothing compares them against a
// configured spending limit.
//
// Only this package issues SQL for the table (module ownership rules, section
// 6.1). The handlers call these methods.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
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
	currency TEXT DEFAULT ''
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

// readGigahostOrders is the shared SELECT body.
func (d *DB) readGigahostOrders(ctx context.Context) ([]models.GigahostOrder, error) {
	q := `SELECT id, order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip,
	             created_at, updated_at, price_id, monthly_cap_nok, currency
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
		var assignedIP, currency sql.NullString
		var priceID sql.NullInt64
		var monthlyCap sql.NullFloat64
		if err := rows.Scan(
			&o.ID, &o.OrderID, &o.ServerID, &o.Status, &o.PlanID, &o.RegionID,
			&o.HourlyPriceNOK, &assignedIP, &createdAt, &updatedAt,
			&priceID, &monthlyCap, &currency,
		); err != nil {
			return nil, err
		}
		o.AssignedIP = assignedIP.String
		o.Currency = currency.String
		o.PriceID = int(priceID.Int64)
		o.MonthlyCapNOK = monthlyCap.Float64
		o.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		list = append(list, o)
	}
	return list, rows.Err()
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
