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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
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
	{"ssh_key_enc", `ALTER TABLE gigahost_orders ADD COLUMN ssh_key_enc TEXT DEFAULT ''`},
	{"ssh_public_key", `ALTER TABLE gigahost_orders ADD COLUMN ssh_public_key TEXT DEFAULT ''`},
	{"provider_ssh_key_id", `ALTER TABLE gigahost_orders ADD COLUMN provider_ssh_key_id INTEGER DEFAULT 0`},
	// The purchase-provenance stamp. It is added last and defaults to the empty
	// value, so every row that already exists - legacy, imported, mirror-created -
	// reads as "not purchased by this panel" and can never gain the stamp later.
	{"purchase_origin", `ALTER TABLE gigahost_orders ADD COLUMN purchase_origin TEXT NOT NULL DEFAULT ''`},
	{"purchase_recorded_at", `ALTER TABLE gigahost_orders ADD COLUMN purchase_recorded_at TEXT NOT NULL DEFAULT ''`},
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
	             created_at, updated_at, price_id, monthly_cap_nok, currency,
	             purchase_origin, purchase_recorded_at
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
		var purchaseOrigin, purchaseRecordedAt sql.NullString
		var priceID sql.NullInt64
		var monthlyCap sql.NullFloat64
		if err := rows.Scan(
			&o.ID, &o.OrderID, &o.ServerID, &o.Status, &o.PlanID, &o.RegionID,
			&o.HourlyPriceNOK, &assignedIP, &createdAt, &updatedAt,
			&priceID, &monthlyCap, &currency,
			&purchaseOrigin, &purchaseRecordedAt,
		); err != nil {
			return nil, err
		}
		o.AssignedIP = assignedIP.String
		o.Currency = currency.String
		o.PriceID = int(priceID.Int64)
		o.MonthlyCapNOK = monthlyCap.Float64
		o.PurchaseOrigin = purchaseOrigin.String
		o.PurchaseRecordedAt = parseSetupTimestamp(purchaseRecordedAt.String)
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
	// The provenance stamp is written here and nowhere else. It is one statement with
	// the row it describes, so a row cannot exist that claims a purchase origin
	// without having been written by the purchase path, and no later writer can add
	// the stamp to a row that appeared some other way.
	origin := strings.TrimSpace(o.PurchaseOrigin)
	recordedAt := ""
	if origin != "" {
		if o.PurchaseRecordedAt.IsZero() {
			o.PurchaseRecordedAt = o.CreatedAt
		}
		recordedAt = o.PurchaseRecordedAt.UTC().Format(time.RFC3339Nano)
	}
	q := `INSERT INTO gigahost_orders
	      (order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip,
	       created_at, updated_at, price_id, monthly_cap_nok, currency,
	       purchase_origin, purchase_recorded_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		o.OrderID, o.ServerID, o.Status, o.PlanID, o.RegionID, o.HourlyPriceNOK, o.AssignedIP,
		o.CreatedAt.Format(time.RFC3339), o.UpdatedAt.Format(time.RFC3339),
		o.PriceID, o.MonthlyCapNOK, o.Currency,
		origin, recordedAt,
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
//
// Price identity is written once at order time and is not rewritten here, and neither
// is purchase provenance: this is not the purchase writer, so a row that reached the
// ledger some other way must not be able to acquire the stamp by being updated. The
// columns are simply absent from the SET list, which is the enforcement.
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

// orderCredentialQuery is the shared SELECT for one credential row. Both readers
// use it so the column list and scan order cannot drift apart.
const orderCredentialQuery = `SELECT order_id, ssh_key_enc, ssh_public_key, provider_ssh_key_id
	FROM gigahost_orders`

// scanOrderCredential reads one credential row, decrypting the private key.
//
// A row with no stored credential reports found=false without an error; a stored
// credential that cannot be decrypted is an error, never a silent absence.
func (d *DB) scanOrderCredential(row *sql.Row, what string) (*models.GigahostOrderCredential, bool, error) {
	var cred models.GigahostOrderCredential
	var encKey, publicKey sql.NullString
	var providerKeyID sql.NullInt64
	if err := row.Scan(&cred.OrderID, &encKey, &publicKey, &providerKeyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read %s: %w", what, err)
	}
	if !encKey.Valid || encKey.String == "" {
		return nil, false, nil
	}
	plain, err := security.DecryptCredential(encKey.String, d.secretKey)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decrypt %s: %w", what, err)
	}
	cred.PrivateKey = plain
	cred.PublicKey = publicKey.String
	cred.ProviderKeyID = providerKeyID.Int64
	return &cred, true, nil
}

// SetGigahostOrderCredential attaches the managed SSH credential to an existing
// ledger row, addressed by the row's order_id.
//
// The private key is encrypted with the same credential encryption the server
// table uses, so the panel holds one encryption boundary rather than a second
// key store. PublicKey and ProviderKeyID are the correlation between what this
// order authorized at the provider and the material the panel will log in with;
// they are deliberately stored in clear because neither is a secret.
//
// An update that matches no row is an error: a credential with no order would be
// access material nobody owns, and silently dropping it would lose the ability to
// ever reach the server.
func (d *DB) SetGigahostOrderCredential(ctx context.Context, cred *models.GigahostOrderCredential) error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	if err := validateOrderCredential(cred); err != nil {
		return err
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return err
	}
	encKey, err := d.encryptOrderCredential(cred.PrivateKey)
	if err != nil {
		return err
	}
	return d.writeOrderCredential(ctx, cred, encKey)
}

// writeOrderCredential performs the row update and refuses an update that matched
// no row, so a credential can never exist without the order it belongs to.
func (d *DB) writeOrderCredential(ctx context.Context, cred *models.GigahostOrderCredential, encKey string) error {
	q := `UPDATE gigahost_orders
	      SET ssh_key_enc = ?, ssh_public_key = ?, provider_ssh_key_id = ?, updated_at = ?
	      WHERE order_id = ?`
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.sqlDB.ExecContext(ctx, q,
		encKey, cred.PublicKey, cred.ProviderKeyID, time.Now().UTC().Format(time.RFC3339), cred.OrderID,
	)
	if err != nil {
		return fmt.Errorf("failed to store gigahost order ssh credential: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to confirm gigahost order ssh credential write: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("no gigahost order row matches order id %q", cred.OrderID)
	}
	return nil
}

// validateOrderCredential rejects a credential that could not be stored
// meaningfully: it must name an existing order and carry material.
func validateOrderCredential(cred *models.GigahostOrderCredential) error {
	if cred == nil || strings.TrimSpace(cred.OrderID) == "" {
		return errors.New("gigahost order credential requires an order id")
	}
	if strings.TrimSpace(cred.PrivateKey) == "" {
		return errors.New("gigahost order credential requires private key material")
	}
	return nil
}

// encryptOrderCredential applies the repository credential encryption, and leaves
// an already-encrypted value untouched so a re-store cannot double-encrypt.
func (d *DB) encryptOrderCredential(privateKey string) (string, error) {
	if security.LooksLikeFernetToken(privateKey) {
		return privateKey, nil
	}
	enc, err := security.EncryptCredential(privateKey, d.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt gigahost order ssh key: %w", err)
	}
	return enc, nil
}

// GetGigahostOrder returns one ledger row addressed by its provider order id.
// found=false means the ledger has no such order.
func (d *DB) GetGigahostOrder(ctx context.Context, orderID string) (*models.GigahostOrder, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return nil, false, err
	}
	q := `SELECT id, order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip,
	             created_at, updated_at, price_id, monthly_cap_nok, currency,
	             purchase_origin, purchase_recorded_at
	      FROM gigahost_orders WHERE order_id = ? ORDER BY id DESC LIMIT 1`
	row := d.sqlDB.QueryRowContext(ctx, q, orderID)
	order, err := scanGigahostOrderRow(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read gigahost order: %w", err)
	}
	return order, true, nil
}

// scanGigahostOrderRow scans one row in the canonical column order used by
// readGigahostOrders, so a single-order read cannot drift from the list read.
func scanGigahostOrderRow(row *sql.Row) (*models.GigahostOrder, error) {
	var o models.GigahostOrder
	var createdAt, updatedAt string
	var assignedIP, currency sql.NullString
	var purchaseOrigin, purchaseRecordedAt sql.NullString
	var priceID sql.NullInt64
	var monthlyCap sql.NullFloat64
	if err := row.Scan(
		&o.ID, &o.OrderID, &o.ServerID, &o.Status, &o.PlanID, &o.RegionID,
		&o.HourlyPriceNOK, &assignedIP, &createdAt, &updatedAt,
		&priceID, &monthlyCap, &currency,
		&purchaseOrigin, &purchaseRecordedAt,
	); err != nil {
		return nil, err
	}
	o.AssignedIP = assignedIP.String
	o.Currency = currency.String
	o.PriceID = int(priceID.Int64)
	o.MonthlyCapNOK = monthlyCap.Float64
	o.PurchaseOrigin = purchaseOrigin.String
	o.PurchaseRecordedAt = parseSetupTimestamp(purchaseRecordedAt.String)
	o.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	o.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	return &o, nil
}

// HasGigahostOrderCredential reports whether the order row carries a non-empty
// stored credential.
//
// It deliberately does not decrypt: a background tracker only needs to know
// whether a usable credential reference exists, and there is no reason to bring
// private key material into a scheduler loop. An undecryptable credential is
// still reported as present here; the setup path that actually uses it will fail
// loudly at that point.
func (d *DB) HasGigahostOrderCredential(ctx context.Context, orderID string) (bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return false, nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return false, err
	}
	var encKey sql.NullString
	err := d.sqlDB.QueryRowContext(ctx,
		`SELECT ssh_key_enc FROM gigahost_orders WHERE order_id = ?`, orderID).Scan(&encKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read gigahost order credential presence: %w", err)
	}
	return encKey.Valid && strings.TrimSpace(encKey.String) != "", nil
}

// GetGigahostOrderCredential returns the managed credential stored against an
// order id, with the private key decrypted.
//
// It reports found=false when the row has no credential recorded (every order
// created before this existed, and any order placed without a managed key).
// A stored credential that cannot be decrypted is an error, never a silent
// "no credential": the server would otherwise look unreachable for a reason the
// operator cannot see.
func (d *DB) GetGigahostOrderCredential(ctx context.Context, orderID string) (*models.GigahostOrderCredential, bool, error) {
	if d == nil || d.sqlDB == nil || strings.TrimSpace(orderID) == "" {
		return nil, false, nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return nil, false, err
	}
	row := d.sqlDB.QueryRowContext(ctx, orderCredentialQuery+` WHERE order_id = ?`, orderID)
	return d.scanOrderCredential(row, "gigahost order ssh credential")
}

// LatestGigahostOrderCredential returns the most recently written managed
// credential, with the private key decrypted.
//
// It exists so a new order does not add another account key: the account has a
// finite, operator-visible key list, and re-using the material already recorded
// keeps that list from growing on every order. found=false means no order has ever
// recorded a credential, which is the only case that needs new key material.
func (d *DB) LatestGigahostOrderCredential(ctx context.Context) (*models.GigahostOrderCredential, bool, error) {
	if d == nil || d.sqlDB == nil {
		return nil, false, nil
	}
	if err := d.EnsureGigahostOrdersSchema(ctx); err != nil {
		return nil, false, err
	}
	row := d.sqlDB.QueryRowContext(ctx, orderCredentialQuery+`
		WHERE ssh_key_enc IS NOT NULL AND ssh_key_enc != ''
		ORDER BY id DESC LIMIT 1`)
	return d.scanOrderCredential(row, "reusable gigahost order ssh credential")
}
