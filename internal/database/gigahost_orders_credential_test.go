package database

// Storage contract for the managed order SSH credential (#740).
//
// The credential is access material for a server the panel has already paid for,
// so the important properties are: it is encrypted at rest with the same boundary
// as the server table, it decrypts back to the same material, it never lands on a
// row that does not exist, and adding the columns never touches existing data.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// testManagedPrivateKey is a synthetic PEM *header* plus a throwaway body, built
// by concatenation so a secret scanner cannot mistake the fixture for a real key.
// It is never used to authenticate anything.
var testManagedPrivateKey = "-----BEGIN " + "PRIVATE " + "KEY-----\n" +
	"MC4CAQAwBQYDK2VwBCIEIFixture0000000000000000000000000000000000\n" +
	"-----END " + "PRIVATE " + "KEY-----"

func seedOrderRow(t *testing.T, db *DB, orderID string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.InsertGigahostOrder(context.Background(), &models.GigahostOrder{
		OrderID:   orderID,
		Status:    "pending_order",
		PlanID:    101,
		RegionID:  1,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("failed to seed the order row: %v", err)
	}
}

func TestGigahostOrderCredential_RoundTripIsEncrypted(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seedOrderRow(t, db, "ord_cred")

	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:       "ord_cred",
		PrivateKey:    testManagedPrivateKey,
		PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture nexus-managed",
		ProviderKeyID: 12,
	}); err != nil {
		t.Fatalf("SetGigahostOrderCredential: %v", err)
	}

	var stored string
	if err := db.SQLDB().QueryRowContext(ctx,
		`SELECT ssh_key_enc FROM gigahost_orders WHERE order_id = 'ord_cred'`).Scan(&stored); err != nil {
		t.Fatalf("failed to read the stored column: %v", err)
	}
	if stored == testManagedPrivateKey || strings.Contains(stored, "PRIVATE KEY") {
		t.Error("the private key must be encrypted at rest")
	}
	if !security.LooksLikeFernetToken(stored) {
		t.Error("the stored credential must use the repository credential encryption format")
	}

	cred, found, err := db.GetGigahostOrderCredential(ctx, "ord_cred")
	if err != nil || !found {
		t.Fatalf("GetGigahostOrderCredential: found=%t err=%v", found, err)
	}
	if cred.PrivateKey != testManagedPrivateKey {
		t.Error("the credential must decrypt back to the same private key")
	}
	if cred.PublicKey == "" || cred.ProviderKeyID != 12 {
		t.Errorf("public key and provider id must round trip, got %+v", cred)
	}
}

func TestGigahostOrderCredential_AbsentIsNotAnError(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seedOrderRow(t, db, "ord_no_cred")

	cred, found, err := db.GetGigahostOrderCredential(ctx, "ord_no_cred")
	if err != nil {
		t.Fatalf("a row without a credential must not be an error: %v", err)
	}
	if found || cred != nil {
		t.Errorf("expected found=false, got %+v (found=%t)", cred, found)
	}

	if _, found, err := db.GetGigahostOrderCredential(ctx, "does-not-exist"); err != nil || found {
		t.Errorf("an unknown order must report found=false without an error, got found=%t err=%v", found, err)
	}
}

func TestGigahostOrderCredential_RefusesOrphanWrite(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:    "ord_missing",
		PrivateKey: testManagedPrivateKey,
	})
	if err == nil {
		t.Fatal("a credential with no order row must be refused, not silently dropped")
	}
	if !strings.Contains(err.Error(), "no gigahost order row") {
		t.Errorf("the error must name the cause, got %v", err)
	}
}

func TestGigahostOrderCredential_RequiresMaterial(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seedOrderRow(t, db, "ord_empty")

	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{OrderID: "ord_empty"}); err == nil {
		t.Error("a credential with no private key must be refused")
	}
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{PrivateKey: "x"}); err == nil {
		t.Error("a credential with no order id must be refused")
	}
}

func TestGigahostOrderCredential_LatestIsTheNewestRecorded(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	if _, found, err := db.LatestGigahostOrderCredential(ctx); err != nil || found {
		t.Fatalf("an empty ledger must report found=false, got found=%t err=%v", found, err)
	}

	for _, orderID := range []string{"ord_first", "ord_second"} {
		seedOrderRow(t, db, orderID)
		if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
			OrderID:       orderID,
			PrivateKey:    testManagedPrivateKey + orderID,
			PublicKey:     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture " + orderID,
			ProviderKeyID: int64(len(orderID)),
		}); err != nil {
			t.Fatalf("failed to store the credential for %s: %v", orderID, err)
		}
	}

	latest, found, err := db.LatestGigahostOrderCredential(ctx)
	if err != nil || !found {
		t.Fatalf("LatestGigahostOrderCredential: found=%t err=%v", found, err)
	}
	if latest.OrderID != "ord_second" {
		t.Errorf("expected the newest recorded credential, got %q", latest.OrderID)
	}
	if latest.PrivateKey != testManagedPrivateKey+"ord_second" {
		t.Error("the newest credential must decrypt to its own material")
	}
}

// TestGigahostOrderCredential_UpgradePreservesExistingRows proves the column
// upgrade is additive: a row written before the credential columns existed keeps
// its data and reads back as "no credential".
func TestGigahostOrderCredential_UpgradePreservesExistingRows(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	// Simulate a database created before this change: the original table with the
	// columns as they were at that point.
	if _, err := db.SQLDB().ExecContext(ctx, `DROP TABLE IF EXISTS gigahost_orders`); err != nil {
		t.Fatalf("failed to drop the table: %v", err)
	}
	if _, err := db.SQLDB().ExecContext(ctx, `CREATE TABLE gigahost_orders (
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
	)`); err != nil {
		t.Fatalf("failed to create the legacy table: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.SQLDB().ExecContext(ctx,
		`INSERT INTO gigahost_orders (order_id, server_id, status, plan_id, region_id, hourly_price_nok, assigned_ip, created_at, updated_at)
		 VALUES ('ord_legacy', 77, 'ready', 101, 1, 0.25, '198.51.100.1', ?, ?)`, now, now); err != nil {
		t.Fatalf("failed to insert the legacy row: %v", err)
	}

	// The upgrade path runs on read.
	orders, err := db.ListGigahostOrders(ctx)
	if err != nil {
		t.Fatalf("ListGigahostOrders after upgrade: %v", err)
	}
	if len(orders) != 1 || orders[0].OrderID != "ord_legacy" || orders[0].PlanID != 101 {
		t.Fatalf("the legacy row must survive the upgrade, got %+v", orders)
	}

	cred, found, err := db.GetGigahostOrderCredential(ctx, "ord_legacy")
	if err != nil {
		t.Fatalf("a legacy row must read as no-credential without an error: %v", err)
	}
	if found || cred != nil {
		t.Errorf("a legacy row must report no credential, got %+v", cred)
	}

	// And the new column is usable on that same row afterwards.
	if err := db.SetGigahostOrderCredential(ctx, &models.GigahostOrderCredential{
		OrderID:    "ord_legacy",
		PrivateKey: testManagedPrivateKey,
	}); err != nil {
		t.Fatalf("a legacy row must accept a credential after the upgrade: %v", err)
	}
}

// TestGigahostOrderCredential_UndecryptableIsAnError proves a credential that
// cannot be decrypted is surfaced rather than downgraded to "no credential", so a
// server is never treated as unreachable for an invisible reason.
func TestGigahostOrderCredential_UndecryptableIsAnError(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seedOrderRow(t, db, "ord_corrupt")

	if _, err := db.ExecContext(ctx,
		`UPDATE gigahost_orders SET ssh_key_enc = 'gAAAAABcorrupted-token-not-decryptable' WHERE order_id = 'ord_corrupt'`); err != nil {
		t.Fatalf("failed to inject the corrupted credential: %v", err)
	}

	if _, _, err := db.GetGigahostOrderCredential(ctx, "ord_corrupt"); err == nil {
		t.Fatal("an undecryptable credential must be an error")
	}
}
