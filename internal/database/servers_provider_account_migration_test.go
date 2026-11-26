package database

// A store that predates the provider-account association must keep working: it
// opens, the column appears, the rows keep their values, and their association
// reads as unknown rather than as a match for any account. That unknown reading is
// what keeps such a row out of every absence decision.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestServersProviderAccountMigrationKeepsLegacyRowsUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider_account_migration.db")
	ctx := context.Background()

	first, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open the store: %v", err)
	}
	id, err := first.CreateServer(ctx, &models.Server{
		Name:      "legacy",
		Host:      "198.51.100.7",
		SSHUser:   "root",
		SSHPort:   22,
		Protocols: map[string]any{"provider": "gigahost", "provider_server_id": int64(501)},
	})
	if err != nil {
		t.Fatalf("failed to seed the legacy row: %v", err)
	}

	// Model a store written by a build that did not know the association yet.
	if _, err := first.sqlDB.ExecContext(ctx, `ALTER TABLE servers DROP COLUMN provider_account_id`); err != nil {
		t.Fatalf("failed to drop the association column for the legacy shape: %v", err)
	}
	if has, err := dbHasColumn(t, first, "servers", "provider_account_id"); err != nil || has {
		t.Fatalf("the legacy store still has the association column (has=%v err=%v)", has, err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("failed to close the legacy store: %v", err)
	}

	second, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("opening a store that predates the association failed: %v", err)
	}
	defer func() { _ = second.Close() }()

	if has, err := dbHasColumn(t, second, "servers", "provider_account_id"); err != nil || !has {
		t.Fatalf("reopening the legacy store did not add the association column (has=%v err=%v)", has, err)
	}

	row, err := second.GetServer(ctx, id)
	if err != nil || row == nil {
		t.Fatalf("failed to read the legacy row back: row=%v err=%v", row, err)
	}
	if row.ProviderAccountID != "" || row.ProviderAccountKnown() {
		t.Fatalf("a row that predates the association claims one: %q", row.ProviderAccountID)
	}
	if row.Name != "legacy" || row.Host != "198.51.100.7" || row.SSHPort != 22 {
		t.Fatalf("the migration changed the row: %+v", row)
	}
	if row.ProviderAbsent() {
		t.Fatal("the migration invented a provider absence")
	}

	// A row created after the change records the association it was given.
	registeredID, err := second.CreateServer(ctx, &models.Server{
		Name:              "registered",
		Host:              "198.51.100.8",
		SSHUser:           "root",
		SSHPort:           22,
		ProviderAccountID: "acct-north",
	})
	if err != nil {
		t.Fatalf("failed to create a row with an association: %v", err)
	}
	registered, err := second.GetServer(ctx, registeredID)
	if err != nil || registered == nil {
		t.Fatalf("failed to read the registered row back: row=%v err=%v", registered, err)
	}
	if registered.ProviderAccountID != "acct-north" || !registered.ProviderAccountKnown() {
		t.Fatalf("the recorded association = %q (known=%v), want acct-north", registered.ProviderAccountID, registered.ProviderAccountKnown())
	}
}
