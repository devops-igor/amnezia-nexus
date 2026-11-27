package database

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestGigahostRepairMigrationPreservesUnknownAndSurvivesReopen(t *testing.T) {
	db, key := setupTestDB(t)
	ctx := context.Background()
	seed := seedLedgerRow(t, db)
	// Exactly the predecessor schema, with a real historical row and known provider id.
	if _, err := db.SQLDB().ExecContext(ctx, `ALTER TABLE gigahost_orders DROP COLUMN live_repaired_at`); err != nil {
		t.Fatal(err)
	}
	if err := db.InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.InitSchema(ctx); err != nil {
		t.Fatal(err)
	}
	var unknown sql.NullString
	if err := db.SQLDB().QueryRowContext(ctx, `SELECT live_repaired_at FROM gigahost_orders WHERE id = ?`, seed.ID).Scan(&unknown); err != nil {
		t.Fatal(err)
	}
	if unknown.Valid {
		t.Fatalf("migration guessed a repair: %q", unknown.String)
	}
	repaired := time.Now().UTC()
	seed.LiveRepairedAt = &repaired
	if err := db.UpdateGigahostOrderObservation(ctx, &seed, nil); err != nil {
		t.Fatal(err)
	}
	var path string
	var sequence int
	var name string
	if err := db.SQLDB().QueryRowContext(ctx, `PRAGMA database_list`).Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Clean(path), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, found, err := reopened.GetGigahostOrder(ctx, seed.OrderID)
	if err != nil || !found {
		t.Fatalf("reopen: found=%t err=%v", found, err)
	}
	if got.LiveRepairedAt == nil || !got.LiveRepairedAt.Equal(repaired) {
		t.Fatalf("repair lost on reopen: %+v", got)
	}
}

func TestGigahostOrderObservationFencesRetiredReader(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()
	seed := seedLedgerRow(t, db)
	stale := seed
	repaired := time.Now().UTC()
	seed.LiveRepairedAt = &repaired
	if err := db.UpdateGigahostOrderObservation(ctx, &seed, nil); err != nil {
		t.Fatal(err)
	}
	stale.Status = "deleted"
	if err := db.UpdateGigahostOrderObservation(ctx, &stale, nil); !errors.Is(err, ErrGigahostObservationRetired) {
		t.Fatalf("stale deletion accepted: %v", err)
	}
	got, _, err := db.GetGigahostOrder(ctx, seed.OrderID)
	if err != nil || got.Status != "ready" {
		t.Fatalf("retired reader changed row: %+v %v", got, err)
	}
	// No retry/adoption: a current observation may still record a genuine ending.
	got.Status = "deleted"
	if err := db.UpdateGigahostOrderObservation(ctx, got, got.LiveRepairedAt); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListGigahostDeployments(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("read deployments: %+v %v", list, err)
	}
	if list[0].Status != "deleted" || list[0].LiveRepairedAt == nil || !list[0].LiveRepairedAt.Equal(repaired) {
		t.Fatalf("current write lost evidence: %+v", list[0])
	}
}
