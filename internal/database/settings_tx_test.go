package database

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestGigahostCredentialWritersAdvanceEpoch(t *testing.T) {
	writers := []struct {
		name string
		save func(*DB) error
	}{
		{"SetSetting", func(db *DB) error {
			return db.SetSetting(t.Context(), "gigahost", map[string]any{"api_key": "fixture"})
		}},
		{"SetSettingsBulk", func(db *DB) error {
			return db.SetSettingsBulk(t.Context(), map[string]any{"gigahost": map[string]any{"api_key": "fixture"}})
		}},
		{"SettingsTx", func(db *DB) error {
			return db.UpdateSettings(t.Context(), func(tx *SettingsTx) error {
				return tx.Set("gigahost", map[string]any{"api_key": "fixture"})
			})
		}},
		{"SaveDataReplacement", func(db *DB) error {
			return db.SaveData(t.Context(), &models.BackupData{Settings: map[string]any{"gigahost": map[string]any{"api_key": "fixture"}}})
		}},
		{"SaveDataRemoval", func(db *DB) error { return db.SaveData(t.Context(), &models.BackupData{}) }},
	}
	for _, writer := range writers {
		t.Run(writer.name, func(t *testing.T) {
			db, _ := setupTestDB(t)
			if err := db.SetSetting(t.Context(), "gigahost", map[string]any{"api_key": "original"}); err != nil {
				t.Fatal(err)
			}
			before := settingsEpoch(t, db)
			if err := writer.save(db); err != nil {
				t.Fatal(err)
			}
			if after := settingsEpoch(t, db); after != before+1 {
				t.Fatalf("epoch = %d -> %d, want one increment", before, after)
			}
		})
	}
}

func TestSettingsTxEpochRollsBackWithCredential(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := t.Context()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"api_key": "original"}); err != nil {
		t.Fatal(err)
	}
	before := settingsEpoch(t, db)
	stop := errors.New("abort settings transaction")
	err := db.UpdateSettings(ctx, func(tx *SettingsTx) error {
		if err := tx.Set("gigahost", map[string]any{"api_key": "replacement"}); err != nil {
			return err
		}
		var inside int64
		if err := tx.tx.QueryRowContext(ctx, "SELECT epoch FROM gigahost_config_epoch WHERE id = 1").Scan(&inside); err != nil {
			return err
		}
		if inside != before+1 {
			t.Errorf("epoch inside credential transaction = %d, want %d", inside, before+1)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("transaction error = %v, want deliberate abort", err)
	}
	if settingsEpoch(t, db) != before {
		t.Fatal("rolled-back credential save advanced the epoch")
	}
	var stored map[string]any
	if err := db.GetSetting(ctx, "gigahost", &stored); err != nil {
		t.Fatal(err)
	}
	if stored["api_key"] != "original" {
		t.Fatal("rolled-back transaction changed the credential")
	}
	if err := db.UpdateSettings(ctx, func(tx *SettingsTx) error { return tx.Set("appearance", map[string]any{"title": "Example"}) }); err != nil {
		t.Fatal(err)
	}
	if settingsEpoch(t, db) != before {
		t.Fatal("unrelated settings save advanced the provider epoch")
	}
}

func TestSettingsTxEpochFailureRollsBackCredential(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := t.Context()
	if err := db.SetSetting(ctx, "gigahost", map[string]any{"api_key": "original"}); err != nil {
		t.Fatal(err)
	}
	before := settingsEpoch(t, db)
	// A denied epoch write must fail the whole save, never leave a new credential
	// alongside the old epoch. The trigger exists only in this disposable fixture.
	if _, err := db.sqlDB.ExecContext(ctx, `CREATE TRIGGER deny_epoch BEFORE UPDATE ON gigahost_config_epoch
		BEGIN SELECT RAISE(ABORT, 'epoch write denied'); END`); err != nil {
		t.Fatal(err)
	}
	err := db.UpdateSettings(ctx, func(tx *SettingsTx) error {
		return tx.Set("gigahost", map[string]any{"api_key": "replacement"})
	})
	if err == nil {
		t.Fatal("save succeeded despite the denied epoch write")
	}
	if settingsEpoch(t, db) != before {
		t.Fatal("failed epoch write changed the epoch")
	}
	var stored map[string]any
	if err := db.GetSetting(ctx, "gigahost", &stored); err != nil {
		t.Fatal(err)
	}
	if stored["api_key"] != "original" {
		t.Fatal("failed epoch write committed the replacement credential")
	}
}

func settingsEpoch(t *testing.T, db *DB) int64 {
	t.Helper()
	epoch, err := db.GigahostConfigEpoch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return epoch
}
