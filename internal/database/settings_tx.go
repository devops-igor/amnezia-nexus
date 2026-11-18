package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// SettingsTx reads and writes settings rows inside one transaction. It exists
// so a caller can decide what to write from the rows as they are at write time,
// for example keeping a stored credential the request did not supply, without a
// second writer slipping in between the read and the write.
type SettingsTx struct {
	d   *DB
	tx  *sql.Tx
	ctx context.Context
}

// UpdateSettings runs fn in a single transaction that holds the database write
// lock. Every Set fn made is committed together, and a returned error rolls all
// of them back, so a failure part way leaves no section changed.
func (d *DB) UpdateSettings(ctx context.Context, fn func(*SettingsTx) error) error {
	return d.WithTransaction(ctx, func(tx *sql.Tx) error {
		return fn(&SettingsTx{d: d, tx: tx, ctx: ctx})
	})
}

// Get decodes one stored setting into target, decrypting stored credentials the
// same way DB.GetSetting does. An absent or empty row leaves target untouched
// and is not an error; a failed read or an undecodable row is.
func (t *SettingsTx) Get(key string, target any) error {
	var val sql.NullString
	err := t.tx.QueryRowContext(t.ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get setting %s: %w", key, err)
	}
	if !val.Valid || val.String == "" {
		return nil
	}
	return t.d.decodeStoredSetting(key, val.String, target)
}

// Set stores one setting, applying the same at-rest encryption as
// DB.SetSetting. The vpn_config record has its own validated writer and is
// refused here rather than written around it.
func (t *SettingsTx) Set(key string, value any) error {
	if key == "vpn_config" {
		return errors.New("vpn_config is written through SaveVPNConfig")
	}
	valToStore, err := t.d.prepareSettingForStore(key, value)
	if err != nil {
		return err
	}
	b, err := json.Marshal(valToStore)
	if err != nil {
		return fmt.Errorf("failed to marshal setting %s: %w", key, err)
	}
	_, err = t.tx.ExecContext(t.ctx,
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, string(b),
	)
	if err != nil {
		return fmt.Errorf("failed to set setting %s: %w", key, err)
	}
	return nil
}
