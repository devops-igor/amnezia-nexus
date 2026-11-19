package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// credentialFields names, per settings key, the fields the database stores
// encrypted. A caller that has to carry one of them forward must be able to tell
// three states apart: absent (no row, or an empty field), readable, and present
// but unreadable under the active key. The lossy readers fold the third into the
// first, which is correct for display and wrong for a write.
var credentialFields = map[string][]string{
	"ssl":           {"key_text", "cert_text"},
	"gigahost":      {"api_key"},
	"notifications": {"app_token"},
}

// CredentialUnreadableError reports a stored credential that is present but
// cannot be decrypted with the active key. Writing the setting anyway would
// replace it with an empty value that no later key correction can recover.
type CredentialUnreadableError struct {
	Key   string
	Field string
}

func (e *CredentialUnreadableError) Error() string {
	return fmt.Sprintf("stored %s.%s cannot be decrypted with the active key", e.Key, e.Field)
}

// unreadableCredential returns the first of the named fields (all credential
// fields of key when none are named) that holds ciphertext this database cannot
// decrypt. An empty or absent field is not unreadable. A value that is not a JSON
// object is left to the ordinary decoder, which reports it.
func (d *DB) unreadableCredential(key, raw string, fields []string) error {
	if len(fields) == 0 {
		fields = credentialFields[key]
	}
	var stored map[string]any
	if json.Unmarshal([]byte(raw), &stored) != nil {
		return nil
	}
	for _, field := range fields {
		value, ok := stored[field].(string)
		if !ok || value == "" {
			continue
		}
		if _, err := security.DecryptCredential(value, d.secretKey); err != nil {
			return &CredentialUnreadableError{Key: key, Field: field}
		}
	}
	return nil
}

// CheckCredentialsReadable reports a CredentialUnreadableError when the stored
// row for key holds one of the named credential fields (all of them when none are
// named) that cannot be decrypted. A missing row or an empty field is readable.
func (d *DB) CheckCredentialsReadable(ctx context.Context, key string, fields ...string) error {
	val, found, err := d.GetSettingRaw(ctx, key)
	if err != nil {
		return err
	}
	if !found || !val.Valid || val.String == "" {
		return nil
	}
	return d.unreadableCredential(key, val.String, fields)
}

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

// GetStrict is Get for a caller that is about to carry credentials forward. It
// fails with a CredentialUnreadableError, before decoding anything, when one of
// the named credential fields (all of them when none are named) is present but
// cannot be decrypted. Name only the fields that really have to be preserved: a
// field the request replaces does not need to be readable, which is what keeps
// supplying replacement material a way out of an unreadable credential.
func (t *SettingsTx) GetStrict(key string, target any, fields ...string) error {
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
	if err := t.d.unreadableCredential(key, val.String, fields); err != nil {
		return err
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
