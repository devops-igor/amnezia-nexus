package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/security"
)

// Fault injection for the migrations that record their completion in
// migration_flags.
//
// The faults are real SQLite failures raised by triggers on the tables the
// migrations write, so no production code carries a test seam: the injected
// error travels through the same ExecContext call the migration uses. Each
// injector returns a function that removes the trigger again.

// injectServerWriteFailure makes every UPDATE of servers with the given id fail.
func injectServerWriteFailure(t *testing.T, db *DB, id int64) (remove func()) {
	t.Helper()

	stmt := "CREATE TRIGGER inject_servers_write BEFORE UPDATE ON servers WHEN NEW.id = " +
		strconv.FormatInt(id, 10) + " BEGIN SELECT RAISE(ABORT, 'injected server write failure'); END"
	if _, err := db.SQLDB().ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("failed to install server write fault: %v", err)
	}
	return func() {
		if _, err := db.SQLDB().ExecContext(context.Background(), "DROP TRIGGER IF EXISTS inject_servers_write"); err != nil {
			t.Errorf("failed to remove server write fault: %v", err)
		}
	}
}

// injectFlagWriteFailure makes writing the named migration flag fail.
func injectFlagWriteFailure(t *testing.T, db *DB, key string) (remove func()) {
	t.Helper()

	ctx := context.Background()
	insert := "CREATE TRIGGER inject_flag_insert BEFORE INSERT ON migration_flags " +
		"WHEN NEW.key = '" + key + "' BEGIN SELECT RAISE(ABORT, 'injected flag write failure'); END"
	update := "CREATE TRIGGER inject_flag_update BEFORE UPDATE ON migration_flags " +
		"WHEN NEW.key = '" + key + "' BEGIN SELECT RAISE(ABORT, 'injected flag write failure'); END"
	for _, stmt := range []string{insert, update} {
		if _, err := db.SQLDB().ExecContext(ctx, stmt); err != nil {
			t.Fatalf("failed to install flag write fault: %v", err)
		}
	}
	return func() {
		for _, name := range []string{"inject_flag_insert", "inject_flag_update"} {
			if _, err := db.SQLDB().ExecContext(ctx, "DROP TRIGGER IF EXISTS "+name); err != nil {
				t.Errorf("failed to remove flag write fault: %v", err)
			}
		}
	}
}

// injectSSLSettingWriteFailure makes rewriting the ssl setting fail.
func injectSSLSettingWriteFailure(t *testing.T, db *DB) (remove func()) {
	t.Helper()

	stmt := "CREATE TRIGGER inject_ssl_write BEFORE UPDATE ON settings WHEN OLD.key = 'ssl' " +
		"BEGIN SELECT RAISE(ABORT, 'injected ssl write failure'); END"
	if _, err := db.SQLDB().ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("failed to install ssl write fault: %v", err)
	}
	return func() {
		if _, err := db.SQLDB().ExecContext(context.Background(), "DROP TRIGGER IF EXISTS inject_ssl_write"); err != nil {
			t.Errorf("failed to remove ssl write fault: %v", err)
		}
	}
}

// seedLegacyPlaintextState resets the three flag migrations to "not run" and
// writes the legacy plaintext data they are supposed to transform.
func seedLegacyPlaintextState(t *testing.T, db *DB) {
	t.Helper()

	ctx := context.Background()
	statements := []string{
		"DELETE FROM servers",
		"DELETE FROM migration_flags WHERE key IN ('credentials_encrypted', 'xray_private_keys_cleared', 'ssl_keys_encrypted')",
		`INSERT INTO servers (id, name, host, ssh_user, ssh_port, ssh_pass, ssh_key, protocols, created_at) VALUES
			(1, 'alpha', '192.0.2.10', 'root', 22, 'plaintext-pass-1', 'plaintext-key-1',
			 '{"xray":{"port":443,"reality_private_key":"PRIVATE-KEY-1","reality_public_key":"PUBLIC-1"}}', '2026-01-01T00:00:00Z'),
			(2, 'beta', '192.0.2.11', 'root', 22, 'plaintext-pass-2', 'plaintext-key-2',
			 '{"xray":{"port":8443,"reality_private_key":"PRIVATE-KEY-2","reality_public_key":"PUBLIC-2"}}', '2026-01-01T00:00:00Z')`,
		`INSERT INTO settings (key, value) VALUES ('ssl', '{"enabled":true,"domain":"","cert_path":"","key_path":"","cert_text":"plaintext-tls-cert","key_text":"plaintext-tls-key","panel_port":5000}')
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
	}
	for _, stmt := range statements {
		if _, err := db.SQLDB().ExecContext(ctx, stmt); err != nil {
			t.Fatalf("failed to seed legacy plaintext state: %v", err)
		}
	}
}

func migrationFlag(t *testing.T, db *DB, key string) string {
	t.Helper()

	var value string
	err := db.SQLDB().QueryRowContext(context.Background(),
		"SELECT value FROM migration_flags WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatalf("failed to read migration flag %s: %v", key, err)
	}
	return value
}

func serverCredentials(t *testing.T, db *DB, id int64) (sshPass, sshKey, protocols string) {
	t.Helper()

	var pass, key, protos sql.NullString
	err := db.SQLDB().QueryRowContext(context.Background(),
		"SELECT ssh_pass, ssh_key, protocols FROM servers WHERE id = ?", id).Scan(&pass, &key, &protos)
	if err != nil {
		t.Fatalf("failed to read server %d: %v", id, err)
	}
	return pass.String, key.String, protos.String
}

func sslSetting(t *testing.T, db *DB) string {
	t.Helper()

	var value string
	if err := db.SQLDB().QueryRowContext(context.Background(),
		"SELECT value FROM settings WHERE key = 'ssl'").Scan(&value); err != nil {
		t.Fatalf("failed to read ssl setting: %v", err)
	}
	return value
}

// TestInjectedWriteFailuresReachMigrationStatements is the control for the
// atomicity tests below: it proves the triggers really abort the statements those
// migrations execute, so a green atomicity assertion is not vacuous.
func TestInjectedWriteFailuresReachMigrationStatements(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	seedLegacyPlaintextState(t, db)
	ctx := context.Background()

	removeServers := injectServerWriteFailure(t, db, 2)
	_, err = db.SQLDB().ExecContext(ctx, "UPDATE servers SET ssh_pass = ?, ssh_key = ? WHERE id = ?", "x", "y", 2)
	if err == nil || !strings.Contains(err.Error(), "injected server write failure") {
		removeServers()
		t.Fatalf("the server write fault did not reach the statement: %v", err)
	}
	// Negative control: the same statement for another row still succeeds, so the
	// fault is scoped to the row the migration writes and is not a blanket error.
	if _, err := db.SQLDB().ExecContext(ctx, "UPDATE servers SET ssh_pass = ?, ssh_key = ? WHERE id = ?", "x", "y", 1); err != nil {
		removeServers()
		t.Fatalf("the server write fault also blocked an unrelated row: %v", err)
	}
	removeServers()

	removeFlag := injectFlagWriteFailure(t, db, "credentials_encrypted")
	_, err = db.SQLDB().ExecContext(ctx,
		"INSERT INTO migration_flags (key, value) VALUES ('credentials_encrypted', '1') ON CONFLICT(key) DO UPDATE SET value = '1'")
	if err == nil || !strings.Contains(err.Error(), "injected flag write failure") {
		removeFlag()
		t.Fatalf("the flag write fault did not reach the statement: %v", err)
	}
	removeFlag()

	removeSSL := injectSSLSettingWriteFailure(t, db)
	_, err = db.SQLDB().ExecContext(ctx,
		"INSERT INTO settings (key, value) VALUES ('ssl', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", `{"enabled":false}`)
	if err == nil || !strings.Contains(err.Error(), "injected ssl write failure") {
		removeSSL()
		t.Fatalf("the ssl write fault did not reach the statement: %v", err)
	}
	removeSSL()
}

// TestCredentialMigrationIsAtomicWithItsCompletionFlag covers both directions of
// the defect: a failed credential rewrite must not leave the completion flag
// behind, and a failed flag write must roll the already-applied rewrite back.
func TestCredentialMigrationIsAtomicWithItsCompletionFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	seedLegacyPlaintextState(t, db)

	// 1. The rewrite fails for the second server.
	remove := injectServerWriteFailure(t, db, 2)
	err = db.InitSchema(ctx)
	if err == nil {
		remove()
		t.Fatal("InitSchema succeeded although the credential rewrite was aborted")
	}
	if !strings.Contains(err.Error(), "injected server write failure") {
		remove()
		t.Fatalf("InitSchema failed for an unrelated reason: %v", err)
	}
	remove()

	if flag := migrationFlag(t, db, "credentials_encrypted"); flag != "" {
		t.Fatalf("credentials_encrypted flag was recorded although the rewrite failed: %q", flag)
	}
	for id := int64(1); id <= 2; id++ {
		pass, key, _ := serverCredentials(t, db, id)
		if pass != "plaintext-pass-"+fmt.Sprint(id) || key != "plaintext-key-"+fmt.Sprint(id) {
			t.Fatalf("server %d credentials changed despite the failed migration: pass=%q key=%q", id, pass, key)
		}
	}

	// 2. The rewrite succeeds but recording the flag fails: the rewrite must be
	//    rolled back with it.
	removeFlag := injectFlagWriteFailure(t, db, "credentials_encrypted")
	err = db.InitSchema(ctx)
	if err == nil {
		removeFlag()
		t.Fatal("InitSchema succeeded although the completion flag write was aborted")
	}
	if !strings.Contains(err.Error(), "injected flag write failure") {
		removeFlag()
		t.Fatalf("InitSchema failed for an unrelated reason: %v", err)
	}
	removeFlag()

	if flag := migrationFlag(t, db, "credentials_encrypted"); flag != "" {
		t.Fatalf("credentials_encrypted flag survived a failed flag write: %q", flag)
	}
	for id := int64(1); id <= 2; id++ {
		pass, key, _ := serverCredentials(t, db, id)
		if pass != "plaintext-pass-"+fmt.Sprint(id) || key != "plaintext-key-"+fmt.Sprint(id) {
			t.Fatalf("server %d rewrite survived the failed flag write: pass=%q key=%q", id, pass, key)
		}
	}

	// 3. Without the faults the migration completes and actually encrypts.
	if err := db.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema failed after the faults were removed: %v", err)
	}
	if flag := migrationFlag(t, db, "credentials_encrypted"); flag != "1" {
		t.Fatalf("credentials_encrypted flag = %q after a successful migration, want \"1\"", flag)
	}
	for id := int64(1); id <= 2; id++ {
		pass, key, _ := serverCredentials(t, db, id)
		if !security.LooksLikeFernetToken(pass) || !security.LooksLikeFernetToken(key) {
			t.Fatalf("server %d credentials are not encrypted: pass=%q key=%q", id, pass, key)
		}
		decPass, err := security.DecryptCredential(pass, testSecretKey)
		if err != nil || decPass != "plaintext-pass-"+fmt.Sprint(id) {
			t.Fatalf("server %d ssh_pass does not decrypt to the original: %q (%v)", id, decPass, err)
		}
		decKey, err := security.DecryptCredential(key, testSecretKey)
		if err != nil || decKey != "plaintext-key-"+fmt.Sprint(id) {
			t.Fatalf("server %d ssh_key does not decrypt to the original: %q (%v)", id, decKey, err)
		}
	}

	// 4. A further run is a no-op: the guard still short-circuits a completed
	//    migration, and the values stay as they are.
	before := make([]string, 0, 4)
	for id := int64(1); id <= 2; id++ {
		pass, key, _ := serverCredentials(t, db, id)
		before = append(before, pass, key)
	}
	if err := db.InitSchema(ctx); err != nil {
		t.Fatalf("repeated InitSchema failed: %v", err)
	}
	for id := int64(1); id <= 2; id++ {
		pass, key, _ := serverCredentials(t, db, id)
		if pass != before[2*(id-1)] || key != before[2*(id-1)+1] {
			t.Fatalf("server %d credentials were rewritten by a repeated run", id)
		}
	}
}

// TestXrayKeyMigrationIsAtomicWithItsCompletionFlag checks that a failed
// protocols rewrite cannot leave 'xray_private_keys_cleared' behind.
func TestXrayKeyMigrationIsAtomicWithItsCompletionFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	seedLegacyPlaintextState(t, db)

	// A row whose protocols value is not valid JSON is tolerated by design: there
	// is no plaintext field to identify in it, so the migration must not block.
	if _, err := db.SQLDB().ExecContext(ctx,
		"INSERT INTO servers (id, name, host, ssh_port, protocols, created_at) VALUES (3, 'gamma', '192.0.2.12', 22, 'not-json', '2026-01-01T00:00:00Z')"); err != nil {
		t.Fatalf("failed to seed malformed protocols row: %v", err)
	}

	remove := injectServerWriteFailure(t, db, 2)
	err = db.InitSchema(ctx)
	if err == nil {
		remove()
		t.Fatal("InitSchema succeeded although the protocols rewrite was aborted")
	}
	if !strings.Contains(err.Error(), "injected server write failure") {
		remove()
		t.Fatalf("InitSchema failed for an unrelated reason: %v", err)
	}
	remove()

	if flag := migrationFlag(t, db, "xray_private_keys_cleared"); flag != "" {
		t.Fatalf("xray_private_keys_cleared flag was recorded although the rewrite failed: %q", flag)
	}
	for id := int64(1); id <= 2; id++ {
		_, _, protocols := serverCredentials(t, db, id)
		if !strings.Contains(protocols, "PRIVATE-KEY-"+fmt.Sprint(id)) {
			t.Fatalf("server %d private key was removed despite the failed migration: %q", id, protocols)
		}
	}

	if err := db.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema failed after the fault was removed: %v", err)
	}
	if flag := migrationFlag(t, db, "xray_private_keys_cleared"); flag != "1" {
		t.Fatalf("xray_private_keys_cleared flag = %q after a successful migration, want \"1\"", flag)
	}
	for id := int64(1); id <= 2; id++ {
		_, _, protocols := serverCredentials(t, db, id)
		if strings.Contains(protocols, "PRIVATE-KEY-"+fmt.Sprint(id)) || strings.Contains(protocols, "reality_private_key") {
			t.Fatalf("server %d still carries a private key after the migration: %q", id, protocols)
		}
		if !strings.Contains(protocols, "PUBLIC-"+fmt.Sprint(id)) {
			t.Fatalf("server %d lost its non-sensitive protocol data: %q", id, protocols)
		}
	}
	if _, _, protocols := serverCredentials(t, db, 3); protocols != "not-json" {
		t.Fatalf("malformed protocols value was rewritten: %q", protocols)
	}
}

// TestSSLKeyMigrationIsAtomicWithItsCompletionFlag checks that a failed ssl
// settings rewrite cannot leave 'ssl_keys_encrypted' behind.
func TestSSLKeyMigrationIsAtomicWithItsCompletionFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	seedLegacyPlaintextState(t, db)

	remove := injectSSLSettingWriteFailure(t, db)
	err = db.InitSchema(ctx)
	if err == nil {
		remove()
		t.Fatal("InitSchema succeeded although the ssl rewrite was aborted")
	}
	if !strings.Contains(err.Error(), "injected ssl write failure") {
		remove()
		t.Fatalf("InitSchema failed for an unrelated reason: %v", err)
	}
	remove()

	if flag := migrationFlag(t, db, "ssl_keys_encrypted"); flag != "" {
		t.Fatalf("ssl_keys_encrypted flag was recorded although the rewrite failed: %q", flag)
	}
	if value := sslSetting(t, db); !strings.Contains(value, "plaintext-tls-key") || !strings.Contains(value, "plaintext-tls-cert") {
		t.Fatalf("ssl settings changed despite the failed migration: %q", value)
	}

	if err := db.InitSchema(ctx); err != nil {
		t.Fatalf("InitSchema failed after the fault was removed: %v", err)
	}
	if flag := migrationFlag(t, db, "ssl_keys_encrypted"); flag != "1" {
		t.Fatalf("ssl_keys_encrypted flag = %q after a successful migration, want \"1\"", flag)
	}
	value := sslSetting(t, db)
	if strings.Contains(value, "plaintext-tls-key") || strings.Contains(value, "plaintext-tls-cert") {
		t.Fatalf("ssl settings still carry plaintext material: %q", value)
	}
	var sslMap map[string]any
	if err := json.Unmarshal([]byte(value), &sslMap); err != nil {
		t.Fatalf("ssl settings are not valid JSON after the migration: %v", err)
	}
	for _, field := range []string{"key_text", "cert_text"} {
		raw, _ := sslMap[field].(string)
		if !security.LooksLikeFernetToken(raw) {
			t.Fatalf("ssl %s is not encrypted: %q", field, raw)
		}
		want := map[string]string{"key_text": "plaintext-tls-key", "cert_text": "plaintext-tls-cert"}[field]
		if dec, err := security.DecryptCredential(raw, testSecretKey); err != nil || dec != want {
			t.Fatalf("ssl %s does not decrypt to the original: %q (%v)", field, dec, err)
		}
	}
}

// TestSchemaInitRetriesAfterPartiallyAppliedMigrationSequence interrupts
// initialization inside the migration sequence and then runs the real initializer
// again: each migration must be all-or-nothing with its flag, and the retry must
// finish the remaining work idempotently.
func TestSchemaInitRetriesAfterPartiallyAppliedMigrationSequence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := Open(path, testSecretKey)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	seedLegacyPlaintextState(t, db)

	// The ssl migration runs after the credential and xray migrations, so this
	// fault interrupts initialization partway through the sequence.
	remove := injectSSLSettingWriteFailure(t, db)
	err = db.InitSchema(ctx)
	if err == nil {
		remove()
		t.Fatal("InitSchema succeeded although the ssl rewrite was aborted")
	}
	if !strings.Contains(err.Error(), "injected ssl write failure") {
		remove()
		t.Fatalf("InitSchema failed for an unrelated reason: %v", err)
	}
	remove()

	// Completed migrations are committed with their flags and their data.
	if flag := migrationFlag(t, db, "credentials_encrypted"); flag != "1" {
		t.Fatalf("credentials_encrypted flag = %q after the completed migration, want \"1\"", flag)
	}
	if pass, _, _ := serverCredentials(t, db, 1); !security.LooksLikeFernetToken(pass) {
		t.Fatalf("credentials were not encrypted by the completed migration: %q", pass)
	}
	if flag := migrationFlag(t, db, "xray_private_keys_cleared"); flag != "1" {
		t.Fatalf("xray_private_keys_cleared flag = %q after the completed migration, want \"1\"", flag)
	}
	if _, _, protocols := serverCredentials(t, db, 1); strings.Contains(protocols, "PRIVATE-KEY-1") {
		t.Fatalf("private key was not cleared by the completed migration: %q", protocols)
	}

	// The interrupted migration is neither flagged nor partially applied.
	if flag := migrationFlag(t, db, "ssl_keys_encrypted"); flag != "" {
		t.Fatalf("ssl_keys_encrypted flag = %q after the interrupted migration, want empty", flag)
	}
	if value := sslSetting(t, db); !strings.Contains(value, "plaintext-tls-key") {
		t.Fatalf("ssl settings were partially rewritten by the interrupted migration: %q", value)
	}

	// Re-running the real initializer completes the remaining migration.
	if err := db.InitSchema(ctx); err != nil {
		t.Fatalf("retry after the interruption failed: %v", err)
	}
	for _, key := range []string{"credentials_encrypted", "xray_private_keys_cleared", "ssl_keys_encrypted"} {
		if flag := migrationFlag(t, db, key); flag != "1" {
			t.Fatalf("%s flag = %q after the retry, want \"1\"", key, flag)
		}
	}
	if value := sslSetting(t, db); strings.Contains(value, "plaintext-tls-key") {
		t.Fatalf("ssl settings are still plaintext after the retry: %q", value)
	}

	// And a third run changes nothing.
	credsBefore, _, _ := serverCredentials(t, db, 1)
	sslBefore := sslSetting(t, db)
	if err := db.InitSchema(ctx); err != nil {
		t.Fatalf("repeated InitSchema failed: %v", err)
	}
	credsAfter, _, _ := serverCredentials(t, db, 1)
	if credsAfter != credsBefore {
		t.Fatal("a repeated initialization rewrote already-encrypted credentials")
	}
	if sslSetting(t, db) != sslBefore {
		t.Fatal("a repeated initialization rewrote the encrypted ssl settings")
	}
}
