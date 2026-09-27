package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/security"
	"golang.org/x/crypto/curve25519"
)

func preflightDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel ?# snapshot.db")
	uri := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(SchemaSQL); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{23}, 32)
	public, _ := curve25519.X25519(key, curve25519.Basepoint)
	private := base64.StdEncoding.EncodeToString(key)
	pub := base64.StdEncoding.EncodeToString(public)
	encrypted, err := security.EncryptCredential(private, "audit-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	clientKey := bytes.Repeat([]byte{37}, 32)
	clientPublic, _ := curve25519.X25519(clientKey, curve25519.Basepoint)
	clientPrivate := base64.StdEncoding.EncodeToString(clientKey)
	clientPub := base64.StdEncoding.EncodeToString(clientPublic)
	cfg, _ := json.Marshal(map[string]any{"server_private_key": encrypted, "server_public_key": pub,
		"listen_port": 51820, "subnet_cidr": "10.100.0.0/24", "h1": "100-200", "s4": 25})
	params, _ := json.Marshal(map[string]any{"assigned_ip": "10.100.0.2", "client_private_key": clientPrivate, "RejectAfterTime": 190})
	for _, stmt := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO settings(key,value) VALUES ('vpn_config',?)", []any{string(cfg)}},
		{"INSERT INTO users(id,username,enabled) VALUES ('owner','owner',1)", nil},
		{"INSERT INTO user_connections(id,user_id,server_id,protocol,client_id,client_params) VALUES ('peer','owner',0,'awg2',?,?)", []any{clientPub, string(params)}},
	} {
		if _, err := db.Exec(stmt.query, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	return db, path
}

// Byte-for-byte comparison of a closed database also covers untouched tables,
// indexes, VPN runtime sessions, settings, and schema version, not only peers.
func TestAWGPreflightLeavesDatabaseUnchanged(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		db, path := preflightDB(t)
		if invalid {
			if _, err := db.Exec(`INSERT INTO user_connections(id,user_id,server_id,protocol,client_id,client_params)
				SELECT 'duplicate',user_id,server_id,protocol,client_id,client_params FROM user_connections`); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		report, err := AuditAWGMigration(context.Background(), path, "audit-test-secret", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if report.Ready == invalid {
			t.Fatalf("unexpected readiness: %+v", report)
		}
		if invalid && len(report.Peers) != 0 {
			t.Fatal("duplicate identity produced installable peers")
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("audit changed database bytes")
		}
		// The same old reader still sees the same raw identity/configuration.
		uri := url.URL{Scheme: "file", Path: path}
		old, err := sql.Open("sqlite", uri.String())
		if err != nil {
			t.Fatal(err)
		}
		var count int
		err = old.QueryRow("SELECT count(*) FROM user_connections WHERE protocol='awg2'").Scan(&count)
		_ = old.Close()
		want := 1
		if invalid {
			want = 2
		}
		if err != nil || count != want {
			t.Fatal("rollback reader lost legacy connection data")
		}
	}
}

func TestAWGPreflightReadsWALAndAllMalformedRows(t *testing.T) {
	db, path := preflightDB(t)
	if _, err := db.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	// Keep writer open: these committed records remain in the WAL.
	if _, err := db.Exec(`INSERT INTO user_connections(id,user_id,server_id,protocol,client_id,client_params)
		VALUES ('broken','owner',0,'awg','bad-key','{broken')`); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path + "-wal")
	if err != nil || stat.Size() == 0 {
		t.Fatal("fixture has no committed WAL data")
	}
	report, err := AuditAWGMigration(context.Background(), path, "audit-test-secret", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if report.Ready || len(report.Connections) != 2 || len(report.Peers) != 1 || report.Connections[0].ConnectionID != "broken" {
		t.Fatalf("WAL row was lost or malformed JSON skipped: %+v", report)
	}
	// A separate reader transaction remains consistent while the writer changes eligibility.
	uri := url.URL{Scheme: "file", Path: path}
	reader, err := sql.Open("sqlite", uri.String())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var config string
	if err := tx.QueryRow("SELECT value FROM settings WHERE key='vpn_config'").Scan(&config); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE users SET enabled=0 WHERE id='owner'"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readAWGSnapshot(context.Background(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Config != config || !snapshot.Connections[0].User.Enabled {
		t.Fatal("snapshot mixed old config with new authorization")
	}
}

func TestAWGPreflightNeverCreatesOrMigratesDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := AuditAWGMigration(context.Background(), missing, "secret", time.Now()); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("audit created database")
	}
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT); CREATE TABLE user_connections(id TEXT)"); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	before, _ := os.ReadFile(path)
	if _, err := AuditAWGMigration(context.Background(), path, "secret", time.Now()); err == nil || !strings.Contains(err.Error(), "compatible schema") {
		t.Fatal("incompatible legacy schema did not fail closed")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("audit migrated legacy schema")
	}
}
