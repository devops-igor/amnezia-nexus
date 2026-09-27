package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresExistingSecretAndDatabase(t *testing.T) {
	t.Setenv("SECRET_KEY", "")
	var out, errOut bytes.Buffer
	if run(context.Background(), []string{"-db", filepath.Join(t.TempDir(), "missing.db")}, &out, &errOut) != 2 {
		t.Fatal("missing secret accepted")
	}
	if !strings.Contains(errOut.String(), "never generates") {
		t.Fatal("missing secret diagnostic lost")
	}
	secret := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(secret, []byte("test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if run(context.Background(), []string{"-db", filepath.Join(t.TempDir(), "missing.db"), "-secret-key-file", secret}, &out, &errOut) != 2 {
		t.Fatal("missing database accepted")
	}
	if strings.Contains(errOut.String(), "test-secret") {
		t.Fatal("secret leaked")
	}
}

func TestRunWritesBlockedJSONAndExitCode(t *testing.T) {
	t.Setenv("SECRET_KEY", "test-secret")
	path := filepath.Join(t.TempDir(), "db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE settings(key TEXT,value TEXT);
		CREATE TABLE users(id TEXT,enabled INTEGER,traffic_limit INTEGER,traffic_used INTEGER,expires_at TEXT,expiration_date TEXT);
		CREATE TABLE user_connections(id TEXT,user_id TEXT,server_id INTEGER,protocol TEXT,client_id TEXT,client_params TEXT);`)
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-db", path}, &out, &errOut); code != 1 {
		t.Fatalf("got exit %d: %s", code, &errOut)
	}
	if !strings.Contains(out.String(), `"ready": false`) || !strings.Contains(out.String(), "invalid_vpn_config") {
		t.Fatal("missing structured failure report")
	}
}
