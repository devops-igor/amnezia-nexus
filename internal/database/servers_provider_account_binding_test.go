package database

// The write-once provider account association.
//
// The statements under test are the whole protection: the update is conditional on
// the row recording no account, so a recorded account cannot be rewritten, and an
// empty value is refused rather than stored - "bound to nothing" is not a state the
// reconciliation can ever read as an association.

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func newAssociationDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir()+"/association_test.db", testSecretKey)
	if err != nil {
		t.Fatalf("failed to open the test store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedAssociationServer(t *testing.T, db *DB, name, account string) int64 {
	t.Helper()
	id, err := db.CreateServer(context.Background(), &models.Server{
		Name:              name,
		Host:              "198.51.100.20",
		SSHUser:           "root",
		SSHPort:           22,
		Protocols:         map[string]any{"provider": "gigahost", "provider_server_id": int64(701)},
		ProviderAccountID: account,
	})
	if err != nil {
		t.Fatalf("failed to seed server %q: %v", name, err)
	}
	return id
}

// TestBindServerProviderAccountIsWriteOnce proves a row that records no account is
// bound once, that a repeated call reports it changed nothing, and that the value it
// wrote survives the second call.
func TestBindServerProviderAccountIsWriteOnce(t *testing.T) {
	db := newAssociationDB(t)
	ctx := context.Background()
	id := seedAssociationServer(t, db, "legacy", "")

	written, err := db.BindServerProviderAccount(ctx, id, "acct-north")
	if err != nil {
		t.Fatalf("BindServerProviderAccount: %v", err)
	}
	if !written {
		t.Fatal("the first association did not report that it bound the row")
	}

	written, err = db.BindServerProviderAccount(ctx, id, "acct-south")
	if err != nil {
		t.Fatalf("second BindServerProviderAccount: %v", err)
	}
	if written {
		t.Fatal("a second association reported that it bound the row again")
	}

	server, err := db.GetServer(ctx, id)
	if err != nil || server == nil {
		t.Fatalf("failed to read the row back: server=%v err=%v", server, err)
	}
	if server.ProviderAccountID != "acct-north" {
		t.Fatalf("the recorded account is %q, want the first association acct-north", server.ProviderAccountID)
	}
}

// TestBindServerProviderAccountRefusesAnEmptyAccount proves the empty value is
// refused instead of stored: an empty account means unknown, and a caller must not
// be able to turn a recorded association back into unknown.
func TestBindServerProviderAccountRefusesAnEmptyAccount(t *testing.T) {
	db := newAssociationDB(t)
	ctx := context.Background()
	id := seedAssociationServer(t, db, "registered", "acct-north")

	if _, err := db.BindServerProviderAccount(ctx, id, ""); err == nil {
		t.Fatal("binding a server to an empty account was accepted")
	}
	if _, err := db.BindServerProviderAccount(ctx, id, "   "); err == nil {
		t.Fatal("binding a server to a blank account was accepted")
	}

	server, err := db.GetServer(ctx, id)
	if err != nil || server == nil {
		t.Fatalf("failed to read the row back: server=%v err=%v", server, err)
	}
	if server.ProviderAccountID != "acct-north" {
		t.Fatalf("the recorded account became %q; a refused write must change nothing", server.ProviderAccountID)
	}
}

// TestBindServerProviderAccountTouchesNothingElse proves the write is scoped to the
// association columns: a status, an absence observation or a credential must not
// move, because the association is a statement about ownership alone.
func TestBindServerProviderAccountTouchesNothingElse(t *testing.T) {
	db := newAssociationDB(t)
	ctx := context.Background()
	id := seedAssociationServer(t, db, "legacy", "")
	if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC(), "acct-earlier"); err != nil {
		t.Fatalf("SetServerProviderAbsence: %v", err)
	}
	before, err := db.GetServer(ctx, id)
	if err != nil || before == nil {
		t.Fatalf("failed to read the row back: server=%v err=%v", before, err)
	}

	if _, err := db.BindServerProviderAccount(ctx, id, "acct-north"); err != nil {
		t.Fatalf("BindServerProviderAccount: %v", err)
	}
	after, err := db.GetServer(ctx, id)
	if err != nil || after == nil {
		t.Fatalf("failed to read the row back: server=%v err=%v", after, err)
	}

	if after.ProviderAbsentAt != before.ProviderAbsentAt || after.ProviderAbsentAccountID != before.ProviderAbsentAccountID {
		t.Fatalf("the association changed the absence observation: %q/%q -> %q/%q",
			before.ProviderAbsentAt, before.ProviderAbsentAccountID, after.ProviderAbsentAt, after.ProviderAbsentAccountID)
	}
	if after.Host != before.Host || after.Name != before.Name || after.SSHPass != before.SSHPass || after.SSHKey != before.SSHKey {
		t.Fatal("the association changed a field that is not the recorded account")
	}
}
