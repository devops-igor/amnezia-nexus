package database

import (
	"context"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Regression tests for issue #391 round 4c batch E, finding F4.
//
// user_connections.client_id is declared NULLABLE (schema.sql), and NULL rows
// genuinely exist in production: imported/partial connection rows carry no
// peer identity. portalPeerKeysForUser — the capture step that both
// DeleteConnectionsByUserID and deleteUser run before their deleting statement —
// scanned that column into a plain Go string, so a single NULL row made
// database/sql abort the scan ("converting NULL to string is unsupported").
// Because the capture runs before the DELETE, one such row PERMANENTLY blocked
// bulk connection deletion AND user deletion for that user.
//
// The fix scans into sql.NullString and lets the existing empty-string guard
// skip the row, matching the scanConnection convention in the same file.

// insertNullClientIDConnection inserts a connection row whose client_id is an
// explicit SQL NULL (the shape CreateConnection cannot produce, and the shape
// an import/partial row has on disk).
func insertNullClientIDConnection(t *testing.T, db *DB, id, userID string, serverID int64, protocol string) {
	t.Helper()
	_, err := db.sqlDB.ExecContext(context.Background(),
		"INSERT INTO user_connections (id, user_id, server_id, protocol, client_id) VALUES (?, ?, ?, ?, NULL)",
		id, userID, serverID, protocol)
	if err != nil {
		t.Fatalf("failed to insert NULL-client_id connection %s: %v", id, err)
	}
}

func countConnectionRows(t *testing.T, db *DB, id string) int {
	t.Helper()
	var n int
	if err := db.sqlDB.QueryRow("SELECT COUNT(*) FROM user_connections WHERE id = ?", id).Scan(&n); err != nil {
		t.Fatalf("count query for %s failed: %v", id, err)
	}
	return n
}

// TestDeleteConnectionsByUserIDWithNullClientID is the pm_bot reproduction as a
// permanent test: a user whose connections include a NULL client_id row must
// still be deletable, and the row must actually be gone afterwards.
func TestDeleteConnectionsByUserIDWithNullClientID(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.CreateServer(ctx, &models.Server{Name: "S1", Host: "1.1.1.1"}); err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: "null_client_id_user"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	insertNullClientIDConnection(t, db, "conn-null-cid", uID, 0, "awg")

	n, err := db.DeleteConnectionsByUserID(ctx, uID)
	if err != nil {
		t.Fatalf("DeleteConnectionsByUserID failed on NULL client_id row: %v", err)
	}
	if n != 1 {
		t.Errorf("DeleteConnectionsByUserID = %d, want 1", n)
	}
	if got := countConnectionRows(t, db, "conn-null-cid"); got != 0 {
		t.Errorf("NULL-client_id connection row still present after deletion: %d rows", got)
	}
}

// TestDeleteUserWithNullClientID proves the second, worse symptom: user
// deletion itself was blocked, not just bulk connection deletion.
func TestDeleteUserWithNullClientID(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	if _, err := db.CreateServer(ctx, &models.Server{Name: "S1", Host: "1.1.1.1"}); err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: "null_client_id_delete_user"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	insertNullClientIDConnection(t, db, "conn-null-cid-user", uID, 0, "awg")

	ok, err := db.DeleteUser(ctx, uID)
	if err != nil {
		t.Fatalf("DeleteUser failed on NULL client_id row: %v", err)
	}
	if !ok {
		t.Error("DeleteUser returned false, want true")
	}
	if got := countConnectionRows(t, db, "conn-null-cid-user"); got != 0 {
		t.Errorf("NULL-client_id connection row still present after user deletion: %d rows", got)
	}
}

// TestPortalPeerKeysForUserMixedRowsSkipsNullAndKeepsRealPortalKey pins both
// halves of the contract: a NULL client_id row contributes NOTHING (no key, and
// in particular no empty string), while a real portal AWG row is still captured
// so revocation keeps firing for the session that actually exists.
func TestPortalPeerKeysForUserMixedRowsSkipsNullAndKeepsRealPortalKey(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	uID, err := db.CreateUser(ctx, &models.User{Username: "mixed_null_user"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	insertNullClientIDConnection(t, db, "conn-mixed-null", uID, 0, "awg")
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:       "conn-mixed-real",
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: "realPortalPeerKey=",
	}); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	keys, err := portalPeerKeysForUser(ctx, db.sqlDB, uID)
	if err != nil {
		t.Fatalf("portalPeerKeysForUser failed on mixed NULL/real rows: %v", err)
	}
	if len(keys) != 1 || keys[0] != "realPortalPeerKey=" {
		t.Fatalf("captured keys = %#v, want exactly [realPortalPeerKey=]", keys)
	}
	for _, k := range keys {
		if k == "" {
			t.Error("captured keys contain an empty string from a NULL client_id row")
		}
	}
}

// TestPortalPeerKeysForUserExcludesNonPortalRows proves the NULL handling did
// not widen the capture: a NULL-client_id portal row and a regular server row
// (server_id != 0) yield no keys at all.
func TestPortalPeerKeysForUserExcludesNonPortalRows(t *testing.T) {
	db, _ := setupTestDB(t)
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{Name: "S1", Host: "1.1.1.1"})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	uID, err := db.CreateUser(ctx, &models.User{Username: "exclusion_user"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	insertNullClientIDConnection(t, db, "conn-excl-null", uID, 0, "awg")
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID:       "conn-excl-server",
		UserID:   uID,
		ServerID: sID,
		Protocol: "awg",
		ClientID: "serverSidePeerKey=",
	}); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	keys, err := portalPeerKeysForUser(ctx, db.sqlDB, uID)
	if err != nil {
		t.Fatalf("portalPeerKeysForUser failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("captured keys = %#v, want none (NULL portal row + regular server row are out of scope)", keys)
	}
}
