package database

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestPeerLifecycle_CRUDAndMigration(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:", "")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	defer db.Close()

	// 1. Verify schema migration created the table and seeded existing user_connections
	// First insert a user and user_connection
	u := &models.User{
		ID:        "u-lifecycle-1",
		Username:  "lifecycle_user",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	conn := &models.UserConnection{
		ID:        "conn-seed-1",
		UserID:    u.ID,
		ServerID:  1,
		Protocol:  "awg",
		ClientID:  "client-seed-101",
		Name:      "Seed Connection",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("failed to create connection: %v", err)
	}

	// Re-run migration to test idempotency and seeding
	if err := db.migratePeerLifecycle(ctx); err != nil {
		t.Fatalf("migratePeerLifecycle failed: %v", err)
	}

	// Check seeded peer
	activeIDs, err := db.GetActivePeerIDs(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if !activeIDs["client-seed-101"] {
		t.Fatalf("expected client-seed-101 to be seeded into peer_lifecycle, got %v", activeIDs)
	}

	// 2. Record unassigned connection in peer_lifecycle
	unassignedClientID := "client-unassigned-202"
	if err := db.RecordPeerLifecycle(ctx, 1, "awg", unassignedClientID, "Unassigned Conn", "", "active"); err != nil {
		t.Fatalf("RecordPeerLifecycle failed: %v", err)
	}

	activeIDs, err = db.GetActivePeerIDs(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if !activeIDs[unassignedClientID] {
		t.Fatalf("expected %s in activeIDs, got %v", unassignedClientID, activeIDs)
	}

	// 3. Upsert: update status and user_id
	if err := db.RecordPeerLifecycle(ctx, 1, "awg", unassignedClientID, "Bound Conn", u.ID, "active"); err != nil {
		t.Fatalf("RecordPeerLifecycle upsert failed: %v", err)
	}

	// 4. Update status to 'failed'
	if err := db.SetPeerLifecycleStatus(ctx, 1, "awg", unassignedClientID, "failed"); err != nil {
		t.Fatalf("SetPeerLifecycleStatus failed: %v", err)
	}

	activeIDs, err = db.GetActivePeerIDs(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if activeIDs[unassignedClientID] {
		t.Fatalf("expected 'failed' peer %s to NOT be in activeIDs", unassignedClientID)
	}

	// 5. Update status to 'pending' -> should be included in activeIDs
	if err := db.SetPeerLifecycleStatus(ctx, 1, "awg", unassignedClientID, "pending"); err != nil {
		t.Fatalf("SetPeerLifecycleStatus to pending failed: %v", err)
	}
	activeIDs, err = db.GetActivePeerIDs(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if !activeIDs[unassignedClientID] {
		t.Fatalf("expected 'pending' peer %s to be in activeIDs", unassignedClientID)
	}

	// 6. Delete peer lifecycle
	if err := db.DeletePeerLifecycle(ctx, 1, "awg", unassignedClientID); err != nil {
		t.Fatalf("DeletePeerLifecycle failed: %v", err)
	}
	activeIDs, err = db.GetActivePeerIDs(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if activeIDs[unassignedClientID] {
		t.Fatalf("expected deleted peer %s to NOT be in activeIDs", unassignedClientID)
	}

	// 7. Delete by user ID
	if err := db.DeletePeerLifecycleByUserID(ctx, u.ID); err != nil {
		t.Fatalf("DeletePeerLifecycleByUserID failed: %v", err)
	}
	activeIDs, err = db.GetActivePeerIDs(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if activeIDs["client-seed-101"] {
		t.Fatalf("expected client-seed-101 to be deleted by user ID")
	}

	// 8. Test GetPeerLifecycles
	if err := db.RecordPeerLifecycle(ctx, 1, "awg", "client-multi-1", "Multi 1", "", "active"); err != nil {
		t.Fatalf("RecordPeerLifecycle failed: %v", err)
	}
	if err := db.RecordPeerLifecycle(ctx, 1, "awg", "client-multi-2", "Multi 2", "", "failed"); err != nil {
		t.Fatalf("RecordPeerLifecycle failed: %v", err)
	}
	lifecycles, err := db.GetPeerLifecycles(ctx, 1, "awg")
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	if len(lifecycles) != 2 {
		t.Fatalf("expected 2 lifecycle records, got %d", len(lifecycles))
	}
	if lifecycles["client-multi-1"].Status != "active" {
		t.Errorf("expected active status for client-multi-1, got %s", lifecycles["client-multi-1"].Status)
	}
	if lifecycles["client-multi-2"].Status != "failed" {
		t.Errorf("expected failed status for client-multi-2, got %s", lifecycles["client-multi-2"].Status)
	}
}
