package reconciliation

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestReconciler_CleanupZombiePeers_RevokesDisabledOwnerCredential verifies that an owned
// VLESS credential whose user was disabled (row raced past the disable) is withdrawn
// remotely and from SQLite, while an enabled user's credential is preserved.
func TestReconciler_CleanupZombiePeers_RevokesDisabledOwnerCredential(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "S", Host: "10.0.0.1", SSHPort: 22,
		Protocols: map[string]any{"vless": map[string]any{"installed": true}},
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	for id, enabled := range map[string]bool{"u-off": false, "u-on": true} {
		if _, err := db.CreateUser(ctx, &models.User{ID: id, Username: id, PasswordHash: "h", Role: models.RoleUser, Enabled: enabled, CreatedAt: time.Now()}); err != nil {
			t.Fatalf("create user: %v", err)
		}
		if _, err := db.CreateConnection(ctx, &models.UserConnection{ID: "c-" + id, UserID: id, ServerID: sID, Protocol: "vless", ClientID: "cid-" + id, CreatedAt: time.Now()}); err != nil {
			t.Fatalf("create connection: %v", err)
		}
		if err := db.RecordPeerLifecycle(ctx, sID, "vless", "cid-"+id, id, id, "active"); err != nil {
			t.Fatalf("record lifecycle: %v", err)
		}
	}

	old := time.Now().Add(-15 * time.Minute).Format(time.RFC3339)
	mgr := &mockZombiePeerProtocolManager{proto: "vless", clients: []map[string]any{
		{"clientId": "cid-u-off", "creationDate": old},
		{"clientId": "cid-u-on", "creationDate": old},
	}}
	reg := newMockRegistry()
	reg.Register(mgr)

	if err := New(db, reg).CleanupZombiePeers(ctx); err != nil {
		t.Fatalf("CleanupZombiePeers: %v", err)
	}

	mgr.mu.Lock()
	deleted := append([]string(nil), mgr.deleted...)
	mgr.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "cid-u-off" {
		t.Fatalf("expected only the disabled owner's credential revoked, got %v", deleted)
	}
	if c, _ := db.GetConnection(ctx, "c-u-off"); c != nil {
		t.Error("disabled owner's connection row must be removed")
	}
	if c, _ := db.GetConnection(ctx, "c-u-on"); c == nil {
		t.Error("enabled owner's connection row must be preserved")
	}
}
