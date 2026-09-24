package endpoint

import (
	"context"
	"errors"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestSessionManagerUpdateAndRollbackSessionBackend(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()

	ipam, err := NewIPAM("10.100.0.0/24")
	if err != nil {
		t.Fatalf("NewIPAM failed: %v", err)
	}

	sm := NewSessionManager(db, ipam)

	sID, _ := db.CreateServer(ctx, &models.Server{Name: "VPN Host", Host: "10.0.0.1"})
	tID1, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-1",
		PublicKey:     "tunnel-pubkey-1",
		PrivateKey:    "tunnel-privkey-1",
		Endpoint:      "10.0.0.1:51820",
	})
	tID2, _ := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:      sID,
		InterfaceName: "awg-be-2",
		PublicKey:     "tunnel-pubkey-2",
		PrivateKey:    "tunnel-privkey-2",
		Endpoint:      "10.0.0.1:51821",
	})
	uID, _ := db.CreateUser(ctx, &models.User{Username: "user1"})

	sess, err := sm.CreateSession(ctx, uID, "peer-key-1", "10.100.0.2", tID1, "conn-1")
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	v0 := sm.LifecycleVersion()

	// Update backend to tID2 and status to draining
	oldBackend, peerKey, oldStatus, err := sm.UpdateSessionBackend(sess.ID, tID2, "draining")
	if err != nil {
		t.Fatalf("UpdateSessionBackend failed: %v", err)
	}
	if oldBackend != tID1 {
		t.Errorf("expected oldBackend %d, got %d", tID1, oldBackend)
	}
	if peerKey != "peer-key-1" {
		t.Errorf("expected peerKey 'peer-key-1', got %s", peerKey)
	}
	if oldStatus != "connected" {
		t.Errorf("expected oldStatus 'connected', got %s", oldStatus)
	}
	if sm.LifecycleVersion() <= v0 {
		t.Errorf("expected lifecycle version to increase, v0=%d, now=%d", v0, sm.LifecycleVersion())
	}

	// Verify in-memory state after update
	snap, ok := sm.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("session %s not found", sess.ID)
	}
	if snap.BackendTunnelID != tID2 {
		t.Errorf("expected BackendTunnelID %d, got %d", tID2, snap.BackendTunnelID)
	}
	if snap.Status != "draining" {
		t.Errorf("expected Status 'draining', got %s", snap.Status)
	}

	v1 := sm.LifecycleVersion()

	// Rollback backend to tID1 and status to connected
	if err := sm.RollbackSessionBackend(sess.ID, oldBackend, oldStatus); err != nil {
		t.Fatalf("RollbackSessionBackend failed: %v", err)
	}
	if sm.LifecycleVersion() <= v1 {
		t.Errorf("expected lifecycle version to increase on rollback, v1=%d, now=%d", v1, sm.LifecycleVersion())
	}

	// Verify in-memory state after rollback
	snapRollback, ok := sm.GetSessionSnapshotByID(sess.ID)
	if !ok {
		t.Fatalf("session %s not found after rollback", sess.ID)
	}
	if snapRollback.BackendTunnelID != tID1 {
		t.Errorf("expected BackendTunnelID %d, got %d", tID1, snapRollback.BackendTunnelID)
	}
	if snapRollback.Status != "connected" {
		t.Errorf("expected Status 'connected', got %s", snapRollback.Status)
	}

	// Test non-existent session
	if _, _, _, err := sm.UpdateSessionBackend("non-existent-id", 200, "draining"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
	if err := sm.RollbackSessionBackend("non-existent-id", 101, "connected"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}

	// Test nil session manager
	var nilSM *SessionManager
	if _, _, _, err := nilSM.UpdateSessionBackend("id", 100, "draining"); err == nil {
		t.Error("expected error for nil SessionManager on UpdateSessionBackend")
	}
	if err := nilSM.RollbackSessionBackend("id", 100, "connected"); err == nil {
		t.Error("expected error for nil SessionManager on RollbackSessionBackend")
	}
}
