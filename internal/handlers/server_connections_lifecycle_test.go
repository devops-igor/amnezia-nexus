package handlers

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRemoveServerConnectionHandlerUsesCanonicalClientID(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	userID := "canonical-remove-user"
	if _, err := db.CreateUser(ctx, &models.User{
		ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	const rowID = "canonical-remove-row"
	const clientID = "5e7a2e9d-96b2-4f1f-b0f4-8631e0d62ee2"
	createResourceRBACConnection(t, db, rowID, userID, serverID, models.ProtocolVLESS, clientID)

	var removedClientID string
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		removeClientFn: func(_ context.Context, _ *models.Server, id string) error {
			removedClientID = id
			return nil
		},
	})

	path := fmt.Sprintf("/api/servers/%d/connections/remove", serverID)
	w := resourceRBACRequest(t, setupFullServerConnectionsRouter(h), http.MethodPost, path,
		resourceRBACSession(models.RoleAdmin), models.ConnectionActionRequest{
			Protocol: models.ProtocolVLESS,
			ClientID: rowID,
		})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if removedClientID != clientID {
		t.Fatalf("RemoveClient client ID = %q, want canonical %q", removedClientID, clientID)
	}
	conn, err := db.GetConnection(ctx, rowID)
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if conn != nil {
		t.Fatalf("database row %q was not deleted", rowID)
	}
}

func TestConnectionTransferAndUserDeletionPreserveTransferredConnection(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	const sourceUserID = "lifecycle-user-a"
	const destUserID = "lifecycle-user-b"
	for _, userID := range []string{sourceUserID, destUserID} {
		if _, err := db.CreateUser(ctx, &models.User{
			ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser(%s): %v", userID, err)
		}
	}
	const rowID = "lifecycle-transfer-row"
	createResourceRBACConnection(t, db, rowID, sourceUserID, serverID, models.ProtocolVLESS, "lifecycle-client")

	remoteRemovals := make(chan string, 1)
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		removeClientFn: func(_ context.Context, _ *models.Server, id string) error {
			remoteRemovals <- id
			return nil
		},
	})

	unlockDest := h.lockUser(destUserID)
	destLocked := true
	defer func() {
		if destLocked {
			unlockDest()
		}
	}()

	editDone := make(chan int, 1)
	transferUserID := destUserID
	go func() {
		path := fmt.Sprintf("/api/servers/%d/connections/edit", serverID)
		w := resourceRBACRequest(t, setupFullServerConnectionsRouter(h), http.MethodPost, path,
			resourceRBACSession(models.RoleAdmin), models.EditConnectionRequest{
				Protocol: models.ProtocolVLESS,
				ClientID: "lifecycle-client",
				UserID:   &transferUserID,
			})
		editDone <- w.Code
	}()

	// The transfer holds the source lock while waiting for the destination lock.
	time.Sleep(100 * time.Millisecond)
	deleteDone := make(chan int, 1)
	go func() {
		w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodPost,
			"/api/users/"+sourceUserID+"/delete", resourceRBACSession(models.RoleAdmin), nil)
		deleteDone <- w.Code
	}()

	select {
	case code := <-deleteDone:
		t.Fatalf("source deletion completed during transfer with status %d", code)
	case <-time.After(100 * time.Millisecond):
	}
	unlockDest()
	destLocked = false

	select {
	case code := <-editDone:
		if code != http.StatusOK {
			t.Fatalf("transfer status = %d, want 200", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transfer did not complete")
	}
	select {
	case code := <-deleteDone:
		if code != http.StatusOK {
			t.Fatalf("source deletion status = %d, want 200", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("source deletion did not complete")
	}

	conn, err := db.GetConnection(ctx, rowID)
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if conn == nil || conn.UserID != destUserID {
		t.Fatalf("transferred connection = %+v, want owner %q", conn, destUserID)
	}
	select {
	case id := <-remoteRemovals:
		t.Fatalf("transferred client %q was remotely revoked", id)
	default:
	}
}
