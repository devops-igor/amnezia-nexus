package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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

func TestDeleteUserHandlerProtectedProtocolAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		role     models.UserRole
		want     int
	}{
		{name: "support VLESS forbidden", protocol: models.ProtocolVLESS, role: models.RoleSupport, want: http.StatusForbidden},
		{name: "support Naive forbidden", protocol: models.ProtocolNaive, role: models.RoleSupport, want: http.StatusForbidden},
		{name: "admin VLESS allowed", protocol: models.ProtocolVLESS, role: models.RoleAdmin, want: http.StatusOK},
		{name: "support AWG allowed", protocol: models.ProtocolAWG, role: models.RoleSupport, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, serverID := setupResourceRBACClosure(t)
			ctx := context.Background()
			const userID = "protected-delete-user"
			const connectionID = "protected-delete-connection"
			if _, err := db.CreateUser(ctx, &models.User{
				ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			createResourceRBACConnection(t, db, connectionID, userID, serverID, tc.protocol, "delete-client")

			var removals []string
			h.registry.Register(&mockProtocolManager{
				protocol: tc.protocol,
				removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
					removals = append(removals, clientID)
					return nil
				},
			})

			w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodPost,
				"/api/users/"+userID+"/delete", resourceRBACSession(tc.role), nil)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.want, w.Body.String())
			}
			user, userErr := db.GetUser(ctx, userID)
			conn, connErr := db.GetConnection(ctx, connectionID)
			if userErr != nil || connErr != nil {
				t.Fatalf("read state: user err=%v connection err=%v", userErr, connErr)
			}
			if tc.want == http.StatusForbidden {
				if !strings.Contains(w.Body.String(), "forbidden") {
					t.Errorf("response does not contain forbidden error: %s", w.Body.String())
				}
				if user == nil || conn == nil {
					t.Fatalf("forbidden deletion changed state: user=%v connection=%v", user, conn)
				}
				if len(removals) != 0 {
					t.Fatalf("forbidden deletion made RemoveClient calls: %v", removals)
				}
				return
			}
			if user != nil || conn != nil {
				t.Fatalf("allowed deletion left state behind: user=%v connection=%v", user, conn)
			}
			if len(removals) != 1 || removals[0] != "delete-client" {
				t.Fatalf("RemoveClient calls = %v, want [delete-client]", removals)
			}
		})
	}
}

func TestToggleUserHandlerProtectedProtocolAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		role     models.UserRole
		want     int
	}{
		{name: "support VLESS forbidden", protocol: models.ProtocolVLESS, role: models.RoleSupport, want: http.StatusForbidden},
		{name: "support Naive forbidden", protocol: models.ProtocolNaive, role: models.RoleSupport, want: http.StatusForbidden},
		{name: "admin VLESS allowed", protocol: models.ProtocolVLESS, role: models.RoleAdmin, want: http.StatusOK},
		{name: "support AWG allowed", protocol: models.ProtocolAWG, role: models.RoleSupport, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, serverID := setupResourceRBACClosure(t)
			ctx := context.Background()
			const userID = "protected-toggle-user"
			const connectionID = "protected-toggle-connection"
			if _, err := db.CreateUser(ctx, &models.User{
				ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			createResourceRBACConnection(t, db, connectionID, userID, serverID, tc.protocol, "toggle-client")

			var removals []string
			h.registry.Register(&mockProtocolManager{
				protocol: tc.protocol,
				removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
					removals = append(removals, clientID)
					return nil
				},
			})

			w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodPost,
				"/api/users/"+userID+"/toggle", resourceRBACSession(tc.role), models.ToggleUserRequest{Enabled: false})
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.want, w.Body.String())
			}
			user, userErr := db.GetUser(ctx, userID)
			conn, connErr := db.GetConnection(ctx, connectionID)
			if userErr != nil || connErr != nil {
				t.Fatalf("read state: user err=%v connection err=%v", userErr, connErr)
			}
			if user == nil {
				t.Fatal("toggle deleted the user")
			}
			if tc.want == http.StatusForbidden {
				if !strings.Contains(w.Body.String(), "forbidden") {
					t.Errorf("response does not contain forbidden error: %s", w.Body.String())
				}
				if !user.Enabled || conn == nil {
					t.Fatalf("forbidden disable changed state: enabled=%v connection=%v", user.Enabled, conn)
				}
				if len(removals) != 0 {
					t.Fatalf("forbidden disable made RemoveClient calls: %v", removals)
				}
				return
			}
			if user.Enabled {
				t.Fatal("allowed disable left user enabled")
			}
			if tc.protocol == models.ProtocolAWG {
				if conn == nil {
					t.Fatal("AWG disable deleted the connection")
				}
				if len(removals) != 0 {
					t.Fatalf("AWG disable made RemoveClient calls: %v", removals)
				}
				return
			}
			if conn != nil {
				t.Fatal("admin disable left protected connection behind")
			}
			if len(removals) != 1 || removals[0] != "toggle-client" {
				t.Fatalf("RemoveClient calls = %v, want [toggle-client]", removals)
			}
		})
	}
}
