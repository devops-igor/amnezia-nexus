package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
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

func TestUpdateUserHandlerProtectedProtocolAccessPolicy(t *testing.T) {
	expiry := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	expiryStr := expiry.Format(time.RFC3339)
	for _, tc := range []struct {
		name     string
		method   string
		protocol string
		role     models.UserRole
		body     map[string]any
		want     int
	}{
		{"support POST expires_at VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleSupport, map[string]any{"expires_at": expiryStr}, http.StatusForbidden},
		{"support POST expiration_date VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleSupport, map[string]any{"expiration_date": expiryStr}, http.StatusForbidden},
		{"support PATCH expires_at VLESS", http.MethodPatch, models.ProtocolVLESS, models.RoleSupport, map[string]any{"expires_at": expiryStr}, http.StatusForbidden},
		{"support PATCH expiration_date VLESS", http.MethodPatch, models.ProtocolVLESS, models.RoleSupport, map[string]any{"expiration_date": expiryStr}, http.StatusForbidden},
		{"support traffic_limit VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleSupport, map[string]any{"traffic_limit": 5}, http.StatusForbidden},
		{"support POST traffic_reset_strategy VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleSupport, map[string]any{"traffic_reset_strategy": "monthly"}, http.StatusForbidden},
		{"support PATCH traffic_reset_strategy VLESS", http.MethodPatch, models.ProtocolVLESS, models.RoleSupport, map[string]any{"traffic_reset_strategy": "monthly"}, http.StatusForbidden},
		{"support traffic_reset_strategy Naive", http.MethodPost, models.ProtocolNaive, models.RoleSupport, map[string]any{"traffic_reset_strategy": "monthly"}, http.StatusForbidden},
		{"admin traffic_reset_strategy VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleAdmin, map[string]any{"traffic_reset_strategy": "monthly"}, http.StatusOK},
		{"support traffic_reset_strategy AWG", http.MethodPost, models.ProtocolAWG, models.RoleSupport, map[string]any{"traffic_reset_strategy": "monthly"}, http.StatusOK},
		{"support expires_at Naive", http.MethodPost, models.ProtocolNaive, models.RoleSupport, map[string]any{"expires_at": expiryStr}, http.StatusForbidden},
		{"support mixed fields VLESS rejected entirely", http.MethodPost, models.ProtocolVLESS, models.RoleSupport, map[string]any{"expires_at": expiryStr, "description": "mixed"}, http.StatusForbidden},
		{"admin expires_at VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleAdmin, map[string]any{"expires_at": expiryStr}, http.StatusOK},
		{"support description VLESS", http.MethodPost, models.ProtocolVLESS, models.RoleSupport, map[string]any{"description": "note"}, http.StatusOK},
		{"support expires_at AWG", http.MethodPost, models.ProtocolAWG, models.RoleSupport, map[string]any{"expires_at": expiryStr}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, serverID := setupResourceRBACClosure(t)
			ctx := context.Background()
			const userID = "protected-update-user"
			const connectionID = "protected-update-connection"
			lastResetAt := "2000-01-01T00:00:00Z"
			if _, err := db.CreateUser(ctx, &models.User{
				ID: userID, Username: userID, Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
				TrafficResetStrategy: models.ResetStrategyNever, LastResetAt: &lastResetAt,
			}); err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			createResourceRBACConnection(t, db, connectionID, userID, serverID, tc.protocol, "update-client")

			router := chi.NewRouter()
			router.Post("/api/users/{user_id}/update", h.UpdateUserHandler)
			router.Patch("/api/users/{user_id}", h.UpdateUserHandler)
			path := "/api/users/" + userID
			if tc.method == http.MethodPost {
				path += "/update"
			}
			w := resourceRBACRequest(t, router, tc.method, path, resourceRBACSession(tc.role), tc.body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.want, w.Body.String())
			}

			user, userErr := db.GetUser(ctx, userID)
			conn, connErr := db.GetConnection(ctx, connectionID)
			if userErr != nil || connErr != nil || user == nil || conn == nil {
				t.Fatalf("read state: user=%v (%v) connection=%v (%v)", user, userErr, conn, connErr)
			}
			if tc.want == http.StatusForbidden {
				if !strings.Contains(w.Body.String(), "forbidden") {
					t.Errorf("response does not contain forbidden error: %s", w.Body.String())
				}
				if user.ExpiresAt != nil || user.ExpirationDate != nil || user.TrafficLimit != 0 || user.Description != nil {
					t.Fatalf("forbidden update changed user: %+v", user)
				}
				if user.TrafficResetStrategy != models.ResetStrategyNever || user.LastResetAt == nil || *user.LastResetAt != lastResetAt {
					t.Fatalf("forbidden update changed reset policy: strategy=%q last_reset_at=%v", user.TrafficResetStrategy, user.LastResetAt)
				}
				return
			}
			if _, ok := tc.body["traffic_reset_strategy"]; ok {
				if user.TrafficResetStrategy != models.ResetStrategyMonthly {
					t.Fatalf("traffic_reset_strategy = %q, want monthly", user.TrafficResetStrategy)
				}
			}
			if _, ok := tc.body["expires_at"]; ok {
				if user.ExpiresAt == nil || !user.ExpiresAt.Equal(expiry) {
					t.Fatalf("expires_at = %v, want %v", user.ExpiresAt, expiry)
				}
			}
			if _, ok := tc.body["description"]; ok {
				if user.Description == nil || *user.Description != "note" {
					t.Fatalf("description = %v, want note", user.Description)
				}
			}
		})
	}
}

func TestRestoreBackupHandlerRequiresAdmin(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       models.UserRole
		wantStatus int
		wantUsers  int
		wantConns  int
	}{
		{name: "support forbidden without restoring", role: models.RoleSupport, wantStatus: http.StatusForbidden},
		{name: "admin allowed", role: models.RoleAdmin, wantStatus: http.StatusOK, wantUsers: 1, wantConns: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, serverID := setupResourceRBACClosure(t)
			backup := models.BackupData{
				Users: []map[string]any{{
					"id": "restore-admin-user", "username": "restore-admin-user",
					"role": models.RoleAdmin, "enabled": true,
				}},
				UserConnections: []map[string]any{{
					"id": "restore-admin-connection", "user_id": "restore-admin-user",
					"server_id": serverID, "protocol": models.ProtocolVLESS,
					"client_id": "restore-admin-client", "name": "restore-admin-connection",
				}},
			}

			w := resourceRBACRequest(t, setupFullSettingsRouter(h), http.MethodPost,
				"/api/settings/backup/restore", resourceRBACSession(tc.role), backup)
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus == http.StatusForbidden && !strings.Contains(w.Body.String(), "forbidden") {
				t.Errorf("response does not contain forbidden error: %s", w.Body.String())
			}

			users, err := db.GetAllUsers(context.Background())
			if err != nil {
				t.Fatalf("GetAllUsers: %v", err)
			}
			connections, err := db.GetAllConnections(context.Background())
			if err != nil {
				t.Fatalf("GetAllConnections: %v", err)
			}
			if len(users) != tc.wantUsers || len(connections) != tc.wantConns {
				t.Fatalf("restored state: users=%d want %d, connections=%d want %d",
					len(users), tc.wantUsers, len(connections), tc.wantConns)
			}
		})
	}
}
