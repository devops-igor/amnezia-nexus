package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func setupResourceRBACClosure(t *testing.T) (*Handlers, *database.DB, int64) {
	t.Helper()
	h, db, _ := setupTestHandlers(t)
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		h.registry.Register(&mockProtocolManager{protocol: protocol})
	}
	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:    "resource-rbac-closure",
		Host:    "192.0.2.90",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			models.ProtocolAWG:   map[string]any{"installed": true},
			models.ProtocolVLESS: map[string]any{"installed": true},
			models.ProtocolNaive: map[string]any{"installed": true},
		},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return h, db, serverID
}

func resourceRBACRequest(
	t *testing.T,
	handler http.Handler,
	method, path string,
	sess *models.SessionData,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("Marshal request: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if sess != nil {
		req = req.WithContext(middleware.WithSession(req.Context(), sess))
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func resourceRBACSession(role models.UserRole) *models.SessionData {
	return &models.SessionData{UserID: "closure-" + string(role), Role: role}
}

func createResourceRBACConnection(
	t *testing.T,
	db *database.DB,
	id, userID string,
	serverID int64,
	protocol, clientID string,
) {
	t.Helper()
	_, err := db.CreateConnection(context.Background(), &models.UserConnection{
		ID:        id,
		UserID:    userID,
		ServerID:  serverID,
		Protocol:  protocol,
		ClientID:  clientID,
		Name:      id,
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("CreateConnection(%s): %v", id, err)
	}
}

func TestResourceRBACClosureAddUserInitialConnection(t *testing.T) {
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive, models.ProtocolAWG} {
		for _, role := range []models.UserRole{models.RoleSupport, models.RoleAdmin} {
			t.Run(fmt.Sprintf("%s/%s", protocol, role), func(t *testing.T) {
				h, db, serverID := setupResourceRBACClosure(t)
				username := fmt.Sprintf("new-%s-%s", protocol, role)
				w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodPost, "/api/users/add", resourceRBACSession(role), models.AddUserRequest{
					Username: username,
					Password: "ClosurePass123!",
					Role:     models.RoleUser,
					ServerID: &serverID,
					Protocol: &protocol,
				})

				want := http.StatusOK
				if role != models.RoleAdmin && protocol != models.ProtocolAWG {
					want = http.StatusForbidden
				}
				if w.Code != want {
					t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
				}
				user, err := db.GetUserByUsername(context.Background(), username)
				if want == http.StatusForbidden && (err == nil && user != nil) {
					t.Fatal("forbidden request created a user")
				}
				if want == http.StatusOK && (err != nil || user == nil) {
					t.Fatalf("allowed request did not create user: user=%v err=%v", user, err)
				}
			})
		}
	}
}

func TestResourceRBACClosureShare(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	shareToken := "closure-share-token"
	user := &models.User{
		ID:           "closure-share-user",
		Username:     "closure-share-user",
		Role:         models.RoleUser,
		Enabled:      true,
		ShareEnabled: true,
		ShareToken:   &shareToken,
		CreatedAt:    time.Now(),
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive, models.ProtocolAWG} {
		createResourceRBACConnection(t, db, "share-"+protocol, user.ID, serverID, protocol, protocol+"-secret")
	}
	router := setupFullShareRouter(h)

	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive, models.ProtocolAWG} {
		t.Run("config/"+protocol, func(t *testing.T) {
			path := fmt.Sprintf("/api/share/%s/config/share-%s", *user.ShareToken, protocol)
			w := resourceRBACRequest(t, router, http.MethodPost, path, nil, nil)
			want := http.StatusForbidden
			if protocol == models.ProtocolAWG {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
			}
		})
	}

	w := resourceRBACRequest(t, router, http.MethodGet, "/api/share/"+*user.ShareToken+"/connections", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d; body: %s", w.Code, w.Body.String())
	}
	var response struct {
		Connections []map[string]any `json:"connections"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode share list: %v", err)
	}
	for _, conn := range response.Connections {
		switch conn["protocol"] {
		case models.ProtocolVLESS:
			if conn["client_id"] != "" {
				t.Errorf("VLESS client_id = %v, want redacted", conn["client_id"])
			}
		case models.ProtocolAWG:
			if conn["client_id"] != "awg-secret" {
				t.Errorf("AWG client_id = %v, want unredacted", conn["client_id"])
			}
		}
	}
}

func TestResourceRBACClosureServerConnectionListings(t *testing.T) {
	h, _, serverID := setupResourceRBACClosure(t)
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		getClientsFn: func(context.Context, *models.Server) ([]map[string]any, error) {
			return []map[string]any{{
				"clientId":  "vless-secret",
				"client_id": "vless-secret",
				"uuid":      "vless-secret",
				"name":      "vless-secret",
				"userData":  map[string]any{"clientName": "vless-secret"},
			}}, nil
		},
	})
	router := setupFullServerConnectionsRouter(h)
	path := fmt.Sprintf("/api/servers/%d/connections?protocol=vless", serverID)

	for _, role := range []models.UserRole{models.RoleSupport, models.RoleAdmin} {
		t.Run("server connections/"+string(role), func(t *testing.T) {
			w := resourceRBACRequest(t, router, http.MethodGet, path, resourceRBACSession(role), nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
			var response struct {
				Clients []map[string]any `json:"clients"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode clients: %v", err)
			}
			if len(response.Clients) != 1 {
				t.Fatalf("clients = %d, want 1", len(response.Clients))
			}
			client := response.Clients[0]
			for _, key := range []string{"clientId", "client_id", "uuid"} {
				want := ""
				if role == models.RoleAdmin {
					want = "vless-secret"
				}
				if client[key] != want {
					t.Errorf("%s = %v, want %q", key, client[key], want)
				}
			}
			wantName := "Unnamed"
			if role == models.RoleAdmin {
				wantName = "vless-secret"
			} else if bytes.Contains(w.Body.Bytes(), []byte("vless-secret")) {
				t.Fatal("Support response contains VLESS authentication UUID")
			}
			if client["name"] != wantName {
				t.Errorf("name = %v, want %q", client["name"], wantName)
			}
			userData, ok := client["userData"].(map[string]any)
			if !ok || userData["clientName"] != wantName {
				t.Errorf("userData.clientName = %v, want %q", client["userData"], wantName)
			}
		})
	}

	t.Run("AWG remains unredacted for support", func(t *testing.T) {
		path := fmt.Sprintf("/api/servers/%d/connections?protocol=awg", serverID)
		w := resourceRBACRequest(t, router, http.MethodGet, path, resourceRBACSession(models.RoleSupport), nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
		}
		var response struct {
			Clients []map[string]any `json:"clients"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode AWG clients: %v", err)
		}
		if len(response.Clients) != 1 || response.Clients[0]["client_id"] != "client-1" {
			t.Fatalf("AWG clients = %#v, want unredacted client-1", response.Clients)
		}
	})
}

func TestResourceRBACClosureUserConnections(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	if _, err := db.CreateUser(context.Background(), &models.User{
		ID: "closure-user", Username: "closure-user", Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	createResourceRBACConnection(t, db, "user-vless", "closure-user", serverID, models.ProtocolVLESS, "vless-secret")
	createResourceRBACConnection(t, db, "user-awg", "closure-user", serverID, models.ProtocolAWG, "awg-secret")

	for _, role := range []models.UserRole{models.RoleSupport, models.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			w := resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodGet, "/api/users/closure-user/connections", resourceRBACSession(role), nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
			var response struct {
				Connections []map[string]any `json:"connections"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode connections: %v", err)
			}
			if len(response.Connections) != 2 {
				t.Fatalf("connections = %d, want 2", len(response.Connections))
			}
			for _, conn := range response.Connections {
				switch conn["protocol"] {
				case models.ProtocolVLESS:
					want := ""
					if role == models.RoleAdmin {
						want = "vless-secret"
					}
					if conn["client_id"] != want {
						t.Errorf("VLESS client_id = %v, want %q", conn["client_id"], want)
					}
				case models.ProtocolAWG:
					if conn["client_id"] != "awg-secret" {
						t.Errorf("AWG client_id = %v, want unredacted", conn["client_id"])
					}
				}
			}
		})
	}
}

func TestResourceRBACClosureProtocolClients(t *testing.T) {
	h, _, serverID := setupResourceRBACClosure(t)
	router := setupFullServerConnectionsRouter(h)

	for _, tc := range []struct {
		name     string
		protocol string
		role     models.UserRole
		want     int
	}{
		{name: "support VLESS forbidden", protocol: models.ProtocolVLESS, role: models.RoleSupport, want: http.StatusForbidden},
		{name: "admin VLESS allowed", protocol: models.ProtocolVLESS, role: models.RoleAdmin, want: http.StatusOK},
		{name: "support AWG allowed", protocol: models.ProtocolAWG, role: models.RoleSupport, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/api/servers/%d/%s/clients", serverID, tc.protocol)
			w := resourceRBACRequest(t, router, http.MethodGet, path, resourceRBACSession(tc.role), nil)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusOK {
				var response struct {
					Clients []map[string]any `json:"clients"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode clients: %v", err)
				}
				if len(response.Clients) != 1 || response.Clients[0]["id"] != "client-1" {
					t.Fatalf("clients = %#v, want unredacted client-1", response.Clients)
				}
			}
		})
	}
}

func TestResourceRBACClosureMyConnections(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
		sess := resourceRBACSession(role)
		if _, err := db.CreateUser(ctx, &models.User{
			ID: sess.UserID, Username: sess.UserID, Role: role, Enabled: true, CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser(%s): %v", role, err)
		}
		createResourceRBACConnection(t, db, "my-vless-"+string(role), sess.UserID, serverID, models.ProtocolVLESS, "vless-secret")
		createResourceRBACConnection(t, db, "my-awg-"+string(role), sess.UserID, serverID, models.ProtocolAWG, "awg-secret")

		t.Run(string(role), func(t *testing.T) {
			w := resourceRBACRequest(t, setupFullConnectionsRouter(h), http.MethodGet, "/api/my/connections", sess, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
			var response struct {
				Connections []map[string]any `json:"connections"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode connections: %v", err)
			}
			for _, conn := range response.Connections {
				switch conn["protocol"] {
				case models.ProtocolVLESS:
					if conn["client_id"] != "" {
						t.Errorf("VLESS client_id = %v, want redacted", conn["client_id"])
					}
				case models.ProtocolAWG:
					if conn["client_id"] != "awg-secret" {
						t.Errorf("AWG client_id = %v, want unredacted", conn["client_id"])
					}
				}
			}
		})
	}
}

func TestResourceRBACClosureBackup(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	if _, err := db.CreateUser(context.Background(), &models.User{
		ID: "closure-user", Username: "closure-user", Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	createResourceRBACConnection(t, db, "backup-vless", "closure-user", serverID, models.ProtocolVLESS, "vless-secret")
	createResourceRBACConnection(t, db, "backup-awg", "closure-user", serverID, models.ProtocolAWG, "awg-secret")

	for _, role := range []models.UserRole{models.RoleSupport, models.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			w := resourceRBACRequest(t, setupFullSettingsRouter(h), http.MethodGet, "/api/settings/backup/download", resourceRBACSession(role), nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
			var backup models.BackupData
			if err := json.Unmarshal(w.Body.Bytes(), &backup); err != nil {
				t.Fatalf("decode backup: %v", err)
			}
			for _, conn := range backup.UserConnections {
				switch conn["protocol"] {
				case models.ProtocolVLESS:
					want := ""
					if role == models.RoleAdmin {
						want = "vless-secret"
					}
					if conn["client_id"] != want {
						t.Errorf("VLESS client_id = %v, want %q", conn["client_id"], want)
					}
				case models.ProtocolAWG:
					if conn["client_id"] != "awg-secret" {
						t.Errorf("AWG client_id = %v, want unredacted", conn["client_id"])
					}
				}
			}
		})
	}
}

func TestResourceRBACClosureAssignedVLESSNameRedaction(t *testing.T) {
	h, db, serverID := setupResourceRBACClosure(t)
	ctx := context.Background()
	const credential = "7f2d1290-7953-4f69-a85e-363087c0f331"
	shareToken := "assigned-vless-share-token"
	user := &models.User{
		ID:           "assigned-vless-user",
		Username:     "assigned-vless-user",
		Role:         models.RoleUser,
		Enabled:      true,
		ShareEnabled: true,
		ShareToken:   &shareToken,
		CreatedAt:    time.Now(),
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.RecordPeerLifecycle(ctx, serverID, models.ProtocolVLESS, credential, credential, "", "active"); err != nil {
		t.Fatalf("RecordPeerLifecycle: %v", err)
	}
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		getClientsFn: func(context.Context, *models.Server) ([]map[string]any, error) {
			return []map[string]any{{
				"clientId":  credential,
				"client_id": credential,
				"uuid":      credential,
				"name":      credential,
				"userData":  map[string]any{"clientName": credential},
			}}, nil
		},
	})

	serverRouter := setupFullServerConnectionsRouter(h)
	serverRouter.Get("/{server_id}/connections", h.GetServerConnectionsHandler)
	editPath := fmt.Sprintf("/api/servers/%d/connections/edit", serverID)
	w := resourceRBACRequest(t, serverRouter, http.MethodPost, editPath, resourceRBACSession(models.RoleAdmin), models.EditConnectionRequest{
		Protocol: models.ProtocolVLESS,
		ClientID: credential,
		UserID:   &user.ID,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("edit status = %d; body: %s", w.Code, w.Body.String())
	}
	conn, err := db.GetConnectionByClientID(ctx, credential, serverID)
	if err != nil || conn == nil {
		t.Fatalf("GetConnectionByClientID: conn=%v err=%v", conn, err)
	}
	if conn.Name != "Unnamed" {
		t.Fatalf("persisted name = %q, want Unnamed", conn.Name)
	}

	// Exercise rows persisted before the writer fix, including embedded credentials.
	if _, err := db.UpdateConnection(ctx, conn.ID, map[string]any{"name": "device-" + credential}); err != nil {
		t.Fatalf("UpdateConnection: %v", err)
	}
	connectionsRouter := setupFullConnectionsRouter(h)
	connectionsRouter.Get("/api/connections/", h.UserGetMyConnectionsHandler)
	userSession := resourceRBACSession(models.RoleUser)
	userSession.UserID = user.ID
	adminSession := resourceRBACSession(models.RoleAdmin)
	adminSession.UserID = user.ID
	tests := []struct {
		name      string
		router    http.Handler
		path      string
		sess      *models.SessionData
		adminSess *models.SessionData
	}{
		{
			name: "server connections", router: serverRouter,
			path: fmt.Sprintf("/api/servers/%d/connections?protocol=vless", serverID),
			sess: resourceRBACSession(models.RoleSupport), adminSess: resourceRBACSession(models.RoleAdmin),
		},
		{
			name: "server connections alias", router: serverRouter,
			path: fmt.Sprintf("/%d/connections?protocol=vless", serverID),
			sess: resourceRBACSession(models.RoleSupport), adminSess: resourceRBACSession(models.RoleAdmin),
		},
		{
			name: "staff user connections", router: setupFullUsersRouter(h),
			path: "/api/users/" + user.ID + "/connections",
			sess: resourceRBACSession(models.RoleSupport), adminSess: resourceRBACSession(models.RoleAdmin),
		},
		{
			name: "self connections", router: connectionsRouter, path: "/api/connections/",
			sess: userSession, adminSess: adminSession,
		},
		{
			name: "public share", router: setupFullShareRouter(h),
			path: "/api/share/" + shareToken + "/connections",
		},
		{
			name: "backup", router: setupFullSettingsRouter(h), path: "/api/settings/backup/download",
			sess: resourceRBACSession(models.RoleSupport), adminSess: resourceRBACSession(models.RoleAdmin),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checks := []struct {
				name           string
				sess           *models.SessionData
				wantCredential bool
			}{{name: "redacted", sess: tc.sess}}
			if tc.adminSess != nil {
				checks = append(checks, struct {
					name           string
					sess           *models.SessionData
					wantCredential bool
				}{name: "admin", sess: tc.adminSess, wantCredential: true})
			}
			for _, check := range checks {
				w := resourceRBACRequest(t, tc.router, http.MethodGet, tc.path, check.sess, nil)
				if w.Code != http.StatusOK {
					t.Fatalf("%s status = %d; body: %s", check.name, w.Code, w.Body.String())
				}
				if got := strings.Contains(w.Body.String(), credential); got != check.wantCredential {
					t.Errorf("%s credential presence = %v, want %v; body: %s", check.name, got, check.wantCredential, w.Body.String())
				}
			}
		})
	}

	if _, err := db.UpdateConnection(ctx, conn.ID, map[string]any{"name": "My Phone"}); err != nil {
		t.Fatalf("UpdateConnection friendly name: %v", err)
	}
	w = resourceRBACRequest(t, setupFullUsersRouter(h), http.MethodGet, "/api/users/"+user.ID+"/connections", resourceRBACSession(models.RoleSupport), nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"My Phone"`) {
		t.Errorf("friendly name was not preserved: status=%d body=%s", w.Code, w.Body.String())
	}
}
