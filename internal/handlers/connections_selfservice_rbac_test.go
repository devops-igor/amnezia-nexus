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

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestSelfServiceConnectionProtocolRBAC(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		h.registry.Register(&mockProtocolManager{protocol: protocol})
	}
	ctx := context.Background()
	users := map[models.UserRole]*models.User{
		models.RoleUser:    {ID: "self-user", Username: "self-user", Role: models.RoleUser, Enabled: true},
		models.RoleSupport: {ID: "self-support", Username: "self-support", Role: models.RoleSupport, Enabled: true},
		models.RoleAdmin:   {ID: "self-admin", Username: "self-admin", Role: models.RoleAdmin, Enabled: true},
	}
	for _, user := range users {
		if _, err := db.CreateUser(ctx, user); err != nil {
			t.Fatalf("CreateUser(%s): %v", user.Role, err)
		}
	}
	if err := db.SetSetting(ctx, "limits", models.ConnectionLimits{
		MaxConnectionsPerUser:     100,
		ConnectionRateLimitCount:  100,
		ConnectionRateLimitWindow: 3600,
	}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	serverID, err := db.CreateServer(ctx, &models.Server{
		Name:    "self-service-rbac",
		Host:    "192.0.2.61",
		SSHUser: "ubuntu",
		Protocols: map[string]any{
			models.ProtocolAWG:   map[string]any{"installed": true},
			models.ProtocolVLESS: map[string]any{"installed": true},
			models.ProtocolNaive: map[string]any{"installed": true},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline); err != nil {
		t.Fatalf("UpdateServerReachability: %v", err)
	}

	router := chi.NewRouter()
	router.Post("/api/connections/add", h.UserAddConnectionHandler)
	router.Post("/api/my/connections/add", h.UserAddConnectionHandler)
	router.Get("/api/connections/{connection_id}/config", h.UserGetConnectionConfigHandler)
	router.Post("/api/connections/{connection_id}/delete", h.UserDeleteConnectionHandler)

	request := func(method, path string, role models.UserRole, body any) *httptest.ResponseRecorder {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(payload))
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: users[role].ID,
			Role:   role,
		}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	seed := func(protocol, suffix string) *models.UserConnection {
		t.Helper()
		clientID := "client-1" // present in the mocked AWG clients table
		if strings.HasSuffix(suffix, "delete") {
			clientID = fmt.Sprintf("client-%s-%s", protocol, suffix)
		}
		conn := &models.UserConnection{
			ID:        fmt.Sprintf("rbac-%s-%s", protocol, suffix),
			UserID:    users[models.RoleUser].ID,
			ServerID:  serverID,
			Protocol:  protocol,
			ClientID:  clientID,
			Name:      fmt.Sprintf("rbac-%s-%s", protocol, suffix),
			CreatedAt: time.Now(),
		}
		if _, err := db.CreateConnection(ctx, conn); err != nil {
			t.Fatalf("CreateConnection: %v", err)
		}
		return conn
	}
	assertForbidden := func(w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
		}
		var response map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode forbidden response: %v", err)
		}
		if response["error"] != "forbidden" {
			t.Errorf("error = %v, want forbidden", response["error"])
		}
	}

	addCases := []struct {
		name     string
		protocol string
		path     string
	}{
		{name: "vless canonical", protocol: models.ProtocolVLESS, path: "/api/connections/add"},
		{name: "naive canonical", protocol: models.ProtocolNaive, path: "/api/connections/add"},
		{name: "vless legacy alias", protocol: "vless-reality", path: "/api/my/connections/add"},
		{name: "naive legacy alias", protocol: "naiveproxy", path: "/api/my/connections/add"},
	}
	for _, tc := range addCases {
		for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
			t.Run(fmt.Sprintf("add %s %s", tc.name, role), func(t *testing.T) {
				w := request(http.MethodPost, tc.path, role, models.MyAddConnectionRequest{
					ServerID: serverID,
					Protocol: tc.protocol,
					Name:     fmt.Sprintf("denied-%s-%s", tc.protocol, role),
				})
				assertForbidden(w)
			})
		}
	}

	for _, protocol := range []string{models.ProtocolVLESS, "vless-reality", models.ProtocolNaive, "naiveproxy"} {
		for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
			t.Run(fmt.Sprintf("config and delete %s %s", protocol, role), func(t *testing.T) {
				conn := seed(protocol, string(role))
				assertForbidden(request(http.MethodGet, fmt.Sprintf("/api/connections/%s/config", conn.ID), role, nil))
				assertForbidden(request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", conn.ID), role, nil))
				remaining, err := db.GetConnection(ctx, conn.ID)
				if err != nil || remaining == nil {
					t.Errorf("forbidden delete removed connection: remaining=%v err=%v", remaining, err)
				}
			})
		}
	}

	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run("admin add "+protocol, func(t *testing.T) {
			w := request(http.MethodPost, "/api/connections/add", models.RoleAdmin, models.MyAddConnectionRequest{
				ServerID: serverID,
				Protocol: protocol,
				Name:     "admin-add-" + protocol,
			})
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
		})
		t.Run("admin config and delete "+protocol, func(t *testing.T) {
			configConn := seed(protocol, "admin-config")
			w := request(http.MethodGet, fmt.Sprintf("/api/connections/%s/config", configConn.ID), models.RoleAdmin, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			deleteConn := seed(protocol, "admin-delete")
			w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", deleteConn.ID), models.RoleAdmin, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("delete status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			remaining, err := db.GetConnection(ctx, deleteConn.ID)
			if err != nil || remaining != nil {
				t.Errorf("admin delete did not remove connection: remaining=%v err=%v", remaining, err)
			}
		})
	}

	for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
		t.Run("AWG remains available to "+string(role), func(t *testing.T) {
			w := request(http.MethodPost, "/api/connections/add", role, models.MyAddConnectionRequest{
				ServerID: serverID,
				Protocol: models.ProtocolAWG,
				Name:     "awg-add-" + string(role),
			})
			if w.Code != http.StatusOK {
				t.Fatalf("add status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			configConn := seed(models.ProtocolAWG, string(role)+"-config")
			w = request(http.MethodGet, fmt.Sprintf("/api/connections/%s/config", configConn.ID), role, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			deleteConn := seed(models.ProtocolAWG, string(role)+"-delete")
			w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", deleteConn.ID), role, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("delete status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
		})
	}
}
