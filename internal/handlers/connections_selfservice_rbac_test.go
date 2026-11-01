package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestSelfServiceConnectionProtocolRBAC(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	var removeCalls atomic.Int64
	for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		p := protocol
		h.registry.Register(&mockProtocolManager{
			protocol: p,
			removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
				removeCalls.Add(1)
				return nil
			},
		})
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
	userB := &models.User{ID: "self-user-b", Username: "self-user-b", Role: models.RoleUser, Enabled: true}
	if _, err := db.CreateUser(ctx, userB); err != nil {
		t.Fatalf("CreateUser(userB): %v", err)
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

	request := func(method, path string, user *models.User, body any) *httptest.ResponseRecorder {
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
			UserID: user.ID,
			Role:   user.Role,
		}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	seedForUser := func(ownerID, protocol, suffix string) *models.UserConnection {
		t.Helper()
		clientID := "client-1" // present in mocked AWG clients table
		if strings.HasSuffix(suffix, "delete") || protocol != models.ProtocolAWG {
			clientID = fmt.Sprintf("client-%s-%s-%d", protocol, suffix, time.Now().UnixNano())
		}
		conn := &models.UserConnection{
			ID:        fmt.Sprintf("rbac-%s-%s-%d", protocol, suffix, time.Now().UnixNano()),
			UserID:    ownerID,
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

	// 1. Self-service add connections for regular user, support, and admin
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
		for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport, models.RoleAdmin} {
			t.Run(fmt.Sprintf("add %s %s", tc.name, role), func(t *testing.T) {
				w := request(http.MethodPost, tc.path, users[role], models.MyAddConnectionRequest{
					ServerID: serverID,
					Protocol: tc.protocol,
					Name:     fmt.Sprintf("ok-%s-%s", tc.protocol, role),
				})
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
				}
				var resp map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("Unmarshal add response: %v", err)
				}
				if resp["status"] != "ok" {
					t.Errorf("status = %v, want ok", resp["status"])
				}
				if cfg, _ := resp["config"].(string); cfg == "" {
					t.Errorf("expected non-empty config in add response")
				}
			})
		}
	}

	// 2. Self-service config retrieval and deletion for owned connections
	for _, protocol := range []string{models.ProtocolVLESS, "vless-reality", models.ProtocolNaive, "naiveproxy"} {
		for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport, models.RoleAdmin} {
			t.Run(fmt.Sprintf("config and delete %s %s", protocol, role), func(t *testing.T) {
				user := users[role]
				conn := seedForUser(user.ID, protocol, string(role)+"-lifecycle")

				// Get config succeeds
				w := request(http.MethodGet, fmt.Sprintf("/api/connections/%s/config", conn.ID), user, nil)
				if w.Code != http.StatusOK {
					t.Fatalf("config status = %d, want 200; body: %s", w.Code, w.Body.String())
				}
				var cfgResp map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &cfgResp); err != nil {
					t.Fatalf("Unmarshal config response: %v", err)
				}
				if cfg, _ := cfgResp["config"].(string); cfg == "" {
					t.Errorf("expected non-empty config in config response")
				}

				// Delete succeeds and cleans database
				deleteConn := seedForUser(user.ID, protocol, string(role)+"-delete")
				w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", deleteConn.ID), user, nil)
				if w.Code != http.StatusOK {
					t.Fatalf("delete status = %d, want 200; body: %s", w.Code, w.Body.String())
				}
				remaining, err := db.GetConnection(ctx, deleteConn.ID)
				if err != nil || remaining != nil {
					t.Errorf("delete did not remove connection from db: remaining=%v err=%v", remaining, err)
				}
			})
		}
	}

	// 3. Cross-user tenant isolation
	t.Run("cross-user tenant isolation", func(t *testing.T) {
		for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
			userA := users[models.RoleUser]
			nonOwners := []*models.User{userB, users[models.RoleSupport]}
			for _, nonOwner := range nonOwners {
				connA := seedForUser(userA.ID, protocol, "isolation-owner-"+string(nonOwner.Role))
				removesBefore := removeCalls.Load()

				// Non-owner attempts to retrieve User A's config -> 404
				w := request(http.MethodGet, fmt.Sprintf("/api/connections/%s/config", connA.ID), nonOwner, nil)
				if w.Code != http.StatusNotFound {
					t.Errorf("%s cross-user config status = %d, want 404; body: %s", nonOwner.Role, w.Code, w.Body.String())
				}
				var cfgErr map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &cfgErr); err != nil {
					t.Errorf("Unmarshal %s cross-user config error: %v", nonOwner.Role, err)
				} else if cfgErr["error"] != "not_found" {
					t.Errorf("%s cross-user config error = %v, want not_found", nonOwner.Role, cfgErr["error"])
				}

				// Non-owner attempts to delete User A's connection -> 404
				w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", connA.ID), nonOwner, nil)
				if w.Code != http.StatusNotFound {
					t.Errorf("%s cross-user delete status = %d, want 404; body: %s", nonOwner.Role, w.Code, w.Body.String())
				}
				var delErr map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &delErr); err != nil {
					t.Errorf("Unmarshal %s cross-user delete error: %v", nonOwner.Role, err)
				} else if delErr["error"] != "not_found" {
					t.Errorf("%s cross-user delete error = %v, want not_found", nonOwner.Role, delErr["error"])
				}

				// Verify connection row is untouched
				remaining, err := db.GetConnection(ctx, connA.ID)
				if err != nil || remaining == nil {
					t.Errorf("%s cross-user delete removed connection: remaining=%v err=%v", nonOwner.Role, remaining, err)
				}

				// Verify zero remote removals were invoked
				if removesAfter := removeCalls.Load(); removesAfter != removesBefore {
					t.Errorf("%s cross-user delete invoked remote removal: calls before=%d after=%d", nonOwner.Role, removesBefore, removesAfter)
				}
			}
		}
	})

	// 4. Connection limits and quota enforcement
	t.Run("quota and connection limits enforcement", func(t *testing.T) {
		limitUser := &models.User{
			ID: "quota-user", Username: "quota-user", Role: models.RoleUser, Enabled: true,
			Limits: map[string]any{"max_connections_per_user": float64(1)},
		}
		if _, err := db.CreateUser(ctx, limitUser); err != nil {
			t.Fatalf("CreateUser(quota-user): %v", err)
		}

		// First connection succeeds
		w := request(http.MethodPost, "/api/connections/add", limitUser, models.MyAddConnectionRequest{
			ServerID: serverID,
			Protocol: models.ProtocolVLESS,
			Name:     "quota-conn-1",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("first connection status = %d, want 200; body: %s", w.Code, w.Body.String())
		}

		// Second connection fails due to limit reached (HTTP 428 Precondition Required)
		w = request(http.MethodPost, "/api/connections/add", limitUser, models.MyAddConnectionRequest{
			ServerID: serverID,
			Protocol: models.ProtocolNaive,
			Name:     "quota-conn-2",
		})
		if w.Code != http.StatusPreconditionRequired {
			t.Fatalf("second connection status = %d, want 428; body: %s", w.Code, w.Body.String())
		}
		var errResp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("Unmarshal limit response: %v", err)
		}
		if errResp["error"] != "max_connections_reached" {
			t.Errorf("error = %v, want max_connections_reached", errResp["error"])
		}
	})

	// 5. AWG protocol regression verification
	for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
		t.Run("AWG remains available to "+string(role), func(t *testing.T) {
			user := users[role]
			w := request(http.MethodPost, "/api/connections/add", user, models.MyAddConnectionRequest{
				ServerID: serverID,
				Protocol: models.ProtocolAWG,
				Name:     "awg-add-" + string(role),
			})
			if w.Code != http.StatusOK {
				t.Fatalf("add status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			configConn := seedForUser(user.ID, models.ProtocolAWG, string(role)+"-config")
			w = request(http.MethodGet, fmt.Sprintf("/api/connections/%s/config", configConn.ID), user, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			deleteConn := seedForUser(user.ID, models.ProtocolAWG, string(role)+"-delete")
			w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", deleteConn.ID), user, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("delete status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
		})
	}
}
