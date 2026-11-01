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
	router.Post("/api/connections/{connection_id}/config", h.UserGetConnectionConfigHandler)
	router.Post("/api/my/connections/{connection_id}/config", h.UserGetConnectionConfigHandler)
	router.Post("/api/connections/{connection_id}/rename", h.UserRenameConnectionHandler)
	router.Post("/api/connections/{connection_id}/delete", h.UserDeleteConnectionHandler)
	router.Post("/api/users/{user_id}/share/setup", h.SetupUserShareHandler)
	router.Get("/api/users", h.ListUsersHandler)
	router.Get("/api/settings/backup/download", h.DownloadBackupHandler)
	router.Get("/api/share/{token}/connections", h.GetShareConnectionsHandler)
	router.Post("/api/share/{token}/config/{connection_id}", h.GetShareConnectionConfigHandler)

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
		if user != nil {
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID: user.ID,
				Role:   user.Role,
			}))
		}
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

	// 1. Connection creation protocol RBAC (F1: VLESS is admin-only; Naive is self-service)
	addCases := []struct {
		name     string
		protocol string
		path     string
		isVLESS  bool
	}{
		{name: "vless canonical", protocol: models.ProtocolVLESS, path: "/api/connections/add", isVLESS: true},
		{name: "naive canonical", protocol: models.ProtocolNaive, path: "/api/connections/add", isVLESS: false},
		{name: "vless legacy alias", protocol: "vless-reality", path: "/api/my/connections/add", isVLESS: true},
		{name: "naive legacy alias", protocol: "naiveproxy", path: "/api/my/connections/add", isVLESS: false},
	}
	for _, tc := range addCases {
		for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport, models.RoleAdmin} {
			t.Run(fmt.Sprintf("add %s %s", tc.name, role), func(t *testing.T) {
				w := request(http.MethodPost, tc.path, users[role], models.MyAddConnectionRequest{
					ServerID: serverID,
					Protocol: tc.protocol,
					Name:     fmt.Sprintf("ok-%s-%s", tc.protocol, role),
				})
				if tc.isVLESS && role != models.RoleAdmin {
					if w.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want 403; body: %s", w.Code, w.Body.String())
					}
					var resp map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
						t.Fatalf("Unmarshal add response: %v", err)
					}
					if resp["error"] != "forbidden" {
						t.Errorf("error = %v, want forbidden", resp["error"])
					}
					return
				}
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

	// 2. Config retrieval and deletion for owned connections
	for _, protocol := range []string{models.ProtocolVLESS, "vless-reality", models.ProtocolNaive, "naiveproxy"} {
		isVLESS := models.NormalizeProtocol(protocol) == models.ProtocolVLESS
		for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport, models.RoleAdmin} {
			t.Run(fmt.Sprintf("config and delete %s %s", protocol, role), func(t *testing.T) {
				user := users[role]
				conn := seedForUser(user.ID, protocol, string(role)+"-lifecycle")

				// Get config succeeds via POST (F4: production router uses POST)
				w := request(http.MethodPost, fmt.Sprintf("/api/connections/%s/config", conn.ID), user, nil)
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

				// Deletion (F1: VLESS deletion is admin-only; Naive deletion is self-service)
				deleteConn := seedForUser(user.ID, protocol, string(role)+"-delete")
				w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/delete", deleteConn.ID), user, nil)
				if isVLESS && role != models.RoleAdmin {
					if w.Code != http.StatusForbidden {
						t.Fatalf("delete status = %d, want 403; body: %s", w.Code, w.Body.String())
					}
					var errResp map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
						t.Fatalf("Unmarshal delete response: %v", err)
					}
					if errResp["error"] != "forbidden" {
						t.Errorf("error = %v, want forbidden", errResp["error"])
					}
					remaining, err := db.GetConnection(ctx, deleteConn.ID)
					if err != nil || remaining == nil {
						t.Errorf("forbidden delete removed connection from db: remaining=%v err=%v", remaining, err)
					}
					return
				}

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

	// 3. Cross-user tenant isolation (config retrieval, deletion, and rename F3)
	t.Run("cross-user tenant isolation", func(t *testing.T) {
		for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
			userA := users[models.RoleUser]
			nonOwners := []*models.User{userB, users[models.RoleSupport]}
			for _, nonOwner := range nonOwners {
				connA := seedForUser(userA.ID, protocol, "isolation-owner-"+string(nonOwner.Role))
				removesBefore := removeCalls.Load()

				// Non-owner attempts to retrieve User A's config -> 404 (via POST, F4)
				w := request(http.MethodPost, fmt.Sprintf("/api/connections/%s/config", connA.ID), nonOwner, nil)
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

				// Non-owner attempts to rename User A's connection -> 404 (F3)
				w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/rename", connA.ID), nonOwner, models.RenameConnectionRequest{
					Name: "unauthorized-rename-attempt",
				})
				if w.Code != http.StatusNotFound {
					t.Errorf("%s cross-user rename status = %d, want 404; body: %s", nonOwner.Role, w.Code, w.Body.String())
				}
				var renErr map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &renErr); err != nil {
					t.Errorf("Unmarshal %s cross-user rename error: %v", nonOwner.Role, err)
				} else if renErr["error"] != "not_found" {
					t.Errorf("%s cross-user rename error = %v, want not_found", nonOwner.Role, renErr["error"])
				}

				// Verify connection row is untouched
				remaining, err := db.GetConnection(ctx, connA.ID)
				if err != nil || remaining == nil {
					t.Errorf("%s cross-user operation affected connection: remaining=%v err=%v", nonOwner.Role, remaining, err)
				} else if remaining.Name != connA.Name {
					t.Errorf("%s cross-user rename altered name: got %q, want %q", nonOwner.Role, remaining.Name, connA.Name)
				}

				// Verify zero remote removals were invoked
				if removesAfter := removeCalls.Load(); removesAfter != removesBefore {
					t.Errorf("%s cross-user delete invoked remote removal: calls before=%d after=%d", nonOwner.Role, removesBefore, removesAfter)
				}
			}

			// Owner can rename own connection
			connOwner := seedForUser(userA.ID, protocol, "owner-rename")
			w := request(http.MethodPost, fmt.Sprintf("/api/connections/%s/rename", connOwner.ID), userA, models.RenameConnectionRequest{
				Name: "renamed-by-owner-" + protocol,
			})
			if w.Code != http.StatusOK {
				t.Fatalf("owner rename status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			updated, err := db.GetConnection(ctx, connOwner.ID)
			if err != nil || updated.Name != "renamed-by-owner-"+protocol {
				t.Errorf("owner rename failed in DB: %v", updated)
			}

			// Admin can rename connection
			w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/rename", connOwner.ID), users[models.RoleAdmin], models.RenameConnectionRequest{
				Name: "renamed-by-admin-" + protocol,
			})
			if w.Code != http.StatusOK {
				t.Fatalf("admin rename status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
		}
	})

	// 4. Connection limits and quota enforcement (using self-service NaiveProxy)
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
			Protocol: models.ProtocolNaive,
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
			w = request(http.MethodPost, fmt.Sprintf("/api/connections/%s/config", configConn.ID), user, nil)
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

	// 6. Non-disruptive self-service connection lifecycle (F1 regression)
	t.Run("self-service naive does not disrupt other clients", func(t *testing.T) {
		user := users[models.RoleUser]
		w := request(http.MethodPost, "/api/connections/add", user, models.MyAddConnectionRequest{
			ServerID: serverID,
			Protocol: models.ProtocolNaive,
			Name:     "non-disruptive-naive",
		})
		if w.Code != http.StatusOK {
			t.Fatalf("add status = %d, want 200; body: %s", w.Code, w.Body.String())
		}
	})

	// 7. Support share isolation and public share link retrieval for authenticated visitors (F2)
	t.Run("support share isolation and public share access for authenticated visitors", func(t *testing.T) {
		supportUser := users[models.RoleSupport]
		victimUser := users[models.RoleUser]
		for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
			victimConn := seedForUser(victimUser.ID, protocol, "share-victim-"+protocol)

			// Step 1: Support caller attempts to setup share for victim user -> 403 Forbidden
			pass := ""
			w := request(http.MethodPost, fmt.Sprintf("/api/users/%s/share/setup", victimUser.ID), supportUser, map[string]any{
				"enabled":  true,
				"password": pass,
			})
			if w.Code != http.StatusForbidden {
				t.Fatalf("support share setup status = %d, want 403; body: %s", w.Code, w.Body.String())
			}

			// Step 2: Support caller attempts to read user list -> ShareToken is redacted
			w = request(http.MethodGet, "/api/users", supportUser, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("list users status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			var listResp models.PaginatedUsersResponse
			if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
				t.Fatalf("Unmarshal list users: %v", err)
			}
			for _, uItem := range listResp.Users {
				if uItem.ID == victimUser.ID && uItem.ShareToken != nil {
					t.Errorf("support user can view victim ShareToken: %v", *uItem.ShareToken)
				}
			}

			// Step 3: Pre-seed a legitimate share token on victim user
			shareToken := fmt.Sprintf("legit-token-%s-%d", protocol, time.Now().UnixNano())
			if _, err := db.UpdateUser(ctx, victimUser.ID, map[string]any{
				"share_enabled": true,
				"share_token":   shareToken,
			}); err != nil {
				t.Fatalf("UpdateUser share token: %v", err)
			}

			// Step 4: Authenticated visitors (Support session and other User) possessing valid share link succeed -> 200 OK
			w = request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", shareToken, victimConn.ID), supportUser, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("support share config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			w = request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", shareToken, victimConn.ID), userB, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("other user share config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			// Step 5: Anonymous request via legitimate share link succeeds -> 200 OK
			w = request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", shareToken, victimConn.ID), nil, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("anonymous share config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			// Step 6: Victim user (owner) via share link succeeds -> 200 OK
			w = request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", shareToken, victimConn.ID), victimUser, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("owner share config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			// Step 7: Admin via share link succeeds -> 200 OK
			w = request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", shareToken, victimConn.ID), users[models.RoleAdmin], nil)
			if w.Code != http.StatusOK {
				t.Fatalf("admin share config status = %d, want 200; body: %s", w.Code, w.Body.String())
			}

			// Step 8: Authenticated visitor requesting mismatched connection ID via valid share link -> 404 Not Found
			otherUserConn := seedForUser(userB.ID, protocol, "mismatched-conn-"+protocol)
			w = request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", shareToken, otherUserConn.ID), supportUser, nil)
			if w.Code != http.StatusNotFound {
				t.Fatalf("mismatched connection share config status = %d, want 404; body: %s", w.Code, w.Body.String())
			}
		}
	})

	// 8. Support backup export redacts other users share tokens (Round 3 audit regression)
	t.Run("support backup export redacts other users share tokens", func(t *testing.T) {
		supportUser := users[models.RoleSupport]
		victimUser := users[models.RoleUser]
		adminUser := users[models.RoleAdmin]

		for _, protocol := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
			victimConn := seedForUser(victimUser.ID, protocol, "backup-victim-"+protocol)
			victimToken := fmt.Sprintf("victim-share-token-%s-%d", protocol, time.Now().UnixNano())
			if _, err := db.UpdateUser(ctx, victimUser.ID, map[string]any{
				"share_enabled": true,
				"share_token":   victimToken,
			}); err != nil {
				t.Fatalf("UpdateUser victim share token: %v", err)
			}

			supportToken := fmt.Sprintf("support-own-token-%s-%d", protocol, time.Now().UnixNano())
			if _, err := db.UpdateUser(ctx, supportUser.ID, map[string]any{
				"share_enabled": true,
				"share_token":   supportToken,
			}); err != nil {
				t.Fatalf("UpdateUser support share token: %v", err)
			}

			type backupUserItem struct {
				ID         string  `json:"id"`
				ShareToken *string `json:"share_token"`
			}
			type backupResponse struct {
				Users []backupUserItem `json:"users"`
			}

			// Step 1: Support downloads backup: victim's share_token is redacted (nil/omitted), Support's own share_token is preserved
			w := request(http.MethodGet, "/api/settings/backup/download", supportUser, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("support backup download status = %d, want 200; body: %s", w.Code, w.Body.String())
			}
			var supportBackup backupResponse
			if err := json.Unmarshal(w.Body.Bytes(), &supportBackup); err != nil {
				t.Fatalf("Unmarshal support backup: %v", err)
			}
			var acquiredVictimToken string
			for _, u := range supportBackup.Users {
				if u.ID == victimUser.ID && u.ShareToken != nil {
					t.Errorf("protocol %s: support backup export leaked victim share_token: %q", protocol, *u.ShareToken)
					acquiredVictimToken = *u.ShareToken
				}
				if u.ID == supportUser.ID {
					if u.ShareToken == nil || *u.ShareToken != supportToken {
						t.Errorf("protocol %s: support user own share_token not preserved in backup: got %v, want %q", protocol, u.ShareToken, supportToken)
					}
				}
			}

			// Step 2: Support cannot discover victim's share token from backup to anonymously retrieve config
			if acquiredVictimToken != "" {
				wAnon := request(http.MethodPost, fmt.Sprintf("/api/share/%s/config/%s", acquiredVictimToken, victimConn.ID), nil, nil)
				if wAnon.Code == http.StatusOK {
					t.Errorf("protocol %s: Support exploited leaked backup token to anonymously retrieve victim config", protocol)
				}
			}

			// Step 3: Admin downloads backup: victim's share_token remains present
			wAdmin := request(http.MethodGet, "/api/settings/backup/download", adminUser, nil)
			if wAdmin.Code != http.StatusOK {
				t.Fatalf("admin backup download status = %d, want 200; body: %s", wAdmin.Code, wAdmin.Body.String())
			}
			var adminBackup backupResponse
			if err := json.Unmarshal(wAdmin.Body.Bytes(), &adminBackup); err != nil {
				t.Fatalf("Unmarshal admin backup: %v", err)
			}
			foundVictimTokenInAdmin := false
			for _, u := range adminBackup.Users {
				if u.ID == victimUser.ID {
					if u.ShareToken == nil || *u.ShareToken != victimToken {
						t.Errorf("protocol %s: admin backup export missing victim share_token: got %v, want %q", protocol, u.ShareToken, victimToken)
					} else {
						foundVictimTokenInAdmin = true
					}
				}
			}
			if !foundVictimTokenInAdmin {
				t.Errorf("protocol %s: victim user not found in admin backup export", protocol)
			}
		}
	})

	// 9. Full production router verification (F4)
	t.Run("full router connections endpoints match POST specification", func(t *testing.T) {
		fullRouter := setupFullConnectionsRouter(h)
		conn := seedForUser(users[models.RoleUser].ID, models.ProtocolNaive, "full-router-test")
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/connections/%s/config", conn.ID), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: users[models.RoleUser].ID,
			Role:   models.RoleUser,
		}))
		w := httptest.NewRecorder()
		fullRouter.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("full router POST config status = %d, want 200; body: %s", w.Code, w.Body.String())
		}
	})
}
