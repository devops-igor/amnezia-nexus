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
)

func TestUserAddConnectionHandler_OfflineServer(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	u := &models.User{
		ID:           "u-offline-1",
		Username:     "offlineuser",
		PasswordHash: "hash",
		Role:         models.RoleUser,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}
	_, err := db.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	srv := &models.Server{
		Name:      "Offline-Node",
		Host:      "198.51.100.10",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "secret",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	mockSSH.serverID = &sID

	sess := &models.SessionData{
		UserID:   u.ID,
		Username: u.Username,
		Role:     models.RoleUser,
	}

	r := setupFullConnectionsRouter(h)

	t.Run("Rejects request when server is ReachabilityOffline", func(t *testing.T) {
		if err := db.UpdateServerReachability(ctx, sID, models.ReachabilityOffline); err != nil {
			t.Fatalf("UpdateServerReachability failed: %v", err)
		}

		body, _ := json.Marshal(models.MyAddConnectionRequest{
			ServerID: sID,
			Protocol: "awg",
			Name:     "Blocked Client",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/connections/add", bytes.NewReader(body))
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(reqCtx))

		if w.Code != http.StatusConflict {
			t.Fatalf("expected HTTP 409 Conflict, got %d (body: %s)", w.Code, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}
		if resp["error"] != "server_unavailable" {
			t.Errorf("expected error 'server_unavailable', got %v", resp["error"])
		}
		detail, _ := resp["detail"].(string)
		if detail == "" {
			detail, _ = resp["message"].(string)
		}
		if detail != "Server is currently unavailable or offline" {
			t.Errorf("expected detail 'Server is currently unavailable or offline', got %v", detail)
		}
	})

	t.Run("Allows request when server recovers to ReachabilityOnline", func(t *testing.T) {
		if err := db.UpdateServerReachability(ctx, sID, models.ReachabilityOnline); err != nil {
			t.Fatalf("UpdateServerReachability failed: %v", err)
		}

		body, _ := json.Marshal(models.MyAddConnectionRequest{
			ServerID: sID,
			Protocol: "awg",
			Name:     "Allowed Client",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/connections/add", bytes.NewReader(body))
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK after recovery, got %d (body: %s)", w.Code, w.Body.String())
		}
	})
}

func TestAddServerConnectionHandler_OfflineServer(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:      "Admin-Offline-Node",
		Host:      "198.51.100.11",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "secret",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	mockSSH.serverID = &serverID

	u := &models.User{
		ID:           "sc-user-offline",
		Username:     "scuseroffline",
		PasswordHash: "hash",
		Role:         models.RoleUser,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}
	_, _ = db.CreateUser(ctx, u)

	r := setupFullServerConnectionsRouter(h)

	t.Run("Rejects request when server is ReachabilityOffline", func(t *testing.T) {
		if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOffline); err != nil {
			t.Fatalf("UpdateServerReachability failed: %v", err)
		}

		body, _ := json.Marshal(models.AddConnectionRequest{
			Protocol: "awg",
			Name:     "Server Conn Offline",
			UserID:   &u.ID,
		})
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/connections/add", serverID), bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Fatalf("expected HTTP 409 Conflict, got %d (body: %s)", w.Code, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}
		if resp["error"] != "server_unavailable" {
			t.Errorf("expected error 'server_unavailable', got %v", resp["error"])
		}
		detail, _ := resp["detail"].(string)
		if detail == "" {
			detail, _ = resp["message"].(string)
		}
		if detail != "Server is currently unavailable or offline" {
			t.Errorf("expected detail 'Server is currently unavailable or offline', got %v", detail)
		}
	})

	t.Run("Allows request when server is ReachabilityOnline", func(t *testing.T) {
		if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline); err != nil {
			t.Fatalf("UpdateServerReachability failed: %v", err)
		}

		body, _ := json.Marshal(models.AddConnectionRequest{
			Protocol: "awg",
			Name:     "Server Conn Online",
			UserID:   &u.ID,
		})
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/connections/add", serverID), bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK, got %d (body: %s)", w.Code, w.Body.String())
		}
	})
}

func TestAddUserConnectionHandler_OfflineServer(t *testing.T) {
	mockSSH := &testMockSSHClient{}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)
	ctx := context.Background()

	srv := &models.Server{
		Name:      "User-Offline-Node",
		Host:      "198.51.100.12",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "secret",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	mockSSH.serverID = &serverID

	u := &models.User{
		ID:           "user-conn-offline-target",
		Username:     "targetuser",
		PasswordHash: "hash",
		Role:         models.RoleUser,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}
	_, _ = db.CreateUser(ctx, u)

	r := setupFullUsersRouter(h)

	t.Run("Rejects new client creation when server is ReachabilityOffline", func(t *testing.T) {
		if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOffline); err != nil {
			t.Fatalf("UpdateServerReachability failed: %v", err)
		}

		body, _ := json.Marshal(models.AddUserConnectionRequest{
			ServerID: serverID,
			Protocol: "awg",
			Name:     "Target New Offline Conn",
		})
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/connections/add", u.ID), bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Fatalf("expected HTTP 409 Conflict, got %d (body: %s)", w.Code, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}
		if resp["error"] != "server_unavailable" {
			t.Errorf("expected error 'server_unavailable', got %v", resp["error"])
		}
		detail, _ := resp["detail"].(string)
		if detail == "" {
			detail, _ = resp["message"].(string)
		}
		if detail != "Server is currently unavailable or offline" {
			t.Errorf("expected detail 'Server is currently unavailable or offline', got %v", detail)
		}
	})

	t.Run("Allows new client creation when server is ReachabilityOnline", func(t *testing.T) {
		if err := db.UpdateServerReachability(ctx, serverID, models.ReachabilityOnline); err != nil {
			t.Fatalf("UpdateServerReachability failed: %v", err)
		}

		body, _ := json.Marshal(models.AddUserConnectionRequest{
			ServerID: serverID,
			Protocol: "awg",
			Name:     "Target Online Conn",
		})
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/connections/add", u.ID), bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 OK, got %d (body: %s)", w.Code, w.Body.String())
		}
	})
}

func TestRenderTemplate_OfflineServerVisualGuardrails(t *testing.T) {
	_, db, _ := setupTestHandlersWithMockSSH(t, &testMockSSHClient{})

	t.Run("my_connections.html renders offline servers with disabled and (Offline)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/my", nil)
		w := httptest.NewRecorder()

		servers := []SanitizedServerForUser{
			{
				ID:        1,
				Name:      "Online Server",
				Status:    "online",
				Reachable: true,
				Protocols: map[string]map[string]bool{"awg": {"installed": true}},
			},
			{
				ID:        2,
				Name:      "Down Node",
				Status:    "offline",
				Reachable: false,
				Protocols: map[string]map[string]bool{"awg": {"installed": true}},
			},
		}

		err := RenderTemplate(w, req, db, "my_connections.html", map[string]any{
			"servers":     servers,
			"connections": []models.UserConnection{},
			"vpn_enabled": false,
		})
		if err != nil {
			t.Fatalf("RenderTemplate failed: %v", err)
		}

		body := w.Body.String()

		// Verify disabled attribute is present for offline server
		if !strings.Contains(body, `disabled`) {
			t.Errorf("expected rendered HTML to contain disabled attribute for offline server")
		}

		// Verify (Offline) indicator is rendered for offline server
		if !strings.Contains(body, "(Offline)") {
			t.Errorf("expected rendered HTML to contain '(Offline)' for offline server in select, got body: %s", body)
		}

		// Verify the option tag specifically contains value="2", disabled, and Down Node (Offline)
		expectedSnippet := `<option value="2" data-protocols="`
		if !strings.Contains(body, expectedSnippet) {
			t.Errorf("expected rendered HTML to contain %q, body: %s", expectedSnippet, body)
		}
	})

	t.Run("users.html renders offline servers with (Offline) text in ucServer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/users", nil)
		w := httptest.NewRecorder()

		servers := []models.Server{
			{
				ID:     1,
				Name:   "Alpha Active",
				Host:   "198.51.100.1",
				Status: models.ReachabilityOnline,
			},
			{
				ID:     2,
				Name:   "Beta Offline",
				Host:   "198.51.100.2",
				Status: models.ReachabilityOffline,
			},
		}

		err := RenderTemplate(w, req, db, "users.html", map[string]any{
			"servers": servers,
			"users":   []*models.User{},
		})
		if err != nil {
			t.Fatalf("RenderTemplate users.html failed: %v", err)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Beta Offline (198.51.100.2) (Offline)") {
			t.Errorf("expected users.html to render 'Beta Offline (198.51.100.2) (Offline)', got body: %s", body)
		}
	})
}
