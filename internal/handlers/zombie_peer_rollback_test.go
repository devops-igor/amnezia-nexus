package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestUserAddConnectionHandler_RollbackOnDBCreateFailure(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	var mu sync.Mutex
	var removedClientIDs []string
	expectedClientID := "test-client-rollback-101"

	mgr := &mockProtocolManager{
		protocol: "awg",
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id": expectedClientID,
				"config":    "dummy-config",
			}, nil
		},
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			mu.Lock()
			defer mu.Unlock()
			removedClientIDs = append(removedClientIDs, clientID)
			return nil
		},
		getClientConfigFn: func(ctx context.Context, server *models.Server, clientID string) (string, error) {
			return "dummy-config", nil
		},
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(mgr)

	srv := &models.Server{
		Name:      "Server 1",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{"awg": map[string]any{"installed": true}},
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	u := &models.User{
		ID:        "u-rollback-1",
		Username:  "user_rollback_1",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Trigger simulated CreateConnection failure on user_connections table
	_, err = db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_user BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated connection insert failure'); END;")
	if err != nil {
		t.Fatalf("failed to create failure trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_user")
	}()

	body, _ := json.Marshal(models.MyAddConnectionRequest{
		ServerID: sID,
		Protocol: "awg",
		Name:     "Test Rollback Conn",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/connections/add", bytes.NewReader(body))
	reqCtx := middleware.WithSession(req.Context(), &models.SessionData{UserID: u.ID, Role: models.RoleUser})
	w := httptest.NewRecorder()

	r := setupFullConnectionsRouter(h)
	r.ServeHTTP(w, req.WithContext(reqCtx))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on DB failure, got %d (body: %s)", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(removedClientIDs) != 1 || removedClientIDs[0] != expectedClientID {
		t.Fatalf("expected remote client %s to be rolled back, got: %v", expectedClientID, removedClientIDs)
	}
}

func TestAddServerConnectionHandler_RollbackOnDBCreateFailure(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	var mu sync.Mutex
	var removedClientIDs []string
	expectedClientID := "test-server-rollback-202"

	mgr := &mockProtocolManager{
		protocol: "awg",
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id": expectedClientID,
				"config":    "dummy-server-config",
			}, nil
		},
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			mu.Lock()
			defer mu.Unlock()
			removedClientIDs = append(removedClientIDs, clientID)
			return nil
		},
		getClientConfigFn: func(ctx context.Context, server *models.Server, clientID string) (string, error) {
			return "dummy-server-config", nil
		},
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(mgr)

	srv := &models.Server{
		Name:      "Server 1",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{"awg": map[string]any{"installed": true}},
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	u := &models.User{
		ID:        "u-rollback-2",
		Username:  "user_rollback_2",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Trigger simulated CreateConnection failure on user_connections table
	_, err = db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_server BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated connection insert failure'); END;")
	if err != nil {
		t.Fatalf("failed to create failure trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_server")
	}()

	body, _ := json.Marshal(models.AddConnectionRequest{
		Protocol: "awg",
		Name:     "Server Rollback Conn",
		UserID:   &u.ID,
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/connections/add", sID), bytes.NewReader(body))
	reqCtx := middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin-1", Role: models.RoleAdmin})
	w := httptest.NewRecorder()

	r := setupFullServerConnectionsRouter(h)
	r.ServeHTTP(w, req.WithContext(reqCtx))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on DB failure, got %d (body: %s)", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(removedClientIDs) != 1 || removedClientIDs[0] != expectedClientID {
		t.Fatalf("expected remote client %s to be rolled back, got: %v", expectedClientID, removedClientIDs)
	}
}

func TestAdminAddUserConnectionHandler_RollbackOnDBCreateFailure(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	var mu sync.Mutex
	var removedClientIDs []string
	expectedClientID := "test-admin-rollback-303"

	mgr := &mockProtocolManager{
		protocol: "awg",
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id": expectedClientID,
				"config":    "dummy-admin-config",
			}, nil
		},
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			mu.Lock()
			defer mu.Unlock()
			removedClientIDs = append(removedClientIDs, clientID)
			return nil
		},
		getClientConfigFn: func(ctx context.Context, server *models.Server, clientID string) (string, error) {
			return "dummy-admin-config", nil
		},
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(mgr)

	srv := &models.Server{
		Name:      "Server 1",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{"awg": map[string]any{"installed": true}},
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	u := &models.User{
		ID:        "u-rollback-3",
		Username:  "user_rollback_3",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Trigger simulated CreateConnection failure on user_connections table
	_, err = db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_admin BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated connection insert failure'); END;")
	if err != nil {
		t.Fatalf("failed to create failure trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_admin")
	}()

	body, _ := json.Marshal(models.AddUserConnectionRequest{
		ServerID: sID,
		Protocol: "awg",
		Name:     "Admin Rollback Conn",
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/connections/add", u.ID), bytes.NewReader(body))
	reqCtx := middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin-1", Role: models.RoleAdmin})
	w := httptest.NewRecorder()

	r := setupFullUsersRouter(h)
	r.ServeHTTP(w, req.WithContext(reqCtx))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on DB failure, got %d (body: %s)", w.Code, w.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(removedClientIDs) != 1 || removedClientIDs[0] != expectedClientID {
		t.Fatalf("expected remote client %s to be rolled back, got: %v", expectedClientID, removedClientIDs)
	}
}

func TestProvisionInitialConnection_RollbackOnDBCreateFailure(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	var mu sync.Mutex
	var removedClientIDs []string
	expectedClientID := "test-initial-rollback-404"

	mgr := &mockProtocolManager{
		protocol: "awg",
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id": expectedClientID,
				"config":    "dummy-initial-config",
			}, nil
		},
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			mu.Lock()
			defer mu.Unlock()
			removedClientIDs = append(removedClientIDs, clientID)
			return nil
		},
		getClientConfigFn: func(ctx context.Context, server *models.Server, clientID string) (string, error) {
			return "dummy-initial-config", nil
		},
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(mgr)

	srv := &models.Server{
		Name:      "Server 1",
		Host:      "127.0.0.1",
		SSHPort:   22,
		Protocols: map[string]any{"awg": map[string]any{"installed": true}},
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	u := &models.User{
		ID:        "u-rollback-4",
		Username:  "user_rollback_4",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Trigger simulated CreateConnection failure on user_connections table
	_, err = db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_initial BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated connection insert failure'); END;")
	if err != nil {
		t.Fatalf("failed to create failure trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_initial")
	}()

	protoAWG := "awg"
	connName := "Initial Rollback Conn"
	resp := map[string]any{
		"status":  "ok",
		"user_id": u.ID,
	}
	addReq := models.AddUserRequest{
		Username:       u.Username,
		Role:           models.RoleUser,
		ServerID:       &sID,
		Protocol:       &protoAWG,
		ConnectionName: &connName,
	}

	h.provisionInitialConnection(ctx, u, addReq, resp)

	if created, ok := resp["connection_created"].(bool); ok && created {
		t.Fatalf("expected connection_created to not be set to true on DB error, got %v", resp["connection_created"])
	}
	if _, ok := resp["config"]; ok {
		t.Fatalf("expected config to not be populated on DB error")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(removedClientIDs) != 1 || removedClientIDs[0] != expectedClientID {
		t.Fatalf("expected remote client %s to be rolled back, got: %v", expectedClientID, removedClientIDs)
	}
}
