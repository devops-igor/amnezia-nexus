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

func TestAddUserHandler_InitialConnectionFailure_SurfacesError(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	var mu sync.Mutex
	var rolledBackClients []string
	expectedClientID := "test-initial-http-505"

	mgr := &mockProtocolManager{
		protocol: "awg",
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id": expectedClientID,
				"config":    "dummy-initial-config",
			}, nil
		},
		rollbackAddClientFn: func(ctx context.Context, server *models.Server, addResult map[string]any) error {
			mu.Lock()
			defer mu.Unlock()
			cid, _ := addResult["client_id"].(string)
			rolledBackClients = append(rolledBackClients, cid)
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

	// Trigger simulated CreateConnection failure on user_connections table
	_, err = db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_add_user BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated user_connections db error'); END;")
	if err != nil {
		t.Fatalf("failed to create failure trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_add_user")
	}()

	protoAWG := "awg"
	connName := "Initial User Conn"
	addReq := models.AddUserRequest{
		Username:       "user_with_initial_conn",
		Password:       "ValidPassword123!",
		Role:           models.RoleUser,
		ServerID:       &sID,
		Protocol:       &protoAWG,
		ConnectionName: &connName,
	}
	body, err := json.Marshal(addReq)
	if err != nil {
		t.Fatalf("failed to marshal add user req: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/users/add", bytes.NewReader(body))
	reqCtx := middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin-1", Role: models.RoleAdmin})
	w := httptest.NewRecorder()

	r := setupFullUsersRouter(h)
	r.ServeHTTP(w, req.WithContext(reqCtx))

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK from AddUserHandler even if initial connection fails, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
	userID, ok := resp["user_id"].(string)
	if !ok || userID == "" {
		t.Errorf("expected user_id to be returned")
	}
	connCreated, ok := resp["connection_created"].(bool)
	if !ok || connCreated {
		t.Errorf("expected connection_created == false, got %v", resp["connection_created"])
	}
	connErr, ok := resp["connection_error"].(string)
	if !ok || connErr == "" {
		t.Errorf("expected connection_error to be populated, got %v", resp["connection_error"])
	}

	mu.Lock()
	defer mu.Unlock()
	if len(rolledBackClients) != 1 || rolledBackClients[0] != expectedClientID {
		t.Fatalf("expected remote client %s to be rolled back, got: %v", expectedClientID, rolledBackClients)
	}

	// Verify peer_lifecycle was cleaned up
	activePeers, err := db.GetActivePeerIDs(ctx, sID, "awg")
	if err != nil {
		t.Fatalf("GetActivePeerIDs failed: %v", err)
	}
	if activePeers[expectedClientID] {
		t.Fatalf("expected client %s to not be active in peer_lifecycle after rollback", expectedClientID)
	}
}

func TestHandler_AddConnection_RollbackUpsertDoesNotDeleteExistingPeer(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	var mu sync.Mutex
	var removedClients []string
	var rolledBackResults []map[string]any
	targetClientID := "peer-upsert-existing-999"

	mgr := &mockProtocolManager{
		protocol: "awg",
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"client_id":     targetClientID,
				"config":        "new-upsert-config",
				"is_upsert":     true,
				"previous_peer": "pre-existing-peer-data",
			}, nil
		},
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			mu.Lock()
			defer mu.Unlock()
			removedClients = append(removedClients, clientID)
			return nil
		},
		rollbackAddClientFn: func(ctx context.Context, server *models.Server, addResult map[string]any) error {
			mu.Lock()
			defer mu.Unlock()
			rolledBackResults = append(rolledBackResults, addResult)
			// Do NOT delete the peer if is_upsert == true!
			if isUpsert, _ := addResult["is_upsert"].(bool); !isUpsert {
				removedClients = append(removedClients, addResult["client_id"].(string))
			}
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
		ID:        "u-upsert-rollback",
		Username:  "user_upsert_rollback",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Trigger simulated CreateConnection failure on user_connections table
	_, err = db.ExecContext(ctx, "CREATE TRIGGER fail_conn_insert_upsert BEFORE INSERT ON user_connections BEGIN SELECT RAISE(ABORT, 'simulated connection insert failure'); END;")
	if err != nil {
		t.Fatalf("failed to create failure trigger: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_conn_insert_upsert")
	}()

	body, _ := json.Marshal(models.MyAddConnectionRequest{
		ServerID: sID,
		Protocol: "awg",
		Name:     "Existing Client Name",
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
	if len(rolledBackResults) != 1 {
		t.Fatalf("expected RollbackAddClient to be called exactly once, got %d", len(rolledBackResults))
	}
	if isUpsert, ok := rolledBackResults[0]["is_upsert"].(bool); !ok || !isUpsert {
		t.Errorf("expected rolled back result to have is_upsert=true")
	}
	if len(removedClients) != 0 {
		t.Fatalf("expected pre-existing peer NOT to be deleted via RemoveClient during upsert rollback, but got removed: %v", removedClients)
	}
}
