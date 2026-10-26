package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestClearServer_StopsAndRemovesNewProtocolContainers(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "clear-test-server",
		Host:    "192.0.2.50",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{"installed": true},
			"naive": map[string]any{"installed": true},
			"awg":   map[string]any{"installed": true},
		},
	})
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	var mu sync.Mutex
	commands := []string{}
	h.sshPool = &testMockSSHPool{
		client: &testMockSSHClient{
			cmdFunc: func(_ context.Context, cmd string) (string, string, int, error) {
				mu.Lock()
				commands = append(commands, cmd)
				mu.Unlock()
				return "OK", "", 0, nil
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("server_id", fmt.Sprint(sid))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))

	w := httptest.NewRecorder()
	h.ClearServerHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ClearServerHandler returned %d: %s", w.Code, w.Body.String())
	}

	saved, err := db.GetServer(ctx, sid)
	if err != nil {
		t.Fatalf("failed to fetch server: %v", err)
	}
	if len(saved.Protocols) != 0 {
		t.Errorf("expected empty protocols after clear, got: %v", saved.Protocols)
	}

	mu.Lock()
	cmds := append([]string{}, commands...)
	mu.Unlock()

	for _, container := range []string{"amnezia-xray", "amnezia-caddy"} {
		stopped, removed := false, false
		for _, cmd := range cmds {
			if strings.Contains(cmd, "docker stop") && strings.Contains(cmd, container) {
				stopped = true
			}
			if strings.Contains(cmd, "docker rm") && strings.Contains(cmd, container) {
				removed = true
			}
		}
		if !stopped || !removed {
			t.Errorf("container %s was not properly torn down (stopped=%v, removed=%v)", container, stopped, removed)
		}
	}
}

func TestClearServer_TeardownFailurePreservesRecords(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "clear-fail-server",
		Host:    "192.0.2.51",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{"installed": true},
			"naive": map[string]any{"installed": true},
		},
	})
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	// Create a dummy user and connection to ensure connections are preserved on failure
	_, err = db.CreateUser(ctx, &models.User{
		ID:       "clear-test-user",
		Username: "cleartestuser",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	conn := &models.UserConnection{
		ServerID: sid,
		UserID:   "clear-test-user",
		Protocol: "vless",
		ClientID: "client-vless-1",
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("failed to create test connection: %v", err)
	}

	var mu sync.Mutex
	commands := []string{}
	h.sshPool = &testMockSSHPool{
		client: &testMockSSHClient{
			cmdFunc: func(_ context.Context, cmd string) (string, string, int, error) {
				mu.Lock()
				commands = append(commands, cmd)
				mu.Unlock()
				if strings.Contains(cmd, "amnezia-xray") {
					return "", "simulated ssh container error", 1, errors.New("ssh command failure on xray container")
				}
				return "OK", "", 0, nil
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("server_id", fmt.Sprint(sid))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{Role: models.RoleAdmin}))

	w := httptest.NewRecorder()
	h.ClearServerHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on teardown failure, got %d: %s", w.Code, w.Body.String())
	}

	// Verify rm -rf /opt/amnezia was never executed
	mu.Lock()
	cmds := append([]string{}, commands...)
	mu.Unlock()
	for _, cmd := range cmds {
		if strings.Contains(cmd, "rm -rf /opt/amnezia") {
			t.Errorf("rm -rf /opt/amnezia was executed despite container teardown failure: %s", cmd)
		}
	}

	// Verify protocols are preserved in database
	saved, err := db.GetServer(ctx, sid)
	if err != nil {
		t.Fatalf("failed to fetch server: %v", err)
	}
	if len(saved.Protocols) == 0 {
		t.Errorf("expected protocols to be preserved after teardown failure, got empty map")
	}
	if _, ok := saved.Protocols["vless"]; !ok {
		t.Errorf("expected vless protocol to be preserved")
	}

	// Verify connections are preserved in database
	conns, err := db.GetConnectionsByServerID(ctx, sid)
	if err != nil {
		t.Fatalf("failed to get connections: %v", err)
	}
	if len(conns) == 0 {
		t.Errorf("expected connections to be preserved after teardown failure, got 0")
	}
}
