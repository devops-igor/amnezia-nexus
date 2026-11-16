package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestAddUserConnectionHandler_AddClientFailureLogged verifies that the
// user-connection handler still returns the opaque add_client_failed 500 but no
// longer destroys the underlying cause (issue #744).
//
// The E2E lifecycle could only report "HTTP 500 add_client_failed" for seven
// client-creation cases because this handler discarded the AddClient error,
// while the admin path in server_connections.go already logged it. The lifecycle
// finalizer reduces the operator log to a closed schema, so the cause has to
// reach slog with these exact fields or it is lost with the container.
func TestAddUserConnectionHandler_AddClientFailureLogged(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	u := &models.User{
		ID:           "add-client-log-user",
		Username:     "addclientlogin",
		PasswordHash: "hashedpass",
		Role:         models.RoleUser,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}
	if _, err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	srv := &models.Server{
		Name:      "Add-Client-Log-Server",
		Host:      "10.0.0.91",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	// The producer's own wrapper text: the step classifier allowlists it, and
	// the assertion below proves the handler logged the cause rather than a
	// generic placeholder.
	const failure = "failed to save clients table: database is locked"
	h.registry = manager.NewRegistry()
	h.registry.Register(&mockProtocolManager{
		protocol: "awg",
		addClientFn: func(context.Context, *models.Server, map[string]any) (map[string]any, error) {
			return nil, errors.New(failure)
		},
	})

	var logBuf testSyncWriter
	origLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(origLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))

	body, _ := json.Marshal(models.AddUserConnectionRequest{
		ServerID: serverID,
		Protocol: "awg",
		Name:     "add-client-log-conn",
	})
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/users/%s/connections/add", u.ID),
		bytes.NewReader(body),
	)
	w := httptest.NewRecorder()
	setupFullUsersRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on AddClient failure, got %d (body: %s)", w.Code, w.Body.String())
	}
	// The client-visible contract must not change: same code, same message.
	if !strings.Contains(w.Body.String(), "add_client_failed") {
		t.Errorf("expected the masked add_client_failed body, got %s", w.Body.String())
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "failed to add client") {
		t.Fatalf("expected slog output to contain 'failed to add client', got:\n%s", logs)
	}
	for _, want := range []string{
		"server_id=" + fmt.Sprint(serverID),
		"protocol=awg",
		"error=",
		failure,
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected client-creation log to include %q, got:\n%s", want, logs)
		}
	}
}
