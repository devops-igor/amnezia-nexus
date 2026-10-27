package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestDeleteUserHandlerFailsClosedOnRemoteRemoval verifies that a failed remote
// RemoveClient keeps the user and connection rows (so ownership survives for a
// retry) and that the retry succeeds once the remote error clears (R9-H1).
func TestDeleteUserHandlerFailsClosedOnRemoteRemoval(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	var removeErr error
	var removed []string
	h.registry.Register(&mockProtocolManager{
		protocol: "awg",
		removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
			if removeErr != nil {
				return removeErr
			}
			removed = append(removed, clientID)
			return nil
		},
	})

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "Del-VPN", Host: "192.168.1.90", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	user := &models.User{
		ID: "r9h1-user", Username: "r9h1user", PasswordHash: "hash",
		Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	conn := &models.UserConnection{
		ID: "r9h1-conn", UserID: user.ID, ServerID: sID, Protocol: "awg",
		ClientID: "r9h1-client", Name: "R9H1", CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	doDelete := func() int {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/delete", user.ID), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "some-other-admin", Role: models.RoleAdmin,
		}))
		w := httptest.NewRecorder()
		setupFullUsersRouter(h).ServeHTTP(w, req)
		return w.Code
	}

	removeErr = errors.New("ssh: connection refused")
	if code := doDelete(); code != http.StatusInternalServerError {
		t.Fatalf("remote failure: expected 500, got %d", code)
	}
	if u, _ := db.GetUser(ctx, user.ID); u == nil {
		t.Error("user must be preserved when remote removal fails")
	}
	if c, _ := db.GetConnection(ctx, conn.ID); c == nil {
		t.Error("connection must be preserved when remote removal fails")
	}

	removeErr = nil
	if code := doDelete(); code != http.StatusOK {
		t.Fatalf("retry: expected 200, got %d", code)
	}
	if len(removed) != 1 || removed[0] != conn.ClientID {
		t.Errorf("expected retry to remove %q remotely, got %v", conn.ClientID, removed)
	}
	if u, _ := db.GetUser(ctx, user.ID); u != nil {
		t.Error("user must be deleted after successful retry")
	}
	if c, _ := db.GetConnection(ctx, conn.ID); c != nil {
		t.Error("connection must be deleted after successful retry")
	}
}
