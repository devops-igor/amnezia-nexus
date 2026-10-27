package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// TestToggleUserHandlerDisableRevokesNonToggleProtocols verifies that disabling
// a user revokes VLESS/Naive credentials remotely (as userops does) instead of
// rejecting, and fails closed when the remote revocation fails.
func TestToggleUserHandlerDisableRevokesNonToggleProtocols(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	var removeErr error
	removed := map[string][]string{}
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		h.registry.Register(&mockProtocolManager{
			protocol: proto,
			removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
				if removeErr != nil {
					return removeErr
				}
				removed[proto] = append(removed[proto], clientID)
				return nil
			},
		})
	}

	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "UT-VPN", Host: "192.168.1.95", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{
			"vless": map[string]any{"installed": true},
			"naive": map[string]any{"installed": true},
		},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	user := &models.User{
		ID: "ut-user", Username: "utuser", PasswordHash: "hash",
		Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	for _, c := range []struct{ id, proto string }{{"ut-vless", "vless"}, {"ut-naive", "naive"}} {
		if _, err := db.CreateConnection(ctx, &models.UserConnection{
			ID: c.id, UserID: user.ID, ServerID: sID, Protocol: c.proto, ClientID: c.id + "-client", CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("create connection: %v", err)
		}
	}

	disable := func() int {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/toggle", user.ID), bytes.NewReader([]byte(`{"enabled":false}`)))
		w := httptest.NewRecorder()
		setupFullUsersRouter(h).ServeHTTP(w, req)
		return w.Code
	}

	removeErr = errors.New("ssh: connection refused")
	if code := disable(); code != http.StatusInternalServerError {
		t.Fatalf("remote failure: expected 500, got %d", code)
	}
	if u, _ := db.GetUser(ctx, user.ID); u == nil || !u.Enabled {
		t.Error("user must stay enabled when remote revocation fails")
	}
	if c, _ := db.GetConnection(ctx, "ut-vless"); c == nil {
		t.Error("connection must be preserved when remote revocation fails")
	}

	removeErr = nil
	if code := disable(); code != http.StatusOK {
		t.Fatalf("retry: expected 200, got %d", code)
	}
	if got := removed["vless"]; len(got) != 1 || got[0] != "ut-vless-client" {
		t.Errorf("vless revocation = %v", got)
	}
	if got := removed["naive"]; len(got) != 1 || got[0] != "ut-naive-client" {
		t.Errorf("naive revocation = %v", got)
	}
	if u, _ := db.GetUser(ctx, user.ID); u == nil || u.Enabled {
		t.Error("user must be disabled after successful revocation")
	}
	if conns, _ := db.GetConnectionsByUserID(ctx, user.ID); len(conns) != 0 {
		t.Errorf("revoked connections must be dropped, got %d", len(conns))
	}
}
