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

// TestDeleteServerHandlerAdminManagedProtocols verifies that deleting a server
// hosting VLESS/Naive is Admin-only, tears the remote protocol down first, and
// fails closed (records preserved) when that teardown fails.
func TestDeleteServerHandlerAdminManagedProtocols(t *testing.T) {
	for _, proto := range []string{models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := t.Context()

			var uninstallErr error
			var uninstalled int
			h.registry.Register(&mockProtocolManager{
				protocol: proto,
				uninstallFn: func(_ context.Context, _ *models.Server) error {
					if uninstallErr != nil {
						return uninstallErr
					}
					uninstalled++
					return nil
				},
			})

			sID, err := db.CreateServer(ctx, &models.Server{
				Name: "Multi-VPN", Host: "192.168.1.77", SSHPort: 22, SSHUser: "root",
				Protocols: map[string]any{
					"awg": map[string]any{"port": 55424, "installed": true},
					proto: map[string]any{"port": 443, "installed": true},
				},
				CreatedAt: time.Now(),
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}
			if _, err := db.CreateUser(ctx, &models.User{
				ID: "md-user", Username: "mduser", PasswordHash: "hash", Role: models.RoleUser, Enabled: true, CreatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("create user: %v", err)
			}
			if _, err := db.CreateConnection(ctx, &models.UserConnection{
				ID: "md-conn", UserID: "md-user", ServerID: sID, Protocol: proto, ClientID: "md-client", CreatedAt: time.Now(),
			}); err != nil {
				t.Fatalf("create connection: %v", err)
			}

			doDelete := func(role models.UserRole) int {
				req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", sID), nil)
				if role != "" {
					req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "actor", Role: role}))
				}
				w := httptest.NewRecorder()
				setupFullServerRouter(h).ServeHTTP(w, req)
				return w.Code
			}
			assertPreserved := func(step string) {
				t.Helper()
				if s, _ := db.GetServer(ctx, sID); s == nil {
					t.Errorf("%s: server must be preserved", step)
				}
				if c, _ := db.GetConnection(ctx, "md-conn"); c == nil {
					t.Errorf("%s: connection must be preserved", step)
				}
			}

			for _, role := range []models.UserRole{models.RoleSupport, ""} {
				if code := doDelete(role); code != http.StatusForbidden {
					t.Fatalf("role %q: expected 403, got %d", role, code)
				}
			}
			if uninstalled != 0 {
				t.Fatalf("non-admin delete must not uninstall, got %d calls", uninstalled)
			}
			assertPreserved("non-admin")

			uninstallErr = errors.New("container removal failed: permission denied")
			if code := doDelete(models.RoleAdmin); code != http.StatusInternalServerError {
				t.Fatalf("teardown failure: expected 500, got %d", code)
			}
			assertPreserved("teardown failure")

			uninstallErr = nil
			if code := doDelete(models.RoleAdmin); code != http.StatusOK {
				t.Fatalf("admin retry: expected 200, got %d", code)
			}
			if uninstalled != 1 {
				t.Errorf("expected exactly 1 uninstall, got %d", uninstalled)
			}
			if s, _ := db.GetServer(ctx, sID); s != nil {
				t.Error("server must be deleted after successful teardown")
			}
			if c, _ := db.GetConnection(ctx, "md-conn"); c != nil {
				t.Error("connections must be deleted after successful teardown")
			}
		})
	}
}

// TestDeleteServerHandlerAWGOnlyStaysSupportDeletable guards that the Admin gate
// applies only to Admin-managed protocols.
func TestDeleteServerHandlerAWGOnlyStaysSupportDeletable(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()
	sID, err := db.CreateServer(ctx, &models.Server{
		Name: "AWG-Only", Host: "192.168.1.78", SSHPort: 22, SSHUser: "root",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", sID), nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "s", Role: models.RoleSupport}))
	w := httptest.NewRecorder()
	setupFullServerRouter(h).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
