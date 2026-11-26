package router

// The VPN child documents answer the same gate as the overview: an administrator and a
// support user both reach them, and an unauthenticated visitor is redirected to the
// login page. They are covered in their own test so the shared router fixture file
// stays within the size rule while these pages keep growing.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRouterVPNChildDocuments(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	r := NewRouter(cfg, db, nil)

	ctx := context.Background()
	adminUser := &models.User{
		ID:        "admin-vpn-child-test",
		Username:  "adminvpnchild",
		Role:      models.RoleAdmin,
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateUser(ctx, adminUser); err != nil {
		t.Fatalf("failed to seed admin user: %v", err)
	}
	supportUser := &models.User{
		ID:        "support-vpn-child-test",
		Username:  "supportvpnchild",
		Role:      models.RoleSupport,
		Enabled:   true,
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateUser(ctx, supportUser); err != nil {
		t.Fatalf("failed to seed support user: %v", err)
	}

	// 4. The two child documents answer the same gate: Admin and Support reach
	// them, an unauthenticated visitor is redirected to the login page.
	adminSess := &models.SessionData{UserID: adminUser.ID, Username: adminUser.Username, Role: adminUser.Role}
	supportSess := &models.SessionData{UserID: supportUser.ID, Username: supportUser.Username, Role: supportUser.Role}
	for _, role := range []struct {
		name string
		sess *models.SessionData
	}{
		{"admin", adminSess},
		{"support", supportSess},
	} {
		for _, page := range []struct{ path, marker string }{
			{"/vpn/backends", "vpnBackendsTable"},
			{"/vpn/diagnostics", "vpn-forwarder-card"},
		} {
			req := httptest.NewRequest(http.MethodGet, page.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req.WithContext(middleware.WithSession(req.Context(), role.sess)))
			if w.Code != http.StatusOK {
				t.Errorf("%s %s = %d, want 200", role.name, page.path, w.Code)
				continue
			}
			if !strings.Contains(w.Body.String(), page.marker) {
				t.Errorf("%s %s does not render %q", role.name, page.path, page.marker)
			}
		}
	}
	reqChildUnauth := httptest.NewRequest(http.MethodGet, "/vpn/backends", nil)
	wChildUnauth := httptest.NewRecorder()
	r.ServeHTTP(wChildUnauth, reqChildUnauth)
	if wChildUnauth.Code != http.StatusFound || wChildUnauth.Header().Get("Location") != "/login" {
		t.Errorf("expected 302 redirect to /login for unauthenticated /vpn/backends, got %d", wChildUnauth.Code)
	}
}
