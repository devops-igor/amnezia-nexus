package router

// The retired VPN child routes answer the same gate as the page they lead to: an
// administrator and a support user both reach the redirect, and an unauthenticated
// visitor is still sent to the login page rather than being told the route is gone.
//
// #1006 merged the three VPN documents back into one page, so /vpn/backends and
// /vpn/diagnostics redirect into its sections. These cases keep what the split
// guaranteed about the gate and replace the old "renders its own document"
// assertion - which is the behaviour this delivery retires - with the redirect it
// actually ships.

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

func TestRouterVPNChildRoutesRedirectIntoTheMergedPage(t *testing.T) {
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

	adminSess := &models.SessionData{UserID: adminUser.ID, Username: adminUser.Username, Role: adminUser.Role}
	supportSess := &models.SessionData{UserID: supportUser.ID, Username: supportUser.Username, Role: supportUser.Role}

	// 1. Both roles reach a redirect that names the section now owning the content.
	for _, role := range []struct {
		name string
		sess *models.SessionData
	}{
		{"admin", adminSess},
		{"support", supportSess},
	} {
		for _, page := range []struct{ path, location string }{
			{"/vpn/backends", "/vpn?section=backends"},
			{"/vpn/diagnostics", "/vpn?section=diagnostics"},
		} {
			req := httptest.NewRequest(http.MethodGet, page.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req.WithContext(middleware.WithSession(req.Context(), role.sess)))
			if w.Code != http.StatusFound {
				t.Errorf("%s %s = %d, want 302", role.name, page.path, w.Code)
				continue
			}
			if got := w.Header().Get("Location"); got != page.location {
				t.Errorf("%s %s redirects to %q, want %q", role.name, page.path, got, page.location)
			}
			// The redirect must not restate a fragment: a redirect target's own
			// fragment is REPLACED by the one the visitor already carried, so
			// naming one here would discard the legacy deep link being followed.
			if strings.Contains(w.Header().Get("Location"), "#") {
				t.Errorf("%s %s redirect carries a fragment, which would discard the legacy one: %q",
					role.name, page.path, w.Header().Get("Location"))
			}
		}
	}

	// 2. An unauthenticated visitor is still sent to the login page.
	for _, path := range []string{"/vpn/backends", "/vpn/diagnostics"} {
		reqUnauth := httptest.NewRequest(http.MethodGet, path, nil)
		wUnauth := httptest.NewRecorder()
		r.ServeHTTP(wUnauth, reqUnauth)
		if wUnauth.Code != http.StatusFound || wUnauth.Header().Get("Location") != "/login" {
			t.Errorf("expected 302 redirect to /login for unauthenticated %s, got %d %q",
				path, wUnauth.Code, wUnauth.Header().Get("Location"))
		}
	}
}
