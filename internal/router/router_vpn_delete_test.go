package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestRouter_VPNDeleteBackendRoute(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	r := NewRouter(cfg, db, nil)
	ctx := context.Background()

	// Seed regular user for non-admin check
	_, err := db.CreateUser(ctx, &models.User{
		ID:        "user-regular-id",
		Username:  "regularuser",
		Role:      models.RoleUser,
		Enabled:   true,
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to seed regular user: %v", err)
	}

	// 1. Unauthenticated request -> 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodPost, "/api/vpn/backends/1/delete", nil)
	ctxUnauth := middleware.WithCSRFToken(ctx, "test-csrf-token")
	reqUnauth = reqUnauth.WithContext(ctxUnauth)
	reqUnauth.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "test-csrf-token"})
	reqUnauth.Header.Set(middleware.CSRFHeaderName, "test-csrf-token")
	wUnauth := httptest.NewRecorder()
	r.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for unauthenticated request, got %d (body: %s)", wUnauth.Code, wUnauth.Body.String())
	}

	// 2. Regular user (non-admin) -> 403 Forbidden
	userCtx := middleware.WithSession(ctx, &models.SessionData{
		UserID:   "user-regular-id",
		Username: "regularuser",
		Role:     models.RoleUser,
	})
	userCtx = middleware.WithCSRFToken(userCtx, "test-csrf-token")
	reqUser := httptest.NewRequest(http.MethodPost, "/api/vpn/backends/1/delete", nil).WithContext(userCtx)
	reqUser.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "test-csrf-token"})
	reqUser.Header.Set(middleware.CSRFHeaderName, "test-csrf-token")
	wUser := httptest.NewRecorder()
	r.ServeHTTP(wUser, reqUser)
	if wUser.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for regular user, got %d", wUser.Code)
	}

	// 3. Authenticated Admin request -> 200 OK (routed to VPNDeleteBackendHandler; vpnSvc is nil in test router DB setup)
	adminCtx := middleware.WithSession(ctx, &models.SessionData{
		UserID:   "admin-id",
		Username: "admin",
		Role:     models.RoleAdmin,
	})
	adminCtx = middleware.WithCSRFToken(adminCtx, "test-csrf-token")
	reqAdmin := httptest.NewRequest(http.MethodPost, "/api/vpn/backends/1/delete", nil).WithContext(adminCtx)
	reqAdmin.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "test-csrf-token"})
	reqAdmin.Header.Set(middleware.CSRFHeaderName, "test-csrf-token")
	wAdmin := httptest.NewRecorder()
	r.ServeHTTP(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admin user, got %d (body: %s)", wAdmin.Code, wAdmin.Body.String())
	}

	// 4. Verify DELETE /api/vpn/backends/1 backwards compatibility
	reqDelete := httptest.NewRequest(http.MethodDelete, "/api/vpn/backends/1", nil).WithContext(adminCtx)
	reqDelete.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "test-csrf-token"})
	reqDelete.Header.Set(middleware.CSRFHeaderName, "test-csrf-token")
	wDelete := httptest.NewRecorder()
	r.ServeHTTP(wDelete, reqDelete)
	if wDelete.Code != http.StatusOK {
		t.Errorf("expected 200 OK for DELETE admin user, got %d (body: %s)", wDelete.Code, wDelete.Body.String())
	}
}
