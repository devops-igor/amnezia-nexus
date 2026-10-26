package router

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/handlers"
	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestScanRealitySNI_RBAC(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	reg := manager.NewRegistry()

	h := handlers.NewHandlers(handlers.Dependencies{
		Config:   cfg,
		DB:       db,
		Registry: reg,
	})

	r := NewRouterWithOptions(Options{
		Config:   cfg,
		DB:       db,
		Handlers: h,
	})

	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:    "sni-test-server",
		Host:    "127.0.0.1",
		SSHPort: 22,
		SSHUser: "root",
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	_, _ = db.CreateUser(context.Background(), &models.User{
		ID:       "user-1",
		Username: "regular-user",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	_, _ = db.CreateUser(context.Background(), &models.User{
		ID:       "support-1",
		Username: "support-user",
		Role:     models.RoleSupport,
		Enabled:  true,
	})

	targetURL := fmt.Sprintf("/api/servers/%d/reality/scan-sni", serverID)
	csrfTok := "csrf-token-test"

	newReq := func(role models.UserRole, body string) *http.Request {
		var bodyReader *strings.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		} else {
			bodyReader = strings.NewReader("")
		}
		req := httptest.NewRequest(http.MethodPost, targetURL, bodyReader)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(middleware.CSRFHeaderName, csrfTok)
		req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: csrfTok})
		req = req.WithContext(middleware.WithCSRFToken(req.Context(), csrfTok))

		if role != "" {
			uid := "user-1"
			if role == models.RoleAdmin {
				uid = "admin-id"
			} else if role == models.RoleSupport {
				uid = "support-1"
			}
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   uid,
				Username: string(role) + "-user",
				Role:     role,
			}))
		}
		return req
	}

	// Case 1: Unauthenticated -> 401 Unauthorized
	t.Run("Unauthenticated gets 401", func(t *testing.T) {
		req := newReq("", "")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d (body: %s)", w.Code, w.Body.String())
		}
	})

	// Case 2: Regular user -> 403 Forbidden
	t.Run("User role gets 403", func(t *testing.T) {
		req := newReq(models.RoleUser, "")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for regular user, got %d (body: %s)", w.Code, w.Body.String())
		}
	})

	// Case 3: Support role -> 403 Forbidden (RequireAdmin is strict!)
	t.Run("Support role gets 403", func(t *testing.T) {
		req := newReq(models.RoleSupport, "")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for support role on scan-sni, got %d (body: %s)", w.Code, w.Body.String())
		}
	})

	// Case 4: Admin role -> 200 OK
	t.Run("Admin role gets 200", func(t *testing.T) {
		body := `{"domains":["127.0.0.1.nip.io"],"concurrency":1,"timeout_sec":1}`
		req := newReq(models.RoleAdmin, body)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK for admin on scan-sni, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "server_ip") {
			t.Errorf("expected response to contain server_ip, got: %s", w.Body.String())
		}
	})
}
