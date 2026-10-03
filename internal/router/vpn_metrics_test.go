package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestVPNMetricsSignedCookieAuthorization(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	if _, err := db.CreateUser(t.Context(), &models.User{ID: "metrics-user", Username: "metrics-user", Enabled: true, Role: models.RoleUser}); err != nil {
		t.Fatal(err)
	}
	r := NewRouter(cfg, db, nil)
	for _, tc := range []struct {
		name    string
		session *models.SessionData
		want    int
	}{
		{"anonymous", nil, http.StatusUnauthorized},
		{"admin", &models.SessionData{UserID: "admin-id", Role: models.RoleAdmin}, http.StatusOK},
		{"ordinary user", &models.SessionData{UserID: "metrics-user", Role: models.RoleUser}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/vpn/metrics", nil)
			if tc.session != nil {
				cookies := httptest.NewRecorder()
				if err := middleware.SetSessionCookie(cookies, tc.session, cfg.SecretKey, 3600); err != nil {
					t.Fatal(err)
				}
				req.AddCookie(cookies.Result().Cookies()[0])
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status=%d; want %d", w.Code, tc.want)
			}
			if tc.want == http.StatusOK {
				if w.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
					t.Fatal("invalid Prometheus content type")
				}
				text := w.Body.String()
				if !strings.HasSuffix(text, "\n") || len(text) > 1500 || !strings.Contains(text, "_bucket{le=\"+Inf\"} 0") || !strings.Contains(text, "_count 0") {
					t.Fatalf("invalid bounded histogram: %s", text)
				}
			}
		})
	}
}
