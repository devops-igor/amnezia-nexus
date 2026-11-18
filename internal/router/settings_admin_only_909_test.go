package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

// Route-level contract for the Settings surface: the page, GET /api/settings and
// POST /api/settings/save are Admin-only, while the ordinary backup download
// stays reachable by Support. Every case runs through the real router, the real
// session, CSRF and role middlewares and a real database.

const (
	settingsSaveTitle = "Role Matrix Title"
	settingsSaveBody  = `{"appearance":{"title":"` + settingsSaveTitle + `","logo":"shield","subtitle":"Panel","language":"en"}}`
)

type settingsEntryPoint struct {
	name   string
	method string
	path   string
	body   string
}

var (
	settingsPage     = settingsEntryPoint{"page", http.MethodGet, "/settings", ""}
	settingsRead     = settingsEntryPoint{"read", http.MethodGet, "/api/settings", ""}
	settingsSave     = settingsEntryPoint{"save", http.MethodPost, "/api/settings/save", settingsSaveBody}
	settingsBackupDL = settingsEntryPoint{"backup download", http.MethodGet, "/api/settings/backup/download", ""}
)

func serveAs(t *testing.T, h http.Handler, role models.UserRole, ep settingsEntryPoint) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if ep.body != "" {
		body = []byte(ep.body)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, roleRequest(t, role, ep.method, ep.path, body))
	return w
}

func serveAnonymous(h http.Handler, ep settingsEntryPoint) *httptest.ResponseRecorder {
	req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(ep.body))
	if ep.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	ctx := middleware.WithCSRFToken(req.Context(), "token123")
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
	req.Header.Set(middleware.CSRFHeaderName, "token123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req.WithContext(ctx))
	return w
}

func newSettingsRoleRouter(t *testing.T) (http.Handler, func() models.AppearanceSettings) {
	t.Helper()
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)
	readAppearance := func() models.AppearanceSettings {
		var a models.AppearanceSettings
		_ = db.GetSetting(context.Background(), "appearance", &a)
		return a
	}
	return r, readAppearance
}

// Support is refused on the three restricted entry points with 403, and the
// refused save writes nothing.
func TestSupportDeniedOnRestrictedSettingsEntryPoints(t *testing.T) {
	r, appearance := newSettingsRoleRouter(t)

	for _, ep := range []settingsEntryPoint{settingsPage, settingsRead, settingsSave} {
		t.Run(ep.name, func(t *testing.T) {
			w := serveAs(t, r, models.RoleSupport, ep)
			if w.Code != http.StatusForbidden {
				t.Fatalf("Support %s %s = %d, want 403; body=%s", ep.method, ep.path, w.Code, w.Body.String())
			}
		})
	}

	if got := appearance().Title; got == settingsSaveTitle {
		t.Errorf("refused Support save persisted appearance title %q", got)
	}
}

// Support keeps the ordinary backup download exactly as #893 left it.
func TestSupportKeepsBackupDownload(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)

	w := serveAs(t, r, models.RoleSupport, settingsBackupDL)
	if w.Code != http.StatusOK {
		t.Fatalf("Support backup download = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if _, settings := backupExport(t, w.Body.Bytes()); settings == nil {
		t.Fatal("Support backup carries no settings object")
	}
}

// Admin is unaffected on all four entry points, and the save really persists.
func TestAdminReachesAllSettingsEntryPoints(t *testing.T) {
	r, appearance := newSettingsRoleRouter(t)

	for _, ep := range []settingsEntryPoint{settingsPage, settingsRead, settingsSave, settingsBackupDL} {
		t.Run(ep.name, func(t *testing.T) {
			w := serveAs(t, r, models.RoleAdmin, ep)
			if w.Code != http.StatusOK {
				t.Fatalf("Admin %s %s = %d, want 200; body=%s", ep.method, ep.path, w.Code, w.Body.String())
			}
		})
	}

	if got := appearance().Title; got != settingsSaveTitle {
		t.Errorf("Admin save persisted appearance title %q, want %q", got, settingsSaveTitle)
	}
}

// A plain user stays refused on all four entry points.
func TestUserDeniedOnAllSettingsEntryPoints(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)

	for _, ep := range []settingsEntryPoint{settingsPage, settingsRead, settingsSave, settingsBackupDL} {
		t.Run(ep.name, func(t *testing.T) {
			if w := serveAs(t, r, models.RoleUser, ep); w.Code != http.StatusForbidden {
				t.Fatalf("user %s %s = %d, want 403; body=%s", ep.method, ep.path, w.Code, w.Body.String())
			}
		})
	}
}

// The unauthenticated path is unchanged: the page redirects to login rather than
// answering with a denial, and the API answers 401 rather than 403.
func TestAnonymousSettingsPathUnchanged(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)

	w := serveAnonymous(r, settingsPage)
	if w.Code != http.StatusFound {
		t.Fatalf("anonymous GET /settings = %d, want 302; body=%s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("anonymous GET /settings redirects to %q, want /login", loc)
	}

	for _, ep := range []settingsEntryPoint{settingsRead, settingsSave, settingsBackupDL} {
		t.Run(ep.name, func(t *testing.T) {
			if w := serveAnonymous(r, ep); w.Code != http.StatusUnauthorized {
				t.Fatalf("anonymous %s %s = %d, want 401; body=%s", ep.method, ep.path, w.Code, w.Body.String())
			}
		})
	}
}

// Routes that shared the group with Settings are not part of this decision and
// stay open to Support, while restore stays Admin-only.
func TestSupportKeepsNeighbouringRoutes(t *testing.T) {
	r, _ := newSettingsRoleRouter(t)

	for _, ep := range []settingsEntryPoint{
		{"users page", http.MethodGet, "/users", ""},
		{"vpn page", http.MethodGet, "/vpn", ""},
		{"users api", http.MethodGet, "/api/users", ""},
		{"vpn status", http.MethodGet, "/api/vpn/status", ""},
	} {
		t.Run(ep.name, func(t *testing.T) {
			if w := serveAs(t, r, models.RoleSupport, ep); w.Code != http.StatusOK {
				t.Fatalf("Support %s %s = %d, want 200; body=%s", ep.method, ep.path, w.Code, w.Body.String())
			}
		})
	}

	restore := settingsEntryPoint{"restore", http.MethodPost, "/api/settings/backup/restore", "{}"}
	if w := serveAs(t, r, models.RoleSupport, restore); w.Code != http.StatusForbidden {
		t.Fatalf("Support restore = %d, want 403", w.Code)
	}
}
