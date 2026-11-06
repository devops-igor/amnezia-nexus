package router

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// These tests exercise the four #678 policy endpoints through the real router,
// the real middlewares (session + CSRF + RequireAdmin) and a real SQLite
// database. They assert persistence and authorization outcomes, not mocks of
// the handlers under test.

// adminRequest builds a request carrying an admin session and a valid CSRF pair.
func adminRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "policy-admin",
		Role:   models.RoleAdmin,
	})
	ctx = middleware.WithCSRFToken(ctx, "token123")
	req = req.WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
	req.Header.Set(middleware.CSRFHeaderName, "token123")
	return req
}

// roleRequest builds a request carrying a session with the given role.
func roleRequest(t *testing.T, role models.UserRole, method, target string, body []byte) *http.Request {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	ctx := middleware.WithSession(req.Context(), &models.SessionData{
		UserID: "policy-" + string(role),
		Role:   role,
	})
	ctx = middleware.WithCSRFToken(ctx, "token123")
	req = req.WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
	req.Header.Set(middleware.CSRFHeaderName, "token123")
	return req
}

// seedPolicySessions creates the DB users the session middleware validates
// against, so RequireAdmin's active-user check passes for admins and fails
// authorization (not authentication) for lower roles.
func seedPolicySessions(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := context.Background()
	for _, u := range []struct {
		id   string
		name string
		role models.UserRole
	}{
		{"policy-admin", "policy-admin", models.RoleAdmin},
		{"policy-support", "policy-support", models.RoleSupport},
		{"policy-user", "policy-user", models.RoleUser},
	} {
		if _, err := db.CreateUser(ctx, &models.User{
			ID:        u.id,
			Username:  u.name,
			Role:      u.role,
			Enabled:   true,
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("failed to seed %s user: %v", u.name, err)
		}
	}
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode JSON response (status %d): %v", w.Code, err)
	}
	return out
}

// Acceptance A1: a fresh install must read back as disabled with no preset, so
// the existing all-proxy route is preserved without any migration.
func TestGetPolicyDefaultsToDisabled(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/policy = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	out := decodeJSON(t, w)
	if enabled, _ := out["enabled"].(bool); enabled {
		t.Errorf("fresh install reports enabled=true, want false (all-proxy default)")
	}
	if preset, _ := out["preset"].(string); preset != "" {
		t.Errorf("fresh install reports preset=%q, want empty", preset)
	}
	if interval, _ := out["sync_interval_seconds"].(float64); int64(interval) != int64(policy.DefaultSyncInterval/time.Second) {
		t.Errorf("fresh install sync interval = %v, want %d", out["sync_interval_seconds"], int64(policy.DefaultSyncInterval/time.Second))
	}
}

// The original four endpoints must all reject non-admin roles, including reads.
func TestPolicyEndpointsRejectNonAdmin(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	validBody, err := json.Marshal(policy.DefaultSettings())
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}

	endpoints := []struct {
		method string
		target string
		body   []byte
	}{
		{http.MethodGet, "/api/vpn/policy", nil},
		{http.MethodPut, "/api/vpn/policy", validBody},
		{http.MethodPost, "/api/vpn/policy/sync", nil},
		{http.MethodGet, "/api/vpn/policy/stats", nil},
	}

	for _, role := range []models.UserRole{models.RoleUser, models.RoleSupport} {
		for _, ep := range endpoints {
			t.Run(string(role)+" "+ep.method+" "+ep.target, func(t *testing.T) {
				w := httptest.NewRecorder()
				r.ServeHTTP(w, roleRequest(t, role, ep.method, ep.target, ep.body))
				if w.Code != http.StatusForbidden {
					t.Fatalf("%s %s as %s = %d, want 403", ep.method, ep.target, role, w.Code)
				}
			})
		}
	}

	// Unauthenticated access must be rejected too.
	for _, ep := range endpoints {
		t.Run("anonymous "+ep.method+" "+ep.target, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.target, bytes.NewReader(ep.body))
			ctx := middleware.WithCSRFToken(req.Context(), "token123")
			req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName, Value: "token123"})
			req.Header.Set(middleware.CSRFHeaderName, "token123")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req.WithContext(ctx))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s anonymous = %d, want 401", ep.method, ep.target, w.Code)
			}
		})
	}
}

// Acceptance A4: invalid settings are rejected and, critically, do NOT overwrite
// the stored configuration.
func TestPutPolicyRejectsInvalidWithoutOverwriting(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	// Store a known-good record first (enabled=false so activation is a no-op).
	good := policy.DefaultSettings()
	good.Preset = policy.PresetGeoblock
	goodBody, err := json.Marshal(good)
	if err != nil {
		t.Fatalf("marshal good settings: %v", err)
	}
	wGood := httptest.NewRecorder()
	r.ServeHTTP(wGood, adminRequest(t, http.MethodPut, "/api/vpn/policy", goodBody))
	if wGood.Code != http.StatusOK {
		t.Fatalf("PUT valid settings = %d, want 200; body=%s", wGood.Code, wGood.Body.String())
	}

	// Now attempt several invalid records; each must 400 and leave the row intact.
	invalid := []struct {
		name string
		body map[string]any
	}{
		{"ssrf internal target", map[string]any{
			"enabled": false, "preset": "custom",
			"custom_urls": []string{"https://10.0.0.5/x.lst"}, "sync_interval_seconds": 3600,
		}},
		{"cloud metadata target", map[string]any{
			"enabled": false, "preset": "custom",
			"custom_urls": []string{"https://169.254.169.254/latest/meta-data/"}, "sync_interval_seconds": 3600,
		}},
		{"http scheme", map[string]any{
			"enabled": false, "preset": "custom",
			"custom_urls": []string{"http://lists.example/x.lst"}, "sync_interval_seconds": 3600,
		}},
		{"interval below minimum", map[string]any{
			"enabled": false, "preset": "geoblock", "sync_interval_seconds": 60,
		}},
		{"interval above maximum", map[string]any{
			"enabled": false, "preset": "geoblock", "sync_interval_seconds": 60 * 60 * 48,
		}},
		{"unknown preset", map[string]any{
			"enabled": false, "preset": "russia_outside", "sync_interval_seconds": 3600,
		}},
		{"preset mixed with custom urls", map[string]any{
			"enabled": false, "preset": "geoblock",
			"custom_urls": []string{"https://lists.example/x.lst"}, "sync_interval_seconds": 3600,
		}},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("PUT invalid (%s) = %d, want 400; body=%s", tc.name, w.Code, w.Body.String())
			}

			// The stored record must still be the good one.
			var stored policy.Settings
			if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
				t.Fatalf("read back stored settings: %v", err)
			}
			if stored.Preset != policy.PresetGeoblock {
				t.Fatalf("rejected request overwrote stored preset: got %q, want %q (value %+v)",
					stored.Preset, policy.PresetGeoblock, stored)
			}
			if stored.Enabled {
				t.Fatalf("rejected request enabled policy routing: %+v", stored)
			}
		})
	}
}

// Settings must survive a simulated restart: a new router over the same database
// reads the previously persisted record.
func TestPolicySettingsSurviveRestart(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	saved := policy.DefaultSettings()
	saved.Preset = policy.PresetAntifilterDomains
	saved.SyncInterval = int64(2 * time.Hour / time.Second)
	body, err := json.Marshal(saved)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wSave := httptest.NewRecorder()
	r.ServeHTTP(wSave, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if wSave.Code != http.StatusOK {
		t.Fatalf("PUT = %d, want 200; body=%s", wSave.Code, wSave.Body.String())
	}

	// "Restart": a brand new router instance over the same DB handle, which is what
	// a process restart produces once the row is durable.
	r2 := NewRouter(cfg, db, nil)
	wGet := httptest.NewRecorder()
	r2.ServeHTTP(wGet, adminRequest(t, http.MethodGet, "/api/vpn/policy", nil))
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET after restart = %d, want 200", wGet.Code)
	}
	out := decodeJSON(t, wGet)
	if preset, _ := out["preset"].(string); preset != string(policy.PresetAntifilterDomains) {
		t.Errorf("preset after restart = %q, want %q", preset, policy.PresetAntifilterDomains)
	}
	if interval, _ := out["sync_interval_seconds"].(float64); int64(interval) != int64(2*time.Hour/time.Second) {
		t.Errorf("sync interval after restart = %v, want %d", out["sync_interval_seconds"], int64(2*time.Hour/time.Second))
	}
}

// Acceptance A3: enabling with no reachable policy source must fail with a useful
// error and must NOT leave the stored record enabled. This exercises the real
// activation path; with no VPN data plane in this harness the failure is the
// prerequisite rejection rather than a successful activation.
func TestPutPolicyEnableFailsClosedWithoutDataPlane(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	enable := policy.DefaultSettings()
	enable.Enabled = true
	enable.Preset = policy.PresetGeoblock
	body, err := json.Marshal(enable)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPut, "/api/vpn/policy", body))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("PUT enable without data plane = %d, want 422; body=%s", w.Code, w.Body.String())
	}

	// The rollback must have restored the previous (disabled) record.
	var stored policy.Settings
	if err := db.GetSetting(context.Background(), policy.SettingsKey, &stored); err != nil {
		t.Fatalf("read back settings: %v", err)
	}
	if stored.Enabled {
		t.Fatalf("failed activation left the record enabled: %+v", stored)
	}
}

// Sync must fail with a clear response when policy routing was never started
// rather than silently reporting success.
func TestSyncPolicyWithoutStartReportsFailure(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodPost, "/api/vpn/policy/sync", nil))
	if w.Code == http.StatusOK {
		t.Fatalf("POST /api/vpn/policy/sync with no active policy = 200, want an error status; body=%s", w.Body.String())
	}
}

// Stats must expose only aggregate counters: no client addresses, no queried
// domains, no credentials.
func TestPolicyStatsExposeAggregateCountersOnly(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	seedPolicySessions(t, db)
	r := NewRouter(cfg, db, nil)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, adminRequest(t, http.MethodGet, "/api/vpn/policy/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/policy/stats = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	out := decodeJSON(t, w)
	for _, key := range []string{
		"proxy_bytes", "direct_bytes", "proxy_drops", "direct_drops",
		"route_cache", "route_sessions", "active_rules", "enabled",
	} {
		if _, ok := out[key]; !ok {
			t.Errorf("stats response missing %q; got %v", key, out)
		}
	}

	// Negative assertions: none of the disallowed fields may appear.
	for _, forbidden := range []string{
		"domains", "queried_domains", "dns_history", "clients", "client_ip",
		"private_ip", "credentials", "password", "api_key", "sessions",
	} {
		if _, ok := out[forbidden]; ok {
			t.Errorf("stats response leaked disallowed field %q", forbidden)
		}
	}
}
