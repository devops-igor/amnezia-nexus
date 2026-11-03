package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/devops-igor/amnezia-nexus/internal/manager/updater"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func newMockUpstreamEngineServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "naiveproxy"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v154.0.8037.49-5",
				"html_url":     "https://github.com/klzgrad/naiveproxy/releases/tag/v154.0.8037.49-5",
				"published_at": time.Now().Format(time.RFC3339),
			})
		case strings.Contains(r.URL.Path, "forwardproxy"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v2.11.7-naive2",
				"html_url":     "https://github.com/klzgrad/forwardproxy/releases/tag/v2.11.7-naive2",
				"published_at": time.Now().Format(time.RFC3339),
			})
		case strings.Contains(r.URL.Path, "caddy"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v2.8.4",
				"html_url":     "https://github.com/caddyserver/caddy/releases/tag/v2.8.4",
				"published_at": time.Now().Format(time.RFC3339),
			})
		case strings.Contains(r.URL.Path, "Xray-core"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v26.10.29",
				"html_url":     "https://github.com/XTLS/Xray-core/releases/tag/v26.10.29",
				"published_at": time.Now().Format(time.RFC3339),
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func setupEngineTestHandlers(t *testing.T) (*Handlers, *models.Server, func()) {
	t.Helper()
	h, db, _ := setupTestHandlers(t)

	upstreamSrv := newMockUpstreamEngineServer(t)
	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	server := &models.Server{
		Name:    "Test Multi-Engine Server",
		Host:    "192.0.2.10",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed":      true,
				"engine_profile": "modern_pq",
				"engine_version": "26.10.28",
			},
			models.ProtocolNaive: map[string]any{
				"installed":      true,
				"caddy_version":  "v2.8.0",
				"plugin_version": "v2.11.7-naive1",
			},
		},
		CreatedAt: time.Now(),
		Status:    models.ReachabilityOnline,
	}

	serverID, err := db.CreateServer(context.Background(), server)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	server.ID = serverID

	cleanup := func() {
		upstreamSrv.Close()
	}
	return h, server, cleanup
}

func TestListServersHandler_EngineStatusRBAC(t *testing.T) {
	h, server, cleanup := setupEngineTestHandlers(t)
	defer cleanup()

	// 1. Admin caller: engine_status MUST be populated
	t.Run("admin receives populated engine_status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "admin-1",
			Role:   models.RoleAdmin,
		}))
		w := httptest.NewRecorder()
		h.ListServersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var servers []models.ServerItemResponse
		if err := json.Unmarshal(w.Body.Bytes(), &servers); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		var found *models.ServerItemResponse
		for i := range servers {
			if servers[i].ID == server.ID {
				found = &servers[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("server %d not found in response", server.ID)
		}

		if found.EngineStatus == nil {
			t.Fatalf("expected EngineStatus to be populated for admin, got nil")
		}

		// Verify VLESS / Xray status
		if vlessStatus, ok := found.EngineStatus["vless"]; !ok || vlessStatus == nil {
			t.Errorf("expected vless status in EngineStatus, got %+v", found.EngineStatus)
		}
		// Verify Caddy status
		if caddyStatus, ok := found.EngineStatus["caddy"]; !ok || caddyStatus == nil {
			t.Errorf("expected caddy status in EngineStatus, got %+v", found.EngineStatus)
		}
	})

	// 2. Support caller: engine_status MUST be omitted
	t.Run("support caller has engine_status omitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "support-1",
			Role:   models.RoleSupport,
		}))
		w := httptest.NewRecorder()
		h.ListServersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var raw []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
			t.Fatalf("failed to decode raw response: %v", err)
		}

		for _, item := range raw {
			if id, ok := item["id"].(float64); ok && int64(id) == server.ID {
				if _, has := item["engine_status"]; has {
					t.Errorf("expected engine_status to be omitted for support, found: %+v", item["engine_status"])
				}
			}
		}
	})

	// 3. Regular user caller: engine_status MUST be omitted
	t.Run("regular user caller has engine_status omitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "user-1",
			Role:   models.RoleUser,
		}))
		w := httptest.NewRecorder()
		h.ListServersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var raw []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
			t.Fatalf("failed to decode raw response: %v", err)
		}

		for _, item := range raw {
			if id, ok := item["id"].(float64); ok && int64(id) == server.ID {
				if _, has := item["engine_status"]; has {
					t.Errorf("expected engine_status to be omitted for regular user, found: %+v", item["engine_status"])
				}
			}
		}
	})

	// 4. Unauthenticated caller: engine_status MUST be omitted
	t.Run("unauthenticated caller has engine_status omitted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
		w := httptest.NewRecorder()
		h.ListServersHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var raw []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
			t.Fatalf("failed to decode raw response: %v", err)
		}

		for _, item := range raw {
			if id, ok := item["id"].(float64); ok && int64(id) == server.ID {
				if _, has := item["engine_status"]; has {
					t.Errorf("expected engine_status to be omitted for unauthenticated caller, found: %+v", item["engine_status"])
				}
			}
		}
	})
}

func TestServerEngineStatusHandler_RBAC(t *testing.T) {
	h, server, cleanup := setupEngineTestHandlers(t)
	defer cleanup()

	targetURL := fmt.Sprintf("/api/servers/%d/engine-status", server.ID)

	makeReq := func(session *models.SessionData, sID int64) *http.Request {
		url := fmt.Sprintf("/api/servers/%d/engine-status", sID)
		req := httptest.NewRequest(http.MethodGet, url, nil)
		routeCtx := chi.NewRouteContext()
		routeCtx.URLParams.Add("server_id", fmt.Sprint(sID))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		if session != nil {
			req = req.WithContext(middleware.WithSession(req.Context(), session))
		}
		return req
	}

	// 1. Admin returns 200 OK with accurate metadata
	t.Run("admin returns 200 with engine status", func(t *testing.T) {
		req := makeReq(&models.SessionData{UserID: "admin-1", Role: models.RoleAdmin}, server.ID)
		w := httptest.NewRecorder()
		h.ServerEngineStatusHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["status"] != "ok" {
			t.Errorf("expected status 'ok', got %v", resp["status"])
		}

		engineStatusRaw, ok := resp["engine_status"].(map[string]any)
		if !ok || engineStatusRaw == nil {
			t.Fatalf("expected engine_status map in response, got %+v", resp)
		}

		if _, hasVless := engineStatusRaw["vless"]; !hasVless {
			t.Errorf("expected vless in engine_status")
		}
		if _, hasCaddy := engineStatusRaw["caddy"]; !hasCaddy {
			t.Errorf("expected caddy in engine_status")
		}
		if _, hasNaive := engineStatusRaw["naive"]; !hasNaive {
			t.Errorf("expected naive in engine_status")
		}
	})

	// 2. Support user receives 403 Forbidden
	t.Run("support user returns 403", func(t *testing.T) {
		req := makeReq(&models.SessionData{UserID: "support-1", Role: models.RoleSupport}, server.ID)
		w := httptest.NewRecorder()
		h.ServerEngineStatusHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for support, got %d", w.Code)
		}
	})

	// 3. Regular user receives 403 Forbidden
	t.Run("regular user returns 403", func(t *testing.T) {
		req := makeReq(&models.SessionData{UserID: "user-1", Role: models.RoleUser}, server.ID)
		w := httptest.NewRecorder()
		h.ServerEngineStatusHandler(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for regular user, got %d", w.Code)
		}
	})

	// 4. Unauthenticated caller receives 401 Unauthorized
	t.Run("unauthenticated returns 401", func(t *testing.T) {
		req := makeReq(nil, server.ID)
		w := httptest.NewRecorder()
		h.ServerEngineStatusHandler(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for unauthenticated, got %d", w.Code)
		}
	})

	// 5. Non-existent server returns 404
	t.Run("non-existent server returns 404", func(t *testing.T) {
		req := makeReq(&models.SessionData{UserID: "admin-1", Role: models.RoleAdmin}, 999999)
		w := httptest.NewRecorder()
		h.ServerEngineStatusHandler(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found for missing server, got %d", w.Code)
		}
	})

	_ = targetURL
}

func TestServerEngineStatus_XrayProfileAwareness(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "Xray-core") {
			// Upstream is at modern CalVer 26.10.29
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v26.10.29",
				"html_url": "https://github.com/XTLS/Xray-core/releases/tag/v26.10.29",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer upstreamSrv.Close()

	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	ctx := context.Background()

	// 1. Legacy Profile: installed 1.8.24 with upstream 26.10.29
	// Should be: UpstreamNewer = true, UpgradeCompatible = false, UpdateAvailable = false
	t.Run("legacy profile incompatibility protection", func(t *testing.T) {
		legacyServer := &models.Server{
			Name: "Legacy Xray Server",
			Host: "192.0.2.11",
			Protocols: map[string]any{
				models.ProtocolVLESS: map[string]any{
					"installed":      true,
					"engine_profile": "legacy",
					"engine_version": "1.8.24",
				},
			},
		}
		sID, err := db.CreateServer(ctx, legacyServer)
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		legacyServer.ID = sID

		statusMap := h.resolveServerEngineStatus(ctx, legacyServer)
		if statusMap == nil {
			t.Fatalf("expected statusMap to be populated")
		}

		vStatus, ok := statusMap["vless"].(updater.EngineStatus)
		if !ok {
			t.Fatalf("expected updater.EngineStatus for vless, got %T", statusMap["vless"])
		}

		if !vStatus.UpstreamNewer {
			t.Errorf("expected UpstreamNewer = true for legacy 1.8.24 vs 26.10.29")
		}
		if vStatus.UpgradeCompatible {
			t.Errorf("expected UpgradeCompatible = false for legacy profile crossing into modern 26.x")
		}
		if vStatus.UpdateAvailable {
			t.Errorf("expected UpdateAvailable = false due to profile incompatibility")
		}
		if vStatus.Channel != "legacy" {
			t.Errorf("expected channel 'legacy', got %q", vStatus.Channel)
		}
	})

	// 2. Modern PQ Profile: installed 26.10.28 with upstream 26.10.29
	// Should be: UpstreamNewer = true, UpgradeCompatible = true, UpdateAvailable = true
	t.Run("modern_pq profile safe update", func(t *testing.T) {
		modernServer := &models.Server{
			Name: "Modern PQ Xray Server",
			Host: "192.0.2.12",
			Protocols: map[string]any{
				models.ProtocolVLESS: map[string]any{
					"installed":      true,
					"engine_profile": "modern_pq",
					"engine_version": "26.10.28",
				},
			},
		}
		sID, err := db.CreateServer(ctx, modernServer)
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		modernServer.ID = sID

		statusMap := h.resolveServerEngineStatus(ctx, modernServer)
		if statusMap == nil {
			t.Fatalf("expected statusMap to be populated")
		}

		vStatus, ok := statusMap["vless"].(updater.EngineStatus)
		if !ok {
			t.Fatalf("expected updater.EngineStatus for vless, got %T", statusMap["vless"])
		}

		if !vStatus.UpstreamNewer {
			t.Errorf("expected UpstreamNewer = true for 26.10.28 vs 26.10.29")
		}
		if !vStatus.UpgradeCompatible {
			t.Errorf("expected UpgradeCompatible = true for modern_pq profile on 26.x")
		}
		if !vStatus.UpdateAvailable {
			t.Errorf("expected UpdateAvailable = true for compatible modern_pq update")
		}
		if vStatus.Channel != "modern_pq" {
			t.Errorf("expected channel 'modern_pq', got %q", vStatus.Channel)
		}
	})

	// 3. Modern PQ Profile: installed 26.10.29 (already latest)
	// Should be: UpstreamNewer = false, UpgradeCompatible = true, UpdateAvailable = false
	t.Run("modern_pq profile up to date", func(t *testing.T) {
		upToDateServer := &models.Server{
			Name: "UpToDate Modern Server",
			Host: "192.0.2.13",
			Protocols: map[string]any{
				models.ProtocolVLESS: map[string]any{
					"installed":      true,
					"engine_profile": "modern_pq",
					"engine_version": "26.10.29",
				},
			},
		}
		sID, err := db.CreateServer(ctx, upToDateServer)
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		upToDateServer.ID = sID

		statusMap := h.resolveServerEngineStatus(ctx, upToDateServer)
		if statusMap == nil {
			t.Fatalf("expected statusMap to be populated")
		}

		vStatus, ok := statusMap["vless"].(updater.EngineStatus)
		if !ok {
			t.Fatalf("expected updater.EngineStatus for vless, got %T", statusMap["vless"])
		}

		if vStatus.UpstreamNewer {
			t.Errorf("expected UpstreamNewer = false when installed is 26.10.29")
		}
		if vStatus.UpdateAvailable {
			t.Errorf("expected UpdateAvailable = false when already up to date")
		}
	})
}

func TestServerEngineStatus_NaiveAndCaddyComponents(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "caddy"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2.8.4",
				"html_url": "https://github.com/caddyserver/caddy/releases/tag/v2.8.4",
			})
		case strings.Contains(r.URL.Path, "forwardproxy"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2.11.7-naive2",
				"html_url": "https://github.com/klzgrad/forwardproxy/releases/tag/v2.11.7-naive2",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstreamSrv.Close()

	checker := updater.NewReleaseChecker(
		updater.WithBaseURL(upstreamSrv.URL),
		updater.WithHTTPClient(upstreamSrv.Client()),
	)
	h.SetUpdaterService(checker)

	ctx := context.Background()
	naiveServer := &models.Server{
		Name: "Naive Server",
		Host: "192.0.2.14",
		Protocols: map[string]any{
			models.ProtocolNaive: map[string]any{
				"installed":      true,
				"caddy_version":  "v2.8.0",
				"plugin_version": "v2.11.7-naive1",
			},
		},
	}
	sID, err := db.CreateServer(ctx, naiveServer)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	naiveServer.ID = sID

	statusMap := h.resolveServerEngineStatus(ctx, naiveServer)
	if statusMap == nil {
		t.Fatalf("expected statusMap to be populated")
	}

	// 1. Caddy Core component reporting
	caddyStatus, ok := statusMap["caddy"].(updater.EngineStatus)
	if !ok {
		t.Fatalf("expected updater.EngineStatus for caddy, got %T", statusMap["caddy"])
	}
	if caddyStatus.Protocol != "caddy" {
		t.Errorf("expected caddy protocol 'caddy', got %q", caddyStatus.Protocol)
	}
	if caddyStatus.InstalledVersion != "v2.8.0" {
		t.Errorf("expected installed version 'v2.8.0', got %q", caddyStatus.InstalledVersion)
	}
	if caddyStatus.LatestVersion != "v2.8.4" {
		t.Errorf("expected latest version 'v2.8.4', got %q", caddyStatus.LatestVersion)
	}
	if !caddyStatus.UpdateAvailable {
		t.Errorf("expected caddy UpdateAvailable = true (v2.8.0 < v2.8.4)")
	}

	// 2. Naive ForwardProxy Plugin component reporting
	naiveStatus, ok := statusMap["naive"].(updater.EngineStatus)
	if !ok {
		t.Fatalf("expected updater.EngineStatus for naive, got %T", statusMap["naive"])
	}
	if naiveStatus.Protocol != "naive" {
		t.Errorf("expected naive protocol 'naive', got %q", naiveStatus.Protocol)
	}
	if naiveStatus.InstalledVersion != "v2.11.7-naive1" {
		t.Errorf("expected installed version 'v2.11.7-naive1', got %q", naiveStatus.InstalledVersion)
	}
	if naiveStatus.LatestVersion != "v2.11.7-naive2" {
		t.Errorf("expected latest version 'v2.11.7-naive2', got %q", naiveStatus.LatestVersion)
	}
	if !naiveStatus.UpdateAvailable {
		t.Errorf("expected naive UpdateAvailable = true (v2.11.7-naive1 < v2.11.7-naive2)")
	}
}

func TestServerEngineStatus_UninstalledProtocols(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	ctx := context.Background()
	server := &models.Server{
		Name: "Uninstalled Protocols Server",
		Host: "192.0.2.15",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{
				"installed": false,
			},
			models.ProtocolNaive: map[string]any{
				"installed": false,
			},
			"awg": map[string]any{
				"installed": true,
			},
		},
	}
	sID, err := db.CreateServer(ctx, server)
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}
	server.ID = sID

	statusMap := h.resolveServerEngineStatus(ctx, server)
	if len(statusMap) != 0 {
		t.Errorf("expected empty engine status for server with no installed engines, got %+v", statusMap)
	}
}

func TestServerEngineStatus_RouterSubrouterMount(t *testing.T) {
	h, server, cleanup := setupEngineTestHandlers(t)
	defer cleanup()

	// Build subrouter matching router.go registration
	r := chi.NewRouter()
	r.Route("/api/servers", func(r chi.Router) {
		r.Get("/", h.ListServersHandler)
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireAdmin)
			r.Get("/{server_id}/engine-status", h.ServerEngineStatusHandler)
		})
	})

	// 1. Admin gets 200 through mounted router
	t.Run("router admin 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/servers/%d/engine-status", server.ID), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "admin-1",
			Role:   models.RoleAdmin,
		}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
		}
	})

	// 2. Support gets 403 through mounted router
	t.Run("router support 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/servers/%d/engine-status", server.ID), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
			UserID: "support-1",
			Role:   models.RoleSupport,
		}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	// 3. Unauthenticated gets 401 through mounted router
	t.Run("router unauthenticated 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/servers/%d/engine-status", server.ID), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})
}
