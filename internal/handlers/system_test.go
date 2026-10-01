package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSystemHandlers(t *testing.T) {
	h, _, cfg := setupTestHandlers(t)

	t.Run("HealthHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		w := httptest.NewRecorder()
		h.HealthHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp HealthResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Status != "ok" || resp.Version != cfg.AppVersion {
			t.Errorf("unexpected health response: %+v", resp)
		}
		if resp.ActiveEngine != "custom" {
			t.Errorf("expected active_engine custom, got %q", resp.ActiveEngine)
		}
		if resp.ReturnRouteOwner != "custom" {
			t.Errorf("expected return_route_owner custom, got %q", resp.ReturnRouteOwner)
		}
	})

	t.Run("HealthHandler_UpstreamEngine", func(t *testing.T) {
		if h.vpnSvc != nil {
			_ = h.vpnSvc.SetClientAWGEngine("upstream")
			defer func() { _ = h.vpnSvc.SetClientAWGEngine("custom") }()
		}

		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		w := httptest.NewRecorder()
		h.HealthHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp HealthResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.ActiveEngine != "upstream" {
			t.Errorf("expected active_engine upstream, got %q", resp.ActiveEngine)
		}
		if resp.ReturnRouteOwner != "upstream" {
			t.Errorf("expected return_route_owner upstream, got %q", resp.ReturnRouteOwner)
		}
	})

	t.Run("VersionHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
		w := httptest.NewRecorder()
		h.VersionHandler(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp["version"] != cfg.AppVersion {
			t.Errorf("expected version %q, got %q", cfg.AppVersion, resp["version"])
		}
		if resp["codename"] != cfg.AppCodename {
			t.Errorf("expected codename %q, got %q", cfg.AppCodename, resp["codename"])
		}
	})
}
