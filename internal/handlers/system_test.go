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
