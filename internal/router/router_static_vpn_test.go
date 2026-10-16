package router

import (
	"bytes"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/web"
)

func TestRouterVPNCompanionStaticAssetsServing(t *testing.T) {
	db, cfg := setupTestRouterDB(t)
	r := NewRouter(cfg, db, nil)

	staticSubFS, err := web.GetStaticSubFS()
	if err != nil {
		t.Fatalf("GetStaticSubFS failed: %v", err)
	}

	vpnAssets := []string{
		"/static/js/vpn/backends.js",
		"/static/js/vpn/health_problems.js",
		"/static/js/vpn/health_summary.js",
		"/static/js/vpn/charts.js",
		"/static/js/vpn/sessions.js",
		"/static/js/vpn/page.js",
	}

	for _, asset := range vpnAssets {
		t.Run(asset, func(t *testing.T) {
			relPath := strings.TrimPrefix(asset, "/static/")
			expectedBytes, err := fs.ReadFile(staticSubFS, relPath)
			if err != nil {
				t.Fatalf("failed to read embedded %s: %v", relPath, err)
			}
			if len(bytes.TrimSpace(expectedBytes)) == 0 {
				t.Fatalf("embedded %s is empty or whitespace", relPath)
			}

			req := httptest.NewRequest(http.MethodGet, asset, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected HTTP 200 for %s, got %d", asset, w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
				t.Errorf("expected Content-Type containing 'javascript' for %s, got %q", asset, ct)
			}
			if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
				t.Errorf("expected Cache-Control 'public, max-age=86400' for %s, got %q", asset, cc)
			}
			if !bytes.Equal(w.Body.Bytes(), expectedBytes) {
				t.Errorf("served bytes do not match embedded bytes for %s (len served=%d, len embedded=%d)",
					asset, w.Body.Len(), len(expectedBytes))
			}
		})
	}

	// Non-existent static asset returns 404 without redirect or HTML fallback
	t.Run("NonExistentVPNAssetReturns404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/static/js/vpn/nonexistent_file.js", nil)
		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected HTTP 404 for non-existent static asset, got %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Errorf("expected non-HTML response for 404 static asset, got %q", ct)
		}
	})
}
