package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

func TestScanRealitySNIHandler_Unit(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	// Case 1: Invalid server_id
	t.Run("Invalid server_id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/servers/abc/reality/scan-sni", nil)
		w := httptest.NewRecorder()
		h.ScanRealitySNIHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request, got %d", w.Code)
		}
	})

	// Case 2: Server not found
	t.Run("Server not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/servers/9999/reality/scan-sni", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("server_id", "9999")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		h.ScanRealitySNIHandler(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 Not Found, got %d", w.Code)
		}
	})

	// Case 3: Success with real server record
	t.Run("Success with server record", func(t *testing.T) {
		serverID, err := db.CreateServer(context.Background(), &models.Server{
			Name:    "real-test-server",
			Host:    "127.0.0.1",
			SSHPort: 22,
			SSHUser: "root",
		})
		if err != nil {
			t.Fatalf("failed to create server: %v", err)
		}

		body := `{"domains":["127.0.0.1.nip.io"],"concurrency":1,"timeout_sec":1}`
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/reality/scan-sni", serverID), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("server_id", fmt.Sprintf("%d", serverID))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		h.ScanRealitySNIHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "server_ip") {
			t.Errorf("expected response to contain server_ip, got %s", w.Body.String())
		}
	})
}
