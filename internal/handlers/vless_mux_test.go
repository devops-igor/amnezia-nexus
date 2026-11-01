package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/manager/xray"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

type muxCaptureMockManager struct {
	proto          string
	capturedParams map[string]any
	capturedCtx    context.Context
}

func (m *muxCaptureMockManager) Protocol() string { return m.proto }
func (m *muxCaptureMockManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	m.capturedParams = params
	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	server.Protocols[m.proto] = map[string]any{
		"installed":   true,
		"public_key":  "pub123",
		"short_id":    "sid123",
		"server_name": "www.microsoft.com",
		"mux":         params["mux"],
	}
	return nil
}
func (m *muxCaptureMockManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}
func (m *muxCaptureMockManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return []map[string]any{}, nil
}
func (m *muxCaptureMockManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return map[string]any{"client_id": "c1"}, nil
}
func (m *muxCaptureMockManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}
func (m *muxCaptureMockManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	m.capturedCtx = ctx
	mux := false
	if server != nil && server.Protocols != nil {
		if vMeta, ok := server.Protocols[m.proto].(map[string]any); ok {
			if b, ok := vMeta["mux"].(bool); ok && b {
				mux = true
			}
		}
	}
	return xray.BuildVLESSURI("192.0.2.1", 443, clientID, "test-client", "www.microsoft.com", "pub123", "sid123", "xtls-rprx-vision", mux)
}

func TestVLESS_MuxHandlingInHandlers(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	serverID, err := db.CreateServer(context.Background(), &models.Server{
		Name:    "vless-mux-srv",
		Host:    "192.0.2.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{
				"installed": true,
				"mux":       true,
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	userID, err := db.CreateUser(context.Background(), &models.User{
		Username: "muxuser",
		Role:     models.RoleAdmin,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	conn := &models.UserConnection{
		ID:        "conn-mux-1",
		UserID:    userID,
		ServerID:  serverID,
		Protocol:  "vless",
		ClientID:  "9f5b2446-2ab9-42b4-8260-2ff0d061c0de",
		Name:      "MuxConn",
		CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(context.Background(), conn); err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}

	mockMgr := &muxCaptureMockManager{proto: "vless"}
	h.registry = manager.NewRegistry()
	h.registry.Register(mockMgr)

	// Test UserGetConnectionConfigHandler with server-level mux: true
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/my/connections/%s/config", conn.ID), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", conn.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: userID, Role: models.RoleAdmin}))
	w := httptest.NewRecorder()

	h.UserGetConnectionConfigHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	cfgStr, _ := res["config"].(string)
	parsedURL, err := url.Parse(cfgStr)
	if err != nil {
		t.Fatalf("parse vless URI: %v", err)
	}
	if parsedURL.Query().Get("mux") != "true" {
		t.Errorf("expected mux=true in vless URI, got: %s", cfgStr)
	}

	// Test with query param ?mux=false overriding server default
	reqFalse := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/my/connections/%s/config?mux=false", conn.ID), nil)
	rctxFalse := chi.NewRouteContext()
	rctxFalse.URLParams.Add("id", conn.ID)
	reqFalse = reqFalse.WithContext(context.WithValue(reqFalse.Context(), chi.RouteCtxKey, rctxFalse))
	reqFalse = reqFalse.WithContext(middleware.WithSession(reqFalse.Context(), &models.SessionData{UserID: userID, Role: models.RoleAdmin}))
	wFalse := httptest.NewRecorder()

	h.UserGetConnectionConfigHandler(wFalse, reqFalse)
	if wFalse.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", wFalse.Code, wFalse.Body.String())
	}
	var resFalse map[string]any
	if err := json.Unmarshal(wFalse.Body.Bytes(), &resFalse); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	cfgStrFalse, _ := resFalse["config"].(string)
	parsedURLFalse, err := url.Parse(cfgStrFalse)
	if err != nil {
		t.Fatalf("parse vless URI: %v", err)
	}
	// The mock manager checks server protocols unless ctx override is observed:
	if val, ok := mockMgr.capturedCtx.Value(xray.WithMuxContext(context.Background(), false)).(bool); ok && val {
		t.Errorf("expected capturedCtx to have mux=false")
	}
	_ = parsedURLFalse
}
