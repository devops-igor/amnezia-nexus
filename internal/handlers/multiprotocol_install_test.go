package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/go-chi/chi/v5"
)

type captureMockProtocolManager struct {
	proto          string
	capturedParams map[string]any
}

func (m *captureMockProtocolManager) Protocol() string {
	return m.proto
}

func (m *captureMockProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	m.capturedParams = params
	return nil
}

func (m *captureMockProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	return nil
}

func (m *captureMockProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return []map[string]any{}, nil
}

func (m *captureMockProtocolManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return map[string]any{"client_id": "c1"}, nil
}

func (m *captureMockProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}

func (m *captureMockProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "mock-config", nil
}

func (m *captureMockProtocolManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{"container_running": true, "port": 443}, nil
}

func TestInstallProtocolHandler_VLESSAndNaiveForwarding(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	vlessMock := &captureMockProtocolManager{proto: "vless"}
	naiveMock := &captureMockProtocolManager{proto: "naive"}

	h.registry = manager.NewRegistry()
	h.registry.Register(vlessMock)
	h.registry.Register(naiveMock)

	server := &models.Server{
		Name:      "multi-proto-server",
		Host:      "198.51.100.10",
		SSHPort:   22,
		Protocols: make(map[string]any),
	}
	serverID, err := db.CreateServer(context.Background(), server)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// 1. Test VLESS install forwarding
	vlessReq := models.InstallProtocolRequest{
		Protocol: "vless",
		Port:     "443",
		VLESSOptions: &models.VLESSInstallOptions{
			Port:       "443",
			ServerName: "gateway.icloud.com",
			Flow:       "xtls-rprx-vision",
		},
	}
	body, _ := json.Marshal(vlessReq)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("server_id", fmt.Sprintf("%d", serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.InstallProtocolHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK installing vless, got %d (body: %s)", w.Code, w.Body.String())
	}
	if vlessMock.capturedParams == nil {
		t.Fatalf("expected vlessMock to capture install params")
	}
	vo, ok := vlessMock.capturedParams["vless_options"].(*models.VLESSInstallOptions)
	if !ok || vo == nil || vo.ServerName != "gateway.icloud.com" {
		t.Errorf("vless_options not forwarded correctly: %+v", vlessMock.capturedParams["vless_options"])
	}

	// 2. Test Naive install forwarding
	naiveReq := models.InstallProtocolRequest{
		Protocol: "naive",
		Port:     "443",
		NaiveOptions: &models.NaiveInstallOptions{
			Port:          "443",
			Domain:        "naive.example.com",
			DecoyTemplate: "default",
		},
	}
	body, _ = json.Marshal(naiveReq)
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	rctxNaive := chi.NewRouteContext()
	rctxNaive.URLParams.Add("server_id", fmt.Sprintf("%d", serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctxNaive))
	w = httptest.NewRecorder()
	h.InstallProtocolHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK installing naive, got %d (body: %s)", w.Code, w.Body.String())
	}
	if naiveMock.capturedParams == nil {
		t.Fatalf("expected naiveMock to capture install params")
	}
	no, ok := naiveMock.capturedParams["naive_options"].(*models.NaiveInstallOptions)
	if !ok || no == nil || no.Domain != "naive.example.com" {
		t.Errorf("naive_options not forwarded correctly: %+v", naiveMock.capturedParams["naive_options"])
	}
}
