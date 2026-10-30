package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/manager"
	"github.com/devops-igor/amnezia-nexus/internal/middleware"
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
	if server.Protocols == nil {
		server.Protocols = make(map[string]any)
	}
	server.Protocols[m.proto] = map[string]any{
		"installed":   true,
		"public_key":  "pubkey123",
		"short_id":    "shortid123",
		"server_name": "gateway.icloud.com",
		"flow":        "xtls-rprx-vision",
	}
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

	adminSession := &models.SessionData{UserID: "admin-1", Username: "admin", Role: models.RoleAdmin}

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
	req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
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
	req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
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

func TestInstallAndUninstallProtocolHandler_AdminRBAC(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	vlessMock := &captureMockProtocolManager{proto: "vless"}
	naiveMock := &captureMockProtocolManager{proto: "naive"}
	awgMock := &captureMockProtocolManager{proto: "awg"}

	h.registry = manager.NewRegistry()
	h.registry.Register(vlessMock)
	h.registry.Register(naiveMock)
	h.registry.Register(awgMock)

	server := &models.Server{
		Name:      "rbac-test-server",
		Host:      "198.51.100.10",
		SSHPort:   22,
		Protocols: map[string]any{"vless": map[string]any{"installed": true}, "naive": map[string]any{"installed": true}, "awg": map[string]any{"installed": true}},
	}
	serverID, err := db.CreateServer(context.Background(), server)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	testCases := []struct {
		name       string
		action     string // "install" or "uninstall"
		proto      string
		role       models.UserRole
		wantStatus int
	}{
		// Install: Support denied on VLESS and Naive
		{"Install VLESS Support", "install", "vless", models.RoleSupport, http.StatusForbidden},
		{"Install Naive Support", "install", "naive", models.RoleSupport, http.StatusForbidden},
		// Install: User denied on VLESS and Naive
		{"Install VLESS User", "install", "vless", models.RoleUser, http.StatusForbidden},
		{"Install Naive User", "install", "naive", models.RoleUser, http.StatusForbidden},
		// Install: Admin allowed
		{"Install VLESS Admin", "install", "vless", models.RoleAdmin, http.StatusOK},
		{"Install Naive Admin", "install", "naive", models.RoleAdmin, http.StatusOK},
		// Install: Support allowed on legacy protocol AWG
		{"Install AWG Support", "install", "awg", models.RoleSupport, http.StatusOK},

		// Uninstall: Support denied on VLESS and Naive
		{"Uninstall VLESS Support", "uninstall", "vless", models.RoleSupport, http.StatusForbidden},
		{"Uninstall Naive Support", "uninstall", "naive", models.RoleSupport, http.StatusForbidden},
		// Uninstall: User denied on VLESS and Naive
		{"Uninstall VLESS User", "uninstall", "vless", models.RoleUser, http.StatusForbidden},
		{"Uninstall Naive User", "uninstall", "naive", models.RoleUser, http.StatusForbidden},
		// Uninstall: Admin allowed
		{"Uninstall VLESS Admin", "uninstall", "vless", models.RoleAdmin, http.StatusOK},
		{"Uninstall Naive Admin", "uninstall", "naive", models.RoleAdmin, http.StatusOK},
		// Uninstall: Support allowed on legacy protocol AWG
		{"Uninstall AWG Support", "uninstall", "awg", models.RoleSupport, http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			if tc.action == "install" {
				reqPayload := models.InstallProtocolRequest{
					Protocol: tc.proto,
					Port:     "443",
				}
				body, _ = json.Marshal(reqPayload)
			} else {
				reqPayload := models.ProtocolRequest{
					Protocol: tc.proto,
				}
				body, _ = json.Marshal(reqPayload)
			}

			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/%s", serverID, tc.action), bytes.NewReader(body))
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("server_id", fmt.Sprintf("%d", serverID))
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID:   "test-user",
				Username: "testuser",
				Role:     tc.role,
			}))

			w := httptest.NewRecorder()
			if tc.action == "install" {
				h.InstallProtocolHandler(w, req)
			} else {
				h.UninstallProtocolHandler(w, req)
			}

			if w.Code != tc.wantStatus {
				t.Errorf("%s: expected status %d, got %d (body: %s)", tc.name, tc.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

type failUninstallMockProtocolManager struct {
	*captureMockProtocolManager
	failErr error
}

func (m *failUninstallMockProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	return m.failErr
}

func TestUninstallProtocolHandler_FailurePreservesRecords(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	failMgr := &failUninstallMockProtocolManager{
		captureMockProtocolManager: &captureMockProtocolManager{proto: "vless"},
		failErr:                    fmt.Errorf("remote SSH error: docker stop failed"),
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(failMgr)

	ctx := context.Background()
	server := &models.Server{
		Name:      "uninstall-fail-server",
		Host:      "198.51.100.11",
		SSHPort:   22,
		Protocols: map[string]any{"vless": map[string]any{"installed": true, "port": 443}},
	}
	serverID, err := db.CreateServer(ctx, server)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// Seed user for foreign key constraint
	_, err = db.CreateUser(ctx, &models.User{
		ID:       "test-user-id",
		Username: "testuser",
		Role:     models.RoleUser,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Seed connection record for this server and protocol
	connID, err := db.CreateConnection(ctx, &models.UserConnection{
		UserID:   "test-user-id",
		ServerID: serverID,
		Protocol: "vless",
		ClientID: "test-client-uuid",
		Name:     "Active Client",
	})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}

	body, _ := json.Marshal(models.ProtocolRequest{Protocol: "vless"})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/uninstall", serverID), bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("server_id", fmt.Sprintf("%d", serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
		UserID:   "admin-id",
		Username: "admin",
		Role:     models.RoleAdmin,
	}))

	w := httptest.NewRecorder()
	h.UninstallProtocolHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on uninstall failure, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify DB state is PRESERVED
	savedServer, err := db.GetServer(ctx, serverID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if savedServer.Protocols == nil || savedServer.Protocols["vless"] == nil {
		t.Errorf("expected server.Protocols[vless] to be preserved in database, got: %+v", savedServer.Protocols)
	}

	savedConn, err := db.GetConnection(ctx, connID)
	if err != nil || savedConn == nil {
		t.Errorf("expected connection %s to be preserved in database, got: %v, err: %v", connID, savedConn, err)
	}
}

func TestInstallProtocolHandler_PreservesProtocolMetadata(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	vlessMock := &captureMockProtocolManager{proto: "vless"}
	h.registry = manager.NewRegistry()
	h.registry.Register(vlessMock)

	server := &models.Server{
		Name:      "meta-test-server",
		Host:      "198.51.100.12",
		SSHPort:   22,
		Protocols: make(map[string]any),
	}
	serverID, err := db.CreateServer(context.Background(), server)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	adminSession := &models.SessionData{
		UserID:   "admin-user",
		Username: "admin",
		Role:     models.RoleAdmin,
	}

	reqBody := models.InstallProtocolRequest{
		Protocol: "vless",
		Port:     "443",
		VLESSOptions: &models.VLESSInstallOptions{
			Port:       "443",
			ServerName: "gateway.icloud.com",
			Flow:       "xtls-rprx-vision",
		},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("server_id", fmt.Sprintf("%d", serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
	w := httptest.NewRecorder()
	h.InstallProtocolHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK installing vless, got %d (body: %s)", w.Code, w.Body.String())
	}

	savedServer, err := db.GetServer(context.Background(), serverID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	pMap, ok := savedServer.Protocols["vless"].(map[string]any)
	if !ok {
		t.Fatalf("expected savedServer.Protocols[vless] to be map[string]any")
	}
	if pMap["installed"] != true {
		t.Errorf("expected installed: true, got %v", pMap["installed"])
	}
	if pMap["port"] != "443" {
		t.Errorf("expected port: 443, got %v", pMap["port"])
	}
	if pMap["public_key"] != "pubkey123" {
		t.Errorf("expected public_key: pubkey123, got %v", pMap["public_key"])
	}
	if pMap["short_id"] != "shortid123" {
		t.Errorf("expected short_id: shortid123, got %v", pMap["short_id"])
	}
	if pMap["server_name"] != "gateway.icloud.com" {
		t.Errorf("expected server_name: gateway.icloud.com, got %v", pMap["server_name"])
	}
}

type dbClosingMockProtocolManager struct {
	proto     string
	closeFunc func()
}

func (m *dbClosingMockProtocolManager) Protocol() string { return m.proto }
func (m *dbClosingMockProtocolManager) Install(ctx context.Context, server *models.Server, params map[string]any) error {
	if m.closeFunc != nil {
		m.closeFunc()
	}
	return nil
}
func (m *dbClosingMockProtocolManager) Uninstall(ctx context.Context, server *models.Server) error {
	if m.closeFunc != nil {
		m.closeFunc()
	}
	return nil
}
func (m *dbClosingMockProtocolManager) GetClients(ctx context.Context, server *models.Server) ([]map[string]any, error) {
	return []map[string]any{}, nil
}
func (m *dbClosingMockProtocolManager) AddClient(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
	return map[string]any{"client_id": "c1"}, nil
}
func (m *dbClosingMockProtocolManager) RemoveClient(ctx context.Context, server *models.Server, clientID string) error {
	return nil
}
func (m *dbClosingMockProtocolManager) GetClientConfig(ctx context.Context, server *models.Server, clientID string) (string, error) {
	return "mock-config", nil
}
func (m *dbClosingMockProtocolManager) GetServerStatus(ctx context.Context, server *models.Server) (map[string]any, error) {
	return map[string]any{"container_running": true, "port": 443}, nil
}

func TestInstallProtocolHandler_DatabaseFailureReturns500(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	server := &models.Server{
		Name:      "db-fail-install-server",
		Host:      "198.51.100.11",
		SSHPort:   22,
		Protocols: make(map[string]any),
	}
	serverID, err := db.CreateServer(context.Background(), server)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	mockProto := &dbClosingMockProtocolManager{
		proto: "vless",
		closeFunc: func() {
			_ = db.Close()
		},
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(mockProto)

	adminSession := &models.SessionData{UserID: "admin-1", Username: "admin", Role: models.RoleAdmin}

	body, _ := json.Marshal(models.InstallProtocolRequest{
		Protocol: "vless",
		Port:     "443",
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", serverID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("server_id", fmt.Sprint(serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))

	w := httptest.NewRecorder()
	h.InstallProtocolHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 when database update fails, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestUninstallProtocolHandler_DatabaseFailureReturns500(t *testing.T) {
	h, db, _ := setupTestHandlers(t)

	server := &models.Server{
		Name:      "db-fail-uninstall-server",
		Host:      "198.51.100.12",
		SSHPort:   22,
		Protocols: map[string]any{"vless": map[string]any{"installed": true}},
	}
	serverID, err := db.CreateServer(context.Background(), server)
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	mockProto := &dbClosingMockProtocolManager{
		proto: "vless",
		closeFunc: func() {
			_ = db.Close()
		},
	}
	h.registry = manager.NewRegistry()
	h.registry.Register(mockProto)

	adminSession := &models.SessionData{UserID: "admin-1", Username: "admin", Role: models.RoleAdmin}

	body, _ := json.Marshal(models.ProtocolRequest{
		Protocol: "vless",
	})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/uninstall", serverID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithSession(req.Context(), adminSession))
	rc := chi.NewRouteContext()
	rc.URLParams.Add("server_id", fmt.Sprint(serverID))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))

	w := httptest.NewRecorder()
	h.UninstallProtocolHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 when database uninstall update fails, got %d (body: %s)", w.Code, w.Body.String())
	}
}

func TestInstallProtocolHandler_EngineProfileForwarding(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "top_level", payload: `{"protocol":"vless","port":"443","engine_profile":"modern_pq"}`},
		{name: "nested", payload: `{"protocol":"vless","port":"443","vless_options":{"engine_profile":"modern_pq","server_name":"example.com"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			capture := &captureMockProtocolManager{proto: models.ProtocolVLESS}
			h.registry = manager.NewRegistry()
			h.registry.Register(capture)
			id, err := db.CreateServer(context.Background(), &models.Server{
				Name: "test-profile-srv", Host: "192.0.2.1", SSHPort: 22,
				Protocols: map[string]any{},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", id), strings.NewReader(tc.payload))
			rc := chi.NewRouteContext()
			rc.URLParams.Add("server_id", fmt.Sprint(id))
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "admin-1", Username: "admin", Role: models.RoleAdmin,
			}))
			rec := httptest.NewRecorder()
			h.InstallProtocolHandler(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			if capture.capturedParams["engine_profile"] == "modern_pq" {
				return
			}
			encoded, err := json.Marshal(capture.capturedParams["vless_options"])
			if err != nil {
				t.Fatal(err)
			}
			nested := map[string]any{}
			if err := json.Unmarshal(encoded, &nested); err != nil {
				t.Fatal(err)
			}
			if nested["engine_profile"] == "modern_pq" {
				return
			}
			t.Fatalf("engine_profile not forwarded to manager: %#v", capture.capturedParams)
		})
	}
}

func TestInstallProtocolHandler_ProfileSwitchPreservesExistingNonstandardPort(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{name: "top_level_profile_omitted_port", payload: `{"protocol":"vless","engine_profile":"modern_pq"}`},
		{name: "nested_profile_omitted_port", payload: `{"protocol":"vless","vless_options":{"engine_profile":"modern_pq"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			capture := &captureMockProtocolManager{proto: models.ProtocolVLESS}
			h.registry = manager.NewRegistry()
			h.registry.Register(capture)
			id, err := db.CreateServer(context.Background(), &models.Server{
				Name:    "test-vless-srv",
				Host:    "192.0.2.1",
				SSHPort: 22,
				Protocols: map[string]any{
					models.ProtocolVLESS: map[string]any{
						"installed":      true,
						"port":           8443,
						"engine_profile": "legacy",
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/install", id), strings.NewReader(tc.payload))
			rc := chi.NewRouteContext()
			rc.URLParams.Add("server_id", fmt.Sprint(id))
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{
				UserID: "admin-1", Username: "admin", Role: models.RoleAdmin,
			}))
			rec := httptest.NewRecorder()
			h.InstallProtocolHandler(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}

			// Verify manager received the preserved nonstandard port 8443
			if portVal := capture.capturedParams["port"]; portVal != "8443" && portVal != 8443 {
				t.Errorf("expected manager captured port to preserve 8443, got %#v", portVal)
			}

			// Verify server protocols in database preserved port 8443
			server, err := db.GetServer(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			vMeta, ok := server.Protocols[models.ProtocolVLESS].(map[string]any)
			if !ok {
				t.Fatalf("expected VLESS protocol in server.Protocols")
			}
			if p := fmt.Sprint(vMeta["port"]); p != "8443" {
				t.Errorf("expected DB server.Protocols[vless] port = 8443, got %v", vMeta["port"])
			}
		})
	}
}
