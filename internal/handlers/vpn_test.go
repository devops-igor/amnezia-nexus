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
	"time"

	"github.com/devops-igor/amnezia-web-ui-go/internal/middleware"
	"github.com/devops-igor/amnezia-web-ui-go/internal/models"
)

func TestVPNHandlers(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Seed user and server
	u := &models.User{
		ID:           "vpn-user-1",
		Username:     "vpnuser",
		PasswordHash: "hash",
		Role:         models.RoleUser,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}
	_, _ = db.CreateUser(ctx, u)

	srv := &models.Server{
		Name:      "VPN-Node",
		Host:      "192.168.1.50",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "pass",
		Protocols: map[string]any{"awg": map[string]any{"port": 55424, "installed": true}},
		CreatedAt: time.Now(),
	}
	sID, _ := db.CreateServer(ctx, srv)

	sess := &models.SessionData{
		UserID: u.ID,
		Role:   models.RoleUser,
	}

	r := setupFullVPNRouter(h)

	t.Run("VPNStatusHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNBackendsHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/backends", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNTunnelsHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/tunnels", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNGetConfigHandler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNUpdateConfigHandler", func(t *testing.T) {
		cfg := models.VPNConfig{
			Algorithm:          models.LBLeastConnections,
			HealthThresholdMS:  400,
			ListenPort:         51820,
			SubnetCIDR:         "10.100.0.0/16",
			MaxTotalPeers:      500,
			MaxPeersPerBackend: 100,
		}
		body, _ := json.Marshal(cfg)
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/config", bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNUpdateConfigHandler PUT PublicEndpoint", func(t *testing.T) {
		// Read initial config
		reqGet := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
		wGet := httptest.NewRecorder()
		r.ServeHTTP(wGet, reqGet)
		if wGet.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", wGet.Code)
		}
		var initialCfg models.VPNConfig
		_ = json.Unmarshal(wGet.Body.Bytes(), &initialCfg)
		origH1 := initialCfg.H1
		origS1 := initialCfg.S1

		// 1. Update public_endpoint via PUT
		putBody := []byte(`{"public_endpoint": "lb.amnezia.org:51820"}`)
		reqPut := httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewReader(putBody))
		wPut := httptest.NewRecorder()
		r.ServeHTTP(wPut, reqPut)
		if wPut.Code != http.StatusOK {
			t.Fatalf("expected 200 on PUT, got %d: %s", wPut.Code, wPut.Body.String())
		}

		// Verify GET returns updated public_endpoint without corrupting H/S
		reqGet2 := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
		wGet2 := httptest.NewRecorder()
		r.ServeHTTP(wGet2, reqGet2)
		var updatedCfg models.VPNConfig
		_ = json.Unmarshal(wGet2.Body.Bytes(), &updatedCfg)
		if updatedCfg.PublicEndpoint != "lb.amnezia.org:51820" {
			t.Errorf("expected public_endpoint = lb.amnezia.org:51820, got: %s", updatedCfg.PublicEndpoint)
		}
		if origH1 != 0 && updatedCfg.H1 != origH1 {
			t.Errorf("expected H1 to be preserved (%d), got: %d", origH1, updatedCfg.H1)
		}
		if origS1 != 0 && updatedCfg.S1 != origS1 {
			t.Errorf("expected S1 to be preserved (%d), got: %d", origS1, updatedCfg.S1)
		}

		// 2. Clear public_endpoint via PUT with empty string
		putBodyClear := []byte(`{"public_endpoint": ""}`)
		reqPutClear := httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewReader(putBodyClear))
		wPutClear := httptest.NewRecorder()
		r.ServeHTTP(wPutClear, reqPutClear)
		if wPutClear.Code != http.StatusOK {
			t.Fatalf("expected 200 on PUT clear, got %d: %s", wPutClear.Code, wPutClear.Body.String())
		}

		reqGet3 := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
		wGet3 := httptest.NewRecorder()
		r.ServeHTTP(wGet3, reqGet3)
		var clearedCfg models.VPNConfig
		_ = json.Unmarshal(wGet3.Body.Bytes(), &clearedCfg)
		if clearedCfg.PublicEndpoint != "" {
			t.Errorf("expected public_endpoint to be cleared, got: %s", clearedCfg.PublicEndpoint)
		}
		if origH1 != 0 && clearedCfg.H1 != origH1 {
			t.Errorf("expected H1 to be preserved after clear (%d), got: %d", origH1, clearedCfg.H1)
		}
	})

	t.Run("VPNMyConnectionHandler Unauth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-connection", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})

	t.Run("VPNMyConnectionHandler Auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-connection", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNMyConfigHandler Unauth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-config", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}
	})

	t.Run("VPNMyConfigHandler Auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/vpn/my-config", nil)
		reqCtx := middleware.WithSession(req.Context(), sess)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(reqCtx))

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("VPNEnableBackendHandler Without AWG", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sID), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when enabling server without AWG, got %d", w.Code)
		}
		var errResp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&errResp)
		errCode, _ := errResp["error"].(string)
		if errCode != "awg_not_installed" {
			t.Errorf("expected error code 'awg_not_installed', got: %s", errCode)
		}
		detail, _ := errResp["detail"].(string)
		if !strings.Contains(detail, "AmneziaWG") {
			t.Errorf("expected error detail to mention 'AmneziaWG', got: %s", detail)
		}
	})

	t.Run("VPNEnableBackendHandler Server Not Found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/backends/99999/enable", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 when enabling non-existent server, got %d", w.Code)
		}
		var errResp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&errResp)
		errCode, _ := errResp["error"].(string)
		if errCode != "server_not_found" {
			t.Errorf("expected error code 'server_not_found', got: %s", errCode)
		}
	})

	t.Run("VPNEnableBackendHandler 500 Sanitization", func(t *testing.T) {
		srv500 := &models.Server{
			Name:    "VPN-Node-500",
			Host:    "invalid-internal-host-999.internal.corp",
			SSHPort: 22,
			SSHUser: "root",
			SSHPass: "pass",
			Protocols: map[string]any{
				"awg": map[string]any{
					"port":       float64(51820),
					"public_key": "x9aB1234567890abcdef1234567890abcdef123456=",
					"installed":  true,
				},
			},
			CreatedAt: time.Now(),
		}
		sID500, err := db.CreateServer(ctx, srv500)
		if err != nil {
			t.Fatalf("failed to create test server for 500 test: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sID500), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for failed backend enable, got %d (body: %s)", w.Code, w.Body.String())
		}
		var errResp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&errResp)
		errCode, _ := errResp["error"].(string)
		if errCode != "internal_error" {
			t.Errorf("expected error code 'internal_error', got: %s", errCode)
		}
		detail, _ := errResp["detail"].(string)
		if detail != "Failed to enable backend" {
			t.Errorf("expected generic detail 'Failed to enable backend', got: %s", detail)
		}

		bodyStr := w.Body.String()
		if strings.Contains(bodyStr, "invalid-internal-host") || strings.Contains(bodyStr, "UDP") || strings.Contains(bodyStr, "socket") {
			t.Errorf("500 response leaked internal details: %s", bodyStr)
		}
	})

	t.Run("VPNEnableBackendHandler With AWG Success", func(t *testing.T) {
		srvWithAWG := &models.Server{
			Name:    "VPN-Node-AWG-Success",
			Host:    "127.0.0.1",
			SSHPort: 22,
			SSHUser: "root",
			SSHPass: "pass",
			Protocols: map[string]any{
				"awg": map[string]any{
					"port":       float64(51820),
					"public_key": "x9aB1234567890abcdef1234567890abcdef123456=",
					"installed":  true,
				},
			},
			CreatedAt: time.Now(),
		}
		sIDWithAWG, err := db.CreateServer(ctx, srvWithAWG)
		if err != nil {
			t.Fatalf("failed to create test server: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sIDWithAWG), nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 when enabling valid AWG server, got %d (body: %s)", w.Code, w.Body.String())
		}

		// Now disable it
		reqDisable := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/disable", sIDWithAWG), nil)
		wDisable := httptest.NewRecorder()
		r.ServeHTTP(wDisable, reqDisable)

		if wDisable.Code != http.StatusOK {
			t.Fatalf("expected 200 when disabling backend, got %d", wDisable.Code)
		}
	})

	t.Run("VPNUpdateConfigHandler Invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/config", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("VPNEnableBackendHandler Invalid ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/backends/invalid/enable", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("VPNDisableBackendHandler Invalid ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/backends/invalid/disable", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("VPNDisconnectHandler", func(t *testing.T) {
		// Session ID
		body, _ := json.Marshal(map[string]any{"session_id": "sess-123"})
		req := httptest.NewRequest(http.MethodPost, "/api/vpn/disconnect", bytes.NewReader(body))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		// User ID
		bodyUser, _ := json.Marshal(map[string]any{"user_id": u.ID})
		reqUser := httptest.NewRequest(http.MethodPost, "/api/vpn/disconnect", bytes.NewReader(bodyUser))
		wUser := httptest.NewRecorder()
		r.ServeHTTP(wUser, reqUser)
		if wUser.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", wUser.Code)
		}

		// Invalid Body
		reqBad := httptest.NewRequest(http.MethodPost, "/api/vpn/disconnect", bytes.NewReader([]byte("bad-json")))
		wBad := httptest.NewRecorder()
		r.ServeHTTP(wBad, reqBad)
		if wBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", wBad.Code)
		}
	})

	t.Run("Nil VPNService Fallbacks", func(t *testing.T) {
		hNil := NewHandlers(Dependencies{
			Config: h.cfg,
			DB:     db,
		})
		rNil := setupFullVPNRouter(hNil)

		// Status
		reqS := httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil)
		wS := httptest.NewRecorder()
		rNil.ServeHTTP(wS, reqS)
		if wS.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wS.Code)
		}

		// Backends
		reqB := httptest.NewRequest(http.MethodGet, "/api/vpn/backends", nil)
		wB := httptest.NewRecorder()
		rNil.ServeHTTP(wB, reqB)
		if wB.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wB.Code)
		}

		// Tunnels
		reqT := httptest.NewRequest(http.MethodGet, "/api/vpn/tunnels", nil)
		wT := httptest.NewRecorder()
		rNil.ServeHTTP(wT, reqT)
		if wT.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wT.Code)
		}

		// Config
		reqC := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
		wC := httptest.NewRecorder()
		rNil.ServeHTTP(wC, reqC)
		if wC.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wC.Code)
		}

		// Update Config (saves to db)
		cfg := models.VPNConfig{ListenPort: 51821}
		body, _ := json.Marshal(cfg)
		reqUC := httptest.NewRequest(http.MethodPost, "/api/vpn/config", bytes.NewReader(body))
		wUC := httptest.NewRecorder()
		rNil.ServeHTTP(wUC, reqUC)
		if wUC.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wUC.Code)
		}

		// MyConnection
		reqMC := httptest.NewRequest(http.MethodGet, "/api/vpn/my-connection", nil)
		reqMCCtx := middleware.WithSession(reqMC.Context(), sess)
		wMC := httptest.NewRecorder()
		rNil.ServeHTTP(wMC, reqMC.WithContext(reqMCCtx))
		if wMC.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wMC.Code)
		}

		// MyConfig
		reqMCfg := httptest.NewRequest(http.MethodGet, "/api/vpn/my-config", nil)
		reqMCfgCtx := middleware.WithSession(reqMCfg.Context(), sess)
		wMCfg := httptest.NewRecorder()
		rNil.ServeHTTP(wMCfg, reqMCfg.WithContext(reqMCfgCtx))
		if wMCfg.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", wMCfg.Code)
		}
	})
}

// TestVPNUpdateConfigHandler_PUT_PublicEndpointMerge covers the
// edit-public-endpoint path (Issue #16, C3): PUT /api/vpn/config through the
// REAL handler (the mergeVPNConfig path), asserting 200, the persisted value
// via GET, and that an update WITHOUT public_endpoint preserves the current
// one (regression guard for the merge semantics the UI's edit-endpoint flow
// relies on).
func TestVPNUpdateConfigHandler_PUT_PublicEndpointMerge(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	r := setupFullVPNRouter(h)
	ctx := context.Background()

	getEndpoint := func() string {
		t.Helper()
		reqGet := httptest.NewRequest(http.MethodGet, "/api/vpn/config", nil)
		wGet := httptest.NewRecorder()
		r.ServeHTTP(wGet, reqGet)
		if wGet.Code != http.StatusOK {
			t.Fatalf("GET /api/vpn/config expected 200, got %d", wGet.Code)
		}
		var cfg models.VPNConfig
		if err := json.Unmarshal(wGet.Body.Bytes(), &cfg); err != nil {
			t.Fatalf("GET response is not valid VPNConfig JSON: %v", err)
		}
		return cfg.PublicEndpoint
	}

	// 1. PUT with public_endpoint: "host:port" -> 200, persisted value via GET.
	putBody := []byte(`{"public_endpoint": "edit.example.net:31458"}`)
	reqPut := httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewReader(putBody))
	wPut := httptest.NewRecorder()
	r.ServeHTTP(wPut, reqPut)
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT with public_endpoint expected 200, got %d: %s", wPut.Code, wPut.Body.String())
	}
	if got := getEndpoint(); got != "edit.example.net:31458" {
		t.Errorf("public_endpoint not persisted after PUT: got %q", got)
	}

	// 2. Update WITHOUT a public_endpoint key -> 200, current endpoint
	//    preserved by the merge (the UI sends partial payloads).
	partial := models.VPNConfig{Algorithm: models.LBWeighted}
	partialBody, err := json.Marshal(partial)
	if err != nil {
		t.Fatalf("marshal partial config: %v", err)
	}
	reqPut2 := httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewReader(partialBody))
	wPut2 := httptest.NewRecorder()
	r.ServeHTTP(wPut2, reqPut2)
	if wPut2.Code != http.StatusOK {
		t.Fatalf("PUT without public_endpoint expected 200, got %d: %s", wPut2.Code, wPut2.Body.String())
	}
	if got := getEndpoint(); got != "edit.example.net:31458" {
		t.Errorf("public_endpoint lost by update without the key: got %q", got)
	}

	// 3. Update with an empty JSON object (no keys at all) -> also preserved.
	emptyBody := []byte(`{}`)
	reqPut3 := httptest.NewRequest(http.MethodPut, "/api/vpn/config", bytes.NewReader(emptyBody))
	wPut3 := httptest.NewRecorder()
	r.ServeHTTP(wPut3, reqPut3)
	if wPut3.Code != http.StatusOK {
		t.Fatalf("PUT with empty object expected 200, got %d: %s", wPut3.Code, wPut3.Body.String())
	}
	if got := getEndpoint(); got != "edit.example.net:31458" {
		t.Errorf("public_endpoint lost by empty-object PUT: got %q", got)
	}

	// The endpoint must also be in the persisted DB config row, not just
	// the service's in-memory copy.
	stored, err := db.GetVPNConfig(ctx)
	if err != nil {
		t.Fatalf("GetVPNConfig failed: %v", err)
	}
	if stored.PublicEndpoint != "edit.example.net:31458" {
		t.Errorf("persisted public_endpoint: want edit.example.net:31458, got %q", stored.PublicEndpoint)
	}
}

func TestVPNEnableBackendHandler_DynamicFallback(t *testing.T) {
	ctx := context.Background()
	mockSSH := &testMockSSHClient{
		cmdFunc: func(ctx context.Context, cmd string) (string, string, int, error) {
			if strings.Contains(cmd, "docker ps -a") && strings.Contains(cmd, "amnezia-awg") {
				return "amnezia-awg\n", "", 0, nil
			}
			if strings.Contains(cmd, "docker ps") && strings.Contains(cmd, "amnezia-awg") {
				return "Up 1 hour\n", "", 0, nil
			}
			if strings.Contains(cmd, "wg0.conf") || strings.Contains(cmd, "awg0.conf") {
				return "[Interface]\nListenPort = 51820\nPrivateKey = server-priv\n", "", 0, nil
			}
			if strings.Contains(cmd, "wireguard_server_public_key.key") {
				return "fallback-server-public-key\n", "", 0, nil
			}
			return "", "", 0, nil
		},
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mockSSH)

	srvNoAWG := &models.Server{
		Name:      "VPN-Node-AWG-Fallback",
		Host:      "127.0.0.1",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "pass",
		Protocols: map[string]any{},
		CreatedAt: time.Now(),
	}
	sIDFallback, err := db.CreateServer(ctx, srvNoAWG)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	mockSSH.serverID = &sIDFallback

	r := setupFullVPNRouter(h)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sIDFallback), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when enabling server with live fallback, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify database was updated
	srv, err := db.GetServer(ctx, sIDFallback)
	if err != nil {
		t.Fatalf("failed to load server from db: %v", err)
	}
	awgData, ok := srv.Protocols["awg"].(map[string]any)
	if !ok {
		t.Fatalf("expected awg protocol in server.Protocols, got: %+v", srv.Protocols)
	}
	if pubKey, _ := awgData["public_key"].(string); pubKey != "fallback-server-public-key" {
		t.Errorf("expected public_key fallback-server-public-key, got %v", pubKey)
	}
	if portVal := fmt.Sprint(awgData["port"]); portVal != "51820" {
		t.Errorf("expected port 51820, got %v", awgData["port"])
	}
}
