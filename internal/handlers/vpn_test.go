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

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

// TestVPNSessionsHandler covers the admin sessions endpoint (issues #189/#191):
// rows come from Service.SessionsEnriched, management-only mode (nil vpn
// service) must yield an empty JSON list, and a service error maps to 500.
func TestVPNSessionsHandler(t *testing.T) {
	ctx := context.Background()

	t.Run("returns enriched sessions", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)

		sID, err := db.CreateServer(ctx, &models.Server{Name: "Edge Node 9", Host: "198.51.100.19"})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}
		uID, err := db.CreateUser(ctx, &models.User{Username: "dave"})
		if err != nil {
			t.Fatalf("CreateUser failed: %v", err)
		}
		tID, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
			ServerID:      sID,
			InterfaceName: "awg-be-9",
			PublicKey:     "pubkey-be-9",
			PrivateKey:    "privkey-be-9",
			Endpoint:      "198.51.100.19:51820",
		})
		if err != nil {
			t.Fatalf("CreateBackendTunnel failed: %v", err)
		}
		if err := db.CreateVPNSession(ctx, &models.VPNSession{
			ID:              "sess-handler",
			UserID:          uID,
			BackendTunnelID: tID,
			PeerPublicKey:   "peer-handler",
			AssignedIP:      "10.100.0.39",
			RxBytes:         10,
			TxBytes:         20,
			Status:          "connected",
		}); err != nil {
			t.Fatalf("CreateVPNSession failed: %v", err)
		}

		r := setupFullVPNRouter(h)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil))

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
		}
		var got struct {
			Sessions []models.EnrichedVPNSession `json:"sessions"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("failed to decode response: %v (body: %s)", err, w.Body.String())
		}
		if len(got.Sessions) != 1 {
			t.Fatalf("expected 1 session row, got %d: %+v", len(got.Sessions), got.Sessions)
		}
		row := got.Sessions[0]
		if row.Username != "dave" {
			t.Errorf("expected username 'dave' from join, got %q", row.Username)
		}
		if row.ServerName != "Edge Node 9" {
			t.Errorf("expected server_name 'Edge Node 9' from join, got %q", row.ServerName)
		}
		if row.AssignedIP != "10.100.0.39" {
			t.Errorf("expected assigned_ip '10.100.0.39', got %q", row.AssignedIP)
		}
	})

	t.Run("nil vpn service returns empty list", func(t *testing.T) {
		_, db, cfg := setupTestHandlers(t)
		hNil := NewHandlers(Dependencies{Config: cfg, DB: db})
		r := setupFullVPNRouter(hNil)

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil))

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 in management-only mode, got %d (body: %s)", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, `"sessions":[]`) {
			t.Errorf("expected empty JSON list (not null), got: %s", body)
		}
	})

	t.Run("service error maps to 500", func(t *testing.T) {
		h, _, _ := setupTestHandlers(t)
		// Zero-value service has no DB backing, so SessionsEnriched fails;
		// construction starts nothing, so this stays a pure test double.
		h.vpnSvc = &vpn.Service{}

		r := setupFullVPNRouter(h)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/vpn/sessions", nil))

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d (body: %s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "internal_error") {
			t.Errorf("expected internal_error code, got: %s", w.Body.String())
		}
	})
}

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
		if !origH1.IsZero() && updatedCfg.H1 != origH1 {
			t.Errorf("expected H1 to be preserved (%s), got: %s", origH1, updatedCfg.H1)
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
		if !origH1.IsZero() && clearedCfg.H1 != origH1 {
			t.Errorf("expected H1 to be preserved after clear (%s), got: %s", origH1, clearedCfg.H1)
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

// newAWGMockSSH returns an SSH client mock that satisfies the AWG
// auto-detection fallback path (issue #29 delete tests): the server carries
// no awg protocol entry, so EnableBackend resolves credentials via live SSH
// probing — docker ps for the amnezia-awg container, wg0.conf for the port
// and private key, wireguard_server_public_key.key for the public key.
func newAWGMockSSH() *testMockSSHClient {
	return &testMockSSHClient{
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
}

// TestVPNDeleteBackendHandler covers the issue #29 DELETE route end-to-end
// through setupFullVPNRouter: enable (mocked AWG over SSH) -> delete (200,
// backend gone from the pool listing and the backend_tunnels table) ->
// delete again (404) -> invalid id (400) -> unknown id (404).
func TestVPNDeleteBackendHandler(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	srv := &models.Server{
		Name:      "VPN-Node-Delete",
		Host:      "127.0.0.1",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "pass",
		Protocols: map[string]any{},
		CreatedAt: time.Now(),
	}
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	r := setupFullVPNRouter(h)

	// Enable first so the backend tunnel exists in pool + DB.
	reqEnable := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sID), nil)
	wEnable := httptest.NewRecorder()
	r.ServeHTTP(wEnable, reqEnable)
	if wEnable.Code != http.StatusOK {
		t.Fatalf("setup: expected 200 when enabling backend, got %d (body: %s)", wEnable.Code, wEnable.Body.String())
	}

	// Success path: DELETE returns 200 and the backend disappears from the
	// pool listing and the DB.
	reqDelete := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/vpn/backends/%d", sID), nil)
	wDelete := httptest.NewRecorder()
	r.ServeHTTP(wDelete, reqDelete)
	if wDelete.Code != http.StatusOK {
		t.Fatalf("expected 200 when deleting backend, got %d (body: %s)", wDelete.Code, wDelete.Body.String())
	}

	reqList := httptest.NewRequest(http.MethodGet, "/api/vpn/backends", nil)
	wList := httptest.NewRecorder()
	r.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 when listing backends, got %d", wList.Code)
	}
	var listResp struct {
		Backends []struct {
			ServerID int64 `json:"server_id"`
		} `json:"backends"`
	}
	if err := json.NewDecoder(wList.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed to decode backends listing: %v", err)
	}
	for _, b := range listResp.Backends {
		if b.ServerID == sID {
			t.Errorf("backend %d still listed after DELETE", sID)
		}
	}

	row, err := db.GetBackendTunnelByServerID(ctx, sID)
	if err != nil {
		t.Fatalf("GetBackendTunnelByServerID failed: %v", err)
	}
	if row != nil {
		t.Errorf("backend_tunnels row id=%d still present after DELETE", row.ID)
	}

	// The server itself must be untouched (only the tunnel registration is
	// removed, never the server or its protocol config).
	if _, err := db.GetServer(ctx, sID); err != nil {
		t.Errorf("server %d must survive backend delete: %v", sID, err)
	}

	// DELETE after already deleted -> 404 backend_not_found.
	reqAgain := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/vpn/backends/%d", sID), nil)
	wAgain := httptest.NewRecorder()
	r.ServeHTTP(wAgain, reqAgain)
	if wAgain.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when deleting an already-deleted backend, got %d (body: %s)", wAgain.Code, wAgain.Body.String())
	}
	var errResp map[string]any
	_ = json.NewDecoder(wAgain.Body).Decode(&errResp)
	if errCode, _ := errResp["error"].(string); errCode != "backend_not_found" {
		t.Errorf("expected error code 'backend_not_found', got: %v", errCode)
	}

	// Invalid server_id -> 400.
	reqInvalid := httptest.NewRequest(http.MethodDelete, "/api/vpn/backends/invalid", nil)
	wInvalid := httptest.NewRecorder()
	r.ServeHTTP(wInvalid, reqInvalid)
	if wInvalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid server_id, got %d", wInvalid.Code)
	}

	// Unknown server id -> 404.
	reqUnknown := httptest.NewRequest(http.MethodDelete, "/api/vpn/backends/99999", nil)
	wUnknown := httptest.NewRecorder()
	r.ServeHTTP(wUnknown, reqUnknown)
	if wUnknown.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown server id, got %d", wUnknown.Code)
	}
}

// TestVPNEnableBackendHandler_ContextCancellationResilience verifies that canceling
// the incoming HTTP request context (e.g. client disconnect, reverse proxy timeout)
// does not abort backend enablement due to context.WithoutCancel decoupling with 45s deadline.
func TestVPNEnableBackendHandler_ContextCancellationResilience(t *testing.T) {
	ctx := context.Background()
	var capturedErr error
	var capturedRemaining time.Duration
	var capturedHasDeadline bool
	var capturedCount int
	mockSSH := &testMockSSHClient{
		cmdFunc: func(cmdCtx context.Context, cmd string) (string, string, int, error) {
			capturedCount++
			capturedErr = cmdCtx.Err()
			if deadline, ok := cmdCtx.Deadline(); ok {
				capturedHasDeadline = true
				capturedRemaining = time.Until(deadline)
			}
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

	srv := &models.Server{
		Name:    "VPN-Node-Cancel-Resilience",
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
	sID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}

	r := setupFullVPNRouter(h)

	// Create an HTTP request with a pre-canceled context simulating client disconnect
	reqCtx, cancelReq := context.WithCancel(context.Background())
	cancelReq()

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sID), nil).WithContext(reqCtx)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 when enabling backend despite canceled request context, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify that the operation was executed with an active context bounded by ~45s
	if capturedCount == 0 {
		t.Fatal("expected EnableBackend to execute SSH commands, but none were executed")
	}
	if capturedErr != nil {
		t.Fatalf("expected command execution context to not be canceled, got err: %v", capturedErr)
	}
	if !capturedHasDeadline {
		t.Fatal("expected command execution context to have a deadline")
	}
	if capturedRemaining <= 0 || capturedRemaining > 45*time.Second {
		t.Fatalf("expected deadline within (0, 45s], got remaining: %v", capturedRemaining)
	}

	// Verify the backend tunnel was actually registered in the DB
	backends, err := db.GetBackendTunnels(ctx)
	if err != nil {
		t.Fatalf("failed to get backend tunnels: %v", err)
	}
	var found bool
	for _, b := range backends {
		if b.ServerID == sID && b.Status != "disabled" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected backend for server %d to be enabled in backend_tunnels table", sID)
	}
}
