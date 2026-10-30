package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/go-chi/chi/v5"
)

func TestVPNEnableBackendHandler_ProxyBootstrap(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	vpnCfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() {
		ts, _ := vpnSvc.GetTunnels(ctx)
		for _, tun := range ts {
			if d := vpnSvc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})
	h.vpnSvc = vpnSvc

	r := chi.NewRouter()
	r.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

	naiveParams := models.NaiveProxyParams{
		Domain:   "example.com",
		Username: "user1",
		Password: "pass1",
		EnableH3: false,
	}
	paramsRaw, _ := json.Marshal(naiveParams)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "proxy-node-http",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"domain":    "example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"protocol":        "naive",
		"protocol_params": json.RawMessage(paramsRaw),
	})

	// R2-B1: Verify Support role cannot supply or replace protected proxy credentials
	reqSupport := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), bytes.NewReader(body))
	reqSupport = reqSupport.WithContext(middleware.WithSession(reqSupport.Context(), &models.SessionData{UserID: "support", Role: models.RoleSupport}))
	wSupport := httptest.NewRecorder()
	r.ServeHTTP(wSupport, reqSupport)
	if wSupport.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for Support role with proxy body, got %d: %s", wSupport.Code, wSupport.Body.String())
	}

	// 1. Enable with JSON body specifying protocol and protocol_params (Admin authorization)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with proxy body, got %d: %s", w.Code, w.Body.String())
	}

	tun, err := vpnSvc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("expected tunnel for server %d, got %+v err=%v", sid, tun, err)
	}
	if tun.Protocol != models.ProtocolNaive {
		t.Fatalf("expected protocol %q, got %q", models.ProtocolNaive, tun.Protocol)
	}

	// 1b. Normal no-body re-enable preserves stored backend credentials (R2-H1)
	if err := vpnSvc.DisableBackend(ctx, sid); err != nil {
		t.Fatalf("DisableBackend failed: %v", err)
	}
	reqReenable := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
	reqReenable = reqReenable.WithContext(middleware.WithSession(reqReenable.Context(), &models.SessionData{UserID: "support", Role: models.RoleSupport}))
	wReenable := httptest.NewRecorder()
	r.ServeHTTP(wReenable, reqReenable)
	if wReenable.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on no-body re-enable, got %d: %s", wReenable.Code, wReenable.Body.String())
	}
	tunReenabled, err := vpnSvc.GetTunnel(sid)
	if err != nil || tunReenabled == nil || !tunReenabled.Enabled {
		t.Fatalf("expected backend %d re-enabled with preserved credentials, got %+v err=%v", sid, tunReenabled, err)
	}

	// Clean up for omitted options check
	_ = vpnSvc.DeleteBackend(ctx, sid)

	// Register protocol manager to provision dedicated client credentials
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"username": "auto-naive-user",
				"password": "auto-naive-password",
				"domain":   "example.com",
			}, nil
		},
	})

	// R4-B1: Support cannot enroll proxy backend without body on first-time enrollment
	reqSupportNoBody := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
	reqSupportNoBody = reqSupportNoBody.WithContext(middleware.WithSession(reqSupportNoBody.Context(), &models.SessionData{UserID: "support", Role: models.RoleSupport}))
	wSupportNoBody := httptest.NewRecorder()
	r.ServeHTTP(wSupportNoBody, reqSupportNoBody)
	if wSupportNoBody.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for Support role on initial proxy enrollment without body, got %d: %s", wSupportNoBody.Code, wSupportNoBody.Body.String())
	}

	// 2. Admin enable without body resolves installed proxy from server.Protocols
	// and provisions client credentials via protocol manager.
	reqEmpty := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
	reqEmpty = reqEmpty.WithContext(middleware.WithSession(reqEmpty.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wEmpty := httptest.NewRecorder()
	r.ServeHTTP(wEmpty, reqEmpty)

	if wEmpty.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with omitted body, got %d: %s", wEmpty.Code, wEmpty.Body.String())
	}

	tunAfter, err := vpnSvc.GetTunnel(sid)
	if err != nil || tunAfter == nil {
		t.Fatalf("expected tunnel for server %d, got %+v err=%v", sid, tunAfter, err)
	}
	if tunAfter.Protocol != models.ProtocolNaive {
		t.Fatalf("expected resolved protocol %q, got %q", models.ProtocolNaive, tunAfter.Protocol)
	}
	var provisionedNaive models.NaiveProxyParams
	if err := json.Unmarshal(tunAfter.ProtocolParams, &provisionedNaive); err != nil {
		t.Fatalf("failed to decode auto-provisioned naive params: %v", err)
	}
	if provisionedNaive.Username == "" || provisionedNaive.Password == "" || provisionedNaive.Domain == "" {
		t.Fatalf("expected complete auto-provisioned naive params, got %+v", provisionedNaive)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || dbTun == nil || len(dbTun.ProtocolParams) == 0 {
		t.Fatalf("expected encrypted protocol params persisted in db for server %d, got %+v err=%v", sid, dbTun, err)
	}

	lifecycles, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	rec, ok := lifecycles[provisionedNaive.Username]
	if !ok || rec.Status != "backend_active" {
		t.Fatalf("expected peer_lifecycle record for %s with status backend_active, got %+v", provisionedNaive.Username, lifecycles)
	}
}

func TestVPNEnableBackendHandler_ProxyBootstrap_VLESS(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	vpnCfg := &models.VPNConfig{
		EnableMultiProtocolBackends: true,
		ListenPort:                  51820,
	}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() {
		ts, _ := vpnSvc.GetTunnels(ctx)
		for _, tun := range ts {
			if d := vpnSvc.GetBackendDeviceForTest(tun.ID); d != nil {
				_ = d.Close()
			}
		}
	})
	h.vpnSvc = vpnSvc

	r := chi.NewRouter()
	r.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "vless-node-http",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{
				"installed":   true,
				"port":        443,
				"server_name": "gateway.icloud.com",
				"flow":        "xtls-rprx-vision",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	// Register protocol manager to provision dedicated client credentials
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			return map[string]any{
				"uuid":        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
				"flow":        "xtls-rprx-vision",
				"public_key":  "e-JgU2X7X8aH1pQ1pZqUuWbWw5K2s6J8f8gH9jK1lM4",
				"short_id":    "0123456789abcdef",
				"server_name": "gateway.icloud.com",
			}, nil
		},
	})

	// R4-B1: Support cannot enroll VLESS proxy backend without body on first-time enrollment
	reqSupport := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
	reqSupport = reqSupport.WithContext(middleware.WithSession(reqSupport.Context(), &models.SessionData{UserID: "support", Role: models.RoleSupport}))
	wSupport := httptest.NewRecorder()
	r.ServeHTTP(wSupport, reqSupport)
	if wSupport.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for Support role on initial VLESS enrollment without body, got %d: %s", wSupport.Code, wSupport.Body.String())
	}

	// Admin enable without body on server with standard VLESS installer metadata.
	reqEmpty := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
	reqEmpty = reqEmpty.WithContext(middleware.WithSession(reqEmpty.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wEmpty := httptest.NewRecorder()
	r.ServeHTTP(wEmpty, reqEmpty)

	if wEmpty.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with omitted body for VLESS, got %d: %s", wEmpty.Code, wEmpty.Body.String())
	}

	tun, err := vpnSvc.GetTunnel(sid)
	if err != nil || tun == nil {
		t.Fatalf("expected tunnel for server %d, got %+v err=%v", sid, tun, err)
	}
	if tun.Protocol != models.ProtocolVLESS {
		t.Fatalf("expected resolved protocol %q, got %q", models.ProtocolVLESS, tun.Protocol)
	}
	var provisionedVLESS models.VLESSRealityParams
	if err := json.Unmarshal(tun.ProtocolParams, &provisionedVLESS); err != nil {
		t.Fatalf("failed to decode auto-provisioned vless params: %v", err)
	}
	if provisionedVLESS.UUID == "" || provisionedVLESS.PublicKey == "" || provisionedVLESS.ShortID == "" || provisionedVLESS.ServerName == "" {
		t.Fatalf("expected complete auto-provisioned vless params, got %+v", provisionedVLESS)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || dbTun == nil || len(dbTun.ProtocolParams) == 0 {
		t.Fatalf("expected encrypted protocol params persisted in db for server %d, got %+v err=%v", sid, dbTun, err)
	}

	lifecycles, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolVLESS)
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	rec, ok := lifecycles[provisionedVLESS.UUID]
	if !ok || rec.Status != "backend_active" {
		t.Fatalf("expected peer_lifecycle record for %s with status backend_active, got %+v", provisionedVLESS.UUID, lifecycles)
	}
}

func TestVPNEnableBackendHandler_ProxyDisabled_RejectsWithoutProvisioning(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := context.Background()

	// Multi-protocol backends explicitly disabled
	vpnCfg := &models.VPNConfig{
		EnableMultiProtocolBackends: false,
		ListenPort:                  51820,
	}
	vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	h.vpnSvc = vpnSvc

	r := chi.NewRouter()
	r.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

	sidVLESS, err := db.CreateServer(ctx, &models.Server{
		Name:    "vless-node-disabled",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"vless": map[string]any{
				"installed":   true,
				"port":        443,
				"server_name": "gateway.icloud.com",
				"flow":        "xtls-rprx-vision",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	var vlessAddCalls atomic.Int32
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			vlessAddCalls.Add(1)
			return map[string]any{
				"uuid":        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
				"flow":        "xtls-rprx-vision",
				"public_key":  "e-JgU2X7X8aH1pQ1pZqUuWbWw5K2s6J8f8gH9jK1lM4",
				"short_id":    "0123456789abcdef",
				"server_name": "gateway.icloud.com",
			}, nil
		},
	})

	// 1. Admin enable without body (bootstrap from server.Protocols):
	// Must fail closed with 400 multi_protocol_disabled, and protoMgr.AddClient must NOT be called.
	reqEmpty := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sidVLESS), nil)
	reqEmpty = reqEmpty.WithContext(middleware.WithSession(reqEmpty.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wEmpty := httptest.NewRecorder()
	r.ServeHTTP(wEmpty, reqEmpty)

	if wEmpty.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request with omitted body when feature flag disabled, got %d: %s", wEmpty.Code, wEmpty.Body.String())
	}
	var respEmpty map[string]any
	if err := json.Unmarshal(wEmpty.Body.Bytes(), &respEmpty); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if respEmpty["error"] != "multi_protocol_disabled" {
		t.Fatalf("expected error code multi_protocol_disabled, got: %v", respEmpty["error"])
	}
	if calls := vlessAddCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 AddClient calls on omitted-body enable, got %d", calls)
	}

	// 2. Admin enable with explicit proxy payload:
	// Must also fail closed with 400 multi_protocol_disabled without calling AddClient.
	vlessParams := models.VLESSRealityParams{
		UUID:       "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		PublicKey:  "e-JgU2X7X8aH1pQ1pZqUuWbWw5K2s6J8f8gH9jK1lM4",
		ShortID:    "0123456789abcdef",
		ServerName: "gateway.icloud.com",
		Flow:       "xtls-rprx-vision",
	}
	pRaw, _ := json.Marshal(vlessParams)
	bodyExplicit, _ := json.Marshal(map[string]any{
		"protocol":        "vless",
		"protocol_params": json.RawMessage(pRaw),
	})
	reqExplicit := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sidVLESS), bytes.NewReader(bodyExplicit))
	reqExplicit = reqExplicit.WithContext(middleware.WithSession(reqExplicit.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wExplicit := httptest.NewRecorder()
	r.ServeHTTP(wExplicit, reqExplicit)

	if wExplicit.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request with explicit proxy body when feature flag disabled, got %d: %s", wExplicit.Code, wExplicit.Body.String())
	}
	if calls := vlessAddCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 AddClient calls on explicit enable, got %d", calls)
	}

	// 3. Verify no backend tunnel or DB state was created
	tun, err := vpnSvc.GetTunnel(sidVLESS)
	if err == nil && tun != nil {
		t.Fatalf("expected no tunnel in pool for server %d, got %+v", sidVLESS, tun)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, sidVLESS)
	if err == nil && dbTun != nil {
		t.Fatalf("expected no backend tunnel in db for server %d, got %+v", sidVLESS, dbTun)
	}

	// 4. Test NaiveProxy server with omitted body when feature flag disabled:
	sidNaive, err := db.CreateServer(ctx, &models.Server{
		Name:    "naive-node-disabled",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"domain":    "example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer naive failed: %v", err)
	}

	var naiveAddCalls atomic.Int32
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
			naiveAddCalls.Add(1)
			return map[string]any{
				"username": "auto-naive-user",
				"password": "auto-naive-password",
				"domain":   "example.com",
			}, nil
		},
	})

	reqNaive := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sidNaive), nil)
	reqNaive = reqNaive.WithContext(middleware.WithSession(reqNaive.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wNaive := httptest.NewRecorder()
	r.ServeHTTP(wNaive, reqNaive)

	if wNaive.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for Naive with omitted body when feature flag disabled, got %d: %s", wNaive.Code, wNaive.Body.String())
	}
	var respNaive map[string]any
	if err := json.Unmarshal(wNaive.Body.Bytes(), &respNaive); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if respNaive["error"] != "multi_protocol_disabled" {
		t.Fatalf("expected error code multi_protocol_disabled for Naive, got: %v", respNaive["error"])
	}
	if calls := naiveAddCalls.Load(); calls != 0 {
		t.Fatalf("expected 0 AddClient calls for Naive on omitted-body enable, got %d", calls)
	}
}

func TestVPNEnableBackendHandler_EnrollmentFailure_RollsBackOrphanClient(t *testing.T) {
	ctx := context.Background()

	t.Run("successful rollback deletes pending lifecycle and revokes remote client", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		vpnCfg := &models.VPNConfig{
			EnableMultiProtocolBackends: true,
			ListenPort:                  51820,
		}
		vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}
		h.vpnSvc = vpnSvc

		r := chi.NewRouter()
		r.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

		// Server with invalid port 99999 so EnableBackendWithConfig fails at dialer creation after AddClient
		sid, err := db.CreateServer(ctx, &models.Server{
			Name:    "naive-node-fail-port",
			Host:    "127.0.0.1",
			SSHPort: 22,
			Protocols: map[string]any{
				"naive": map[string]any{
					"installed": true,
					"port":      99999,
					"domain":    "example.com",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}

		var addedClients []string
		var removedClients []string
		h.registry.Register(&mockProtocolManager{
			protocol: models.ProtocolNaive,
			addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
				username := "orphan-rollback-user"
				addedClients = append(addedClients, username)
				return map[string]any{
					"username": username,
					"password": "temp-password",
					"domain":   "example.com",
				}, nil
			},
			removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
				removedClients = append(removedClients, clientID)
				return nil
			},
		})

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 InternalServerError on failed backend enable, got %d: %s", w.Code, w.Body.String())
		}

		if len(addedClients) != 1 || addedClients[0] != "orphan-rollback-user" {
			t.Fatalf("expected AddClient called for orphan-rollback-user, got %v", addedClients)
		}
		if len(removedClients) != 1 || removedClients[0] != "orphan-rollback-user" {
			t.Fatalf("expected RemoveClient rollback called for orphan-rollback-user, got %v", removedClients)
		}

		lifecycles, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
		if err != nil {
			t.Fatalf("GetPeerLifecycles failed: %v", err)
		}
		if rec, exists := lifecycles["orphan-rollback-user"]; exists {
			t.Fatalf("expected lifecycle record deleted after successful rollback, got %+v", rec)
		}
	})

	t.Run("failed rollback marks lifecycle as failed for reconciler cleanup", func(t *testing.T) {
		h, db, _ := setupTestHandlers(t)
		vpnCfg := &models.VPNConfig{
			EnableMultiProtocolBackends: true,
			ListenPort:                  51820,
		}
		vpnSvc, err := vpn.NewVPNService(db, vpnCfg)
		if err != nil {
			t.Fatalf("NewVPNService failed: %v", err)
		}
		h.vpnSvc = vpnSvc

		r := chi.NewRouter()
		r.Post("/api/vpn/backends/{server_id}/enable", h.VPNEnableBackendHandler)

		sid, err := db.CreateServer(ctx, &models.Server{
			Name:    "naive-node-fail-remove",
			Host:    "127.0.0.1",
			SSHPort: 22,
			Protocols: map[string]any{
				"naive": map[string]any{
					"installed": true,
					"port":      99999,
					"domain":    "example.com",
				},
			},
		})
		if err != nil {
			t.Fatalf("CreateServer failed: %v", err)
		}

		h.registry.Register(&mockProtocolManager{
			protocol: models.ProtocolNaive,
			addClientFn: func(ctx context.Context, server *models.Server, clientParams map[string]any) (map[string]any, error) {
				return map[string]any{
					"username": "orphan-failed-user",
					"password": "temp-password",
					"domain":   "example.com",
				}, nil
			},
			removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
				return errors.New("remote SSH connection down")
			},
		})

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), nil)
		req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 InternalServerError, got %d: %s", w.Code, w.Body.String())
		}

		lifecycles, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
		if err != nil {
			t.Fatalf("GetPeerLifecycles failed: %v", err)
		}
		rec, exists := lifecycles["orphan-failed-user"]
		if !exists {
			t.Fatal("expected lifecycle record to exist with status 'failed' after failed rollback")
		}
		if rec.Status != "failed" {
			t.Fatalf("expected lifecycle status 'failed', got %q (never backend_active)", rec.Status)
		}
	})
}
