package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/reconciliation"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/go-chi/chi/v5"
)

func testPersistenceFailureRecovery(t *testing.T, recoverBeforeDelete bool) {
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
	r.Post("/api/vpn/backends/{server_id}/delete", h.VPNDeleteBackendHandler)
	r.Delete("/api/vpn/backends/{server_id}", h.VPNDeleteBackendHandler)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "operator-proxy-node-fail-persist",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"domain":    "fail.example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	var removedClients []string
	operatorUser := "operator_fail_user_777"
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		getClientsFn: func(context.Context, *models.Server) ([]map[string]any, error) {
			return []map[string]any{{
				"clientId":     operatorUser,
				"username":     operatorUser,
				"creationDate": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
			}}, nil
		},
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			removedClients = append(removedClients, clientID)
			return nil
		},
	})

	paramsRaw, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "fail.example.com",
		Username: operatorUser,
		Password: "supersecretpassword",
	})
	body, _ := json.Marshal(map[string]any{
		"protocol":        "naive",
		"protocol_params": json.RawMessage(paramsRaw),
	})

	// Inject failure on peer_lifecycle insertion
	if _, err := db.ExecContext(ctx, "CREATE TRIGGER fail_peer_lifecycle_insert BEFORE INSERT ON peer_lifecycle BEGIN SELECT RAISE(FAIL, 'injected peer_lifecycle insert failure'); END;"); err != nil {
		t.Fatalf("create trigger failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_peer_lifecycle_insert")
	})

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Invariant: Do NOT return 200 OK when ownership persistence fails; fail closed with 500
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError, got %d: %s", w.Code, w.Body.String())
	}

	// Invariant: Externally managed credential must NOT be revoked/removed
	if len(removedClients) != 0 {
		t.Fatalf("expected 0 remote removals for operator credential, got %v", removedClients)
	}

	// Invariant: Backend must be disabled (fail-closed)
	tun, err := vpnSvc.GetTunnel(sid)
	if err == nil && tun != nil && tun.Enabled {
		t.Fatalf("expected backend tunnel to be disabled, but was enabled")
	}

	persisted, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || persisted == nil || persisted.Enabled {
		t.Fatalf("expected durable disabled row: row=%v err=%v", persisted, err)
	}
	life, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := life[operatorUser]; ok {
		t.Fatal("injected failed insert unexpectedly persisted lifecycle")
	}

	// Model a transient write fault recovering before an administrator removes the failed enrollment.
	if _, err := db.ExecContext(ctx, "DROP TRIGGER fail_peer_lifecycle_insert"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, fmt.Sprintf("legacy_peers_adopted:%d:naive", sid), true); err != nil {
		t.Fatal(err)
	}
	rec := reconciliation.New(db, h.registry)
	if recoverBeforeDelete {
		if err := rec.CleanupZombiePeers(ctx); err != nil {
			t.Fatal(err)
		}
		if len(removedClients) != 0 {
			t.Fatalf("unexpected pre-delete removal: %v", removedClients)
		}
	}
	delReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/delete", sid), nil)
	delReq = delReq.WithContext(middleware.WithSession(delReq.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	delW := httptest.NewRecorder()
	r.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("delete got %d %s", delW.Code, delW.Body.String())
	}
	tunnels, err := db.GetBackendTunnelsByServerID(ctx, sid)
	if err != nil || len(tunnels) != 0 {
		t.Fatalf("backend not actually deleted: count=%d err=%v", len(tunnels), err)
	}
	life, err = db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
	if err != nil {
		t.Fatal(err)
	}
	if recLife, ok := life[operatorUser]; !ok || recLife.Status != "active" {
		t.Fatalf("expected durable active peer_lifecycle record for %s after backend deletion, got: %v", operatorUser, recLife)
	}
	if err := rec.CleanupZombiePeers(ctx); err != nil {
		t.Fatal(err)
	}
	if len(removedClients) != 0 {
		t.Fatalf("externally managed credential revoked after failed enrollment was removed: RemoveClient=%v", removedClients)
	}
}

func TestVPNEnableBackendHandler_OwnershipPersistenceFailure_FailsClosedAndPreservesCredential(t *testing.T) {
	t.Run("delete_before_recovery_cycle", func(t *testing.T) {
		testPersistenceFailureRecovery(t, false)
	})
	t.Run("recovery_cycle_before_delete_control", func(t *testing.T) {
		testPersistenceFailureRecovery(t, true)
	})
}

func TestAudit663_PersistenceFailureThenDelete(t *testing.T) {
	t.Run("delete_before_recovery_cycle", func(t *testing.T) {
		testPersistenceFailureRecovery(t, false)
	})
	t.Run("recovery_cycle_before_delete_control", func(t *testing.T) {
		testPersistenceFailureRecovery(t, true)
	})
}

func TestVPNEnableBackendHandler_OwnershipPersistenceFailure_DeleteWithActiveFaultFailsClosed(t *testing.T) {
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
	r.Post("/api/vpn/backends/{server_id}/delete", h.VPNDeleteBackendHandler)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "operator-proxy-node-fail-delete-closed",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"domain":    "fail.example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	operatorUser := "operator_fail_user_888"
	paramsRaw, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "fail.example.com",
		Username: operatorUser,
		Password: "supersecretpassword",
	})
	body, _ := json.Marshal(map[string]any{
		"protocol":        "naive",
		"protocol_params": json.RawMessage(paramsRaw),
	})

	if _, err := db.ExecContext(ctx, "CREATE TRIGGER fail_peer_lifecycle_insert BEFORE INSERT ON peer_lifecycle BEGIN SELECT RAISE(FAIL, 'injected peer_lifecycle insert failure'); END;"); err != nil {
		t.Fatalf("create trigger failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DROP TRIGGER IF EXISTS fail_peer_lifecycle_insert")
	})

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError, got %d: %s", w.Code, w.Body.String())
	}

	// Trigger is still active! Attempting to delete backend must fail closed because preservation cannot be persisted.
	delReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/delete", sid), nil)
	delReq = delReq.WithContext(middleware.WithSession(delReq.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	delW := httptest.NewRecorder()
	r.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on delete when preservation fails, got %d: %s", delW.Code, delW.Body.String())
	}

	// Assert backend row remains in DB (not deleted)
	persisted, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || persisted == nil {
		t.Fatalf("expected backend row to remain in DB after failed delete: %v, err=%v", persisted, err)
	}
}

func TestVPNEnableBackendHandler_PreservesExistingUserAssociation(t *testing.T) {
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
	r.Delete("/api/vpn/backends/{server_id}", h.VPNDeleteBackendHandler)

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "operator-proxy-node-user-assoc",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{
				"installed": true,
				"port":      443,
				"domain":    "user.example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	sharedUser := "user_and_backend_shared_user"
	realUserID := "user-uuid-original-42"

	// 1. Initial user connection in peer_lifecycle
	if err := db.RecordPeerLifecycle(ctx, sid, models.ProtocolNaive, sharedUser, "User Phone", realUserID, "active"); err != nil {
		t.Fatalf("RecordPeerLifecycle failed: %v", err)
	}

	// A lifecycle-only record does not establish ownership. Create a real user connection.
	if _, err := db.CreateUser(ctx, &models.User{ID: realUserID, Username: "shared-owner", Role: models.RoleUser, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "shared-connection", UserID: realUserID, ServerID: sid,
		Protocol: models.ProtocolNaive, ClientID: sharedUser,
	}); err != nil {
		t.Fatal(err)
	}
	// 2. Admin attempts to enroll a backend using the same credential
	paramsRaw, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "user.example.com",
		Username: sharedUser,
		Password: "supersecretpassword",
	})
	body, _ := json.Marshal(map[string]any{
		"protocol":        "naive",
		"protocol_params": json.RawMessage(paramsRaw),
	})

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/vpn/backends/%d/enable", sid), bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict, got %d: %s", w.Code, w.Body.String())
	}
	if tun, err := db.GetBackendTunnelByServerID(ctx, sid); err != nil || tun != nil {
		t.Fatalf("rejected credential enrolled as backend: %+v, %v", tun, err)
	}
	if conn, err := db.GetConnection(ctx, "shared-connection"); err != nil || conn == nil {
		t.Fatalf("existing user connection changed: %+v, %v", conn, err)
	}
	lifecycles, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
	if err != nil || lifecycles[sharedUser].UserID != realUserID {
		t.Fatalf("user lifecycle changed: %v, %v", lifecycles, err)
	}
}

func TestToggleUserHandler_PreservesSharedBackendCredential(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "naive-srv-toggle",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{"installed": true, "port": 443, "domain": "toggle.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	var removedClients []string
	sharedCred := "shared-toggle-user"
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
			removedClients = append(removedClients, clientID)
			return nil
		},
	})

	naiveParams, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "toggle.example.com",
		Username: sharedCred,
		Password: "password",
	})
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:       sid,
		InterfaceName:  "naive-be-toggle",
		Endpoint:       "127.0.0.1:443",
		Protocol:       models.ProtocolNaive,
		ProtocolParams: naiveParams,
		Enabled:        true,
		Status:         models.TunnelStatusActive,
		StateVersion:   1,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	user := &models.User{
		ID: "u-toggle", Username: "utoggle", Role: models.RoleUser, Enabled: true,
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	conn := &models.UserConnection{
		ID: "c-toggle", UserID: user.ID, ServerID: sid, Protocol: models.ProtocolNaive,
		ClientID: sharedCred, Name: "Shared Toggle Conn", CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}
	_ = db.RecordPeerLifecycle(ctx, sid, models.ProtocolNaive, sharedCred, "Shared Toggle Conn", user.ID, "active")

	body, _ := json.Marshal(models.ToggleUserRequest{Enabled: false})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/toggle", user.ID), bytes.NewReader(body))
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	setupFullUsersRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected shared credential operation to fail, got %d: %s", w.Code, w.Body.String())
	}
	if len(removedClients) != 0 {
		t.Fatalf("backend credential was removed: %v", removedClients)
	}
	if c, err := db.GetConnection(ctx, conn.ID); err != nil || c == nil {
		t.Fatalf("shared connection must remain retryable: %+v, %v", c, err)
	}
	if u, err := db.GetUser(ctx, user.ID); err != nil || u == nil || !u.Enabled {
		t.Fatalf("user must remain enabled: %+v, %v", u, err)
	}
	if tunnels, err := db.GetBackendTunnelsByServerID(ctx, sid); err != nil || len(tunnels) != 1 || !tunnels[0].Enabled {
		t.Fatalf("backend must remain enabled: %+v, %v", tunnels, err)
	}
}

func TestUserHandlers_RotateSharedBackendCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		delete  bool
		failAdd bool
	}{
		{name: "delete rotates and revokes", delete: true},
		{name: "disable rotates and revokes"},
		{name: "delete provisioning failure preserves user and backend", delete: true, failAdd: true},
		{name: "disable provisioning failure preserves user and backend", failAdd: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := t.Context()
			sid, err := db.CreateServer(ctx, &models.Server{Name: "shared-node", Host: "127.0.0.1", SSHPort: 22})
			if err != nil {
				t.Fatal(err)
			}
			uid, err := db.CreateUser(ctx, &models.User{Username: "shared-owner", Role: models.RoleUser, Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			old := "shared-username"
			params, err := json.Marshal(models.NaiveProxyParams{Username: old, Password: "old-secret", Domain: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
				ServerID: sid, InterfaceName: "naive-be", Endpoint: "127.0.0.1:443",
				Protocol: models.ProtocolNaive, ProtocolParams: params, Enabled: true, Status: models.TunnelStatusActive,
			})
			if err != nil {
				t.Fatal(err)
			}
			conn := &models.UserConnection{
				ID: "shared-conn", UserID: uid, ServerID: sid, Protocol: models.ProtocolNaive, ClientID: old,
			}
			if _, err := db.CreateConnection(ctx, conn); err != nil {
				t.Fatal(err)
			}
			if err := db.RecordPeerLifecycle(ctx, sid, models.ProtocolNaive, old, "User", uid, "active"); err != nil {
				t.Fatal(err)
			}
			svc, err := vpn.NewVPNService(db, &models.VPNConfig{EnableMultiProtocolBackends: true})
			if err != nil {
				t.Fatal(err)
			}
			h.vpnSvc = svc
			t.Cleanup(func() {
				if tun, err := svc.GetTunnel(sid); err == nil {
					if dev := svc.GetBackendDeviceForTest(tun.ID); dev != nil {
						_ = dev.Close()
					}
				}
			})
			var removed []string
			var provisioned int
			h.registry.Register(&mockProtocolManager{
				protocol: models.ProtocolNaive,
				addClientFn: func(_ context.Context, _ *models.Server, p map[string]any) (map[string]any, error) {
					provisioned++
					if tc.failAdd {
						return nil, fmt.Errorf("injected add failure")
					}
					if p["name"] != fmt.Sprintf("vpn-backend-%d", sid) {
						t.Fatalf("unexpected replacement name: %v", p)
					}
					return map[string]any{"username": "new-backend-username", "password": "new-secret"}, nil
				},
				removeClientFn: func(_ context.Context, _ *models.Server, id string) error {
					removed = append(removed, id)
					return nil
				},
			})
			path := fmt.Sprintf("/api/users/%s/toggle", uid)
			var body []byte
			if tc.delete {
				path = fmt.Sprintf("/api/users/%s/delete", uid)
			} else {
				body, err = json.Marshal(models.ToggleUserRequest{Enabled: false})
				if err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			w := httptest.NewRecorder()
			setupFullUsersRouter(h).ServeHTTP(w, req)
			wantStatus := http.StatusOK
			if tc.failAdd {
				wantStatus = http.StatusInternalServerError
			}
			if w.Code != wantStatus {
				t.Fatalf("user withdrawal got %d: %s", w.Code, w.Body.String())
			}
			if provisioned != 1 {
				t.Fatalf("AddClient calls: %d", provisioned)
			}
			if tc.failAdd {
				if len(removed) != 0 {
					t.Fatalf("old credential revoked after failed provision: %v", removed)
				}
			} else if len(removed) != 1 || removed[0] != old {
				t.Fatalf("old remote credential not revoked: %v", removed)
			}
			want := "new-backend-username"
			if tc.failAdd {
				want = old
			}
			row, err := db.GetBackendTunnelByServerID(ctx, sid)
			if err != nil || row == nil {
				t.Fatalf("backend row: %+v %v", row, err)
			}
			live, err := svc.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			if !row.Enabled || row.Status != models.TunnelStatusActive ||
				vpn.ExtractClientIDFromProtocolParams(row.Protocol, row.ProtocolParams) != want ||
				vpn.ExtractClientIDFromProtocolParams(live.Protocol, live.ProtocolParams) != want {
				t.Fatalf("backend did not retain active identity %q: row=%+v live=%+v", want, row, live)
			}
			got, err := db.GetConnection(ctx, conn.ID)
			if err != nil || (got != nil) != tc.failAdd {
				t.Fatalf("user connection: %+v %v", got, err)
			}
			user, err := db.GetUser(ctx, uid)
			if err != nil {
				t.Fatal(err)
			}
			if tc.delete {
				if (user != nil) != tc.failAdd {
					t.Fatalf("deleted user state: %+v", user)
				}
			} else if user == nil || user.Enabled != tc.failAdd {
				t.Fatalf("disabled user state: %+v", user)
			}
		})
	}
}

func TestRotationRemoteDelayDoesNotBlockUnrelatedIngressAdmission(t *testing.T) {
	_, db, _ := setupTestHandlers(t)
	ctx := t.Context()
	sid, err := db.CreateServer(ctx, &models.Server{Name: "slow-naive", Host: "127.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	server, err := db.GetServer(ctx, sid)
	if err != nil || server == nil {
		t.Fatalf("load slow server: %+v %v", server, err)
	}
	params, err := json.Marshal(models.NaiveProxyParams{Username: "old-user", Password: "old-secret", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sid, InterfaceName: "slow-naive", Endpoint: "127.0.0.1:443",
		Protocol: models.ProtocolNaive, ProtocolParams: params, Enabled: true, Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	awgID, err := db.CreateServer(ctx, &models.Server{Name: "healthy-awg", Host: "127.0.0.2", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: awgID, InterfaceName: "healthy-awg", Endpoint: "127.0.0.2:51820",
		Protocol: models.ProtocolAWG, Enabled: true, Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	uid, err := db.CreateUser(ctx, &models.User{Username: "admitted", Role: models.RoleUser, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	const peerKey = "healthy-awg-peer-key"
	const assignedIP = "10.100.3.20"
	if _, err := db.CreateConnection(ctx, &models.UserConnection{
		ID: "healthy-awg-conn", UserID: uid, Protocol: models.ProtocolAWG, ClientID: peerKey,
		ClientParams: map[string]any{"assigned_ip": assignedIP},
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := vpn.NewVPNService(db, &models.VPNConfig{EnableMultiProtocolBackends: true})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	mgr := &mockProtocolManager{
		protocol: models.ProtocolNaive,
		addClientFn: func(_ context.Context, _ *models.Server, _ map[string]any) (map[string]any, error) {
			close(entered)
			<-release
			return map[string]any{"username": "replacement", "password": "replacement-secret"}, nil
		},
	}
	rotationDone := make(chan error, 1)
	go func() {
		rotationDone <- svc.RotateSharedBackendCredential(ctx, server, mgr, models.ProtocolNaive, "old-user")
	}()
	rotationFinished := false
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		if !rotationFinished {
			<-rotationDone
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("remote provisioning never started")
	}
	admissionDone := make(chan error, 1)
	go func() {
		session, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ingress.PeerOwnership{
			PeerPublicKey: peerKey, ConnectionID: "healthy-awg-conn", UserID: uid, IP: netip.MustParseAddr(assignedIP),
		})
		if err == nil && (session == nil || backend == nil || backend.ServerID != awgID) {
			err = fmt.Errorf("wrong admission: session=%+v backend=%+v", session, backend)
		}
		admissionDone <- err
	}()
	select {
	case err := <-admissionDone:
		if err != nil {
			t.Fatalf("unrelated ingress admission: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("healthy AWG admission blocked by remote rotation")
	}
	close(release)
	rotationErr := <-rotationDone
	rotationFinished = true
	if rotationErr != nil {
		t.Fatalf("rotation after release: %v", rotationErr)
	}
}

func TestRotationPendingAdministrativeDisableKeepsBackendDetached(t *testing.T) {
	_, db, _ := setupTestHandlers(t)
	ctx := t.Context()
	sid, err := db.CreateServer(ctx, &models.Server{Name: "rotation-disable", Host: "127.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	server, err := db.GetServer(ctx, sid)
	if err != nil || server == nil {
		t.Fatalf("load server: %+v %v", server, err)
	}
	params, err := json.Marshal(models.NaiveProxyParams{Username: "old-user", Password: "old-secret", Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sid, InterfaceName: "naive-be", Endpoint: "127.0.0.1:443",
		Protocol: models.ProtocolNaive, ProtocolParams: params, Enabled: true, Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := vpn.NewVPNService(db, &models.VPNConfig{EnableMultiProtocolBackends: true})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	mgr := &mockProtocolManager{
		protocol: models.ProtocolNaive,
		addClientFn: func(_ context.Context, _ *models.Server, _ map[string]any) (map[string]any, error) {
			close(entered)
			<-release
			return map[string]any{"username": "replacement", "password": "replacement-secret"}, nil
		},
	}
	rotationDone := make(chan error, 1)
	go func() {
		rotationDone <- svc.RotateSharedBackendCredential(ctx, server, mgr, models.ProtocolNaive, "old-user")
	}()
	released := false
	defer func() {
		if !released {
			close(release)
			<-rotationDone
		}
	}()
	select {
	case <-entered:
	case err := <-rotationDone:
		close(release)
		released = true
		t.Fatalf("rotation failed before provisioning: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("remote provisioning never started")
	}
	if err := svc.DisableBackend(ctx, sid); err != nil {
		t.Fatalf("disable during remote provisioning: %v", err)
	}
	close(release)
	released = true
	if err := <-rotationDone; err != nil {
		t.Fatalf("rotation after disable: %v", err)
	}
	row, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || row == nil {
		t.Fatalf("persisted backend: %+v %v", row, err)
	}
	live, err := svc.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []*models.BackendTunnel{row, live} {
		var got models.NaiveProxyParams
		if err := json.Unmarshal(backend.ProtocolParams, &got); err != nil {
			t.Fatal(err)
		}
		if backend.Enabled || backend.DisableReason != models.DisableReasonAdmin ||
			got.Username != "replacement" || got.Password != "replacement-secret" {
			t.Fatalf("disabled backend lost state or rotated credentials: %+v params=%+v", backend, got)
		}
	}
	if dev := svc.GetBackendDeviceForTest(live.ID); dev != nil {
		_ = dev.Close()
		t.Fatal("rotation reattached an administratively disabled backend")
	}
}

func TestRotateVLESSBackendPreservesExplicitEmptyReplacementFlow(t *testing.T) {
	_, db, _ := setupTestHandlers(t)
	ctx := t.Context()
	sid, err := db.CreateServer(ctx, &models.Server{Name: "vless-node", Host: "127.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	server, err := db.GetServer(ctx, sid)
	if err != nil || server == nil {
		t.Fatalf("server: %+v %v", server, err)
	}
	const oldID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	const newID = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
	params, err := json.Marshal(models.VLESSRealityParams{
		UUID: oldID, Flow: "xtls-rprx-vision", PublicKey: "e-JgU2X7X8aH1pQ1pZqUuWbWw5K2s6J8f8gH9jK1lM4",
		ShortID: "0123456789abcdef", ServerName: "example.com", Fingerprint: "chrome",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID: sid, InterfaceName: "vless-be", Endpoint: "127.0.0.1:443",
		Protocol: models.ProtocolVLESS, ProtocolParams: params, Enabled: true, Status: models.TunnelStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	svc, err := vpn.NewVPNService(db, &models.VPNConfig{EnableMultiProtocolBackends: true})
	if err != nil {
		t.Fatal(err)
	}
	mgr := &mockProtocolManager{
		protocol: models.ProtocolVLESS,
		addClientFn: func(_ context.Context, _ *models.Server, _ map[string]any) (map[string]any, error) {
			return map[string]any{"uuid": newID, "flow": ""}, nil
		},
	}
	if err := svc.RotateSharedBackendCredential(ctx, server, mgr, models.ProtocolVLESS, oldID); err != nil {
		t.Fatalf("rotate VLESS: %v", err)
	}
	row, err := db.GetBackendTunnelByServerID(ctx, sid)
	if err != nil || row == nil {
		t.Fatalf("persisted backend: %+v %v", row, err)
	}
	live, err := svc.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []*models.BackendTunnel{row, live} {
		var got models.VLESSRealityParams
		if err := json.Unmarshal(backend.ProtocolParams, &got); err != nil {
			t.Fatal(err)
		}
		if got.UUID != newID || got.Flow != "" {
			t.Fatalf("rotated VLESS params: %+v", got)
		}
	}
	if dev := svc.GetBackendDeviceForTest(live.ID); dev == nil {
		t.Fatal("replacement VLESS device not attached")
	} else {
		t.Cleanup(func() { _ = dev.Close() })
	}
}

func TestDeleteUserHandler_PreservesSharedBackendCredential(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	sid, err := db.CreateServer(ctx, &models.Server{
		Name:    "naive-srv-del",
		Host:    "127.0.0.1",
		SSHPort: 22,
		Protocols: map[string]any{
			"naive": map[string]any{"installed": true, "port": 443, "domain": "del.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CreateServer failed: %v", err)
	}

	var removedClients []string
	sharedCred := "shared-del-user"
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		removeClientFn: func(_ context.Context, _ *models.Server, clientID string) error {
			removedClients = append(removedClients, clientID)
			return nil
		},
	})

	naiveParams, _ := json.Marshal(models.NaiveProxyParams{
		Domain:   "del.example.com",
		Username: sharedCred,
		Password: "password",
	})
	_, err = db.CreateBackendTunnel(ctx, &models.BackendTunnel{
		ServerID:       sid,
		InterfaceName:  "naive-be-del",
		Endpoint:       "127.0.0.1:443",
		Protocol:       models.ProtocolNaive,
		ProtocolParams: naiveParams,
		Enabled:        true,
		Status:         models.TunnelStatusActive,
		StateVersion:   1,
	})
	if err != nil {
		t.Fatalf("CreateBackendTunnel failed: %v", err)
	}

	user := &models.User{
		ID: "u-del", Username: "udel", Role: models.RoleUser, Enabled: true,
	}
	if _, err := db.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	conn := &models.UserConnection{
		ID: "c-del", UserID: user.ID, ServerID: sid, Protocol: models.ProtocolNaive,
		ClientID: sharedCred, Name: "Shared Del Conn", CreatedAt: time.Now(),
	}
	if _, err := db.CreateConnection(ctx, conn); err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}
	_ = db.RecordPeerLifecycle(ctx, sid, models.ProtocolNaive, sharedCred, "Shared Del Conn", user.ID, "active")

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/delete", user.ID), nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()
	setupFullUsersRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected shared credential operation to fail, got %d: %s", w.Code, w.Body.String())
	}
	if len(removedClients) != 0 {
		t.Fatalf("backend credential was removed: %v", removedClients)
	}
	if c, err := db.GetConnection(ctx, conn.ID); err != nil || c == nil {
		t.Fatalf("shared connection must remain retryable: %+v, %v", c, err)
	}
	if u, err := db.GetUser(ctx, user.ID); err != nil || u == nil || !u.Enabled {
		t.Fatalf("user must remain enabled: %+v, %v", u, err)
	}
	if tunnels, err := db.GetBackendTunnelsByServerID(ctx, sid); err != nil || len(tunnels) != 1 || !tunnels[0].Enabled {
		t.Fatalf("backend must remain enabled: %+v, %v", tunnels, err)
	}
}
