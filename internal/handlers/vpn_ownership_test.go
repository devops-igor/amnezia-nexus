package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/go-chi/chi/v5"
)

func TestVPNEnableBackendHandler_OwnershipPersistenceFailure_FailsClosedAndPreservesCredential(t *testing.T) {
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
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		removeClientFn: func(ctx context.Context, server *models.Server, clientID string) error {
			removedClients = append(removedClients, clientID)
			return nil
		},
	})

	operatorUser := "operator_fail_user_777"
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

	// 2. Admin enables backend using the same credential
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	// Invariant: user_id must NOT be overwritten by operator_supplied
	lifecycles, err := db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	rec, exists := lifecycles[sharedUser]
	if !exists {
		t.Fatalf("expected peer lifecycle record for %s", sharedUser)
	}
	if rec.UserID != realUserID {
		t.Fatalf("expected user_id to remain %q, got %q", realUserID, rec.UserID)
	}
	if rec.Status != "backend_active" {
		t.Fatalf("expected status 'backend_active', got %q", rec.Status)
	}

	// 3. Delete backend
	delReq := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/vpn/backends/%d", sid), nil)
	delReq = delReq.WithContext(middleware.WithSession(delReq.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	delW := httptest.NewRecorder()
	r.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on delete, got %d: %s", delW.Code, delW.Body.String())
	}

	// Verify user_id is still preserved after backend deletion
	lifecycles, err = db.GetPeerLifecycles(ctx, sid, models.ProtocolNaive)
	if err != nil {
		t.Fatalf("GetPeerLifecycles failed: %v", err)
	}
	rec = lifecycles[sharedUser]
	if rec.UserID != realUserID {
		t.Fatalf("expected user_id to be preserved as %q after backend delete, got %q", realUserID, rec.UserID)
	}
}
