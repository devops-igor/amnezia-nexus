package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestDeleteServerHandler_WithActiveVPNBackend(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	srv := &models.Server{
		Name:    "VPN-Backend-Server",
		Host:    "192.168.10.50",
		SSHPort: 22,
		SSHUser: "root",
		SSHPass: "pass123",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "backend-pubkey-123",
			},
		},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := vpnSvc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	// Verify backend tunnel exists in in-memory pool and in DB
	tun, err := vpnSvc.GetTunnel(serverID)
	if err != nil || tun == nil {
		t.Fatalf("expected backend tunnel in pool before delete, got error: %v", err)
	}
	dbTun, err := db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || dbTun == nil {
		t.Fatalf("expected backend_tunnels row in DB before delete, got error: %v", err)
	}

	serverRouter := setupFullServerRouter(h)
	vpnRouter := setupFullVPNRouter(h)

	// Verify /api/vpn/backends lists it before delete
	reqList := httptest.NewRequest(http.MethodGet, "/api/vpn/backends", nil)
	wList := httptest.NewRecorder()
	vpnRouter.ServeHTTP(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/vpn/backends, got %d", wList.Code)
	}
	var listResp struct {
		Backends []struct {
			ServerID int64 `json:"server_id"`
		} `json:"backends"`
	}
	if err := json.NewDecoder(wList.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed to decode backends: %v", err)
	}
	foundInList := false
	for _, b := range listResp.Backends {
		if b.ServerID == serverID {
			foundInList = true
			break
		}
	}
	if !foundInList {
		t.Fatal("expected backend to be listed in /api/vpn/backends before delete")
	}

	// Delete server
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DeleteServerHandler, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	// 1. In-memory tunnel must be removed
	tunAfter, err := vpnSvc.GetTunnel(serverID)
	if err == nil || tunAfter != nil {
		t.Fatalf("expected tunnel to be removed from in-memory pool, but GetTunnel succeeded: %+v", tunAfter)
	}
	if !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound, got: %v", err)
	}

	// 2. DB backend_tunnels row must be removed
	dbTunAfter, err := db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil {
		t.Errorf("GetBackendTunnelByServerID after delete returned error: %v", err)
	}
	if dbTunAfter != nil {
		t.Errorf("expected backend_tunnels row to be deleted from DB, got: %+v", dbTunAfter)
	}

	// 3. /api/vpn/backends must no longer list it (no zombie tunnel)
	wListAfter := httptest.NewRecorder()
	vpnRouter.ServeHTTP(wListAfter, httptest.NewRequest(http.MethodGet, "/api/vpn/backends", nil))
	if wListAfter.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/vpn/backends after delete, got %d", wListAfter.Code)
	}
	var listRespAfter struct {
		Backends []struct {
			ServerID int64 `json:"server_id"`
		} `json:"backends"`
	}
	if err := json.NewDecoder(wListAfter.Body).Decode(&listRespAfter); err != nil {
		t.Fatalf("failed to decode backends after delete: %v", err)
	}
	for _, b := range listRespAfter.Backends {
		if b.ServerID == serverID {
			t.Errorf("server %d still found in /api/vpn/backends after delete (zombie tunnel)", serverID)
		}
	}

	// 4. Server row must be deleted from DB
	srvAfter, err := db.GetServer(ctx, serverID)
	if err == nil && srvAfter != nil {
		t.Errorf("expected server to be deleted from DB, but still exists: %+v", srvAfter)
	}
}

func TestDeleteServerHandler_WithoutVPNBackend(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	srv := &models.Server{
		Name:      "Non-VPN-Server",
		Host:      "192.168.10.51",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "pass123",
		Protocols: map[string]any{},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Ensure it is NOT a VPN backend
	if _, err := vpnSvc.GetTunnel(serverID); !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Fatalf("expected ErrTunnelNotFound before delete, got: %v", err)
	}

	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when deleting non-VPN server, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	srvAfter, err := db.GetServer(ctx, serverID)
	if err == nil && srvAfter != nil {
		t.Errorf("expected server %d to be deleted from DB", serverID)
	}
}

func TestDeleteServerHandler_NilVPNService(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())
	h.vpnSvc = nil

	srv := &models.Server{
		Name:      "VPN-Disabled-Server",
		Host:      "192.168.10.52",
		SSHPort:   22,
		SSHUser:   "root",
		SSHPass:   "pass123",
		Protocols: map[string]any{},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when h.vpnSvc is nil, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	srvAfter, err := db.GetServer(ctx, serverID)
	if err == nil && srvAfter != nil {
		t.Errorf("expected server %d to be deleted from DB", serverID)
	}
}

func TestDeleteServerHandler_BackendTeardownError_FailsClosed(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	srv := &models.Server{
		Name:    "Teardown-Fail-Server",
		Host:    "192.168.10.53",
		SSHPort: 22,
		SSHUser: "root",
		SSHPass: "pass123",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "backend-pubkey-fail",
			},
		},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := vpnSvc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	_ = db.SaveKnownHostFingerprint(ctx, serverID, "fingerprint-abc")

	// Inject unexpected error into DeleteBackend
	injectedErr := errors.New("simulated backend teardown failure")
	vpnSvc.SetDeleteBackendErrorForTest(injectedErr)
	t.Cleanup(func() { vpnSvc.SetDeleteBackendErrorForTest(nil) })

	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)

	// Must fail fast with 500
	if wDel.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError on teardown failure, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	var errResp map[string]any
	if err := json.NewDecoder(wDel.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"] != "internal_error" {
		t.Errorf("expected error 'internal_error', got %v", errResp["error"])
	}
	if errResp["detail"] != "Failed to teardown VPN backend" {
		t.Errorf("expected detail 'Failed to teardown VPN backend', got %v", errResp["detail"])
	}

	// Server row MUST still exist in DB (fail-closed, not half-deleted)
	srvAfter, err := db.GetServer(ctx, serverID)
	if err != nil || srvAfter == nil {
		t.Fatalf("server row was deleted or errored on teardown failure: err=%v, srv=%v", err, srvAfter)
	}
	if srvAfter.ID != serverID {
		t.Errorf("expected server ID %d, got %d", serverID, srvAfter.ID)
	}

	// Backend tunnel row MUST still exist in DB
	dbTun, err := db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil || dbTun == nil {
		t.Errorf("backend tunnel row should remain intact, err=%v, dbTun=%v", err, dbTun)
	}
}

func TestDeleteServerHandler_WithActiveVPNBackend_DrainsAndMigratesSessions(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	// Server 1
	s1 := &models.Server{
		Name:    "VPN-Backend-1",
		Host:    "192.168.10.101",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "pubkey-1",
			},
		},
		CreatedAt: time.Now(),
	}
	s1ID, err := db.CreateServer(ctx, s1)
	if err != nil {
		t.Fatalf("CreateServer 1 failed: %v", err)
	}
	if err := vpnSvc.EnableBackend(ctx, s1ID); err != nil {
		t.Fatalf("EnableBackend 1 failed: %v", err)
	}

	// Server 2
	s2 := &models.Server{
		Name:    "VPN-Backend-2",
		Host:    "192.168.10.102",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51821,
				"public_key": "pubkey-2",
			},
		},
		CreatedAt: time.Now(),
	}
	s2ID, err := db.CreateServer(ctx, s2)
	if err != nil {
		t.Fatalf("CreateServer 2 failed: %v", err)
	}
	if err := vpnSvc.EnableBackend(ctx, s2ID); err != nil {
		t.Fatalf("EnableBackend 2 failed: %v", err)
	}

	tun1, err := vpnSvc.GetTunnel(s1ID)
	if err != nil || tun1 == nil {
		t.Fatalf("GetTunnel 1 failed: %v", err)
	}
	tun2, err := vpnSvc.GetTunnel(s2ID)
	if err != nil || tun2 == nil {
		t.Fatalf("GetTunnel 2 failed: %v", err)
	}

	// Create user connection for portal client (serverID = 0)
	uID, err := db.CreateUser(ctx, &models.User{
		Username: "drain-user",
		Role:     "user",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	_, err = db.CreateConnection(ctx, &models.UserConnection{
		UserID:   uID,
		ServerID: 0,
		Protocol: "awg",
		ClientID: "peer-drain-alice",
	})
	if err != nil {
		t.Fatalf("CreateConnection failed: %v", err)
	}

	sess, initialBackend, err := vpnSvc.HandleIncomingPeerForTest(ctx, "peer-drain-alice")
	if err != nil {
		t.Fatalf("HandleIncomingPeerForTest failed: %v", err)
	}
	if initialBackend == nil || sess == nil {
		t.Fatalf("expected non-nil session and backend")
	}

	// Delete server 1
	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", s1ID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	// Server 1 gone from pool and DB
	if _, err := vpnSvc.GetTunnel(s1ID); !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Errorf("expected tun1 gone from pool, got: %v", err)
	}
	if srv, _ := db.GetServer(ctx, s1ID); srv != nil {
		t.Errorf("expected server 1 gone from db")
	}
	if bt, _ := db.GetBackendTunnelByServerID(ctx, s1ID); bt != nil {
		t.Errorf("expected backend_tunnels 1 gone from db")
	}

	// Server 2 still in pool and DB
	if _, err := vpnSvc.GetTunnel(s2ID); err != nil {
		t.Errorf("expected tun2 still in pool, got: %v", err)
	}
	if srv, _ := db.GetServer(ctx, s2ID); srv == nil {
		t.Errorf("expected server 2 still in db")
	}
	if bt, _ := db.GetBackendTunnelByServerID(ctx, s2ID); bt == nil {
		t.Errorf("expected backend_tunnels 2 still in db")
	}

	// Session must have failed over to server 2's tunnel
	sessAfter, err := db.GetVPNSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetVPNSessionByID failed: %v", err)
	}
	if sessAfter == nil {
		t.Fatal("expected session to survive and migrate")
	}
	if sessAfter.BackendTunnelID != tun2.ID {
		t.Errorf("expected session BackendTunnelID %d, got %d", tun2.ID, sessAfter.BackendTunnelID)
	}
}

func TestDeleteServerHandler_ConcurrentEnableBackend_CannotResurrectZombieTunnel(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	srv := &models.Server{
		Name:    "Zombie-Race-Server",
		Host:    "192.168.10.60",
		SSHPort: 22,
		SSHUser: "root",
		SSHPass: "pass123",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "backend-pubkey-zombie",
			},
		},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := vpnSvc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	tunBefore, err := vpnSvc.GetTunnel(serverID)
	if err != nil || tunBefore == nil {
		t.Fatalf("expected backend tunnel before delete: %v", err)
	}

	preAddCalled := make(chan struct{})
	resumeAdd := make(chan struct{})
	vpnSvc.SetEnableBackendPreAddTunnelHookForTest(func() {
		close(preAddCalled)
		<-resumeAdd
	})
	t.Cleanup(func() {
		vpnSvc.SetEnableBackendPreAddTunnelHookForTest(nil)
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- vpnSvc.EnableBackend(ctx, serverID)
	}()

	select {
	case <-preAddCalled:
	case <-time.After(5 * time.Second):
		close(resumeAdd)
		t.Fatal("timed out waiting for goroutine A to reach preAdd hook")
	}

	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		close(resumeAdd)
		t.Fatalf("expected 200 OK on DeleteServerHandler, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	close(resumeAdd)
	var enableErr error
	select {
	case enableErr = <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for goroutine A to finish EnableBackend")
	}

	if enableErr == nil {
		t.Fatal("expected EnableBackend to fail on tombstoned server, got nil")
	}
	if !errors.Is(enableErr, vpn.ErrServerNotFound) {
		t.Errorf("expected ErrServerNotFound, got: %v", enableErr)
	}

	// 1. Server row absent from DB
	srvAfter, err := db.GetServer(ctx, serverID)
	if err == nil && srvAfter != nil {
		t.Errorf("expected server to be deleted from DB, but still exists: %+v", srvAfter)
	}

	// 2. backend_tunnels absent from DB
	dbTunAfter, err := db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil {
		t.Errorf("GetBackendTunnelByServerID after delete returned error: %v", err)
	}
	if dbTunAfter != nil {
		t.Errorf("expected backend_tunnels row to be deleted from DB, got: %+v", dbTunAfter)
	}

	// 3. pool.GetTunnel(serverID) == ErrTunnelNotFound
	tunAfter, err := vpnSvc.GetTunnel(serverID)
	if err == nil || tunAfter != nil {
		t.Fatalf("expected tunnel to be absent from in-memory pool, got: %+v", tunAfter)
	}
	if !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound, got: %v", err)
	}

	// 4. /api/vpn/backends has no server 1
	vpnRouter := setupFullVPNRouter(h)
	wListAfter := httptest.NewRecorder()
	vpnRouter.ServeHTTP(wListAfter, httptest.NewRequest(http.MethodGet, "/api/vpn/backends", nil))
	if wListAfter.Code != http.StatusOK {
		t.Fatalf("expected 200 from /api/vpn/backends after delete, got %d", wListAfter.Code)
	}
	var listRespAfter struct {
		Backends []struct {
			ServerID int64 `json:"server_id"`
		} `json:"backends"`
	}
	if err := json.NewDecoder(wListAfter.Body).Decode(&listRespAfter); err != nil {
		t.Fatalf("failed to decode backends after delete: %v", err)
	}
	for _, b := range listRespAfter.Backends {
		if b.ServerID == serverID {
			t.Errorf("server %d still found in /api/vpn/backends after delete (zombie tunnel)", serverID)
		}
	}

	// 5. No backend device attached
	if dev := vpnSvc.GetBackendDeviceForTest(tunBefore.ID); dev != nil {
		t.Errorf("expected no backend device for tunnel %d, got %+v", tunBefore.ID, dev)
	}
}

func TestDeleteServerHandler_SelfHealing_CannotResurrectDeletedServer(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	srv := &models.Server{
		Name:    "Self-Healing-Target-Server",
		Host:    "192.168.10.70",
		SSHPort: 22,
		SSHUser: "root",
		SSHPass: "pass123",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "backend-pubkey-selfheal",
			},
		},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := vpnSvc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	// Delete server
	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DeleteServerHandler, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	// Attempt self-healing resurrection
	selfHealCtx := tunnel.ContextWithSelfHealing(ctx)
	enableErr := vpnSvc.EnableBackend(selfHealCtx, serverID)
	if enableErr == nil {
		t.Fatal("expected EnableBackend with self-healing to fail on deleted server, got nil")
	}
	if !errors.Is(enableErr, vpn.ErrServerNotFound) {
		t.Errorf("expected ErrServerNotFound, got: %v", enableErr)
	}

	// Ensure no tunnel was created in pool
	tunAfter, err := vpnSvc.GetTunnel(serverID)
	if err == nil || tunAfter != nil {
		t.Fatalf("expected no tunnel in pool, but found: %+v", tunAfter)
	}
	if !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound, got: %v", err)
	}

	// Ensure no tunnel in DB
	dbTun, err := db.GetBackendTunnelByServerID(ctx, serverID)
	if err != nil {
		t.Errorf("GetBackendTunnelByServerID error: %v", err)
	}
	if dbTun != nil {
		t.Errorf("expected no backend_tunnels in DB, got: %+v", dbTun)
	}
}

func TestDeleteServerHandler_BackupRestoreSameID_CanEnableBackend(t *testing.T) {
	ctx := context.Background()
	h, db, _ := setupTestHandlersWithMockSSH(t, newAWGMockSSH())

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService failed: %v", err)
	}
	vpnSvc.SetProbeFunc(func(ctx context.Context, endpoint, serverPubKey, clientPrivKey, psk, hpKey string, h1, h2 any, s1, s2 int, timeout time.Duration) (time.Duration, error) {
		return 10 * time.Millisecond, nil
	})
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	srv := &models.Server{
		Name:    "Backup-Restore-Target-Server",
		Host:    "192.168.10.80",
		SSHPort: 22,
		SSHUser: "root",
		SSHPass: "pass123",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "backend-pubkey-restore",
			},
		},
		CreatedAt: time.Now(),
	}
	serverID, err := db.CreateServer(ctx, srv)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := vpnSvc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("EnableBackend failed: %v", err)
	}

	tunBefore, err := vpnSvc.GetTunnel(serverID)
	if err != nil || tunBefore == nil {
		t.Fatalf("expected backend tunnel before delete: %v", err)
	}

	// Delete server via DeleteServerHandler
	serverRouter := setupFullServerRouter(h)
	reqDel := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", serverID), nil)
	wDel := httptest.NewRecorder()
	serverRouter.ServeHTTP(wDel, reqDel)
	if wDel.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on DeleteServerHandler, got %d (body: %s)", wDel.Code, wDel.Body.String())
	}

	// Verify server is deleted from DB and pool
	srvAfterDel, err := db.GetServer(ctx, serverID)
	if err == nil && srvAfterDel != nil {
		t.Fatalf("expected server to be deleted from DB, but still exists: %+v", srvAfterDel)
	}

	tunAfterDel, err := vpnSvc.GetTunnel(serverID)
	if err == nil || tunAfterDel != nil {
		t.Fatalf("expected tunnel to be absent from pool, but found: %+v", tunAfterDel)
	}
	if !errors.Is(err, tunnel.ErrTunnelNotFound) {
		t.Errorf("expected ErrTunnelNotFound, got: %v", err)
	}

	// Verify that while server is absent from DB, EnableBackend cannot resurrect it
	delErr := vpnSvc.EnableBackend(ctx, serverID)
	if delErr == nil {
		t.Fatal("expected EnableBackend on deleted server to fail, got nil")
	}
	if !errors.Is(delErr, vpn.ErrServerNotFound) {
		t.Errorf("expected ErrServerNotFound, got: %v", delErr)
	}

	// Recreate/restore server in DB with the same ID via restoreBackupServers
	serverBackup := map[string]any{
		"id":       serverID,
		"name":     srv.Name,
		"host":     srv.Host,
		"ssh_user": srv.SSHUser,
		"ssh_port": srv.SSHPort,
		"ssh_pass": srv.SSHPass,
		"protocols": map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": "backend-pubkey-restore",
			},
		},
	}
	restoredCount, _ := h.restoreBackupServers(ctx, []map[string]any{serverBackup})
	if restoredCount != 1 {
		t.Fatalf("expected 1 restored server, got %d", restoredCount)
	}

	restoredSrv, err := db.GetServer(ctx, serverID)
	if err != nil || restoredSrv == nil {
		t.Fatalf("failed to load restored server %d: %v", serverID, err)
	}
	if restoredSrv.ID != serverID {
		t.Fatalf("expected restored server ID %d, got %d", serverID, restoredSrv.ID)
	}

	// EnableBackend on that server ID: verify it SUCCEEDS cleanly without requiring process restart!
	if err := vpnSvc.EnableBackend(ctx, serverID); err != nil {
		t.Fatalf("expected EnableBackend to succeed on restored server %d without process restart, got: %v", serverID, err)
	}

	tunRestored, err := vpnSvc.GetTunnel(serverID)
	if err != nil || tunRestored == nil {
		t.Fatalf("expected backend tunnel for restored server: %v", err)
	}
	if !tunRestored.Enabled {
		t.Errorf("expected restored tunnel to be enabled")
	}
}
