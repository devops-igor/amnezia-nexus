package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/middleware"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

func TestIsNetworkOrDialError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"context deadline exceeded", context.DeadlineExceeded, true},
		{"syscall ECONNREFUSED", syscall.ECONNREFUSED, true},
		{"syscall ETIMEDOUT", syscall.ETIMEDOUT, true},
		{"syscall EHOSTUNREACH", syscall.EHOSTUNREACH, true},
		{"syscall ENETUNREACH", syscall.ENETUNREACH, true},
		{"wrapped syscall", fmt.Errorf("connect failed: %w", syscall.ECONNREFUSED), true},
		{"net.OpError with syscall", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"net.DNSError with timeout", &net.DNSError{IsTimeout: true}, true},
		{"string i/o timeout", errors.New("dial tcp 192.0.2.1:22: i/o timeout"), true},
		{"string connection refused", errors.New("ssh: connect: connection refused"), true},
		{"string no route to host", errors.New("dial: no route to host"), true},
		{"string network is unreachable", errors.New("connect: network is unreachable"), true},
		{"string failed to dial", errors.New("failed to dial SSH server"), true},
		{"generic error", errors.New("something went wrong"), false},
		{"validation error", errors.New("invalid parameter"), false},
		{"database error", errors.New("sql: no rows in result set"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isNetworkOrDialError(tc.err)
			if got != tc.expected {
				t.Errorf("isNetworkOrDialError(%v) = %v; want %v", tc.err, got, tc.expected)
			}
		})
	}
}

func TestDeleteServerHandler_UnreachableHost_StandardDeleteReturns409(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		uninstallFn: func(_ context.Context, _ *models.Server) error {
			return errors.New("dial tcp 192.0.2.1:22: i/o timeout")
		},
	})

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "Unreachable-VLESS",
		Host:    "192.0.2.1",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{"port": 443, "installed": true},
		},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	_, err = db.CreateUser(ctx, &models.User{
		ID:           "test-user-1",
		Username:     "testuser1",
		PasswordHash: "hash",
		Role:         models.RoleAdmin,
		Enabled:      true,
		CreatedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, err = db.CreateConnection(ctx, &models.UserConnection{
		ID:        "conn-unreachable-1",
		UserID:    "test-user-1",
		ServerID:  sID,
		Protocol:  models.ProtocolVLESS,
		ClientID:  "client-1",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", sID), nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()

	setupFullServerRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409 Conflict, got %d (body: %s)", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "server_unreachable" {
		t.Errorf("expected error 'server_unreachable', got %v", resp["error"])
	}
	expectedDetail := "Remote server is unreachable: container cleanup failed. Use force delete to remove from panel."
	if resp["detail"] != expectedDetail {
		t.Errorf("expected detail %q, got %q", expectedDetail, resp["detail"])
	}

	// Verify database records stay intact (fail closed)
	serverAfter, err := db.GetServer(ctx, sID)
	if err != nil || serverAfter == nil {
		t.Errorf("server must stay intact in DB when delete returns 409: err=%v, server=%v", err, serverAfter)
	}
	connAfter, err := db.GetConnection(ctx, "conn-unreachable-1")
	if err != nil || connAfter == nil {
		t.Errorf("connection must stay intact in DB when delete returns 409: err=%v, conn=%v", err, connAfter)
	}
}

func TestDeleteServerHandler_UnreachableHost_ForceDeleteViaQueryParamReturns200(t *testing.T) {
	for _, queryParam := range []string{"?force=true", "?force=1"} {
		t.Run("query_"+queryParam, func(t *testing.T) {
			h, db, _ := setupTestHandlers(t)
			ctx := t.Context()

			var uninstallCalls int
			h.registry.Register(&mockProtocolManager{
				protocol: models.ProtocolVLESS,
				uninstallFn: func(_ context.Context, _ *models.Server) error {
					uninstallCalls++
					return errors.New("dial tcp 192.0.2.1:22: connect: connection refused")
				},
			})

			sID, err := db.CreateServer(ctx, &models.Server{
				Name:    "Unreachable-Force-Query",
				Host:    "192.0.2.1",
				SSHPort: 22,
				SSHUser: "root",
				Protocols: map[string]any{
					models.ProtocolVLESS: map[string]any{"port": 443, "installed": true},
				},
				CreatedAt: time.Now(),
			})
			if err != nil {
				t.Fatalf("create server: %v", err)
			}

			_, err = db.CreateUser(ctx, &models.User{
				ID:           "test-user-force",
				Username:     "testuserforce",
				PasswordHash: "hash",
				Role:         models.RoleAdmin,
				Enabled:      true,
				CreatedAt:    time.Now(),
			})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}

			_, err = db.CreateConnection(ctx, &models.UserConnection{
				ID:        fmt.Sprintf("conn-force-%d", time.Now().UnixNano()),
				UserID:    "test-user-force",
				ServerID:  sID,
				Protocol:  models.ProtocolVLESS,
				ClientID:  "client-force",
				CreatedAt: time.Now(),
			})
			if err != nil {
				t.Fatalf("create connection: %v", err)
			}
			_ = db.SaveKnownHostFingerprint(ctx, sID, "known-host-fingerprint")

			req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete%s", sID, queryParam), nil)
			req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
			w := httptest.NewRecorder()

			setupFullServerRouter(h).ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected HTTP 200 OK on force delete, got %d (body: %s)", w.Code, w.Body.String())
			}

			if uninstallCalls != 1 {
				t.Errorf("expected 1 uninstall attempt with timeout, got %d", uninstallCalls)
			}

			// Verify records purged
			serverAfter, err := db.GetServer(ctx, sID)
			if err == nil && serverAfter != nil {
				t.Errorf("server must be deleted from DB after force delete, found: %+v", serverAfter)
			}
			connsAfter, err := db.GetConnectionsByServerID(ctx, sID)
			if err != nil || len(connsAfter) > 0 {
				t.Errorf("connections must be deleted from DB after force delete, found: %v", connsAfter)
			}
			fp, _ := db.GetKnownHostFingerprint(ctx, sID)
			if fp != "" {
				t.Errorf("known host must be deleted from DB after force delete, found: %s", fp)
			}
		})
	}
}

func TestDeleteServerHandler_UnreachableHost_ForceDeleteViaRequestBodyReturns200(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	var uninstallCalls int
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolNaive,
		uninstallFn: func(_ context.Context, _ *models.Server) error {
			uninstallCalls++
			return errors.New("failed to dial: dial tcp 192.0.2.1:22: i/o timeout")
		},
	})

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "Unreachable-Force-Body",
		Host:    "192.0.2.1",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			models.ProtocolNaive: map[string]any{"port": 443, "installed": true},
		},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	bodyBytes, _ := json.Marshal(map[string]bool{"force": true})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", sID), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()

	setupFullServerRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK on force delete via body, got %d (body: %s)", w.Code, w.Body.String())
	}

	if uninstallCalls != 1 {
		t.Errorf("expected 1 uninstall attempt, got %d", uninstallCalls)
	}

	serverAfter, err := db.GetServer(ctx, sID)
	if err == nil && serverAfter != nil {
		t.Errorf("server must be deleted from DB after force delete, found: %+v", serverAfter)
	}
}

func TestDeleteServerHandler_ReachableHost_StandardDeleteSucceeds(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	var uninstallCalls int
	h.registry.Register(&mockProtocolManager{
		protocol: models.ProtocolVLESS,
		uninstallFn: func(_ context.Context, _ *models.Server) error {
			uninstallCalls++
			return nil
		},
	})

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:    "Reachable-Server",
		Host:    "192.0.2.1",
		SSHPort: 22,
		SSHUser: "root",
		Protocols: map[string]any{
			models.ProtocolVLESS: map[string]any{"port": 443, "installed": true},
		},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", sID), nil)
	req = req.WithContext(middleware.WithSession(req.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	w := httptest.NewRecorder()

	setupFullServerRouter(h).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK on standard delete of reachable server, got %d (body: %s)", w.Code, w.Body.String())
	}

	if uninstallCalls != 1 {
		t.Errorf("expected 1 uninstall call, got %d", uninstallCalls)
	}

	serverAfter, err := db.GetServer(ctx, sID)
	if err == nil && serverAfter != nil {
		t.Errorf("server must be deleted from DB, found: %+v", serverAfter)
	}
}

func TestDeleteServerHandler_ForceDelete_WithFailingVPNBackend(t *testing.T) {
	h, db, _ := setupTestHandlers(t)
	ctx := t.Context()

	vpnSvc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatalf("NewVPNService: %v", err)
	}
	t.Cleanup(func() { _ = vpnSvc.Stop() })
	h.vpnSvc = vpnSvc

	sID, err := db.CreateServer(ctx, &models.Server{
		Name:      "Failing-VPN-Force",
		Host:      "192.0.2.1",
		SSHPort:   22,
		SSHUser:   "root",
		Protocols: map[string]any{},
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	// Inject error into vpnSvc DeleteBackend
	injectedErr := errors.New("simulated backend teardown failure")
	vpnSvc.SetDeleteBackendErrorForTest(injectedErr)
	t.Cleanup(func() { vpnSvc.SetDeleteBackendErrorForTest(nil) })

	// When force=false, deletion fails with 500
	reqStd := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete", sID), nil)
	reqStd = reqStd.WithContext(middleware.WithSession(reqStd.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wStd := httptest.NewRecorder()
	setupFullServerRouter(h).ServeHTTP(wStd, reqStd)

	if wStd.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on standard delete with failing backend, got %d", wStd.Code)
	}

	// When force=true, deletion continues despite backend teardown failure and purges DB records
	reqForce := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/delete?force=true", sID), nil)
	reqForce = reqForce.WithContext(middleware.WithSession(reqForce.Context(), &models.SessionData{UserID: "admin", Role: models.RoleAdmin}))
	wForce := httptest.NewRecorder()
	setupFullServerRouter(h).ServeHTTP(wForce, reqForce)

	if wForce.Code != http.StatusOK {
		t.Fatalf("expected 200 on force delete with failing backend, got %d (body: %s)", wForce.Code, wForce.Body.String())
	}

	serverAfter, err := db.GetServer(ctx, sID)
	if err == nil && serverAfter != nil {
		t.Errorf("server must be deleted from DB after force delete, found: %+v", serverAfter)
	}
}
