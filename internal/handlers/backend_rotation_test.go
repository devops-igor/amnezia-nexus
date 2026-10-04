package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"golang.org/x/crypto/curve25519"
)

type opsLiveStatusProvider struct {
	publicKey string
	calls     int
}

func (p *opsLiveStatusProvider) GetServerStatus(_ context.Context, _ *models.Server) (map[string]any, error) {
	p.calls++
	return map[string]any{"container_running": true, "public_key": p.publicKey, "port": 51820}, nil
}

func deriveTestKey(t *testing.T, seed byte) (string, string) {
	t.Helper()
	raw := bytes.Repeat([]byte{seed}, 32)
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(pub)
}

func setupRotationMockSSH(initialConfig string, oldPriv, oldPub, newPriv, newPub string) (*testMockSSHClient, func() string) {
	current := initialConfig
	uploads := map[string][]byte{}
	mock := &testMockSSHClient{}
	mock.cmdFunc = func(_ context.Context, cmd string) (string, string, int, error) {
		switch {
		case strings.Contains(cmd, "docker ps"):
			return "amnezia-awg2", "", 0, nil
		case strings.Contains(cmd, "docker inspect"):
			return "container-fixture", "", 0, nil
		case strings.Contains(cmd, "docker exec") && strings.Contains(cmd, " cat ") && strings.Contains(cmd, "awg0.conf"):
			return current, "", 0, nil
		case strings.Contains(cmd, "show awg0 public-key"):
			if strings.Contains(current, newPriv) {
				return newPub, "", 0, nil
			}
			return oldPub, "", 0, nil
		case strings.Contains(cmd, "docker cp") && strings.Contains(cmd, "_amnz_edit_config"):
			for p, data := range uploads {
				if strings.Contains(cmd, p) {
					current = string(data)
					return "", "", 0, nil
				}
			}
		}
		return "", "", 0, nil
	}
	mock.uploadFn = func(_ context.Context, p string, data []byte) error {
		uploads[p] = append([]byte(nil), data...)
		return nil
	}
	return mock, func() string { return current }
}

func TestBackendIdentityRotationReconcilesPersistedAndActiveIdentity(t *testing.T) {
	oldPriv, oldPub := deriveTestKey(t, 1)
	newPriv, newPub := deriveTestKey(t, 2)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	mock, _ := setupRotationMockSSH(original, oldPriv, oldPub, newPriv, newPub)

	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{
		Name:    "rotation-fixture",
		Host:    "192.0.2.91",
		SSHUser: "fixture",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": oldPub,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc

	if err = svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}

	r := setupFullServerRouter(h)
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": strings.ReplaceAll(original, oldPriv, newPriv)})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("configuration save failed: status=%d", w.Code)
	}

	server, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	live, err := h.awgMgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	if live != newPub {
		t.Fatal("rotation fixture did not change the real manager's observed remote identity")
	}

	cached, _ := server.Protocols["awg"].(map[string]any)["public_key"].(string)
	if cached != newPub {
		t.Errorf("cached identity in DB was not reconciled: got %q, want %q", cached, newPub)
	}

	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if tun.PublicKey != newPub {
		t.Errorf("active tunnel public key was not reconciled: got %q, want %q", tun.PublicKey, newPub)
	}

	provider := &opsLiveStatusProvider{publicKey: newPub}
	svc.SetAWGStatusProvider(provider)
	if err = svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	tun, err = svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if tun.PublicKey != newPub {
		t.Errorf("re-enabled tunnel retains old public key: got %q, want %q", tun.PublicKey, newPub)
	}
}

func TestBackendIdentityRotation_UnchangedKeyNoOp(t *testing.T) {
	oldPriv, oldPub := deriveTestKey(t, 10)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	mock, _ := setupRotationMockSSH(original, oldPriv, oldPub, "", "")

	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{
		Name:    "unchanged-key-fixture",
		Host:    "192.0.2.92",
		SSHUser: "fixture",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": oldPub,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc

	if err = svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}

	r := setupFullServerRouter(h)
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": original})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("configuration save failed: status=%d", w.Code)
	}

	server, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cached, _ := server.Protocols["awg"].(map[string]any)["public_key"].(string)
	if cached != oldPub {
		t.Errorf("cached identity unexpectedly changed: got %q, want %q", cached, oldPub)
	}
}

func TestBackendIdentityRotation_DisabledBackend(t *testing.T) {
	oldPriv, oldPub := deriveTestKey(t, 20)
	newPriv, newPub := deriveTestKey(t, 21)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	mock, _ := setupRotationMockSSH(original, oldPriv, oldPub, newPriv, newPub)

	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{
		Name:    "disabled-rotation-fixture",
		Host:    "192.0.2.93",
		SSHUser: "fixture",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": oldPub,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc

	// Start enabled then administratively disable it
	if err = svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = svc.DisableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}

	r := setupFullServerRouter(h)
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": strings.ReplaceAll(original, oldPriv, newPriv)})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("configuration save failed: status=%d", w.Code)
	}

	server, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cached, _ := server.Protocols["awg"].(map[string]any)["public_key"].(string)
	if cached != newPub {
		t.Errorf("cached identity was not updated on disabled backend: got %q, want %q", cached, newPub)
	}

	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if tun.PublicKey != newPub {
		t.Errorf("tunnel public key was not updated on disabled backend: got %q, want %q", tun.PublicKey, newPub)
	}
	if tun.Enabled {
		t.Errorf("disabled backend was unexpectedly re-enabled during key rotation")
	}
}

func TestBackendIdentityRotation_ReconciliationFailureRollback(t *testing.T) {
	oldPriv, oldPub := deriveTestKey(t, 30)
	newPriv, newPub := deriveTestKey(t, 31)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	mock, currentConfig := setupRotationMockSSH(original, oldPriv, oldPub, newPriv, newPub)

	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{
		Name:    "rollback-fixture",
		Host:    "192.0.2.94",
		SSHUser: "fixture",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": oldPub,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc

	if err = svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}

	// Inject failure into VPN service reconciliation
	svc.SetUpdateBackendServerPublicKeyErrorForTest(errors.New("injected vpn reconciliation failure"))

	r := setupFullServerRouter(h)
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": strings.ReplaceAll(original, oldPriv, newPriv)})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on reconciliation failure, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "reconcile_failed") {
		t.Errorf("expected error response to contain reconcile_failed, got %s", w.Body.String())
	}

	server, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cached, _ := server.Protocols["awg"].(map[string]any)["public_key"].(string)
	if cached != oldPub {
		t.Errorf("expected cached identity in DB to be rolled back to %q, got %q", oldPub, cached)
	}
	if got := currentConfig(); got != original {
		t.Errorf("expected remote AWG configuration to be rolled back after reconciliation failure\nwant:\n%s\ngot:\n%s", original, got)
	}
	live, err := h.awgMgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("read rolled-back remote identity: %v", err)
	}
	if live != oldPub {
		t.Errorf("expected live remote identity to be rolled back to %q, got %q", oldPub, live)
	}
	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatalf("GetTunnel after rollback: %v", err)
	}
	if tun.PublicKey != oldPub {
		t.Errorf("expected VPN pool identity to remain %q after rollback, got %q", oldPub, tun.PublicKey)
	}
}


func TestBackendIdentityRotation_VPNRollbackFailureKeepsNewIdentityAndQuarantines(t *testing.T) {
	oldPriv, oldPub := deriveTestKey(t, 40)
	newPriv, newPub := deriveTestKey(t, 41)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	rotated := strings.ReplaceAll(original, oldPriv, newPriv)
	mock, currentConfig := setupRotationMockSSH(original, oldPriv, oldPub, newPriv, newPub)

	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{
		Name:    "rollback-failure-fixture",
		Host:    "192.0.2.95",
		SSHUser: "fixture",
		Protocols: map[string]any{
			"awg": map[string]any{
				"installed":  true,
				"port":       51820,
				"public_key": oldPub,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc
	if err = svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}

	// NEW is persisted successfully. Forwarder reconciliation then fails, and
	// the compensation attempt to OLD fails too, producing ErrVPNRollbackFailed.
	svc.SetSyncBackendForwarderHookForTest(func() error {
		return errors.New("injected forwarder reconciliation failure")
	})
	svc.SetTunnelPublicKeyHookForTest(func(_ context.Context, _ int64, publicKey string) error {
		if publicKey == oldPub {
			return errors.New("injected public-key rollback failure")
		}
		return nil
	})

	r := setupFullServerRouter(h)
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": rotated})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", id), bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 on failed VPN compensation, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "reconcile_failed") {
		t.Fatalf("expected reconcile_failed response, got %s", w.Body.String())
	}

	// Once VPN rollback has failed, OLD is no longer a safe convergence target.
	// The transaction must keep the already-applied NEW remote config/DB identity
	// and quarantine the backend instead of rolling remote+DB back to OLD.
	if got := currentConfig(); !strings.Contains(got, newPriv) {
		t.Fatalf("remote AWG config was rolled away from the convergence identity: %s", got)
	}
	server, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	cached, _ := server.Protocols["awg"].(map[string]any)["public_key"].(string)
	if cached != newPub {
		t.Fatalf("server DB identity=%q, want kept NEW identity %q", cached, newPub)
	}
	live, err := h.awgMgr.GetServerPublicKey(ctx, server)
	if err != nil {
		t.Fatalf("read live identity: %v", err)
	}
	if live != newPub {
		t.Fatalf("remote live identity=%q, want kept NEW identity %q", live, newPub)
	}
	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatalf("GetTunnel after failed compensation: %v", err)
	}
	if tun.PublicKey != newPub {
		t.Fatalf("VPN pool identity=%q, want NEW identity %q after failed rollback", tun.PublicKey, newPub)
	}
	if tun.Enabled {
		t.Fatal("backend remained enabled after VPN identity rollback failure; expected quarantine")
	}
}
