package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteRollbackFailureQuarantinesBeforeResponse(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	oldPriv, oldPub := deriveTestKey(t, 70)
	newPriv, newPub := deriveTestKey(t, 71)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	mock, disk := setupRotationMockSSH(original, oldPriv, oldPub, newPriv, newPub)
	base := mock.cmdFunc
	live := oldPub
	newApplied := false
	mock.cmdFunc = func(ctx context.Context, cmd string) (string, string, int, error) {
		if strings.Contains(cmd, "show awg0 public-key") {
			return live, "", 0, nil
		}
		if strings.Contains(cmd, "ip link show") {
			return "2: awg0: <UP> state UP", "", 0, nil
		}
		if strings.Contains(cmd, "syncconf") {
			if strings.Contains(disk(), newPriv) {
				live = newPub
				newApplied = true
				return "", "", 0, nil
			}
			if newApplied {
				cancelRequest()
				return "", "fixture restore sync rejected", 1, errors.New("restore sync rejected")
			}
		}
		return base(ctx, cmd)
	}
	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	id, err := db.CreateServer(context.Background(), &models.Server{Name: "remote-restore-probe", Host: "192.0.2.70", SSHUser: "fixture",
		Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": 51820, "public_key": oldPub}}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc
	if err := svc.EnableBackend(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.SetTunnelEnabledHookForTest(nil); _ = svc.DisableBackend(context.Background(), id) })
	svc.SetUpdateBackendServerPublicKeyErrorForTest(errors.New("fixture VPN reconciliation failure"))
	svc.SetTunnelEnabledHookForTest(func(ctx context.Context, _ int64, enabled bool, _ string) error {
		if !enabled {
			deadline, ok := ctx.Deadline()
			if ctx.Err() != nil || !ok || time.Until(deadline) > 5*time.Second {
				t.Fatal("quarantine must detach cancellation and be bounded")
			}
		}
		return nil
	})
	body, _ := json.Marshal(map[string]any{"protocol": "awg", "config": strings.ReplaceAll(original, oldPriv, newPriv)})
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/servers/%d/server_config/save", id), bytes.NewReader(body))
	req = req.WithContext(requestCtx)
	w := httptest.NewRecorder()
	setupFullServerRouter(h).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatal("expected failed reconciliation")
	}
	server, err := db.GetServer(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := server.Protocols["awg"].(map[string]any)["public_key"].(string)
	if pub != oldPub || tun.PublicKey != oldPub || disk() != original || live != newPub || tun.Enabled {
		t.Fatal("remote split identity must be explicitly quarantined")
	}
	row, err := db.GetBackendTunnel(context.Background(), tun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Enabled || svc.GetBackendDeviceForTest(tun.ID) != nil {
		t.Fatal("quarantine must persist and detach device before response")
	}
}

func TestQueuedConfigSaveRefreshesCompensationSnapshot(t *testing.T) {
	oldPriv, oldPub := deriveTestKey(t, 90)
	aPriv, aPub := deriveTestKey(t, 91)
	bPriv, _ := deriveTestKey(t, 92)
	original := "[Interface]\nPrivateKey = " + oldPriv + "\nAddress = 192.0.2.1/24\nListenPort = 51820\nTable = off\n"
	mock, disk := setupRotationMockSSH(original, oldPriv, oldPub, aPriv, aPub)
	h, db, _ := setupTestHandlersWithMockSSH(t, mock)
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{Name: "queued-save-probe", Host: "192.0.2.90", SSHUser: "fixture",
		Protocols: map[string]any{"awg": map[string]any{"installed": true, "port": 51820, "public_key": oldPub}}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := vpn.NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.vpnSvc = svc
	if err := svc.EnableBackend(ctx, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.DisableBackend(context.Background(), id) })
	// Save B's handler captures this row before its AWG transaction obtains
	// the server lock. Save A can commit while B is queued on that lock.
	staleB, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	requestA, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	aConfig := strings.ReplaceAll(original, oldPriv, aPriv)
	if err := h.awgMgr.WriteConfigurationWithPostApply(ctx, requestA, aConfig, func(tx context.Context) error {
		return h.reconcileAWGServerIdentity(tx, requestA, aConfig)
	}); err != nil {
		t.Fatal(err)
	}
	svc.SetUpdateBackendServerPublicKeyErrorForTest(errors.New("fixture B reconciliation rejected"))
	bConfig := strings.ReplaceAll(original, oldPriv, bPriv)
	err = h.awgMgr.WriteConfigurationWithPostApply(ctx, staleB, bConfig, func(tx context.Context) error {
		return h.reconcileAWGServerIdentity(tx, staleB, bConfig)
	})
	if err == nil {
		t.Fatal("expected ordinary B transaction failure")
	}
	after, err := db.GetServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := after.Protocols["awg"].(map[string]any)["public_key"].(string)
	tun, err := svc.GetTunnel(id)
	if err != nil {
		t.Fatal(err)
	}
	if pub != aPub || tun.PublicKey != aPub || disk() != aConfig || !tun.Enabled {
		t.Fatal("baseline stale-snapshot compensation observation changed")
	}

}
