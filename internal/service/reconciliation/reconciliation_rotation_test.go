package reconciliation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn"
)

type rotationNaiveManager struct {
	*mockZombiePeerProtocolManager
	failAdd bool
	added   []string
}

func (m *rotationNaiveManager) AddClient(_ context.Context, _ *models.Server, params map[string]any) (map[string]any, error) {
	if m.failAdd {
		return nil, errors.New("injected provisioning failure")
	}
	name, _ := params["name"].(string)
	m.added = append(m.added, name)
	return map[string]any{"username": name, "password": "new-secret"}, nil
}

func TestReconciler_WithdrawDisabledOwnerConns_RotatesBackend(t *testing.T) {
	for _, failAdd := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail_add_%v", failAdd), func(t *testing.T) {
			db, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := t.Context()
			server := &models.Server{Name: "shared", Host: "127.0.0.1", SSHPort: 22}
			sid, err := db.CreateServer(ctx, server)
			if err != nil {
				t.Fatal(err)
			}
			server.ID = sid
			oldID := "disabled-user"
			params, err := json.Marshal(models.NaiveProxyParams{Username: oldID, Password: "old-secret", Domain: "example.com"})
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
			_, err = db.CreateUser(ctx, &models.User{ID: "disabled", Username: "disabled", Enabled: false})
			if err != nil {
				t.Fatal(err)
			}
			conn := &models.UserConnection{
				ID: "disabled-conn", UserID: "disabled", ServerID: sid, Protocol: models.ProtocolNaive, ClientID: oldID,
			}
			if _, err = db.CreateConnection(ctx, conn); err != nil {
				t.Fatal(err)
			}
			vpnSvc, err := vpn.NewVPNService(db, &models.VPNConfig{EnableMultiProtocolBackends: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if tun, err := vpnSvc.GetTunnel(sid); err == nil {
					if dev := vpnSvc.GetBackendDeviceForTest(tun.ID); dev != nil {
						_ = dev.Close()
					}
				}
			})
			mgr := &rotationNaiveManager{mockZombiePeerProtocolManager: &mockZombiePeerProtocolManager{proto: models.ProtocolNaive}, failAdd: failAdd}
			r := New(db, nil)
			r.SetVPNService(vpnSvc)
			r.withdrawDisabledOwnerConns(ctx, server, models.ProtocolNaive, mgr, []models.UserConnection{*conn})
			mgr.mu.Lock()
			removed := append([]string{}, mgr.deleted...)
			mgr.mu.Unlock()
			want := oldID
			if !failAdd {
				want = fmt.Sprintf("vpn-backend-%d", sid)
				if len(mgr.added) != 1 || len(removed) != 1 || removed[0] != oldID {
					t.Fatalf("missing provisioning or remote revocation: added=%v removed=%v", mgr.added, removed)
				}
			} else if len(mgr.added) != 0 || len(removed) != 0 {
				t.Fatalf("remote state changed on failed provision: added=%v removed=%v", mgr.added, removed)
			}
			row, err := db.GetBackendTunnelByServerID(ctx, sid)
			if err != nil || row == nil {
				t.Fatalf("backend row: %+v %v", row, err)
			}
			live, err := vpnSvc.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			if !row.Enabled || row.Status != models.TunnelStatusActive ||
				vpn.ExtractClientIDFromProtocolParams(row.Protocol, row.ProtocolParams) != want ||
				vpn.ExtractClientIDFromProtocolParams(live.Protocol, live.ProtocolParams) != want {
				t.Fatalf("backend identity mismatch: row=%+v live=%+v want=%s", row, live, want)
			}
			remaining, err := db.GetConnection(ctx, conn.ID)
			if err != nil || (remaining != nil) != failAdd {
				t.Fatalf("disabled user's connection: %+v %v", remaining, err)
			}
		})
	}
}
