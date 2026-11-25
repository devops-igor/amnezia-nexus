package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

func TestAbsentBackendRefusesNativeReadinessWithoutMutation(t *testing.T) {
	db := setupTestDB(t)
	svc, err := NewVPNService(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()
	ctx := context.Background()
	id, err := db.CreateServer(ctx, &models.Server{Name: "native-readiness", Host: "127.0.0.1", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(models.NaiveProxyParams{Username: "user", Password: "pass", Domain: "example.com", EnableH3: true, H3Supported: true})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.AddTunnelWithConfig(ctx, id, "127.0.0.1:443", "", tunnel.BackendTunnelOptions{Protocol: models.ProtocolNaive, ProtocolParams: params})
	if err != nil {
		t.Fatal(err)
	}
	before, err := db.GetBackendTunnelByServerID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetServerProviderAbsence(ctx, id, time.Now().UTC(), ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnableBackendWithConfig(ctx, id); !errors.Is(err, tunnel.ErrProviderAbsent) {
		t.Errorf("enable = %v", err)
	}
	if err := svc.finishEnableBackend(ctx, svc.pool, tun, nil, id, 0); !errors.Is(err, tunnel.ErrProviderAbsent) {
		t.Errorf("readiness = %v", err)
	}
	after, err := db.GetBackendTunnelByServerID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Error("refusal changed tunnel ownership or health")
	}
	if err := db.SetServerProviderAbsence(ctx, id, time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.refuseAbsentReadiness(ctx, id); err != nil {
		t.Errorf("listed readiness control = %v", err)
	}
}
