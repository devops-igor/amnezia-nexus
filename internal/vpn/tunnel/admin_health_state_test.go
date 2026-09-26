package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestBackendAdministrativeStateIndependentFromHealth(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "state-split", Host: "192.0.2.90"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, serverID, "192.0.2.90:51820", "server-key")
	if err != nil {
		t.Fatal(err)
	}
	if !tun.Enabled {
		t.Fatal("new backend must be administratively enabled")
	}

	if err := pool.SetTunnelStatus(ctx, serverID, models.TunnelStatusDegraded, 321); err != nil {
		t.Fatal(err)
	}
	beforeDisable, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}

	if err := pool.SetTunnelEnabled(ctx, serverID, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	disabled, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("administrative disable did not persist enabled=false")
	}
	if disabled.Status != beforeDisable.Status || disabled.LatencyMS != beforeDisable.LatencyMS {
		t.Fatalf("administrative disable changed runtime health: before=%+v after=%+v", beforeDisable, disabled)
	}

	// Health writers are fenced while the backend is administratively disabled.
	if err := pool.SetTunnelStatus(ctx, serverID, models.TunnelStatusActive, 10); err != nil {
		t.Fatal(err)
	}
	stillDisabled, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if stillDisabled.Enabled || stillDisabled.Status != models.TunnelStatusDegraded {
		t.Fatalf("health write resurrected administratively disabled backend: %+v", stillDisabled)
	}
}

func TestProbeFailureDoesNotChangeAdministrativeEnabledState(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "probe-failure", Host: "192.0.2.91"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, serverID, "192.0.2.91:51820", "server-key")
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultHealthConfig()
	cfg.FailureThreshold = 1
	prober := NewHealthProber(pool, db, cfg, func(
		context.Context, string, string, string, string, string, any, any, int, int, time.Duration,
	) (time.Duration, error) {
		return 0, errors.New("injected probe failure")
	})

	if _, err := prober.ProbeTunnel(ctx, tun); err == nil {
		t.Fatal("expected probe failure")
	}
	got, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled {
		t.Fatal("probe failure changed administrative enabled state")
	}
	if got.Status != models.TunnelStatusDisabled || got.DisableReason != models.DisableReasonHealth {
		t.Fatalf("expected health-disabled runtime state, got status=%q reason=%q", got.Status, got.DisableReason)
	}
}

func TestSyncFromDBResetsEnabledBackendHealthToConnecting(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	enabledServer, _ := db.CreateServer(ctx, &models.Server{Name: "enabled", Host: "192.0.2.92"})
	disabledServer, _ := db.CreateServer(ctx, &models.Server{Name: "disabled", Host: "192.0.2.93"})

	if _, err := pool.AddTunnel(ctx, enabledServer, "192.0.2.92:51820", "key-enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.AddTunnel(ctx, disabledServer, "192.0.2.93:51820", "key-disabled"); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, enabledServer, models.TunnelStatusActive, 15); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, disabledServer, models.TunnelStatusDegraded, 400); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelEnabled(ctx, disabledServer, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}

	restarted := NewPool(db)
	if err := restarted.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}

	enabled, err := restarted.GetTunnel(enabledServer)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Enabled || enabled.Status != models.TunnelStatusConnecting || enabled.LatencyMS != 0 || enabled.LastHealthCheck != nil {
		t.Fatalf("enabled backend did not restart unverified: %+v", enabled)
	}

	disabled, err := restarted.GetTunnel(disabledServer)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("administratively disabled backend was enabled on restart")
	}
	if disabled.Status != models.TunnelStatusDegraded || disabled.LatencyMS != 400 {
		t.Fatalf("disabled backend runtime health was overwritten on restart: %+v", disabled)
	}
}
