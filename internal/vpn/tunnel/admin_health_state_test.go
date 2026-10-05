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

func TestSyncFromDBPreservesIndependentAdministrativeAndHealthState(t *testing.T) {
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
	if err := pool.SetTunnelStatus(ctx, enabledServer, models.TunnelStatusDegraded, 250); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, disabledServer, models.TunnelStatusActive, 20); err != nil {
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
	if !enabled.Enabled || enabled.Status != models.TunnelStatusDegraded || enabled.LatencyMS != 250 {
		t.Fatalf("enabled backend dimensions were not restored independently: %+v", enabled)
	}

	disabled, err := restarted.GetTunnel(disabledServer)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("administratively disabled backend was enabled on restart")
	}
	if disabled.Status != models.TunnelStatusActive || disabled.LatencyMS != 20 {
		t.Fatalf("admin state overwrote persisted runtime health on restart: %+v", disabled)
	}
	if disabled.DisableReason != models.DisableReasonAdmin {
		t.Fatalf("admin provenance not restored: %+v", disabled)
	}
}

func TestResetEnabledHealthForStartupRequiresFreshProbe(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	enabledServer, _ := db.CreateServer(ctx, &models.Server{Name: "startup-enabled", Host: "192.0.2.94"})
	disabledServer, _ := db.CreateServer(ctx, &models.Server{Name: "startup-disabled", Host: "192.0.2.95"})

	if _, err := pool.AddTunnel(ctx, enabledServer, "192.0.2.94:51820", "key-startup-enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.AddTunnel(ctx, disabledServer, "192.0.2.95:51820", "key-startup-disabled"); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, enabledServer, models.TunnelStatusDegraded, 333); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, disabledServer, models.TunnelStatusActive, 27); err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelEnabled(ctx, disabledServer, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}

	restarted := NewPool(db)
	if err := restarted.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	beforeDisabled, err := restarted.GetTunnel(disabledServer)
	if err != nil {
		t.Fatal(err)
	}

	if err := restarted.ResetEnabledHealthForStartup(ctx); err != nil {
		t.Fatal(err)
	}

	enabled, err := restarted.GetTunnel(enabledServer)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Enabled || enabled.Status != models.TunnelStatusConnecting {
		t.Fatalf("enabled backend did not enter unknown startup health: %+v", enabled)
	}
	if enabled.DisableReason != models.DisableReasonNone || enabled.LatencyMS != 0 || enabled.LastHealthCheck != nil {
		t.Fatalf("enabled backend retained stale health metadata: %+v", enabled)
	}

	disabled, err := restarted.GetTunnel(disabledServer)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatal("administratively disabled backend was enabled by startup reset")
	}
	if disabled.Status != beforeDisabled.Status ||
		disabled.DisableReason != beforeDisabled.DisableReason ||
		disabled.LatencyMS != beforeDisabled.LatencyMS {
		t.Fatalf("startup reset changed disabled backend health: before=%+v after=%+v", beforeDisabled, disabled)
	}

	dbEnabled, err := db.GetBackendTunnel(ctx, enabled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbEnabled.Status != models.TunnelStatusConnecting ||
		dbEnabled.DisableReason != models.DisableReasonNone ||
		dbEnabled.LatencyMS != 0 ||
		dbEnabled.LastHealthCheck != nil {
		t.Fatalf("database retained stale startup health: %+v", dbEnabled)
	}
	dbDisabled, err := db.GetBackendTunnel(ctx, disabled.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbDisabled.Enabled ||
		dbDisabled.Status != beforeDisabled.Status ||
		dbDisabled.DisableReason != beforeDisabled.DisableReason ||
		dbDisabled.LatencyMS != beforeDisabled.LatencyMS {
		t.Fatalf("database startup reset changed admin-disabled backend: %+v", dbDisabled)
	}
}

func TestTransferConnectionsRejectsAdminDisabledActiveTarget(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	fromServer, _ := db.CreateServer(ctx, &models.Server{Name: "transfer-from", Host: "192.0.2.96"})
	toServer, _ := db.CreateServer(ctx, &models.Server{Name: "transfer-to", Host: "192.0.2.97"})
	from, err := pool.AddTunnel(ctx, fromServer, "192.0.2.96:51820", "key-from")
	if err != nil {
		t.Fatal(err)
	}
	to, err := pool.AddTunnel(ctx, toServer, "192.0.2.97:51820", "key-to")
	if err != nil {
		t.Fatal(err)
	}

	pool.IncrementConnections(from.ID)
	if err := pool.SetTunnelEnabled(ctx, toServer, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}

	if err := pool.TransferConnectionsIfActive(from.ID, to.ID); err == nil {
		t.Fatal("expected transfer to reject administratively disabled target with active health")
	}

	fromAfter, err := pool.GetTunnel(fromServer)
	if err != nil {
		t.Fatal(err)
	}
	toAfter, err := pool.GetTunnel(toServer)
	if err != nil {
		t.Fatal(err)
	}
	if fromAfter.ActiveConnections != 1 || toAfter.ActiveConnections != 0 {
		t.Fatalf("rejected transfer changed gauges: from=%d to=%d", fromAfter.ActiveConnections, toAfter.ActiveConnections)
	}
}

func TestAdminGenerationSeparatedFromHealthUpdates(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	pool := NewPool(db)

	serverID, err := db.CreateServer(ctx, &models.Server{Name: "gen-test", Host: "192.0.2.98"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, serverID, "192.0.2.98:51820", "server-key-initial")
	if err != nil {
		t.Fatal(err)
	}

	initialGen := pool.AdminGeneration(serverID)
	if initialGen <= 0 {
		t.Fatalf("expected positive initial admin generation, got %d", initialGen)
	}

	// 1. Health updates must advance StateVersion but NOT AdminGeneration.
	if err := pool.SetTunnelStatus(ctx, serverID, models.TunnelStatusDegraded, 150); err != nil {
		t.Fatal(err)
	}
	if gen := pool.AdminGeneration(serverID); gen != initialGen {
		t.Fatalf("SetTunnelStatus changed admin generation: expected %d, got %d", initialGen, gen)
	}

	if err := pool.SetTunnelStatusWithReason(ctx, serverID, models.TunnelStatusDisabled, models.DisableReasonHealth, 0); err != nil {
		t.Fatal(err)
	}
	if gen := pool.AdminGeneration(serverID); gen != initialGen {
		t.Fatalf("SetTunnelStatusWithReason changed admin generation: expected %d, got %d", initialGen, gen)
	}

	tunAfterHealth, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if tunAfterHealth.StateVersion <= tun.StateVersion {
		t.Fatalf("expected StateVersion to advance on health updates (before=%d, after=%d)", tun.StateVersion, tunAfterHealth.StateVersion)
	}

	// 2. SetTunnelEnabled must advance AdminGeneration.
	if err := pool.SetTunnelEnabled(ctx, serverID, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	genAfterDisable := pool.AdminGeneration(serverID)
	if genAfterDisable != initialGen+1 {
		t.Fatalf("SetTunnelEnabled(false) did not advance admin generation by 1: expected %d, got %d", initialGen+1, genAfterDisable)
	}

	if err := pool.SetTunnelEnabled(ctx, serverID, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	genAfterEnable := pool.AdminGeneration(serverID)
	if genAfterEnable != genAfterDisable+1 {
		t.Fatalf("SetTunnelEnabled(true) did not advance admin generation: expected %d, got %d", genAfterDisable+1, genAfterEnable)
	}

	// Redundant administrative assertion must still advance AdminGeneration to fence in-flight work.
	if err := pool.SetTunnelEnabled(ctx, serverID, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	genAfterRedundant := pool.AdminGeneration(serverID)
	if genAfterRedundant != genAfterEnable+1 {
		t.Fatalf("redundant SetTunnelEnabled did not advance admin generation: expected %d, got %d", genAfterEnable+1, genAfterRedundant)
	}

	// 3. SetTunnelEndpoint must advance AdminGeneration.
	if err := pool.SetTunnelEndpoint(ctx, tun.ID, "192.0.2.98:51821"); err != nil {
		t.Fatal(err)
	}
	genAfterEndpoint := pool.AdminGeneration(serverID)
	if genAfterEndpoint != genAfterRedundant+1 {
		t.Fatalf("SetTunnelEndpoint did not advance admin generation: expected %d, got %d", genAfterRedundant+1, genAfterEndpoint)
	}

	// 4. AddTunnel with changed credentials must advance AdminGeneration.
	if _, err := pool.AddTunnel(ctx, serverID, "192.0.2.98:51821", "server-key-rotated"); err != nil {
		t.Fatal(err)
	}
	genAfterKeyRotate := pool.AdminGeneration(serverID)
	if genAfterKeyRotate != genAfterEndpoint+1 {
		t.Fatalf("AddTunnel with changed key did not advance admin generation: expected %d, got %d", genAfterEndpoint+1, genAfterKeyRotate)
	}
}
