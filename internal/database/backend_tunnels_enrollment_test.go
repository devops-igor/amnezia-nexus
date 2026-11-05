package database

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestResetBackendTunnelForEnrollment(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "enrollment.db"), "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sid, err := db.CreateServer(ctx, &models.Server{Name: "enrollment", Host: "192.0.2.71"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{ServerID: sid, InterfaceName: "awg-enroll", Enabled: false, Status: models.TunnelStatusActive, StateVersion: 7, Endpoint: "192.0.2.71:443", DisableReason: models.DisableReasonAdmin, LatencyMS: 42})
	if err != nil {
		t.Fatal(err)
	}
	updates := map[string]any{"endpoint": "192.0.2.72:443", "private_key": "enrollment-private", "probe_private_key": "enrollment-probe"}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := db.ResetBackendTunnelForEnrollment(canceled, id, 7, updates); err == nil {
		t.Fatal("canceled reset succeeded")
	}
	for _, col := range []string{"status", "enabled", "state_version", "endpoint = NULL --"} {
		if _, err := db.ResetBackendTunnelForEnrollment(ctx, id, 7, map[string]any{col: 1}); err == nil {
			t.Fatalf("accepted forbidden column %s", col)
		}
	}
	if ok, err := db.ResetBackendTunnelForEnrollment(ctx, id, 6, updates); err != nil || ok {
		t.Fatalf("stale reset: %v %v", ok, err)
	}
	before, err := db.GetBackendTunnelByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if before.Endpoint != "192.0.2.71:443" || before.StateVersion != 7 || before.Status != models.TunnelStatusActive {
		t.Fatal("failed reset partially mutated row")
	}
	if ok, err := db.ResetBackendTunnelForEnrollment(ctx, id, 7, updates); err != nil || !ok {
		t.Fatalf("reset: %v %v", ok, err)
	}
	after, err := db.GetBackendTunnelByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Enabled || after.Status != models.TunnelStatusConnecting || after.StateVersion != 8 || after.LatencyMS != 0 || after.LastHealthCheck != nil || after.DisableReason != models.DisableReasonNone || after.Endpoint != "192.0.2.72:443" || after.PrivateKey != "enrollment-private" || after.ProbePrivateKey != "enrollment-probe" {
		t.Fatal("reset did not atomically refresh identity and health")
	}
	var encrypted string
	if err := db.sqlDB.QueryRowContext(ctx, "SELECT private_key FROM backend_tunnels WHERE id = ?", id).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if encrypted == after.PrivateKey {
		t.Fatal("reset stored plaintext private key")
	}
	if err := db.UpdateBackendTunnelEnabled(ctx, id, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.CompareAndSwapTunnelStatus(ctx, id, models.TunnelStatusActive, models.DisableReasonAdmin, 7, models.TunnelStatusActive, models.DisableReasonNone, 1); err != nil || ok {
		t.Fatalf("stale health resurrected reset: %v %v", ok, err)
	}
	if err := db.DeleteBackendTunnel(ctx, id); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.ResetBackendTunnelForEnrollment(ctx, id, 9, updates); err != nil || ok {
		t.Fatalf("missing reset: %v %v", ok, err)
	}
}

func TestResetBackendTunnelEnrollmentConcurrentHealth(t *testing.T) {
	ctx := context.Background()
	db, err := Open(filepath.Join(t.TempDir(), "concurrent.db"), "test-secret-key-1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sid, err := db.CreateServer(ctx, &models.Server{Name: "concurrent", Host: "192.0.2.73"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.CreateBackendTunnel(ctx, &models.BackendTunnel{ServerID: sid, InterfaceName: "awg-enroll-race", Enabled: true, Status: models.TunnelStatusActive, StateVersion: 1, Endpoint: "192.0.2.73:443"})
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		before, err := db.GetBackendTunnelByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		type result struct {
			ok  bool
			err error
		}
		health := make(chan result, 1)
		go func() {
			<-start
			ok, err := db.CompareAndSwapTunnelStatus(ctx, id, before.Status, before.DisableReason, before.StateVersion, models.TunnelStatusActive, models.DisableReasonNone, 9)
			health <- result{ok, err}
		}()
		close(start)
		reset, err := db.ResetBackendTunnelForEnrollment(ctx, id, before.StateVersion, map[string]any{"endpoint": "192.0.2.74:443"})
		probe := <-health
		if err != nil || probe.err != nil {
			t.Fatalf("concurrent writes failed: reset=%v health=%v", err, probe.err)
		}
		if reset == probe.ok {
			t.Fatalf("exactly one versioned writer must succeed: reset=%v health=%v", reset, probe.ok)
		}
		after, err := db.GetBackendTunnelByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if after.StateVersion != before.StateVersion+1 {
			t.Fatal("concurrent writer rewound or duplicated state version")
		}
		if reset && (after.Status != models.TunnelStatusConnecting || after.LatencyMS != 0 || after.LastHealthCheck != nil) {
			t.Fatal("health writer overwrote enrollment reset")
		}
	}
}
