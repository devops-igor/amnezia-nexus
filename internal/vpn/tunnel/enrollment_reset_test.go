package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/database"
	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDeployEnrollmentResetDurable(t *testing.T) {
	for _, proto := range []string{models.ProtocolAWG, models.ProtocolVLESS, models.ProtocolNaive} {
		t.Run(proto, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "enrollment.db")
			const secret = "test-secret-key-1234567890123456"
			db, err := database.Open(path, secret)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			pool := NewPool(db)
			pool.SetMultiProtocolEnabled(true)
			sid, err := db.CreateServer(ctx, &models.Server{Name: "enrollment", Host: "192.0.2.70"})
			if err != nil {
				t.Fatal(err)
			}
			opts := BackendTunnelOptions{Protocol: proto}
			if proto != models.ProtocolAWG {
				opts.ProtocolParams = json.RawMessage(`{}`)
			}
			old, err := pool.AddTunnelWithConfig(ctx, sid, "192.0.2.70:443", "", opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := pool.SetTunnelStatus(ctx, sid, models.TunnelStatusActive, 19); err != nil {
				t.Fatal(err)
			}
			if err := pool.SetTunnelEnabled(ctx, sid, false, models.DisableReasonAdmin); err != nil {
				t.Fatal(err)
			}
			before, err := pool.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			enrollCtx := context.WithValue(ctx, DeployEnrollmentKey, true)
			reset, err := pool.AddTunnelWithConfig(enrollCtx, sid, old.Endpoint, "", opts)
			if err != nil {
				t.Fatal(err)
			}
			assertEnrollmentReset(t, reset, false, before.StateVersion+1)
			persisted, err := db.GetBackendTunnelByID(ctx, old.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertEnrollmentReset(t, persisted, false, reset.StateVersion)
			if !models.SameTunnelIdentity(old, reset) {
				t.Fatal("same-identity enrollment rotated credentials")
			}

			// Reopen the actual SQLite database, not just another pool over its handle.
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = database.Open(path, secret)
			if err != nil {
				t.Fatal(err)
			}
			restarted := NewPool(db)
			restarted.SetMultiProtocolEnabled(true)
			if err := restarted.SyncFromDB(ctx); err != nil {
				t.Fatal(err)
			}
			if err := restarted.SetTunnelEnabled(ctx, sid, true, models.DisableReasonNone); err != nil {
				t.Fatal(err)
			}
			current, err := restarted.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			assertEnrollmentReset(t, current, true, reset.StateVersion+1)
			if len(restarted.GetActiveTunnels()) != 0 {
				t.Fatal("unqualified restart became eligible")
			}
			if err := restarted.SetTunnelStatusIfCurrentWithVersion(ctx, sid, old.ID, before.StateVersion, models.TunnelStatusActive, 1); !errors.Is(err, ErrStaleStateVersion) {
				t.Fatalf("stale probe accepted: %v", err)
			}
			if err := restarted.SetTunnelStatusIfCurrentWithVersion(ctx, sid, old.ID, current.StateVersion, models.TunnelStatusActive, 2); err != nil {
				t.Fatal(err)
			}
			if len(restarted.GetActiveTunnels()) != 1 {
				t.Fatal("fresh qualification did not restore eligibility")
			}
		})
	}
}

func assertEnrollmentReset(t *testing.T, got *models.BackendTunnel, enabled bool, version int64) {
	t.Helper()
	if got == nil {
		t.Fatal("missing tunnel")
	}
	if got.Status != models.TunnelStatusConnecting || got.Enabled != enabled || got.StateVersion != version || got.LatencyMS != 0 || got.LastHealthCheck != nil || got.DisableReason != models.DisableReasonNone {
		t.Fatalf("enrollment retained stale health or intent: status=%s enabled=%v version=%d latency=%d checked=%v reason=%s", got.Status, got.Enabled, got.StateVersion, got.LatencyMS, got.LastHealthCheck, got.DisableReason)
	}
}
