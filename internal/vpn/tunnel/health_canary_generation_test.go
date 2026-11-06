package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestCanarySuccessDoesNotResetNewerHealthHistory(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "generation-test", Host: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.AddTunnel(ctx, serverID, "192.0.2.1:51820", "test-public-key")
	if err != nil {
		t.Fatal(err)
	}
	stale, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	hp := NewHealthProber(pool, db, DefaultHealthConfig(), nil)
	hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		if err := pool.SetTunnelStatus(ctx, serverID, models.TunnelStatusHandshakeBlocked, 0); err != nil {
			t.Fatal(err)
		}
		hp.recordCanaryFailure(serverID)
		return nil
	})
	called := false
	hp.SetCanarySuccessCallback(func(int64) { called = true })
	t.Cleanup(func() { hp.SetCanarySuccessCallback(nil) })
	_ = hp.ProbeCanary(ctx, stale)
	if got := hp.GetCanaryFailCount(serverID); got != 1 {
		t.Errorf("stale success reset current failure history: got %d", got)
	}
	if called {
		t.Error("stale success notified scheduler")
	}
}

func TestOuterThresholdDoesNotBypassInnerConfirmation(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	serverID, err := db.CreateServer(ctx, &models.Server{Name: "outer-history-test", Host: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := pool.AddTunnel(ctx, serverID, "192.0.2.2:51820", "test-public-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, serverID, models.TunnelStatusActive, 1); err != nil {
		t.Fatal(err)
	}
	pool.IncrementConnections(serverID)
	hp := NewHealthProber(pool, db, DefaultHealthConfig(), func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("outer failure")
	})
	innerFails := false
	hp.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		if innerFails {
			return errors.New("inner failure")
		}
		return nil
	})
	_, _ = hp.ProbeTunnel(ctx, tun)
	_, _ = hp.ProbeTunnel(ctx, tun)
	innerFails = true
	_, _ = hp.ProbeTunnel(ctx, tun)
	current, err := pool.GetTunnel(serverID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("first inner failure after success: status %s, want handshake_blocked", current.Status)
	}
}
