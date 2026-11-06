package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
)

func TestDeployEnrollmentRejectsInflightProbe(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	pool := NewPool(db)
	sid, err := db.CreateServer(ctx, &models.Server{Name: "inflight", Host: "192.0.2.75"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := pool.AddTunnel(ctx, sid, "192.0.2.75:443", "server-key")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	prober := NewHealthProber(pool, db, DefaultHealthConfig(), func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		close(entered)
		<-release
		return time.Millisecond, nil
	})
	result := make(chan error, 1)
	go func() { _, err := prober.ProbeTunnel(ctx, old); result <- err }()
	<-entered
	if err := pool.SetTunnelEnabled(ctx, sid, false, models.DisableReasonAdmin); err != nil {
		t.Fatal(err)
	}
	disabled, err := pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	reset, err := pool.AddTunnel(context.WithValue(ctx, DeployEnrollmentKey, true), sid, old.Endpoint, old.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	assertEnrollmentReset(t, reset, false, disabled.StateVersion+1)
	if err := pool.SetTunnelEnabled(ctx, sid, true, models.DisableReasonNone); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrStaleStateVersion) {
		t.Fatalf("inflight probe not fenced: %v", err)
	}
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatal("inflight health made reenrollment eligible")
	}
	persisted, err := db.GetBackendTunnelByID(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertEnrollmentReset(t, persisted, true, reset.StateVersion+1)
}

func TestDeployEnrollmentPersistenceFailurePreservesPool(t *testing.T) {
	for _, failure := range []string{"canceled", "missing", "concurrent-version"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			db := setupTestDB(t)
			pool := NewPool(db)
			sid, err := db.CreateServer(ctx, &models.Server{Name: "failure", Host: "192.0.2.76"})
			if err != nil {
				t.Fatal(err)
			}
			old, err := pool.AddTunnel(ctx, sid, "192.0.2.76:443", "server-key")
			if err != nil {
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
			switch failure {
			case "canceled":
				var cancel context.CancelFunc
				enrollCtx, cancel = context.WithCancel(enrollCtx)
				cancel()
			case "missing":
				if err := db.DeleteBackendTunnel(ctx, old.ID); err != nil {
					t.Fatal(err)
				}
			case "concurrent-version":
				if err := db.UpdateBackendTunnelEnabled(ctx, old.ID, false, models.DisableReasonAdmin); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.AddTunnel(enrollCtx, sid, "192.0.2.77:443", old.PublicKey); err == nil {
				t.Fatal("failed enrollment reported success")
			}
			after, err := pool.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			if !models.SameTunnelIdentity(before, after) || after.Enabled || after.Status != before.Status || after.StateVersion != before.StateVersion || after.DisableReason != before.DisableReason {
				t.Fatal("failed enrollment changed pool")
			}
			if len(pool.GetActiveTunnels()) != 0 {
				t.Fatal("failed enrollment exposed eligible tunnel")
			}
		})
	}
}

func TestReconnectDoesNotOverwriteNewEnrollment(t *testing.T) {
	ctx := context.Background()
	pool := NewPool(nil)
	old, err := pool.AddTunnel(ctx, 1, "192.0.2.78:443", "server-key")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SetTunnelStatus(ctx, 1, models.TunnelStatusDegraded, 500); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	prober := NewHealthProber(pool, nil, DefaultHealthConfig(), func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		close(entered)
		<-release
		return time.Millisecond, nil
	})
	rm := NewReconnectManager(pool, prober, DefaultReconnectConfig())
	done := make(chan int, 1)
	go func() { done <- rm.CheckAndReconnect(ctx) }()
	<-entered
	// Stop reconnect's bookkeeping after ProbeTunnel's fenced commit. Enrollment
	// can occur in this exact gap; the old duplicate status write was unfenced.
	rm.mu.Lock()
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for {
		current, err := pool.GetTunnel(1)
		if err != nil {
			rm.mu.Unlock()
			t.Fatal(err)
		}
		if current.Status == models.TunnelStatusActive {
			break
		}
		if time.Now().After(deadline) {
			rm.mu.Unlock()
			t.Fatal("probe did not commit")
		}
		time.Sleep(time.Millisecond)
	}
	reset, err := pool.AddTunnel(context.WithValue(ctx, DeployEnrollmentKey, true), 1, old.Endpoint, old.PublicKey)
	rm.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("reconnect did not finish")
	}
	current, err := pool.GetTunnel(1)
	if err != nil {
		t.Fatal(err)
	}
	assertEnrollmentReset(t, current, true, reset.StateVersion)
	if len(pool.GetActiveTunnels()) != 0 {
		t.Fatal("reconnect resurrected enrollment")
	}
}
