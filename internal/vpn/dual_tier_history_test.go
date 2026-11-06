package vpn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

type historyCanaryDevice struct {
	testCanaryDevice
	fail atomic.Bool
}

func (d *historyCanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	if d.fail.Load() {
		return errors.New("injected inner loss")
	}
	return nil
}

// Both workers must preserve actual authenticated session/DB/forwarder state
// when outer failures accumulated across successful inner observations. Only
// the third subsequent inner loss permits real failover.
func TestDualTierHistoryOuterThreshold(t *testing.T) {
	for _, worker := range []string{"ordinary", "scheduled", "alternating"} {
		t.Run(worker, func(t *testing.T) {
			ctx := t.Context()
			db := setupTestDB(t)
			svc, sid, other, _, _ := setupTestVPNService(t, db)
			t.Cleanup(func() { _ = svc.Stop() })
			svc.SetCanaryProbeFunc(nil)
			if err := svc.pool.SyncFromDB(ctx); err != nil {
				t.Fatal(err)
			}
			if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
				t.Fatal(err)
			}
			source, _ := svc.pool.GetTunnel(sid)
			target, _ := svc.pool.GetTunnel(other)
			dev := &historyCanaryDevice{}
			svc.SetBackendDeviceForTest(source.ID, dev)
			svc.SetBackendDeviceForTest(target.ID, &testCanaryDevice{})
			peer := seedIngressPeer(t, db, "history-"+worker, "history-peer-"+worker, "10.100.3.94")
			sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusActive, 0); err != nil {
				t.Fatal(err)
			}
			outer := func(_ context.Context, endpoint, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
				if endpoint == source.Endpoint {
					return 0, errors.New("outer blocked")
				}
				return time.Millisecond, nil
			}
			svc.SetProbeFunc(outer)
			svc.SetCanaryProbeFunc(nil)
			orch := orchestrator.New(db, nil, orchestrator.WithProbeFunc(outer))
			orch.SetTunnelStatusUpdater(svc)
			orch.SetSessionMigrator(svc)
			t.Cleanup(func() { svc.SetCanarySuccessCallback(nil) })
			step := 0
			probe := func() {
				t.Helper()
				step++
				if worker == "scheduled" || (worker == "alternating" && step%2 == 0) {
					if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
						t.Fatal(err)
					}
				} else {
					cur, err := svc.pool.GetTunnel(sid)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := svc.prober.ProbeTunnel(ctx, cur); err == nil {
						t.Fatal("missing injected outer failure")
					}
				}
			}
			preserved := func() {
				t.Helper()
				cur, err := svc.pool.GetTunnel(sid)
				if err != nil {
					t.Fatal(err)
				}
				stored, err := db.GetBackendTunnel(ctx, source.ID)
				if err != nil || stored == nil || cur.Status != models.TunnelStatusHandshakeBlocked || stored.Status != cur.Status || stored.StateVersion != cur.StateVersion {
					t.Fatalf("blocked DB/pool state lost: pool_status=%s stored_present=%t err=%v", cur.Status, stored != nil, err)
				}
				again, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
				if err != nil || again.ID != sess.ID || backend.ID != source.ID {
					t.Fatalf("established session moved before inner threshold: session_present=%t backend_present=%t err=%v", again != nil, backend != nil, err)
				}
				row, err := db.GetVPNSessionByID(ctx, sess.ID)
				if err != nil || row == nil || row.BackendTunnelID != source.ID || !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
					t.Fatalf("durable session or source route lost: row=%+v err=%v", row, err)
				}
				for _, candidate := range svc.pool.GetActiveTunnels() {
					if candidate.ID == source.ID {
						t.Fatal("blocked source admitted new clients")
					}
				}
			}
			probe()
			probe()
			dev.fail.Store(true)
			for want := 1; want <= 2; want++ {
				probe()
				preserved()
				if got := orch.GetCanaryFailCount(source.ID); got != want {
					t.Fatalf("shared failure count=%d want=%d", got, want)
				}
			}
			probe()
			cur, _ := svc.pool.GetTunnel(sid)
			if cur.Status != models.TunnelStatusDisabled && cur.Status != models.TunnelStatusDegraded {
				t.Fatalf("sustained loss did not enable failover: %s", cur.Status)
			}
			again, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
			if err != nil || backend.ID != target.ID || again.BackendTunnelID != target.ID {
				t.Fatalf("sustained loss did not move session to target: session_present=%t backend_present=%t err=%v", again != nil, backend != nil, err)
			}
			if svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
				t.Fatal("sustained loss left old source route live")
			}
		})
	}
}

func TestDualTierHistoryDelayedNotificationCannotResetNewLoss(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, _, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sid)
	dev := &historyCanaryDevice{}
	svc.SetCanaryProbeFunc(nil)
	svc.SetBackendDeviceForTest(source.ID, dev)
	orch := orchestrator.New(db, nil)
	orch.SetTunnelStatusUpdater(svc)
	entered, release := make(chan struct{}), make(chan struct{})
	svc.SetCanarySuccessCallback(func(id int64) {
		close(entered)
		<-release
		orch.ResetCanaryFailCount(id)
	})
	t.Cleanup(func() { svc.SetCanarySuccessCallback(nil) })
	done := make(chan error, 1)
	go func() { done <- svc.ProbeCanary(ctx, source) }()
	<-entered
	dev.fail.Store(true)
	newErr := svc.ProbeCanary(ctx, source)
	close(release)
	oldErr := <-done
	if newErr == nil || !errors.Is(oldErr, tunnel.ErrStaleStateVersion) {
		t.Fatalf("unexpected probe results: newer=%v older=%v", newErr, oldErr)
	}
	if got := orch.GetCanaryFailCount(source.ID); got != 1 {
		t.Fatalf("delayed notification erased newer loss: %d", got)
	}
}
