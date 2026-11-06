package vpn

import (
	"context"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
)

func TestDualTierHistoryDelayedScheduledSuccessCannotRestoreAdmission(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)
	svc, sid, other, _, _ := setupTestVPNService(t, db)
	t.Cleanup(func() { _ = svc.Stop() })
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatal(err)
	}
	source, _ := svc.pool.GetTunnel(sid)
	dev := &historyCanaryDevice{}
	dev.fail.Store(true)
	svc.SetCanaryProbeFunc(nil)
	svc.SetBackendDeviceForTest(source.ID, dev)
	peer := seedIngressPeer(t, db, "callback-history", "callback-history-peer", "10.100.3.93")
	sess, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := svc.pool.GetTunnel(sid)
	if _, err := svc.prober.ProbeTunnel(ctx, cur); err != nil {
		t.Fatal(err)
	}
	dev.fail.Store(false)
	orch := orchestrator.New(db, nil, orchestrator.WithProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return time.Millisecond, nil
	}))
	orch.SetTunnelStatusUpdater(svc)
	entered, release := make(chan struct{}), make(chan struct{})
	svc.SetCanarySuccessCallback(func(id int64) {
		close(entered)
		<-release
		orch.ResetCanaryFailCount(id)
	})
	t.Cleanup(func() { svc.SetCanarySuccessCallback(nil) })
	done := make(chan error, 1)
	go func() { done <- orch.CheckBackendTunnelHealth(ctx) }()
	<-entered
	dev.fail.Store(true)
	cur, _ = svc.pool.GetTunnel(sid)
	_, probeErr := svc.prober.ProbeTunnel(ctx, cur)
	close(release)
	schedulerErr := <-done
	if probeErr != nil || schedulerErr != nil {
		t.Fatalf("probe=%v scheduler=%v", probeErr, schedulerErr)
	}
	cur, _ = svc.pool.GetTunnel(sid)
	stored, err := db.GetBackendTunnel(ctx, source.ID)
	if err != nil || stored == nil || cur.Status != models.TunnelStatusHandshakeBlocked || stored.Status != cur.Status {
		t.Fatalf("delayed success restored admission: pool_status=%s stored_present=%t err=%v", cur.Status, stored != nil, err)
	}
	if got := orch.GetCanaryFailCount(source.ID); got != 1 {
		t.Fatalf("delayed success erased current loss: %d", got)
	}
	again, backend, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	if err != nil || again.ID != sess.ID || backend.ID != source.ID || !svc.forwarder.HasSessionRoute(peer.peerKey, sess.ID, peer.connID, peer.ip.String(), source.ID) {
		t.Fatalf("current loss evicted established session: session_present=%t backend_present=%t err=%v", again != nil, backend != nil, err)
	}
}
