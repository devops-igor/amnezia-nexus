package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
)

type auditR14CanaryDevice struct {
	testCanaryDevice
	fail bool
}

func (d *auditR14CanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	if d.fail {
		return errors.New("fixture payload failure")
	}
	return nil
}

// Cross-component state/admission counterexample. No service Start, encrypted
// engine, WAN, browser or E2E. Only outer result and optional device are injected.
func TestAuditR14ScheduledBootstrapRequiresInnerProof(t *testing.T) {
	for _, scenario := range []string{"missing_device", "attached_failed", "attached_good"} {
		t.Run(scenario, func(t *testing.T) {
			db := setupTestDB(t)
			svc, sid, other, _, _ := setupTestVPNService(t, db)
			ctx := t.Context()
			svc.SetCanaryProbeFunc(nil)
			if err := svc.pool.SyncFromDB(ctx); err != nil {
				t.Fatal(err)
			}
			if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
				t.Fatal(err)
			}
			if err := svc.pool.SetTunnelStatus(ctx, sid, models.TunnelStatusConnecting, 0); err != nil {
				t.Fatal(err)
			}
			tun, err := svc.pool.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			dev := &auditR14CanaryDevice{fail: scenario == "attached_failed"}
			if scenario != "missing_device" {
				svc.SetBackendDeviceForTest(tun.ID, dev)
			}
			if _, ok := svc.GetDevice(tun.ID); scenario == "missing_device" && ok {
				t.Fatal("fixture unexpectedly has a device")
			}
			available := svc.HasCanaryProber(tun)
			orch := orchestrator.New(db, nil, orchestrator.WithTunnelStatusUpdater(svc), orchestrator.WithProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
				return 20 * time.Millisecond, nil
			}))
			if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
				t.Fatal(err)
			}
			current, err := svc.pool.GetTunnel(sid)
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := db.GetBackendTunnel(ctx, tun.ID)
			if err != nil {
				t.Fatal(err)
			}
			peer := seedIngressPeer(t, db, "audit-r14", "audit-r14-peer", "10.100.3.94")
			session, backend, _, admitErr := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
			connected, route := false, false
			if session != nil && backend != nil {
				connected = session.Status == "connected"
				route = svc.forwarder.HasSessionRoute(peer.peerKey, session.ID, peer.connID, peer.ip.String(), backend.ID)
			}
			_, hasDeviceAfter := svc.GetDevice(tun.ID)
			t.Logf("scenario=%s available=%t canary_calls=%d pool=%s db=%s candidates=%d connected=%t route=%t device_after=%t admission_err=%v", scenario, available, dev.canaryCalls, current.Status, persisted.Status, len(svc.pool.GetActiveTunnels()), connected, route, hasDeviceAfter, admitErr)
			if scenario == "attached_good" {
				if dev.canaryCalls != 1 || !connected || !route || current.Status != models.TunnelStatusActive {
					t.Error("both-good control did not reach active admission")
				}
			} else if current.Status == models.TunnelStatusActive || persisted.Status == models.TunnelStatusActive || connected || route {
				t.Error("scheduled health published active and admitted a fresh peer without successful inner proof")
			}
		})
	}
}
