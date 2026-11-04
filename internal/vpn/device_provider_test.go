package vpn

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
)

type testCanaryDevice struct {
	canaryCalls int
}

func (d *testCanaryDevice) Read([]byte) (int, error)     { return 0, io.EOF }
func (d *testCanaryDevice) Write(p []byte) (int, error)  { return len(p), nil }
func (d *testCanaryDevice) Close() error                 { return nil }
func (d *testCanaryDevice) IsClosed() bool               { return false }
func (d *testCanaryDevice) CreatedAt() time.Time         { return time.Now() }
func (d *testCanaryDevice) LastHandshakeTime() time.Time { return time.Now() }
func (d *testCanaryDevice) DroppedPackets() uint64       { return 0 }
func (d *testCanaryDevice) ProbeCanary(context.Context, time.Duration) error {
	d.canaryCalls++
	return nil
}

func TestVPNService_DeviceProvider_ProductionCanaryWiring(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	dev := &testCanaryDevice{}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}

	// Verify prober discovers the device via Service.GetDevice
	proberDev := svc.prober.GetDevice(tun.ID)
	if proberDev == nil {
		t.Fatal("expected prober.GetDevice to return the attached backend device via Service provider")
	}

	// Outer handshake probe always fails (simulating DPI handshake blocking)
	svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, errors.New("DPI handshake drop")
	})

	// Direct canary probe must succeed through the live device
	if err := svc.prober.ProbeCanary(ctx, tun); err != nil {
		t.Fatalf("expected ProbeCanary to succeed, got %v", err)
	}
	if dev.canaryCalls == 0 {
		t.Fatal("expected canary probe to reach attached device")
	}

	// Run outer probes up to FailureThreshold
	for i := 0; i < svc.prober.Config().FailureThreshold; i++ {
		_, _ = svc.prober.ProbeTunnel(ctx, tun)
	}

	got, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := db.GetBackendTunnel(ctx, tun.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected pool status %s, got %s", models.TunnelStatusHandshakeBlocked, got.Status)
	}
	if persisted.Status != models.TunnelStatusHandshakeBlocked {
		t.Errorf("expected DB status %s, got %s", models.TunnelStatusHandshakeBlocked, persisted.Status)
	}
}

func TestVPNService_DeviceProvider_GetDeviceByServerID(t *testing.T) {
	db := setupTestDB(t)
	svc, s1, _, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()

	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	dev := &testCanaryDevice{}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}

	// Look up by server ID should find the device via pool fallback
	foundDev, ok := svc.GetDevice(s1)
	if !ok || foundDev == nil {
		t.Fatalf("expected GetDevice(%d) by server ID to succeed, got ok=%v dev=%v", s1, ok, foundDev)
	}

	// Non-existent server/tunnel ID
	missingDev, ok := svc.GetDevice(999999)
	if ok || missingDev != nil {
		t.Fatalf("expected missing device for unknown ID, got ok=%v dev=%v", ok, missingDev)
	}
}

func TestVPNService_DeviceProvider_SubnetCIDRWiring(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, _, _ := setupTestVPNService(t, db)

	// Default configured SubnetCIDR in test setup (10.100.0.0/16)
	if got := svc.SubnetCIDR(); got != "10.100.0.0/16" {
		t.Fatalf("expected default subnet 10.100.0.0/16, got %s", got)
	}

	// HealthProber must receive the subnet via SetDeviceProvider(svc)
	if proberSubnet := svc.prober.GetSubnetCIDR(); proberSubnet != "10.100.0.0/16" {
		t.Fatalf("expected prober to resolve 10.100.0.0/16, got %s", proberSubnet)
	}

	// Change SubnetCIDR on service config
	svc.cfg.SubnetCIDR = "10.200.0.0/16"
	if got := svc.SubnetCIDR(); got != "10.200.0.0/16" {
		t.Fatalf("expected updated subnet 10.200.0.0/16, got %s", got)
	}
	if proberSubnet := svc.prober.GetSubnetCIDR(); proberSubnet != "10.200.0.0/16" {
		t.Fatalf("expected prober to reflect updated 10.200.0.0/16, got %s", proberSubnet)
	}
}

func TestScheduledHealth_PreservesHandshakeBlocked(t *testing.T) {
	for _, outerRecovers := range []bool{false, true} {
		name := "outer_still_blocked"
		if outerRecovers {
			name = "outer_recovers_inner_fails"
		}
		t.Run(name, func(t *testing.T) {
			db := setupTestDB(t)
			svc, s1, s2, _, _ := setupTestVPNService(t, db)
			ctx := t.Context()
			if err := svc.pool.SyncFromDB(ctx); err != nil {
				t.Fatal(err)
			}
			a, err := svc.pool.GetTunnel(s1)
			if err != nil {
				t.Fatal(err)
			}
			b, err := svc.pool.GetTunnel(s2)
			if err != nil {
				t.Fatal(err)
			}
			peer := seedIngressPeer(t, db, "audit-713-user", "audit-713-peer", "10.100.3.77")
			// Force initial session onto A through normal production admission.
			svc.stickyMgr.AssignPeerAffinity(peer.peerKey, a.ID)
			initial, _, _, err := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
			if err != nil {
				t.Fatal(err)
			}
			svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
				return 0, errors.New("DPI handshake drop")
			})
			canaryCalls := 0
			svc.prober.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
				canaryCalls++
				return nil
			})
			for i := 0; i < svc.prober.Config().FailureThreshold; i++ {
				_, _ = svc.prober.ProbeTunnel(ctx, a)
			}
			blocked, err := svc.pool.GetTunnel(s1)
			if err != nil {
				t.Fatal(err)
			}
			if blocked.Status != models.TunnelStatusHandshakeBlocked {
				t.Fatalf("precondition status=%s", blocked.Status)
			}
			callsBefore := canaryCalls
			// Actual production updater and session migrator, with only outer network mocked.
			orch := orchestrator.New(db, nil, orchestrator.WithProbeFunc(func(_ context.Context, ep, _, _, _, _ string, _, _ any, _, _ int, _ time.Duration) (time.Duration, error) {
				if strings.EqualFold(ep, a.Endpoint) && !outerRecovers {
					return 0, errors.New("DPI handshake drop")
				}
				return 20 * time.Millisecond, nil
			}))
			orch.SetTunnelStatusUpdater(svc)
			orch.SetSessionMigrator(svc)
			if outerRecovers {
				svc.prober.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
					canaryCalls++
					return errors.New("inner blackhole")
				})
			}
			for i := 0; i < orch.ProbeFailureThreshold(); i++ {
				if err := orch.CheckBackendTunnelHealth(ctx); err != nil {
					t.Fatal(err)
				}
			}
			got, err := svc.pool.GetTunnel(s1)
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := db.GetBackendTunnel(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			sess, err := db.GetVPNSessionByID(ctx, initial.ID)
			if err != nil {
				t.Fatal(err)
			}
			live, ok := svc.sessionMgr.GetSessionSnapshotByPeer(peer.peerKey)
			t.Logf("outer_recovers=%t threshold=%d canary_calls_during_orchestrator=%d source=%d alternative=%d pool_status=%s db_status=%s session_backend=%d memory_backend=%d route_on_original=%t",
				outerRecovers, orch.ProbeFailureThreshold(), canaryCalls-callsBefore, a.ID, b.ID, got.Status, persisted.Status, sess.BackendTunnelID, live.BackendTunnelID, svc.forwarder.HasSessionRoute(peer.peerKey, initial.ID, peer.connID, peer.ip.String(), a.ID))
			if got.Status != models.TunnelStatusHandshakeBlocked || persisted.Status != models.TunnelStatusHandshakeBlocked {
				t.Errorf("scheduler bypassed dual-tier health: pool=%s db=%s", got.Status, persisted.Status)
			}
			if !outerRecovers && (sess.BackendTunnelID != a.ID || !ok || live.BackendTunnelID != a.ID) {
				t.Error("scheduled outer-only health moved an established viable session")
			}
		})
	}
}
