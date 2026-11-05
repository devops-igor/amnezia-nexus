package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/service/orchestrator"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

type mockBackendCanaryDevice struct {
	mu          sync.Mutex
	written     [][]byte
	replyData   []byte
	canaryHooks map[uint64]tunnel.CanaryResponseHook
	nextHookID  uint64
}

var _ tunnel.CanaryResponseDemuxer = (*mockBackendCanaryDevice)(nil)
var _ BackendDevice = (*mockBackendCanaryDevice)(nil)

func (m *mockBackendCanaryDevice) Read([]byte) (int, error)     { return 0, io.EOF }
func (m *mockBackendCanaryDevice) Close() error                 { return nil }
func (m *mockBackendCanaryDevice) IsClosed() bool               { return false }
func (m *mockBackendCanaryDevice) CreatedAt() time.Time         { return time.Now() }
func (m *mockBackendCanaryDevice) LastHandshakeTime() time.Time { return time.Now() }
func (m *mockBackendCanaryDevice) DroppedPackets() uint64       { return 0 }

func (m *mockBackendCanaryDevice) RegisterCanaryResponseHook(hook tunnel.CanaryResponseHook) func() {
	m.mu.Lock()
	if m.canaryHooks == nil {
		m.canaryHooks = make(map[uint64]tunnel.CanaryResponseHook)
	}
	m.nextHookID++
	id := m.nextHookID
	m.canaryHooks[id] = hook
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		delete(m.canaryHooks, id)
		m.mu.Unlock()
	}
}

func (m *mockBackendCanaryDevice) Write(p []byte) (int, error) {
	m.mu.Lock()
	cp := make([]byte, len(p))
	copy(cp, p)
	m.written = append(m.written, cp)

	if len(p) >= 28 && p[9] == 1 {
		ihl := int(p[0]&0x0f) * 4
		if len(p) >= ihl+8 {
			id := binary.BigEndian.Uint16(p[ihl+4 : ihl+6])
			seq := binary.BigEndian.Uint16(p[ihl+6 : ihl+8])
			src := net.IP(p[12:16])
			dst := net.IP(p[16:20])
			reply := tunnel.BuildCanaryICMPEchoReply(dst, src, id, seq)
			for _, h := range m.canaryHooks {
				if h != nil {
					go h(reply)
				}
			}
		}
	} else if len(m.replyData) > 0 {
		reply := make([]byte, len(m.replyData))
		copy(reply, m.replyData)
		for _, h := range m.canaryHooks {
			if h != nil {
				go h(reply)
			}
		}
	}
	m.mu.Unlock()
	return len(p), nil
}

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
	svc.SetCanaryProbeFunc(nil)
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

	// HealthProber resolves default subnet 10.100.0.0/16 immutably configured from DefaultHealthConfig
	if proberSubnet := svc.prober.GetSubnetCIDR(); proberSubnet != "10.100.0.0/16" {
		t.Fatalf("expected prober to resolve 10.100.0.0/16, got %s", proberSubnet)
	}

	// Direct service config mutation does not dynamic-callback prober without explicit update
	svc.cfg.SubnetCIDR = "10.200.0.0/16"
	if got := svc.SubnetCIDR(); got != "10.200.0.0/16" {
		t.Fatalf("expected updated subnet 10.200.0.0/16, got %s", got)
	}
	// Prober retains its immutable SubnetCIDR without deadlocking or dynamic cross-lock callbacks
	if proberSubnet := svc.prober.GetSubnetCIDR(); proberSubnet != "10.100.0.0/16" {
		t.Fatalf("expected prober to retain immutable subnet 10.100.0.0/16, got %s", proberSubnet)
	}

	// Explicit update via SetDeviceProvider propagates updated subnet to prober safely
	svc.prober.SetDeviceProvider(svc)
	if proberSubnet := svc.prober.GetSubnetCIDR(); proberSubnet != "10.200.0.0/16" {
		t.Fatalf("expected prober to update to 10.200.0.0/16 via SetDeviceProvider, got %s", proberSubnet)
	}
}

func TestVPNService_CustomSubnetCIDR_CanaryGatewaySourceIP(t *testing.T) {
	db := setupTestDB(t)
	customCIDR := "10.200.0.0/16"
	svc, s1, _, _, _ := setupTestVPNService(t, db, func(c *models.VPNConfig) {
		c.SubnetCIDR = customCIDR
	})
	svc.SetCanaryProbeFunc(nil)

	if got := svc.SubnetCIDR(); got != customCIDR {
		t.Fatalf("expected service subnet %s, got %s", customCIDR, got)
	}

	// Prober must be initialized with the custom SubnetCIDR from Service configuration
	if got := svc.prober.GetSubnetCIDR(); got != customCIDR {
		t.Fatalf("expected prober subnet %s, got %s", customCIDR, got)
	}

	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(s1)
	if err != nil {
		t.Fatal(err)
	}

	// Echo reply matching canary request (target responder 1.1.1.1, gateway 10.200.0.1)
	dev := &mockBackendCanaryDevice{
		replyData: tunnel.BuildCanaryICMPEchoReply(net.IPv4(1, 1, 1, 1), net.IPv4(10, 200, 0, 1), 0x0713, 1),
	}
	svc.backendDevices = map[int64]BackendDevice{tun.ID: dev}

	if err := svc.ProbeCanary(ctx, tun); err != nil {
		t.Fatalf("expected ProbeCanary to succeed, got %v", err)
	}

	dev.mu.Lock()
	defer dev.mu.Unlock()
	if len(dev.written) == 0 {
		t.Fatal("expected at least one canary packet written to device")
	}

	pkt := dev.written[0]
	if len(pkt) < 20 {
		t.Fatalf("written packet too short for IPv4 header: %d bytes", len(pkt))
	}

	// Bytes 12..16 are the IPv4 source address
	srcIP := net.IP(pkt[12:16])
	expectedSrcIP := net.IPv4(10, 200, 0, 1).To4()
	if !srcIP.Equal(expectedSrcIP) {
		t.Fatalf("expected canary source IP %s derived from %s, got %s", expectedSrcIP, customCIDR, srcIP)
	}

	// Bytes 16..20 are the IPv4 destination address (public canary responder 1.1.1.1)
	dstIP := net.IP(pkt[16:20])
	expectedDstIP := net.IPv4(1, 1, 1, 1).To4()
	if !dstIP.Equal(expectedDstIP) {
		t.Fatalf("expected canary destination IP %s, got %s", expectedDstIP, dstIP)
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
			expectedStatus := models.TunnelStatusHandshakeBlocked
			if outerRecovers {
				expectedStatus = models.TunnelStatusDegraded
			}
			if got.Status != expectedStatus || persisted.Status != expectedStatus {
				t.Errorf("expected status %s: pool=%s db=%s", expectedStatus, got.Status, persisted.Status)
			}
			if !outerRecovers && (sess.BackendTunnelID != a.ID || !ok || live.BackendTunnelID != a.ID) {
				t.Error("scheduled outer-only health moved an established viable session")
			}
		})
	}
}

func TestAudit713ProductionRecoveryAdmitsBrokenDataPlane(t *testing.T) {
	db := setupTestDB(t)
	svc, sid, other, _, _ := setupTestVPNService(t, db)
	ctx := t.Context()
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	tun, err := svc.pool.GetTunnel(sid)
	if err != nil {
		t.Fatal(err)
	}
	// Attached, not closed, but payload is not transiting: the real active hook only checks attachment.
	svc.backendDevices = map[int64]BackendDevice{tun.ID: &mockBackendCanaryDevice{}}
	if err := svc.pool.SetTunnelStatus(ctx, sid, models.TunnelStatusHandshakeBlocked, 20); err != nil {
		t.Fatal(err)
	}
	if err := svc.pool.SetTunnelStatus(ctx, other, models.TunnelStatusDisabled, 0); err != nil {
		t.Fatal(err)
	}
	calls := 0
	svc.prober.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		calls++
		return errors.New("data peer remains blackholed")
	})
	svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 20 * time.Millisecond, nil
	})
	// Keep the constructor's actual active hook and provider unchanged.
	_, probeErr := svc.prober.ProbeTunnel(ctx, tun)
	peer := seedIngressPeer(t, db, "audit-recovery", "audit-recovery-peer-key", "10.100.3.81")
	session, backend, _, admitErr := svc.EnsureBackendSessionForIngress(ctx, ownershipFor(peer))
	persisted, _ := db.GetBackendTunnel(ctx, tun.ID)
	route := false
	sessionStatus := "none"
	selected := int64(0)
	if session != nil && backend != nil {
		selected = backend.ID
		sessionStatus = session.Status
		route = svc.forwarder.HasSessionRoute(peer.peerKey, session.ID, peer.connID, peer.ip.String(), backend.ID)
	}
	t.Logf("real_active_hook=true canary_calls=%d probe_err=%v db_status=%s admission_err=%v new_session=%s backend=%d broken_backend=%d registered_route=%t", calls, probeErr, persisted.Status, admitErr, sessionStatus, selected, tun.ID, route)
	if admitErr == nil {
		t.Error("fresh peer admitted to broken payload path after outer-only recovery")
	}
}

func TestVPNService_HasCanaryProber(t *testing.T) {
	var nilSvc *Service
	tun := &models.BackendTunnel{ID: 42}
	if nilSvc.HasCanaryProber(tun) {
		t.Error("expected nil service to return false for HasCanaryProber")
	}

	svc := &Service{}
	if svc.HasCanaryProber(tun) {
		t.Error("expected service without prober to return false for HasCanaryProber")
	}

	db := setupTestDB(t)
	pool := tunnel.NewPool(db)
	cfg := tunnel.DefaultHealthConfig()
	svc.prober = tunnel.NewHealthProber(pool, db, cfg, nil)

	if svc.HasCanaryProber(tun) {
		t.Error("expected prober without device or probe function to return false for HasCanaryProber")
	}

	svc.prober.SetCanaryProbeFunc(func(context.Context, *models.BackendTunnel) error {
		return nil
	})
	if !svc.HasCanaryProber(tun) {
		t.Error("expected prober with probe function to return true for HasCanaryProber")
	}
}
