package vpn

// Consumer-level admission proof for issue #731: a new portal client and a
// route-loss re-admission must reach a handshake-blocked backend whose inner
// data path is proven alive, and must be refused there in every case where that
// proof is absent, stale, withdrawn or belongs to a different device.
//
// Chain exercised (production code except where stated):
//
//	REAL amneziawg-go client engine (netstack TCP)
//	  -> REAL portal ClientAWGDevice / IngressEngine
//	  -> REAL ingress Router.HandlePacket
//	  -> REAL Service.ensureBackendSessionForIngress
//	     (sticky, LB, accounting, route registration)
//	  -> REAL Forwarder
//	  -> backend device
//	  -> REAL pumpBackendReturns -> client
//
// Fixture-only parts: the backend device is an in-memory netstack echo wrapper
// rather than a remote AWG peer (it answers the genuine matched ICMP canary
// through the real CanaryResponseDemuxer path and can be switched to refuse the
// canary or to drop everything), and the outer handshake failure is a failing
// probe function rather than real DPI. Status transitions come from the real
// HealthProber.ProbeTunnel; no canary success override is installed.
//
// Two distinct enrolled peers are used because they exercise different
// contracts: the "existing" peer goes through live-session reuse and route loss,
// while the "fresh" peer has never been admitted, so it is the only way to test
// FIRST admission. Re-dialling one peer would be served by its preserved route
// and would prove nothing about admission.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/clientawg"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// Backend device behaviour used by the admission fixtures.
const (
	canaryDevAlive      int32 = iota
	canaryDevDead             // drops payload and canary
	canaryDevCanaryOnly       // payload flows, canary gets no reply
)

// canaryBackendDevice is a real netstack echo backend that additionally answers
// the genuine AWG ICMP canary and reports a device generation, which is what the
// admission evidence has to be bound to.
type canaryBackendDevice struct {
	inner      *returnStackDevice
	state      atomic.Int32
	created    time.Time
	closed     atomic.Bool
	hooksMu    sync.Mutex
	hooks      map[uint64]tunnel.CanaryResponseHook
	nextHookID uint64
}

var (
	_ BackendDevice                = (*canaryBackendDevice)(nil)
	_ tunnel.CanaryResponseDemuxer = (*canaryBackendDevice)(nil)
	_ tunnel.DeviceGeneration      = (*canaryBackendDevice)(nil)
)

func (d *canaryBackendDevice) Read(p []byte) (int, error) { return d.inner.Read(p) }
func (d *canaryBackendDevice) Write(p []byte) (int, error) {
	if d.state.Load() == canaryDevDead {
		return len(p), nil
	}
	// Matched ICMP echo request toward 1.1.1.1: answer it exactly as a real
	// backend would, so the probe's own reply matcher decides the verdict.
	if len(p) >= 28 && p[9] == 1 && p[20] == 8 && net.IP(p[16:20]).Equal(net.IPv4(1, 1, 1, 1)) {
		if d.state.Load() == canaryDevAlive {
			id := binary.BigEndian.Uint16(p[24:26])
			seq := binary.BigEndian.Uint16(p[26:28])
			d.deliver(tunnel.BuildCanaryICMPEchoReply(net.IP(p[16:20]), net.IP(p[12:16]), id, seq))
		}
		return len(p), nil
	}
	return d.inner.Write(p)
}

func (d *canaryBackendDevice) Close() error                 { d.closed.Store(true); return d.inner.Close() }
func (d *canaryBackendDevice) IsClosed() bool               { return d.closed.Load() }
func (d *canaryBackendDevice) CreatedAt() time.Time         { return d.created }
func (d *canaryBackendDevice) LastHandshakeTime() time.Time { return d.created }
func (d *canaryBackendDevice) DroppedPackets() uint64       { return 0 }

// deliver hands one canary reply to the registered hooks. A canary reply is a
// single matched packet, so it is delivered synchronously: no goroutine ordering
// participates in deciding the verdict.
func (d *canaryBackendDevice) deliver(packet []byte) {
	d.hooksMu.Lock()
	hooks := make([]tunnel.CanaryResponseHook, 0, len(d.hooks))
	for _, h := range d.hooks {
		hooks = append(hooks, h)
	}
	d.hooksMu.Unlock()
	for _, h := range hooks {
		if h(packet) {
			return
		}
	}
}

func (d *canaryBackendDevice) RegisterCanaryResponseHook(hook tunnel.CanaryResponseHook) func() {
	d.hooksMu.Lock()
	if d.hooks == nil {
		d.hooks = make(map[uint64]tunnel.CanaryResponseHook)
	}
	d.nextHookID++
	id := d.nextHookID
	d.hooks[id] = hook
	d.hooksMu.Unlock()
	return func() {
		d.hooksMu.Lock()
		delete(d.hooks, id)
		d.hooksMu.Unlock()
	}
}

// canaryAdmissionEnv is one service with a real ingress engine, two enrolled
// portal clients and exactly one candidate backend.
type canaryAdmissionEnv struct {
	svc     *Service
	engine  *IngressEngine
	blocked *models.BackendTunnel
	dev     *canaryBackendDevice
	// existing is the peer that goes through live-session reuse and route loss.
	existing      enginePeer
	existingSaved string
	// fresh has never been admitted, so it always exercises FIRST admission.
	fresh      enginePeer
	freshSaved string
	dest       netip.Addr
}

// newCanaryAdmissionEnv builds the fixture: two pool tunnels from the standard
// test service, the second administratively disabled so the first is the only
// candidate, a real netstack echo backend in front of it, and a real upstream
// engine with two enrolled portal clients.
func newCanaryAdmissionEnv(t *testing.T, mutate ...func(*models.VPNConfig)) *canaryAdmissionEnv {
	t.Helper()
	ctx := t.Context()
	db := setupTestDB(t)
	muts := append([]func(*models.VPNConfig){fullAmneziaWGOpts()}, mutate...)
	svc := newIngressEngineService(t, db, muts...)
	existing, existingSaved := newEnginePeer(t, svc, db, "canary-existing")
	fresh, freshSaved := newEnginePeer(t, svc, db, "canary-fresh")
	if err := svc.pool.SyncFromDB(ctx); err != nil {
		t.Fatalf("pool sync: %v", err)
	}
	tunnels := svc.pool.ListTunnels()
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })
	if len(tunnels) < 2 {
		t.Fatalf("fixture: %d pool tunnels, want 2", len(tunnels))
	}
	blocked, other := tunnels[0], tunnels[1]

	dest := netip.MustParseAddr("198.51.100.99")
	dev := startCanaryBackend(t, svc, blocked, dest)
	// The other backend must not be a candidate, or a refusal of the blocked one
	// could be satisfied by admitting there instead.
	if err := svc.pool.SetTunnelEnabled(ctx, other.ServerID, false, models.DisableReasonAdmin); err != nil {
		t.Fatalf("disable second backend: %v", err)
	}
	svc.forwarder.StartPumps(ctx)
	t.Cleanup(svc.forwarder.StopPumps)

	engine, err := svc.NewIngressEngine(ctx, "canary-admission-portal", []clientawg.Peer{
		{PublicKey: existing.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(existing.assignedIP), 32)},
		{PublicKey: fresh.publicKey, AllowedIP: netip.PrefixFrom(netip.MustParseAddr(fresh.assignedIP), 32)},
	})
	if err != nil {
		t.Fatalf("NewIngressEngine: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	t.Cleanup(func() { _ = engine.Stop() })

	// The real production canary path must be in force: a success-only override
	// would prove nothing about the data plane.
	svc.SetCanaryProbeFunc(nil)
	if svc.prober.GetCanaryProbeFunc() != nil {
		t.Fatal("fixture: a canary override is installed")
	}

	return &canaryAdmissionEnv{
		svc: svc, engine: engine, blocked: blocked, dev: dev,
		existing: existing, existingSaved: existingSaved,
		fresh: fresh, freshSaved: freshSaved,
		dest: dest,
	}
}

// startCanaryBackend attaches a real netstack echo backend to the tunnel.
func startCanaryBackend(t *testing.T, svc *Service, tun *models.BackendTunnel, dest netip.Addr) *canaryBackendDevice {
	t.Helper()
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{dest}, nil, 1280)
	if err != nil {
		t.Fatalf("create backend netstack: %v", err)
	}
	dev := &canaryBackendDevice{
		inner:   &returnStackDevice{tun: vt},
		created: time.Now(),
		hooks:   map[uint64]tunnel.CanaryResponseHook{},
	}
	svc.mu.Lock()
	if svc.backendDevices == nil {
		svc.backendDevices = map[int64]BackendDevice{}
	}
	svc.backendDevices[tun.ID] = dev
	svc.mu.Unlock()
	svc.forwarder.AttachBackendDevice(tun.ID, dev)

	done := make(chan struct{})
	go func() { defer close(done); svc.pumpBackendReturns(tun.ID, tun.ServerID, dev) }()
	t.Cleanup(func() { _ = dev.Close(); <-done })

	tcpLn, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(dest, 40001))
	if err != nil {
		t.Fatalf("listen backend tcp: %v", err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if _, err := c.Write([]byte{0xA1}); err != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return dev
}

// sweepFailingOuter runs one real health sweep whose outer handshake fails, so
// the real prober drives the backend to handshake_blocked (or keeps it there)
// using its own inner canary verdict.
func (e *canaryAdmissionEnv) sweepFailingOuter(t *testing.T) *models.BackendTunnel {
	t.Helper()
	e.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return 0, fmt.Errorf("outer handshake dropped")
	})
	return e.oneSweep(t)
}

// sweepSlowOuterSuccess runs one real health sweep whose outer handshake
// SUCCEEDS above the latency threshold (the #742 preservation case).
func (e *canaryAdmissionEnv) sweepSlowOuterSuccess(t *testing.T) *models.BackendTunnel {
	t.Helper()
	slow := time.Duration(e.svc.prober.LatencyThresholdMS()+500) * time.Millisecond
	e.svc.prober.SetProbeFunc(func(context.Context, string, string, string, string, string, any, any, int, int, time.Duration) (time.Duration, error) {
		return slow, nil
	})
	return e.oneSweep(t)
}

// oneSweep probes the blocked backend once and returns its resulting pool row.
// The probe's own error is logged, not asserted: what the caller cares about is
// the state the real prober decided.
func (e *canaryAdmissionEnv) oneSweep(t *testing.T) *models.BackendTunnel {
	t.Helper()
	live, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if _, err := e.svc.prober.ProbeTunnel(t.Context(), live); err != nil {
		t.Logf("probe returned %v", err)
	}
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("re-read tunnel: %v", err)
	}
	return cur
}

// dial starts one real upstream client and completes the marker handshake.
// peer/saved select which enrolled portal client is exercised.
func (e *canaryAdmissionEnv) dial(t *testing.T, peer enginePeer, saved string, timeout time.Duration, name string) (net.Conn, error) {
	t.Helper()
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(peer.assignedIP)}, nil, 1280)
	if err != nil {
		t.Fatalf("create client netstack: %v", err)
	}
	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, name))
	t.Cleanup(dev.Close)
	if err := dev.IpcSet(configToUAPI(t, saved)); err != nil {
		t.Fatalf("client config rejected: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("client up: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	c, err := stack.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(e.dest, 40001))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	marker := make([]byte, 1)
	if _, err := io.ReadFull(c, marker); err != nil {
		return c, fmt.Errorf("read marker: %w", err)
	}
	if marker[0] != 0xA1 {
		return c, fmt.Errorf("marker = %#x, want 0xa1", marker[0])
	}
	return c, nil
}

// echo writes a payload and reads it back through the full data path.
func echo(c net.Conn, payload string, timeout time.Duration) error {
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte(payload)); err != nil {
		return err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != payload {
		return fmt.Errorf("echo mismatch: got %q want %q", buf, payload)
	}
	return nil
}

// admissionOwnership snapshots what the admission must get right for one peer:
// session identity, route ownership, the backend gauge and the (unchanged) label.
type admissionOwnership struct {
	admitted        bool
	sessionID       string
	backendTunnelID int64
	routeSessionID  string
	activeConns     int
	tunnelStatus    string
}

func (e *canaryAdmissionEnv) ownership(t *testing.T, peerKey string) admissionOwnership {
	t.Helper()
	o := admissionOwnership{routeSessionID: e.svc.forwarder.RouteSessionID(peerKey)}
	if sess, ok := e.svc.sessionMgr.GetSessionSnapshotByPeer(peerKey); ok && sess.Status == "connected" {
		o.admitted = true
		o.sessionID = sess.ID
		o.backendTunnelID = sess.BackendTunnelID
	}
	cur, err := e.svc.pool.GetTunnel(e.blocked.ServerID)
	if err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	o.activeConns = cur.ActiveConnections
	o.tunnelStatus = cur.Status
	return o
}

// requireAdmittedOnBlockedBackend asserts the full positive contract: the peer is
// admitted onto the blocked backend, its route belongs to that same session, the
// gauge equals wantConns and the label never changed.
func (e *canaryAdmissionEnv) requireAdmittedOnBlockedBackend(t *testing.T, peerKey string, wantConns int) {
	t.Helper()
	o := e.ownership(t, peerKey)
	if !o.admitted {
		t.Fatalf("peer was not admitted: %+v", o)
	}
	if o.backendTunnelID != e.blocked.ID {
		t.Fatalf("session backend = %d, want the blocked backend %d", o.backendTunnelID, e.blocked.ID)
	}
	if o.routeSessionID != o.sessionID {
		t.Fatalf("route owner = %q, want the admitted session %q", o.routeSessionID, o.sessionID)
	}
	if o.activeConns != wantConns {
		t.Fatalf("backend gauge = %d, want %d", o.activeConns, wantConns)
	}
	if o.tunnelStatus != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("backend status = %q, want handshake_blocked preserved (admission must not relabel)", o.tunnelStatus)
	}
}

// requireRefusedNewAdmission asserts a FIRST admission was refused AND left
// nothing behind: no session, no route.
func (e *canaryAdmissionEnv) requireRefusedNewAdmission(t *testing.T, who string) {
	t.Helper()
	if c, err := e.dial(t, e.fresh, e.freshSaved, 3*time.Second, "canary-refused-"+who); err == nil {
		if c != nil {
			_ = c.Close()
		}
		t.Fatalf("%s: a brand-new client was admitted", who)
	}
	o := e.ownership(t, e.fresh.publicKey)
	if o.admitted || o.routeSessionID != "" {
		t.Fatalf("%s: refused admission left state behind: %+v", who, o)
	}
}

// TestCanaryAdmission_ActiveControlValidatesFixture is the fixture-validity
// control: with the backend genuinely active the same path carries bidirectional
// payload for both peers. Without it a later refusal could just be a broken
// fixture.
func TestCanaryAdmission_ActiveControlValidatesFixture(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	cases := []struct {
		name  string
		peer  enginePeer
		saved string
	}{
		{"existing", e.existing, e.existingSaved},
		{"fresh", e.fresh, e.freshSaved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := e.dial(t, tc.peer, tc.saved, 10*time.Second, "canary-control-"+tc.name)
			if err != nil {
				t.Fatalf("active backend did not carry the client: %v", err)
			}
			if err := echo(c, "canary-admission-active-control-"+tc.name, 5*time.Second); err != nil {
				t.Fatalf("active backend did not carry payload: %v", err)
			}
			if o := e.ownership(t, tc.peer.publicKey); !o.admitted || o.backendTunnelID != e.blocked.ID {
				t.Fatalf("active control ownership = %+v", o)
			}
		})
	}
}

// TestCanaryAdmission_NewClientOnBlockedBackendWithFreshCanary proves the
// headline requirement: a brand-new portal client is admitted onto a
// handshake-blocked backend while its attached inner path is proven alive, and
// carries bidirectional payload with correct session/route/gauge identity.
func TestCanaryAdmission_NewClientOnBlockedBackendWithFreshCanary(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	cur := e.sweepFailingOuter(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: backend status = %q, want handshake_blocked", cur.Status)
	}
	if cur.ActiveConnections != 0 {
		t.Fatalf("fixture: backend already has %d sessions", cur.ActiveConnections)
	}

	c, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "canary-new-client")
	if err != nil {
		t.Fatalf("new client refused on a canary-proven blocked backend: %v", err)
	}
	e.requireAdmittedOnBlockedBackend(t, e.fresh.publicKey, 1)
	if err := echo(c, "canary-admission-new-client-payload", 5*time.Second); err != nil {
		t.Fatalf("admitted client got no bidirectional payload: %v", err)
	}
}

// TestCanaryAdmission_RouteLossReadmission proves the second admitted case: a
// client whose forwarder route was lost while pinned to the blocked backend is
// re-admitted there with payload, instead of being refused or moved.
func TestCanaryAdmission_RouteLossReadmission(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-route-loss")
	if err != nil {
		t.Fatalf("initial admission on the active backend: %v", err)
	}
	if err := echo(c, "canary-admission-pre-block", 5*time.Second); err != nil {
		t.Fatalf("pre-block payload: %v", err)
	}
	cur := e.sweepFailingOuter(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: backend status = %q", cur.Status)
	}
	// Preservation: the established route is untouched by the outer failure.
	if err := echo(c, "canary-admission-preserved-route", 5*time.Second); err != nil {
		t.Fatalf("existing route lost when the backend became blocked: %v", err)
	}

	e.svc.forwarder.UnregisterSession(e.existing.publicKey)
	if got := e.svc.forwarder.RouteSessionID(e.existing.publicKey); got != "" {
		t.Fatalf("fixture: route still present after unregister (%q)", got)
	}
	if err := echo(c, "canary-admission-readmitted", 10*time.Second); err != nil {
		t.Fatalf("route-loss peer was not re-admitted with payload: %v", err)
	}
	e.requireAdmittedOnBlockedBackend(t, e.existing.publicKey, 1)
}

// TestCanaryAdmission_SlowOuterSuccessPreservesThenAdmits covers the #742
// interaction: a slow outer SUCCESS on a session-carrying blocked backend keeps
// the preservation label, and because the inner canary succeeded on that same
// sweep the backend also stays admissible for a new client.
func TestCanaryAdmission_SlowOuterSuccessPreservesThenAdmits(t *testing.T) {
	e := newCanaryAdmissionEnv(t)
	c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-slow-existing")
	if err != nil {
		t.Fatalf("initial admission: %v", err)
	}
	if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("fixture: status = %q", cur.Status)
	}
	cur := e.sweepSlowOuterSuccess(t)
	if cur.Status != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("slow outer success changed a session-carrying blocked backend to %q, want handshake_blocked preserved", cur.Status)
	}
	if err := echo(c, "canary-admission-slow-preserved", 5*time.Second); err != nil {
		t.Fatalf("slow outer success disturbed the established route: %v", err)
	}
	// The same slow sweep ran the inner canary, so a new client must be admitted.
	nc, err := e.dial(t, e.fresh, e.freshSaved, 10*time.Second, "canary-slow-new")
	if err != nil {
		t.Fatalf("new client refused after a canary-proven slow outer success: %v", err)
	}
	if err := echo(nc, "canary-admission-slow-new-payload", 5*time.Second); err != nil {
		t.Fatalf("newly admitted client got no payload: %v", err)
	}
	o := e.ownership(t, e.fresh.publicKey)
	if !o.admitted || o.backendTunnelID != e.blocked.ID || o.activeConns != 2 {
		t.Fatalf("slow-success admission ownership = %+v (want 2 sessions on the blocked backend)", o)
	}
	if o.tunnelStatus != models.TunnelStatusHandshakeBlocked {
		t.Fatalf("status = %q, want handshake_blocked preserved", o.tunnelStatus)
	}
}

// TestCanaryAdmission_RefusesWithoutFreshEvidence is the label-only negative
// control: every blocked-but-unproven backend must still refuse a first
// admission, which is what stops "admit anything blocked" from shipping.
func TestCanaryAdmission_RefusesWithoutFreshEvidence(t *testing.T) {
	t.Run("never probed inner path", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		// Blocked by label only: no sweep ran, so no canary evidence exists.
		if err := e.svc.pool.SetTunnelStatus(t.Context(), e.blocked.ServerID, models.TunnelStatusHandshakeBlocked, 0); err != nil {
			t.Fatalf("set blocked status: %v", err)
		}
		e.requireRefusedNewAdmission(t, "never-probed")
		if n := e.engine.Router().StatsSnapshot().NoActiveBackendDrops; n == 0 {
			t.Fatal("refusal was not accounted as a no-active-backend drop")
		}
	})

	t.Run("transient suspicion keeps routes but refuses new clients", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		c, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-transient")
		if err != nil {
			t.Fatalf("initial admission: %v", err)
		}
		e.sweepFailingOuter(t)
		// One inner failure: below the confirmation threshold, and the
		// established session keeps the blocked label.
		e.dev.state.Store(canaryDevCanaryOnly)
		cur := e.sweepFailingOuter(t)
		if cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q, want handshake_blocked preserved for one inner failure", cur.Status)
		}
		if fails := e.svc.prober.GetCanaryFailCount(e.blocked.ServerID); fails != 1 {
			t.Fatalf("fixture: inner failure count = %d, want 1", fails)
		}
		e.requireRefusedNewAdmission(t, "transient")
		// The established client must keep its route through transient suspicion.
		e.dev.state.Store(canaryDevAlive)
		if err := echo(c, "canary-admission-existing-survives", 5*time.Second); err != nil {
			t.Fatalf("transient inner suspicion disturbed the established route: %v", err)
		}
	})

	t.Run("dead inner path", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if _, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-dead-seed"); err != nil {
			t.Fatalf("initial admission: %v", err)
		}
		e.sweepFailingOuter(t)
		e.dev.state.Store(canaryDevDead)
		e.sweepFailingOuter(t)
		e.requireRefusedNewAdmission(t, "dead-inner")
	})

	t.Run("stale evidence", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		clock := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
		e.svc.prober.SetNowFuncForTest(func() time.Time { return clock })
		t.Cleanup(func() { e.svc.prober.SetNowFuncForTest(nil) })
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		// Step past the freshness bound derived from the probe cadence.
		cfg := e.svc.prober.Config()
		clock = clock.Add(cfg.Interval*2 + cfg.Timeout)
		e.requireRefusedNewAdmission(t, "stale-evidence")
	})

	t.Run("replaced device on the same tunnel", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		// Same tunnel row and ID, different device object: a credential
		// replacement or a detach/re-attach.
		replacement := &canaryBackendDevice{
			inner:   e.dev.inner,
			created: e.dev.created.Add(time.Hour),
			hooks:   map[uint64]tunnel.CanaryResponseHook{},
		}
		e.svc.mu.Lock()
		e.svc.backendDevices[e.blocked.ID] = replacement
		e.svc.mu.Unlock()
		e.svc.forwarder.AttachBackendDevice(e.blocked.ID, replacement)

		e.requireRefusedNewAdmission(t, "replaced-device")
	})

	t.Run("detached device", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		e.svc.mu.Lock()
		delete(e.svc.backendDevices, e.blocked.ID)
		e.svc.mu.Unlock()
		e.requireRefusedNewAdmission(t, "detached-device")
	})
}

// TestCanaryAdmission_GuardsStillRefuse proves the non-health guards keep their
// authority for evidence-carrying blocked backends.
func TestCanaryAdmission_GuardsStillRefuse(t *testing.T) {
	t.Run("administrative disable", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t)
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		if err := e.svc.pool.SetTunnelEnabled(t.Context(), e.blocked.ServerID, false, models.DisableReasonAdmin); err != nil {
			t.Fatalf("disable backend: %v", err)
		}
		e.requireRefusedNewAdmission(t, "admin-disabled")
	})

	t.Run("per-backend capacity", func(t *testing.T) {
		e := newCanaryAdmissionEnv(t, func(cfg *models.VPNConfig) { cfg.MaxPeersPerBackend = 1 })
		if _, err := e.dial(t, e.existing, e.existingSaved, 10*time.Second, "canary-capacity-seed"); err != nil {
			t.Fatalf("initial admission: %v", err)
		}
		if cur := e.sweepFailingOuter(t); cur.Status != models.TunnelStatusHandshakeBlocked {
			t.Fatalf("fixture: status = %q", cur.Status)
		}
		before := e.ownership(t, e.existing.publicKey)
		if before.activeConns != 1 {
			t.Fatalf("fixture: gauge = %d, want 1 (capacity limit is 1)", before.activeConns)
		}
		// The blocked backend is at capacity, so it must be refused even with
		// fresh evidence; the only other backend is disabled.
		e.requireRefusedNewAdmission(t, "capacity")
		after := e.ownership(t, e.existing.publicKey)
		if after.activeConns != before.activeConns {
			t.Fatalf("capacity refusal changed the gauge: %d -> %d", before.activeConns, after.activeConns)
		}
		if after.routeSessionID != before.routeSessionID {
			t.Fatalf("capacity refusal disturbed the established route: %q -> %q", before.routeSessionID, after.routeSessionID)
		}
	})
}
