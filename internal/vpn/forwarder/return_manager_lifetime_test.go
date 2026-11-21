package forwarder

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Direct-egress manager lifetime (issue #861).
//
// Observing a backend reply or a proxy dispatch reads the forwarder's direct-egress
// manager. That pointer is cleared or replaced by SetDirectEgress under the forwarder
// lock while an administrator disables or reconfigures policy routing, and backend
// readers keep serving replies across that transition. Each helper therefore captures
// the pointer ONCE under that lock and uses only the captured value: a second unlocked
// read is a data race AND can name a pointer that is already gone.
//
// These cases drive the real packet path (RouteClientToBackend, RouteBackendToClient and
// the client writer) through the public forwarder setters. Nothing mutates a forwarder
// field directly, nothing replaces the manager's own read lock, and no evidence is
// fabricated by a test-side counter.

const (
	lifetimeClientIP   = "10.100.0.7"
	lifetimePeer       = "peer-lifetime"
	lifetimeSessionID  = "sess-lifetime"
	lifetimeBackendID  = int64(31)
	lifetimeRemote     = "5.5.5.5"
	lifetimeRemotePort = uint16(443)
	lifetimeClientPort = uint16(44000)
)

type managerLifetimeFixture struct {
	fwd     *Forwarder
	dem     *DirectEgressManager
	capture *testCaptureReturnPath
}

// newManagerLifetimeFixture builds a policy-active forwarder whose route owns a captured
// plaintext writer, so a delivered reply is observable in the client writer.
func newManagerLifetimeFixture(t *testing.T, queueSize int) *managerLifetimeFixture {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", queueSize)
	fwd.SetPBREnabled(true)
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: newMockPacketDev(),
	}, fwd)
	fwd.SetDirectEgress(dem)
	t.Cleanup(func() { _ = dem.Close() })
	// No published policy snapshot: every dispatch takes the fail-closed PROXY
	// default, which is the branch that reads dispatch evidence.
	capture := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(lifetimeSessionID, "conn-lifetime", lifetimePeer, lifetimeClientIP, lifetimeBackendID, capture.path)
	fwd.StartPumps(t.Context())
	t.Cleanup(fwd.StopPumps)
	return &managerLifetimeFixture{fwd: fwd, dem: dem, capture: capture}
}

// clientPacket is the client's own packet: client -> remote on the tuple under test.
func lifetimeClientPacket() []byte {
	return buildTestIPv4TCPPacket(
		netip.MustParseAddr(lifetimeClientIP), netip.MustParseAddr(lifetimeRemote),
		lifetimeClientPort, lifetimeRemotePort, 0x02, nil)
}

// replyPacket is the backend's answer to that packet: remote -> client.
func lifetimeReplyPacket() []byte {
	return buildTestIPv4TCPPacket(
		netip.MustParseAddr(lifetimeRemote), netip.MustParseAddr(lifetimeClientIP),
		lifetimeRemotePort, lifetimeClientPort, 0x12, []byte("answer"))
}

func (fix *managerLifetimeFixture) dispatch(t *testing.T) {
	t.Helper()
	if err := fix.fwd.RouteClientToBackend(lifetimePeer, lifetimeClientPacket()); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
}

func (fix *managerLifetimeFixture) reply(t *testing.T) error {
	t.Helper()
	return fix.fwd.RouteBackendToClient(lifetimeBackendID, lifetimeReplyPacket(), lifetimeClientIP)
}

// flow copies the one flow under test from the manager the fixture created, which stays
// reachable even while the forwarder has the manager detached.
func (fix *managerLifetimeFixture) flow(t *testing.T) SessionFlow {
	t.Helper()
	flow, ok := fix.findFlow()
	if !ok {
		t.Fatalf("no flow for %s:%d", lifetimeRemote, lifetimeRemotePort)
	}
	return flow
}

func (fix *managerLifetimeFixture) findFlow() (SessionFlow, bool) {
	list := fix.dem.SnapshotSessionFlows(lifetimeSessionID, 0, time.Now(), 0)
	for _, flow := range list.Flows {
		if flow.DstPort == lifetimeRemotePort {
			return flow, true
		}
	}
	return SessionFlow{}, false
}

// waitDelivered waits for the client writer to accept want replies.
func (fix *managerLifetimeFixture) waitDelivered(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(fix.capture.getPackets()) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("client writer accepted %d packets, want %d", len(fix.capture.getPackets()), want)
}

// TestReturnObservationFollowsManagerLifetime is the live/nil/re-attached control for the
// reply path. Attribution follows the manager the forwarder actually holds, and a reply
// keeps reaching the client even while no manager is configured.
func TestReturnObservationFollowsManagerLifetime(t *testing.T) {
	fix := newManagerLifetimeFixture(t, 8)
	fix.dispatch(t)
	if flow := fix.flow(t); flow.ForwardPackets != 1 {
		t.Fatalf("dispatch evidence = %d packet(s), want the one that was admitted", flow.ForwardPackets)
	}

	// Live manager: the reply reverses to the admitting flow and reaches the client.
	if err := fix.reply(t); err != nil {
		t.Fatalf("live reply refused: %v", err)
	}
	fix.waitDelivered(t, 1)
	flow := fix.flow(t)
	if flow.ReturnMatched != 1 || flow.ReturnAdmitted != 1 || flow.ReturnDelivered != 1 {
		t.Fatalf("live return = matched %d / admitted %d / delivered %d, want 1/1/1",
			flow.ReturnMatched, flow.ReturnAdmitted, flow.ReturnDelivered)
	}

	// Detached manager: nothing is attributed, and the reply is still delivered.
	unmatched := fix.fwd.proxyReturnsUnmatched.Load()
	fix.fwd.SetDirectEgress(nil)
	if err := fix.reply(t); err != nil {
		t.Fatalf("reply with no manager refused: %v", err)
	}
	fix.waitDelivered(t, 2)
	if got := fix.flow(t).ReturnMatched; got != 1 {
		t.Errorf("detached return matched %d, want the live count unchanged at 1", got)
	}
	if got := fix.fwd.proxyReturnsUnmatched.Load(); got != unmatched+1 {
		t.Errorf("unmatched returns = %d, want %d for the unattributable reply", got, unmatched+1)
	}

	// Re-attached manager: the same flow is attributed again.
	fix.fwd.SetDirectEgress(fix.dem)
	if err := fix.reply(t); err != nil {
		t.Fatalf("re-attached reply refused: %v", err)
	}
	fix.waitDelivered(t, 3)
	if got := fix.flow(t).ReturnMatched; got != 2 {
		t.Errorf("re-attached return matched %d, want 2", got)
	}
}

// TestReturnObservationToleratesClosedManagerStillAttached covers the real disable order:
// ConfigurePBR closes the manager and detaches it afterwards, so a backend reply can be
// observed through a manager that is already closed. The frozen flow table is still a
// truthful record of what that manager admitted, and reading it must stay safe.
func TestReturnObservationToleratesClosedManagerStillAttached(t *testing.T) {
	fix := newManagerLifetimeFixture(t, 8)
	fix.dispatch(t)
	if err := fix.reply(t); err != nil {
		t.Fatalf("live reply refused: %v", err)
	}
	fix.waitDelivered(t, 1)

	if err := fix.dem.Close(); err != nil {
		t.Fatalf("close manager: %v", err)
	}
	if err := fix.reply(t); err != nil {
		t.Fatalf("reply through a closed manager refused: %v", err)
	}
	fix.waitDelivered(t, 2)
	flow := fix.flow(t)
	if flow.ReturnMatched != 2 || flow.ReturnDelivered != 2 {
		t.Errorf("closed-manager return = matched %d / delivered %d, want 2/2",
			flow.ReturnMatched, flow.ReturnDelivered)
	}
}

// TestDispatchObservationFollowsManagerLifetime is the live/nil/re-attached/closed control
// for the dispatch path. A packet keeps reaching the backend through every transition; the
// attribution follows the manager the forwarder holds.
func TestDispatchObservationFollowsManagerLifetime(t *testing.T) {
	fix := newManagerLifetimeFixture(t, 64)
	fix.dispatch(t)
	if flow := fix.flow(t); flow.ForwardPackets != 1 {
		t.Fatalf("live dispatch = %d attributed packet(s), want 1", flow.ForwardPackets)
	}

	// Detached manager: the packet still reaches the proxy backend, and nothing is
	// attributed because there is no manager to attribute it through.
	queued := len(fix.fwd.backendQueues[lifetimeBackendID])
	fix.fwd.SetDirectEgress(nil)
	fix.dispatch(t)
	if got := len(fix.fwd.backendQueues[lifetimeBackendID]); got != queued+1 {
		t.Errorf("backend queue holds %d packets, want %d", got, queued+1)
	}
	if got := fix.flow(t).ForwardPackets; got != 1 {
		t.Errorf("detached dispatch attributed %d packets, want the live count unchanged at 1", got)
	}

	// Re-attached manager: the sticky flow is found again and the dispatch is attributed.
	fix.fwd.SetDirectEgress(fix.dem)
	fix.dispatch(t)
	if got := fix.flow(t).ForwardPackets; got != 2 {
		t.Errorf("re-attached dispatch attributed %d packets, want 2", got)
	}

	// Closed but still attached: safe, and attributed from the frozen table.
	if err := fix.dem.Close(); err != nil {
		t.Fatalf("close manager: %v", err)
	}
	fix.dispatch(t)
	if got := fix.flow(t).ForwardPackets; got != 3 {
		t.Errorf("closed-manager dispatch attributed %d packets, want 3", got)
	}
}

// TestReturnObservationOverlapsManagerReplacement is the concurrency control for the reply
// path: real backend returns while administrator-driven disable/reconfigure clears and
// re-publishes the manager. It must finish without a data race, a panic or a refused reply,
// and every reply must be either attributed to the flow or counted as unattributed.
func TestReturnObservationOverlapsManagerReplacement(t *testing.T) {
	fix := newManagerLifetimeFixture(t, 512)
	fix.dispatch(t)

	const rounds = 400
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			fix.fwd.SetPBREnabled(false)
			fix.fwd.SetDirectEgress(nil)
			fix.fwd.SetDirectEgress(fix.dem)
			fix.fwd.SetPBREnabled(true)
		}
	}()
	var returnErr error
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			if err := fix.fwd.RouteBackendToClient(lifetimeBackendID, lifetimeReplyPacket(), lifetimeClientIP); err != nil {
				returnErr = err
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	if returnErr != nil {
		t.Fatalf("backend return refused during manager replacement: %v", returnErr)
	}

	// Conservation: each reply was either attributed to the admitting flow or counted as
	// unattributed, never silently dropped and never attributed twice.
	flow := fix.flow(t)
	if got, want := flow.ReturnMatched+fix.fwd.proxyReturnsUnmatched.Load(), uint64(rounds); got != want {
		t.Errorf("attributed %d + unattributed %d = %d, want %d replies accounted for once",
			flow.ReturnMatched, fix.fwd.proxyReturnsUnmatched.Load(), got, want)
	}
}

// TestDispatchObservationOverlapsManagerReplacement is the concurrency control for the
// dispatch path: real client dispatches while administrator-driven disable/reconfigure
// publishes and clears managers. It must finish without a data race or a panic, and the
// live path must still attribute evidence afterwards.
//
// Each manager is published exactly once. Re-publishing the same manager would rewrite the
// forwarder back-pointer that the sticky-flow lookup reads, which is a different question
// than the helper pointer this control is about.
func TestDispatchObservationOverlapsManagerReplacement(t *testing.T) {
	fix := newManagerLifetimeFixture(t, 64)
	const rounds = 200

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			dem := NewDirectEgressManager(DirectEgressConfig{
				HostWANIP: netip.MustParseAddr("203.0.113.1"),
			}, fix.fwd)
			fix.fwd.SetPBREnabled(false)
			fix.fwd.SetDirectEgress(dem)
			fix.fwd.SetPBREnabled(true)
			fix.fwd.SetDirectEgress(nil)
			_ = dem.Close()
		}
	}()
	var dispatchErr error
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < rounds; i++ {
			err := fix.fwd.RouteClientToBackend(lifetimePeer, lifetimeClientPacket())
			if err != nil && !errors.Is(err, ErrQueueFull) && !errors.Is(err, ErrDirectEgressUnavailable) {
				dispatchErr = err
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	if dispatchErr != nil {
		t.Fatalf("client dispatch failed during manager replacement: %v", dispatchErr)
	}
	// Every dispatch reached the backend queue: the transition drops no packet.
	if got := len(fix.fwd.backendQueues[lifetimeBackendID]); got != rounds {
		t.Errorf("backend queue holds %d packets, want the %d dispatched ones", got, rounds)
	}

	// The live path still attributes evidence once a manager is held again.
	fix.fwd.SetPBREnabled(true)
	fix.fwd.SetDirectEgress(fix.dem)
	var before uint64
	if flow, ok := fix.findFlow(); ok {
		before = flow.ForwardPackets
	}
	fix.dispatch(t)
	if got := fix.flow(t).ForwardPackets; got != before+1 {
		t.Errorf("attributed dispatches = %d, want %d after the replacement storm", got, before+1)
	}
	if got := len(fix.fwd.backendQueues[lifetimeBackendID]); got != rounds+1 {
		t.Errorf("backend queue holds %d packets, want %d", got, rounds+1)
	}
}
