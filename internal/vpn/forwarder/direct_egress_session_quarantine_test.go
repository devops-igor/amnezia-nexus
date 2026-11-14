//go:build linux

package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// The tests in this file cover the session-isolation rule for a direct-NAT
// tuple that a retired session previously owned. A replacement session of the
// SAME peer is a different authenticated session, so the retired binding's
// quarantine window must refuse it exactly like any other rebinder: otherwise
// the retired flow's in-flight replies are relabelled with the replacement
// session and delivered to it.
//
// Everything below runs through the authentic components: Forwarder session
// registration and replacement (which retires NAT state through PurgePeer), the
// real direct-NAT allocator with real kernel host-tuple reservations, and the
// real WAN reply demultiplexer with the real ReturnPath/generation fence. Only
// the WAN packet device and the return-path sinks are fixtures.

type sessionQuarantineHarness struct {
	t       *testing.T
	fwd     *Forwarder
	dem     *DirectEgressManager
	wanDev  *mockPacketDev
	cache   *testRouteCache
	hostWAN netip.Addr
	client  netip.Addr
	remote  netip.Addr
	peerKey string
	sinks   map[string]*testCaptureReturnPath
}

func newSessionQuarantineHarness(t *testing.T, minPort, maxPort uint16) *sessionQuarantineHarness {
	return newDirectEgressHarness(t, DirectEgressConfig{MinPort: minPort, MaxPort: maxPort})
}

// newDirectEgressHarness builds the same authentic dispatcher fixture with an
// explicit manager configuration, so other direct-egress regressions can drive a
// configured bound instead of this file's NAT pool.
func newDirectEgressHarness(t *testing.T, cfg DirectEgressConfig) *sessionQuarantineHarness {
	t.Helper()
	h := &sessionQuarantineHarness{
		t:       t,
		hostWAN: netip.MustParseAddr("203.0.113.1"),
		client:  netip.MustParseAddr("10.100.0.2"),
		remote:  netip.MustParseAddr("1.1.1.1"),
		peerKey: "quarantine-peer",
		sinks:   make(map[string]*testCaptureReturnPath),
	}
	h.wanDev = newMockPacketDev()
	cfg.HostWANIP = h.hostWAN
	cfg.WANDevice = h.wanDev
	h.fwd = NewForwarder(nil, "10.100.0.0/16", 8)
	h.dem = NewDirectEgressManager(cfg, h.fwd)
	h.fwd.SetDirectEgress(h.dem)
	h.fwd.SetPBREnabled(true)
	h.cache = newTestRouteCache()
	h.fwd.SetRouteCache(h.cache)
	t.Cleanup(func() {
		h.fwd.UnregisterSession(h.peerKey)
		_ = h.dem.Close()
	})
	return h
}

// register starts one authenticated session for the shared peer and returns its
// reply sink. Calling it a second time is the real replacement path: the
// forwarder purges the replaced route's direct-NAT state before installing the
// new route with the next registration generation.
func (h *sessionQuarantineHarness) register(sessionID string) *testCaptureReturnPath {
	h.t.Helper()
	sink := newTestCaptureReturnPath()
	h.sinks[sessionID] = sink
	h.fwd.RegisterSessionWithReturnPath(sessionID, "connection-"+sessionID, h.peerKey, h.client.String(), 1, sink.path)
	// The retired route's cache scope is released with it; the replacement
	// session observes fresh DIRECT evidence for the same remote.
	h.cache.Set(sessionID, h.remote, policy.Direct)
	return sink
}

// dispatchUDP sends one client UDP packet through the authentic dispatcher.
func (h *sessionQuarantineHarness) dispatchUDP(srcPort, dstPort uint16, payload string) error {
	h.t.Helper()
	pkt := buildTestIPv4UDPPacket(h.client, h.remote, srcPort, dstPort, []byte(payload))
	return h.fwd.RouteClientToBackend(h.peerKey, pkt)
}

// lastNATPort returns the SNAT source port of the most recent WAN packet, which
// is the direct-NAT port the allocator committed.
func (h *sessionQuarantineHarness) lastNATPort() uint16 {
	h.t.Helper()
	pkts := h.wanDev.getPackets()
	if len(pkts) == 0 {
		h.t.Fatal("no direct-WAN packet was written, so no NAT port was allocated")
	}
	return binary.BigEndian.Uint16(pkts[len(pkts)-1][20:22])
}

// requireDelivered asserts a reply from the flow's remote is DNATed back to the
// originating client tuple of the given session and carries the payload.
func (h *sessionQuarantineHarness) requireDelivered(sink *testCaptureReturnPath, natPort, remotePort uint16, payload, what string) {
	h.t.Helper()
	before := len(sink.getPackets())
	reply := buildTestIPv4UDPPacket(h.remote, h.hostWAN, remotePort, natPort, []byte(payload))
	if err := h.dem.HandleWANReply(reply); err != nil {
		h.t.Fatalf("%s: legitimate direct reply refused: %v", what, err)
	}
	pkts := sink.getPackets()
	if len(pkts) != before+1 {
		h.t.Fatalf("%s: expected one delivered reply, got %d", what, len(pkts)-before)
	}
	p := pkts[len(pkts)-1]
	if got := string(p[28:]); got != payload {
		h.t.Fatalf("%s: delivered payload = %q, want %q", what, got, payload)
	}
	if got := binary.BigEndian.Uint16(p[22:24]); got != 12345 {
		h.t.Fatalf("%s: delivered to client port %d, want 12345", what, got)
	}
	if got := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}); got != h.client {
		h.t.Fatalf("%s: delivered to client address %s, want %s", what, got, h.client)
	}
}

// requireNotDelivered asserts a WAN reply is refused and reaches no peer sink,
// naming the session that received it if the fence failed.
func (h *sessionQuarantineHarness) requireNotDelivered(sinks map[string]*testCaptureReturnPath, reply []byte, want error, what string) error {
	h.t.Helper()
	names := make([]string, 0, len(sinks))
	for name := range sinks {
		names = append(names, name)
	}
	before := make(map[string]int, len(sinks))
	for name, s := range sinks {
		before[name] = len(s.getPackets())
	}
	err := h.dem.HandleWANReply(reply)
	for _, name := range names {
		if got := len(sinks[name].getPackets()); got != before[name] {
			h.t.Fatalf("%s: %d reply packet(s) were delivered to session %q", what, got-before[name], name)
		}
	}
	if want != nil && !errors.Is(err, want) {
		h.t.Fatalf("%s: want %v, got %v", what, want, err)
	}
	return err
}

// natBindingState is the observable ownership of one (port, remote) NAT tuple.
type natBindingState struct {
	found       bool
	active      bool
	sessionID   string
	epoch       uint64
	releasedAt  time.Time
	portEpoch   uint64
	quarantined bool
	used        bool
}

func (h *sessionQuarantineHarness) bindingState(natPort, remotePort uint16) natBindingState {
	h.dem.mu.RLock()
	defer h.dem.mu.RUnlock()
	var st natBindingState
	if b := h.dem.remoteBindings[remoteBindingKey{protocol: 17, natPort: natPort, remoteIP: h.remote, remotePort: remotePort}]; b != nil {
		st.found = true
		st.active = b.active
		st.sessionID = b.sessionID
		st.epoch = b.epoch
		st.releasedAt = b.releasedAt
	}
	st.portEpoch = h.dem.portEpoch[natPort]
	_, st.quarantined = h.dem.quarantinedPorts[natPort]
	st.used = h.dem.usedPorts[natPort]
	return st
}

// TestDirectEgressRetiredBindingQuarantineBlocksSamePeerReplacement is the
// cross-session confidentiality regression: one-port NAT pool, two sequential
// authenticated sessions of the same peer, one remote endpoint and a reply that
// the retired session would have received. The replacement session must not be
// able to rebind the retired tuple, and the delayed reply must never reach it.
func TestDirectEgressRetiredBindingQuarantineBlocksSamePeerReplacement(t *testing.T) {
	base := freeNATRange(t, 1)
	h := newSessionQuarantineHarness(t, base, base)
	quarantine := 300 * time.Millisecond
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)

	first := h.register("session-one")
	if err := h.dispatchUDP(12345, 53, "session-one-query"); err != nil {
		t.Fatalf("first session could not establish direct egress: %v", err)
	}
	natPort := h.lastNATPort()
	if natPort != base {
		t.Fatalf("allocator used port %d, want the only pool port %d", natPort, base)
	}

	// Positive control: the live session's own reply is delivered.
	h.requireDelivered(first, natPort, 53, "session-one-reply", "live session reply")

	live := h.bindingState(natPort, 53)
	if !live.found || !live.active || live.sessionID != "session-one" || !live.used {
		t.Fatalf("precondition: want an active session-one binding on %d, got %+v", natPort, live)
	}

	// Replacement through the authentic forwarder path (PurgePeer of the
	// retired route happens inside registration).
	h.register("session-two")
	if gen, sid, ok := h.fwd.ActivePeerGeneration(h.peerKey); !ok || sid != "session-two" || gen == 0 {
		t.Fatalf("precondition: replacement session is not the active route (gen=%d sid=%q ok=%v)", gen, sid, ok)
	}

	retired := h.bindingState(natPort, 53)
	if !retired.found {
		t.Fatalf("precondition: retired binding for port %d disappeared instead of being quarantined", natPort)
	}
	if retired.active {
		t.Fatalf("precondition: retired binding still active for session %q", retired.sessionID)
	}
	if retired.sessionID != "session-one" || retired.epoch == 0 {
		t.Fatalf("precondition: retired binding lost its owner (sessionID=%q epoch=%d)", retired.sessionID, retired.epoch)
	}
	if retired.releasedAt.IsZero() || !retired.quarantined {
		t.Fatalf("precondition: retired binding is not in quarantine (releasedAt=%v quarantined=%v)", retired.releasedAt, retired.quarantined)
	}
	if retired.used {
		t.Fatalf("precondition: port %d is still marked in use", natPort)
	}
	if got := h.dem.HostReservationCount(); got != 1 {
		t.Fatalf("precondition: retired binding released its kernel tuple, reservations=%d", got)
	}
	if got := h.dem.RemoteBindingCount(); got != 1 {
		t.Fatalf("precondition: want exactly one retained binding, got %d", got)
	}

	wanBefore := len(h.wanDev.getPackets())
	replaceErr := h.dispatchUDP(12345, 53, "session-two-query")

	// The harm assertion comes first so a failing run reports the leak itself.
	delayed := buildTestIPv4UDPPacket(h.remote, h.hostWAN, 53, natPort, []byte("session-one-delayed"))
	h.requireNotDelivered(h.sinks, delayed, ErrStaleSessionReply,
		"delayed reply for the retired session's tuple")

	if !errors.Is(replaceErr, ErrNATPortExhaustion) {
		t.Fatalf("replacement session rebound the retired tuple: got %v, want ErrNATPortExhaustion", replaceErr)
	}
	if got := len(h.wanDev.getPackets()); got != wanBefore {
		t.Fatalf("refused replacement flow still wrote %d WAN packet(s)", got-wanBefore)
	}

	after := h.bindingState(natPort, 53)
	if after.active || after.sessionID != retired.sessionID || after.portEpoch != retired.portEpoch || after.epoch != retired.epoch {
		t.Fatalf("refused reuse overwrote the retired binding ownership: before=%+v after=%+v", retired, after)
	}
	if got := len(first.getPackets()); got != 1 {
		t.Fatalf("retired session received %d replies, want only its own 1", got)
	}
}

// TestDirectEgressRetiredBindingQuarantineKeepsSafeReplacementWorking proves the
// correction is not a blanket denial: when the pool has another safe port the
// replacement session establishes DIRECT egress on it, its own replies are
// delivered, and the retired tuple still refuses the old flow's reply.
func TestDirectEgressRetiredBindingQuarantineKeepsSafeReplacementWorking(t *testing.T) {
	base := freeNATRange(t, 2)
	h := newSessionQuarantineHarness(t, base, base+1)
	quarantine := 300 * time.Millisecond
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)

	first := h.register("session-one")
	if err := h.dispatchUDP(12345, 53, "session-one-query"); err != nil {
		t.Fatalf("first session could not establish direct egress: %v", err)
	}
	retiredPort := h.lastNATPort()
	h.requireDelivered(first, retiredPort, 53, "session-one-reply", "live session reply")

	second := h.register("session-two")
	if err := h.dispatchUDP(12345, 53, "session-two-query"); err != nil {
		t.Fatalf("replacement session could not use a safe port: %v", err)
	}
	newPort := h.lastNATPort()
	if newPort == retiredPort {
		t.Fatalf("replacement session reused the quarantined port %d", retiredPort)
	}

	// The retired tuple keeps refusing the old flow's reply.
	delayed := buildTestIPv4UDPPacket(h.remote, h.hostWAN, 53, retiredPort, []byte("session-one-delayed"))
	h.requireNotDelivered(h.sinks, delayed, ErrStaleSessionReply,
		"delayed reply for the retired tuple")

	// The replacement session's own traffic still works end to end.
	h.requireDelivered(second, newPort, 53, "session-two-reply", "replacement session reply")
}

// TestDirectEgressRetiredBindingQuarantineExpiresWithTheWindow proves the refusal
// is bounded by the quarantine window: once it elapses the same tuple is a
// legitimate allocation again, with a fresh epoch and a working reply path.
func TestDirectEgressRetiredBindingQuarantineExpiresWithTheWindow(t *testing.T) {
	base := freeNATRange(t, 1)
	h := newSessionQuarantineHarness(t, base, base)
	quarantine := 150 * time.Millisecond
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)

	first := h.register("session-one")
	if err := h.dispatchUDP(12345, 53, "session-one-query"); err != nil {
		t.Fatalf("first session could not establish direct egress: %v", err)
	}
	natPort := h.lastNATPort()
	h.requireDelivered(first, natPort, 53, "session-one-reply", "live session reply")

	second := h.register("session-two")
	if err := h.dispatchUDP(12345, 53, "session-two-query"); !errors.Is(err, ErrNATPortExhaustion) {
		t.Fatalf("reuse inside the quarantine window: got %v, want ErrNATPortExhaustion", err)
	}

	// No manual sweep: the allocator itself observes that both the port
	// cooldown and the binding's quarantine window have elapsed.
	time.Sleep(2 * quarantine)

	if err := h.dispatchUDP(12345, 53, "session-two-query"); err != nil {
		t.Fatalf("reuse after the quarantine window was still refused: %v", err)
	}
	if got := h.lastNATPort(); got != natPort {
		t.Fatalf("expected the expired quarantine to free port %d, got %d", natPort, got)
	}
	reused := h.bindingState(natPort, 53)
	if !reused.found || !reused.active || reused.sessionID != "session-two" {
		t.Fatalf("want an active session-two binding after reuse, got %+v", reused)
	}
	if reused.portEpoch <= 1 {
		t.Fatalf("reused binding epoch %d did not advance past the retired flow", reused.portEpoch)
	}
	h.requireDelivered(second, natPort, 53, "session-two-reply", "reused tuple reply")
}
