//go:build linux

package forwarder

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// The tests in this file cover the flow-lifetime rule for the INCOMING
// direction. A direct-NAT flow's configured idle timeout is a property of the
// mapping, not of the direction a packet travelled: an incoming WAN reply used
// to refresh the matched flow unconditionally, so a peer could revive a mapping
// whose lifetime had already elapsed and which side spoke first decided the
// path. These tests pin the rule in both directions.
//
// Everything below runs through the authentic components: session registration
// and policy evidence, the real direct-NAT allocator with real kernel host-tuple
// reservations, and the real WAN reply demultiplexer. Only the WAN packet device
// and the return-path sinks are fixtures. The configured timeouts are shortened
// so an idle flow completes its lifetime inside the test; no other timeout,
// retention or selection behaviour is changed.

const (
	issue866ClientPort = 12345
	issue866RemotePort = 53
)

// issue866FlowState is the observable sticky state of one 5-tuple.
type issue866FlowState struct {
	Present  bool
	NATPort  uint16
	LastSeen time.Time
}

func issue866FlowStateOf(h *sessionQuarantineHarness, proto uint8, srcPort, dstPort uint16) issue866FlowState {
	key := FlowKey{
		PeerKey:  h.peerKey,
		Protocol: proto,
		SrcIP:    h.client.As4(),
		DstIP:    h.remote.As4(),
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}
	h.dem.mu.RLock()
	defer h.dem.mu.RUnlock()
	f := h.dem.flows[key]
	if f == nil {
		return issue866FlowState{}
	}
	return issue866FlowState{Present: true, NATPort: f.natPort, LastSeen: f.lastSeen}
}

// issue866PayloadReachedAnySink reports whether any protected payload was
// delivered to any session sink, so a leak fails on the payload itself rather
// than only on an error string.
func issue866PayloadReachedAnySink(h *sessionQuarantineHarness, payload string) bool {
	for _, sink := range h.sinks {
		for _, pkt := range sink.getPackets() {
			if bytes.Contains(pkt, []byte(payload)) {
				return true
			}
		}
	}
	return false
}

// requireTCPDelivered asserts a reply from the flow's remote is DNATed back to
// the originating client tuple and carries the payload.
func (h *sessionQuarantineHarness) requireTCPDelivered(sink *testCaptureReturnPath, natPort, remotePort uint16, payload, what string) {
	h.t.Helper()
	before := len(sink.getPackets())
	reply := buildTestIPv4TCPPacket(h.remote, h.hostWAN, remotePort, natPort, 0x18, []byte(payload))
	if err := h.dem.HandleWANReply(reply); err != nil {
		h.t.Fatalf("%s: legitimate TCP reply refused: %v", what, err)
	}
	pkts := sink.getPackets()
	if len(pkts) != before+1 {
		h.t.Fatalf("%s: expected one delivered TCP reply, got %d", what, len(pkts)-before)
	}
	delivered := pkts[len(pkts)-1]
	if !bytes.Contains(delivered, []byte(payload)) {
		h.t.Fatalf("%s: delivered TCP reply lost its payload", what)
	}
	if got := netip.AddrFrom4([4]byte{delivered[16], delivered[17], delivered[18], delivered[19]}); got != h.client {
		h.t.Fatalf("%s: delivered to %s, want the client %s", what, got, h.client)
	}
}

// TestIssue866ExpiredReplyIsRefusedWithoutResurrection is the deciding
// regression: after the flow's configured idle timeout has elapsed, an incoming
// reply must be refused and retired through the ordinary rules instead of
// refreshing the mapping it found. It fails on the defective source at the
// protected-payload assertion, where the reply is delivered and the flow is
// revived.
func TestIssue866ExpiredReplyIsRefusedWithoutResurrection(t *testing.T) {
	base := freeNATRange(t, 2)
	const flowTimeout = 120 * time.Millisecond
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:    base,
		MaxPort:    base + 1,
		UDPTimeout: flowTimeout,
	})
	quarantine := 4 * flowTimeout
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)
	sink := h.register("session-one")

	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "query-live"); err != nil {
		t.Fatalf("first DIRECT admission failed: %v", err)
	}
	natPort := h.lastNATPort()

	// Boundary, inside the lifetime: this reply is legitimate and extends the flow.
	h.requireDelivered(sink, natPort, issue866RemotePort, "reply-in-time", "reply inside the flow lifetime")

	// Let the mapping go idle beyond its configured timeout in both directions.
	time.Sleep(4 * flowTimeout)

	expired := buildTestIPv4UDPPacket(h.remote, h.hostWAN, issue866RemotePort, natPort, []byte("reply-too-late"))
	dropsBefore := h.dem.DirectDrops()
	h.requireNotDelivered(h.sinks, expired, ErrStaleSessionReply, "reply after the flow idle timeout")
	if got := h.dem.DirectDrops(); got != dropsBefore+1 {
		t.Fatalf("refused reply was not counted once: drops %d -> %d", dropsBefore, got)
	}
	if issue866PayloadReachedAnySink(h, "reply-too-late") {
		t.Fatal("the payload of an expired reply reached a client sink")
	}

	// No resurrection: the mapping is retired, not refreshed, so the sticky
	// lookup that the client's own packets use finds nothing.
	if st := issue866FlowStateOf(h, 17, issue866ClientPort, issue866RemotePort); st.Present {
		t.Fatalf("the expired reply revived its flow (natPort=%d, lastSeen %v ago)", st.NATPort, time.Since(st.LastSeen))
	}
	query := buildTestIPv4UDPPacket(h.client, h.remote, issue866ClientPort, issue866RemotePort, []byte("query-live"))
	if choice, found := h.dem.LookupFlow(h.peerKey, query); found {
		t.Fatalf("sticky lookup after the refusal returned %v, want no flow", choice)
	}

	// Retirement used the existing rules: the tuple stays attributable through
	// its quarantine window and keeps its kernel ownership, and no tracking entry
	// survives.
	retired := h.bindingState(natPort, issue866RemotePort)
	if !retired.found || retired.active {
		t.Fatalf("expired flow's binding was not retired: %+v", retired)
	}
	if !retired.quarantined || retired.releasedAt.IsZero() {
		t.Fatalf("retired binding is not in quarantine: %+v", retired)
	}
	if retired.epoch == 0 || retired.portEpoch != retired.epoch {
		t.Fatalf("retirement lost the tuple's epoch: %+v", retired)
	}
	h.dem.mu.RLock()
	_, entryThere := h.dem.inboundNAT[inboundKey{protocol: 17, natPort: natPort}]
	h.dem.mu.RUnlock()
	if entryThere {
		t.Fatalf("retired flow left its inbound NAT entry for port %d behind", natPort)
	}
	if got := h.dem.HostReservationCount(); got != 1 {
		t.Fatalf("retirement dropped kernel ownership before the quarantine elapsed: reservations=%d, want 1", got)
	}

	// The client's next packet is a new incarnation: a new port and epoch, with
	// the retired tuple still refusing the old reply and not disturbing the owner.
	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "query-resumed"); err != nil {
		t.Fatalf("client resume after retirement failed: %v", err)
	}
	resumedPort := h.lastNATPort()
	if resumedPort == natPort {
		t.Fatalf("the resumed tuple reused the retired NAT port %d", natPort)
	}
	h.requireNotDelivered(h.sinks, expired, ErrStaleSessionReply, "old reply after the client resumed")
	h.requireDelivered(sink, resumedPort, issue866RemotePort, "reply-new-incarnation", "new incarnation's reply")
	if issue866PayloadReachedAnySink(h, "reply-too-late") {
		t.Fatal("the retired flow's reply payload reached a client sink after replacement")
	}
}

// TestIssue866IncomingReplyRefusedAfterReplacementKeepsCurrentOwner proves the
// refusal path cannot damage the tuple's current owner: an expired flow's port is
// quarantined, a replacement incarnation gets a fresh port, and the stale reply
// for the old port is refused while the live incarnation keeps working.
func TestIssue866IncomingReplyRefusedAfterReplacementKeepsCurrentOwner(t *testing.T) {
	base := freeNATRange(t, 2)
	const flowTimeout = 120 * time.Millisecond
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:    base,
		MaxPort:    base + 1,
		UDPTimeout: flowTimeout,
	})
	quarantine := 6 * flowTimeout
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)
	sink := h.register("session-one")

	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "first-incarnation"); err != nil {
		t.Fatalf("first incarnation admission failed: %v", err)
	}
	retiredPort := h.lastNATPort()
	h.requireDelivered(sink, retiredPort, issue866RemotePort, "first-reply", "first incarnation reply")

	time.Sleep(4 * flowTimeout)

	// The expired incarnation's reply retires the mapping and is refused.
	stale := buildTestIPv4UDPPacket(h.remote, h.hostWAN, issue866RemotePort, retiredPort, []byte("stale-payload"))
	h.requireNotDelivered(h.sinks, stale, ErrStaleSessionReply, "expired incarnation reply")

	// The tuple is retired in place: quarantined, inactive, epoch preserved.
	retired := h.bindingState(retiredPort, issue866RemotePort)
	if !retired.found || retired.active || retired.portEpoch == 0 {
		t.Fatalf("expired incarnation's tuple was not retired in place: %+v", retired)
	}

	// The same 5-tuple resumes on a replacement incarnation with a fresh port.
	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "second-incarnation"); err != nil {
		t.Fatalf("replacement incarnation admission failed: %v", err)
	}
	currentPort := h.lastNATPort()
	if currentPort == retiredPort {
		t.Fatalf("replacement incarnation reused the quarantined port %d", retiredPort)
	}
	live := h.bindingState(currentPort, issue866RemotePort)
	if !live.found || !live.active || live.sessionID != "session-one" {
		t.Fatalf("replacement incarnation's binding is not the live owner: %+v", live)
	}
	if live.portEpoch == 0 || live.epoch != live.portEpoch {
		t.Fatalf("replacement incarnation's binding does not own its port epoch: %+v", live)
	}
	// The stale reply is refused again and must not touch the current owner.
	h.requireNotDelivered(h.sinks, stale, ErrStaleSessionReply, "stale reply after replacement")
	after := h.bindingState(currentPort, issue866RemotePort)
	if !after.active || after.sessionID != live.sessionID || after.epoch != live.epoch || after.portEpoch != live.portEpoch {
		t.Fatalf("stale reply rewrote the current owner's binding: before=%+v after=%+v", live, after)
	}
	if st := issue866FlowStateOf(h, 17, issue866ClientPort, issue866RemotePort); !st.Present || st.NATPort != currentPort {
		t.Fatalf("stale reply disturbed the current incarnation's flow: %+v", st)
	}
	if issue866PayloadReachedAnySink(h, "stale-payload") {
		t.Fatal("the stale reply's payload reached a client sink")
	}
	h.requireDelivered(sink, currentPort, issue866RemotePort, "second-reply", "replacement incarnation reply")
}

// TestIssue866ReverseTrafficExtendsLiveFlow proves the refusal is not a blanket
// expiry check: replies that arrive inside the lifetime still extend a live flow,
// so a peer that keeps sending holds the mapping open and the client stays on one
// NAT tuple.
func TestIssue866ReverseTrafficExtendsLiveFlow(t *testing.T) {
	base := freeNATRange(t, 1)
	const flowTimeout = 200 * time.Millisecond
	const keepalive = flowTimeout / 4
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:    base,
		MaxPort:    base,
		UDPTimeout: flowTimeout,
	})
	quarantine := 4 * flowTimeout
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)
	sink := h.register("session-one")

	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "query"); err != nil {
		t.Fatalf("DIRECT admission failed: %v", err)
	}
	natPort := h.lastNATPort()

	// The client sends nothing more. Five replies, each well inside the
	// lifetime, outlast one full timeout measured from the client's own packet.
	const pushes = 5
	for i := 0; i < pushes; i++ {
		time.Sleep(keepalive)
		h.requireDelivered(sink, natPort, issue866RemotePort, "server-push", "reverse traffic inside the lifetime")
	}
	if elapsed := time.Duration(pushes) * keepalive; elapsed <= flowTimeout {
		t.Fatalf("precondition: reverse traffic (%v) did not outlast the timeout (%v)", elapsed, flowTimeout)
	}

	st := issue866FlowStateOf(h, 17, issue866ClientPort, issue866RemotePort)
	if !st.Present || st.NATPort != natPort {
		t.Fatalf("maintained flow was not kept alive by its replies: %+v", st)
	}
	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "query-after-push"); err != nil {
		t.Fatalf("client packet on the maintained flow failed: %v", err)
	}
	if got := h.lastNATPort(); got != natPort {
		t.Fatalf("maintained flow moved to a new NAT port: %d, want %d", got, natPort)
	}
	h.requireDelivered(sink, natPort, issue866RemotePort, "reply-after-push", "reply after the client resumed")
}

// TestIssue866ActiveTrafficStableAfterReclassification is the control for the
// expiry rule: an established flow keeps its decision and tuple when the address
// classification that chose DIRECT is withdrawn, so a changed decision input
// cannot move live traffic. A tuple decided after the withdrawal has no
// classification and fails closed to PROXY.
func TestIssue866ActiveTrafficStableAfterReclassification(t *testing.T) {
	base := freeNATRange(t, 2)
	const flowTimeout = 200 * time.Millisecond
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:    base,
		MaxPort:    base + 1,
		UDPTimeout: flowTimeout,
	})
	quarantine := 4 * flowTimeout
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)
	sink := h.register("session-one")

	if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "classified-query"); err != nil {
		t.Fatalf("DIRECT admission of the classified destination failed: %v", err)
	}
	natPort := h.lastNATPort()
	h.requireDelivered(sink, natPort, issue866RemotePort, "classified-reply", "reply on the classified destination")

	// The classification that justified DIRECT is withdrawn; the live flow must not care.
	h.fwd.SetDestinationClassifier(nil)

	// Failure-only diagnostics: the state this case depends on is recorded around each real
	// dispatch and reply, and printed only if the case fails. Nothing here changes a flow, a
	// budget or an assertion; the samples are read through the flow table's own lock.
	var issue866Samples []string
	recordIssue866 := func(phase string) {
		state := issue866FlowStateOf(h, 17, issue866ClientPort, issue866RemotePort)
		issue866Samples = append(issue866Samples, fmt.Sprintf(
			"phase=%s at=%s flow_present=%v nat_port=%d stored_age=%s",
			phase, time.Now().Format("15:04:05.000000"), state.Present, state.NATPort,
			time.Since(state.LastSeen).Round(time.Microsecond)))
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, sample := range issue866Samples {
			t.Log(sample)
		}
	})

	for i := 0; i < 2; i++ {
		time.Sleep(flowTimeout / 4)
		recordIssue866(fmt.Sprintf("before_dispatch_%d", i))
		if err := h.dispatchUDP(issue866ClientPort, issue866RemotePort, "reclassified-query"); err != nil {
			t.Fatalf("client packet on the established flow failed: %v", err)
		}
		recordIssue866(fmt.Sprintf("after_dispatch_%d", i))
		if got := h.lastNATPort(); got != natPort {
			t.Fatalf("live flow changed NAT port after reclassification: %d, want %d", got, natPort)
		}
		recordIssue866(fmt.Sprintf("before_reply_%d", i))
		h.requireDelivered(sink, natPort, issue866RemotePort, "reclassified-reply", "reply on the established flow")
	}

	// Fail-closed selection is preserved for a tuple decided with no classification.
	wanBefore := len(h.wanDev.getPackets())
	if err := h.dispatchUDP(issue866ClientPort+1, issue866RemotePort, "uncovered-new-tuple"); err != nil {
		t.Fatalf("dispatch of an uncovered tuple failed: %v", err)
	}
	if got := len(h.wanDev.getPackets()); got != wanBefore {
		t.Fatalf("an uncovered tuple egressed directly: %d new WAN packet(s)", got-wanBefore)
	}
	fresh := buildTestIPv4UDPPacket(h.client, h.remote, issue866ClientPort+1, issue866RemotePort, []byte("uncovered-new-tuple"))
	if choice, found := h.dem.LookupFlow(h.peerKey, fresh); !found || choice != EgressChoiceProxy {
		t.Fatalf("uncovered tuple decision: got %v (found=%v), want PROXY", choice, found)
	}
}

// TestIssue866TCPReplyLifetimeAndCloseWindow covers TCP: the configured connect
// lifetime applies to replies in both directions, while the deliberately shorter
// post-close window is untouched by this correction.
func TestIssue866TCPReplyLifetimeAndCloseWindow(t *testing.T) {
	base := freeNATRange(t, 2)
	const tcpTimeout = 150 * time.Millisecond
	h := newDirectEgressHarness(t, DirectEgressConfig{
		MinPort:    base,
		MaxPort:    base + 1,
		TCPTimeout: tcpTimeout,
	})
	quarantine := 4 * tcpTimeout
	h.dem.SetPortCooldown(quarantine)
	h.dem.SetQuarantineDurations(quarantine, quarantine)
	sink := h.register("session-one")

	const remotePort = 80
	syn := buildTestIPv4TCPPacket(h.client, h.remote, issue866ClientPort, remotePort, 0x02, nil)
	if err := h.fwd.RouteClientToBackend(h.peerKey, syn); err != nil {
		t.Fatalf("TCP DIRECT admission failed: %v", err)
	}
	natPort := h.lastNATPort()
	h.requireTCPDelivered(sink, natPort, remotePort, "tcp-reply-live", "TCP reply inside the lifetime")

	// Idle past the configured TCP lifetime: the reply is refused, not delivered.
	time.Sleep(3 * tcpTimeout)
	late := buildTestIPv4TCPPacket(h.remote, h.hostWAN, remotePort, natPort, 0x18, []byte("tcp-reply-late"))
	h.requireNotDelivered(h.sinks, late, ErrStaleSessionReply, "TCP reply after the flow idle timeout")
	if issue866PayloadReachedAnySink(h, "tcp-reply-late") {
		t.Fatal("the payload of an expired TCP reply reached a client sink")
	}

	// A closed flow keeps the existing 5 s close window: the configured TCP
	// lifetime has elapsed, but the FIN window has not, so the reply is still
	// admitted. This arm pins that pre-existing rule as unchanged.
	closedPort := uint16(issue866ClientPort + 1)
	closedSYN := buildTestIPv4TCPPacket(h.client, h.remote, closedPort, remotePort, 0x02, nil)
	if err := h.fwd.RouteClientToBackend(h.peerKey, closedSYN); err != nil {
		t.Fatalf("closed-flow DIRECT admission failed: %v", err)
	}
	closedNATPort := h.lastNATPort()
	fin := buildTestIPv4TCPPacket(h.client, h.remote, closedPort, remotePort, 0x01, nil)
	if err := h.fwd.RouteClientToBackend(h.peerKey, fin); err != nil {
		t.Fatalf("client FIN was refused: %v", err)
	}
	if st := issue866FlowStateOf(h, 6, closedPort, remotePort); !st.Present || st.NATPort != closedNATPort {
		t.Fatalf("closed flow was not tracked on its tuple: %+v", st)
	}
	time.Sleep(3 * tcpTimeout)
	postClose := buildTestIPv4TCPPacket(h.remote, h.hostWAN, remotePort, closedNATPort, 0x18, []byte("tcp-reply-post-close"))
	before := len(sink.getPackets())
	if err := h.dem.HandleWANReply(postClose); err != nil {
		t.Fatalf("reply inside the post-close window was refused: %v", err)
	}
	if got := len(sink.getPackets()); got != before+1 {
		t.Fatalf("reply inside the post-close window was not delivered: %d packet(s)", got-before)
	}
}
