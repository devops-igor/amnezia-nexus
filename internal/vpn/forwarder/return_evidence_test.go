package forwarder

import (
	"net/netip"
	"testing"
	"time"
)

// Real producer controls for the PROXY return direction (issue #861, R18).
//
// Each case drives a client packet through RouteClientToBackend so a flow is decided and
// recorded, then hands a genuine backend reply to RouteBackendToClient. The observations
// under test come from that return path and the client writer, never from a test that
// sets a counter.

// proxyReturnFixture builds a policy-active forwarder with a captured client return path.
func proxyReturnFixture(t *testing.T, bufSize int) (*Forwarder, *testCaptureReturnPath, string, string) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", bufSize)
	fwd.SetPBREnabled(true)
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:    netip.MustParseAddr("203.0.113.1"),
		GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
		WANDevice:    newMockPacketDev(),
	}, fwd)
	fwd.SetDirectEgress(dem)
	fwd.SetRouteCache(newTestRouteCache())
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("sess-return", "conn-1", "peer-return", "10.100.0.7", 31, capPath.path)
	fwd.StartPumps(t.Context())
	t.Cleanup(fwd.StopPumps)
	return fwd, capPath, "peer-return", "sess-return"
}

// proxyReply builds the backend's answer to the client's own packet: remote -> client,
// with the client's port as the destination.
func proxyReply(remote string, remotePort, clientPort uint16, payload []byte) []byte {
	return buildTestIPv4TCPPacket(
		netip.MustParseAddr(remote), netip.MustParseAddr("10.100.0.7"),
		remotePort, clientPort, 0x12, payload)
}

func returnEvidenceOf(t *testing.T, fwd *Forwarder, sessionID, remote string, remotePort uint16) SessionFlow {
	t.Helper()
	list := fwd.DirectEgress().SnapshotSessionFlows(sessionID, 0, time.Now(), 0)
	for _, flow := range list.Flows {
		if flow.DstIP.String() == remote && flow.DstPort == remotePort {
			return flow
		}
	}
	t.Fatalf("no flow for %s:%d in %+v", remote, remotePort, list.Flows)
	return SessionFlow{}
}

func waitReturn(t *testing.T, fwd *Forwarder, sessionID, remote string, remotePort uint16, done func(SessionFlow) bool) SessionFlow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		flow := returnEvidenceOf(t, fwd, sessionID, remote, remotePort)
		if done(flow) {
			return flow
		}
		time.Sleep(2 * time.Millisecond)
	}
	return returnEvidenceOf(t, fwd, sessionID, remote, remotePort)
}

// TestProxyReturnObservedChain is the positive control: a real reply reverses to the flow
// that admitted the request, is admitted to the client queue and is handed to the client
// writer. All three are visible and distinct.
func TestProxyReturnObservedChain(t *testing.T) {
	fwd, capPath, peer, sessionID := proxyReturnFixture(t, 8)
	const remote, remotePort = "5.5.5.5", uint16(443)

	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
		44000, remotePort, 0x02, nil)); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
	if err := fwd.RouteBackendToClient(31, proxyReply(remote, remotePort, 44000, []byte("answer")), "10.100.0.7"); err != nil {
		t.Fatalf("backend return refused: %v", err)
	}

	flow := waitReturn(t, fwd, sessionID, remote, remotePort, func(f SessionFlow) bool { return f.ReturnDelivered > 0 })
	if !flow.PROXYReturnMeasured {
		t.Fatal("a matched reply left the flow reporting not measured")
	}
	if flow.ReturnMatched != 1 || flow.ReturnAdmitted != 1 || flow.ReturnDelivered != 1 {
		t.Errorf("return chain = matched %d / admitted %d / delivered %d, want 1/1/1",
			flow.ReturnMatched, flow.ReturnAdmitted, flow.ReturnDelivered)
	}
	if flow.ReturnFailed != 0 || flow.ReturnFailure != "" {
		t.Errorf("return failed = %d (%q), want none", flow.ReturnFailed, flow.ReturnFailure)
	}
	if got := len(capPath.getPackets()); got != 1 {
		t.Errorf("client writer received %d packets, want the reply once", got)
	}
}

// TestProxyReturnRefusalsAreNotMatches covers refusals that must not fabricate flow
// evidence: a wrong backend, a malformed reply, and a tuple no recorded flow owns.
func TestProxyReturnRefusalsAreNotMatches(t *testing.T) {
	cases := []struct {
		name  string
		reply func() []byte
		from  int64
	}{
		{"WrongBackend", func() []byte { return proxyReply("5.5.5.5", 443, 44000, []byte("x")) }, 32},
		{"MalformedReply", func() []byte { return []byte{0x45, 0x00} }, 31},
		{"UnmatchedTuple", func() []byte {
			return buildTestIPv4TCPPacket(netip.MustParseAddr("7.7.7.7"), netip.MustParseAddr("10.100.0.7"), 999, 44000, 0x12, nil)
		}, 31},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
			if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
				netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr("5.5.5.5"),
				44000, 443, 0x02, nil)); err != nil {
				t.Fatalf("client dispatch: %v", err)
			}
			before := int(fwd.proxyReturnsUnmatched.Load())
			_ = fwd.RouteBackendToClient(tc.from, tc.reply(), "10.100.0.7")

			flow := returnEvidenceOf(t, fwd, sessionID, "5.5.5.5", 443)
			if flow.ReturnMatched != 0 || flow.ReturnAdmitted != 0 || flow.ReturnDelivered != 0 {
				t.Errorf("unattributable reply produced flow evidence: matched %d / admitted %d / delivered %d",
					flow.ReturnMatched, flow.ReturnAdmitted, flow.ReturnDelivered)
			}
			if flow.PROXYReturnMeasured {
				t.Error("an unattributable reply left the flow claiming a measurement")
			}
			if tc.name == "UnmatchedTuple" && int(fwd.proxyReturnsUnmatched.Load()) <= before {
				t.Error("unattributed reply was not counted for the operator")
			}
		})
	}
}

// TestProxyReturnQueueFullStopsAtTheQueue proves admission is a separate fact: a matched
// reply that finds the client queue full states arrival and the refusal, never delivery.
func TestProxyReturnQueueFullStopsAtTheQueue(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 1)
	fwd.StopPumps()

	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr("6.6.6.6"),
		44000, 8080, 0x02, nil)); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
	reply := proxyReply("6.6.6.6", 8080, 44000, []byte("a"))
	if err := fwd.RouteBackendToClient(31, reply, "10.100.0.7"); err != nil {
		t.Fatalf("first return refused unexpectedly: %v", err)
	}
	if err := fwd.RouteBackendToClient(31, proxyReply("6.6.6.6", 8080, 44000, []byte("b")), "10.100.0.7"); err != ErrQueueFull {
		t.Fatalf("second return = %v, want ErrQueueFull so the refusal is real", err)
	}

	flow := returnEvidenceOf(t, fwd, sessionID, "6.6.6.6", 8080)
	if flow.ReturnMatched != 2 {
		t.Errorf("matched = %d, want both replies attributed to the flow", flow.ReturnMatched)
	}
	if flow.ReturnAdmitted != 1 {
		t.Errorf("admitted = %d, want only the reply that fit", flow.ReturnAdmitted)
	}
	if flow.ReturnDropped != 1 || flow.ReturnFailure != FlowReturnQueueFull {
		t.Errorf("dropped = %d (%q), want 1 with %q", flow.ReturnDropped, flow.ReturnFailure, FlowReturnQueueFull)
	}
	if flow.ReturnDelivered != 0 {
		t.Errorf("delivered = %d, want 0 with the pump stopped", flow.ReturnDelivered)
	}
}

// TestProxyReturnStaleReplyIsNotCreditedToTheSuccessor is the wrong-owner control: the
// reply is admitted before a same-session rekey, then handed off after it. The new
// incarnation must not inherit the retired flow's return evidence.
func TestProxyReturnStaleReplyIsNotCreditedToTheSuccessor(t *testing.T) {
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	const remote, remotePort = "8.8.8.8", uint16(53)

	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
		44000, remotePort, 0x02, nil)); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
	if err := fwd.RouteBackendToClient(31, proxyReply(remote, remotePort, 44000, nil), "10.100.0.7"); err != nil {
		t.Fatalf("return refused: %v", err)
	}
	old := returnEvidenceOf(t, fwd, sessionID, remote, remotePort)
	if old.ReturnMatched != 1 || old.ReturnAdmitted != 1 {
		t.Fatalf("pre-replacement chain = matched %d / admitted %d, want 1/1", old.ReturnMatched, old.ReturnAdmitted)
	}

	fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", peer, "10.100.0.7", 31, newTestCaptureReturnPath().path)
	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
		44001, remotePort, 0x02, nil)); err != nil {
		t.Fatalf("successor dispatch: %v", err)
	}
	// A reply for the OLD client port arrives after the replacement.
	_ = fwd.RouteBackendToClient(31, proxyReply(remote, remotePort, 44000, nil), "10.100.0.7")

	successor := returnEvidenceOf(t, fwd, sessionID, remote, remotePort)
	if successor.ReturnMatched != 0 || successor.ReturnAdmitted != 0 {
		t.Errorf("successor inherited the retired flow's return evidence: matched %d / admitted %d",
			successor.ReturnMatched, successor.ReturnAdmitted)
	}
}
