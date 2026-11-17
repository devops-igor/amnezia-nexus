package forwarder

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Return-tuple authority controls (issue #861, R19).
//
// A backend reply may only be attributed to a flow when its OWN declared IPv4/IPv6
// datagram is complete enough to carry the transport ports that name the flow. A packet
// whose header claims a 20-byte IP datagram but whose slice continues with bytes that
// happen to look like ports must not match anything: the trailing bytes are outside the
// declared payload, so the tuple was never in the packet.

// primeProxyFlow records a single PROXY flow client 10.100.0.7:44000 -> remote:port and
// stops the pumps, so the reply outcome is read before any writer runs.
func primeProxyFlow(t *testing.T, remote string, remotePort, clientPort uint16) (*Forwarder, string) {
	t.Helper()
	return primeProxyFlowProto(t, remote, remotePort, clientPort, 6)
}

// primeProxyFlowProto records one PROXY flow of the given transport protocol.
func primeProxyFlowProto(t *testing.T, remote string, remotePort, clientPort uint16, protocol uint8) (*Forwarder, string) {
	t.Helper()
	fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
	fwd.StopPumps()
	var packet []byte
	if protocol == 17 {
		packet = buildTestIPv4UDPRequest(netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote), clientPort, remotePort)
	} else {
		packet = buildTestIPv4TCPPacket(
			netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
			clientPort, remotePort, 0x02, nil)
	}
	if err := fwd.RouteClientToBackend(peer, packet); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
	return fwd, sessionID
}

// buildTestIPv4UDPRequest builds the client's own UDP packet, so the flow table records a
// UDP tuple the reply can match.
func buildTestIPv4UDPRequest(src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 28)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], srcPort)
	binary.BigEndian.PutUint16(packet[22:24], dstPort)
	binary.BigEndian.PutUint16(packet[24:26], 8)
	return packet
}

// TestReturnMustNotAttributePortsOutsideDeclaredDatagram is the reported defect: the
// declared IP total length ends before the ports, so the packet carries no tuple at all.
func TestReturnMustNotAttributePortsOutsideDeclaredDatagram(t *testing.T) {
	fwd, sessionID := primeProxyFlow(t, "5.5.5.5", 443, 44000)

	reply := proxyReply("5.5.5.5", 443, 44000, nil)
	if len(reply) < 24 {
		t.Fatalf("fixture reply is %d bytes, needs room for the trailing bytes", len(reply))
	}
	binary.BigEndian.PutUint16(reply[2:4], 20)

	if err := fwd.RouteBackendToClient(31, reply, "10.100.0.7"); err == nil {
		t.Log("the routing policy accepted the reply; only the evidence claim is under test")
	}

	flow := returnEvidenceOf(t, fwd, sessionID, "5.5.5.5", 443)
	if flow.ReturnMatched != 0 || flow.ReturnAdmitted != 0 {
		t.Fatalf("port bytes outside the declared IP datagram were attributed: matched=%d admitted=%d",
			flow.ReturnMatched, flow.ReturnAdmitted)
	}
	if flow.PROXYReturnMeasured {
		t.Error("a shape-invalid reply left the flow claiming a return measurement")
	}
}

// TestReturnMustNotAttributeIncompleteTransportHeader covers the other shapes that carry
// no usable ports: a truncated TCP header, a truncated UDP header and a non-initial
// fragment.
func TestReturnMustNotAttributeIncompleteTransportHeader(t *testing.T) {
	cases := []struct {
		name  string
		build func() []byte
	}{
		{"TruncatedTCPHeader", func() []byte {
			// Declared total ends 8 bytes into the transport header: the ports exist but
			// the TCP header does not.
			p := proxyReply("5.5.5.5", 443, 44000, nil)
			binary.BigEndian.PutUint16(p[2:4], 28)
			return p
		}},
		{"TruncatedUDPHeader", func() []byte {
			p := buildTestIPv4UDPReply("5.5.5.5", 443, 44000)
			binary.BigEndian.PutUint16(p[2:4], 24)
			return p
		}},
		{"NonInitialFragment", func() []byte {
			p := proxyReply("5.5.5.5", 443, 44000, nil)
			// Fragment offset 1 with more-fragments set: the transport header belongs to
			// an earlier fragment, so this packet carries no ports of its own.
			binary.BigEndian.PutUint16(p[6:8], 0x2001)
			return p
		}},
		{"DeclaredLengthBeyondSlice", func() []byte {
			p := proxyReply("5.5.5.5", 443, 44000, nil)
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)+40))
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fwd, sessionID := primeProxyFlow(t, "5.5.5.5", 443, 44000)
			_ = fwd.RouteBackendToClient(31, tc.build(), "10.100.0.7")

			flow := returnEvidenceOf(t, fwd, sessionID, "5.5.5.5", 443)
			if flow.ReturnMatched != 0 || flow.ReturnAdmitted != 0 {
				t.Errorf("shape-invalid reply was attributed: matched=%d admitted=%d",
					flow.ReturnMatched, flow.ReturnAdmitted)
			}
		})
	}
}

// TestReturnAttributesCompleteTCPAndUDPReplies is the positive control beside the shape
// negatives: a well-formed reply of either supported protocol is attributed.
func TestReturnAttributesCompleteTCPAndUDPReplies(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		fwd, sessionID := primeProxyFlow(t, "5.5.5.5", 443, 44000)
		if err := fwd.RouteBackendToClient(31, proxyReply("5.5.5.5", 443, 44000, []byte("ok")), "10.100.0.7"); err != nil {
			t.Fatalf("complete TCP reply refused: %v", err)
		}
		flow := returnEvidenceOf(t, fwd, sessionID, "5.5.5.5", 443)
		if flow.ReturnMatched != 1 || flow.ReturnAdmitted != 1 {
			t.Errorf("TCP reply = matched %d / admitted %d, want 1/1", flow.ReturnMatched, flow.ReturnAdmitted)
		}
	})
	t.Run("UDP", func(t *testing.T) {
		fwd, sessionID := primeProxyFlowProto(t, "5.5.5.6", 53, 44001, 17)
		if err := fwd.RouteBackendToClient(31, buildTestIPv4UDPReply("5.5.5.6", 53, 44001), "10.100.0.7"); err != nil {
			t.Fatalf("complete UDP reply refused: %v", err)
		}
		flow := returnEvidenceOf(t, fwd, sessionID, "5.5.5.6", 53)
		if flow.ReturnMatched != 1 || flow.ReturnAdmitted != 1 {
			t.Errorf("UDP reply = matched %d / admitted %d, want 1/1", flow.ReturnMatched, flow.ReturnAdmitted)
		}
	})
}

// buildTestIPv4UDPReply builds a UDP reply remote -> client with a consistent inner UDP
// length, so a complete datagram is the control the truncation negatives are contrasted
// with.
func buildTestIPv4UDPReply(remote string, remotePort, clientPort uint16) []byte {
	header := 20
	udp := 8
	packet := make([]byte, header+udp)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(header+udp))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], netip.MustParseAddr(remote).AsSlice())
	copy(packet[16:20], netip.MustParseAddr("10.100.0.7").AsSlice())
	binary.BigEndian.PutUint16(packet[header:header+2], remotePort)
	binary.BigEndian.PutUint16(packet[header+2:header+4], clientPort)
	binary.BigEndian.PutUint16(packet[header+4:header+6], uint16(udp))
	return packet
}
