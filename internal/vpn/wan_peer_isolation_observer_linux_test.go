//go:build linux

package vpn

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// The observation itself lives here, next to its controls: the fixture asks what
// was delivered, and this file owns how a delivery is judged.

// s4PeerRegistration is one client peer the fixture registers with the production
// dispatcher: the peer key and the client address that peer owns.
type s4PeerRegistration struct {
	peerKey  string
	clientIP string
}

// s4PeerRegistrations is the single list of peers the fixture registers. The
// ownership observation iterates this same list, so it can only ask about peers
// that actually have a return path: asking a peer that owns nothing always reports
// "nothing delivered" and proves nothing.
var s4PeerRegistrations = []s4PeerRegistration{
	{peerKey: "peer-s4-udp", clientIP: "10.100.0.10"},
	{peerKey: "peer-s4-tcp", clientIP: "10.100.0.11"},
	{peerKey: "peer-s4-proxy", clientIP: s4ProxyBackendClientIP},
}

// s4ReplySink is the return-path write callback the fixture registers for every
// peer: it records the delivered packet under the peer key the production return
// path reports, which is what the ownership observation reads.
func s4ReplySink(replies *s4PeerReplies) func(peerKey, assignedIP string, packet []byte) (int, error) {
	return func(peerKey, assignedIP string, packet []byte) (int, error) {
		replies.add(peerKey, packet)
		return len(packet), nil
	}
}

// s4ReplyView is the parsed view of a delivered IPv4 packet.
type s4ReplyView struct {
	proto   uint8
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	payload string
}

// sameFlow reports whether other carries the same remote flow and payload, i.e. is
// a copy of this reply.
//
// The local destination is deliberately excluded. A copy that was re-translated for
// another peer's client still carries the same remote endpoint and the same payload,
// and that is exactly the delivery this observation must catch; including the
// destination would let it hide behind a changed DNAT address. Sequence numbers,
// acknowledgements and checksums are excluded too, so a retransmission of the owning
// flow's reply is still recognised as that flow's reply.
func (v s4ReplyView) sameFlow(other s4ReplyView) bool {
	return v.proto == other.proto && v.srcIP == other.srcIP && v.srcPort == other.srcPort && v.payload == other.payload
}

// s4ViewOf parses a delivered IPv4 packet into the fields the ownership observation
// compares. Both TCP and UDP carry their endpoints at the same offset after the IP
// header, and the transport payload begins where the header's own lengths say.
func s4ViewOf(packet []byte) (s4ReplyView, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return s4ReplyView{}, false
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || len(packet) < headerLen+4 {
		return s4ReplyView{}, false
	}
	payloadOffset, ok := s4PayloadOffset(packet)
	if !ok || payloadOffset > len(packet) {
		return s4ReplyView{}, false
	}
	return s4ReplyView{
		proto:   packet[9],
		srcIP:   netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]}).String(),
		srcPort: binary.BigEndian.Uint16(packet[headerLen : headerLen+2]),
		dstIP:   netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}).String(),
		dstPort: binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4]),
		payload: string(packet[payloadOffset:]),
	}, true
}

// s4OwnershipViolations reports the registered peers other than the reply's owner
// whose return path received a copy of that reply. An empty result is the required
// outcome.
//
// The owner is derived from the reply's own destination address, so the caller
// cannot name the wrong owner, and a destination that belongs to no registered peer
// is an error: the observation fails closed instead of comparing against a peer that
// owns nothing. It also deliberately does not ask "did this peer receive anything":
// the direct peers own real flows and keep receiving their own replies, so presence
// alone is true on every run and cannot separate a leak from legitimate traffic.
func s4OwnershipViolations(replies *s4PeerReplies, reply []byte) ([]string, error) {
	observed, ok := s4ViewOf(reply)
	if !ok {
		return nil, fmt.Errorf("observation is not a parseable IPv4 reply: %d bytes", len(reply))
	}
	owner := ""
	for _, peer := range s4PeerRegistrations {
		if peer.clientIP == observed.dstIP {
			owner = peer.peerKey
			break
		}
	}
	if owner == "" {
		return nil, fmt.Errorf("reply destination %s:%d belongs to no registered peer", observed.dstIP, observed.dstPort)
	}
	var violations []string
	for _, peer := range s4PeerRegistrations {
		if peer.peerKey == owner {
			continue
		}
		for _, delivered := range replies.packets(peer.peerKey) {
			if other, parsed := s4ViewOf(delivered); parsed && observed.sameFlow(other) {
				violations = append(violations, peer.peerKey)
				break
			}
		}
	}
	return violations, nil
}

// TestS4PeerIsolationObserver pins the ownership observation the S4 gate makes on
// the replies the production return path delivered.
//
// It is namespace-free and deterministic: it exercises the observation boundary
// (the return-path write callback, the per-peer sink and the flow comparison) with
// no TUN device, no namespace, no remote peer and no privilege, so it runs in
// ordinary CI.
//
// It also keeps the historical contradiction explicit. The gate used to answer "did
// this peer ever receive a packet?" for peers that legitimately own direct flows;
// that is true on every run that reaches the assertion, so the gate rejected a
// correct product. The first control asserts that presence predicate is still true
// on the same state the new observation passes, which is what makes these controls
// defect-sensitive: restoring the presence predicate fails them.
func TestS4PeerIsolationObserver(t *testing.T) {
	remote := netip.MustParseAddr(s4RemotePeer)
	remotePort := uint16(s4RemotePort)

	directUDP := s4TestUDPReply(remote, remotePort, s4TestClientIP(t, "peer-s4-udp"), 12345, "s4-udp-probe")
	directTCP := s4TestTCPReply(remote, remotePort, s4TestClientIP(t, "peer-s4-tcp"), 23456, "s4-tcp-probe")
	proxyReply := s4TestUDPReply(s4ProxyDstIP, 53, s4ProxyBackendClientIP, 5555, "proxy-probe")

	t.Run("legitimate earlier direct replies are not a leak", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)
		s4TestDeliver(t, replies, "peer-s4-tcp", directTCP)
		s4TestDeliver(t, replies, "peer-s4-proxy", proxyReply)

		// The historical predicate is true on this legitimate state. That is the
		// contradiction: it cannot tell this state from a leak.
		if !s4PeerGotReply(replies, "peer-s4-udp") || !s4PeerGotReply(replies, "peer-s4-tcp") {
			t.Fatal("presence must be true for peers that own real flows, or this control does not demonstrate the old contradiction")
		}
		for _, observed := range []struct {
			description string
			reply       []byte
		}{
			{"direct UDP reply", directUDP},
			{"direct TCP reply", directTCP},
			{"proxy reply", proxyReply},
		} {
			s4TestCheckViolations(t, replies, observed.reply, nil)
		}
	})

	t.Run("matching wrong-peer proxy reply is rejected", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)
		s4TestDeliver(t, replies, "peer-s4-tcp", directTCP)
		s4TestDeliver(t, replies, "peer-s4-proxy", proxyReply)
		s4TestDeliver(t, replies, "peer-s4-tcp", proxyReply)

		s4TestCheckViolations(t, replies, proxyReply, []string{"peer-s4-tcp"})
		// The legitimate traffic of the same peers must still be accepted.
		s4TestCheckViolations(t, replies, directUDP, nil)
	})

	t.Run("matching wrong-peer direct reply is rejected", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)
		s4TestDeliver(t, replies, "peer-s4-tcp", directTCP)
		s4TestDeliver(t, replies, "peer-s4-tcp", directUDP)

		s4TestCheckViolations(t, replies, directUDP, []string{"peer-s4-tcp"})
		s4TestCheckViolations(t, replies, directTCP, nil)
	})

	t.Run("copy re-translated for another peer's client is rejected", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)
		s4TestDeliver(t, replies, "peer-s4-proxy", proxyReply)
		s4TestDeliver(t, replies, "peer-s4-tcp",
			s4TestUDPReply(s4ProxyDstIP, 53, s4TestClientIP(t, "peer-s4-tcp"), 23456, "proxy-probe"))

		// The copy carries a different local destination; the remote flow and the
		// payload are what identify it as the proxied reply.
		s4TestCheckViolations(t, replies, proxyReply, []string{"peer-s4-tcp"})
	})

	t.Run("late copy is rejected without a counter reset", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)
		s4TestDeliver(t, replies, "peer-s4-proxy", proxyReply)
		s4TestCheckViolations(t, replies, proxyReply, nil)

		// Delivered after the observation was already clean once: the sink keeps the
		// whole history, so the copy is still visible and no baseline is reset.
		s4TestDeliver(t, replies, "peer-s4-udp", proxyReply)
		s4TestCheckViolations(t, replies, proxyReply, []string{"peer-s4-udp"})
	})

	t.Run("a different flow on the same peer is not a leak", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)
		s4TestDeliver(t, replies, "peer-s4-tcp", directTCP)
		// Same remote endpoint and peer, different payload; and the direct UDP
		// payload over a different protocol.
		s4TestDeliver(t, replies, "peer-s4-tcp",
			s4TestUDPReply(remote, remotePort, s4TestClientIP(t, "peer-s4-tcp"), 23456, "other-probe"))
		s4TestDeliver(t, replies, "peer-s4-tcp",
			s4TestTCPReply(remote, remotePort, s4TestClientIP(t, "peer-s4-tcp"), 23456, "s4-udp-probe"))

		s4TestCheckViolations(t, replies, directUDP, nil)
		s4TestCheckViolations(t, replies, directTCP, nil)
	})

	t.Run("fail closed", func(t *testing.T) {
		replies := newS4PeerReplies()
		s4TestDeliver(t, replies, "peer-s4-udp", directUDP)

		unregistered := s4TestUDPReply(s4ProxyDstIP, 53, "10.100.0.99", 5555, "proxy-probe")
		if _, err := s4OwnershipViolations(replies, unregistered); err == nil {
			t.Fatal("a reply addressed to no registered peer must be an error, not a silent pass")
		}
		if _, err := s4OwnershipViolations(replies, directUDP[:24]); err == nil {
			t.Fatal("a truncated observation must be an error, not a silent pass")
		}
		if _, err := s4OwnershipViolations(replies, nil); err == nil {
			t.Fatal("an empty observation must be an error, not a silent pass")
		}
	})
}

// s4TestUDPReply builds the UDP reply a remote endpoint returns to one client.
func s4TestUDPReply(src netip.Addr, srcPort uint16, dstIP string, dstPort uint16, body string) []byte {
	return buildTestPBRUDPPacket(src, netip.MustParseAddr(dstIP), srcPort, dstPort, []byte("ECHO:"+body))
}

// s4TestTCPReply builds the TCP reply a remote endpoint returns to one client.
func s4TestTCPReply(src netip.Addr, srcPort uint16, dstIP string, dstPort uint16, body string) []byte {
	return buildTestPBRTCPPacket(src, netip.MustParseAddr(dstIP), srcPort, dstPort, []byte("ECHO:"+body))
}

// s4TestClientIP returns the address the fixture registers for peerKey, so the
// controls use the fixture's own registration instead of a second copy of it.
func s4TestClientIP(t *testing.T, peerKey string) string {
	t.Helper()
	for _, peer := range s4PeerRegistrations {
		if peer.peerKey == peerKey {
			return peer.clientIP
		}
	}
	t.Fatalf("peer %s is not registered by the fixture", peerKey)
	return ""
}

// s4TestDeliver writes a reply through the production ReturnPath the fixture
// registers for peerKey, so the sink is filled by the same boundary the gate
// observes rather than by a direct call to the sink.
func s4TestDeliver(t *testing.T, replies *s4PeerReplies, peerKey string, reply []byte) {
	t.Helper()
	path := forwarder.NewReturnPath(s4ReplySink(replies))
	defer path.Close()
	if _, err := path.Write(peerKey, s4TestClientIP(t, peerKey), reply); err != nil {
		t.Fatalf("write a reply through the return path of %s: %v", peerKey, err)
	}
}

// s4TestCheckViolations compares the peers the ownership observation reports.
func s4TestCheckViolations(t *testing.T, replies *s4PeerReplies, reply []byte, want []string) {
	t.Helper()
	got, err := s4OwnershipViolations(replies, reply)
	if err != nil {
		t.Fatalf("ownership observation: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("ownership violations = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ownership violations = %v, want %v", got, want)
		}
	}
}
