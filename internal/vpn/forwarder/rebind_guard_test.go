package forwarder

import (
	"errors"
	"net"
	"testing"
)

// Regression tests for issue #89: the srcIP "self-heal" rebind in
// RouteClientToBackend used to trust the inner packet's claimed source IP
// unconditionally. Any authenticated peer could send an inner packet with a
// victim's assigned IP (sequential IPAM makes victim IPs guessable) and
// steal the victim's routesByIP entry — hijacking the victim's downstream
// traffic. The rebind is now gated on: claimed srcIP inside the portal
// subnet AND currently unassigned; everything else is dropped and counted.

// helper: build a minimal IPv4 packet (20-byte header + UDP-ish payload)
// with the given dotted-quad source address.
func rebindTestPacket(src string) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45 // IPv4, IHL=5
	ip := net.ParseIP(src).To4()
	if ip == nil {
		panic("rebindTestPacket: bad test IP " + src)
	}
	pkt[12], pkt[13], pkt[14], pkt[15] = ip[0], ip[1], ip[2], ip[3]
	return pkt
}

// TestRebindHijackBlocked is the two-peer regression test: peer A sends an
// inner packet claiming peer B's assigned IP. B's route MUST stay intact,
// A's packet MUST be dropped (never reach the backend queue), and the
// spoof counter MUST increment.
func TestRebindHijackBlocked(t *testing.T) {
	f := NewForwarder(NewTrafficAccountant(nil, 0), "10.100.0.0/16", 64)

	const backendID = int64(1)
	const ipA = "10.100.0.10" // sequentially guessable neighbor of B
	const ipB = "10.100.0.11" // the victim's assigned IP
	f.RegisterSession("sess-a", "conn-a", "peer-a", ipA, backendID)
	f.RegisterSession("sess-b", "conn-b", "peer-b", ipB, backendID)

	beChan, ok := f.GetBackendPacketChannel(backendID)
	if !ok {
		t.Fatalf("no backend channel for %d", backendID)
	}

	// Drain any residual packets.
	for len(beChan) > 0 {
		<-beChan
	}

	// The hijack attempt: attacker (peer-a) claims the victim's IP.
	if err := f.RouteClientToBackend("peer-a", rebindTestPacket(ipB)); !errors.Is(err, ErrSpoofedSourceIP) {
		t.Fatalf("spoofed rebind not rejected: got err=%v, want ErrSpoofedSourceIP", err)
	}

	// A's packet must be dropped: nothing arrives on the backend queue.
	select {
	case pkt := <-beChan:
		t.Fatalf("spoofed packet was forwarded to the backend: %v", pkt)
	default:
	}

	// B's route must be untouched: return traffic to B's IP still lands on
	// B's client queue, and B's routesByIP entry still maps to B's route.
	clientB, ok := f.GetClientPacketChannel("peer-b")
	if !ok {
		t.Fatalf("no client channel for peer-b")
	}
	if err := f.RouteBackendToClient(backendID, []byte("return-to-b"), ipB); err != nil {
		t.Fatalf("return route to victim's IP broken by hijack attempt: %v", err)
	}
	select {
	case pkt := <-clientB:
		if string(pkt) != "return-to-b" {
			t.Fatalf("victim received wrong packet: %q", pkt)
		}
	default:
		t.Fatal("victim's route was stolen: no return packet for B")
	}

	// A's own route must also still work (its assigned IP is unchanged).
	if err := f.RouteBackendToClient(backendID, []byte("return-to-a"), ipA); err != nil {
		t.Fatalf("A's own route broken: %v", err)
	}

	// Spoof counter incremented (exactly once so far).
	if got := f.SpoofedRebinds(); got != 1 {
		t.Fatalf("SpoofedRebinds = %d, want 1", got)
	}

	// Repeat the attack: counter keeps counting, route still intact.
	if err := f.RouteClientToBackend("peer-a", rebindTestPacket(ipB)); !errors.Is(err, ErrSpoofedSourceIP) {
		t.Fatalf("second spoofed rebind not rejected: %v", err)
	}
	if got := f.SpoofedRebinds(); got != 2 {
		t.Fatalf("SpoofedRebinds after second attempt = %d, want 2", got)
	}
	if err := f.RouteBackendToClient(backendID, []byte("return-to-b2"), ipB); err != nil {
		t.Fatalf("victim route broken after second hijack attempt: %v", err)
	}
	<-clientB
}

// TestLegitimateRebindStillWorks covers the NAT/misconfig self-heal use
// case: a peer whose traffic appears from a DIFFERENT unassigned IP inside
// the portal subnet still gets its return route rebound to the new IP.
func TestLegitimateRebindStillWorks(t *testing.T) {
	f := NewForwarder(NewTrafficAccountant(nil, 0), "10.100.0.0/16", 64)

	const backendID = int64(2)
	const initialIP = "10.100.0.20"
	const newIP = "10.100.0.21" // unassigned, inside the portal subnet
	f.RegisterSession("sess-l", "conn-l", "peer-l", initialIP, backendID)

	clientChan, ok := f.GetClientPacketChannel("peer-l")
	if !ok {
		t.Fatalf("no client channel")
	}

	// Self-heal: peer sends an inner packet with a NEW, unassigned,
	// in-subnet source IP.
	if err := f.RouteClientToBackend("peer-l", rebindTestPacket(newIP)); err != nil {
		t.Fatalf("legitimate rebind rejected: %v", err)
	}

	// Return traffic to the NEW IP must reach the peer.
	if err := f.RouteBackendToClient(backendID, []byte("self-healed"), newIP); err != nil {
		t.Fatalf("RouteBackendToClient for rebound IP: %v", err)
	}
	select {
	case pkt := <-clientChan:
		if string(pkt) != "self-healed" {
			t.Fatalf("payload mismatch: %q", pkt)
		}
	default:
		t.Fatal("no packet on client queue after legit rebind")
	}

	// The old IP entry was moved, not copied: the old address is no longer
	// routed.
	if err := f.RouteBackendToClient(backendID, []byte("old"), initialIP); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("old IP still routed after legit rebind: %v", err)
	}

	// A legitimate rebind must NOT count as spoofed.
	if got := f.SpoofedRebinds(); got != 0 {
		t.Fatalf("SpoofedRebinds = %d after legitimate rebind, want 0", got)
	}
}

// TestSpoofedRebindsOutsideSubnet covers the guard's subnet half: an inner
// packet whose claimed source is OUTSIDE the portal subnet is dropped and
// counted even though the IP is "unassigned" — nothing outside the client
// pool can be a legitimate self-heal target.
func TestSpoofedRebindsOutsideSubnet(t *testing.T) {
	f := NewForwarder(NewTrafficAccountant(nil, 0), "10.100.0.0/16", 64)

	const backendID = int64(3)
	const assignedIP = "10.100.0.30"
	f.RegisterSession("sess-o", "conn-o", "peer-o", assignedIP, backendID)

	// A claimed source outside the portal subnet (Internet host behind a
	// misconfigured NAT) must be dropped and counted.
	if err := f.RouteClientToBackend("peer-o", rebindTestPacket("203.0.113.9")); !errors.Is(err, ErrSpoofedSourceIP) {
		t.Fatalf("out-of-subnet rebind not rejected: %v", err)
	}
	if got := f.SpoofedRebinds(); got != 1 {
		t.Fatalf("SpoofedRebinds = %d, want 1", got)
	}

	// No rebind happened: return traffic still goes to the original IP.
	if err := f.RouteBackendToClient(backendID, []byte("ok"), assignedIP); err != nil {
		t.Fatalf("original route lost after out-of-subnet claim: %v", err)
	}

	// Fail-closed: with no portal subnet configured, even an in-subnet
	// unclaimed IP must be rejected.
	fNoSubnet := NewForwarder(NewTrafficAccountant(nil, 0), "", 64)
	fNoSubnet.RegisterSession("sess-n", "conn-n", "peer-n", assignedIP, backendID)
	if err := fNoSubnet.RouteClientToBackend("peer-n", rebindTestPacket("10.100.0.55")); !errors.Is(err, ErrSpoofedSourceIP) {
		t.Fatalf("rebind allowed without a configured subnet: %v", err)
	}
	if got := fNoSubnet.SpoofedRebinds(); got != 1 {
		t.Fatalf("SpoofedRebinds (no subnet) = %d, want 1", got)
	}
}
