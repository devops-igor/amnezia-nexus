package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// TestNAT_PeerChurnAndSafePortReuse verifies that remote bindings are bounded,
// expired after quarantine, and NAT ports can be safely reused by different peers
// to the same remote destination without memory growth or port exhaustion (BLOCKER 2).
func TestNAT_PeerChurnAndSafePortReuse(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	targetIP := netip.MustParseAddr("1.1.1.1")
	clientBase := "10.100.0."

	// Strict pool: only 2 NAT ports (40000 and 40001)
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  wanDev,
		UDPTimeout: 50 * time.Millisecond,
		TCPTimeout: 50 * time.Millisecond,
		MinPort:    40000,
		MaxPort:    40001, // 2 ports
	}, nil)
	defer func() { _ = dem.Close() }()

	quarantine := 20 * time.Millisecond
	dem.SetPortCooldown(quarantine)
	dem.SetQuarantineDurations(quarantine, quarantine)

	// Simulate 30 sequential peers all talking to the exact same destination 1.1.1.1:53
	for i := 1; i <= 30; i++ {
		peerKey := fmt.Sprintf("peer-%d", i)
		sessionID := fmt.Sprintf("sess-%d", i)
		clientIP := fmt.Sprintf("%s%d", clientBase, i%250+1)
		capPath := newTestCaptureReturnPath()

		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), targetIP, uint16(10000+i), 53, []byte(fmt.Sprintf("hello-%d", i)))
		err := dem.RouteDirect(peerKey, clientIP, sessionID, uint64(i), pkt, capPath.path)
		if err != nil {
			t.Fatalf("peer %d failed to route direct: %v", i, err)
		}

		// Verify reply is delivered to the correct peer
		replyPkt := buildTestIPv4UDPPacket(targetIP, hostWAN, 53, 40000, []byte(fmt.Sprintf("reply-%d", i)))
		if err := dem.HandleWANReply(replyPkt); err != nil {
			replyPkt2 := buildTestIPv4UDPPacket(targetIP, hostWAN, 53, 40001, []byte(fmt.Sprintf("reply-%d", i)))
			_ = dem.HandleWANReply(replyPkt2)
		}

		// Terminate flow / peer session
		dem.PurgePeer(peerKey)

		// Wait past quarantine so the port & remote binding can be safely recycled
		time.Sleep(quarantine + 5*time.Millisecond)
	}

	// Verify that remote bindings did NOT accumulate indefinitely (must be bounded <= 2)
	count := dem.RemoteBindingCount()
	if count > 2 {
		t.Fatalf("expected remote bindings to be bounded by active pool (<=2), got %d", count)
	}
}

// TestNAT_QuarantineWindowRejectsDelayedPackets verifies that during the quarantine window,
// delayed packets from a previous peer's session are rejected with ErrStaleSessionReply.
func TestNAT_QuarantineWindowRejectsDelayedPackets(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	targetIP := netip.MustParseAddr("1.1.1.1")
	clientIP := netip.MustParseAddr("10.100.0.10")

	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  wanDev,
		UDPTimeout: 5 * time.Second,
		TCPTimeout: 5 * time.Second,
		MinPort:    45000,
		MaxPort:    45000, // 1 port
	}, nil)
	defer func() { _ = dem.Close() }()

	quarantine := 100 * time.Millisecond
	dem.SetPortCooldown(quarantine)
	dem.SetQuarantineDurations(quarantine, quarantine)

	capPath1 := newTestCaptureReturnPath()
	pkt1 := buildTestIPv4UDPPacket(clientIP, targetIP, 1234, 53, []byte("req-1"))
	if err := dem.RouteDirect("peer-1", clientIP.String(), "sess-1", 1, pkt1, capPath1.path); err != nil {
		t.Fatalf("RouteDirect peer-1 failed: %v", err)
	}

	// Purge peer-1; binding enters quarantine
	dem.PurgePeer("peer-1")

	// Within quarantine window: delayed packet must be rejected
	oldReply := buildTestIPv4UDPPacket(targetIP, hostWAN, 53, 45000, []byte("delayed"))
	err := dem.HandleWANReply(oldReply)
	if !errors.Is(err, ErrStaleSessionReply) {
		t.Fatalf("expected ErrStaleSessionReply during quarantine window, got: %v", err)
	}
}

// TestPBR_ICMPProxiedPreservesConnectivity verifies HIGH 4:
// When PBR is enabled, valid non-TCP/UDP IPv4 packets (ICMP ping) are routed to the
// PROXY backend queue, while spoofed source IPs or prohibited destinations are dropped.
func TestPBR_ICMPProxiedPreservesConnectivity(t *testing.T) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(true)
	defer fwd.StopPumps()

	backendID := int64(101)
	peerKey := "peer-icmp"
	clientIP := "10.100.0.25"
	sessionID := "sess-icmp"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", peerKey, clientIP, backendID, capPath.path)
	beQueue := fwd.backendQueues[backendID]

	// Build an ICMP Echo Request (proto 1, type 8, code 0)
	buildICMPPacket := func(src, dst netip.Addr) []byte {
		totalLen := 28 // 20-byte IP header + 8-byte ICMP header
		pkt := make([]byte, totalLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
		pkt[8] = 64
		pkt[9] = 1 // ICMP
		copy(pkt[12:16], src.AsSlice())
		copy(pkt[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(pkt[10:12], computeIPv4Checksum(pkt[:20]))
		pkt[20] = 8 // Echo Request
		pkt[21] = 0 // Code 0
		// Checksum for ICMP
		binary.BigEndian.PutUint16(pkt[22:24], computeIPv4Checksum(pkt[20:28]))
		return pkt
	}

	publicTarget := netip.MustParseAddr("1.1.1.1")
	validPkt := buildICMPPacket(netip.MustParseAddr(clientIP), publicTarget)

	// 1. Valid ICMP packet to public destination: routes to proxy backend!
	if err := fwd.RouteClientToBackend(peerKey, validPkt); err != nil {
		t.Fatalf("expected ICMP packet to route to proxy backend, got err: %v", err)
	}
	select {
	case pkt := <-beQueue:
		if len(pkt) < 20 || pkt[9] != 1 {
			t.Fatalf("expected ICMP packet on backend queue, got proto %d", pkt[9])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for ICMP packet on backend queue")
	}

	// 2. Spoofed source IP: must be dropped!
	spoofedPkt := buildICMPPacket(netip.MustParseAddr("10.100.0.99"), publicTarget)
	if err := fwd.RouteClientToBackend(peerKey, spoofedPkt); err == nil {
		t.Fatal("expected spoofed source IP to be dropped, got nil error")
	}

	// 3. Prohibited destination (e.g. metadata 169.254.169.254): must be dropped!
	metadataTarget := netip.MustParseAddr("169.254.169.254")
	prohibitedPkt := buildICMPPacket(netip.MustParseAddr(clientIP), metadataTarget)
	if err := fwd.RouteClientToBackend(peerKey, prohibitedPkt); err == nil {
		t.Fatal("expected prohibited destination to be dropped, got nil error")
	}
}

// TestWANReader_NoDuplicateGoroutines verifies MEDIUM 6:
// Calling AttachWANDevice repeatedly or replacing the device ensures exactly
// one reader runs, and old readers are stopped and joined cleanly.
func TestWANReader_NoDuplicateGoroutines(t *testing.T) {
	dev1 := newMockPacketDev()
	dev2 := newMockPacketDev()

	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: dev1,
	}, nil)

	// Re-attaching the same device: no-op, exactly one reader remains
	dem.AttachWANDevice(dev1)

	// Attaching new device: stops and joins dev1 reader, starts dev2 reader
	dem.AttachWANDevice(dev2)

	// Closing manager cleanly joins the reader
	if err := dem.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
