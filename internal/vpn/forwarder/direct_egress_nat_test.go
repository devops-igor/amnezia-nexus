package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
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

// TestNAT_LookupExpiryRetiresRemoteBindingAndReclaimsPort verifies HIGH R18-B2:
// When an idle flow expires during LookupFlow, its remote binding must be retired
// with a release timestamp so it can be swept and allow different peers to reuse the port.
func TestNAT_LookupExpiryRetiresRemoteBindingAndReclaimsPort(t *testing.T) {
	dev := newMockPacketDev()
	m := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: dev,
		MinPort:   45000,
		MaxPort:   45000,
	}, nil)
	defer func() { _ = m.Close() }()

	a := netip.MustParseAddr("10.100.0.1")
	target := netip.MustParseAddr("1.1.1.1")
	pkt := buildTestIPv4UDPPacket(a, target, 12345, 53, []byte("one"))
	if err := m.RouteDirect("peer-a", a.String(), "session-a", uint64(1), pkt, newTestCaptureReturnPath().path); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	for _, f := range m.flows {
		f.lastSeen = time.Now().Add(-time.Minute)
	}
	m.mu.Unlock()
	if _, found := m.LookupFlow("peer-a", pkt); found {
		t.Fatal("idle flow did not expire")
	}
	// Explicit sweep after quarantine cleans the retired binding
	m.Sweep(time.Now().Add(time.Hour))
	m.mu.RLock()
	var active int
	for _, b := range m.remoteBindings {
		if b.active {
			active++
		}
	}
	if active != 0 {
		t.Fatalf("expected 0 active bindings after idle expiry and sweep, got %d", active)
	}
	m.mu.RUnlock()

	b := netip.MustParseAddr("10.100.0.2")
	other := buildTestIPv4UDPPacket(b, target, 23456, 53, []byte("two"))
	err := m.RouteDirect("peer-b", b.String(), "session-b", uint64(1), other, newTestCaptureReturnPath().path)
	if errors.Is(err, ErrNATPortExhaustion) {
		t.Fatalf("orphaned active remote binding permanently prevents different peer from reusing otherwise free NAT port: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestNAT_ProductionDispatchAfterDNSEvidenceExpiry verifies HIGH R18-B2 across full dispatch:
// After DNS evidence expires and flow moves to PROXY, NAT port and remote binding are retired.
func TestNAT_ProductionDispatchAfterDNSEvidenceExpiry(t *testing.T) {
	f, m, dev, rc := setupForwarderWithPBR(t)
	defer func() { _ = m.Close() }()
	m.mu.Lock()
	m.cfg.MinPort = 45000
	m.cfg.MaxPort = 45000
	m.nextPort = 45000
	m.mu.Unlock()

	target := netip.MustParseAddr("1.1.1.1")
	a := netip.MustParseAddr("10.100.0.10")
	b := netip.MustParseAddr("10.100.0.11")
	f.RegisterSessionWithReturnPath("session-a", "connection-a", "peer-a", a.String(), 101, newTestCaptureReturnPath().path)
	rc.Set("session-a", target, policy.Direct)
	packet := buildTestIPv4UDPPacket(a, target, 12345, 53, []byte("initial-direct"))
	if err := f.RouteClientToBackend("peer-a", packet); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	for _, flow := range m.flows {
		flow.lastSeen = time.Now().Add(-time.Minute)
	}
	m.mu.Unlock()

	// Simulate the ordinary expiry of client DNS evidence before the next packet
	rc.Set("session-a", target, policy.Unknown)
	if err := f.RouteClientToBackend("peer-a", packet); err != nil {
		t.Fatal(err)
	}
	if got := len(f.backendQueues[101]); got != 1 {
		t.Fatalf("expected expired evidence to use PROXY, queued=%d", got)
	}
	if got := len(dev.getPackets()); got != 1 {
		t.Fatalf("expired evidence unexpectedly emitted another WAN packet, total=%d", got)
	}
	m.Sweep(time.Now().Add(time.Hour))
	m.mu.RLock()
	active := 0
	for _, binding := range m.remoteBindings {
		if binding.active {
			active++
		}
	}
	if active != 0 {
		t.Fatalf("expected 0 active bindings, got %d", active)
	}
	m.mu.RUnlock()

	f.RegisterSessionWithReturnPath("session-b", "connection-b", "peer-b", b.String(), 101, newTestCaptureReturnPath().path)
	rc.Set("session-b", target, policy.Direct)
	other := buildTestIPv4UDPPacket(b, target, 23456, 53, []byte("other-peer-direct"))
	err := f.RouteClientToBackend("peer-b", other)
	if errors.Is(err, ErrNATPortExhaustion) {
		t.Fatalf("production dispatch left active orphan preventing free-port reuse: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// TestNAT_TableSaturationPreservesQuarantineAndFailsClosed verifies BLOCKER 2:
// Under table capacity pressure where all bindings are in active quarantine,
// pruneOldestBindingsLocked must NEVER evict unexpired quarantined bindings.
// Instead, it must fail closed (ErrNATTableFull / ErrNoAvailablePorts),
// ensuring delayed packets for quarantined sessions cannot reach new peers.
func TestNAT_TableSaturationPreservesQuarantineAndFailsClosed(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	target1, target2, target3 := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("3.3.3.3")
	clientBase := "10.100.0."

	// Saturated table: exactly 2 remote bindings max, with 5 available NAT ports
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:   hostWAN,
		WANDevice:   wanDev,
		UDPTimeout:  5 * time.Second,
		TCPTimeout:  5 * time.Second,
		MinPort:     40000,
		MaxPort:     40005,
		MaxBindings: 2,
	}, nil)
	defer func() { _ = dem.Close() }()

	quarantine := 80 * time.Millisecond
	dem.SetPortCooldown(0) // Zero port cooldown to isolate remote binding quarantine behavior
	dem.SetQuarantineDurations(quarantine, quarantine)

	capPath1 := newTestCaptureReturnPath()
	client1 := clientBase + "1"
	pkt1 := buildTestIPv4UDPPacket(netip.MustParseAddr(client1), target1, 10001, 53, []byte("req-1"))
	if err := dem.RouteDirect("peer-1", client1, "sess-1", 1, pkt1, capPath1.path); err != nil {
		t.Fatalf("peer-1 RouteDirect failed: %v", err)
	}

	capPath2 := newTestCaptureReturnPath()
	client2 := clientBase + "2"
	pkt2 := buildTestIPv4UDPPacket(netip.MustParseAddr(client2), target2, 10002, 53, []byte("req-2"))
	if err := dem.RouteDirect("peer-2", client2, "sess-2", 1, pkt2, capPath2.path); err != nil {
		t.Fatalf("peer-2 RouteDirect failed: %v", err)
	}

	if count := dem.RemoteBindingCount(); count != 2 {
		t.Fatalf("expected 2 active bindings, got %d", count)
	}

	// Purge both sessions so both bindings enter active quarantine (unexpired)
	dem.PurgeSession("sess-1")
	dem.PurgeSession("sess-2")

	// Verify both bindings are still present and in quarantine
	if count := dem.RemoteBindingCount(); count != 2 {
		t.Fatalf("expected 2 quarantined bindings preserved, got %d", count)
	}

	// Now table is saturated with 2 unexpired quarantined bindings.
	// Peer-3 attempts to route to a new destination (target3:53).
	// Because table is full of unexpired quarantine, it MUST fail closed:
	// it must NOT evict unexpired quarantine records!
	capPath3 := newTestCaptureReturnPath()
	client3 := clientBase + "3"
	pkt3 := buildTestIPv4UDPPacket(netip.MustParseAddr(client3), target3, 10003, 53, []byte("req-3"))
	err := dem.RouteDirect("peer-3", client3, "sess-3", 1, pkt3, capPath3.path)
	if !errors.Is(err, ErrNATTableFull) && !errors.Is(err, ErrNoAvailablePorts) {
		t.Fatalf("expected ErrNATTableFull or ErrNoAvailablePorts under table saturation, got: %v", err)
	}

	// Verify unexpired quarantine records were strictly preserved
	if count := dem.RemoteBindingCount(); count != 2 {
		t.Fatalf("expected table to retain 2 quarantined bindings without premature eviction, got %d", count)
	}

	// Delayed packets arrive from target1:53 and target2:53 targeting NAT ports 40000 and 40001
	delayedReply1 := buildTestIPv4UDPPacket(target1, hostWAN, 53, 40000, []byte("delayed-reply-1"))
	if err := dem.HandleWANReply(delayedReply1); !errors.Is(err, ErrStaleSessionReply) {
		t.Fatalf("expected delayed packet 1 to be rejected as ErrStaleSessionReply, got: %v", err)
	}

	delayedReply2 := buildTestIPv4UDPPacket(target2, hostWAN, 53, 40001, []byte("delayed-reply-2"))
	if err := dem.HandleWANReply(delayedReply2); !errors.Is(err, ErrStaleSessionReply) {
		t.Fatalf("expected delayed packet 2 to be rejected as ErrStaleSessionReply, got: %v", err)
	}

	// Ensure no delayed packets were delivered to peer-3
	if pkts := capPath3.getPackets(); len(pkts) != 0 {
		t.Fatalf("delayed packets leaked to peer-3! count=%d", len(pkts))
	}

	// Wait past quarantine window
	time.Sleep(quarantine + 20*time.Millisecond)

	// Now that quarantine has expired, new connection should safely succeed
	err = dem.RouteDirect("peer-3", client3, "sess-3", 1, pkt3, capPath3.path)
	if err != nil {
		t.Fatalf("peer-3 RouteDirect failed after quarantine expiration: %v", err)
	}
}

// TestNAT_DirectRetirementDoesNotMutateUnrelatedBindingTimestamps verifies HIGH 3:
// releasePortLocked retires specific matching bindings in O(1) without scanning the map
// and without updating releasedAt timestamps of other bindings.
func TestNAT_DirectRetirementDoesNotMutateUnrelatedBindingTimestamps(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	target1 := netip.MustParseAddr("1.1.1.1")
	target2 := netip.MustParseAddr("2.2.2.2")
	clientIP := netip.MustParseAddr("10.100.0.10")

	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: hostWAN,
		WANDevice: wanDev,
		MinPort:   40000,
		MaxPort:   40001,
	}, nil)
	defer func() { _ = dem.Close() }()
	dem.SetPortCooldown(0)

	capPath1 := newTestCaptureReturnPath()
	pkt1 := buildTestIPv4UDPPacket(clientIP, target1, 10001, 53, []byte("one"))
	if err := dem.RouteDirect("peer-1", clientIP.String(), "sess-1", 1, pkt1, capPath1.path); err != nil {
		t.Fatal(err)
	}

	capPath2 := newTestCaptureReturnPath()
	pkt2 := buildTestIPv4UDPPacket(clientIP, target2, 10002, 53, []byte("two"))
	if err := dem.RouteDirect("peer-2", clientIP.String(), "sess-2", 1, pkt2, capPath2.path); err != nil {
		t.Fatal(err)
	}

	// Retire flow 1
	dem.PurgeSession("sess-1")

	// Get releasedAt timestamp of binding 1
	dem.mu.RLock()
	var releasedAt1 time.Time
	bKey1 := remoteBindingKey{protocol: 17, natPort: 40000, remoteIP: target1, remotePort: 53}
	if b1, ok := dem.remoteBindings[bKey1]; ok && b1 != nil {
		releasedAt1 = b1.releasedAt
	} else {
		t.Fatal("binding 1 not found in remoteBindings")
	}
	dem.mu.RUnlock()

	if releasedAt1.IsZero() {
		t.Fatal("expected binding 1 to have non-zero releasedAt")
	}

	// Advance time and retire flow 2
	time.Sleep(30 * time.Millisecond)
	dem.PurgeSession("sess-2")

	// Verify binding 1's timestamp was NOT updated by session 2's retirement
	dem.mu.RLock()
	b1After := dem.remoteBindings[bKey1]
	if b1After == nil {
		t.Fatal("binding 1 unexpectedly disappeared")
	}
	if !b1After.releasedAt.Equal(releasedAt1) {
		t.Fatalf("binding 1 releasedAt mutated by unrelated release! before=%v, after=%v", releasedAt1, b1After.releasedAt)
	}
	dem.mu.RUnlock()
}

func TestNAT_SetMaxBindingsAndNilReceiver(t *testing.T) {
	var nilDem *DirectEgressManager
	nilDem.SetMaxBindings(10)
	if count := nilDem.RemoteBindingCount(); count != 0 {
		t.Fatalf("expected 0 for nil receiver, got %d", count)
	}

	dem := NewDirectEgressManager(DirectEgressConfig{}, nil)
	defer func() { _ = dem.Close() }()

	dem.SetMaxBindings(50)
	dem.mu.RLock()
	if dem.maxBindings != 50 {
		t.Fatalf("expected maxBindings=50, got %d", dem.maxBindings)
	}
	dem.mu.RUnlock()

	dem.SetMaxBindings(0)
	dem.mu.RLock()
	if dem.maxBindings != defaultMaxRemoteBindings {
		t.Fatalf("expected defaultMaxRemoteBindings, got %d", dem.maxBindings)
	}
	dem.mu.RUnlock()
}
