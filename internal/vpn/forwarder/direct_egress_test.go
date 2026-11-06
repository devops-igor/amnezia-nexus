package forwarder

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func buildTestIPv4TCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags uint8, payload []byte) []byte {
	ihl := 20
	tcpHdrLen := 20
	totalLen := ihl + tcpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // #nosec G115
	binary.BigEndian.PutUint16(pkt[4:6], 1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64                                  // TTL
	pkt[9] = 6                                   // TCP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	ipCS := computeIPv4Checksum(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	// TCP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], 1000) // Seq
	binary.BigEndian.PutUint32(pkt[28:32], 0)    // Ack
	pkt[32] = 0x50                               // Data offset = 5 (20 bytes)
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 65535) // Window
	copy(pkt[40:], payload)

	tcpCS := computeL4Checksum(srcBytes, dstBytes, 6, pkt[20:])
	binary.BigEndian.PutUint16(pkt[36:38], tcpCS)

	return pkt
}

func buildTestIPv4UDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 20
	udpHdrLen := 8
	totalLen := ihl + udpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // #nosec G115
	binary.BigEndian.PutUint16(pkt[4:6], 1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 17 // UDP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	ipCS := computeIPv4Checksum(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], ipCS)

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpHdrLen+len(payload))) // #nosec G115
	copy(pkt[28:], payload)

	udpCS := computeL4Checksum(srcBytes, dstBytes, 17, pkt[20:])
	binary.BigEndian.PutUint16(pkt[26:28], udpCS)

	return pkt
}

type testCaptureReturnPath struct {
	mu      sync.Mutex
	packets [][]byte
	path    *ReturnPath
}

func newTestCaptureReturnPath() *testCaptureReturnPath {
	c := &testCaptureReturnPath{}
	c.path = NewReturnPath(func(peerKey, assignedIP string, packet []byte) (int, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		cp := make([]byte, len(packet))
		copy(cp, packet)
		c.packets = append(c.packets, cp)
		return len(packet), nil
	})
	return c
}

func (c *testCaptureReturnPath) getPackets() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := make([][]byte, len(c.packets))
	copy(res, c.packets)
	return res
}

func TestDirectEgress_IsProhibitedDestination(t *testing.T) {
	gwDNS := netip.MustParseAddr("10.100.0.1")
	cfg := DirectEgressConfig{
		HostWANIP:    netip.MustParseAddr("203.0.113.1"),
		GatewayDNSIP: gwDNS,
	}
	dem := NewDirectEgressManager(cfg, nil)
	defer func() { _ = dem.Close() }()

	tests := []struct {
		name       string
		addr       string
		prohibited bool
	}{
		{"loopback localhost", "127.0.0.1", true},
		{"loopback high", "127.255.255.254", true},
		{"link-local unicast", "169.254.1.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"RFC1918 10/8", "10.0.0.5", true},
		{"RFC1918 172.16/12", "172.16.5.5", true},
		{"RFC1918 192.168/16", "192.168.1.1", true},
		{"multicast 224/4", "224.0.0.1", true},
		{"unspecified 0.0.0.0", "0.0.0.0", true},
		{"broadcast 255.255.255.255", "255.255.255.255", true},
		{"designated gateway DNS", "10.100.0.1", false}, // EXPLICIT EXCEPTION
		{"public Cloudflare DNS", "1.1.1.1", false},
		{"public Google DNS", "8.8.8.8", false},
		{"public example.com", "93.184.216.34", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.addr)
			got := dem.IsProhibitedDestination(ip)
			if got != tt.prohibited {
				t.Errorf("IsProhibitedDestination(%s) = %v, want %v", tt.addr, got, tt.prohibited)
			}
		})
	}
}

func TestDirectEgress_TCP(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.50")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: hostWAN,
		WANDevice: wanDev,
	}, nil)
	defer func() { _ = dem.Close() }()

	clientIP := netip.MustParseAddr("10.100.0.2")
	targetIP := netip.MustParseAddr("93.184.216.34")
	clientPort := uint16(51234)
	targetPort := uint16(80)

	capPath := newTestCaptureReturnPath()
	peerKey := "peer-test-tcp"

	// 1. Client sends TCP SYN
	synPkt := buildTestIPv4TCPPacket(clientIP, targetIP, clientPort, targetPort, 0x02, nil)
	err := dem.RouteTCPDirect(peerKey, synPkt, capPath.path)
	if err != nil {
		t.Fatalf("RouteTCPDirect failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected 1 WAN packet, got %d", len(wanPkts))
	}
	fwdPkt := wanPkts[0]

	// Verify SNAT
	srcIP := netip.AddrFrom4([4]byte{fwdPkt[12], fwdPkt[13], fwdPkt[14], fwdPkt[15]})
	if srcIP != hostWAN {
		t.Errorf("expected SNAT source IP %s, got %s", hostWAN, srcIP)
	}
	natPort := binary.BigEndian.Uint16(fwdPkt[20:22])
	if natPort < defaultMinNATPort || natPort > defaultMaxNATPort {
		t.Errorf("allocated natPort %d outside expected range", natPort)
	}
	dstIP := netip.AddrFrom4([4]byte{fwdPkt[16], fwdPkt[17], fwdPkt[18], fwdPkt[19]})
	if dstIP != targetIP {
		t.Errorf("expected target IP %s, got %s", targetIP, dstIP)
	}

	// Verify checksums
	if computeIPv4Checksum(fwdPkt[:20]) != 0 {
		t.Errorf("IPv4 checksum invalid")
	}
	if computeL4Checksum(hostWAN.As4(), targetIP.As4(), 6, fwdPkt[20:]) != 0 {
		t.Errorf("TCP checksum invalid")
	}

	// 2. WAN sends TCP SYN-ACK reply
	replyPkt := buildTestIPv4TCPPacket(targetIP, hostWAN, targetPort, natPort, 0x12, nil)
	err = dem.HandleWANReply(replyPkt)
	if err != nil {
		t.Fatalf("HandleWANReply failed: %v", err)
	}

	retPkts := capPath.getPackets()
	if len(retPkts) != 1 {
		t.Fatalf("expected 1 returned packet, got %d", len(retPkts))
	}
	clientPkt := retPkts[0]

	// Verify DNAT
	retDstIP := netip.AddrFrom4([4]byte{clientPkt[16], clientPkt[17], clientPkt[18], clientPkt[19]})
	if retDstIP != clientIP {
		t.Errorf("expected return destination IP %s, got %s", clientIP, retDstIP)
	}
	retDstPort := binary.BigEndian.Uint16(clientPkt[22:24])
	if retDstPort != clientPort {
		t.Errorf("expected return destination port %d, got %d", clientPort, retDstPort)
	}
	if computeIPv4Checksum(clientPkt[:20]) != 0 {
		t.Errorf("return IPv4 checksum invalid")
	}
	if computeL4Checksum(targetIP.As4(), clientIP.As4(), 6, clientPkt[20:]) != 0 {
		t.Errorf("return TCP checksum invalid")
	}
}

func TestDirectEgress_UDP(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.88")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: hostWAN,
		WANDevice: wanDev,
	}, nil)
	defer func() { _ = dem.Close() }()

	clientIP := netip.MustParseAddr("10.100.0.3")
	targetIP := netip.MustParseAddr("8.8.8.8")
	clientPort := uint16(43210)
	targetPort := uint16(53)

	capPath := newTestCaptureReturnPath()
	peerKey := "peer-test-udp"

	udpPayload := []byte("ping-udp")
	udpPkt := buildTestIPv4UDPPacket(clientIP, targetIP, clientPort, targetPort, udpPayload)

	err := dem.RouteUDPDirect(peerKey, udpPkt, capPath.path)
	if err != nil {
		t.Fatalf("RouteUDPDirect failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected 1 WAN packet, got %d", len(wanPkts))
	}
	fwdPkt := wanPkts[0]

	// Check SNAT
	srcIP := netip.AddrFrom4([4]byte{fwdPkt[12], fwdPkt[13], fwdPkt[14], fwdPkt[15]})
	if srcIP != hostWAN {
		t.Errorf("expected SNAT source %s, got %s", hostWAN, srcIP)
	}
	natPort := binary.BigEndian.Uint16(fwdPkt[20:22])

	// Inbound reply
	replyPayload := []byte("pong-udp")
	replyPkt := buildTestIPv4UDPPacket(targetIP, hostWAN, targetPort, natPort, replyPayload)
	err = dem.HandleWANReply(replyPkt)
	if err != nil {
		t.Fatalf("HandleWANReply failed: %v", err)
	}

	retPkts := capPath.getPackets()
	if len(retPkts) != 1 {
		t.Fatalf("expected 1 returned packet, got %d", len(retPkts))
	}
	clientPkt := retPkts[0]

	retDstIP := netip.AddrFrom4([4]byte{clientPkt[16], clientPkt[17], clientPkt[18], clientPkt[19]})
	if retDstIP != clientIP {
		t.Errorf("expected DNAT dst IP %s, got %s", clientIP, retDstIP)
	}
	retDstPort := binary.BigEndian.Uint16(clientPkt[22:24])
	if retDstPort != clientPort {
		t.Errorf("expected DNAT dst port %d, got %d", clientPort, retDstPort)
	}
}

func TestDirectEgress_FlowStickiness(t *testing.T) {
	dem := NewDirectEgressManager(DirectEgressConfig{}, nil)
	defer func() { _ = dem.Close() }()

	clientIP := netip.MustParseAddr("10.100.0.5")
	targetIP := netip.MustParseAddr("1.1.1.1")
	pkt := buildTestIPv4TCPPacket(clientIP, targetIP, 12345, 443, 0x02, nil)
	peerKey := "peer-sticky"

	// Initially no flow
	choice, found := dem.LookupFlow(peerKey, pkt)
	if found || choice != EgressChoiceNone {
		t.Fatalf("expected no initial flow, got choice %v found %v", choice, found)
	}

	// Record PROXY choice
	dem.RecordFlow(peerKey, pkt, EgressChoiceProxy)

	choice, found = dem.LookupFlow(peerKey, pkt)
	if !found || choice != EgressChoiceProxy {
		t.Fatalf("expected sticky PROXY choice, got choice %v found %v", choice, found)
	}

	// Change to DIRECT
	dem.RecordFlow(peerKey, pkt, EgressChoiceDirect)
	choice, found = dem.LookupFlow(peerKey, pkt)
	if !found || choice != EgressChoiceDirect {
		t.Fatalf("expected sticky DIRECT choice, got choice %v found %v", choice, found)
	}
}

func TestDirectEgress_FlowExpirationAndCleanup(t *testing.T) {
	dem := NewDirectEgressManager(DirectEgressConfig{
		UDPTimeout: 50 * time.Millisecond,
		TCPTimeout: 50 * time.Millisecond,
	}, nil)
	defer func() { _ = dem.Close() }()

	clientIP := netip.MustParseAddr("10.100.0.10")
	targetIP := netip.MustParseAddr("8.8.8.8")
	pkt := buildTestIPv4UDPPacket(clientIP, targetIP, 50000, 53, []byte("test"))
	peerKey := "peer-expire"

	dem.RecordFlow(peerKey, pkt, EgressChoiceDirect)
	_, found := dem.LookupFlow(peerKey, pkt)
	if !found {
		t.Fatal("expected flow to be found immediately")
	}

	// PurgePeer cleans up immediately
	dem.PurgePeer(peerKey)
	_, found = dem.LookupFlow(peerKey, pkt)
	if found {
		t.Fatal("expected flow to be purged after PurgePeer")
	}

	// Re-record and test Sweep
	dem.RecordFlow(peerKey, pkt, EgressChoiceDirect)
	time.Sleep(70 * time.Millisecond)
	dem.Sweep(time.Now())
	_, found = dem.LookupFlow(peerKey, pkt)
	if found {
		t.Fatal("expected flow to be expired after sweep")
	}
}

func TestDirectEgress_ClientIsolation(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: hostWAN,
		WANDevice: wanDev,
	}, nil)
	defer func() { _ = dem.Close() }()

	clientA := netip.MustParseAddr("10.100.0.101")
	clientB := netip.MustParseAddr("10.100.0.102")
	targetIP := netip.MustParseAddr("93.184.216.34")

	capA := newTestCaptureReturnPath()
	capB := newTestCaptureReturnPath()

	// Both clients happen to use source port 4000 to same destination 80
	pktA := buildTestIPv4TCPPacket(clientA, targetIP, 4000, 80, 0x02, nil)
	pktB := buildTestIPv4TCPPacket(clientB, targetIP, 4000, 80, 0x02, nil)

	if err := dem.RouteTCPDirect("peerA", pktA, capA.path); err != nil {
		t.Fatalf("client A direct route failed: %v", err)
	}
	if err := dem.RouteTCPDirect("peerB", pktB, capB.path); err != nil {
		t.Fatalf("client B direct route failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 2 {
		t.Fatalf("expected 2 WAN packets, got %d", len(wanPkts))
	}

	natPortA := binary.BigEndian.Uint16(wanPkts[0][20:22])
	natPortB := binary.BigEndian.Uint16(wanPkts[1][20:22])

	if natPortA == natPortB {
		t.Fatalf("NAT ports for Client A and Client B must be distinct, got %d for both", natPortA)
	}

	// Send reply to Client A's NAT port
	replyA := buildTestIPv4TCPPacket(targetIP, hostWAN, 80, natPortA, 0x12, nil)
	if err := dem.HandleWANReply(replyA); err != nil {
		t.Fatalf("HandleWANReply A failed: %v", err)
	}

	if len(capA.getPackets()) != 1 {
		t.Fatalf("Client A must receive 1 packet, got %d", len(capA.getPackets()))
	}
	if len(capB.getPackets()) != 0 {
		t.Fatalf("Client B must receive 0 packets, got %d", len(capB.getPackets()))
	}
}

func TestDirectEgress_ProhibitedDrops(t *testing.T) {
	dem := NewDirectEgressManager(DirectEgressConfig{
		GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
	}, nil)
	defer func() { _ = dem.Close() }()

	capPath := newTestCaptureReturnPath()
	clientIP := netip.MustParseAddr("10.100.0.2")

	prohibitedTargets := []string{
		"127.0.0.1",
		"169.254.169.254",
		"10.0.0.5",
		"172.16.1.1",
		"192.168.1.1",
		"224.0.0.1",
	}

	for _, target := range prohibitedTargets {
		pkt := buildTestIPv4TCPPacket(clientIP, netip.MustParseAddr(target), 12345, 80, 0x02, nil)
		err := dem.RouteTCPDirect("peer-prohibited", pkt, capPath.path)
		if err != ErrProhibitedDestination {
			t.Errorf("expected ErrProhibitedDestination for target %s, got %v", target, err)
		}
	}

	if dem.DirectDrops() != uint64(len(prohibitedTargets)) {
		t.Errorf("expected %d directDrops, got %d", len(prohibitedTargets), dem.DirectDrops())
	}
}

func TestDirectEgress_LookupExpirationAndBidirectionalRefresh(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  wanDev,
		UDPTimeout: 60 * time.Millisecond,
		TCPTimeout: 60 * time.Millisecond,
		MinPort:    50000,
		MaxPort:    50001, // exactly 2 ports
		MaxFlows:   2,
	}, nil)
	defer func() { _ = dem.Close() }()

	capPath := newTestCaptureReturnPath()
	clientIP := netip.MustParseAddr("10.100.0.5")
	targetIP := netip.MustParseAddr("8.8.8.8")
	pkt := buildTestIPv4UDPPacket(clientIP, targetIP, 10001, 53, []byte("f3-test"))
	peerKey := "peer-f3"

	// 1. Record flow and verify it expires on LookupFlow without Sweep
	dem.RecordFlow(peerKey, pkt, EgressChoiceDirect)
	if choice, found := dem.LookupFlow(peerKey, pkt); !found || choice != EgressChoiceDirect {
		t.Fatalf("expected immediate flow lookup success, got %v, %v", choice, found)
	}

	time.Sleep(80 * time.Millisecond)
	if choice, found := dem.LookupFlow(peerKey, pkt); found || choice != EgressChoiceNone {
		t.Fatalf("expected expired flow to return false on LookupFlow, got %v, %v", choice, found)
	}

	// 2. Bidirectional lastSeen refresh via WAN reply
	pkt2 := buildTestIPv4UDPPacket(clientIP, targetIP, 10002, 53, []byte("refresh-test"))
	if err := dem.RouteUDPDirect(peerKey, pkt2, capPath.path); err != nil {
		t.Fatalf("RouteUDPDirect failed: %v", err)
	}
	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected 1 wan packet, got %d", len(wanPkts))
	}
	natPort := binary.BigEndian.Uint16(wanPkts[0][20:22])

	// Sleep 40ms, send reply to refresh lastSeen
	time.Sleep(40 * time.Millisecond)
	reply := buildTestIPv4UDPPacket(targetIP, hostWAN, 53, natPort, []byte("reply-refresh"))
	if err := dem.HandleWANReply(reply); err != nil {
		t.Fatalf("HandleWANReply failed: %v", err)
	}

	// Sleep another 40ms (total elapsed since outbound = 80ms > 60ms timeout, but only 40ms since reply)
	time.Sleep(40 * time.Millisecond)
	if choice, found := dem.LookupFlow(peerKey, pkt2); !found || choice != EgressChoiceDirect {
		t.Fatalf("expected flow to remain active due to WAN reply refresh, got %v, %v", choice, found)
	}

	// 3. Port exhaustion and automatic sweep during allocation
	// Wait for pkt2 to expire
	time.Sleep(80 * time.Millisecond)
	// We had minPort 50000, maxPort 50001 (2 ports total). Allocate both.
	p1 := buildTestIPv4UDPPacket(clientIP, targetIP, 20001, 53, []byte("p1"))
	p2 := buildTestIPv4UDPPacket(clientIP, targetIP, 20002, 53, []byte("p2"))
	if err := dem.RouteUDPDirect(peerKey, p1, capPath.path); err != nil {
		t.Fatalf("alloc p1 failed: %v", err)
	}
	if err := dem.RouteUDPDirect(peerKey, p2, capPath.path); err != nil {
		t.Fatalf("alloc p2 failed: %v", err)
	}

	// Immediate 3rd allocation should fail with ErrNATPortExhaustion
	p3 := buildTestIPv4UDPPacket(clientIP, targetIP, 20003, 53, []byte("p3"))
	if err := dem.RouteUDPDirect(peerKey, p3, capPath.path); err != ErrNATPortExhaustion && err != ErrFlowTableFull {
		t.Fatalf("expected exhaustion error, got: %v", err)
	}

	// Wait for p1 and p2 to expire (>60ms)
	time.Sleep(80 * time.Millisecond)

	// Now 3rd allocation should reclaim expired ports during allocation
	if err := dem.RouteUDPDirect(peerKey, p3, capPath.path); err != nil {
		t.Fatalf("expected allocation after sweep to succeed, got: %v", err)
	}

	// 4. MaxFlows strict enforcement
	p4 := buildTestIPv4UDPPacket(clientIP, targetIP, 20004, 53, []byte("p4"))
	if err := dem.RouteUDPDirect(peerKey, p4, capPath.path); err != nil {
		t.Fatalf("alloc p4 failed: %v", err)
	}
	// MaxFlows is 2, p3 and p4 are active. 5th flow should hit capacity
	p5 := buildTestIPv4UDPPacket(clientIP, targetIP, 20005, 53, []byte("p5"))
	if err := dem.RouteUDPDirect(peerKey, p5, capPath.path); err != ErrFlowTableFull && err != ErrNATPortExhaustion {
		t.Fatalf("expected ErrFlowTableFull or exhaustion when capacity reached, got: %v", err)
	}
}

func TestDirectEgress_WANReplyEndpointVerification(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: hostWAN,
		WANDevice: wanDev,
	}, nil)
	defer func() { _ = dem.Close() }()

	capPath := newTestCaptureReturnPath()
	clientIP := netip.MustParseAddr("10.100.0.15")
	targetIP := netip.MustParseAddr("93.184.216.34")
	peerKey := "peer-f4"

	pkt := buildTestIPv4TCPPacket(clientIP, targetIP, 12345, 80, 0x02, nil)
	if err := dem.RouteTCPDirect(peerKey, pkt, capPath.path); err != nil {
		t.Fatalf("RouteTCPDirect failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected 1 wan packet, got %d", len(wanPkts))
	}
	natPort := binary.BigEndian.Uint16(wanPkts[0][20:22])

	// Case 1: Destination IP does not match hostWAN
	wrongDstReply := buildTestIPv4TCPPacket(targetIP, netip.MustParseAddr("203.0.113.99"), 80, natPort, 0x12, nil)
	if err := dem.HandleWANReply(wrongDstReply); err == nil {
		t.Fatalf("expected error for mismatched destination IP, got nil")
	}

	// Case 2: Spoofed remote source IP
	spoofedIPReply := buildTestIPv4TCPPacket(netip.MustParseAddr("1.2.3.4"), hostWAN, 80, natPort, 0x12, nil)
	if err := dem.HandleWANReply(spoofedIPReply); err == nil {
		t.Fatalf("expected error for spoofed remote source IP, got nil")
	}

	// Case 3: Spoofed remote source port
	spoofedPortReply := buildTestIPv4TCPPacket(targetIP, hostWAN, 8080, natPort, 0x12, nil)
	if err := dem.HandleWANReply(spoofedPortReply); err == nil {
		t.Fatalf("expected error for spoofed remote source port, got nil")
	}

	// Case 4: Legitimate reply succeeds
	validReply := buildTestIPv4TCPPacket(targetIP, hostWAN, 80, natPort, 0x12, nil)
	if err := dem.HandleWANReply(validReply); err != nil {
		t.Fatalf("expected valid reply to succeed, got %v", err)
	}

	if len(capPath.getPackets()) != 1 {
		t.Fatalf("expected 1 delivered packet to client, got %d", len(capPath.getPackets()))
	}
}
