package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestValidation_ProhibitedDestinations(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		prohibited bool
	}{
		{"0.0.0.0/8 unspecified", "0.0.0.1", true},
		{"10.0.0.0/8 RFC1918", "10.0.0.1", true},
		{"100.64.0.0/10 CGNAT lower", "100.64.0.1", true},
		{"100.64.0.0/10 CGNAT mid", "100.100.50.25", true},
		{"100.64.0.0/10 CGNAT upper", "100.127.255.254", true},
		{"100.128.0.1 public outside CGNAT", "100.128.0.1", false},
		{"127.0.0.0/8 loopback", "127.0.0.1", true},
		{"169.254.0.0/16 link-local", "169.254.1.1", true},
		{"169.254.169.254 cloud metadata", "169.254.169.254", true},
		{"172.16.0.0/12 RFC1918", "172.16.0.1", true},
		{"172.31.255.254 RFC1918", "172.31.255.254", true},
		{"192.0.0.0/24 IETF protocol", "192.0.0.1", true},
		{"192.0.2.0/24 TEST-NET-1", "192.0.2.55", true},
		{"192.168.0.0/16 RFC1918", "192.168.1.1", true},
		{"198.18.0.0/15 benchmark", "198.18.1.1", true},
		{"198.19.255.254 benchmark", "198.19.255.254", true},
		{"198.51.100.0/24 TEST-NET-2", "198.51.100.1", true},
		{"203.0.113.0/24 TEST-NET-3", "203.0.113.1", true},
		{"224.0.0.0/4 multicast", "224.0.0.1", true},
		{"239.255.255.250 SSDP multicast", "239.255.255.250", true},
		{"240.0.0.0/4 reserved", "240.0.0.1", true},
		{"255.255.255.255 broadcast", "255.255.255.255", true},
		{"1.1.1.1 public Cloudflare", "1.1.1.1", false},
		{"8.8.8.8 public Google", "8.8.8.8", false},
		{"93.184.216.34 public example.com", "93.184.216.34", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.ip)
			got := IsProhibitedIPv4Destination(addr)
			if got != tt.prohibited {
				t.Errorf("IsProhibitedIPv4Destination(%s) = %v, want %v", tt.ip, got, tt.prohibited)
			}
		})
	}
}

func TestValidation_GatewayDNSNarrowScoping(t *testing.T) {
	gwDNS := netip.MustParseAddr("10.100.0.1")

	// Port 53 must be allowed (DNS exception)
	if err := ValidateDirectDestination(gwDNS, 53, gwDNS); err != nil {
		t.Fatalf("expected port 53 to gateway DNS to be allowed, got: %v", err)
	}

	// Any non-53 port to gateway DNS must be dropped
	nonDNSPorts := []uint16{80, 443, 22, 5353, 8080}
	for _, port := range nonDNSPorts {
		err := ValidateDirectDestination(gwDNS, port, gwDNS)
		if !errors.Is(err, ErrProhibitedDestination) {
			t.Errorf("expected ErrProhibitedDestination for gateway DNS port %d, got: %v", port, err)
		}
	}
}

func TestValidation_StrictSourceIPValidation(t *testing.T) {
	clientIP := netip.MustParseAddr("10.100.0.2")
	targetIP := netip.MustParseAddr("1.1.1.1")

	// Valid matching source
	validPkt := buildTestIPv4UDPPacket(clientIP, targetIP, 12345, 53, []byte("data"))
	parsed, err := ParseAndValidateClientIPv4(validPkt, clientIP.String())
	if err != nil {
		t.Fatalf("expected valid packet to parse, got %v", err)
	}
	if parsed.SrcIP != clientIP {
		t.Errorf("expected parsed SrcIP %v, got %v", clientIP, parsed.SrcIP)
	}

	// Source 0.0.0.0 must be rejected
	zeroSrcPkt := buildTestIPv4UDPPacket(netip.MustParseAddr("0.0.0.0"), targetIP, 12345, 53, []byte("data"))
	_, err = ParseAndValidateClientIPv4(zeroSrcPkt, clientIP.String())
	if !errors.Is(err, ErrInvalidSourceIP) {
		t.Errorf("expected ErrInvalidSourceIP for source 0.0.0.0, got: %v", err)
	}

	// Mismatched source IP must be rejected
	wrongSrcPkt := buildTestIPv4UDPPacket(netip.MustParseAddr("10.100.0.99"), targetIP, 12345, 53, []byte("data"))
	_, err = ParseAndValidateClientIPv4(wrongSrcPkt, clientIP.String())
	if !errors.Is(err, ErrInvalidSourceIP) {
		t.Errorf("expected ErrInvalidSourceIP for mismatched client IP, got: %v", err)
	}
}

func TestValidation_IPv4HeaderAndFragmentation(t *testing.T) {
	clientIP := netip.MustParseAddr("10.100.0.2")
	targetIP := netip.MustParseAddr("1.1.1.1")

	basePkt := buildTestIPv4TCPPacket(clientIP, targetIP, 12345, 80, 0x02, nil)

	// Truncated packet (< 20 bytes)
	_, err := ParseAndValidateClientIPv4(basePkt[:15], clientIP.String())
	if !errors.Is(err, ErrInvalidIPv4Packet) {
		t.Errorf("expected ErrInvalidIPv4Packet for packet < 20 bytes, got: %v", err)
	}

	// Invalid version (IPv6 instead of IPv4)
	v6Pkt := append([]byte(nil), basePkt...)
	v6Pkt[0] = 0x65 // Version 6
	_, err = ParseAndValidateClientIPv4(v6Pkt, clientIP.String())
	if !errors.Is(err, ErrInvalidIPv4Packet) {
		t.Errorf("expected ErrInvalidIPv4Packet for version != 4, got: %v", err)
	}

	// IHL < 5 (e.g. 4 -> 16 bytes)
	ihlShort := append([]byte(nil), basePkt...)
	ihlShort[0] = 0x44
	_, err = ParseAndValidateClientIPv4(ihlShort, clientIP.String())
	if !errors.Is(err, ErrInvalidIPv4Packet) {
		t.Errorf("expected ErrInvalidIPv4Packet for IHL < 5, got: %v", err)
	}

	// Total length greater than buffer length
	totLenOverflow := append([]byte(nil), basePkt...)
	binary.BigEndian.PutUint16(totLenOverflow[2:4], uint16(len(basePkt)+50))
	_, err = ParseAndValidateClientIPv4(totLenOverflow, clientIP.String())
	if !errors.Is(err, ErrInvalidIPv4Packet) {
		t.Errorf("expected ErrInvalidIPv4Packet for total length > buffer, got: %v", err)
	}

	// Total length less than header length
	totLenUnderflow := append([]byte(nil), basePkt...)
	binary.BigEndian.PutUint16(totLenUnderflow[2:4], 10)
	_, err = ParseAndValidateClientIPv4(totLenUnderflow, clientIP.String())
	if !errors.Is(err, ErrInvalidIPv4Packet) {
		t.Errorf("expected ErrInvalidIPv4Packet for total length < IHL, got: %v", err)
	}

	// Fragmented: More Fragments (MF) flag set (bit 13 -> 0x2000)
	mfPkt := append([]byte(nil), basePkt...)
	binary.BigEndian.PutUint16(mfPkt[6:8], 0x2000)
	_, err = ParseAndValidateClientIPv4(mfPkt, clientIP.String())
	if !errors.Is(err, ErrPacketFragmented) {
		t.Errorf("expected ErrPacketFragmented for MF=1, got: %v", err)
	}

	// Fragmented: Fragment Offset > 0 (e.g. offset = 100)
	fragOffPkt := append([]byte(nil), basePkt...)
	binary.BigEndian.PutUint16(fragOffPkt[6:8], 0x0064)
	_, err = ParseAndValidateClientIPv4(fragOffPkt, clientIP.String())
	if !errors.Is(err, ErrPacketFragmented) {
		t.Errorf("expected ErrPacketFragmented for fragment offset > 0, got: %v", err)
	}

	// Truncated TCP header (< 20 bytes transport)
	tcpTrunc := append([]byte(nil), basePkt[:35]...)
	binary.BigEndian.PutUint16(tcpTrunc[2:4], 35)
	_, err = ParseAndValidateClientIPv4(tcpTrunc, clientIP.String())
	if !errors.Is(err, ErrInvalidTransportHdr) {
		t.Errorf("expected ErrInvalidTransportHdr for truncated TCP header, got: %v", err)
	}

	// Truncated UDP header (< 8 bytes transport)
	udpBase := buildTestIPv4UDPPacket(clientIP, targetIP, 12345, 53, []byte("data"))
	udpTrunc := append([]byte(nil), udpBase[:25]...)
	binary.BigEndian.PutUint16(udpTrunc[2:4], 25)
	_, err = ParseAndValidateClientIPv4(udpTrunc, clientIP.String())
	if !errors.Is(err, ErrInvalidTransportHdr) {
		t.Errorf("expected ErrInvalidTransportHdr for truncated UDP header, got: %v", err)
	}
}

func TestValidation_DelayedRepliesOnNATPortReuse(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.10")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  wanDev,
		UDPTimeout: 5 * time.Second,
		TCPTimeout: 5 * time.Second,
		MinPort:    55000,
		MaxPort:    55000, // exactly 1 port to force immediate reuse
	}, nil)
	defer func() { _ = dem.Close() }()
	// Set cooldown to 0 for this immediate-reuse test
	dem.SetPortCooldown(0)

	capPath1 := newTestCaptureReturnPath()
	clientIP := netip.MustParseAddr("10.100.0.5")
	targetIP := netip.MustParseAddr("1.1.1.1")

	// 1. Session 1 sends outbound packet
	session1 := "session-1"
	pkt1 := buildTestIPv4UDPPacket(clientIP, targetIP, 10001, 53, []byte("req-1"))
	if err := dem.RouteDirect("peer-1", clientIP.String(), session1, uint64(1), pkt1, capPath1.path); err != nil {
		t.Fatalf("Session 1 RouteDirect failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected 1 wan packet, got %d", len(wanPkts))
	}
	natPort := binary.BigEndian.Uint16(wanPkts[0][20:22])
	if natPort != 55000 {
		t.Fatalf("expected natPort 55000, got %d", natPort)
	}

	// 2. Terminate Session 1
	dem.PurgeSession(session1)

	// 3. Session 2 allocates the same recycled NAT port 55000 for a different destination
	capPath2 := newTestCaptureReturnPath()
	session2 := "session-2"
	targetIP2 := netip.MustParseAddr("8.8.8.8")
	pkt2 := buildTestIPv4UDPPacket(clientIP, targetIP2, 20002, 53, []byte("req-2"))
	if err := dem.RouteDirect("peer-2", clientIP.String(), session2, uint64(2), pkt2, capPath2.path); err != nil {
		t.Fatalf("Session 2 RouteDirect failed: %v", err)
	}

	// 4. Delayed reply arrives from Session 1 (same targetIP, same natPort)
	// Because Session 2 reallocated the port with a new epoch, Session 1's reply must be rejected as stale
	delayedReply := buildTestIPv4UDPPacket(targetIP, hostWAN, 53, natPort, []byte("delayed-reply-session-1"))

	// In dem.inboundNAT, the active entry belongs to Session 2 with epoch 2.
	dem.mu.Lock()
	inKey := inboundKey{protocol: 17, natPort: natPort}
	activeEntry := dem.inboundNAT[inKey]
	if activeEntry == nil || activeEntry.sessionID != session2 {
		dem.mu.Unlock()
		t.Fatalf("expected active entry for session-2, got %v", activeEntry)
	}
	dem.mu.Unlock()

	// Verify delayed reply from Session 1 is fenced via tombstone and does NOT leak to Session 2
	err := dem.HandleWANReply(delayedReply)
	if !errors.Is(err, ErrStaleSessionReply) {
		t.Fatalf("expected ErrStaleSessionReply on recycled port tombstone match, got: %v", err)
	}
	if len(capPath2.getPackets()) != 0 {
		t.Fatalf("session 2 received delayed reply belonging to session 1; tenant isolation violated")
	}

	// Verify valid reply for Session 2 is admitted and delivered
	validReply2 := buildTestIPv4UDPPacket(targetIP2, hostWAN, 53, natPort, []byte("reply-2"))
	if err := dem.HandleWANReply(validReply2); err != nil {
		t.Fatalf("expected Session 2 reply to succeed, got: %v", err)
	}
	if len(capPath2.getPackets()) != 1 {
		t.Fatalf("expected exactly 1 packet delivered to session 2, got %d", len(capPath2.getPackets()))
	}
}

func TestValidation_TenantIsolationBlocksPortReuseSameRemoteEndpoint(t *testing.T) {
	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.10")
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  wanDev,
		UDPTimeout: 5 * time.Second,
		TCPTimeout: 5 * time.Second,
		MinPort:    55000,
		MaxPort:    55000, // exactly 1 port to force conflict
	}, nil)
	defer func() { _ = dem.Close() }()
	dem.SetPortCooldown(0)

	capPath1 := newTestCaptureReturnPath()
	clientIP := netip.MustParseAddr("10.100.0.5")
	targetIP := netip.MustParseAddr("1.1.1.1")

	// Session 1 from peer-1
	session1 := "session-1"
	pkt1 := buildTestIPv4UDPPacket(clientIP, targetIP, 10001, 53, []byte("req-1"))
	if err := dem.RouteDirect("peer-1", clientIP.String(), session1, uint64(1), pkt1, capPath1.path); err != nil {
		t.Fatalf("Session 1 RouteDirect failed: %v", err)
	}

	// Terminate Session 1
	dem.PurgeSession(session1)

	// Session 2 from peer-2 (different tenant) tries to use same port for same targetIP:53
	capPath2 := newTestCaptureReturnPath()
	session2 := "session-2"
	pkt2 := buildTestIPv4UDPPacket(clientIP, targetIP, 20002, 53, []byte("req-2"))
	err := dem.RouteDirect("peer-2", clientIP.String(), session2, uint64(2), pkt2, capPath2.path)
	if !errors.Is(err, ErrNATPortExhaustion) {
		t.Fatalf("expected ErrNATPortExhaustion when reusing port for same remote endpoint across tenants, got: %v", err)
	}
}

func TestValidation_FlowTableExhaustion(t *testing.T) {
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		MaxFlows:  2,
	}, nil)
	defer func() { _ = dem.Close() }()

	clientIP := netip.MustParseAddr("10.100.0.5")
	targetIP := netip.MustParseAddr("1.1.1.1")

	p1 := buildTestIPv4UDPPacket(clientIP, targetIP, 10001, 53, []byte("p1"))
	p2 := buildTestIPv4UDPPacket(clientIP, targetIP, 10002, 53, []byte("p2"))
	p3 := buildTestIPv4UDPPacket(clientIP, targetIP, 10003, 53, []byte("p3"))

	if err := dem.RecordFlow("peer-1", p1, EgressChoiceDirect); err != nil {
		t.Fatalf("RecordFlow p1 failed: %v", err)
	}
	if err := dem.RecordFlow("peer-1", p2, EgressChoiceDirect); err != nil {
		t.Fatalf("RecordFlow p2 failed: %v", err)
	}

	// 3rd flow should fail with ErrFlowTableFull
	err := dem.RecordFlow("peer-1", p3, EgressChoiceDirect)
	if !errors.Is(err, ErrFlowTableFull) {
		t.Fatalf("expected ErrFlowTableFull on 3rd flow, got: %v", err)
	}
}
