package forwarder

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

type testRouteCache struct {
	mu        sync.Mutex
	decisions map[string]map[netip.Addr]policy.Decision
}

func newTestRouteCache() *testRouteCache {
	return &testRouteCache{
		decisions: make(map[string]map[netip.Addr]policy.Decision),
	}
}

func (c *testRouteCache) Set(sessionID string, ip netip.Addr, d policy.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.decisions[sessionID] == nil {
		c.decisions[sessionID] = make(map[netip.Addr]policy.Decision)
	}
	c.decisions[sessionID][ip] = d
}

func (c *testRouteCache) Lookup(sessionID string, ip netip.Addr) policy.Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sess, ok := c.decisions[sessionID]; ok {
		if d, ok := sess[ip]; ok {
			return d
		}
	}
	return policy.Unknown
}

func setupForwarderWithPBR(t *testing.T) (*Forwarder, *DirectEgressManager, *mockPacketDev, *testRouteCache) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(true)

	wanDev := newMockPacketDev()
	hostWAN := netip.MustParseAddr("203.0.113.1")
	gwDNS := netip.MustParseAddr("10.100.0.1")

	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:    hostWAN,
		GatewayDNSIP: gwDNS,
		WANDevice:    wanDev,
	}, fwd)
	fwd.SetDirectEgress(dem)
	fwd.SetGatewayDNSIP(gwDNS)

	rc := newTestRouteCache()
	fwd.SetRouteCache(rc)

	return fwd, dem, wanDev, rc
}

func TestPolicyDispatch_PBROff_AllProxy(t *testing.T) {
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(false) // PBR OFF

	peerKey := "peer-pbr-off"
	backendID := int64(101)
	clientIP := "10.100.0.5"

	fwd.RegisterSession("s-off", "c-off", peerKey, clientIP, backendID)

	beQueue := fwd.backendQueues[backendID]
	targetIP := netip.MustParseAddr("93.184.216.34")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 12345, 80, 0x02, nil)

	err := fwd.RouteClientToBackend(peerKey, pkt)
	if err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}

	if len(beQueue) != 1 {
		t.Fatalf("expected packet in proxy backend queue, got %d", len(beQueue))
	}

	// Under PBR OFF, proxiedBytes and directBytes remain 0
	if fwd.ProxiedBytes() != 0 || fwd.DirectBytes() != 0 {
		t.Fatalf("expected 0 PBR bytes when PBR disabled, got proxied=%d direct=%d", fwd.ProxiedBytes(), fwd.DirectBytes())
	}
}

func TestPolicyDispatch_ProhibitedDestinations(t *testing.T) {
	fwd, _, _, _ := setupForwarderWithPBR(t)

	peerKey := "peer-prohibited"
	backendID := int64(201)
	clientIP := "10.100.0.10"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath("s-proh", "c-proh", peerKey, clientIP, backendID, capPath.path)

	prohibitedTargets := []string{
		"127.0.0.1",
		"127.255.0.1",
		"169.254.1.1",
		"169.254.169.254", // Cloud metadata
		"10.0.0.5",
		"172.16.5.5",
		"192.168.1.1",
		"224.0.0.1",
	}

	for _, target := range prohibitedTargets {
		pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), netip.MustParseAddr(target), 12345, 80, 0x02, nil)
		err := fwd.RouteClientToBackend(peerKey, pkt)
		if err != ErrProhibitedDestination {
			t.Errorf("target %s: expected ErrProhibitedDestination, got %v", target, err)
		}
	}

	if fwd.DirectDrops() != uint64(len(prohibitedTargets)) {
		t.Errorf("expected %d directDrops, got %d", len(prohibitedTargets), fwd.DirectDrops())
	}
}

func TestPolicyDispatch_GatewayDNSException(t *testing.T) {
	fwd, _, _, _ := setupForwarderWithPBR(t)

	peerKey := "peer-gwdns"
	backendID := int64(202)
	clientIP := "10.100.0.15"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath("s-gw", "c-gw", peerKey, clientIP, backendID, capPath.path)

	// Traffic to GatewayDNSIP (10.100.0.1:53) must NOT be dropped by Step 1
	gwDNS := netip.MustParseAddr("10.100.0.1")
	dnsPkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), gwDNS, 54321, 53, []byte("dns-query"))

	err := fwd.RouteClientToBackend(peerKey, dnsPkt)
	// Safe default routes to proxy backend queue
	if err != nil {
		t.Fatalf("expected gateway DNS query to be accepted, got: %v", err)
	}

	beQueue := fwd.backendQueues[backendID]
	if len(beQueue) != 1 {
		t.Fatalf("expected packet in backend queue, got %d", len(beQueue))
	}
	if fwd.DirectDrops() != 0 {
		t.Errorf("gateway DNS must not cause directDrops, got %d", fwd.DirectDrops())
	}
}

func TestPolicyDispatch_PolicySnapshotCIDRMatch(t *testing.T) {
	fwd, _, _, _ := setupForwarderWithPBR(t)

	proxyCIDR := netip.MustParsePrefix("198.51.100.0/24")
	snap, err := policy.CompileSnapshot(1, "gen-snap", []policy.SourceParsedRules{
		{
			SourceID: "test-rules",
			Rules: policy.ParsedRules{
				CIDRs: []netip.Prefix{proxyCIDR},
			},
		},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot failed: %v", err)
	}
	matcher := policy.NewMatcher()
	matcher.Publish(snap)
	fwd.SetPolicyMatcher(matcher)

	peerKey := "peer-snap"
	backendID := int64(203)
	clientIP := "10.100.0.20"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath("s-snap", "c-snap", peerKey, clientIP, backendID, capPath.path)

	// Destination within policy proxy CIDR: routes to proxy backend
	targetIP := netip.MustParseAddr("198.51.100.42")
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 23456, 443, 0x02, nil)

	err = fwd.RouteClientToBackend(peerKey, pkt)
	if err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}

	beQueue := fwd.backendQueues[backendID]
	if len(beQueue) != 1 {
		t.Fatalf("expected 1 packet in proxy backend queue, got %d", len(beQueue))
	}
	if fwd.ProxiedBytes() != int64(len(pkt)) {
		t.Errorf("expected %d proxiedBytes, got %d", len(pkt), fwd.ProxiedBytes())
	}
	if fwd.DirectBytes() != 0 {
		t.Errorf("expected 0 directBytes, got %d", fwd.DirectBytes())
	}
}

func TestPolicyDispatch_RouteCacheProxyMatch(t *testing.T) {
	fwd, _, _, rc := setupForwarderWithPBR(t)

	peerKey := "peer-rc-proxy"
	backendID := int64(204)
	clientIP := "10.100.0.25"
	sessionID := "s-rc-proxy"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionID, "c-rc-proxy", peerKey, clientIP, backendID, capPath.path)

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionID, targetIP, policy.Proxy)

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 34567, 80, 0x02, nil)
	err := fwd.RouteClientToBackend(peerKey, pkt)
	if err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}

	beQueue := fwd.backendQueues[backendID]
	if len(beQueue) != 1 {
		t.Fatalf("expected packet in proxy backend queue, got %d", len(beQueue))
	}
	if fwd.ProxiedBytes() != int64(len(pkt)) {
		t.Errorf("expected %d proxiedBytes, got %d", len(pkt), fwd.ProxiedBytes())
	}
}

func TestPolicyDispatch_RouteCacheDirectMatch(t *testing.T) {
	fwd, _, wanDev, rc := setupForwarderWithPBR(t)

	peerKey := "peer-rc-direct"
	backendID := int64(205)
	clientIP := "10.100.0.30"
	sessionID := "s-rc-direct"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionID, "c-rc-direct", peerKey, clientIP, backendID, capPath.path)

	targetIP := netip.MustParseAddr("1.1.1.1")
	rc.Set(sessionID, targetIP, policy.Direct)

	pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), targetIP, 45678, 53, []byte("dns-req"))
	err := fwd.RouteClientToBackend(peerKey, pkt)
	if err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 1 {
		t.Fatalf("expected 1 packet on direct WAN device, got %d", len(wanPkts))
	}
	if fwd.DirectBytes() != int64(len(pkt)) {
		t.Errorf("expected %d directBytes, got %d", len(pkt), fwd.DirectBytes())
	}
	if fwd.ProxiedBytes() != 0 {
		t.Errorf("expected 0 proxiedBytes, got %d", fwd.ProxiedBytes())
	}
}

func TestPolicyDispatch_UnknownRoute_SafeDefault(t *testing.T) {
	fwd, _, _, _ := setupForwarderWithPBR(t)

	peerKey := "peer-unknown"
	backendID := int64(206)
	clientIP := "10.100.0.35"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath("s-unknown", "c-unknown", peerKey, clientIP, backendID, capPath.path)

	// Destination has no DNS evidence / RouteCache returns Unknown (0) -> Safe Default to PROXY
	targetIP := netip.MustParseAddr("8.8.4.4")
	pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), targetIP, 56789, 53, []byte("dns-unknown"))

	err := fwd.RouteClientToBackend(peerKey, pkt)
	if err != nil {
		t.Fatalf("RouteClientToBackend failed: %v", err)
	}

	beQueue := fwd.backendQueues[backendID]
	if len(beQueue) != 1 {
		t.Fatalf("expected safe default to proxy backend queue, got %d", len(beQueue))
	}
	if fwd.ProxiedBytes() != int64(len(pkt)) {
		t.Errorf("expected %d proxiedBytes, got %d", len(pkt), fwd.ProxiedBytes())
	}
}

func TestPolicyDispatch_ProxyBackendUnavailable_FailClosed(t *testing.T) {
	fwd, _, wanDev, rc := setupForwarderWithPBR(t)

	peerKey := "peer-failclosed"
	backendID := int64(999) // Will delete queue to simulate backend outage
	clientIP := "10.100.0.40"
	sessionID := "s-failclosed"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionID, "c-failclosed", peerKey, clientIP, backendID, capPath.path)

	// Remove backend queue to simulate backend unavailable
	fwd.mu.Lock()
	delete(fwd.backendQueues, backendID)
	fwd.mu.Unlock()

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionID, targetIP, policy.Proxy)

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 11223, 80, 0x02, nil)
	err := fwd.RouteClientToBackend(peerKey, pkt)

	// Strict Fail-Closed: Must drop with ErrBackendNotFound, increment proxyDrops, and NEVER leak to DIRECT
	if err != ErrBackendNotFound {
		t.Fatalf("expected ErrBackendNotFound, got %v", err)
	}
	if fwd.ProxyDrops() != 1 {
		t.Errorf("expected 1 proxyDrop, got %d", fwd.ProxyDrops())
	}
	if len(wanDev.getPackets()) != 0 {
		t.Fatalf("STRICT FAIL-CLOSED VIOLATION: dropped proxy packet leaked to direct WAN device!")
	}
}

func TestPolicyDispatch_FlowStickinessAcrossTTL(t *testing.T) {
	fwd, _, wanDev, rc := setupForwarderWithPBR(t)

	peerKey := "peer-stickiness"
	backendID := int64(207)
	clientIP := "10.100.0.45"
	sessionID := "s-stickiness"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionID, "c-stickiness", peerKey, clientIP, backendID, capPath.path)

	targetIP := netip.MustParseAddr("1.1.1.1")
	rc.Set(sessionID, targetIP, policy.Direct)

	clientPort := uint16(22334)
	targetPort := uint16(443)

	// 1. Initial packet: routes DIRECT according to RouteCache
	pkt1 := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, clientPort, targetPort, 0x02, nil)
	err := fwd.RouteClientToBackend(peerKey, pkt1)
	if err != nil {
		t.Fatalf("initial packet failed: %v", err)
	}
	if len(wanDev.getPackets()) != 1 {
		t.Fatalf("expected 1 WAN packet, got %d", len(wanDev.getPackets()))
	}

	// 2. RouteCache TTL expires: now returns Unknown or Proxy
	rc.Set(sessionID, targetIP, policy.Unknown)

	// 3. Subsequent packet in active flow: must stick to DIRECT despite RouteCache change!
	pkt2 := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, clientPort, targetPort, 0x10, []byte("data"))
	err = fwd.RouteClientToBackend(peerKey, pkt2)
	if err != nil {
		t.Fatalf("sticky packet failed: %v", err)
	}

	if len(wanDev.getPackets()) != 2 {
		t.Fatalf("expected flow stickiness to direct WAN, got %d WAN packets", len(wanDev.getPackets()))
	}
	beQueue := fwd.backendQueues[backendID]
	if len(beQueue) != 0 {
		t.Fatalf("sticky DIRECT flow must not leak into proxy backend queue")
	}
}

func TestPolicyDispatch_TwoClientIsolation(t *testing.T) {
	fwd, dem, wanDev, rc := setupForwarderWithPBR(t)

	peerA := "peer-iso-A"
	peerB := "peer-iso-B"
	clientA := "10.100.0.51"
	clientB := "10.100.0.52"
	sessionA := "sess-A"
	sessionB := "sess-B"

	capA := newTestCaptureReturnPath()
	capB := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionA, "conn-A", peerA, clientA, 301, capA.path)
	fwd.RegisterSessionWithReturnPath(sessionB, "conn-B", peerB, clientB, 302, capB.path)

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionA, targetIP, policy.Direct)
	rc.Set(sessionB, targetIP, policy.Direct)

	// Both clients use same source port to same destination
	pktA := buildTestIPv4TCPPacket(netip.MustParseAddr(clientA), targetIP, 5000, 80, 0x02, nil)
	pktB := buildTestIPv4TCPPacket(netip.MustParseAddr(clientB), targetIP, 5000, 80, 0x02, nil)

	if err := fwd.RouteClientToBackend(peerA, pktA); err != nil {
		t.Fatalf("route client A failed: %v", err)
	}
	if err := fwd.RouteClientToBackend(peerB, pktB); err != nil {
		t.Fatalf("route client B failed: %v", err)
	}

	wanPkts := wanDev.getPackets()
	if len(wanPkts) != 2 {
		t.Fatalf("expected 2 WAN packets, got %d", len(wanPkts))
	}
	natPortA := binary.BigEndian.Uint16(wanPkts[0][20:22])
	natPortB := binary.BigEndian.Uint16(wanPkts[1][20:22])

	if natPortA == natPortB {
		t.Fatalf("NAT ports for two clients must differ, got %d", natPortA)
	}

	// Send reply to client A's NAT port
	hostWAN := dem.cfg.HostWANIP
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

func TestPolicyDispatch_AccountingMetrics(t *testing.T) {
	fwd, _, _, rc := setupForwarderWithPBR(t)

	peerKey := "peer-metrics"
	backendID := int64(208)
	clientIP := "10.100.0.60"
	sessionID := "s-metrics"
	capPath := newTestCaptureReturnPath()

	fwd.RegisterSessionWithReturnPath(sessionID, "c-metrics", peerKey, clientIP, backendID, capPath.path)

	directIP := netip.MustParseAddr("1.1.1.1")
	rc.Set(sessionID, directIP, policy.Direct)

	proxyIP := netip.MustParseAddr("8.8.8.8")
	rc.Set(sessionID, proxyIP, policy.Proxy)

	prohibitedIP := netip.MustParseAddr("127.0.0.1")

	// 1. Direct packet
	pktDirect := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), directIP, 10001, 53, []byte("d"))
	_ = fwd.RouteClientToBackend(peerKey, pktDirect)

	// 2. Proxy packet
	pktProxy := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), proxyIP, 10002, 53, []byte("p"))
	_ = fwd.RouteClientToBackend(peerKey, pktProxy)

	// 3. Prohibited packet
	pktProhib := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), prohibitedIP, 10003, 80, 0x02, nil)
	_ = fwd.RouteClientToBackend(peerKey, pktProhib)

	proxiedBytes, directBytes, proxyDrops, directDrops := fwd.DispatchMetrics()

	if directBytes != int64(len(pktDirect)) {
		t.Errorf("expected directBytes %d, got %d", len(pktDirect), directBytes)
	}
	if proxiedBytes != int64(len(pktProxy)) {
		t.Errorf("expected proxiedBytes %d, got %d", len(pktProxy), proxiedBytes)
	}
	if proxyDrops != 0 {
		t.Errorf("expected 0 proxyDrops, got %d", proxyDrops)
	}
	if directDrops != 1 {
		t.Errorf("expected 1 directDrop, got %d", directDrops)
	}
}
