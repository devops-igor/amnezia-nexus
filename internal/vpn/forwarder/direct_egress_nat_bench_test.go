package forwarder

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// BenchmarkNAT_ConnectionChurn measures connection lifecycle under high table occupancy
// to verify O(1) port release without full-map scanning (HIGH 3).
func BenchmarkNAT_ConnectionChurn(b *testing.B) {
	hostWAN := netip.MustParseAddr("203.0.113.1")
	targetIP := netip.MustParseAddr("1.1.1.1")
	clientIP := netip.MustParseAddr("10.100.0.1")

	wanDev := newMockPacketDev()
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  wanDev,
		MinPort:    10000,
		MaxPort:    60000,
		MaxFlows:   100000,
		UDPTimeout: time.Hour,
	}, nil)
	defer func() { _ = dem.Close() }()
	dem.SetPortCooldown(0)

	capPath := newTestCaptureReturnPath()

	// Pre-populate with 10,000 bindings to ensure releasePortLocked operates
	// over a populated table. Under O(N) scanning this would be measurably slow;
	// under O(1) direct retirement it remains consistently fast.
	const prePopulate = 10000
	for i := 1; i <= prePopulate; i++ {
		remoteAddr := netip.AddrFrom4([4]byte{198, 51, 100, byte(i % 250)})
		pkt := buildTestIPv4UDPPacket(clientIP, remoteAddr, uint16(10000+(i%40000)), uint16(i%60000+1), []byte("seed"))
		_ = dem.RouteDirect(fmt.Sprintf("seed-peer-%d", i), clientIP.String(), fmt.Sprintf("seed-sess-%d", i), 1, pkt, capPath.path)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		peer := fmt.Sprintf("churn-peer-%d", i%500)
		session := fmt.Sprintf("churn-sess-%d", i%500)
		srcPort := uint16(20000 + (i % 20000))
		pkt := buildTestIPv4UDPPacket(clientIP, targetIP, srcPort, 53, []byte("churn"))

		if err := dem.RouteDirect(peer, clientIP.String(), session, 1, pkt, capPath.path); err != nil {
			b.Fatalf("RouteDirect failed at iteration %d: %v", i, err)
		}
		dem.PurgeSession(session)
	}
}
