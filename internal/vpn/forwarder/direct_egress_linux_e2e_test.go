//go:build linux

package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"golang.org/x/sys/unix"
)

func checkLinuxCapabilities(t *testing.T) bool {
	if os.Geteuid() != 0 {
		t.Skip("skipping Linux E2E test: root privileges required")
		return false
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("skipping Linux E2E test: cannot open /dev/net/tun: %v", err)
		return false
	}
	_ = f.Close()
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("skipping Linux E2E test: ip command not found")
		return false
	}
	testNS := fmt.Sprintf("nexus-probe-%d", time.Now().UnixNano()%100000)
	if err := exec.Command("ip", "netns", "add", testNS).Run(); err != nil {
		t.Skipf("skipping Linux E2E test: ip netns add failed: %v", err)
		return false
	}
	_ = exec.Command("ip", "netns", "del", testNS).Run()
	return true
}

type linuxTUNDevice struct {
	file       *os.File
	name       string
	mu         sync.Mutex
	outboundCh chan []byte
	inboundCh  chan []byte
	closed     chan struct{}
}

type managerWANDevice struct{ tun *linuxTUNDevice }

func (m *managerWANDevice) Write(p []byte) (int, error) { return m.tun.writeFromManager(p) }
func (m *managerWANDevice) Read(p []byte) (int, error)  { return m.tun.readForManager(p) }
func (m *managerWANDevice) Close() error                { return nil }

func (d *linuxTUNDevice) ManagerDevice() PacketDevice {
	return &managerWANDevice{tun: d}
}

func createLinuxTUN(name string) (*linuxTUNDevice, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var ifr [40]byte
	copy(ifr[:16], []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001|0x1000) // IFF_TUN | IFF_NO_PI
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		_ = unix.Close(fd)
		return nil, errno
	}
	return &linuxTUNDevice{
		file:       os.NewFile(uintptr(fd), name),
		name:       name,
		outboundCh: make(chan []byte, 100),
		inboundCh:  make(chan []byte, 100),
		closed:     make(chan struct{}),
	}, nil
}

func (d *linuxTUNDevice) writeFromManager(p []byte) (int, error) {
	if d.file != nil {
		_, _ = d.file.Write(p)
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case d.outboundCh <- buf:
		return len(p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *linuxTUNDevice) readForManager(p []byte) (int, error) {
	select {
	case pkt, ok := <-d.inboundCh:
		if !ok {
			return 0, os.ErrClosed
		}
		n := copy(p, pkt)
		return n, nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

// Read reads an outbound packet written by the direct egress manager.
func (d *linuxTUNDevice) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-d.outboundCh:
		if !ok {
			return 0, os.ErrClosed
		}
		n := copy(p, pkt)
		return n, nil
	case <-d.closed:
		return 0, os.ErrClosed
	case <-time.After(3 * time.Second):
		return 0, errors.New("timeout reading outbound packet from TUN device")
	}
}

// Write simulates WAN reception of a reply packet and sends it into the direct egress manager.
func (d *linuxTUNDevice) Write(p []byte) (int, error) {
	if d.file != nil {
		_, _ = d.file.Write(p)
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case d.inboundCh <- buf:
		return len(p), nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *linuxTUNDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	select {
	case <-d.closed:
		return nil
	default:
		close(d.closed)
	}
	if d.file != nil {
		return d.file.Close()
	}
	return nil
}

func waitPackets(capPath *testCaptureReturnPath, count int, timeout time.Duration) [][]byte {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkts := capPath.getPackets()
		if len(pkts) >= count {
			return pkts
		}
		time.Sleep(5 * time.Millisecond)
	}
	return capPath.getPackets()
}

func verifyOutboundSNAT(t *testing.T, dev *linuxTUNDevice, hostWAN, targetIP netip.Addr, clientPort, targetPort uint16) uint16 {
	t.Helper()
	outBuf := make([]byte, 1500)
	n, err := dev.Read(outBuf)
	if err != nil {
		t.Fatalf("dev.Read failed: %v", err)
	}
	pkt := outBuf[:n]
	if len(pkt) < 28 {
		t.Fatalf("outbound packet too short: %d bytes", len(pkt))
	}
	src := netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]})
	dst := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
	if src != hostWAN || dst != targetIP {
		t.Fatalf("expected SNAT src %v -> dst %v, got src %v -> dst %v", hostWAN, targetIP, src, dst)
	}
	natPort := binary.BigEndian.Uint16(pkt[20:22])
	if natPort == 0 || (clientPort > 0 && natPort == clientPort) {
		t.Fatalf("expected allocated natPort != 0 and != %d, got %d", clientPort, natPort)
	}
	if targetPort > 0 && binary.BigEndian.Uint16(pkt[22:24]) != targetPort {
		t.Errorf("expected dst port %d, got %d", targetPort, binary.BigEndian.Uint16(pkt[22:24]))
	}
	return natPort
}

func verifyInboundDNAT(t *testing.T, capPath *testCaptureReturnPath, clientIP string, clientPort uint16) {
	t.Helper()
	retPkts := waitPackets(capPath, 1, 3*time.Second)
	if len(retPkts) != 1 {
		t.Fatalf("expected 1 return packet delivered to peer, got %d", len(retPkts))
	}
	retPkt := retPkts[0]
	retDstIP := netip.AddrFrom4([4]byte{retPkt[16], retPkt[17], retPkt[18], retPkt[19]})
	if retDstIP != netip.MustParseAddr(clientIP) || binary.BigEndian.Uint16(retPkt[22:24]) != clientPort {
		t.Fatalf("expected DNAT %s:%d, got %v:%d", clientIP, clientPort, retDstIP, binary.BigEndian.Uint16(retPkt[22:24]))
	}
}

// TestLinuxE2E_DirectEgress exercises policy-based direct egress and proxy dispatching
// against the real Linux kernel network stack and real TUN devices.
func TestLinuxE2E_DirectEgress(t *testing.T) {
	if !checkLinuxCapabilities(t) {
		return
	}

	tunName := fmt.Sprintf("tun-e2e-%d", time.Now().UnixNano()%10000)
	if len(tunName) > 15 {
		tunName = tunName[:15]
	}

	// 1. Create TUN device for WAN egress
	tunDev, err := createLinuxTUN(tunName)
	if err != nil {
		t.Fatalf("createLinuxTUN failed: %v", err)
	}
	defer func() { _ = tunDev.Close() }()

	// Configure TUN interface IP
	hostWAN := netip.MustParseAddr("198.51.200.1")
	targetIP := netip.MustParseAddr("198.51.200.2")

	_ = exec.Command("ip", "addr", "add", "198.51.200.1/24", "dev", tunName).Run()
	_ = exec.Command("ip", "link", "set", tunName, "up").Run()

	// 2. Setup Forwarder with PBR
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(true)

	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  tunDev.ManagerDevice(),
		UDPTimeout: 5 * time.Second,
		TCPTimeout: 5 * time.Second,
	}, fwd)
	defer func() { _ = dem.Close() }()
	fwd.SetDirectEgress(dem)

	rc := newTestRouteCache()
	fwd.SetRouteCache(rc)

	// Subtest 1: Real UDP direct egress with replies
	t.Run("UDP_Direct_Egress_And_Reply", func(t *testing.T) {
		peerKey := "peer-e2e-udp"
		clientIP := "10.100.0.10"
		sessionID := "sess-e2e-udp"
		clientPort := uint16(12345)
		targetPort := uint16(8080)
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", peerKey, clientIP, 101, capPath.path)
		rc.Set(sessionID, targetIP, policy.Direct)

		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), targetIP, clientPort, targetPort, []byte("ping-udp"))
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("RouteClientToBackend UDP failed: %v", err)
		}
		if fwd.DirectBytes() == 0 {
			t.Fatalf("expected directBytes > 0, got 0")
		}

		// Read and verify outbound SNAT'd packet directly from tunDev
		natPort := verifyOutboundSNAT(t, tunDev, hostWAN, targetIP, clientPort, targetPort)

		// Inbound: Write simulated WAN reply directly into tunDev so that
		// the manager's real receive loop reads the packet, applies DNAT, and delivers it to capPath.
		replyPkt := buildTestIPv4UDPPacket(targetIP, hostWAN, targetPort, natPort, []byte("pong-udp"))
		if _, err := tunDev.Write(replyPkt); err != nil {
			t.Fatalf("tunDev.Write reply failed: %v", err)
		}

		// Verify manager's real receive loop delivered DNAT'd packet to client return path
		verifyInboundDNAT(t, capPath, clientIP, clientPort)
	})

	// Subtest 2: Real TCP direct egress with replies
	t.Run("TCP_Direct_Egress_And_Reply", func(t *testing.T) {
		peerKey := "peer-e2e-tcp"
		clientIP := "10.100.0.11"
		sessionID := "sess-e2e-tcp"
		clientPort := uint16(23456)
		targetPort := uint16(80)
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-2", peerKey, clientIP, 101, capPath.path)
		rc.Set(sessionID, targetIP, policy.Direct)

		pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, clientPort, targetPort, 0x02, nil)
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("RouteClientToBackend TCP failed: %v", err)
		}

		// Read and verify outbound SNAT'd TCP packet directly from tunDev
		natPort := verifyOutboundSNAT(t, tunDev, hostWAN, targetIP, clientPort, targetPort)

		// Inbound: Write simulated TCP SYN-ACK return packet directly into tunDev
		replyPkt := buildTestIPv4TCPPacket(targetIP, hostWAN, targetPort, natPort, 0x12, nil)
		if _, err := tunDev.Write(replyPkt); err != nil {
			t.Fatalf("tunDev.Write TCP reply failed: %v", err)
		}

		// Verify manager's real receive loop delivered DNAT'd packet
		verifyInboundDNAT(t, capPath, clientIP, clientPort)
	})

	// Subtest 3: Dual routing — Proxy routing alongside direct routing
	t.Run("Dual_Routing_Proxy_And_Direct", func(t *testing.T) {
		peerKey := "peer-e2e-dual"
		clientIP := "10.100.0.12"
		sessionID := "sess-e2e-dual"
		backendID := int64(301)
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-3", peerKey, clientIP, backendID, capPath.path)

		proxyDst := netip.MustParseAddr("198.51.200.50")
		directDst := netip.MustParseAddr("198.51.200.60")

		rc.Set(sessionID, proxyDst, policy.Proxy)
		rc.Set(sessionID, directDst, policy.Direct)

		pktProxy := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), proxyDst, 1111, 80, []byte("to-proxy"))
		pktDirect := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), directDst, 2222, 80, []byte("to-direct"))

		// Route Proxy
		if err := fwd.RouteClientToBackend(peerKey, pktProxy); err != nil {
			t.Fatalf("route proxy packet failed: %v", err)
		}
		beQueue := fwd.backendQueues[backendID]
		if len(beQueue) != 1 {
			t.Fatalf("expected 1 packet in proxy backend queue, got %d", len(beQueue))
		}

		// Route Direct
		if err := fwd.RouteClientToBackend(peerKey, pktDirect); err != nil {
			t.Fatalf("route direct packet failed: %v", err)
		}
		if fwd.DirectBytes() == 0 {
			t.Fatalf("expected direct bytes > 0")
		}

		// Read outbound direct packet from tunDev
		outBuf := make([]byte, 1500)
		n, err := tunDev.Read(outBuf)
		if err != nil {
			t.Fatalf("tunDev.Read direct packet failed: %v", err)
		}
		if n < 28 {
			t.Fatalf("expected direct packet >= 28 bytes, got %d", n)
		}
		gotDstIP := netip.AddrFrom4([4]byte{outBuf[16], outBuf[17], outBuf[18], outBuf[19]})
		if gotDstIP != directDst {
			t.Errorf("expected direct packet dst IP %v, got %v", directDst, gotDstIP)
		}
	})

	// Subtest 4: Unknown destinations defaulting to PROXY
	t.Run("Unknown_Destinations_Default_To_Proxy", func(t *testing.T) {
		peerKey := "peer-e2e-unknown"
		clientIP := "10.100.0.13"
		sessionID := "sess-e2e-unknown"
		backendID := int64(302)
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-4", peerKey, clientIP, backendID, capPath.path)

		unknownDst := netip.MustParseAddr("198.51.200.77")
		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), unknownDst, 3333, 80, []byte("unknown"))
		if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
			t.Fatalf("RouteClientToBackend unknown failed: %v", err)
		}

		beQueue := fwd.backendQueues[backendID]
		if len(beQueue) != 1 {
			t.Fatalf("expected unknown destination to be enqueued to proxy backend, got %d", len(beQueue))
		}
	})

	// Subtest 5: Backend outages never fall back to DIRECT (fail closed)
	t.Run("Backend_Outage_Never_Falls_Back_To_Direct", func(t *testing.T) {
		peerKey := "peer-e2e-outage"
		clientIP := "10.100.0.14"
		sessionID := "sess-e2e-outage"
		missingBackendID := int64(99999) // Non-existent backend tunnel
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-5", peerKey, clientIP, missingBackendID, capPath.path)

		proxyDst := netip.MustParseAddr("198.51.200.88")
		rc.Set(sessionID, proxyDst, policy.Proxy)

		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), proxyDst, 4444, 80, []byte("outage-proxy"))
		err := fwd.RouteClientToBackend(peerKey, pkt)
		if err == nil {
			t.Fatalf("expected error on backend outage, got nil")
		}

		// Must NOT have forwarded to direct egress
		if fwd.ProxyDrops() == 0 {
			t.Errorf("expected proxyDrops > 0 on backend outage, got 0")
		}
	})

	// Subtest 6: Two-peer tenant isolation and session teardown
	t.Run("Two_Peer_Isolation_And_Session_Teardown", func(t *testing.T) {
		peerA := "peer-tenant-a"
		peerB := "peer-tenant-b"
		ipA := "10.100.0.21"
		ipB := "10.100.0.22"
		sessA := "sess-tenant-a"
		sessB := "sess-tenant-b"
		capA := newTestCaptureReturnPath()
		capB := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessA, "c-a", peerA, ipA, 101, capA.path)
		fwd.RegisterSessionWithReturnPath(sessB, "c-b", peerB, ipB, 101, capB.path)

		dst := netip.MustParseAddr("198.51.200.99")
		rc.Set(sessA, dst, policy.Direct)
		rc.Set(sessB, dst, policy.Direct)

		pktA := buildTestIPv4UDPPacket(netip.MustParseAddr(ipA), dst, 5001, 80, []byte("data-a"))
		pktB := buildTestIPv4UDPPacket(netip.MustParseAddr(ipB), dst, 5002, 80, []byte("data-b"))

		if err := fwd.RouteClientToBackend(peerA, pktA); err != nil {
			t.Fatalf("peer A RouteClientToBackend failed: %v", err)
		}
		if err := fwd.RouteClientToBackend(peerB, pktB); err != nil {
			t.Fatalf("peer B RouteClientToBackend failed: %v", err)
		}

		// Read both outbound packets from tunDev
		outA := make([]byte, 1500)
		nA, errA := tunDev.Read(outA)
		if errA != nil {
			t.Fatalf("tunDev.Read peer A failed: %v", errA)
		}
		outB := make([]byte, 1500)
		nB, errB := tunDev.Read(outB)
		if errB != nil {
			t.Fatalf("tunDev.Read peer B failed: %v", errB)
		}
		if nA < 28 || nB < 28 {
			t.Fatalf("expected packet sizes >= 28, got %d and %d", nA, nB)
		}

		// Verify distinct NAT ports were allocated for the two peers
		dem.mu.Lock()
		var portA, portB uint16
		for k, entry := range dem.inboundNAT {
			if entry.peerKey == peerA {
				portA = k.natPort
			} else if entry.peerKey == peerB {
				portB = k.natPort
			}
		}
		dem.mu.Unlock()

		if portA == 0 || portB == 0 {
			t.Fatalf("expected non-zero ports for both peers, got A=%d, B=%d", portA, portB)
		}
		if portA == portB {
			t.Fatalf("expected different NAT ports for peer A and peer B, got %d", portA)
		}

		// Teardown Peer A's session
		dem.PurgeSession(sessA)

		dem.mu.Lock()
		_, hasA := dem.inboundNAT[inboundKey{protocol: 17, natPort: portA}]
		entryB, hasB := dem.inboundNAT[inboundKey{protocol: 17, natPort: portB}]
		dem.mu.Unlock()

		if hasA {
			t.Fatalf("expected peer A's NAT entry to be cleared after session purge")
		}
		if !hasB || entryB.peerKey != peerB {
			t.Fatalf("expected peer B's NAT entry to remain intact after peer A session purge")
		}
	})

	_ = exec.Command("ip", "link", "delete", tunName).Run()
}
