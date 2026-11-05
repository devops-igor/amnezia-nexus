//go:build linux

package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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

func init() {
	if os.Getenv("NEXUS_E2E_ECHO_HELPER") == "1" {
		runLinuxE2EEchoServer()
		os.Exit(0)
	}
}

func runLinuxE2EEchoServer() {
	target := os.Getenv("TARGET_ADDR")
	if target == "" {
		target = "198.51.200.2:8080"
	}

	uAddr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ResolveUDPAddr failed: %v\n", err)
		os.Exit(1)
	}
	uConn, err := net.ListenUDP("udp4", uAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenUDP failed: %v\n", err)
		os.Exit(1)
	}
	defer uConn.Close()

	tAddr, err := net.ResolveTCPAddr("tcp4", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ResolveTCPAddr failed: %v\n", err)
		os.Exit(1)
	}
	tLn, err := net.ListenTCP("tcp4", tAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenTCP failed: %v\n", err)
		os.Exit(1)
	}
	defer tLn.Close()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, rAddr, err := uConn.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := append([]byte("ECHO:"), buf[:n]...)
			_, _ = uConn.WriteTo(reply, rAddr)
		}
	}()

	go func() {
		for {
			conn, err := tLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					reply := append([]byte("ECHO:"), buf[:n]...)
					_, _ = c.Write(reply)
				}
			}(conn)
		}
	}()

	fmt.Println("READY")
	_ = os.Stdout.Sync()
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func checkLinuxCapabilities(t *testing.T) bool {
	inCI := os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""
	failOrSkip := func(format string, args ...any) {
		if inCI {
			t.Fatalf(format, args...)
		} else {
			t.Skipf(format, args...)
		}
	}
	if os.Geteuid() != 0 {
		failOrSkip("skipping Linux E2E test: root privileges required")
		return false
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		failOrSkip("skipping Linux E2E test: cannot open /dev/net/tun: %v", err)
		return false
	}
	_ = f.Close()
	if _, err := exec.LookPath("ip"); err != nil {
		failOrSkip("skipping Linux E2E test: ip command not found")
		return false
	}
	_ = os.MkdirAll("/run/netns", 0o755)
	testNS := fmt.Sprintf("nexus-probe-%d", time.Now().UnixNano()%100000)
	if err := exec.Command("ip", "netns", "add", testNS).Run(); err != nil {
		failOrSkip("skipping Linux E2E test: ip netns add failed: %v", err)
		return false
	}
	_ = exec.Command("ip", "netns", "del", testNS).Run()
	return true
}

type linuxE2EWANDevice struct {
	file    *os.File
	rawFile *os.File
	name    string
	hostWAN netip.Addr
	closed  bool
	mu      sync.Mutex
}

func (d *linuxE2EWANDevice) Write(p []byte) (int, error) {
	return d.file.Write(p)
}

func (d *linuxE2EWANDevice) Read(p []byte) (int, error) {
	if d.rawFile == nil {
		return d.file.Read(p)
	}
	for {
		d.mu.Lock()
		closed := d.closed
		d.mu.Unlock()
		if closed {
			return 0, os.ErrClosed
		}
		n, err := d.rawFile.Read(p)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			return 0, err
		}
		if n < 20 || (p[0]>>4) != 4 {
			continue
		}
		ihl := int(p[0]&0x0f) * 4
		if n < ihl+4 {
			continue
		}
		proto := p[9]
		if proto != 6 && proto != 17 {
			continue
		}
		dstPort := binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
		if dstPort < 40000 || dstPort > 65000 {
			continue
		}
		if d.hostWAN.IsValid() && d.hostWAN.Is4() {
			dstIP := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
			if dstIP != d.hostWAN {
				continue
			}
		}
		return n, nil
	}
}

func (d *linuxE2EWANDevice) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()
	var errs []error
	if d.rawFile != nil {
		_ = d.rawFile.Close()
	}
	if d.file != nil {
		_ = d.file.Close()
	}
	return errors.Join(errs...)
}

func createLinuxE2EWANDevice(name string, hostWAN netip.Addr) (*linuxE2EWANDevice, error) {
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

	rawSock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open raw packet socket: %w", err)
	}
	if err := unix.SetNonblock(rawSock, true); err != nil {
		_ = unix.Close(rawSock)
		_ = unix.Close(fd)
		return nil, err
	}
	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  0,
	}
	_ = unix.Bind(rawSock, sll)

	return &linuxE2EWANDevice{
		file:    os.NewFile(uintptr(fd), name),
		rawFile: os.NewFile(uintptr(rawSock), "e2e-raw"),
		name:    name,
		hostWAN: hostWAN,
	}, nil
}

func buildTestIPv4TCPPacketWithSeqAck(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	ihl := 20
	tcpHdrLen := 20
	totalLen := ihl + tcpHdrLen + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 1234)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 6 // TCP
	srcBytes := srcIP.As4()
	dstBytes := dstIP.As4()
	copy(pkt[12:16], srcBytes[:])
	copy(pkt[16:20], dstBytes[:])
	binary.BigEndian.PutUint16(pkt[10:12], computeIPv4Checksum(pkt[:ihl]))

	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], ack)
	pkt[32] = 0x50 // Data offset 5
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	copy(pkt[40:], payload)

	tcpCS := computeL4Checksum(srcBytes, dstBytes, 6, pkt[20:])
	binary.BigEndian.PutUint16(pkt[36:38], tcpCS)
	return pkt
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

// TestLinuxE2E_DirectEgress exercises policy-based direct egress and proxy dispatching
// against the real Linux kernel network stack, TUN devices, and a live echo responder.
func TestLinuxE2E_DirectEgress(t *testing.T) {
	if !checkLinuxCapabilities(t) {
		return
	}

	tunName := fmt.Sprintf("tun-%d", time.Now().UnixNano()%10000)
	if len(tunName) > 15 {
		tunName = tunName[:15]
	}
	vethHost := fmt.Sprintf("vh-%d", time.Now().UnixNano()%10000)
	if len(vethHost) > 15 {
		vethHost = vethHost[:15]
	}
	vethWAN := fmt.Sprintf("vw-%d", time.Now().UnixNano()%10000)
	if len(vethWAN) > 15 {
		vethWAN = vethWAN[:15]
	}
	netnsName := fmt.Sprintf("nexus-ns-%d", time.Now().UnixNano()%10000)
	if len(netnsName) > 15 {
		netnsName = netnsName[:15]
	}

	hostWAN := netip.MustParseAddr("198.51.100.1")
	targetIP := netip.MustParseAddr("198.51.200.2")

	// 1. Create authentic host WAN TUN device with AF_PACKET return capture
	tunDev, err := createLinuxE2EWANDevice(tunName, hostWAN)
	if err != nil {
		t.Fatalf("createLinuxE2EWANDevice failed: %v", err)
	}
	defer func() { _ = tunDev.Close() }()

	_ = exec.Command("ip", "link", "set", tunName, "up").Run()
	_ = exec.Command("ip", "addr", "add", "10.254.1.1/30", "dev", tunName).Run()

	// 2. Create isolated network namespace for external WAN network
	if err := exec.Command("ip", "netns", "add", netnsName).Run(); err != nil {
		t.Fatalf("ip netns add failed: %v", err)
	}
	defer func() {
		_ = exec.Command("ip", "netns", "del", netnsName).Run()
		_ = exec.Command("ip", "link", "del", vethHost).Run()
		_ = exec.Command("ip", "route", "del", "198.51.200.0/24").Run()
	}()

	// 3. Create separate WAN-facing veth interface connecting host to external network
	if err := exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethWAN).Run(); err != nil {
		t.Fatalf("ip link add veth failed: %v", err)
	}
	if err := exec.Command("ip", "link", "set", vethWAN, "netns", netnsName).Run(); err != nil {
		t.Fatalf("ip link set netns failed: %v", err)
	}

	// Host-side WAN interface configuration & kernel forwarding verification
	_ = exec.Command("ip", "addr", "add", "198.51.100.1/24", "dev", vethHost).Run()
	_ = exec.Command("ip", "link", "set", vethHost, "up").Run()

	// Verify and configure kernel prerequisites: IP forwarding and reverse-path filtering
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2").Run()
	_ = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", tunName)).Run()
	_ = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=2", vethHost)).Run()

	// Route traffic for the second network (198.51.200.0/24) via external gateway on veth
	_ = exec.Command("ip", "route", "add", "198.51.200.0/24", "via", "198.51.100.2", "dev", vethHost).Run()

	// Configure external WAN namespace
	_ = exec.Command("ip", "-n", netnsName, "link", "set", "lo", "up").Run()
	_ = exec.Command("ip", "-n", netnsName, "addr", "add", "198.51.100.2/24", "dev", vethWAN).Run()
	_ = exec.Command("ip", "-n", netnsName, "link", "set", vethWAN, "up").Run()
	_ = exec.Command("ip", "-n", netnsName, "addr", "add", "198.51.200.2/32", "dev", "lo").Run()
	_ = exec.Command("ip", "-n", netnsName, "route", "add", "default", "via", "198.51.100.1", "dev", vethWAN).Run()
	_ = exec.Command("ip", "-n", netnsName, "sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// 4. Start live TCP and UDP echo server inside the netns
	cmd := exec.Command("ip", "netns", "exec", netnsName, os.Args[0], "-test.run=TestHelperPlaceholder")
	cmd.Env = append(os.Environ(), "NEXUS_E2E_ECHO_HELPER=1", "TARGET_ADDR=198.51.200.2:8080")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdinPipe failed: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdoutPipe failed: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start echo helper failed: %v", err)
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	readyBuf := make([]byte, 6)
	if _, err := io.ReadFull(stdout, readyBuf); err != nil || string(readyBuf) != "READY\n" {
		t.Fatalf("echo helper not ready: %q, err: %v", string(readyBuf), err)
	}

	// 5. Setup Forwarder with PBR and DirectEgressManager using the authentic TUN device
	fwd := NewForwarder(nil, "10.100.0.0/16", 100)
	fwd.SetPBREnabled(true)

	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:  hostWAN,
		WANDevice:  tunDev,
		UDPTimeout: 5 * time.Second,
		TCPTimeout: 5 * time.Second,
	}, fwd)
	defer func() { _ = dem.Close() }()
	fwd.SetDirectEgress(dem)

	rc := newTestRouteCache()
	fwd.SetRouteCache(rc)

	fwd.StartPumps(t.Context())
	defer fwd.StopPumps()

	// Subtest 1: Real UDP direct egress with authentic Linux kernel socket echo reply
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

		// Direct egress manager writes to TUN fd -> Linux kernel netns routes to live echo server ->
		// Echo server replies -> Linux kernel writes reply to TUN fd -> Direct egress manager reads reply,
		// applies DNAT, and delivers to capPath.
		retPkts := waitPackets(capPath, 1, 3*time.Second)
		if len(retPkts) != 1 {
			t.Fatalf("expected 1 return packet delivered to peer, got %d", len(retPkts))
		}
		retPkt := retPkts[0]
		retDstIP := netip.AddrFrom4([4]byte{retPkt[16], retPkt[17], retPkt[18], retPkt[19]})
		retDstPort := binary.BigEndian.Uint16(retPkt[22:24])
		if retDstIP != netip.MustParseAddr(clientIP) || retDstPort != clientPort {
			t.Fatalf("expected DNAT to %s:%d, got %v:%d", clientIP, clientPort, retDstIP, retDstPort)
		}
		retSrcIP := netip.AddrFrom4([4]byte{retPkt[12], retPkt[13], retPkt[14], retPkt[15]})
		retSrcPort := binary.BigEndian.Uint16(retPkt[20:22])
		if retSrcIP != targetIP || retSrcPort != targetPort {
			t.Fatalf("expected reply from %v:%d, got %v:%d", targetIP, targetPort, retSrcIP, retSrcPort)
		}
		if string(retPkt[28:]) != "ECHO:ping-udp" {
			t.Fatalf("expected payload ECHO:ping-udp, got %q", string(retPkt[28:]))
		}
	})

	// Subtest 2: Real TCP direct egress with authentic Linux kernel TCP handshake and echo
	t.Run("TCP_Direct_Egress_And_Reply", func(t *testing.T) {
		peerKey := "peer-e2e-tcp"
		clientIP := "10.100.0.11"
		sessionID := "sess-e2e-tcp"
		clientPort := uint16(23456)
		targetPort := uint16(8080)
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-2", peerKey, clientIP, 101, capPath.path)
		rc.Set(sessionID, targetIP, policy.Direct)

		// Send SYN (0x02)
		synPkt := buildTestIPv4TCPPacketWithSeqAck(netip.MustParseAddr(clientIP), targetIP, clientPort, targetPort, 1000, 0, 0x02, nil)
		if err := fwd.RouteClientToBackend(peerKey, synPkt); err != nil {
			t.Fatalf("RouteClientToBackend TCP SYN failed: %v", err)
		}

		// Wait for live SYN-ACK from authentic Linux kernel TCP stack
		retPkts := waitPackets(capPath, 1, 3*time.Second)
		if len(retPkts) == 0 {
			t.Fatalf("expected SYN-ACK packet delivered to peer, got 0")
		}
		synAck := retPkts[0]
		retDstIP := netip.AddrFrom4([4]byte{synAck[16], synAck[17], synAck[18], synAck[19]})
		retDstPort := binary.BigEndian.Uint16(synAck[22:24])
		if retDstIP != netip.MustParseAddr(clientIP) || retDstPort != clientPort {
			t.Fatalf("expected DNAT to %s:%d, got %v:%d", clientIP, clientPort, retDstIP, retDstPort)
		}
		if (synAck[33] & 0x12) != 0x12 {
			t.Fatalf("expected SYN-ACK flags 0x12, got 0x%x", synAck[33])
		}
		serverSeq := binary.BigEndian.Uint32(synAck[24:28])

		// Send ACK + data (0x18 PSH|ACK)
		dataPkt := buildTestIPv4TCPPacketWithSeqAck(netip.MustParseAddr(clientIP), targetIP, clientPort, targetPort, 1001, serverSeq+1, 0x18, []byte("ping-tcp"))
		if err := fwd.RouteClientToBackend(peerKey, dataPkt); err != nil {
			t.Fatalf("RouteClientToBackend TCP data failed: %v", err)
		}

		// Wait for live echo reply from TCP echo server
		deadline := time.Now().Add(3 * time.Second)
		var echoFound bool
		for time.Now().Before(deadline) {
			for _, p := range capPath.getPackets() {
				if len(p) >= 40 && p[9] == 6 {
					payload := string(p[40:])
					if payload == "ECHO:ping-tcp" {
						echoFound = true
						break
					}
				}
			}
			if echoFound {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !echoFound {
			t.Fatalf("did not receive ECHO:ping-tcp reply from live TCP server")
		}
	})

	// Subtest 3: Dual routing — Proxy routing alongside direct routing
	t.Run("Dual_Routing_Proxy_And_Direct", func(t *testing.T) {
		peerKey := "peer-e2e-dual"
		clientIP := "10.100.0.12"
		sessionID := "sess-e2e-dual"
		backendID := int64(301)

		var capMu sync.Mutex
		var capturedPeers []string
		capPath := &testCaptureReturnPath{}
		capPath.path = NewReturnPath(func(pKey, assignedIP string, packet []byte) (int, error) {
			capMu.Lock()
			capturedPeers = append(capturedPeers, pKey)
			capMu.Unlock()
			capPath.mu.Lock()
			defer capPath.mu.Unlock()
			cp := make([]byte, len(packet))
			copy(cp, packet)
			capPath.packets = append(capPath.packets, cp)
			return len(packet), nil
		})

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-3", peerKey, clientIP, backendID, capPath.path)

		proxyDst := netip.MustParseAddr("198.51.200.50")
		directDst := targetIP // 198.51.200.2

		rc.Set(sessionID, proxyDst, policy.Proxy)
		rc.Set(sessionID, directDst, policy.Direct)

		pktProxy := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), proxyDst, 1111, 80, []byte("to-proxy"))
		pktDirect := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), directDst, 2222, 8080, []byte("to-direct"))

		// Route Proxy
		if err := fwd.RouteClientToBackend(peerKey, pktProxy); err != nil {
			t.Fatalf("route proxy packet failed: %v", err)
		}
		beQueue := fwd.backendQueues[backendID]
		if len(beQueue) != 1 {
			t.Fatalf("expected 1 packet in proxy backend queue, got %d", len(beQueue))
		}

		// Attached proxy consumer: read from backend queue and route return packet via authentic RouteBackendToClient
		select {
		case proxyPkt := <-beQueue:
			if len(proxyPkt) < 28 || string(proxyPkt[28:]) != "to-proxy" {
				t.Fatalf("unexpected proxy payload: %q", string(proxyPkt))
			}
			proxyReply := buildTestIPv4UDPPacket(proxyDst, netip.MustParseAddr(clientIP), 80, 1111, []byte("proxy-reply"))

			// Verify backend ownership validation: reply from wrong backend is rejected
			if err := fwd.RouteBackendToClient(backendID+999, proxyReply, clientIP); !errors.Is(err, ErrReturnRouteMismatch) {
				t.Fatalf("expected ErrReturnRouteMismatch for wrong backend, got %v", err)
			}

			// Route return packet using authentic production return method
			if err := fwd.RouteBackendToClient(backendID, proxyReply, clientIP); err != nil {
				t.Fatalf("RouteBackendToClient failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for proxy packet in backend queue")
		}

		// Wait for proxy reply to arrive via client pump and assert client-owner delivery
		pkts := waitPackets(capPath, 1, 3*time.Second)
		if len(pkts) != 1 {
			t.Fatalf("expected 1 packet in capPath after proxy reply, got %d", len(pkts))
		}
		if string(pkts[0][28:]) != "proxy-reply" {
			t.Fatalf("expected proxy-reply, got %q", string(pkts[0][28:]))
		}
		capMu.Lock()
		if len(capturedPeers) < 1 || capturedPeers[0] != peerKey {
			t.Fatalf("expected proxy reply delivered to client owner %q, got %v", peerKey, capturedPeers)
		}
		capMu.Unlock()

		// Route Direct
		if err := fwd.RouteClientToBackend(peerKey, pktDirect); err != nil {
			t.Fatalf("route direct packet failed: %v", err)
		}

		// Direct packet reaches live echo server and is echoed back alongside proxy reply
		retPkts := waitPackets(capPath, 2, 3*time.Second)
		if len(retPkts) < 2 {
			t.Fatalf("expected 2 return packets (proxy + direct), got %d", len(retPkts))
		}
		if string(retPkts[0][28:]) != "proxy-reply" {
			t.Fatalf("expected proxy-reply in retPkts[0], got %q", string(retPkts[0][28:]))
		}
		if string(retPkts[1][28:]) != "ECHO:to-direct" {
			t.Fatalf("expected ECHO:to-direct in retPkts[1], got %q", string(retPkts[1][28:]))
		}
		capMu.Lock()
		if len(capturedPeers) < 2 || capturedPeers[1] != peerKey {
			t.Fatalf("expected direct reply delivered to client owner %q, got %v", peerKey, capturedPeers)
		}
		capMu.Unlock()
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
		missingBackendID := int64(99999)
		capPath := newTestCaptureReturnPath()

		fwd.RegisterSessionWithReturnPath(sessionID, "conn-5", peerKey, clientIP, missingBackendID, capPath.path)
		fwd.mu.Lock()
		delete(fwd.backendQueues, missingBackendID)
		fwd.mu.Unlock()

		proxyDst := netip.MustParseAddr("198.51.200.88")
		rc.Set(sessionID, proxyDst, policy.Proxy)

		pkt := buildTestIPv4UDPPacket(netip.MustParseAddr(clientIP), proxyDst, 4444, 80, []byte("outage-proxy"))
		err := fwd.RouteClientToBackend(peerKey, pkt)
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("expected ErrBackendNotFound on backend outage, got %v", err)
		}

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

		dst := targetIP // 198.51.200.2
		rc.Set(sessA, dst, policy.Direct)
		rc.Set(sessB, dst, policy.Direct)

		pktA := buildTestIPv4UDPPacket(netip.MustParseAddr(ipA), dst, 5001, 8080, []byte("data-a"))
		pktB := buildTestIPv4UDPPacket(netip.MustParseAddr(ipB), dst, 5002, 8080, []byte("data-b"))

		if err := fwd.RouteClientToBackend(peerA, pktA); err != nil {
			t.Fatalf("peer A RouteClientToBackend failed: %v", err)
		}
		if err := fwd.RouteClientToBackend(peerB, pktB); err != nil {
			t.Fatalf("peer B RouteClientToBackend failed: %v", err)
		}

		// Both receive live echo replies from the live echo responder
		retA := waitPackets(capA, 1, 3*time.Second)
		retB := waitPackets(capB, 1, 3*time.Second)
		if len(retA) == 0 || string(retA[0][28:]) != "ECHO:data-a" {
			t.Fatalf("expected ECHO:data-a for peer A")
		}
		if len(retB) == 0 || string(retB[0][28:]) != "ECHO:data-b" {
			t.Fatalf("expected ECHO:data-b for peer B")
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
}
