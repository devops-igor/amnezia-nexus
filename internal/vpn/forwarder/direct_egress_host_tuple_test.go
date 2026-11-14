//go:build linux

package forwarder

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// hostIsolationWANIP is a real local address, so a host socket genuinely competes
// for the same (address, port) tuple the direct-NAT allocator wants. The WAN
// packet device stays a fixture: no packet leaves this host.
const hostIsolationWANIP = "127.0.0.1"

// hostIsolationHarness drives direct egress through the authentic forwarder:
// registered authenticated session, DIRECT route evidence, real NAT allocator and
// real WAN reply demultiplexer. Only the packet device and the return path sink
// are fixtures.
type hostIsolationHarness struct {
	t       *testing.T
	fwd     *Forwarder
	dem     *DirectEgressManager
	wanDev  *mockPacketDev
	cache   *testRouteCache
	capture *testCaptureReturnPath
	hostWAN netip.Addr
	client  netip.Addr
	peerKey string
	session string
	conn    string
}

func newHostIsolationHarness(t *testing.T, cfg DirectEgressConfig) *hostIsolationHarness {
	t.Helper()
	h := &hostIsolationHarness{
		t:       t,
		hostWAN: netip.MustParseAddr(hostIsolationWANIP),
		client:  netip.MustParseAddr("10.100.0.2"),
		peerKey: "isolation-peer",
		session: "isolation-session",
		conn:    "isolation-connection",
	}
	h.wanDev = newMockPacketDev()
	cfg.HostWANIP = h.hostWAN
	cfg.WANDevice = h.wanDev

	h.fwd = NewForwarder(nil, "10.100.0.0/16", 8)
	h.dem = NewDirectEgressManager(cfg, h.fwd)
	h.fwd.SetDirectEgress(h.dem)
	h.fwd.SetPBREnabled(true)
	h.cache = newTestRouteCache()
	h.fwd.SetRouteCache(h.cache)
	h.capture = newTestCaptureReturnPath()
	h.fwd.RegisterSessionWithReturnPath(h.session, h.conn, h.peerKey, h.client.String(), 1, h.capture.path)
	t.Cleanup(func() {
		h.fwd.UnregisterSession(h.peerKey)
		_ = h.dem.Close()
	})
	return h
}

// allowDirect records DIRECT evidence for a remote on the harness session.
func (h *hostIsolationHarness) allowDirect(remote netip.Addr) {
	h.cache.Set(h.session, remote, policy.Direct)
}

// dispatchUDP sends one client UDP packet through the authentic forwarder.
func (h *hostIsolationHarness) dispatchUDP(remote netip.Addr, dstPort uint16, payload string) error {
	h.allowDirect(remote)
	pkt := buildTestIPv4UDPPacket(h.client, remote, 12345, dstPort, []byte(payload))
	return h.fwd.RouteClientToBackend(h.peerKey, pkt)
}

// dispatchTCP sends one client TCP packet through the authentic forwarder.
func (h *hostIsolationHarness) dispatchTCP(remote netip.Addr, dstPort uint16, flags uint8) error {
	h.allowDirect(remote)
	pkt := buildTestIPv4TCPPacket(h.client, remote, 12345, dstPort, flags, nil)
	return h.fwd.RouteClientToBackend(h.peerKey, pkt)
}

// wanPorts returns the SNAT source port of every packet written to the WAN device,
// which is the direct-NAT port the allocator committed.
func (h *hostIsolationHarness) wanPorts() []uint16 {
	pkts := h.wanDev.getPackets()
	ports := make([]uint16, 0, len(pkts))
	for _, p := range pkts {
		ports = append(ports, binary.BigEndian.Uint16(p[20:22]))
	}
	return ports
}

// natPort returns the single direct-NAT port the last WAN packet used.
func (h *hostIsolationHarness) natPort() uint16 {
	ports := h.wanPorts()
	if len(ports) == 0 {
		h.t.Fatal("no direct-WAN packet was written, so no NAT port was allocated")
	}
	return ports[len(ports)-1]
}

// requireRejectedReply asserts a WAN reply is refused and never reaches a peer.
func (h *hostIsolationHarness) requireRejectedReply(reply []byte, want error, what string) {
	h.t.Helper()
	before := len(h.capture.getPackets())
	err := h.dem.HandleWANReply(reply)
	if want == nil {
		if err == nil {
			h.t.Fatalf("%s: reply was accepted as a direct reply", what)
		}
	} else if !errors.Is(err, want) {
		h.t.Fatalf("%s: want %v, got %v", what, want, err)
	}
	if got := len(h.capture.getPackets()); got != before {
		h.t.Fatalf("%s: %d reply packet(s) reached a VPN peer", what, got-before)
	}
}

// requireUDPReplyDelivered is the normal direct-reply positive control: a reply
// from the flow's remote endpoint is DNATed back to the originating client tuple.
func (h *hostIsolationHarness) requireUDPReplyDelivered(remote netip.Addr, natPort, remotePort uint16, payload string) {
	h.t.Helper()
	before := len(h.capture.getPackets())
	reply := buildTestIPv4UDPPacket(remote, h.hostWAN, remotePort, natPort, []byte(payload))
	if err := h.dem.HandleWANReply(reply); err != nil {
		h.t.Fatalf("legitimate direct UDP reply refused: %v", err)
	}
	pkts := h.capture.getPackets()
	if len(pkts) != before+1 {
		h.t.Fatalf("expected one delivered UDP reply, got %d", len(pkts)-before)
	}
	p := pkts[len(pkts)-1]
	if got := string(p[28:]); got != payload {
		h.t.Fatalf("delivered payload = %q, want %q", got, payload)
	}
	if got := binary.BigEndian.Uint16(p[22:24]); got != 12345 {
		h.t.Fatalf("delivered to client port %d, want 12345", got)
	}
	if got := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}); got != h.client {
		h.t.Fatalf("delivered to client address %s, want %s", got, h.client)
	}
}

// hostSocketInPool acquires a real unprivileged UDP socket whose ephemeral port is
// inside the default direct-NAT pool, so the reviewed collision shape is
// reproducible without a privileged environment.
func hostSocketInPool(t *testing.T, bindIP net.IP) (*net.UDPConn, uint16) {
	t.Helper()
	for i := 0; i < 512; i++ {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: 0})
		if err != nil {
			t.Fatalf("acquire host UDP socket: %v", err)
		}
		port := conn.LocalAddr().(*net.UDPAddr).Port
		if port >= int(defaultMinNATPort) && port <= int(defaultMaxNATPort) {
			return conn, uint16(port) // #nosec G115 -- bounded by the pool check above
		}
		_ = conn.Close()
	}
	t.Skip("no host ephemeral UDP port available inside the direct-NAT pool")
	return nil, 0
}

// hostTCPListenerInPool acquires a real listening TCP socket inside the pool.
func hostTCPListenerInPool(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	for i := 0; i < 512; i++ {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			t.Fatalf("acquire host TCP listener: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if port >= int(defaultMinNATPort) && port <= int(defaultMaxNATPort) {
			return ln, uint16(port) // #nosec G115 -- bounded by the pool check above
		}
		_ = ln.Close()
	}
	t.Skip("no host ephemeral TCP port available inside the direct-NAT pool")
	return nil, 0
}

// freeNATRange finds 'size' consecutive ports that are free for both protocols.
func freeNATRange(t *testing.T, size int) uint16 {
	t.Helper()
	for base := int(defaultMaxNATPort) - 1; base >= int(defaultMinNATPort); base -= 8 {
		free := true
		for i := 0; i < size; i++ {
			port := uint16(base + i) // #nosec G115 -- bounded by the pool range
			if tryBindHostUDP(net.IPv4zero, port) != nil || tryBindHostTCP(net.IPv4zero, port) != nil {
				free = false
				break
			}
		}
		if free {
			return uint16(base) // #nosec G115 -- bounded by the pool range
		}
	}
	t.Skip("no free direct-NAT port range available on this host")
	return 0
}

func tryBindHostUDP(ip net.IP, port uint16) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip, Port: int(port)})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func tryBindHostTCP(ip net.IP, port uint16) error {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: ip, Port: int(port)})
	if err == nil {
		_ = ln.Close()
	}
	return err
}

// requireTupleHeldByDirectEgress asserts the host cannot take the tuple, which is
// what "exclusive ownership for the binding lifetime" means observably.
func requireTupleHeldByDirectEgress(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: bind succeeded, so direct egress does not own the tuple", what)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("%s: want EADDRINUSE while direct egress owns the tuple, got %v", what, err)
	}
}

func requireTupleReleased(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: bind refused after direct egress released the tuple: %v", what, err)
	}
}

// requireHostSocketUsable proves the host socket still owns its traffic: a
// datagram addressed to its loopback tuple is delivered to it.
func requireHostSocketUsable(t *testing.T, hostConn *net.UDPConn) {
	t.Helper()
	port := hostConn.LocalAddr().(*net.UDPAddr).Port
	peer, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("host client socket: %v", err)
	}
	defer func() { _ = peer.Close() }()
	if _, err := peer.Write([]byte("host-probe")); err != nil {
		t.Fatalf("host client write: %v", err)
	}
	if err := hostConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("host socket deadline: %v", err)
	}
	buf := make([]byte, 32)
	n, _, err := hostConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("host socket no longer receives its own traffic: %v", err)
	}
	if got := string(buf[:n]); got != "host-probe" {
		t.Fatalf("host socket received %q, want %q", got, "host-probe")
	}
}

// TestHostTupleIsolation_HostSocketFirstRefusesDirectAdmission covers the reviewed
// counterexample ordering: an ordinary host UDP socket already owns the WAN tuple
// when a VPN peer asks for the same endpoint. The allocator must refuse instead of
// claiming the tuple, no host payload may reach the peer, and host traffic must be
// untouched.
func TestHostTupleIsolation_HostSocketFirstRefusesDirectAdmission(t *testing.T) {
	remote := netip.MustParseAddr("1.1.1.1")
	for _, tc := range []struct {
		name   string
		bindIP net.IP
	}{
		{"wildcard host socket", net.IPv4zero},
		{"specific host socket", net.IPv4(127, 0, 0, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostConn, hostPort := hostSocketInPool(t, tc.bindIP)
			defer func() { _ = hostConn.Close() }()

			h := newHostIsolationHarness(t, DirectEgressConfig{MinPort: hostPort, MaxPort: hostPort})

			err := h.dispatchUDP(remote, 53, "vpn-query")
			if !errors.Is(err, ErrNATPortExhaustion) {
				t.Fatalf("direct admission used a host-owned tuple: got %v, want ErrNATPortExhaustion", err)
			}
			if got := len(h.wanDev.getPackets()); got != 0 {
				t.Fatalf("refused flow still wrote %d WAN packet(s)", got)
			}
			if got := h.dem.HostReservationCount(); got != 0 {
				t.Fatalf("refused flow holds %d host reservation(s)", got)
			}

			// Same wire identity the review used: the host resolver's own reply.
			reply := buildTestIPv4UDPPacket(remote, h.hostWAN, 53, hostPort, []byte("host-private-response"))
			h.requireRejectedReply(reply, nil, "host reply for a host-owned tuple")

			requireHostSocketUsable(t, hostConn)
		})
	}
}

// TestHostTupleIsolation_NATFirstBlocksHostBindsForBindingLifetime covers the
// inverse ordering: direct egress admitted the flow first, so no local socket may
// take the tuple afterwards, for either binding style, while the flow is live.
func TestHostTupleIsolation_NATFirstBlocksHostBindsForBindingLifetime(t *testing.T) {
	remote := netip.MustParseAddr("1.1.1.1")
	h := newHostIsolationHarness(t, DirectEgressConfig{})

	if err := h.dispatchUDP(remote, 53, "vpn-query"); err != nil {
		t.Fatalf("direct admission failed: %v", err)
	}
	natPort := h.natPort()

	requireTupleHeldByDirectEgress(t, "wildcard host UDP bind while the flow is live", tryBindHostUDP(net.IPv4zero, natPort))
	requireTupleHeldByDirectEgress(t, "specific host UDP bind while the flow is live", tryBindHostUDP(net.IPv4(127, 0, 0, 1), natPort))

	// Normal direct traffic must be unaffected by the reservation.
	h.requireUDPReplyDelivered(remote, natPort, 53, "direct-reply")

	h.dem.SetPortCooldown(0)
	h.dem.PurgePeer(h.peerKey)
	requireTupleReleased(t, "host UDP bind after the port retired", tryBindHostUDP(net.IPv4zero, natPort))
	if got := h.dem.HostReservationCount(); got != 0 {
		t.Fatalf("retired flow still holds %d host reservation(s)", got)
	}
}

// TestHostTupleIsolation_TCPReservationKeepsDirectReplies proves the same
// exclusivity for TCP without disturbing direct TCP replies or the
// generation/ReturnPath fence.
func TestHostTupleIsolation_TCPReservationKeepsDirectReplies(t *testing.T) {
	remote := netip.MustParseAddr("93.184.216.34")
	h := newHostIsolationHarness(t, DirectEgressConfig{})

	if err := h.dispatchTCP(remote, 443, 0x02); err != nil {
		t.Fatalf("direct TCP admission failed: %v", err)
	}
	natPort := h.natPort()

	requireTupleHeldByDirectEgress(t, "wildcard host TCP bind while the flow is live", tryBindHostTCP(net.IPv4zero, natPort))
	requireTupleHeldByDirectEgress(t, "specific host TCP bind while the flow is live", tryBindHostTCP(net.IPv4(127, 0, 0, 1), natPort))

	reply := buildTestIPv4TCPPacket(remote, h.hostWAN, 443, natPort, 0x12, []byte("syn-ack"))
	if err := h.dem.HandleWANReply(reply); err != nil {
		t.Fatalf("legitimate direct TCP reply refused: %v", err)
	}
	pkts := h.capture.getPackets()
	if len(pkts) != 1 {
		t.Fatalf("expected one delivered TCP reply, got %d", len(pkts))
	}
	delivered := pkts[0]
	if got := binary.BigEndian.Uint16(delivered[22:24]); got != 12345 {
		t.Fatalf("TCP reply delivered to client port %d, want 12345", got)
	}
	if delivered[33] != 0x12 {
		t.Fatalf("TCP reply flags = %#x, want 0x12 (SYN-ACK preserved)", delivered[33])
	}

	// Generation fence: once the session is gone the same reply must not land.
	h.fwd.UnregisterSession(h.peerKey)
	h.requireRejectedReply(
		buildTestIPv4TCPPacket(remote, h.hostWAN, 443, natPort, 0x18, []byte("post-retire")),
		nil,
		"reply for a retired generation",
	)
}

// TestHostTupleIsolation_HostListenerFirstRefusesTCPAdmission is the host-first TCP
// ordering: an existing local listener owns the port, so direct TCP must refuse it.
func TestHostTupleIsolation_HostListenerFirstRefusesTCPAdmission(t *testing.T) {
	remote := netip.MustParseAddr("93.184.216.34")
	ln, hostPort := hostTCPListenerInPool(t)
	defer func() { _ = ln.Close() }()

	h := newHostIsolationHarness(t, DirectEgressConfig{MinPort: hostPort, MaxPort: hostPort})

	err := h.dispatchTCP(remote, 443, 0x02)
	if !errors.Is(err, ErrNATPortExhaustion) {
		t.Fatalf("direct TCP admission used a host-owned tuple: got %v, want ErrNATPortExhaustion", err)
	}
	if got := len(h.wanDev.getPackets()); got != 0 {
		t.Fatalf("refused flow still wrote %d WAN packet(s)", got)
	}
	if got := len(h.capture.getPackets()); got != 0 {
		t.Fatalf("refused flow delivered %d packet(s) to a peer", got)
	}
}

// TestHostTupleIsolation_QuarantineKeepsTupleForDelayedReplies covers the release
// ordering: the tuple stays ours through the quarantine window that still attributes
// delayed replies, then returns to the host once that window elapses.
func TestHostTupleIsolation_QuarantineKeepsTupleForDelayedReplies(t *testing.T) {
	remote := netip.MustParseAddr("1.1.1.1")
	h := newHostIsolationHarness(t, DirectEgressConfig{})
	if err := h.dispatchUDP(remote, 53, "vpn-query"); err != nil {
		t.Fatalf("direct admission failed: %v", err)
	}
	natPort := h.natPort()

	cooldown := 120 * time.Millisecond
	h.dem.SetPortCooldown(cooldown)
	h.dem.SetQuarantineDurations(cooldown, cooldown)
	h.dem.PurgePeer(h.peerKey)

	requireTupleHeldByDirectEgress(t, "host UDP bind during quarantine", tryBindHostUDP(net.IPv4zero, natPort))
	h.requireRejectedReply(
		buildTestIPv4UDPPacket(remote, h.hostWAN, 53, natPort, []byte("delayed-reply")),
		ErrStaleSessionReply,
		"delayed reply inside quarantine",
	)

	time.Sleep(cooldown + 60*time.Millisecond)
	h.dem.Sweep(time.Now())
	requireTupleReleased(t, "host UDP bind after quarantine expiry", tryBindHostUDP(net.IPv4zero, natPort))
}

// TestHostTupleIsolation_ResourceFailureRefusesDirect covers the failure ordering:
// when ownership cannot be established the flow is refused instead of falling back
// to a mapping nobody verified, and an already-admitted flow keeps working.
func TestHostTupleIsolation_ResourceFailureRefusesDirect(t *testing.T) {
	remote := netip.MustParseAddr("1.1.1.1")
	h := newHostIsolationHarness(t, DirectEgressConfig{MaxHostReservations: 1})

	if err := h.dispatchUDP(remote, 53, "first-flow"); err != nil {
		t.Fatalf("first direct admission failed: %v", err)
	}
	natPort := h.natPort()

	err := h.dispatchUDP(remote, 443, "second-flow")
	if !errors.Is(err, ErrHostTupleOwnershipUnavailable) {
		t.Fatalf("second flow: want ErrHostTupleOwnershipUnavailable, got %v", err)
	}
	if got := len(h.wanDev.getPackets()); got != 1 {
		t.Fatalf("refused flow still wrote a WAN packet (%d total)", got)
	}
	if got := h.dem.HostReservationCount(); got != 1 {
		t.Fatalf("expected exactly one held reservation, got %d", got)
	}

	h.requireUDPReplyDelivered(remote, natPort, 53, "first-flow-reply")
}

// TestHostTupleIsolation_PortPressureFallbackKeepsOwnership covers the recycle
// allocation path: reusing a quarantined port must keep the same ownership
// guarantee rather than silently mapping an unverified tuple.
func TestHostTupleIsolation_PortPressureFallbackKeepsOwnership(t *testing.T) {
	firstRemote := netip.MustParseAddr("1.1.1.1")
	secondRemote := netip.MustParseAddr("93.184.216.34")
	thirdRemote := netip.MustParseAddr("1.0.0.1")

	base := freeNATRange(t, 2)
	h := newHostIsolationHarness(t, DirectEgressConfig{MinPort: base, MaxPort: base + 1})
	h.dem.SetPortCooldown(5 * time.Second)
	h.dem.SetQuarantineDurations(5*time.Second, 5*time.Second)

	if err := h.dispatchUDP(firstRemote, 53, "first"); err != nil {
		t.Fatalf("first direct admission failed: %v", err)
	}
	if err := h.dispatchUDP(secondRemote, 443, "second"); err != nil {
		t.Fatalf("second direct admission failed: %v", err)
	}
	allocated := h.wanPorts()
	if len(allocated) != 2 {
		t.Fatalf("expected two allocated ports, got %v", allocated)
	}

	// Retire both flows; both ports are quarantined and still owned.
	h.dem.PurgePeer(h.peerKey)
	for _, port := range allocated {
		requireTupleHeldByDirectEgress(t, "host UDP bind during quarantine", tryBindHostUDP(net.IPv4zero, port))
	}

	if err := h.dispatchUDP(thirdRemote, 53, "third"); err != nil {
		t.Fatalf("port-pressure fallback refused a recyclable port: %v", err)
	}
	recycled := h.natPort()
	requireTupleHeldByDirectEgress(t, "host UDP bind on the recycled port", tryBindHostUDP(net.IPv4zero, recycled))
	if got := h.dem.HostReservationCount(); got > 2 {
		t.Fatalf("port-pressure fallback holds %d reservations for a 2-port pool", got)
	}
}

// TestHostTupleIsolation_PurgeAndCloseReleaseOwnership covers the teardown paths:
// discarding all NAT state and closing the manager both return host tuples.
func TestHostTupleIsolation_PurgeAndCloseReleaseOwnership(t *testing.T) {
	remote := netip.MustParseAddr("1.1.1.1")
	h := newHostIsolationHarness(t, DirectEgressConfig{})

	if err := h.dispatchUDP(remote, 53, "first-flow"); err != nil {
		t.Fatalf("direct admission failed: %v", err)
	}
	purged := h.natPort()
	requireTupleHeldByDirectEgress(t, "host UDP bind while the flow is live", tryBindHostUDP(net.IPv4zero, purged))

	h.dem.PurgeAll()
	requireTupleReleased(t, "host UDP bind after PurgeAll", tryBindHostUDP(net.IPv4zero, purged))
	if got := h.dem.HostReservationCount(); got != 0 {
		t.Fatalf("PurgeAll left %d reservation(s)", got)
	}

	if err := h.dispatchUDP(remote, 53, "second-flow"); err != nil {
		t.Fatalf("direct admission after purge failed: %v", err)
	}
	closed := h.natPort()
	requireTupleHeldByDirectEgress(t, "host UDP bind before Close", tryBindHostUDP(net.IPv4zero, closed))
	if err := h.dem.Close(); err != nil {
		t.Fatalf("close direct egress: %v", err)
	}
	requireTupleReleased(t, "host UDP bind after Close", tryBindHostUDP(net.IPv4zero, closed))
	if got := h.dem.HostReservationCount(); got != 0 {
		t.Fatalf("Close left %d reservation(s)", got)
	}
}
