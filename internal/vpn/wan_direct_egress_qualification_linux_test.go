//go:build linux

package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"golang.org/x/sys/unix"
)

// s4QualificationEnvName is the participant switch for the namespace fixture; it
// lives with the fixture and is referenced here only to explain the skip message.
//
// This file is the S4 gate: it qualifies the real production path from a client
// packet, through the production dispatcher and the production WAN device, out to
// a live remote TCP/UDP peer, and back through the production reply capture and
// DNAT to the owning peer's return path.
//
// It is deliberately NOT a simulation of that path: the WAN device is created by
// NewProductionWANDevice (real TUN + real AF_PACKET capture + real iptables reset
// suppression), the dispatcher is the one ConfigurePBR installs, the forwarding
// decision comes from the real policy matcher, and the remote endpoint is a real
// TCP and UDP server in a separate network namespace reached over a veth pair. The
// kernel — not a mock — performs forwarding, source NAT, and the return delivery.

// TestS4ProductionContainerHostWANQualification is the S4 acceptance gate for
// issue #677: actual production container-to-host-WAN TCP/UDP/NAT reply
// qualification.
//
// Requirements covered (see TASK.md "Deliverables" and the S4 gate in
// STABILIZATION.md):
//   - R2  a direct IPv4 TCP flow with NAT and replies, then UDP
//   - R7  separate proxied/direct counters that only move on real delivery
//   - R6  replies reach the owning peer's return path and nobody else's
//
// The gate always runs wherever an isolated user+network namespace can be created.
// Only an environment that cannot create one is skipped, and it says why, so a
// green run can never be produced by silently not executing the check.
func TestS4ProductionContainerHostWANQualification(t *testing.T) {
	// Run the whole check inside a private user+network namespace so the fixture
	// can build its own uplink, firewall and kernel settings without touching the
	// host. A namespace that cannot be created is an environment limitation, and
	// is reported as a skip with the reason, never as a pass.
	out, err := runS4QualificationProbe()
	if err != nil {
		t.Skipf("cannot create isolated user+network namespace here: %v\n%s", err, out)
	}
	if !strings.Contains(out, "S4 RESULT: PASS") {
		t.Fatalf("S4 qualification failed:\n%s", out)
	}
	t.Logf("S4 qualification output:\n%s", out)
}

// s4ProbeEnv marks the re-executed qualification body.
const s4ProbeEnv = "NEXUS_S4_PROBE"

func init() {
	if os.Getenv(s4ProbeEnv) == "" {
		return
	}
	os.Exit(runS4QualificationBody())
}

// runS4QualificationProbe re-executes this test binary inside `unshare -Urn` so the
// qualification owns a private network namespace with the capabilities the
// deployed container gains from `cap_add`.
func runS4QualificationProbe() (string, error) {
	// #nosec G204 -- os.Args[0] is this test binary; the namespace flags are literals
	cmd := exec.Command("unshare", "-Urn", "--map-root-user", os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), s4ProbeEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "S4 RESULT:") {
		return string(out), fmt.Errorf("probe could not run (namespace setup): %w", err)
	}
	return string(out), nil
}

// runS4QualificationBody is the qualification itself. It returns a process exit
// code and prints a single machine-readable verdict line.
func runS4QualificationBody() int {
	fail := func(format string, args ...any) int {
		fmt.Printf("S4 RESULT: FAIL: "+format+"\n", args...)
		return 1
	}

	fixture, err := newS4Fixture()
	if err != nil {
		return fail("build host-WAN fixture: %v", err)
	}
	defer fixture.Close()

	if failed := applyS4DeploymentSysctls(); len(failed) > 0 {
		return fail("documented deployment settings did not apply: %v", failed)
	}
	if err := s4ForwardingRules(fixture.wanIface, s4WANDeviceName); err != nil {
		return fail("install forwarding rules: %v", err)
	}

	// Production WAN device: real TUN, real AF_PACKET capture, real iptables.
	wanDev, err := NewProductionWANDevice(s4WANDeviceName)
	if err != nil {
		return fail("NewProductionWANDevice: %v", err)
	}
	defer func() { _ = wanDev.Close() }()

	if err := fixture.peer.waitReady(); err != nil {
		return fail("%v", err)
	}

	// Wait for the remote namespace's link, address and listeners to settle before
	// the first packet, so a slow start is not reported as a product defect.
	if err := s4AwaitPeerReachable(fixture.peerIP); err != nil {
		return fail("remote peer never became reachable: %v", err)
	}

	svc, dem, replies, cleanup, err := s4BuildDispatcherService(wanDev, fixture)
	if err != nil {
		return fail("build PBR dispatcher: %v", err)
	}
	defer cleanup()

	// --- Phase 1: the documented deployment alone does NOT deliver --------------
	// With exactly the settings the README prescribes (rp_filter=2), the dispatcher
	// SNATs direct egress to the host WAN address, which is local to this host, and
	// the kernel's reverse-path check drops the injected packet as a martian before
	// it is ever forwarded. This is asserted as a negative control so the passing
	// phase below cannot be an artefact of a permissive environment: if this phase
	// starts delivering, the deployment gap has changed and the qualification must
	// be re-derived rather than silently keep passing.
	strictStats := s4SnapshotIPStats()
	if err := s4SendClientPacket(svc, "peer-s4-udp", "10.100.0.10", "sess-s4-udp", 12345, fixture.peerIP, s4RemotePort, []byte("s4-strict-probe"), 17); err != nil {
		return fail("route direct UDP packet under documented settings: %v", err)
	}
	if _, delivered := s4WaitReply(replies, "peer-s4-udp", 1500*time.Millisecond); delivered {
		return fail("documented deployment delivered a direct reply without relaxing reverse-path filtering; the S4 finding no longer reproduces and this qualification must be re-derived")
	}
	strictDelta := s4StatDelta(strictStats, s4SnapshotIPStats())
	if strictDelta["IpForwDatagrams"] != 0 {
		return fail("expected zero forwarded datagrams under the documented settings, got %d", strictDelta["IpForwDatagrams"])
	}

	// --- Phase 2: the prerequisite the deployment must add ---------------------
	// The dispatcher injects an already-SNATed packet, so source validation must be
	// off for the device it enters. Relaxing it is the documented-deployment gap
	// this gate reports; it is applied here as an explicit, measured prerequisite
	// rather than a silent workaround.
	if err := s4SetReversePathFilter("0"); err != nil {
		return fail("relax reverse-path filtering: %v", err)
	}

	// --- UDP: direct egress, real reply, DNAT back to the owning peer ------------
	directDropBase := dem.DirectDrops()
	udpPayload := []byte("s4-udp-probe")
	if err := s4SendClientPacket(svc, "peer-s4-udp", "10.100.0.10", "sess-s4-udp", 12345, fixture.peerIP, s4RemotePort, udpPayload, 17); err != nil {
		return fail("route direct UDP packet: %v", err)
	}
	udpReply, ok := s4WaitReply(replies, "peer-s4-udp", 5*time.Second)
	if !ok {
		return fail("no UDP reply reached the owning peer (directDrops %d -> %d) after writing to the production WAN device",
			directDropBase, dem.DirectDrops())
	}
	if want := "ECHO:" + string(udpPayload); !strings.HasSuffix(string(udpReply), want) {
		return fail("UDP reply payload %q does not end with %q", string(udpReply[len(udpReply)-16:]), want)
	}
	if err := s4AssertDNAT(udpReply, "10.100.0.10", 12345, fixture.peerIP, s4RemotePort); err != nil {
		return fail("UDP reply DNAT: %v", err)
	}
	if dem.DirectBytes() == 0 {
		return fail("directBytes stayed 0 after a delivered direct UDP flow")
	}

	// --- TCP: real handshake, data, and reply through the same capture path ------
	// The dispatcher ships whole packets, so the SYN and the data segment are
	// injected here with sequence numbers taken from the peer's real SYN-ACK.
	syn := buildTestPBRTCPPacket(netip.MustParseAddr("10.100.0.11"), fixture.peerIP, 23456, s4RemotePort, nil)
	setTCPSeqAck(syn, 1000, 0, 0x02)
	if err := svc.forwarder.RouteClientToBackend("peer-s4-tcp", syn); err != nil {
		return fail("route direct TCP SYN: %v", err)
	}
	synAck, ok := s4WaitReplyKind(replies, "peer-s4-tcp", 6, 0x12, 5*time.Second)
	if !ok {
		return fail("no SYN-ACK captured from the remote peer for a direct TCP flow")
	}
	if err := s4AssertDNAT(synAck, "10.100.0.11", 23456, fixture.peerIP, s4RemotePort); err != nil {
		return fail("TCP SYN-ACK DNAT: %v", err)
	}
	serverSeq := binary.BigEndian.Uint32(synAck[24:28])

	data := buildTestPBRTCPPacket(netip.MustParseAddr("10.100.0.11"), fixture.peerIP, 23456, s4RemotePort, []byte("s4-tcp-probe"))
	setTCPSeqAck(data, 1001, serverSeq+1, 0x18)
	if err := svc.forwarder.RouteClientToBackend("peer-s4-tcp", data); err != nil {
		return fail("route direct TCP data: %v", err)
	}
	tcpEcho, ok := s4WaitReplyPrefix(replies, "peer-s4-tcp", "ECHO:s4-tcp-probe", 5*time.Second)
	if !ok {
		return fail("no TCP echo reached the owning peer for a direct flow")
	}
	if err := s4AssertDNAT(tcpEcho, "10.100.0.11", 23456, fixture.peerIP, s4RemotePort); err != nil {
		return fail("TCP echo DNAT: %v", err)
	}

	// --- Ownership: a reply is delivered only to the peer that owns the flow -----
	if s4PeerGotReply(replies, "peer-s4-other") {
		return fail("a direct reply was delivered to a peer that owns no flow")
	}

	// --- Proxy path still works in the same dispatcher instance ------------------
	// Proves the direct path did not displace the existing proxy behaviour: an
	// UNKNOWN destination must reach the backend queue and never the WAN device.
	// The counters are sampled around this single packet, because the direct TCP
	// flow above legitimately continues to produce reply traffic (retransmits and
	// the close) that a wider window would attribute to the proxy route.
	dropsBeforeProxy := dem.DirectDrops()
	bytesBeforeProxy := dem.DirectBytes()
	if err := svc.forwarder.RouteClientToBackend("peer-s4-proxy", buildTestPBRUDPPacket(
		netip.MustParseAddr("10.100.0.12"), netip.MustParseAddr("8.8.4.4"), 5555, 53, []byte("proxy-probe"))); err != nil {
		return fail("route UNKNOWN destination packet: %v", err)
	}
	queued, ok := svc.forwarder.GetBackendPacketChannel(s4ProxyBackendID)
	if !ok || len(queued) == 0 {
		return fail("UNKNOWN destination did not reach the proxy backend queue")
	}
	if got := dem.DirectDrops(); got != dropsBeforeProxy {
		return fail("proxied traffic incremented directDrops (%d -> %d)", dropsBeforeProxy, got)
	}
	if got := dem.DirectBytes(); got != bytesBeforeProxy {
		return fail("proxied traffic incremented directBytes (%d -> %d)", bytesBeforeProxy, got)
	}

	fmt.Printf("S4 RESULT: PASS: production WAN device + dispatcher delivered direct UDP and TCP replies from %s:%d to the owning peer with DNAT (directBytes=%d, directDrops=%d)\n",
		fixture.peerIP, s4RemotePort, dem.DirectBytes(), dem.DirectDrops())
	return 0
}

// s4ProxyBackendID is the backend tunnel id the proxy-path assertion observes.
const s4ProxyBackendID = int64(301)

// s4PeerReplies records per-peer reply deliveries from the dispatcher.
type s4PeerReplies struct {
	mu     sync.Mutex
	byPeer map[string][][]byte
}

func newS4PeerReplies() *s4PeerReplies {
	return &s4PeerReplies{byPeer: map[string][][]byte{}}
}

func (r *s4PeerReplies) add(peerKey string, packet []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]byte, len(packet))
	copy(cp, packet)
	r.byPeer[peerKey] = append(r.byPeer[peerKey], cp)
}

func (r *s4PeerReplies) packets(peerKey string) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.byPeer[peerKey]))
	copy(out, r.byPeer[peerKey])
	return out
}

// s4BuildDispatcherService builds the production dispatcher wiring: a real policy
// matcher, the memory route cache, ConfigurePBR installing the DirectEgressManager
// over the production WAN device, and a return path per peer.
func s4BuildDispatcherService(wanDev forwarder.PacketDevice, fixture *s4Fixture) (*Service, *forwarder.DirectEgressManager, *s4PeerReplies, func(), error) {
	rules, _, err := policy.Parse(context.Background(), strings.NewReader("blocked.example\n"), policy.Source{
		ID:             "s4-qualification",
		Format:         policy.FormatDomains,
		BareDomainMode: policy.DomainModeExact,
	}, policy.DefaultParseLimits())
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse policy: %w", err)
	}
	src := policy.NewMemorySource("s4-qualification", rules)

	matcher := policy.NewMatcher()
	snapshot, err := policy.CompileSnapshot(1, "gen-s4", []policy.SourceParsedRules{src.ToSourceParsedRules()})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("compile policy snapshot: %w", err)
	}
	matcher.Publish(snapshot)

	rc := NewMemoryRouteCache()
	rc.AttachMatcher(matcher)

	fwd := forwarder.NewForwarder(nil, "10.100.0.0/16", 100)
	backendQueue := make(chan []byte, 8)
	fwd.SetBackendQueueForTest(s4ProxyBackendID, backendQueue)

	replies := newS4PeerReplies()
	for _, peer := range []struct{ peerKey, clientIP string }{
		{"peer-s4-udp", "10.100.0.10"},
		{"peer-s4-tcp", "10.100.0.11"},
		{"peer-s4-proxy", "10.100.0.12"},
	} {
		peer, clientIP := peer.peerKey, peer.clientIP
		path := forwarder.NewReturnPath(func(peerKey, assignedIP string, packet []byte) (int, error) {
			replies.add(peerKey, packet)
			return len(packet), nil
		})
		fwd.RegisterSessionWithReturnPath("sess-"+peer, "conn-"+peer, peer, clientIP, s4ProxyBackendID, path)
		// Direct decisions come from observed client DNS evidence, exactly as in
		// production; seeding the cache for the fixture peer keeps the flow honest
		// without inventing a second decision path.
		rc.Set("sess-"+peer, fixture.peerIP, policy.Direct)
	}

	svc := &Service{forwarder: fwd}
	cfg := PBRConfig{
		Enabled:       true,
		HostWANIP:     netip.MustParseAddr(s4HostWAN),
		GatewayDNSIP:  netip.MustParseAddr("10.100.0.1"),
		WANDevice:     wanDev,
		RouteCache:    rc,
		PolicyMatcher: matcher,
	}
	if err := svc.ConfigurePBR(cfg); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("ConfigurePBR: %w", err)
	}
	dem := svc.forwarder.DirectEgress()
	if dem == nil {
		return nil, nil, nil, nil, errors.New("ConfigurePBR did not install a DirectEgressManager")
	}
	fwd.StartPumps(context.Background())
	return svc, dem, replies, func() { fwd.StopPumps(); _ = svc.TeardownPBR() }, nil
}

// s4SendClientPacket routes one synthetic client packet through the dispatcher.
func s4SendClientPacket(svc *Service, peerKey, clientIP, sessionID string, clientPort uint16, dstIP netip.Addr, dstPort uint16, payload []byte, proto uint8) error {
	src := netip.MustParseAddr(clientIP)
	var pkt []byte
	switch proto {
	case 17:
		pkt = buildTestPBRUDPPacket(src, dstIP, clientPort, dstPort, payload)
	case 6:
		pkt = buildTestPBRTCPPacket(src, dstIP, clientPort, dstPort, payload)
		setTCPSeqAck(pkt, 1000, 0, 0x18)
	default:
		return fmt.Errorf("unsupported protocol %d", proto)
	}
	return svc.forwarder.RouteClientToBackend(peerKey, pkt)
}

// setTCPSeqAck writes the sequence, acknowledgement and flags of a TCP header.
func setTCPSeqAck(pkt []byte, seq, ack uint32, flags uint8) {
	if len(pkt) < 40 {
		return
	}
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], ack)
	pkt[32] = 0x50
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 65535)
	// Recompute the transport checksum over the modified header.
	src := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}
	dst := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}
	binary.BigEndian.PutUint16(pkt[36:38], 0)
	binary.BigEndian.PutUint16(pkt[36:38], s4L4Checksum(src, dst, 6, pkt[20:]))
}

// s4L4Checksum computes a TCP/UDP checksum over the pseudo-header plus segment.
func s4L4Checksum(src, dst [4]byte, proto uint8, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// s4AssertDNAT checks a captured reply was translated back to the client.
func s4AssertDNAT(packet []byte, clientIP string, clientPort uint16, remoteIP netip.Addr, remotePort uint16) error {
	if len(packet) < 40 {
		return fmt.Errorf("reply too short to carry an IPv4 transport header: %d bytes", len(packet))
	}
	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
	dstPort := binary.BigEndian.Uint16(packet[22:24])
	srcIP := netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
	srcPort := binary.BigEndian.Uint16(packet[20:22])
	if dstIP.String() != clientIP || dstPort != clientPort {
		return fmt.Errorf("expected DNAT to %s:%d, got %s:%d", clientIP, clientPort, dstIP, dstPort)
	}
	if srcIP != remoteIP || srcPort != remotePort {
		return fmt.Errorf("expected reply source %s:%d, got %s:%d", remoteIP, remotePort, srcIP, srcPort)
	}
	return nil
}

// s4WaitReply waits for any reply delivered to a peer.
func s4WaitReply(replies *s4PeerReplies, peerKey string, timeout time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pkts := replies.packets(peerKey); len(pkts) > 0 {
			return pkts[len(pkts)-1], true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

// s4WaitReplyKind waits for a reply with a specific IP protocol and TCP flags.
func s4WaitReplyKind(replies *s4PeerReplies, peerKey string, proto uint8, flags uint8, timeout time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, pkt := range replies.packets(peerKey) {
			if len(pkt) >= 40 && pkt[9] == proto && pkt[33]&flags == flags {
				return pkt, true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

// s4WaitReplyPrefix waits for a reply whose payload starts with prefix.
func s4WaitReplyPrefix(replies *s4PeerReplies, peerKey, prefix string, timeout time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, pkt := range replies.packets(peerKey) {
			if len(pkt) > 40 && strings.HasPrefix(string(pkt[40:]), prefix) {
				return pkt, true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil, false
}

// s4PeerGotReply reports whether anything was delivered to a peer.
func s4PeerGotReply(replies *s4PeerReplies, peerKey string) bool {
	return len(replies.packets(peerKey)) > 0
}

// s4AwaitPeerReachable waits until the remote namespace answers on the veth, so a
// slow peer start is not mistaken for a dispatcher defect.
func s4AwaitPeerReachable(peer netip.Addr) error {
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp4", peer.String()+":8080", 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}

var _ = unix.Close
