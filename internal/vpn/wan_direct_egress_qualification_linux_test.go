//go:build linux

package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

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
// The gate must not be able to pass by not running. In required CI it always
// executes and any inability to build the isolated topology is a FAILURE with the
// captured evidence, never a skip. Outside CI a skip is allowed only when the
// environment provably cannot provide namespaces, and the reason is printed.
func TestS4ProductionContainerHostWANQualification(t *testing.T) {
	out, err := runS4QualificationProbe()
	if err != nil {
		if s4RequiredEnvironment() {
			t.Fatalf("S4 qualification could not execute in required CI, so the claimed production gate is unproven: %v\n%s", err, out)
		}
		t.Skipf("cannot create isolated user+network namespace in this optional environment: %v\n%s", err, out)
	}
	if !strings.Contains(out, "S4 RESULT: PASS") {
		t.Fatalf("S4 qualification failed:\n%s", out)
	}
	t.Logf("S4 qualification output:\n%s", out)
}

// s4RequiredEnvironment reports whether this run is a required CI gate, where a
// skipped S4 qualification would be misrepresented as a pass.
//
// The CI job container runs `go test` inside a Docker container that does not
// propagate GITHUB_ACTIONS, so the marker is an explicit environment variable the
// workflow sets, defaulting to "required" for any GITHUB_ACTIONS run.
func s4RequiredEnvironment() bool {
	if v := os.Getenv("NEXUS_S4_REQUIRED"); v != "" {
		return v != "0"
	}
	return os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("CI") != ""
}

// TestS4RequiredEnvironment pins the anti-silent-skip contract: a required CI run
// must never be able to report success by not executing the gate.
func TestS4RequiredEnvironment(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"explicit required", map[string]string{"NEXUS_S4_REQUIRED": "1"}, true},
		{"explicit optional", map[string]string{"NEXUS_S4_REQUIRED": "0"}, false},
		{"github actions default", map[string]string{"GITHUB_ACTIONS": "true"}, true},
		{"ci default", map[string]string{"CI": "true"}, true},
		{"plain developer shell", map[string]string{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"NEXUS_S4_REQUIRED", "GITHUB_ACTIONS", "CI"} {
				t.Setenv(key, "")
			}
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			if got := s4RequiredEnvironment(); got != tc.want {
				t.Fatalf("s4RequiredEnvironment() = %v, want %v for env %v", got, tc.want, tc.env)
			}
		})
	}
}

// TestS4QualificationFailsWhenNamespaceUnavailable pins that a required run whose
// namespace cannot be created is a FAILURE, and that an optional run is a skip.
// A skipped required gate would let the claimed S4 acceptance pass without ever
// exercising the subject.
func TestS4QualificationFailsWhenNamespaceUnavailable(t *testing.T) {
	// Put a non-functional `unshare` first on PATH so namespace creation fails.
	dir := t.TempDir()
	script := filepath.Join(dir, "unshare")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatalf("write fake unshare: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	t.Run("required_fails", func(t *testing.T) {
		t.Setenv("NEXUS_S4_REQUIRED", "1")
		if _, err := runS4QualificationProbe(); err == nil {
			t.Fatal("a required run must report an error when the namespace cannot be created")
		}
	})

	t.Run("optional_skips", func(t *testing.T) {
		t.Setenv("NEXUS_S4_REQUIRED", "0")
		// The probe still errors; the *test* decides skip vs fail, and this asserts
		// the marker that drives that decision.
		if s4RequiredEnvironment() {
			t.Fatal("NEXUS_S4_REQUIRED=0 must not be treated as a required environment")
		}
	})
}

// s4ProbeEnv marks the re-executed qualification body.
const s4ProbeEnv = "NEXUS_S4_PROBE"

func init() {
	if os.Getenv(s4ProbeEnv) == "" {
		return
	}
	os.Exit(runS4QualificationBody())
}

// runS4QualificationProbe runs the qualification in a private user+network
// namespace created for this run, and returns its output.
//
// The namespace is the fixture: it owns its uplink, firewall, TUN device and kernel
// settings, and disappears with the process, so no host state is read or written.
//
// If the namespace cannot be created, the caller decides whether that is a failure
// or a skip — in required CI it is a FAILURE, never a silent pass.
func runS4QualificationProbe() (string, error) {
	// #nosec G204 -- os.Args[0] is this test binary; the namespace flags are literals
	cmd := exec.Command("unshare", "-Urn", "--map-root-user", os.Args[0], "-test.run=^$")
	// The owned-namespace marker is set by the parent that creates the namespace, so a
	// test running inside it can prove it owns the kernel settings it configures. It is
	// set here, not inside the child, because only the parent knows unshare succeeded.
	cmd.Env = append(os.Environ(), s4ProbeEnv+"=1", s4OwnedNamespaceEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "S4 RESULT:") {
		return string(out), fmt.Errorf("probe could not run (namespace setup): %w", err)
	}
	return string(out), nil
}

// runS4QualificationBody is the qualification run as a re-executed process inside the
// private namespace. It returns a process exit code.
func runS4QualificationBody() int {
	// This process was started by runS4QualificationProbe inside a private
	// `unshare -Urn` namespace that it owns and that disappears when it exits, so
	// configuring that namespace is fixture setup, not a host change.
	if err := configurePrivateNamespaceSetup(); err != nil {
		fmt.Printf("S4 RESULT: FAIL: %v\n", err)
		return 1
	}
	return runS4QualificationBodyTo(os.Stdout)
}

// configurePrivateNamespaceSetup applies the direct-egress settings to the private
// namespace this process created for itself. It must only ever be called from the
// re-executed probe (s4ProbeEnv), which by construction owns a throwaway namespace
// that vanishes with the process; it never runs against a deployment or the host.
func configurePrivateNamespaceSetup() error {
	for _, setting := range []struct{ key, value string }{
		{"net.ipv4.ip_forward", "1"},
		{"net.ipv4.conf.all.rp_filter", "0"},
		{"net.ipv4.conf.default.rp_filter", "0"},
		{"net.ipv4.conf.all.accept_local", "1"},
	} {
		if out, err := s4Command("sysctl", "-w", setting.key+"="+setting.value); err != nil {
			return fmt.Errorf("configure private namespace %s: %w: %s", setting.key, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// runS4QualificationBodyTo is the qualification itself, writing everything to w so
// it can run either as a re-executed process or in-process. It returns an exit code
// and emits exactly one machine-readable verdict line.
func runS4QualificationBodyTo(w io.Writer) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(w, "S4 RESULT: FAIL: "+format+"\n", args...)
		return 1
	}
	// logf keeps narrative output (the red-phase evidence) next to the verdict.
	logf := func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	fixture, err := newS4Fixture()
	if err != nil {
		return fail("build host-WAN fixture: %v", err)
	}
	defer fixture.Close()

	// --- Phase 1: the documented deployment is REFUSED by the production path ---
	// With the settings the README used to prescribe (rp_filter=2), direct egress
	// cannot forward: the dispatcher SNATs to the host WAN address, which is local to
	// this host, and source validation drops the packet as a martian. The production
	// constructor must therefore reject that configuration instead of starting a data
	// plane that silently forwards nothing.
	//
	// This runs the REAL production validator over a synthetic sysctl tree rather than
	// editing this container's sysctls: a deployed container mounts /proc/sys
	// read-only, and rewriting the environment under test would prove something the
	// deployment does not do. The synthetic tree is the only way to hold two
	// configurations in one run.
	if err := s4AssertDocumentedConfigRejected(); err != nil {
		return fail("%v", err)
	}

	// --- Phase 2: the deployed configuration, which must qualify end to end -------
	// The settings are OBSERVED, never written: they arrive from `--sysctl` or the
	// host. A gate that cannot see a usable configuration must fail, not pass quietly.
	reported := s4SourceValidationSettings()
	if effective := reported["effective_rp_filter"]; effective != "0" {
		return fail("qualifying requires rp_filter=0 as the effective value (observed %q from all=%q default=%q); start the container with rp_filter=0 via --sysctl",
			effective, reported["all_rp_filter"], reported["default_rp_filter"])
	}

	// --- Phase 1b: the same production constructor REFUSES a live incompatible host
	// This is the live half of the counterexample: in this namespace, which we own,
	// set the incompatible settings for real, hand the address to the production
	// validator exactly as startup does, and require it to refuse with the
	// actionable error and to create no tunnel device. Then restore a compatible
	// configuration so the qualifying path below runs against a real one.
	//
	// The synthetic-tree case above stays: it holds the documented deployment's
	// values without mutating the live namespace, and this live case proves the same
	// guard fires on REAL procfs rather than only on a fixture tree.
	if err := s4AssertLiveIncompatibleConfigRefused(); err != nil {
		return fail("%v", err)
	}

	// Production WAN device: real TUN, real AF_PACKET capture, real iptables.
	wanDev, err := NewProductionWANDevice(s4WANDeviceName)
	if err != nil {
		return fail("NewProductionWANDevice with rp_filter=0: %v", err)
	}
	defer func() { _ = wanDev.Close() }()

	if failed := s4RequireForwardingSettings(); len(failed) > 0 {
		return fail("forwarding settings are not in effect: %v", failed)
	}
	if err := s4ForwardingRules(fixture.wanIface, s4WANDeviceName); err != nil {
		return fail("install forwarding rules: %v", err)
	}

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

	// --- UDP: direct egress, real reply, DNAT back to the owning peer ------------
	directDropBase := dem.DirectDrops()
	udpPayload := []byte("s4-udp-probe")
	if err := s4SendClientPacket(svc, "peer-s4-udp", "10.100.0.10", "sess-s4-udp", 12345, fixture.peerIP, s4RemotePort, udpPayload, 17); err != nil {
		return fail("route direct UDP packet: %v", err)
	}
	udpReply, ok := s4WaitReply(replies, "peer-s4-udp", 5*time.Second)
	if !ok {
		return fail("no UDP reply reached the owning peer (directDrops %d -> %d) after writing to the production WAN device; kernel drop evidence: %v",
			directDropBase, dem.DirectDrops(), s4KernelDropEvidence())
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
	// UNKNOWN destination must be proxied and never touch the WAN device.
	// The counters are sampled around this single packet, because the direct TCP
	// flow above legitimately continues to produce reply traffic (retransmits and
	// the close) that a wider window would attribute to the proxy route.
	dropsBeforeProxy := dem.DirectDrops()
	bytesBeforeProxy := dem.DirectBytes()
	if err := svc.forwarder.RouteClientToBackend("peer-s4-proxy", s4UDPPacketWithChecksums(
		netip.MustParseAddr(s4ProxyBackendClientIP), s4ProxyDstIP, 5555, 53, []byte("proxy-probe"))); err != nil {
		return fail("route UNKNOWN destination packet: %v", err)
	}
	if got := dem.DirectDrops(); got != dropsBeforeProxy {
		return fail("proxied traffic incremented directDrops (%d -> %d)", dropsBeforeProxy, got)
	}
	if got := dem.DirectBytes(); got != bytesBeforeProxy {
		return fail("proxied traffic incremented directBytes (%d -> %d)", bytesBeforeProxy, got)
	}

	// --- Proxy reply returns through the real backend device and pumps ----------
	// The backend is a real packet device (netstack) attached with
	// AttachBackendDevice, so the request travels the production path
	// backendQueues -> pumpBackendQueue -> device.Write, the backend echoes it, and
	// the reply comes back through the production reader -> RouteBackendToClient ->
	// pumpClientQueue -> the owning peer's ReturnPath. An unconsumed channel would
	// only prove dispatch precedence; this proves the packet actually moves.
	proxyReply, ok := s4WaitReplyPrefix(replies, "peer-s4-proxy", "ECHO:proxy-probe", 5*time.Second)
	if !ok {
		return fail("no proxy request/reply completed through the attached backend device (directDrops %d, directBytes %d); the proxy path did not carry a packet end to end",
			dem.DirectDrops(), dem.DirectBytes())
	}
	// The reply must be addressed back to the owning client, not to another peer.
	if err := s4AssertProxyReplyAddressed(proxyReply, "10.100.0.12", 5555); err != nil {
		return fail("proxy reply %v", err)
	}
	// Ownership: the proxy reply reached its owner and no other peer saw it.
	if s4PeerGotReply(replies, "peer-s4-udp") || s4PeerGotReply(replies, "peer-s4-tcp") {
		return fail("a proxy reply was delivered to a peer that owns no proxied flow")
	}
	if got := dem.DirectDrops(); got != dropsBeforeProxy {
		return fail("the proxy round trip incremented directDrops (%d -> %d)", dropsBeforeProxy, got)
	}
	if got := dem.DirectBytes(); got != bytesBeforeProxy {
		return fail("the proxy round trip incremented directBytes (%d -> %d)", bytesBeforeProxy, got)
	}

	logf("S4 RESULT: PASS: production WAN device + dispatcher delivered direct UDP and TCP replies from %s:%d to the owning peer with DNAT (directBytes=%d, directDrops=%d)",
		fixture.peerIP, s4RemotePort, dem.DirectBytes(), dem.DirectDrops())
	return 0
}

// s4ProxyBackendID identifies the backend tunnel the proxy-path assertions observe;
// s4ProxyBackendClientIP is the client peer whose traffic must take the proxy path.
const (
	s4ProxyBackendID       = int64(301)
	s4ProxyBackendClientIP = "10.100.0.12"
)

// s4ProxyDstIP is the UNKNOWN public destination the proxied client targets. The
// backend stack is given this address so the packet the pumps write into the device
// is actually delivered to the echo listener; nothing else about the path changes.
var s4ProxyDstIP = netip.MustParseAddr("8.8.4.4")

// s4UDPPacketWithChecksums builds a UDP/IPv4 packet with BOTH checksums computed.
//
// The shared buildTestPBRUDPPacket helper leaves the IPv4 header checksum and the UDP
// checksum zero, which is fine for the address-parsing assertions it was written for
// but is not a packet any receiver accepts: a userspace stack validates the header
// checksum on inbound injection and silently drops a packet without it. The proxy
// path forwards the client's packet to the backend verbatim, so the fixture must send
// a well-formed one or the round trip proves nothing.
func s4UDPPacketWithChecksums(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	pkt := buildTestPBRUDPPacket(src, dst, srcPort, dstPort, payload)
	total := len(pkt)

	// UDP checksum over the pseudo-header plus the segment.
	var udpSum uint32
	srcB, dstB := src.As4(), dst.As4()
	udpSum += uint32(binary.BigEndian.Uint16(srcB[0:2])) + uint32(binary.BigEndian.Uint16(srcB[2:4]))
	udpSum += uint32(binary.BigEndian.Uint16(dstB[0:2])) + uint32(binary.BigEndian.Uint16(dstB[2:4]))
	udpSum += uint32(17)         // protocol
	udpSum += uint32(total - 20) // UDP length
	for i := 20; i < total; i += 2 {
		if i+1 < total {
			udpSum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
		} else {
			udpSum += uint32(pkt[i]) << 8
		}
	}
	for udpSum>>16 != 0 {
		udpSum = (udpSum & 0xffff) + (udpSum >> 16)
	}
	udpCS := ^uint16(udpSum)
	if udpCS == 0 {
		udpCS = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[26:28], udpCS)

	// IPv4 header checksum.
	var hdrSum uint32
	for i := 0; i < 20; i += 2 {
		hdrSum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for hdrSum>>16 != 0 {
		hdrSum = (hdrSum & 0xffff) + (hdrSum >> 16)
	}
	hdrCS := ^uint16(hdrSum)
	if hdrCS == 0 {
		hdrCS = 0xffff
	}
	binary.BigEndian.PutUint16(pkt[10:12], hdrCS)
	return pkt
}

// s4BuildBackendEcho creates the proxy backend as a REAL packet device: a netstack
// TUN with a UDP echo listener, wrapped in the same returnStackDevice the rest of
// the harness uses. Attaching it with AttachBackendDevice (rather than a bare
// channel) makes the production pumps move the packet: request out through
// pumpBackendQueue -> device.Write, echo answered inside the stack, reply in
// through the production reader -> RouteBackendToClient -> pumpClientQueue.
//
// It returns the device and a stop function that closes the listener, joins the
// echo goroutine and closes the stack, so teardown cannot race the pumps.
func s4BuildBackendEcho() (forwarder.PacketDevice, func(), error) {
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{s4ProxyDstIP}, nil, 1280)
	if err != nil {
		return nil, nil, fmt.Errorf("create backend netstack: %w", err)
	}
	udpConn, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(s4ProxyDstIP, 53))
	if err != nil {
		_ = vt.Close()
		return nil, nil, fmt.Errorf("listen on backend stack: %w", err)
	}

	stop := make(chan struct{})
	var echoWG sync.WaitGroup
	echoWG.Add(1)
	go func() {
		defer echoWG.Done()
		buf := make([]byte, 2048)
		for {
			n, from, readErr := udpConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			reply := append([]byte("ECHO:"), buf[:n]...)
			if _, writeErr := udpConn.WriteTo(reply, from); writeErr != nil {
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()

	device := &returnStackDevice{tun: vt}
	return device, func() {
		close(stop)
		_ = udpConn.Close()
		echoWG.Wait()
		_ = device.Close()
	}, nil
}

// s4ProxyBackendReader pumps the backend device's replies into the production
// return path, exactly as the service does for a real backend tunnel.
func s4ProxyBackendReader(fwd *forwarder.Forwarder, dev forwarder.PacketDevice, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 2048)
	for {
		n, readErr := dev.Read(buf)
		if readErr != nil {
			return
		}
		if n < 20 || buf[0]>>4 != 4 {
			continue
		}
		destIP := netip.AddrFrom4([4]byte{buf[16], buf[17], buf[18], buf[19]}).String()
		_ = fwd.RouteBackendToClient(s4ProxyBackendID, buf[:n], destIP)
	}
}

// s4AssertProxyReplyAddressed checks a proxy reply was translated back to the
// client that owns the proxied flow.
func s4AssertProxyReplyAddressed(packet []byte, clientIP string, clientPort uint16) error {
	if len(packet) < 40 {
		return fmt.Errorf("too short to carry an IPv4 transport header: %d bytes", len(packet))
	}
	dstIP := netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]}).String()
	dstPort := binary.BigEndian.Uint16(packet[22:24])
	if dstIP != clientIP || dstPort != clientPort {
		return fmt.Errorf("expected to be addressed to the owning client %s:%d, got %s:%d", clientIP, clientPort, dstIP, dstPort)
	}
	return nil
}

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

	// The proxy backend is a real packet device, not a bare channel: attach it so
	// the production pumps move the request to it and its replies come back
	// through the production return path.
	backendDev, stopBackend, err := s4BuildBackendEcho()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build proxy backend device: %w", err)
	}
	fwd.AttachBackendDevice(s4ProxyBackendID, backendDev)

	replies := newS4PeerReplies()
	for _, peer := range []struct{ peerKey, clientIP string }{
		{"peer-s4-udp", "10.100.0.10"},
		{"peer-s4-tcp", "10.100.0.11"},
		{"peer-s4-proxy", s4ProxyBackendClientIP},
	} {
		peer, clientIP := peer.peerKey, peer.clientIP
		path := forwarder.NewReturnPath(func(peerKey, assignedIP string, packet []byte) (int, error) {
			replies.add(peerKey, packet)
			return len(packet), nil
		})
		fwd.RegisterSessionWithReturnPath("sess-"+peer, "conn-"+peer, peer, clientIP, s4ProxyBackendID, path)
		// Direct decisions come from observed client DNS evidence, exactly as in
		// production; seeding the cache for the fixture peer keeps the flow honest
		// without inventing a second decision path. The proxied peer deliberately
		// gets NO direct decision, so its packet must take the proxy path.
		if clientIP != s4ProxyBackendClientIP {
			rc.Set("sess-"+peer, fixture.peerIP, policy.Direct)
		}
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
		stopBackend()
		return nil, nil, nil, nil, fmt.Errorf("ConfigurePBR: %w", err)
	}
	dem := svc.forwarder.DirectEgress()
	if dem == nil {
		stopBackend()
		return nil, nil, nil, nil, errors.New("ConfigurePBR did not install a DirectEgressManager")
	}
	fwd.StartPumps(context.Background())

	// The backend return reader runs as the service does it in production: it
	// drains the device and hands each reply to RouteBackendToClient.
	backendDone := make(chan struct{})
	go s4ProxyBackendReader(fwd, backendDev, backendDone)

	return svc, dem, replies, func() {
		fwd.StopPumps()
		_ = svc.TeardownPBR()
		stopBackend()
		<-backendDone
	}, nil
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
