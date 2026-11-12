//go:build linux

package vpn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// This file is the topology half of the S4 qualification: a host-WAN fixture that
// lets a test drive the *production* WAN device and the *production* egress
// dispatcher against a real remote TCP/UDP peer, without touching the runner's
// networking and without any privilege the deployed container lacks.
//
// Everything is built inside a user+network namespace created with `unshare -Urn`,
// so no host interface, route, firewall rule or sysctl is modified:
//
//	(this process, namespace A, mapped root)        (nested namespace B)
//	+--------------------------------+              +----------------------+
//	|  host WAN veth "wan0"          |              |  real TCP + UDP echo |
//	|  198.51.200.1/24               |<-- veth ---->|  198.51.200.2:8080   |
//	|        ^                       |              +----------------------+
//	|        | production AF_PACKET  |
//	|  production TUN (WAN device)   |
//	+--------------------------------+
//
// A packet the dispatcher SNATs and writes into the TUN is therefore forwarded by
// the real kernel out of the WAN interface, answered by a real responder off-box,
// captured back through the production reader, DNATed, and delivered to the owning
// peer's return path. That end-to-end path is what the isolated fixture proves.

const (
	// s4QualificationEnv turns this test binary into a fixture participant.
	s4QualificationEnv = "NEXUS_S4_QUALIFICATION"

	// s4HostWAN is the address the deployed host's WAN interface carries, and the
	// address the dispatcher SNATs direct egress to.
	s4HostWAN = "198.51.200.1"

	// s4RemotePeer is the public endpoint the simulated client traffic targets.
	// Both addresses are IANA documentation space, so no real host is implied.
	s4RemotePeer = "198.51.200.2"

	// s4RemotePort is the service port on the remote peer.
	s4RemotePort = 8080

	// s4WANIface and s4WANPeerIface name the two ends of the simulated uplink.
	s4WANIface     = "wan0"
	s4WANPeerIface = "wan-peer"

	// s4WANDeviceName is the WAN tunnel device the fixture creates. It is the
	// production default name so the production prerequisite check validates exactly
	// the interface the fixture then builds, with no name divergence to hide a gap.
	s4WANDeviceName = defaultWANTunnelDeviceName

	// s4RolePeer selects the nested-namespace participant.
	s4RolePeer = "peer"
)

func init() {
	role := os.Getenv(s4QualificationEnv)
	if role == "" {
		return
	}
	os.Exit(runS4Participant(role))
}

// s4Fixture is a prepared, isolated host-WAN topology.
type s4Fixture struct {
	peerIP      netip.Addr
	wanIface    string
	peer        *s4Peer
	wanIfaceIdx int
}

// s4Peer is the handle to the nested namespace running the real echo servers.
type s4Peer struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	pid    int
}

// newS4Fixture builds the veth pair and starts the remote peer namespace. The
// caller must Close it.
func newS4Fixture() (*s4Fixture, error) {
	if out, err := s4Command("ip", "link", "add", s4WANIface, "type", "veth", "peer", "name", s4WANPeerIface); err != nil {
		return nil, fmt.Errorf("create wan veth pair: %w: %s", err, out)
	}
	peer, err := startS4Peer()
	if err != nil {
		return nil, err
	}
	if out, err := s4Command("ip", "link", "set", s4WANPeerIface, "netns", strconv.Itoa(peer.pid)); err != nil {
		peer.Close()
		return nil, fmt.Errorf("move wan peer into remote namespace: %w: %s", err, out)
	}
	for _, args := range [][]string{
		{"addr", "add", s4HostWAN + "/24", "dev", s4WANIface},
		{"link", "set", s4WANIface, "up"},
		{"link", "set", "lo", "up"},
	} {
		if out, err := s4Command("ip", args...); err != nil {
			peer.Close()
			return nil, fmt.Errorf("ip %v: %w: %s", args, err, out)
		}
	}
	iface, err := net.InterfaceByName(s4WANIface)
	if err != nil {
		peer.Close()
		return nil, fmt.Errorf("look up %s: %w", s4WANIface, err)
	}
	return &s4Fixture{
		peerIP:      netip.MustParseAddr(s4RemotePeer),
		wanIface:    s4WANIface,
		peer:        peer,
		wanIfaceIdx: iface.Index,
	}, nil
}

// Close tears the fixture down.
func (f *s4Fixture) Close() {
	if f == nil || f.peer == nil {
		return
	}
	f.peer.Close()
}

// startS4Peer launches the nested namespace and waits for its pid handshake.
func startS4Peer() (*s4Peer, error) {
	// #nosec G204 -- os.Args[0] is this test binary and "unshare -n" takes no input
	cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), s4QualificationEnv+"="+s4RolePeer)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("peer stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start remote namespace: %w", err)
	}
	handle := &s4Peer{cmd: cmd, stdout: stdout}
	line, err := s4ReadLine(stdout, 64)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("remote namespace pid handshake: %w", err)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PID ")))
	if convErr != nil || pid <= 0 {
		handle.Close()
		return nil, fmt.Errorf("unexpected remote namespace handshake %q: %w", line, convErr)
	}
	handle.pid = pid
	return handle, nil
}

// Close kills the nested namespace.
func (p *s4Peer) Close() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

// waitReady blocks until both remote echo servers listen, or the bound expires.
func (p *s4Peer) waitReady() error {
	if p == nil || p.stdout == nil {
		return fmt.Errorf("remote namespace not started")
	}
	line, err := s4ReadLine(p.stdout, 64)
	if err != nil {
		return fmt.Errorf("remote namespace readiness: %w", err)
	}
	if strings.TrimSpace(line) != "READY" {
		return fmt.Errorf("unexpected remote namespace readiness %q", line)
	}
	return nil
}

// s4ReadLine reads one newline-terminated line with a hard byte bound so a wedged
// child can never stall the caller.
func s4ReadLine(r io.Reader, limit int) (string, error) {
	out := make([]byte, 0, limit)
	buf := make([]byte, 1)
	for len(out) < limit {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return strings.TrimRight(string(out), "\r"), nil
			}
			out = append(out, buf[0])
		}
		if err != nil {
			return string(out), err
		}
	}
	return string(out), nil
}

// runS4Participant is the body of a re-executed participant; it never returns to
// the test framework.
func runS4Participant(role string) int {
	if role != s4RolePeer {
		fmt.Printf("RESULT: FAIL: unknown participant role %q\n", role)
		return 1
	}
	// The parent moves the peer link into this namespace after reading the pid.
	fmt.Printf("PID %d\n", os.Getpid())
	_ = os.Stdout.Sync()

	if err := s4WaitForLink(s4WANPeerIface, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "RESULT: FAIL: %v\n", err)
		return 1
	}
	for _, args := range [][]string{
		{"addr", "add", s4RemotePeer + "/24", "dev", s4WANPeerIface},
		{"link", "set", s4WANPeerIface, "up"},
		{"link", "set", "lo", "up"},
	} {
		if out, err := s4Command("ip", args...); err != nil {
			fmt.Fprintf(os.Stderr, "RESULT: FAIL: ip %v: %v (%s)\n", args, err, out)
			return 1
		}
	}
	// The remote host has no reason to filter its own LAN, but a strict default
	// would drop the replies it sends back across the veth.
	_, _ = s4Command("sysctl", "-w", "net.ipv4.conf.all.rp_filter=2")

	port := strconv.Itoa(s4RemotePort)
	tcpLn, err := net.Listen("tcp4", s4RemotePeer+":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "RESULT: FAIL: bind remote tcp: %v\n", err)
		return 1
	}
	defer tcpLn.Close()

	udpConn, err := net.ListenPacket("udp4", s4RemotePeer+":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "RESULT: FAIL: bind remote udp: %v\n", err)
		return 1
	}
	defer udpConn.Close()

	go s4ServeTCP(tcpLn)
	go s4ServeUDP(udpConn)

	fmt.Println("READY")
	_ = os.Stdout.Sync()
	// Outlive the parent's assertions; the parent kills this process.
	time.Sleep(120 * time.Second)
	return 0
}

// s4ServeTCP echoes one line per connection so a completed handshake plus payload
// exchange is observable by the client side.
func s4ServeTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 256)
			n, readErr := c.Read(buf)
			if n == 0 && readErr != nil {
				return
			}
			_, _ = c.Write(append([]byte("ECHO:"), buf[:n]...))
		}(conn)
	}
}

// s4ServeUDP echoes every datagram back to its source.
func s4ServeUDP(conn net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(append([]byte("ECHO:"), buf[:n]...), from)
	}
}

// s4WaitForLink polls until the named link exists in the current namespace.
func s4WaitForLink(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := s4Command("ip", "link", "show", name); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("link %q did not appear within %s", name, timeout)
}

// s4Command runs a fixed fixture command and returns its combined output.
func s4Command(name string, args ...string) (string, error) {
	// #nosec G204 -- callers pass literal topology commands from this fixture only
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// s4KernelDropEvidence summarises the kernel counters that identify where a direct
// packet was dropped, so a failure names the mechanism rather than only the symptom.
func s4KernelDropEvidence() map[string]int64 {
	stats := s4SnapshotIPStats()
	evidence := map[string]int64{}
	for _, key := range []string{
		"IpForwDatagrams", "IpInReceives", "TcpExtIPReversePathFilter",
		"IpInAddrErrors", "UdpInDatagrams", "IpOutRequests",
	} {
		evidence[key] = stats[key]
	}
	return evidence
}

// s4AssertDocumentedConfigRejected drives the real production validator over a
// synthetic sysctl tree describing the formerly documented deployment (rp_filter=2)
// and requires it to be refused with the actionable error. This is the red half of
// the counterexample, and it is the only honest way to hold an incompatible
// configuration alongside the qualifying one in a single container whose /proc/sys is
// read-only.
func s4AssertDocumentedConfigRejected() error {
	root, err := os.MkdirTemp("", "s4-sysctl")
	if err != nil {
		return fmt.Errorf("create synthetic sysctl root: %w", err)
	}
	defer func() { _ = os.RemoveAll(root) }()

	for _, scope := range []string{"all", "default"} {
		dir := filepath.Join(root, "net/ipv4/conf", scope)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		// The formerly documented deployment.
		if err := os.WriteFile(filepath.Join(dir, "rp_filter"), []byte("2\n"), 0o600); err != nil {
			return fmt.Errorf("write %s rp_filter: %w", scope, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "accept_local"), []byte("1\n"), 0o600); err != nil {
			return fmt.Errorf("write %s accept_local: %w", scope, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "net/ipv4/ip_forward"), []byte("1\n"), 0o600); err != nil {
		return fmt.Errorf("write ip_forward: %w", err)
	}

	original := sourceValidationRoot
	sourceValidationRoot = root
	defer func() { sourceValidationRoot = original }()

	rejectErr := validateDirectEgressSourceValidation(root, defaultWANTunnelDeviceName)
	if rejectErr == nil {
		return fmt.Errorf("the production prerequisite accepted rp_filter=2, which was measured to forward no direct traffic; the fail-closed guard is not effective")
	}
	if !errors.Is(rejectErr, ErrHostWANSourceValidation) {
		return fmt.Errorf("production prerequisite rejected the documented configuration with an unexpected error: %w", rejectErr)
	}
	fmt.Printf("S4 red phase: production prerequisite refused rp_filter=2: %v\n", rejectErr)
	return nil
}

// s4OwnedNamespaceEnv marks a process that is running inside the private namespace
// the S4 qualification created for itself. A test that needs to configure kernel
// settings (rp_filter, accept_local, forwarding) must only do so under this marker,
// because only that process owns a throwaway network stack; anything else would be
// mutating the runner's or the operator's host.
const s4OwnedNamespaceEnv = "NEXUS_S4_OWNED_NAMESPACE"

// s4RequireOwnedNamespace reports nil only when the current process provably owns a
// private network namespace created for this run.
func s4RequireOwnedNamespace() error {
	if os.Getenv(s4OwnedNamespaceEnv) != "1" {
		return fmt.Errorf("this process does not own a private network namespace (%s is unset); kernel settings here belong to the host", s4OwnedNamespaceEnv)
	}
	return nil
}

// s4AssertLiveIncompatibleConfigRefused is the LIVE half of the counterexample, and
// it runs inside the private namespace this process owns.
//
// It sets rp_filter to the incompatible value on BOTH conf/all and conf/default,
// calls the production constructor exactly as startup does, and requires:
//   - the constructor to refuse with ErrHostWANSourceValidation, and
//   - no tunnel device to have been created (the refusal happens before the TUN).
//
// It then restores rp_filter=0 on both scopes so the qualifying path below runs on a
// network configuration that genuinely works. Nothing here touches the host: these
// sysctls belong to the throwaway namespace, which disappears with the process.
func s4AssertLiveIncompatibleConfigRefused() error {
	restore, err := s4SetNamespaceRPFilter("2")
	if err != nil {
		return fmt.Errorf("prepare live incompatible configuration: %w", err)
	}
	// Always restore, even when the assertion below fails, so a failure here does
	// not poison the qualifying phases with a configuration we deliberately broke.
	defer func() { _ = restore() }()

	dev, constructErr := NewProductionWANDevice(s4WANDeviceName)
	if constructErr == nil {
		_ = dev.Close()
		return fmt.Errorf("the production constructor ACCEPTED a live effective rp_filter=2, which was measured to forward no direct traffic; the fail-closed guard is not effective on real procfs")
	}
	if !errors.Is(constructErr, ErrHostWANSourceValidation) {
		return fmt.Errorf("the production constructor refused the live incompatible configuration with an unexpected error, not the actionable source-validation error: %w", constructErr)
	}
	// The refusal must precede device creation: a guard that refuses only after
	// creating the TUN would still have mutated the link state of the host it runs on.
	if out, linkErr := s4Command("ip", "link", "show", s4WANDeviceName); linkErr == nil {
		return fmt.Errorf("the refused configuration still created tunnel device %q (ip link show output: %s)", s4WANDeviceName, strings.TrimSpace(out))
	}
	fmt.Printf("S4 red phase (live): production constructor refused a live rp_filter=2 namespace: %v\n", constructErr)
	return nil
}

// s4SetNamespaceRPFilter writes one rp_filter value to conf/all and conf/default in
// the namespace this process owns, and returns a function that puts both scopes back
// to 0. Writing conf/default is required because a device created later inherits from
// it, and writing only conf/all cannot loosen an inherited per-device value.
func s4SetNamespaceRPFilter(value string) (func() error, error) {
	for _, scope := range []string{"all", "default"} {
		if out, err := s4Command("sysctl", "-w", "net.ipv4.conf."+scope+".rp_filter="+value); err != nil {
			return nil, fmt.Errorf("set conf/%s rp_filter=%s: %w: %s", scope, value, err, strings.TrimSpace(out))
		}
	}
	return func() error {
		for _, scope := range []string{"all", "default"} {
			if out, err := s4Command("sysctl", "-w", "net.ipv4.conf."+scope+".rp_filter=0"); err != nil {
				return fmt.Errorf("restore conf/%s rp_filter=0: %w: %s", scope, err, strings.TrimSpace(out))
			}
		}
		return nil
	}, nil
}

// s4SourceValidationSettings reports the kernel source-validation inputs and their
// effective values, reading procfs only. The gate compares these against what a
// deployment must provide; it never writes them, because a deployed container mounts
// /proc/sys read-only and supplies them through `--sysctl` or the host.
func s4SourceValidationSettings() map[string]string {
	read := func(rel string) string {
		// #nosec G304 -- fixed procfs paths
		data, err := os.ReadFile("/proc/sys/net/ipv4/" + rel)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	out := map[string]string{
		"all_rp_filter":        read("conf/all/rp_filter"),
		"default_rp_filter":    read("conf/default/rp_filter"),
		"all_accept_local":     read("conf/all/accept_local"),
		"default_accept_local": read("conf/default/accept_local"),
		"ip_forward":           read("ip_forward"),
	}
	// IN_DEV_RPFILTER = max(all, dev); a device that does not exist yet inherits
	// conf/default, which is exactly the case before NewProductionWANDevice runs.
	out["effective_rp_filter"] = s4MaxNumeric(out["all_rp_filter"], out["default_rp_filter"])
	return out
}

// s4MaxNumeric returns the larger of two sysctl values as a decimal string.
func s4MaxNumeric(a, b string) string {
	ai, aErr := strconv.Atoi(a)
	bi, bErr := strconv.Atoi(b)
	switch {
	case aErr != nil:
		return ""
	case bErr != nil:
		return a
	case bi > ai:
		return b
	default:
		return a
	}
}

// s4RequireForwardingSettings verifies the forwarding prerequisites are already in
// effect and reports any that are not. Like the source-validation check it observes
// rather than writes, so the gate cannot pass by configuring the environment it is
// supposed to be qualifying.
func s4RequireForwardingSettings() []string {
	reported := s4SourceValidationSettings()
	var missing []string
	if reported["ip_forward"] != "1" {
		missing = append(missing, fmt.Sprintf("ip_forward=%q (want 1)", reported["ip_forward"]))
	}
	// IN_DEV_ACCEPT_LOCAL = all || dev; the daemon may also set the device value
	// itself when it creates the tunnel, so only a proven 0/0 is a failure.
	if reported["all_accept_local"] != "1" && reported["default_accept_local"] != "1" {
		missing = append(missing, fmt.Sprintf("accept_local all=%q default=%q (want at least one = 1)",
			reported["all_accept_local"], reported["default_accept_local"]))
	}
	return missing
}

// s4ForwardingRules installs the forwarding and NAT rules direct WAN egress needs.
// The first two are the pair the README documents for the VPN endpoint; the third
// admits traffic the dispatcher injects into the WAN tunnel device, which enters
// the stack as new inbound traffic on that device.
func s4ForwardingRules(wanIface, tunnelDev string) error {
	for _, args := range [][]string{
		{"-A", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"-t", "nat", "-A", "POSTROUTING", "-o", wanIface, "-j", "MASQUERADE"},
		{"-A", "FORWARD", "-i", tunnelDev, "-j", "ACCEPT"},
	} {
		if out, err := s4Command("iptables", args...); err != nil {
			return fmt.Errorf("iptables %v: %w: %s", args, err, out)
		}
	}
	return nil
}

// s4SnapshotIPStats reads the kernel IP counters that report where a forwarded
// packet was dropped, so a failure names the mechanism instead of only the symptom.
func s4SnapshotIPStats() map[string]int64 {
	out, _ := s4Command("nstat", "-az")
	stats := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		var value int64
		if _, err := fmt.Sscanf(fields[1], "%d", &value); err != nil {
			continue
		}
		stats[fields[0]] = value
	}
	return stats
}
