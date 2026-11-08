//go:build linux

package vpn

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
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

	// s4WANDeviceName is the WAN tunnel device the production constructor creates.
	s4WANDeviceName = "nexus-wan-s4"

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

// s4DeploymentSysctls are the kernel settings the documented deployment block sets
// for direct WAN egress. The fixture applies exactly these before proving the
// path, so the qualification covers the shipped deployment rather than a
// permissive superset of it.
var s4DeploymentSysctls = []struct{ key, value string }{
	{"net.ipv4.ip_forward", "1"},
	{"net.ipv4.conf.all.rp_filter", "2"},
	{"net.ipv4.conf.all.accept_local", "1"},
}

// applyS4DeploymentSysctls applies the documented settings and returns the ones
// that did not take effect, so a caller can report an unusable environment instead
// of asserting against it.
func applyS4DeploymentSysctls() []string {
	var failed []string
	for _, setting := range s4DeploymentSysctls {
		if out, err := s4Command("sysctl", "-w", setting.key+"="+setting.value); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v (%s)", setting.key, err, strings.TrimSpace(out)))
		}
	}
	return failed
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

// s4SetReversePathFilter sets the reverse-path filter to 0 on the whole namespace
// (all and every device), which is the prerequisite source validation needs for a
// packet whose source address is local to the box.
func s4SetReversePathFilter(value string) error {
	for _, scope := range []string{"all", "default"} {
		if out, err := s4Command("sysctl", "-w", "net.ipv4.conf."+scope+".rp_filter="+value); err != nil {
			return fmt.Errorf("set %s rp_filter: %w: %s", scope, err, out)
		}
	}
	entries, err := os.ReadDir("/proc/sys/net/ipv4/conf")
	if err != nil {
		return fmt.Errorf("list conf devices: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// #nosec G204 -- name comes from the kernel's own conf directory listing
		if out, err := s4Command("sysctl", "-w", "net.ipv4.conf."+name+".rp_filter="+value); err != nil {
			// A device that vanished mid-loop is not a failure of the fixture.
			if strings.Contains(out, "cannot stat") {
				continue
			}
			return fmt.Errorf("set %s rp_filter: %w: %s", name, err, out)
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

// s4StatDelta reports the counters that moved between two snapshots.
func s4StatDelta(before, after map[string]int64) map[string]int64 {
	delta := map[string]int64{}
	for key, value := range after {
		if d := value - before[key]; d != 0 {
			delta[key] = d
		}
	}
	return delta
}
