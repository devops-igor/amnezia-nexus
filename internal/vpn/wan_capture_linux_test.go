//go:build linux

package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// capNetRawBit is CAP_NET_RAW's position in the capability bitmasks.
const capNetRawBit = 13

// wanCaptureProbeEnv re-executes this test binary inside an isolated user+network
// namespace, which is the only way to obtain the CAP_NET_ADMIN and CAP_NET_RAW this
// probe needs without touching host networking.
const wanCaptureProbeEnv = "NEXUS_WAN_CAPTURE_PROBE"

// Probe addresses use the documentation range so no real host is implied.
const (
	probeHostWAN = "192.0.2.2"
	probePeerIP  = "192.0.2.1"
)

func init() {
	mode := os.Getenv(wanCaptureProbeEnv)
	if mode == "" {
		return
	}
	os.Exit(runWANCaptureProbe(mode))
}

// effectiveCapabilities parses the CapEff mask from /proc/self/status.
func effectiveCapabilities() (uint64, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/status: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0, fmt.Errorf("malformed CapEff line: %q", line)
		}
		var mask uint64
		if _, err := fmt.Sscanf(fields[1], "%x", &mask); err != nil {
			return 0, fmt.Errorf("parse CapEff %q: %w", fields[1], err)
		}
		return mask, nil
	}
	return 0, errors.New("CapEff not found in /proc/self/status")
}

func hasNetRaw() bool {
	mask, err := effectiveCapabilities()
	return err == nil && mask&(1<<capNetRawBit) != 0
}

// dropNetRaw removes CAP_NET_RAW from the process effective and permitted sets so
// AF_PACKET creation fails exactly as it does in the production container, where
// only CAP_NET_ADMIN is granted.
func dropNetRaw() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	for i := range data {
		shift := uint(capNetRawBit - 32*uint(i))
		data[i].Effective &^= 1 << shift
		data[i].Permitted &^= 1 << shift
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if hasNetRaw() {
		return errors.New("CAP_NET_RAW still effective after capset")
	}
	return nil
}

// TestOpenWANCaptureSocket_CapabilityContract pins the capture-socket capability
// contract: without CAP_NET_RAW the failure must be the actionable
// ErrWANCaptureDenied naming the capability, never a bare EPERM; with CAP_NET_RAW
// the socket must open.
func TestOpenWANCaptureSocket_CapabilityContract(t *testing.T) {
	fd, err := openWANCaptureSocket()

	if !hasNetRaw() {
		if fd >= 0 {
			_ = unix.Close(fd)
			t.Fatal("expected capture socket creation to fail without CAP_NET_RAW")
		}
		if !errors.Is(err, ErrWANCaptureDenied) {
			t.Fatalf("expected ErrWANCaptureDenied, got: %v", err)
		}
		if !strings.Contains(err.Error(), "CAP_NET_RAW") {
			t.Fatalf("error must name the missing capability, got: %v", err)
		}
		return
	}

	if err != nil {
		t.Fatalf("expected capture socket to open with CAP_NET_RAW present, got: %v", err)
	}
	if fd < 0 {
		t.Fatalf("expected a valid descriptor, got %d", fd)
	}
	_ = unix.Close(fd)
}

// TestWANCaptureProductionPath runs the production capture path inside an isolated
// user+network namespace and asserts both halves of the deployment contract:
//
//	positive — with CAP_NET_ADMIN and CAP_NET_RAW the documented host settings are
//	           sufficient: prerequisites pass and real inbound WAN traffic is captured.
//	negative — with CAP_NET_RAW withheld (only CAP_NET_ADMIN, the pre-fix image) the
//	           same prepared host fails at startup with ErrWANCaptureDenied.
func TestWANCaptureProductionPath(t *testing.T) {
	for _, mode := range []string{"positive", "negative"} {
		t.Run(mode, func(t *testing.T) {
			out, err := runProbeInNetNS(mode)
			if err != nil {
				t.Skipf("skipping: cannot create isolated user+network namespace here: %v", err)
			}
			if !strings.Contains(out, "RESULT: PASS") {
				t.Fatalf("probe %s failed:\n%s", mode, out)
			}
		})
	}
}

// runProbeInNetNS re-executes this binary under `unshare -Urn` so the probe owns a
// private network namespace with the capabilities the production container would
// have after `cap_add`. Host networking is never modified. A returned error means
// the namespace could not be created at all, which is a skip, not a failure.
func runProbeInNetNS(mode string) (string, error) {
	// #nosec G204 -- os.Args[0] is the test binary; mode is a fixed literal
	cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), wanCaptureProbeEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "RESULT:") {
		return string(out), fmt.Errorf("probe could not run (unshare/namespace setup): %w: %s", err, out)
	}
	return string(out), nil
}

// runWANCaptureProbe is the body of the namespace-isolated probe. It returns a
// process exit code.
func runWANCaptureProbe(mode string) int {
	fail := func(format string, args ...any) int {
		fmt.Printf("RESULT: FAIL: "+format+"\n", args...)
		return 1
	}

	// The namespace is fresh, so build the host-side topology the deployment
	// provides: a WAN interface carrying the host address and the kernel settings
	// the direct-egress contract requires.
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "wan0", "type", "veth", "peer", "name", "wan-peer"},
		{"addr", "add", probeHostWAN + "/24", "dev", "wan0"},
		{"link", "set", "wan0", "up"},
		{"link", "set", "wan-peer", "up"},
		{"route", "add", "default", "dev", "wan0"},
	} {
		// #nosec G204 -- fixed ip invocations with literal probe arguments
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fail("ip %v: %v (%s)", args, err, out)
		}
	}
	for _, setting := range []struct{ path, value string }{
		{"/proc/sys/net/ipv4/ip_forward", "1"},
		{"/proc/sys/net/ipv4/conf/all/rp_filter", "2"},
		{"/proc/sys/net/ipv4/conf/all/accept_local", "1"},
	} {
		if err := os.WriteFile(setting.path, []byte(setting.value+"\n"), 0o600); err != nil {
			return fail("write %s: %v", setting.path, err)
		}
	}

	if mode == "negative" {
		if err := dropNetRaw(); err != nil {
			return fail("drop CAP_NET_RAW: %v", err)
		}
	}

	// 1. Startup prerequisite validation, as the production constructor performs it.
	err := ValidateKernelPrerequisites()
	if mode == "negative" {
		if !errors.Is(err, ErrWANCaptureDenied) {
			return fail("expected ErrWANCaptureDenied from ValidateKernelPrerequisites, got: %v", err)
		}
		if _, captureErr := openWANCaptureSocket(); !errors.Is(captureErr, ErrWANCaptureDenied) {
			return fail("expected ErrWANCaptureDenied from openWANCaptureSocket, got: %v", captureErr)
		}
		fmt.Println("RESULT: PASS: startup rejects a NET_ADMIN-only capability set with ErrWANCaptureDenied")
		return 0
	}
	if err != nil {
		return fail("ValidateKernelPrerequisites with full capabilities: %v", err)
	}

	// 2. Real inbound capture through the production reader.
	fd, err := openWANCaptureSocket()
	if err != nil {
		return fail("openWANCaptureSocket: %v", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return fail("SetNonblock: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP)}); err != nil {
		_ = unix.Close(fd)
		return fail("bind capture socket: %v", err)
	}
	rawFile := os.NewFile(uintptr(fd), "wan-capture-probe")
	dev := &linuxWANDevice{
		rawFile:   rawFile,
		minPort:   40000,
		maxPort:   65000,
		hostWANIP: netip.MustParseAddr(probeHostWAN),
	}
	defer func() {
		dev.closed.Store(true)
		_ = rawFile.Close()
	}()

	peerIface, err := net.InterfaceByName("wan-peer")
	if err != nil {
		return fail("look up wan-peer: %v", err)
	}

	// Out-of-range port first: the reader must ignore it rather than return it.
	if err := injectUDP(peerIface.Index, 39999, []byte("out-of-range")); err != nil {
		return fail("inject out-of-range packet: %v", err)
	}
	if got := readCaptureWithTimeout(dev, 300*time.Millisecond); got != nil {
		return fail("capture reader accepted out-of-range port traffic: %q", string(got))
	}

	// In-range reply traffic must reach the peer through the production reader.
	const payload = "wan-reply-in-range"
	if err := injectUDP(peerIface.Index, 41000, []byte(payload)); err != nil {
		return fail("inject in-range packet: %v", err)
	}
	got := readCaptureWithTimeout(dev, 3*time.Second)
	if got == nil {
		return fail("capture reader did not deliver in-range WAN traffic")
	}
	if !strings.HasSuffix(string(got), payload) {
		return fail("unexpected captured payload: %q", string(got))
	}
	dst := [4]byte{got[16], got[17], got[18], got[19]}
	if fmt.Sprintf("%d.%d.%d.%d", dst[0], dst[1], dst[2], dst[3]) != probeHostWAN {
		return fail("captured traffic is not addressed to the host WAN IP: %v", dst)
	}

	fmt.Println("RESULT: PASS: prerequisites valid and real inbound WAN traffic captured with NET_ADMIN+NET_RAW")
	return 0
}

// injectUDP emits an IPv4/UDP datagram into the namespace through the peer end of
// the veth pair, producing genuine inbound traffic on the host WAN interface.
func injectUDP(ifindex int, dstPort uint16, payload []byte) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("open injection socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	src := net.ParseIP(probePeerIP).To4()
	dst := net.ParseIP(probeHostWAN).To4()
	pkt := buildProbeIPv4UDP([4]byte(src), [4]byte(dst), 12345, dstPort, payload)

	return unix.Sendto(fd, pkt, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  ifindex,
	})
}

// buildProbeIPv4UDP builds a complete IPv4/UDP datagram.
func buildProbeIPv4UDP(src, dst [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	length := 28 + len(payload)
	pkt := make([]byte, length)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
	binary.BigEndian.PutUint16(pkt[4:6], 4321)
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], probeChecksum(pkt[:20]))
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

// probeChecksum computes the Internet checksum over b.
func probeChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// readCaptureWithTimeout reads one matching packet from the production reader,
// bounded by a read deadline so a blocking socket cannot stall the probe.
func readCaptureWithTimeout(dev *linuxWANDevice, timeout time.Duration) []byte {
	if err := dev.rawFile.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	buf := make([]byte, 2048)
	n, err := dev.Read(buf)
	if err != nil || n <= 0 {
		return nil
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}
