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
	"path/filepath"
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
//
// The capture assertion is mandatory in both deployment environments. Kernel
// sysctls (/proc/sys/net/ipv4/...) are only *attempted*: containers commonly
// mount /proc/sys read-only, and a probe that cannot configure them must still
// prove the AF_PACKET capture path instead of failing the whole check. When they
// cannot be written, the prerequisite validator is instead asserted to fail for a
// sysctl reason and specifically NOT with ErrWANCaptureDenied, which keeps the
// capability contract under test in both environments.
func runWANCaptureProbe(mode string) int {
	fail := func(format string, args ...any) int {
		fmt.Printf("RESULT: FAIL: "+format+"\n", args...)
		return 1
	}

	// The namespace is fresh, so build the host-side topology the deployment
	// provides: a WAN interface carrying the host address.
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

	sysctlWritable := applyProbeSysctls()

	if mode == "negative" {
		if err := dropNetRaw(); err != nil {
			return fail("drop CAP_NET_RAW: %v", err)
		}
		// The capability contract: no CAP_NET_RAW means no capture socket, and the
		// error must name the capability rather than being a bare EPERM.
		if _, captureErr := openWANCaptureSocket(); !errors.Is(captureErr, ErrWANCaptureDenied) {
			return fail("expected ErrWANCaptureDenied from openWANCaptureSocket, got: %v", captureErr)
		}
		// Startup validation must also refuse rather than proceed to a data plane
		// that cannot capture replies. The capability check runs before the sysctl
		// checks, so ErrWANCaptureDenied is expected even with a read-only /proc/sys;
		// if another prerequisite fails first, any non-nil error still proves
		// fail-closed startup.
		prereqErr := ValidateKernelPrerequisites()
		if prereqErr == nil {
			return fail("ValidateKernelPrerequisites returned nil with CAP_NET_RAW removed")
		}
		if sysctlWritable && !errors.Is(prereqErr, ErrWANCaptureDenied) {
			return fail("expected ErrWANCaptureDenied from ValidateKernelPrerequisites, got: %v", prereqErr)
		}
		fmt.Printf("RESULT: PASS: startup rejects a NET_ADMIN-only capability set with ErrWANCaptureDenied (sysctl writable=%v)\n", sysctlWritable)
		return 0
	}

	// Real inbound capture through the production reader. This is the proof the
	// check exists for and it does not depend on any sysctl: it exercises socket
	// creation, binding, the reader's port filter and its address filter.
	if code, ok := runCaptureAssertion(fail); !ok {
		return code
	}

	// The kernel-prerequisite contract is asserted with the expectation the
	// environment allows, so neither environment silently skips it.
	outcome := classifyPrerequisiteOutcome(sysctlWritable, ValidateKernelPrerequisites())
	fmt.Println(outcome.message)
	if !outcome.pass {
		return 1
	}
	return 0
}

// prerequisiteOutcome records whether the prerequisite phase passed, plus the
// operator-facing explanation including which environment mode applied.
type prerequisiteOutcome struct {
	pass    bool
	message string
}

// classifyPrerequisiteOutcome decides the prerequisite expectation for a probe
// environment. When sysctls are writable the full contract must hold; when they
// are read-only only a sysctl-caused failure is acceptable, and a missing capture
// capability is always a failure because the capture socket already succeeded.
// Kept pure so both environments are unit-testable without a mount namespace.
func classifyPrerequisiteOutcome(sysctlWritable bool, err error) prerequisiteOutcome {
	const okBase = "RESULT: PASS: real inbound WAN traffic captured with NET_ADMIN+NET_RAW"

	if sysctlWritable {
		if err != nil {
			return prerequisiteOutcome{message: "RESULT: FAIL: ValidateKernelPrerequisites with full capabilities and writable sysctls: " + err.Error()}
		}
		return prerequisiteOutcome{pass: true, message: okBase + " (sysctl writable=true)"}
	}
	if err == nil {
		// Nothing failed to configure, so the writability probe was inconclusive;
		// the full contract holds either way.
		return prerequisiteOutcome{pass: true, message: okBase + " (sysctl writable=false, prerequisites already satisfied)"}
	}
	if errors.Is(err, ErrWANCaptureDenied) {
		return prerequisiteOutcome{message: "RESULT: FAIL: capture capability reported as missing although the capture socket worked: " + err.Error()}
	}
	return prerequisiteOutcome{
		pass: true,
		message: okBase + "; sysctl prerequisites not configurable in this environment (" + err.Error() +
			"), and the failure is a sysctl prerequisite, not a capture-capability failure",
	}
}

// applyProbeSysctls attempts to configure the direct-egress kernel settings and
// reports whether all of them are actually in effect afterwards. It never fails
// the probe: a read-only /proc/sys is an environment property, not a product
// defect, and the caller adjusts its prerequisite expectation accordingly.
//
// NEXUS_PROBE_SYSCTL_ROOT redirects the read/write root so the read-only-proc
// branch can be exercised end-to-end on a host whose netns sysctls are writable.
// It exists only for that purpose and defaults to the real procfs.
func applyProbeSysctls() bool {
	root := os.Getenv(probeSysctlRootEnv)
	if root == "" {
		root = "/proc/sys"
	}
	settings := []struct{ rel, value string }{
		{"net/ipv4/ip_forward", "1"},
		// rp_filter must be 0 for the direct-egress source-validation prerequisite
		// (see wan_source_validation.go): loose mode 2 was measured to drop the
		// locally sourced SNAT packet, so a probe that configured 2 was asking
		// ValidateKernelPrerequisites to pass a configuration that cannot forward.
		{"net/ipv4/conf/all/rp_filter", "0"},
		// conf/default decides the per-device value a newly created interface
		// inherits, and rp_filter is the max of conf/all and the device. Configuring
		// only conf/all would leave the effective value at the inherited default.
		{"net/ipv4/conf/default/rp_filter", "0"},
		{"net/ipv4/conf/all/accept_local", "1"},
	}
	for _, setting := range settings {
		// #nosec G304 -- fixed procfs-relative paths under a controlled root
		if err := os.WriteFile(filepath.Join(root, setting.rel), []byte(setting.value+"\n"), 0o600); err != nil {
			fmt.Printf("sysctl: %s not writable: %v\n", setting.rel, err)
		}
	}
	for _, setting := range settings {
		// #nosec G304 -- fixed procfs-relative paths under a controlled root
		current, err := os.ReadFile(filepath.Join(root, setting.rel))
		if err != nil || strings.TrimSpace(string(current)) != setting.value {
			return false
		}
	}
	return true
}

// probeSysctlRootEnv redirects applyProbeSysctls for read-only-proc testing.
const probeSysctlRootEnv = "NEXUS_PROBE_SYSCTL_ROOT"

// runCaptureAssertion proves the production capture path against the real kernel:
// an in-range reply addressed to the host WAN IP must reach the peer through the
// production reader, and out-of-range traffic must be filtered out. It performs no
// sysctl configuration, so it holds in read-only-proc containers too.
func runCaptureAssertion(fail func(string, ...any) int) (int, bool) {
	fd, err := openWANCaptureSocket()
	if err != nil {
		return fail("openWANCaptureSocket: %v", err), false
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return fail("SetNonblock: %v", err), false
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP)}); err != nil {
		_ = unix.Close(fd)
		return fail("bind capture socket: %v", err), false
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
		return fail("look up wan-peer: %v", err), false
	}

	// Out-of-range port first: the reader must ignore it rather than return it.
	if err := injectUDP(peerIface.Index, 39999, []byte("out-of-range")); err != nil {
		return fail("inject out-of-range packet: %v", err), false
	}
	if got := readCaptureWithTimeout(dev, 300*time.Millisecond); got != nil {
		return fail("capture reader accepted out-of-range port traffic: %q", string(got)), false
	}

	// In-range reply traffic must reach the peer through the production reader.
	const payload = "wan-reply-in-range"
	if err := injectUDP(peerIface.Index, 41000, []byte(payload)); err != nil {
		return fail("inject in-range packet: %v", err), false
	}
	got := readCaptureWithTimeout(dev, 3*time.Second)
	if got == nil {
		return fail("capture reader did not deliver in-range WAN traffic"), false
	}
	if !strings.HasSuffix(string(got), payload) {
		return fail("unexpected captured payload: %q", string(got)), false
	}
	dst := [4]byte{got[16], got[17], got[18], got[19]}
	if fmt.Sprintf("%d.%d.%d.%d", dst[0], dst[1], dst[2], dst[3]) != probeHostWAN {
		return fail("captured traffic is not addressed to the host WAN IP: %v", dst), false
	}
	return 0, true
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
