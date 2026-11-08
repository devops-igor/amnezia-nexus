//go:build linux

package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"golang.org/x/sys/unix"
)

type iptablesRunner func(args ...string) error

var defaultIPTablesRunner = func(args ...string) error {
	path, err := exec.LookPath("iptables")
	if err != nil {
		return err
	}
	// #nosec G204 -- arguments are constructed internally from validated IPv4 and numeric port ranges
	cmd := exec.Command(path, args...)
	return cmd.Run()
}

type linuxWANDevice struct {
	file              *os.File // TUN device for write
	rawFile           *os.File // AF_PACKET socket for return packet capture
	name              string
	closed            atomic.Bool
	minPort           uint16
	maxPort           uint16
	hostWANIP         netip.Addr
	mu                sync.RWMutex
	iptablesInstalled bool
	installedIP       netip.Addr
	installedMinPort  uint16
	installedMaxPort  uint16
	iptablesRunner    iptablesRunner
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func (d *linuxWANDevice) runner() iptablesRunner {
	if d.iptablesRunner != nil {
		return d.iptablesRunner
	}
	return defaultIPTablesRunner
}

const resetSubchain = "NEXUS_WAN_RESET"

func (d *linuxWANDevice) installResetSuppressionRulesLocked() error {
	if !d.hostWANIP.IsValid() || !d.hostWANIP.Is4() || d.hostWANIP.IsLoopback() || d.hostWANIP.IsUnspecified() {
		return nil
	}
	minP := d.minPort
	if minP == 0 {
		minP = 40000
	}
	maxP := d.maxPort
	if maxP == 0 {
		maxP = 65000
	}

	run := d.runner()
	portArg := fmt.Sprintf("%d:%d", minP, maxP)
	ipArg := d.hostWANIP.String()

	var installedRules [][]string
	rollback := func() {
		for i := len(installedRules) - 1; i >= 0; i-- {
			_ = run(installedRules[i]...)
		}
		_ = run("-F", resetSubchain)
		_ = run("-X", resetSubchain)
		d.iptablesInstalled = false
		d.installedIP = netip.Addr{}
		d.installedMinPort = 0
		d.installedMaxPort = 0
	}

	// 1. Ensure dedicated reset suppression sub-chain exists (R10-B1).
	// If it already exists, flush any stale rules.
	if err := run("-N", resetSubchain); err != nil {
		if flushErr := run("-F", resetSubchain); flushErr != nil {
			rollback()
			return fmt.Errorf("create %s subchain: %w", resetSubchain, err)
		}
	}

	for _, proto := range []string{"tcp", "udp"} {
		// 2. Inbound packets matching an existing host socket (e.g. host DNS resolver, outbound HTTPS)
		// must return to the calling chain (INPUT) before any DROP rule within the sub-chain (R11-B1)
		// so that existing host firewall policy applies normally.
		checkReturn := []string{"-C", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-m", "socket", "--nowildcard", "-j", "RETURN"}
		if err := run(checkReturn...); err != nil {
			returnArgs := []string{"-A", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-m", "socket", "--nowildcard", "-j", "RETURN"}
			if err := run(returnArgs...); err != nil {
				rollback()
				return fmt.Errorf("install %s socket return rule: %w", proto, err)
			}
			delReturn := []string{"-D", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-m", "socket", "--nowildcard", "-j", "RETURN"}
			installedRules = append(installedRules, delReturn)
		}

		// 3. Inbound packets without a local socket in the direct egress NAT range are dropped (R8-B2)
		// within the sub-chain to prevent host kernel from emitting TCP resets or ICMP port unreachable.
		checkDrop := []string{"-C", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-j", "DROP"}
		if err := run(checkDrop...); err != nil {
			dropArgs := []string{"-A", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-j", "DROP"}
			if err := run(dropArgs...); err != nil {
				rollback()
				return fmt.Errorf("install %s drop reset suppression rule: %w", proto, err)
			}
			delDrop := []string{"-D", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-j", "DROP"}
			installedRules = append(installedRules, delDrop)
		}
	}

	// 4. Jump to the dedicated sub-chain at position 1 of INPUT (R10-B1),
	// ensuring no-socket DROP executes before any pre-existing established ACCEPT rules.
	checkJump := []string{"-C", "INPUT", "-j", resetSubchain}
	if err := run(checkJump...); err == nil {
		_ = run("-D", "INPUT", "-j", resetSubchain)
	}
	jumpArgs := []string{"-I", "INPUT", "1", "-j", resetSubchain}
	if err := run(jumpArgs...); err != nil {
		rollback()
		return fmt.Errorf("insert %s jump in INPUT: %w", resetSubchain, err)
	}
	delJump := []string{"-D", "INPUT", "-j", resetSubchain}
	installedRules = append(installedRules, delJump)

	d.iptablesInstalled = true
	d.installedIP = d.hostWANIP
	d.installedMinPort = minP
	d.installedMaxPort = maxP
	return nil
}

func (d *linuxWANDevice) removeResetSuppressionRulesLocked() {
	if !d.iptablesInstalled {
		return
	}
	run := d.runner()
	portArg := fmt.Sprintf("%d:%d", d.installedMinPort, d.installedMaxPort)
	ipArg := d.installedIP.String()

	// 1. Remove jump from INPUT first so incoming packets stop entering the subchain.
	_ = run("-D", "INPUT", "-j", resetSubchain)

	// 2. Remove rules inside the subchain.
	if d.installedIP.IsValid() {
		for _, proto := range []string{"tcp", "udp"} {
			deleteReturn := []string{"-D", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-m", "socket", "--nowildcard", "-j", "RETURN"}
			_ = run(deleteReturn...)
			deleteDrop := []string{"-D", resetSubchain, "-p", proto, "--dport", portArg, "-d", ipArg, "-j", "DROP"}
			_ = run(deleteDrop...)
		}
	}

	// 3. Flush and delete the dedicated subchain.
	_ = run("-F", resetSubchain)
	_ = run("-X", resetSubchain)

	d.iptablesInstalled = false
	d.installedIP = netip.Addr{}
	d.installedMinPort = 0
	d.installedMaxPort = 0
}

func (d *linuxWANDevice) SetHostWANIP(ip netip.Addr) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hostWANIP == ip && d.iptablesInstalled {
		return nil
	}
	if d.iptablesInstalled {
		d.removeResetSuppressionRulesLocked()
	}
	d.hostWANIP = ip
	if ip.IsValid() && ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified() {
		if err := d.installResetSuppressionRulesLocked(); err != nil {
			return fmt.Errorf("set host wan ip: %w", err)
		}
	}
	return nil
}

func (d *linuxWANDevice) SetNATPortRange(minPort, maxPort uint16) error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.minPort == minPort && d.maxPort == maxPort {
		return nil
	}
	if d.iptablesInstalled {
		d.removeResetSuppressionRulesLocked()
	}
	d.minPort = minPort
	d.maxPort = maxPort
	if d.hostWANIP.IsValid() && d.hostWANIP.Is4() && !d.hostWANIP.IsLoopback() && !d.hostWANIP.IsUnspecified() {
		if err := d.installResetSuppressionRulesLocked(); err != nil {
			return fmt.Errorf("set nat port range: %w", err)
		}
	}
	return nil
}

func (d *linuxWANDevice) Read(p []byte) (int, error) {
	if d.rawFile == nil {
		for {
			n, err := d.file.Read(p)
			if err != nil && errors.Is(err, unix.EAGAIN) {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			return n, err
		}
	}

	for {
		if d.closed.Load() {
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
		if n < 20 {
			continue
		}
		// Must be IPv4
		if (p[0] >> 4) != 4 {
			continue
		}
		ihl := int(p[0]&0x0f) * 4
		if n < ihl+4 {
			continue
		}
		proto := p[9]
		if proto != 6 && proto != 17 { // TCP or UDP
			continue
		}
		dstPort := binary.BigEndian.Uint16(p[ihl+2 : ihl+4])
		d.mu.RLock()
		minP := d.minPort
		maxP := d.maxPort
		hIP := d.hostWANIP
		d.mu.RUnlock()

		if minP == 0 {
			minP = 40000
		}
		if maxP == 0 {
			maxP = 65000
		}
		if dstPort < minP || dstPort > maxP {
			continue
		}
		if hIP.IsValid() && hIP.Is4() {
			dstIP := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
			if dstIP != hIP {
				continue
			}
		}
		return n, nil
	}
}

func (d *linuxWANDevice) Write(p []byte) (int, error) {
	return d.file.Write(p)
}

func (d *linuxWANDevice) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		d.mu.Lock()
		if d.iptablesInstalled {
			d.removeResetSuppressionRulesLocked()
		}
		d.mu.Unlock()

		var errs []error
		if d.rawFile != nil {
			if err := d.rawFile.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if d.file != nil {
			if err := d.file.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	return nil
}

func newLinuxWANDeviceWithFiles(file, rawFile *os.File, name string, minPort, maxPort uint16, hostWANIP netip.Addr) *linuxWANDevice {
	if minPort == 0 {
		minPort = 40000
	}
	if maxPort == 0 {
		maxPort = 65000
	}
	dev := &linuxWANDevice{
		file:      file,
		rawFile:   rawFile,
		name:      name,
		minPort:   minPort,
		maxPort:   maxPort,
		hostWANIP: hostWANIP,
	}
	if hostWANIP.IsValid() && hostWANIP.Is4() && !hostWANIP.IsLoopback() && !hostWANIP.IsUnspecified() {
		_ = dev.SetHostWANIP(hostWANIP)
	}
	return dev
}

var (
	// ErrIPForwardingDisabled indicates Linux kernel IPv4 forwarding is not enabled.
	ErrIPForwardingDisabled = errors.New("kernel prerequisite failed: net.ipv4.ip_forward must be enabled (value 1)")
	// ErrStrictRPFilter is retained for callers and receipts that reference it. It is
	// no longer produced by prerequisite validation: strict filtering was the wrong
	// model (loose mode 2 does not rescue direct egress either), so validation now
	// reports ErrHostWANSourceValidation for any non-zero effective rp_filter.
	ErrStrictRPFilter = errors.New("kernel prerequisite failed: net.ipv4.conf.all.rp_filter is strict (1); direct WAN egress requires an effective rp_filter of 0")
	// ErrNoDefaultWANRoute indicates no active route exists to forward WAN egress traffic.
	ErrNoDefaultWANRoute = errors.New("kernel prerequisite failed: no active outbound WAN route detected")
	// ErrAcceptLocalDisabled indicates Linux kernel local-source acceptance is not enabled.
	ErrAcceptLocalDisabled = errors.New("kernel prerequisite failed: net.ipv4.conf.all.accept_local must be enabled (value 1)")
	// ErrWANCaptureDenied indicates the process may not open the AF_PACKET socket used to
	// capture direct-WAN return traffic. Opening it requires CAP_NET_RAW, which the
	// production binary does not receive from CAP_NET_ADMIN alone.
	ErrWANCaptureDenied = errors.New("kernel prerequisite failed: opening the AF_PACKET WAN capture socket requires CAP_NET_RAW (grant NET_RAW to the container and keep cap_net_raw in the binary's file capabilities)")
)

// defaultWANTunnelDeviceName is the WAN tunnel device the production constructor
// creates, and therefore the device whose per-interface prerequisites matter.
const defaultWANTunnelDeviceName = "nexus-wan0"

func isAllAcceptLocalEnabled() bool {
	return isAcceptLocalEnabled("/proc/sys/net/ipv4/conf/all/accept_local")
}

// isAcceptLocalEnabled reports whether the accept_local setting at procPath is 1.
func isAcceptLocalEnabled(procPath string) bool {
	// #nosec G304 -- procPath is a kernel procfs setting path constructed internally
	data, err := os.ReadFile(procPath)
	return err == nil && strings.TrimSpace(string(data)) == "1"
}

func checkAcceptLocalPrerequisite(setDevErr error, allEnabled bool, actualName string) error {
	if setDevErr != nil {
		if allEnabled {
			log.Printf("[vpn] warning: setAcceptLocal for %s failed (%v), but all.accept_local is enabled", actualName, setDevErr)
			return nil
		}
		return fmt.Errorf("wan prerequisites: accept_local is disabled on both all and %s (cannot inject SNAT packets without martian drop): %w", actualName, setDevErr)
	}
	return nil
}

func setAcceptLocal(procPath, sysctlKey string) error {
	cleanPath := filepath.Clean(procPath)
	// #nosec G304 -- cleanPath is constructed internally from trusted kernel procfs paths
	_ = os.WriteFile(cleanPath, []byte("1\n"), 0600)
	// #nosec G304 -- cleanPath is constructed internally from trusted kernel procfs paths
	data, err := os.ReadFile(cleanPath)
	if err == nil && strings.TrimSpace(string(data)) == "1" {
		return nil
	}
	sysctlPath, lookErr := exec.LookPath("sysctl")
	if lookErr == nil {
		// #nosec G204 -- sysctlKey is constructed internally from validated dev names
		cmd := exec.Command(sysctlPath, "-w", sysctlKey+"=1")
		_ = cmd.Run()
		// #nosec G304 -- cleanPath is constructed internally from trusted kernel procfs paths
		data, err = os.ReadFile(cleanPath)
		if err == nil && strings.TrimSpace(string(data)) == "1" {
			return nil
		}
	}
	return fmt.Errorf("configure %s: value is not 1", sysctlKey)
}

// ValidateKernelPrerequisites validates host Linux kernel settings required for direct WAN egress:
//  1. net.ipv4.ip_forward == 1
//  2. Effective source validation for the WAN tunnel device permits a locally
//     sourced, source-NATed packet (rp_filter=0 and accept_local=1 as effective
//     max(all,device) / all||device values — see wan_source_validation.go)
//  3. Outbound WAN route exists
//  4. iptables firewall utility is available
//  5. CAP_NET_RAW is available to open the AF_PACKET WAN capture socket
//
// The checks run in order so a failure names the first unmet prerequisite.
func ValidateKernelPrerequisites() error {
	return validateKernelPrerequisitesForDevice(defaultWANTunnelDeviceName)
}

// validateKernelPrerequisitesForDevice is ValidateKernelPrerequisites for an
// explicitly named WAN tunnel device, which is what the production constructor
// creates. It is separated so tests can exercise the real ordering and error
// surfaces against a device name of their choosing.
func validateKernelPrerequisitesForDevice(wanDeviceName string) error {
	for _, check := range []func() error{
		checkIPForwarding,
		func() error { return validateDirectEgressSourceValidation(sourceValidationRoot, wanDeviceName) },
		checkWANRoute,
		checkHostAcceptLocal,
		checkIPTablesAvailable,
		checkWANCaptureCapability,
	} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

// checkIPForwarding requires net.ipv4.ip_forward == 1.
func checkIPForwarding() error {
	fwdData, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("read net.ipv4.ip_forward: %w", err)
	}
	if strings.TrimSpace(string(fwdData)) != "1" {
		return ErrIPForwardingDisabled
	}
	return nil
}

// checkWANRoute requires an outbound WAN route.
func checkWANRoute() error {
	if _, err := DeriveHostWANIP(); err != nil {
		return fmt.Errorf("%w: %v", ErrNoDefaultWANRoute, err)
	}
	return nil
}

// ensureAcceptLocal enables accept_local at procPath, tolerating failure because the
// per-device setting is applied when the TUN device is created.
func ensureAcceptLocal(procPath, sysctlKey string) error {
	if isAcceptLocalEnabled(procPath) {
		return nil
	}
	if err := setAcceptLocal(procPath, sysctlKey); err != nil {
		log.Printf("[vpn] warning: unable to enable %s: %v; relying on per-device accept_local", procPath, err)
	}
	return nil
}

// checkHostAcceptLocal applies the host-wide accept_local prerequisite.
func checkHostAcceptLocal() error {
	return ensureAcceptLocal("/proc/sys/net/ipv4/conf/all/accept_local", "net.ipv4.conf.all.accept_local")
}

// checkIPTablesAvailable requires the iptables utility.
func checkIPTablesAvailable() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %w", err)
	}
	return nil
}

// checkWANCaptureCapability requires CAP_NET_RAW for the AF_PACKET capture socket
// that direct-WAN return traffic is read from.
func checkWANCaptureCapability() error {
	captureFD, err := openWANCaptureSocket()
	if err != nil {
		return err
	}
	_ = unix.Close(captureFD)
	return nil
}

// openWANCaptureSocket opens the AF_PACKET socket used to capture direct-WAN return
// traffic. Creating an AF_PACKET socket requires CAP_NET_RAW; CAP_NET_ADMIN alone is
// not sufficient, so a permission failure is reported as ErrWANCaptureDenied with the
// required capability named instead of a bare EPERM.
func openWANCaptureSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return -1, fmt.Errorf("open raw packet socket for wan return traffic: %w", ErrWANCaptureDenied)
		}
		return -1, fmt.Errorf("open raw packet socket for wan return traffic: %w", err)
	}
	return fd, nil
}

// NewProductionWANDevice creates a real Linux TUN device and raw socket capture for production WAN egress/ingress.
func NewProductionWANDevice(name string) (forwarder.PacketDevice, error) {
	if err := ValidateKernelPrerequisites(); err != nil {
		return nil, fmt.Errorf("wan prerequisites: %w", err)
	}
	if name == "" {
		name = "nexus-wan0"
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}

	var ifr [40]byte
	copy(ifr[:16], []byte(name))
	// IFF_TUN (0x0001) | IFF_NO_PI (0x1000)
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001|0x1000)

	// #nosec G103 -- SYS_IOCTL TUNSETIFF requires pointer to ifreq struct
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, errno
	}

	actualName := strings.TrimRight(string(ifr[:16]), "\x00")
	if actualName == "" {
		actualName = name
	}

	// Bring the interface UP programmatically (IFF_UP | IFF_RUNNING) via socket ioctl SIOCSIFFLAGS
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open socket for ifreq ioctl: %w", err)
	}
	defer unix.Close(sock)

	ifReq, err := unix.NewIfreq(actualName)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create ifreq for %s: %w", actualName, err)
	}

	if err := unix.IoctlIfreq(sock, unix.SIOCGIFFLAGS, ifReq); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("get interface flags for %s: %w", actualName, err)
	}

	flags := ifReq.Uint16() | uint16(unix.IFF_UP|unix.IFF_RUNNING)
	ifReq.SetUint16(flags)
	if err := unix.IoctlIfreq(sock, unix.SIOCSIFFLAGS, ifReq); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set interface flags up for %s: %w", actualName, err)
	}

	// Configure accept_local=1 on the TUN interface so locally sourced SNAT packets are accepted
	devAcceptLocalPath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/accept_local", actualName)
	setDevErr := setAcceptLocal(devAcceptLocalPath, fmt.Sprintf("net.ipv4.conf.%s.accept_local", actualName))
	if err := checkAcceptLocalPrerequisite(setDevErr, isAllAcceptLocalEnabled(), actualName); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	// Inbound return path packet reader: raw packet socket on host network interface
	// filtering for return traffic on allocated NAT ports (40000 - 65000).
	rawSock, err := openWANCaptureSocket()
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	if err := unix.SetNonblock(rawSock, true); err != nil {
		_ = unix.Close(rawSock)
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set raw packet socket non-blocking: %w", err)
	}

	sll := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  0, // capture from all host interfaces
	}
	_ = unix.Bind(rawSock, sll)

	dev := &linuxWANDevice{
		file:    os.NewFile(uintptr(fd), actualName),
		rawFile: os.NewFile(uintptr(rawSock), "nexus-wan-raw"),
		name:    actualName,
		minPort: 40000,
		maxPort: 65000,
	}
	if hostIP, err := DeriveHostWANIP(); err == nil && hostIP.IsValid() && hostIP.Is4() {
		if err := dev.SetHostWANIP(hostIP); err != nil {
			_ = dev.Close()
			return nil, fmt.Errorf("install reset suppression: %w", err)
		}
	}
	return dev, nil
}
