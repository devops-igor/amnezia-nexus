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
	// ErrStrictRPFilter indicates Linux kernel reverse path filtering is in strict mode (1).
	ErrStrictRPFilter = errors.New("kernel prerequisite failed: net.ipv4.conf.all.rp_filter is strict (1); direct WAN egress requires 0 or 2 (loose mode)")
	// ErrNoDefaultWANRoute indicates no active route exists to forward WAN egress traffic.
	ErrNoDefaultWANRoute = errors.New("kernel prerequisite failed: no active outbound WAN route detected")
	// ErrAcceptLocalDisabled indicates Linux kernel local-source acceptance is not enabled.
	ErrAcceptLocalDisabled = errors.New("kernel prerequisite failed: net.ipv4.conf.all.accept_local must be enabled (value 1)")
)

func isAllAcceptLocalEnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/accept_local")
	return err == nil && strings.TrimSpace(string(data)) == "1"
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
// 1. net.ipv4.ip_forward == 1
// 2. net.ipv4.conf.all.rp_filter != 1 (strict reverse path filtering drops asymmetric WAN replies)
// 3. Outbound WAN route exists
// 4. net.ipv4.conf.all.accept_local == 1 (permits locally sourced SNAT packets)
// 5. iptables firewall utility is available
func ValidateKernelPrerequisites() error {
	// 1. IP Forwarding
	fwdData, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return fmt.Errorf("read net.ipv4.ip_forward: %w", err)
	}
	if strings.TrimSpace(string(fwdData)) != "1" {
		return ErrIPForwardingDisabled
	}

	// 2. Reverse-path filtering
	rpData, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter")
	if err == nil {
		val := strings.TrimSpace(string(rpData))
		if val == "1" {
			return ErrStrictRPFilter
		}
	}

	// 3. Outbound WAN route viability
	if _, err := DeriveHostWANIP(); err != nil {
		return fmt.Errorf("%w: %v", ErrNoDefaultWANRoute, err)
	}

	// 4. Local-source acceptance (accept_local=1)
	if !isAllAcceptLocalEnabled() {
		allAcceptLocalPath := "/proc/sys/net/ipv4/conf/all/accept_local"
		if err := setAcceptLocal(allAcceptLocalPath, "net.ipv4.conf.all.accept_local"); err != nil {
			log.Printf("[vpn] warning: unable to enable %s: %v; relying on per-device accept_local", allAcceptLocalPath, err)
		}
	}

	// 5. Firewall / iptables availability
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %w", err)
	}

	return nil
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
	if err := setAcceptLocal(devAcceptLocalPath, fmt.Sprintf("net.ipv4.conf.%s.accept_local", actualName)); err != nil {
		if !isAllAcceptLocalEnabled() {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("enable accept_local for %s: %w", actualName, err)
		}
		log.Printf("[vpn] warning: enable per-device accept_local for %s failed (%v), but all.accept_local is enabled", actualName, err)
	}

	// Inbound return path packet reader: raw packet socket on host network interface
	// filtering for return traffic on allocated NAT ports (40000 - 65000).
	rawSock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open raw packet socket for wan return traffic: %w", err)
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
