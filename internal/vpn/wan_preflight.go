//go:build linux

package vpn

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"unsafe"

	"golang.org/x/sys/unix"
)

// StandaloneResult describes the outcome of one deployment-capability probe.
type StandaloneResult struct {
	Name string
	Err  error
}

// OK reports whether the probe completed without error.
func (r StandaloneResult) OK() bool { return r.Err == nil }

// Label renders the probe status for operator output.
func (r StandaloneResult) Label() string {
	if r.Err != nil {
		return "FAIL"
	}
	return "OK"
}

// RunStandaloneWANChecks reports whether this process holds the capabilities the
// direct WAN egress path needs, and writes a report to w. It is read-only: it opens
// and closes descriptors and reads procfs, but creates no device, rule, or sysctl
// entry and sends no traffic. That makes it safe to run as a container startup or
// smoke assertion, where the goal is to catch a missing capability before PBR
// traffic is ever offered.
func RunStandaloneWANChecks(w io.Writer) []StandaloneResult {
	results := []StandaloneResult{
		{Name: "TUN device access (/dev/net/tun, CAP_NET_ADMIN)", Err: checkTUNAccess()},
		{Name: "AF_PACKET WAN capture socket (CAP_NET_RAW)", Err: checkWANCaptureSocket()},
	}
	printWANCheckReport(w, results)
	return results
}

// checkTUNAccess verifies /dev/net/tun can be opened and that a TUN interface can be
// created, then closes it immediately. Creating the interface is the only state
// change, and it disappears when the descriptor closes.
func checkTUNAccess() error {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open /dev/net/tun: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	var ifr [40]byte
	copy(ifr[:16], []byte("nexus-wanpreflt"))
	// IFF_TUN (0x0001) | IFF_NO_PI (0x1000)
	ifr[16] = 0x01
	ifr[17] = 0x10
	// #nosec G103 -- TUNSETIFF requires a pointer to an ifreq struct
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("create TUN interface (needs CAP_NET_ADMIN): %w", errno)
	}
	return nil
}

// checkWANCaptureSocket opens and closes the production capture socket so a missing
// CAP_NET_RAW is reported as ErrWANCaptureDenied instead of surfacing later.
func checkWANCaptureSocket() error {
	fd, err := openWANCaptureSocket()
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func printWANCheckReport(w io.Writer, results []StandaloneResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\n", r.Label(), r.Name)
		if r.Err != nil {
			fmt.Fprintf(tw, "\t%v\n", r.Err)
		}
	}
	_ = tw.Flush()
}

// EffectiveCapabilityNames lists the capability names in the process effective set,
// for operator diagnostics.
func EffectiveCapabilityNames() []string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil
		}
		var mask uint64
		if _, err := fmt.Sscanf(fields[1], "%x", &mask); err != nil {
			return nil
		}
		names := make([]string, 0, 8)
		for _, c := range knownCapabilities {
			if mask&(1<<c.bit) != 0 {
				names = append(names, c.name)
			}
		}
		return names
	}
	return nil
}

var knownCapabilities = []struct {
	bit  uint
	name string
}{
	{12, "CAP_NET_ADMIN"},
	{13, "CAP_NET_RAW"},
	{21, "CAP_SYS_ADMIN"},
}
