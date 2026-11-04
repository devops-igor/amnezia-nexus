//go:build linux

package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"golang.org/x/sys/unix"
)

type linuxWANDevice struct {
	file      *os.File // TUN device for write
	rawFile   *os.File // AF_PACKET socket for return packet capture
	name      string
	closed    atomic.Bool
	minPort   uint16
	maxPort   uint16
	hostWANIP netip.Addr
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func (d *linuxWANDevice) SetHostWANIP(ip netip.Addr) {
	if d != nil {
		d.hostWANIP = ip
	}
}

func (d *linuxWANDevice) SetNATPortRange(minPort, maxPort uint16) {
	if d != nil {
		d.minPort = minPort
		d.maxPort = maxPort
	}
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
		minP := d.minPort
		if minP == 0 {
			minP = 40000
		}
		maxP := d.maxPort
		if maxP == 0 {
			maxP = 65000
		}
		if dstPort < minP || dstPort > maxP {
			continue
		}
		if d.hostWANIP.IsValid() && d.hostWANIP.Is4() {
			dstIP := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})
			if dstIP != d.hostWANIP {
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
	return &linuxWANDevice{
		file:      file,
		rawFile:   rawFile,
		name:      name,
		minPort:   minPort,
		maxPort:   maxPort,
		hostWANIP: hostWANIP,
	}
}

// NewProductionWANDevice creates a real Linux TUN device and raw socket capture for production WAN egress/ingress.
func NewProductionWANDevice(name string) (forwarder.PacketDevice, error) {
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

	return &linuxWANDevice{
		file:    os.NewFile(uintptr(fd), actualName),
		rawFile: os.NewFile(uintptr(rawSock), "nexus-wan-raw"),
		name:    actualName,
		minPort: 40000,
		maxPort: 65000,
	}, nil
}
