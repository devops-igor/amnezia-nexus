//go:build linux

package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"golang.org/x/sys/unix"
)

type linuxWANDevice struct {
	file *os.File
	name string
}

func (d *linuxWANDevice) Read(p []byte) (int, error) {
	for {
		n, err := d.file.Read(p)
		if err != nil && errors.Is(err, unix.EAGAIN) {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		return n, err
	}
}

func (d *linuxWANDevice) Write(p []byte) (int, error) {
	return d.file.Write(p)
}

func (d *linuxWANDevice) Close() error {
	return d.file.Close()
}

// NewProductionWANDevice creates a real Linux TUN device for production WAN egress.
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

	return &linuxWANDevice{
		file: os.NewFile(uintptr(fd), actualName),
		name: actualName,
	}, nil
}
