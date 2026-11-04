//go:build linux

package vpn

import (
	"encoding/binary"
	"errors"
	"os"
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

	return &linuxWANDevice{
		file: os.NewFile(uintptr(fd), name),
		name: name,
	}, nil
}
