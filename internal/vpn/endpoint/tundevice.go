package endpoint

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrTunUnavailable indicates the Linux TUN device could not be opened —
// typically because /dev/net/tun is absent (missing device mount in the
// container) or the process lacks permission (CAP_NET_ADMIN). Callers treat
// this as a management-only degradation, not a fatal error: the panel keeps
// running with the VPN data plane disabled (listener_running:false).
var ErrTunUnavailable = errors.New("linux tun device unavailable")

// TunDevicePath is the Linux TUN control device used to create new interfaces.
const TunDevicePath = "/dev/net/tun"

// TUN/TAP and socket ioctl constants (linux/if_tun.h, linux/sockios.h).
// Hardcoded rather than referenced from x/sys/unix constants so the data path
// is independent of upstream constant exposure on the target toolchain.
//
//nolint:revive // constants kept local for clarity
const (
	ioctlTunSetIFF   = 0x400454ca // TUNSETIFF
	ioctlSIOCSIFlags = 0x8914     // SIOCSIFFLAGS
	tunIFFTun        = 0x0001     // IFF_TUN
	tunIFFNoPI       = 0x0008     // IFF_NO_PI
	ifIFFUp          = 0x0001     // IFF_UP
	ifIFFRunning     = 0x0040     // IFF_RUNNING
	ifReqNameLen     = 16
	ifReqSize        = 18 // ifr_name[16] + ifr_flags (2 bytes)
	tunMaxNameTries  = 8
)

// TunDevice is a real Linux TUN PacketDevice created from /dev/net/tun with
// IFF_TUN|IFF_NO_PI: Read/Write exchange raw IP packets with the kernel
// network stack (no 4-byte packet-info prefix). The interface is raised
// (IFF_UP|IFF_RUNNING) via a one-shot AF_INET control socket using the
// SIOCSIFFLAGS ioctl — no external `ip` command is executed.
//
// Blocking Read semantics: a goroutine reads the underlying os.File (backed
// by the Go runtime netpoller) and delivers whole packets to a channel, so
// Close reliably unblocks any pending Read.
type TunDevice struct {
	name    string
	mtu     int
	file    *os.File
	packets chan []byte
	errCh   chan error
	doneCh  chan struct{}
	closed  atomic.Bool
	wg      sync.WaitGroup
}

// OpenTunDevice creates and brings up a real Linux TUN interface with the
// requested name (MTU 1420 when mtu <= 0). When the requested name is already
// taken (EEXIST) the fallbacks "awg-ep0".."awg-ep7" are tried. It returns an
// error wrapping ErrTunUnavailable when /dev/net/tun is missing or the ioctl
// is not permitted.
func OpenTunDevice(name string, mtu int) (*TunDevice, error) {
	return openTunDevice(TunDevicePath, name, mtu)
}

// openTunDevice is the testable constructor core; path is injectable so the
// unavailable-device error surface can be exercised hermetically.
func openTunDevice(path, name string, mtu int) (*TunDevice, error) {
	if mtu <= 0 {
		mtu = 1420
	}
	if name == "" {
		name = "awg0"
	}

	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrTunUnavailable, path, err)
	}

	// Wrap the raw descriptor in an os.File so reads go through the Go
	// netpoller: file.Close() then reliably unblocks a pending Read.
	file := os.NewFile(uintptr(fd), path)

	dev, err := tunCreateInterface(file, name, mtu)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return dev, nil
}

// tunCreateInterface performs the TUNSETIFF ioctl (with name fallback) and the
// SIOCSIFFLAGS link-up ioctl on the given descriptor.
func tunCreateInterface(file *os.File, name string, mtu int) (*TunDevice, error) {
	fd := file.Fd()

	candidates := []string{name}
	for i := 0; i < tunMaxNameTries; i++ {
		candidates = append(candidates, fmt.Sprintf("awg-ep%d", i))
	}

	var finalName string
	for _, cand := range candidates {
		var ifr [ifReqSize]byte
		copy(ifr[:ifReqNameLen], []byte(cand)) // trailing NUL padding implicit
		flags := uint16(tunIFFTun | tunIFFNoPI)
		ifr[ifReqNameLen] = byte(flags)
		ifr[ifReqNameLen+1] = byte(flags >> 8)

		// #nosec G115 -- ioctl with a fixed-size stack buffer, standard TUN pattern.
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, ioctlTunSetIFF, uintptr(unsafe.Pointer(&ifr[0])))
		if errno == 0 {
			// The kernel may have assigned a different name (or trimmed
			// ours); read the effective name back from the ifreq.
			finalName = cString(ifr[:ifReqNameLen])
			break
		}
		if errno == unix.EEXIST || errno == unix.EBUSY {
			continue
		}
		return nil, fmt.Errorf("%w: TUNSETIFF for %s: %w", ErrTunUnavailable, cand, errno)
	}
	if finalName == "" {
		return nil, fmt.Errorf("%w: no free tun interface name", ErrTunUnavailable)
	}

	if err := tunLinkUp(fd, finalName); err != nil {
		return nil, err
	}

	dev := &TunDevice{
		name:    finalName,
		mtu:     mtu,
		file:    file,
		packets: make(chan []byte, 512),
		errCh:   make(chan error, 1),
		doneCh:  make(chan struct{}),
	}
	dev.startReadLoop()
	return dev, nil
}

// tunLinkUp raises the interface (IFF_UP|IFF_RUNNING) through a one-shot
// AF_INET control socket and the SIOCSIFFLAGS ioctl.
func tunLinkUp(fd uintptr, name string) error {
	ctrl, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to open control socket: %w", err)
	}
	defer func() { _ = unix.Close(ctrl) }()

	var ifr [ifReqSize]byte
	copy(ifr[:ifReqNameLen], []byte(name))
	flags := uint16(ifIFFUp | ifIFFRunning)
	ifr[ifReqNameLen] = byte(flags)
	ifr[ifReqNameLen+1] = byte(flags >> 8)

	// #nosec G115 -- ioctl with a fixed-size stack buffer, standard ifreq pattern.
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(ctrl), ioctlSIOCSIFlags, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return fmt.Errorf("failed to set IFF_UP on %s: %w", name, errno)
	}
	return nil
}

// startReadLoop pumps whole packets from the kernel into the device channel.
// A full channel drops the packet (packet-loss semantics) so Close can never
// deadlock against the loop.
func (d *TunDevice) startReadLoop() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		buf := make([]byte, d.mtu+128)
		for {
			n, err := d.file.Read(buf)
			if n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				select {
				case d.packets <- pkt:
				default: // inbound queue full: drop
				}
			}
			if err != nil {
				if !d.closed.Load() {
					select {
					case d.errCh <- err:
					default:
					}
				}
				return
			}
		}
	}()
}

// Read blocks until a whole raw IP packet is available, the device is closed,
// or the kernel read fails.
func (d *TunDevice) Read(p []byte) (int, error) {
	select {
	case pkt := <-d.packets:
		n := copy(p, pkt)
		return n, nil
	case err := <-d.errCh:
		return 0, err
	case <-d.doneCh:
		return 0, os.ErrClosed
	}
}

// Write hands a raw IP packet to the kernel (IFF_NO_PI: no packet-info header).
func (d *TunDevice) Write(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	return d.file.Write(p)
}

// Close tears the interface down and unblocks any pending Read.
func (d *TunDevice) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		close(d.doneCh)
		_ = d.file.Close()
	}
	d.wg.Wait()
	return nil
}

// Name returns the kernel-assigned interface name.
func (d *TunDevice) Name() string { return d.name }

// MTU returns the configured device MTU.
func (d *TunDevice) MTU() int { return d.mtu }

// cString extracts a NUL-terminated C string from a fixed-size byte buffer.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
