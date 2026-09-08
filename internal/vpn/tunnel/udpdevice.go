package tunnel

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// PacketDevice abstracts a backend data-path device (UDP socket toward a
// backend AWG endpoint, or any in-memory device).
type PacketDevice interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

// udpQueueSize is the per-device inbound packet buffer depth.
const udpQueueSize = 512

// UDPDevice is a PacketDevice wrapping a connected UDP socket toward a remote
// backend AWG endpoint. It is the minimal viable backend data path of
// Issue #394 Batch 2: packets routed to a backend tunnel are written to this
// device and leave through the UDP socket; inbound datagrams from the backend
// are available via Read.
//
// LIMITATION (deferred to Batch 2b): traffic on this device is NOT encrypted
// with per-backend Noise/AWG sessions yet — the forwarder hands raw
// client-datagrams to the socket. Establishing full AWG sessions to each
// backend server is a follow-up.
type UDPDevice struct {
	name    string
	mtu     int
	conn    *net.UDPConn
	packets chan []byte
	errCh   chan error
	doneCh  chan struct{}
	closed  atomic.Bool
	once    sync.Once
	wg      sync.WaitGroup
}

// NewUDPDevice creates a UDP packet device connected to the given backend
// endpoint ("host:port"). mtu is advisory metadata for forwarders.
func NewUDPDevice(name, endpoint string, mtu int) (*UDPDevice, error) {
	addr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid backend endpoint %q: %w", endpoint, err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial backend endpoint %q: %w", endpoint, err)
	}
	if mtu <= 0 {
		mtu = 1420
	}
	d := &UDPDevice{
		name:    name,
		mtu:     mtu,
		conn:    conn,
		packets: make(chan []byte, udpQueueSize),
		errCh:   make(chan error, 1),
		doneCh:  make(chan struct{}),
	}
	d.startReadLoop()
	return d, nil
}

// startReadLoop pumps inbound backend datagrams into the device channel.
// A full channel drops packets (UDP semantics) so Close cannot deadlock.
func (d *UDPDevice) startReadLoop() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		buf := make([]byte, d.mtu+128)
		for {
			n, err := d.conn.Read(buf)
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

// Read blocks until an inbound backend datagram is available or the device is
// closed / the socket fails.
func (d *UDPDevice) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-d.packets:
		if !ok {
			return 0, errors.New("device closed")
		}
		return copy(p, pkt), nil
	case err := <-d.errCh:
		return 0, err
	case <-d.doneCh:
		return 0, errors.New("device closed")
	}
}

// Write sends a packet to the backend endpoint.
func (d *UDPDevice) Write(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, errors.New("device closed")
	}
	return d.conn.Write(p)
}

// Close closes the underlying UDP socket and unblocks pending reads.
func (d *UDPDevice) Close() error {
	var err error
	d.once.Do(func() {
		d.closed.Store(true)
		close(d.doneCh)
		err = d.conn.Close()
	})
	d.wg.Wait()
	return err
}

// LocalAddr returns the local address of the backend socket (used by peers
// to reply to packets sourced from this device).
func (d *UDPDevice) LocalAddr() net.Addr { return d.conn.LocalAddr() }

// Name returns the device name (backend interface name).
func (d *UDPDevice) Name() string { return d.name }

// MTU returns the device MTU.
func (d *UDPDevice) MTU() int { return d.mtu }
