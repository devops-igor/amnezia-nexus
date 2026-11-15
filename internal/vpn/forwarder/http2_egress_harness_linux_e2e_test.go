//go:build linux

package forwarder

// The measuring harness of the HTTP/2-only egress qualification: the MSS clamp
// applied at the WAN device boundary, the peer TCP stack that drives the
// production dispatcher, the netstack proxy backend device and the peer-facing
// return path that carries the client tunnel's MTU.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// tcpMSSOption returns the MSS option of a SYN segment and the offsets needed to
// rewrite it. ok is false for anything that is not an IPv4 TCP segment.
func tcpMSSOption(pkt []byte) (mss uint16, optOff int, ok bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return 0, 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return 0, 0, false
	}
	dataOff := int(pkt[ihl+12]>>4) * 4
	if dataOff < 20+4 || len(pkt) < ihl+dataOff {
		return 0, 0, false
	}
	for i := ihl + 20; i+4 <= ihl+dataOff; {
		kind := pkt[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= ihl+dataOff {
			break
		}
		l := int(pkt[i+1])
		if l < 2 || i+l > ihl+dataOff {
			break
		}
		if kind == 2 && l == 4 {
			return binary.BigEndian.Uint16(pkt[i+2 : i+4]), i + 2, true
		}
		i += l
	}
	return 0, 0, false
}

// clampSYNMSS rewrites the MSS option of an outbound SYN segment to mss and
// repairs the TCP checksum. It mirrors the kernel TCPMSS rule, which matches
// packets with SYN set and RST clear, and reports whether it changed anything.
func clampSYNMSS(pkt []byte, mss uint16) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return false
	}
	if flags := pkt[ihl+13]; flags&0x02 == 0 || flags&0x04 != 0 {
		return false
	}
	cur, off, ok := tcpMSSOption(pkt)
	if !ok || cur <= mss {
		return false
	}
	binary.BigEndian.PutUint16(pkt[off:off+2], mss)

	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], 0)
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], computeL4Checksum(src, dst, 6, pkt[ihl:]))
	return true
}

// mssClampDevice wraps the WAN packet device and applies the MSS clamp to
// outbound SYN segments. It always records the MSS the client announced, so a
// case can prove the premise it relies on instead of assuming it.
type mssClampDevice struct {
	PacketDevice
	mu       sync.Mutex
	clampMSS uint16 // 0 disables the rewrite (observation only)
	observed uint16 // MSS announced by the last observed client SYN
	rewrites int
}

func (d *mssClampDevice) setClamp(mss uint16) {
	d.mu.Lock()
	d.clampMSS = mss
	d.observed = 0
	d.rewrites = 0
	d.mu.Unlock()
}

func (d *mssClampDevice) stats() (observed uint16, rewrites int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.observed, d.rewrites
}

func (d *mssClampDevice) Write(p []byte) (int, error) {
	if mss, _, ok := tcpMSSOption(p); ok {
		d.mu.Lock()
		d.observed = mss
		if d.clampMSS > 0 && clampSYNMSS(p, d.clampMSS) {
			d.rewrites++
		}
		d.mu.Unlock()
	}
	return d.PacketDevice.Write(p)
}

// h2MTUReturnPath is the peer-facing return path of the fixture. It carries the
// client tunnel's MTU: a packet larger than the tunnel cannot be delivered to
// the peer, so it is dropped and counted instead of injected, which is where an
// unclamped oversized segment disappears in production.
type h2MTUReturnPath struct {
	mu           sync.Mutex
	mtu          int
	inject       func([]byte)
	delivered    int
	oversized    int
	maxPacket    int
	oversizedMax int
}

func newH2MTUReturnPath(mtu int, inject func([]byte)) *h2MTUReturnPath {
	return &h2MTUReturnPath{mtu: mtu, inject: inject}
}

func (p *h2MTUReturnPath) write(_, _ string, packet []byte) (int, error) {
	p.mu.Lock()
	if len(packet) > p.mtu {
		p.oversized++
		if len(packet) > p.oversizedMax {
			p.oversizedMax = len(packet)
		}
		p.mu.Unlock()
		return len(packet), nil
	}
	p.delivered++
	if len(packet) > p.maxPacket {
		p.maxPacket = len(packet)
	}
	cp := append([]byte(nil), packet...)
	p.mu.Unlock()
	p.inject(cp)
	return len(packet), nil
}

func (p *h2MTUReturnPath) stats() (delivered, oversized, maxPacket, oversizedMax int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.delivered, p.oversized, p.maxPacket, p.oversizedMax
}

// h2ClientStack is a real TCP stack on the peer side. Packets it emits are
// submitted to the production dispatcher; packets the forwarder returns are
// injected back into it, so the HTTP/2 client below talks to a live TCP peer.
type h2ClientStack struct {
	ep       *channel.Endpoint
	stack    *stack.Stack
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	submitMu sync.Mutex
	submit   func([]byte) error
	outbound atomic.Int64
	sendErrs atomic.Int64
}

func newH2ClientStack(t *testing.T, clientIP netip.Addr, mtu uint32) *h2ClientStack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ep := channel.New(1024, mtu, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        false,
	})
	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		cancel()
		t.Fatalf("client stack CreateNIC failed: %v", err)
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(clientIP.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		cancel()
		t.Fatalf("client stack AddProtocolAddress failed: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	c := &h2ClientStack{ep: ep, stack: s, cancel: cancel}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			var raw []byte
			if view != nil {
				raw = append([]byte(nil), view.AsSlice()...)
				view.Release()
			}
			pkt.DecRef()
			if len(raw) < 20 {
				continue
			}
			c.submitMu.Lock()
			submit := c.submit
			c.submitMu.Unlock()
			c.outbound.Add(1)
			if submit != nil {
				if err := submit(raw); err != nil {
					c.sendErrs.Add(1)
				}
			}
		}
	}()
	return c
}

func (c *h2ClientStack) setSubmit(submit func([]byte) error) {
	c.submitMu.Lock()
	c.submit = submit
	c.submitMu.Unlock()
}

// inject hands one returned packet to the client stack.
func (c *h2ClientStack) inject(packet []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	c.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

func (c *h2ClientStack) close() {
	c.cancel()
	c.ep.Close()
	c.wg.Wait()
	c.stack.Close()
	c.stack.Wait()
}

// dialTLS opens the TCP connection through the stack and completes the TLS
// handshake, so the transport below never falls back to another protocol.
func (c *h2ClientStack) dialTLS(ctx context.Context, dst netip.AddrPort, cfg *tls.Config) (net.Conn, error) {
	addr := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()), Port: dst.Port()}
	conn, err := gonet.DialContextTCP(ctx, c.stack, addr, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// h2BatchDevice adapts the batch-oriented tun.Device of the netstack proxy
// backend to the forwarder's PacketDevice.
type h2BatchDevice struct {
	dev  tun.Device
	once sync.Once
}

func (d *h2BatchDevice) Read(p []byte) (int, error) {
	sizes := []int{0}
	n, err := d.dev.Read([][]byte{p}, sizes, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return sizes[0], nil
}

func (d *h2BatchDevice) Write(p []byte) (int, error) {
	if _, err := d.dev.Write([][]byte{p}, 0); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (d *h2BatchDevice) Close() (err error) {
	d.once.Do(func() { err = d.dev.Close() })
	return err
}

// h2CountingDevice counts the packets a proxy backend actually carried.
type h2CountingDevice struct {
	PacketDevice
	packets atomic.Int64
}

func (d *h2CountingDevice) Write(p []byte) (int, error) {
	d.packets.Add(1)
	return d.PacketDevice.Write(p)
}
