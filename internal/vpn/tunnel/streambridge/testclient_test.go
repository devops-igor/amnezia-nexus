package streambridge

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type testClient struct {
	ep     *channel.Endpoint
	stack  *stack.Stack
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	ip     netip.Addr
}

func newTestClient(t *testing.T, dev *Device) *testClient {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	ep := channel.New(1024, 1280, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})

	const nicID tcpip.NICID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		cancel()
		t.Fatalf("testClient CreateNIC: %v", err)
	}

	clientIP := netip.MustParseAddr("10.10.10.2")
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(clientIP.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		cancel()
		t.Fatalf("testClient AddProtocolAddress: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	tc := &testClient{
		ep:     ep,
		stack:  s,
		ctx:    ctx,
		cancel: cancel,
		ip:     clientIP,
	}
	tc.startPumps(dev)
	return tc
}

func (c *testClient) startPumps(dev *Device) {
	c.wg.Add(1)

	// Pump: client -> device
	go func() {
		defer c.wg.Done()
		for {
			pkt := c.ep.ReadContext(c.ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			if v != nil {
				_, _ = dev.Write(v.AsSlice())
				v.Release()
			}
			pkt.DecRef()
		}
	}()

	// Pump: device -> client (daemon pump, exits when dev is closed)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				inPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(buf[:n]),
				})
				c.ep.InjectInbound(ipv4.ProtocolNumber, inPkt)
				inPkt.DecRef()
			}
		}
	}()
}

func (c *testClient) DialTCP(ctx context.Context, addr string) (*gonet.TCPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}

	fullAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dstIP.AsSlice()),
		Port: uint16(port),
	}
	return gonet.DialContextTCP(ctx, c.stack, fullAddr, ipv4.ProtocolNumber)
}

func (c *testClient) DialUDP(addr string) (*gonet.UDPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}

	remoteAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dstIP.AsSlice()),
		Port: uint16(port),
	}
	return gonet.DialUDP(c.stack, nil, &remoteAddr, ipv4.ProtocolNumber)
}

func (c *testClient) DialUDPWithBind(localPort uint16, addr string) (*gonet.UDPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	dstIP, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}

	localAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(c.ip.AsSlice()),
		Port: localPort,
	}
	remoteAddr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dstIP.AsSlice()),
		Port: uint16(port),
	}
	return gonet.DialUDP(c.stack, &localAddr, &remoteAddr, ipv4.ProtocolNumber)
}

func (c *testClient) Close() {
	c.cancel()
	c.ep.Close()
	c.stack.Close()
	c.wg.Wait()
	c.stack.Wait()
}
