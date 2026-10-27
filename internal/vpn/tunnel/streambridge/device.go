package streambridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	// DefaultMTU is the default MTU (1280), matching the backend forwarder return MTU.
	DefaultMTU = 1280

	// DefaultMaxFlows is the default capacity for concurrent active flows per backend.
	DefaultMaxFlows = 4096

	// MaxFlowsPerBackend is the maximum supported concurrent flows per stream bridge.
	MaxFlowsPerBackend = 4096

	// DefaultQueueLen is the packet depth of the channel link endpoint.
	DefaultQueueLen = 1024

	// DefaultDialTimeout is the default deadline for establishing outbound streams.
	DefaultDialTimeout = 10 * time.Second

	// DefaultUDPIdleTimeout is the default inactivity period before a UDP flow is reaped.
	DefaultUDPIdleTimeout = 60 * time.Second

	// DefaultTCPHalfCloseTimeout is the timeout applied after FIN propagation before forcibly tearing down.
	DefaultTCPHalfCloseTimeout = 30 * time.Second
)

// Config configures the stream bridge packet device.
type Config struct {
	MTU                 int
	MaxFlows            int
	QueueLen            int
	DialTimeout         time.Duration
	UDPIdleTimeout      time.Duration
	TCPHalfCloseTimeout time.Duration
}

// FlowStats captures flow metrics for observability and diagnostics.
type FlowStats struct {
	Active       int
	Rejected     uint64
	DialFailures uint64
	Total        uint64
}

type deviceStats struct {
	nonIPv4           atomic.Uint64
	oversize          atomic.Uint64
	flowsRejected     atomic.Uint64
	dialFailures      atomic.Uint64
	flowsTotal        atomic.Uint64
	lastHandshakeNano atomic.Int64
}

// Device terminates client L3 packets in a private userspace netstack, demultiplexes
// them into L4/L7 flows, and splices them onto an outbound StreamDialer.
type Device struct {
	cfg                      Config
	dialer                   StreamDialer
	ep                       *channel.Endpoint
	stack                    *stack.Stack
	slots                    chan struct{}
	ctx                      context.Context
	cancel                   context.CancelFunc
	wg                       sync.WaitGroup
	gateMu                   sync.RWMutex
	closed                   atomic.Bool
	closeDone                chan struct{}
	pendingHandshakes        atomic.Int32
	beforeCreateEndpointHook func()
	createdAt                time.Time
	stats                    deviceStats
}

// New creates and initializes a stream bridge Device with gVisor netstack.
func New(cfg Config, d StreamDialer) (*Device, error) {
	if d == nil {
		return nil, errors.New("streambridge: dialer must not be nil")
	}

	if cfg.MTU <= 0 || cfg.MTU > 65535 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = DefaultMaxFlows
	}
	if cfg.MaxFlows > MaxFlowsPerBackend {
		cfg.MaxFlows = MaxFlowsPerBackend
	}
	if cfg.QueueLen <= 0 {
		cfg.QueueLen = DefaultQueueLen
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.UDPIdleTimeout <= 0 {
		cfg.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	if cfg.TCPHalfCloseTimeout <= 0 {
		cfg.TCPHalfCloseTimeout = DefaultTCPHalfCloseTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())

	dev := &Device{
		cfg:       cfg,
		dialer:    d,
		slots:     make(chan struct{}, cfg.MaxFlows),
		closeDone: make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
		createdAt: time.Now(),
	}

	// #nosec G115 -- cfg.MTU is validated in [1, 65535] range above.
	ep := channel.New(cfg.QueueLen, uint32(cfg.MTU), "")
	dev.ep = ep

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	dev.stack = s

	// Mandated TCP buffer size constraints: default 64 KiB, min 4 KiB, max 512 KiB per direction.
	// Prevents uncontrolled memory growth up to 8 GiB under 4096 concurrent flows.
	sendRange := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: 65536,
		Max:     524288,
	}
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sendRange); tcpipErr != nil {
		dev.cleanupOnInitError()
		return nil, fmt.Errorf("streambridge: set tcp send buffer range: %v", tcpipErr)
	}

	recvRange := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 65536,
		Max:     524288,
	}
	if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &recvRange); tcpipErr != nil {
		dev.cleanupOnInitError()
		return nil, fmt.Errorf("streambridge: set tcp recv buffer range: %v", tcpipErr)
	}

	sack := tcpip.TCPSACKEnabled(true)
	_ = s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	const nicID tcpip.NICID = 1
	if tcpipErr := s.CreateNIC(nicID, ep); tcpipErr != nil {
		dev.cleanupOnInitError()
		return nil, fmt.Errorf("streambridge: create nic: %v", tcpipErr)
	}

	if tcpipErr := s.SetPromiscuousMode(nicID, true); tcpipErr != nil {
		dev.cleanupOnInitError()
		return nil, fmt.Errorf("streambridge: set promiscuous mode: %v", tcpipErr)
	}

	if tcpipErr := s.SetSpoofing(nicID, true); tcpipErr != nil {
		dev.cleanupOnInitError()
		return nil, fmt.Errorf("streambridge: set spoofing: %v", tcpipErr)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	tcpFwd := tcp.NewForwarder(s, 0, 256, dev.onTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, dev.onUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return dev, nil
}

func (d *Device) cleanupOnInitError() {
	d.cancel()
	if d.ep != nil {
		d.ep.Close()
	}
	if d.stack != nil {
		d.stack.Close()
		d.stack.Wait()
	}
}

// Write injects an inbound L3 IPv4 packet from the VPN forwarder into the netstack.
// Non-IPv4 packets are dropped and accounted for in DroppedPackets.
func (d *Device) Write(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, net.ErrClosed
	}

	if len(p) < 20 || p[0]>>4 != 4 {
		d.stats.nonIPv4.Add(1)
		return len(p), nil
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(p),
	})
	d.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
	return len(p), nil
}

// Read extracts an outbound L3 packet emitted by the netstack into p.
// It unblocks and returns net.ErrClosed only when the device is closed.
// Oversize packets are safely dropped without returning an error.
func (d *Device) Read(p []byte) (int, error) {
	pkt := d.ep.ReadContext(d.ctx)
	if pkt == nil {
		return 0, net.ErrClosed
	}
	defer pkt.DecRef()

	v := pkt.ToView()
	if v == nil {
		return 0, nil
	}
	defer v.Release()

	if v.Size() > len(p) {
		d.stats.oversize.Add(1)
		return 0, nil
	}

	return copy(p, v.AsSlice()), nil
}

// Close gracefully terminates the device, canceling active flows, closing the netstack,
// and waiting for all flow goroutines to exit.
func (d *Device) Close() error {
	d.gateMu.Lock()
	if !d.closed.CompareAndSwap(false, true) {
		d.gateMu.Unlock()
		if d.closeDone != nil {
			<-d.closeDone
		}
		return nil
	}
	d.cancel()
	d.gateMu.Unlock()

	for {
		if d.stack != nil {
			for _, ep := range d.stack.RegisteredEndpoints() {
				ep.Abort()
			}
		}
		if d.pendingHandshakes.Load() == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	d.wg.Wait()
	d.ep.Close()
	d.stack.Close()
	d.stack.Wait()
	if d.closeDone != nil {
		close(d.closeDone)
	}
	return nil
}

// CreatedAt returns the device creation timestamp.
func (d *Device) CreatedAt() time.Time {
	return d.createdAt
}

// IsClosed returns true if the device has been closed.
func (d *Device) IsClosed() bool {
	return d.closed.Load()
}

// setBeforeCreateEndpointHookForTest registers a test hook called immediately
// before r.CreateEndpoint at the registration boundary.
func (d *Device) setBeforeCreateEndpointHookForTest(hook func()) {
	d.beforeCreateEndpointHook = hook
}

// DroppedPackets returns the cumulative number of dropped packets, including non-IPv4,
// oversize egress packets, and packets dropped due to netstack buffer exhaustion.
func (d *Device) DroppedPackets() uint64 {
	var drops uint64
	drops += d.stats.nonIPv4.Load()
	drops += d.stats.oversize.Load()
	if d.stack != nil {
		if stats := d.stack.Stats(); stats.NICs.TxPacketsDroppedNoBufferSpace != nil {
			drops += stats.NICs.TxPacketsDroppedNoBufferSpace.Value()
		}
	}
	return drops
}

// LastHandshakeTime returns the timestamp of the last successful outbound stream dial.
func (d *Device) LastHandshakeTime() time.Time {
	nano := d.stats.lastHandshakeNano.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

// FlowStats returns flow concurrency and admission statistics.
func (d *Device) FlowStats() FlowStats {
	return FlowStats{
		Active:       len(d.slots),
		Rejected:     d.stats.flowsRejected.Load(),
		DialFailures: d.stats.dialFailures.Load(),
		Total:        d.stats.flowsTotal.Load(),
	}
}
