package vpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// PacketDirection indicates the flow of UDP datagrams relative to client and server.
type PacketDirection int

const (
	DirClientToServer PacketDirection = 1
	DirServerToClient PacketDirection = 2
)

func (d PacketDirection) String() string {
	switch d {
	case DirClientToServer:
		return "ClientToServer"
	case DirServerToClient:
		return "ServerToClient"
	default:
		return "UnknownDirection"
	}
}

// PacketType classifies AmneziaWG packet formats by their deterministic wire size.
type PacketType int

const (
	PacketTypeUnknown PacketType = iota
	PacketTypeInitiation
	PacketTypeResponse
	PacketTypeCookieReply
	PacketTypeTransport
)

func (p PacketType) String() string {
	switch p {
	case PacketTypeInitiation:
		return "Initiation"
	case PacketTypeResponse:
		return "Response"
	case PacketTypeCookieReply:
		return "CookieReply"
	case PacketTypeTransport:
		return "Transport"
	default:
		return "Unknown"
	}
}

// FaultAction represents the deterministic forwarding action performed by UDPFaultShim.
type FaultAction int

const (
	ActionForward FaultAction = iota
	ActionDrop
	ActionDuplicate
)

func (a FaultAction) String() string {
	switch a {
	case ActionForward:
		return "Forward"
	case ActionDrop:
		return "Drop"
	case ActionDuplicate:
		return "Duplicate"
	default:
		return "Unknown"
	}
}

// UDPFaultShim is a test-only userspace UDP proxy on localhost between client and server.
// It intercepts datagrams in both directions, classifying them by wire size and direction,
// and applies deterministic fault schedules (drop, duplicate, delay) strictly in memory.
type UDPFaultShim struct {
	t          testing.TB
	conn       *net.UDPConn
	listenPort int
	serverAddr *net.UDPAddr
	serverPort int
	s1         int
	s2         int
	s3         int
	s4         int
	clientAddr atomic.Pointer[net.UDPAddr]
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
	closed     atomic.Bool

	mu                   sync.Mutex
	dropInitiations      atomic.Int32
	dropResponses        atomic.Int32
	duplicateInitiations atomic.Int32
	customHook           func(dir PacketDirection, pktType PacketType, pkt []byte) (FaultAction, time.Duration)

	// Observable deterministic telemetry counters
	InitiationsReceived   atomic.Int64
	InitiationsDropped    atomic.Int64
	InitiationsForwarded  atomic.Int64
	InitiationsDuplicated atomic.Int64
	ResponsesReceived     atomic.Int64
	ResponsesDropped      atomic.Int64
	ResponsesForwarded    atomic.Int64
	TransportForwarded    atomic.Int64
	TotalPacketsForwarded atomic.Int64
}

// NewUDPFaultShim binds a free UDP port on 127.0.0.1 and starts proxying towards serverPort.
func NewUDPFaultShim(t testing.TB, serverPort int, s1, s2, s3, s4 int) (*UDPFaultShim, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp shim: %w", err)
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	shim := &UDPFaultShim{
		t:          t,
		conn:       conn,
		listenPort: localAddr.Port,
		serverAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort},
		serverPort: serverPort,
		s1:         s1,
		s2:         s2,
		s3:         s3,
		s4:         s4,
		stopCh:     make(chan struct{}),
	}

	shim.wg.Add(1)
	go shim.forwardLoop()
	return shim, nil
}

// Port returns the ephemeral port on 127.0.0.1 where the shim is listening.
func (s *UDPFaultShim) Port() int {
	return s.listenPort
}

// Endpoint returns the host:port string of the shim for client configuration.
func (s *UDPFaultShim) Endpoint() string {
	return fmt.Sprintf("127.0.0.1:%d", s.listenPort)
}

// DropNextInitiation schedules dropping the next client handshake initiation packet.
func (s *UDPFaultShim) DropNextInitiation() {
	s.dropInitiations.Add(1)
}

// DropNextResponse schedules dropping the next server handshake response packet.
func (s *UDPFaultShim) DropNextResponse() {
	s.dropResponses.Add(1)
}

// DuplicateNextInitiation schedules immediate duplication of the next client initiation packet.
func (s *UDPFaultShim) DuplicateNextInitiation() {
	s.duplicateInitiations.Add(1)
}

// SetHook sets a custom classification and action callback for advanced fault schedules.
func (s *UDPFaultShim) SetHook(fn func(dir PacketDirection, pktType PacketType, pkt []byte) (FaultAction, time.Duration)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.customHook = fn
}

// ClassifyPacket determines packet type based on wire length, padding parameters, and direction.
// Initiation: 148 + S1 bytes (Client -> Server)
// Response: 92 + S2 bytes (Server -> Client)
// Cookie reply: 64 + S3 bytes (Server -> Client)
// Transport: >= 32 + S4 bytes (16-byte header + payload + 16-byte Poly1305 MAC)
func (s *UDPFaultShim) ClassifyPacket(dir PacketDirection, length int) PacketType {
	if dir == DirClientToServer && length == 148+s.s1 {
		return PacketTypeInitiation
	}
	if dir == DirServerToClient && length == 92+s.s2 {
		return PacketTypeResponse
	}
	if dir == DirServerToClient && s.s3 >= 0 && length == 64+s.s3 {
		return PacketTypeCookieReply
	}
	if length >= 32+s.s4 {
		return PacketTypeTransport
	}
	return PacketTypeUnknown
}

func (s *UDPFaultShim) evaluateAction(dir PacketDirection, pktType PacketType, pkt []byte) (FaultAction, time.Duration) {
	s.mu.Lock()
	hook := s.customHook
	s.mu.Unlock()
	if hook != nil {
		return hook(dir, pktType, pkt)
	}

	if pktType == PacketTypeInitiation {
		s.InitiationsReceived.Add(1)
		if s.dropInitiations.Load() > 0 {
			s.dropInitiations.Add(-1)
			return ActionDrop, 0
		}
		if s.duplicateInitiations.Load() > 0 {
			s.duplicateInitiations.Add(-1)
			return ActionDuplicate, 0
		}
	}

	if pktType == PacketTypeResponse {
		s.ResponsesReceived.Add(1)
		if s.dropResponses.Load() > 0 {
			s.dropResponses.Add(-1)
			return ActionDrop, 0
		}
	}

	return ActionForward, 0
}

func (s *UDPFaultShim) forwardLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		var dir PacketDirection
		if src.Port == s.serverPort {
			dir = DirServerToClient
		} else {
			dir = DirClientToServer
			s.clientAddr.Store(src)
		}

		pktType := s.ClassifyPacket(dir, n)
		action, delay := s.evaluateAction(dir, pktType, pkt)

		switch action {
		case ActionDrop:
			if pktType == PacketTypeInitiation {
				s.InitiationsDropped.Add(1)
			} else if pktType == PacketTypeResponse {
				s.ResponsesDropped.Add(1)
			}
			// Dropped: do not forward

		case ActionDuplicate:
			if pktType == PacketTypeInitiation {
				s.InitiationsDuplicated.Add(1)
				s.InitiationsForwarded.Add(2)
			}
			s.TotalPacketsForwarded.Add(2)
			if dir == DirClientToServer {
				_, _ = s.conn.WriteToUDP(pkt, s.serverAddr)
				_, _ = s.conn.WriteToUDP(pkt, s.serverAddr)
			} else {
				client := s.clientAddr.Load()
				if client != nil {
					_, _ = s.conn.WriteToUDP(pkt, client)
					_, _ = s.conn.WriteToUDP(pkt, client)
				}
			}

		case ActionForward:
			if pktType == PacketTypeInitiation {
				s.InitiationsForwarded.Add(1)
			} else if pktType == PacketTypeResponse {
				s.ResponsesForwarded.Add(1)
			} else if pktType == PacketTypeTransport {
				s.TransportForwarded.Add(1)
			}
			s.TotalPacketsForwarded.Add(1)

			if delay > 0 {
				go func(p []byte, d PacketDirection) {
					time.Sleep(delay)
					s.deliver(d, p)
				}(pkt, dir)
			} else {
				s.deliver(dir, pkt)
			}
		}
	}
}

func (s *UDPFaultShim) deliver(dir PacketDirection, pkt []byte) {
	if s.closed.Load() {
		return
	}
	if dir == DirClientToServer {
		_, _ = s.conn.WriteToUDP(pkt, s.serverAddr)
	} else {
		client := s.clientAddr.Load()
		if client != nil {
			_, _ = s.conn.WriteToUDP(pkt, client)
		}
	}
}

// Close gracefully stops the UDP forwarder loop and releases the socket.
func (s *UDPFaultShim) Close() error {
	s.closed.Store(true)
	var err error
	s.stopOnce.Do(func() {
		close(s.stopCh)
		err = s.conn.Close()
	})
	s.wg.Wait()
	return err
}

// NewClientViaShim constructs an upstream AWG client device configured to target the UDPFaultShim.
func (h *DifferentialHarness) NewClientViaShim(shim *UDPFaultShim) (*HarnessClient, error) {
	return h.NewClientWithEndpoint(shim.Endpoint())
}

// NewClientWithEndpoint constructs an upstream AWG client device targeting an arbitrary host:port endpoint.
func (h *DifferentialHarness) NewClientWithEndpoint(endpoint string) (*HarnessClient, error) {
	var lines []string
	for _, line := range strings.Split(h.rawClientConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Endpoint") && strings.Contains(trimmed, "=") {
			lines = append(lines, fmt.Sprintf("Endpoint = %s", endpoint))
		} else {
			lines = append(lines, line)
		}
	}
	modifiedConfig := strings.Join(lines, "\n")

	assignedAddr := netip.MustParseAddr(h.clientPeer.AllowedIP.Addr().String())
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{assignedAddr}, nil, 1280)
	if err != nil {
		return nil, fmt.Errorf("client tun: %w", err)
	}

	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "client"))
	uapi := configToUAPI(h.t.(*testing.T), modifiedConfig)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("client uapi: %w", err)
	}
	_ = dev.IpcSet("rekey_after_time=120\nrekey_timeout=1\n")
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("client up: %w", err)
	}

	return &HarnessClient{
		dev:         dev,
		tun:         vt,
		stack:       stack,
		assignedIP:  assignedAddr,
		destination: h.destinationIP,
		echoPort:    h.echoPort,
	}, nil
}

// IpcSet sends UAPI configuration instructions directly to the client device.
func (c *HarnessClient) IpcSet(ipc string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.dev == nil {
		return errors.New("client closed")
	}
	return c.dev.IpcSet(ipc)
}

// IpcGet reads UAPI state from the client device.
func (c *HarnessClient) IpcGet() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.dev == nil {
		return "", errors.New("client closed")
	}
	return c.dev.IpcGet()
}

// Device returns the underlying amneziawg-go device.
func (c *HarnessClient) Device() *device.Device {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dev
}
