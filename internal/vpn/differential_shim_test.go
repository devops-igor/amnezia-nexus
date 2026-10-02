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

// ClassifyPacket determines packet type strictly calibrated to AmneziaWG wire framing
// with HeaderProtection (148+S1 initiation, 92+S2 response, 64+S3 cookie, >=32+S4 transport):
// Initiation: 148 + S1 bytes (Client -> Server) with HeaderProtection
// Response: 92 + S2 bytes (Server -> Client) with HeaderProtection
// Cookie reply: 64 + S3 bytes (Server -> Client) with HeaderProtection
// Transport: >= 32 + S4 bytes (16-byte header + payload + 16-byte Poly1305 MAC, plus trailers/padding) with HeaderProtection
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
			s.deliver(dir, pkt)
			go func(d PacketDirection, p []byte) {
				time.Sleep(10 * time.Millisecond)
				s.deliver(d, p)
			}(dir, pkt)

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

// OuterNATRoamingShim proxies client WireGuard packets towards the server and supports
// genuine outer UDP endpoint roaming via Roam().
// Initially, outbound packets to the server originate from ephemeral local UDP port A.
// When Roam() is called, the shim allocates a new ephemeral local UDP port B.
// Subsequent packets sent by the client arrive at the server from port B, prompting
// the server to update the peer's outer roaming endpoint and return responses to port B.
type OuterNATRoamingShim struct {
	t          testing.TB
	clientConn *net.UDPConn
	clientPort int
	serverAddr *net.UDPAddr

	mu         sync.Mutex
	activeConn *net.UDPConn
	allConns   []*net.UDPConn
	portA      int
	portB      int
	clientAddr atomic.Pointer[net.UDPAddr]

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	closed   atomic.Bool
}

// NewOuterNATRoamingShim binds a client-facing UDP listener and an initial server-facing UDP socket.
func NewOuterNATRoamingShim(t testing.TB, serverPort int) (*OuterNATRoamingShim, error) {
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen client udp shim: %w", err)
	}
	clientLocalAddr := clientConn.LocalAddr().(*net.UDPAddr)

	upstreamConnA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = clientConn.Close()
		return nil, fmt.Errorf("listen upstream udp conn a: %w", err)
	}
	portA := upstreamConnA.LocalAddr().(*net.UDPAddr).Port

	shim := &OuterNATRoamingShim{
		t:          t,
		clientConn: clientConn,
		clientPort: clientLocalAddr.Port,
		serverAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort},
		activeConn: upstreamConnA,
		allConns:   []*net.UDPConn{upstreamConnA},
		portA:      portA,
		stopCh:     make(chan struct{}),
	}

	shim.wg.Add(1)
	go shim.clientForwardLoop()

	shim.wg.Add(1)
	go shim.upstreamReturnLoop(upstreamConnA)

	return shim, nil
}

// Endpoint returns the host:port string of the client-facing listener.
func (s *OuterNATRoamingShim) Endpoint() string {
	return fmt.Sprintf("127.0.0.1:%d", s.clientPort)
}

// InitialUpstreamPort returns the original local UDP port A facing the server.
func (s *OuterNATRoamingShim) InitialUpstreamPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.portA
}

// CurrentUpstreamPort returns the currently active local UDP port facing the server.
func (s *OuterNATRoamingShim) CurrentUpstreamPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.portB != 0 {
		return s.portB
	}
	return s.portA
}

// Roam allocates a new local UDP socket (Port B) facing the server.
// Subsequent packets from the client are forwarded from Port B.
func (s *OuterNATRoamingShim) Roam() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return 0, errors.New("shim closed")
	}

	newConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return 0, fmt.Errorf("roam listen udp: %w", err)
	}
	portB := newConn.LocalAddr().(*net.UDPAddr).Port

	s.activeConn = newConn
	s.allConns = append(s.allConns, newConn)
	s.portB = portB

	s.wg.Add(1)
	go s.upstreamReturnLoop(newConn)

	return portB, nil
}

func (s *OuterNATRoamingShim) clientForwardLoop() {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		n, src, err := s.clientConn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		s.clientAddr.Store(src)
		pkt := append([]byte(nil), buf[:n]...)

		s.mu.Lock()
		conn := s.activeConn
		s.mu.Unlock()

		if conn != nil {
			_, _ = conn.WriteToUDP(pkt, s.serverAddr)
		}
	}
}

func (s *OuterNATRoamingShim) upstreamReturnLoop(uConn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535)

	for {
		n, _, err := uConn.ReadFromUDP(buf)
		if err != nil {
			if s.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n == 0 {
			continue
		}

		pkt := append([]byte(nil), buf[:n]...)
		client := s.clientAddr.Load()
		if client != nil {
			_, _ = s.clientConn.WriteToUDP(pkt, client)
		}
	}
}

// Close terminates all listening sockets and waits for forwarder goroutines to stop.
func (s *OuterNATRoamingShim) Close() error {
	s.closed.Store(true)
	var errs []error
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if err := s.clientConn.Close(); err != nil {
			errs = append(errs, err)
		}
		s.mu.Lock()
		for _, conn := range s.allConns {
			if err := conn.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
	return errors.Join(errs...)
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
