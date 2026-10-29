package vpn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// ReferenceServer wraps a standalone upstream AWG device backed by a netstack echo responder.
type ReferenceServer struct {
	dev         *device.Device
	tun         tun.Device
	stack       *netstack.Net
	tcpListener net.Listener
	udpConn     net.PacketConn
	port        int
	closed      bool
	mu          sync.Mutex

	echoWG     sync.WaitGroup // echo goroutines; netstack WriteNotify runs inside their writes
	acceptDone chan struct{}
	connMu     sync.Mutex
	conns      []net.Conn
}

// StartReferenceServer initializes the standalone reference AWG device and netstack echo server.
func (h *DifferentialHarness) StartReferenceServer() (*ReferenceServer, error) {
	vt, stack, err := netstack.CreateNetTUN([]netip.Addr{h.destinationIP}, nil, 1280)
	if err != nil {
		return nil, fmt.Errorf("reference tun: %w", err)
	}

	dev := device.NewDevice(vt, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "ref-server"))

	tcpListener, err := stack.ListenTCPAddrPort(netip.AddrPortFrom(h.destinationIP, h.echoPort))
	if err != nil {
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("reference tcp listener: %w", err)
	}

	udpConn, err := stack.ListenUDPAddrPort(netip.AddrPortFrom(h.destinationIP, h.echoPort))
	if err != nil {
		_ = tcpListener.Close()
		dev.Close()
		_ = vt.Close()
		return nil, fmt.Errorf("reference udp listener: %w", err)
	}

	ref := &ReferenceServer{
		dev:         dev,
		tun:         vt,
		stack:       stack,
		tcpListener: tcpListener,
		udpConn:     udpConn,
		port:        h.listenPort,
	}

	ref.startEchoWorkers()

	ipc := h.buildReferenceServerIPC()
	if err := dev.IpcSet(ipc); err != nil {
		_ = ref.Close()
		return nil, fmt.Errorf("reference ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		_ = ref.Close()
		return nil, fmt.Errorf("reference up: %w", err)
	}

	return ref, nil
}

func (s *ReferenceServer) startEchoWorkers() {
	s.acceptDone = make(chan struct{})
	s.echoWG.Add(2)
	go func() {
		defer s.echoWG.Done()
		defer close(s.acceptDone)
		for {
			c, err := s.tcpListener.Accept()
			if err != nil {
				return
			}
			s.connMu.Lock()
			s.conns = append(s.conns, c)
			s.connMu.Unlock()
			s.echoWG.Add(1)
			go func(conn net.Conn) {
				defer s.echoWG.Done()
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	go func() {
		defer s.echoWG.Done()
		buf := make([]byte, 4096)
		for {
			n, remote, err := s.udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			_, _ = s.udpConn.WriteTo(pkt, remote)
		}
	}()
}

// stopEchoWorkers closes the echo listeners/conns and waits for every echo goroutine, so no
// write into the netstack is in flight when the TUN channel is closed.
func (s *ReferenceServer) stopEchoWorkers() []error {
	var errs []error
	if s.tcpListener != nil {
		if err := s.tcpListener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.acceptDone != nil {
		<-s.acceptDone // no new conns after this
	}
	s.connMu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.connMu.Unlock()
	s.echoWG.Wait()
	return errs
}

// Close stops the reference AWG device and echo listeners.
func (s *ReferenceServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	errs := s.stopEchoWorkers()
	if s.dev != nil {
		s.dev.Close()
	} else if s.tun != nil {
		if err := s.tun.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PeerEndpoint returns the client's outer roaming endpoint as recorded by the reference server.
func (s *ReferenceServer) PeerEndpoint() (string, error) {
	ipc, err := s.dev.IpcGet()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			return strings.TrimPrefix(line, "endpoint="), nil
		}
	}
	return "", errors.New("peer endpoint not found in reference UAPI")
}

// StopReferenceServer cleanly terminates the reference server.
func (h *DifferentialHarness) StopReferenceServer(ref *ReferenceServer) error {
	if ref == nil {
		return nil
	}
	return ref.Close()
}
