package gatewaydns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// barrierListener is a net.Listener whose Close blocks until released, so a test
// can prove whether Serve returned before listener teardown completed.
type barrierListener struct {
	acceptCh chan net.Conn
	closeCh  chan struct{}
	doneCh   chan struct{}

	closeEntered chan struct{}
	releaseClose chan struct{}

	mu     sync.Mutex
	closed bool
}

func newBarrierListener() *barrierListener {
	return &barrierListener{
		acceptCh:     make(chan net.Conn),
		closeCh:      make(chan struct{}),
		doneCh:       make(chan struct{}),
		closeEntered: make(chan struct{}),
		releaseClose: make(chan struct{}),
	}
}

func (l *barrierListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.acceptCh:
		return c, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// Close signals that teardown started, then parks until the test releases it.
func (l *barrierListener) Close() error {
	l.mu.Lock()
	alreadyClosed := l.closed
	l.closed = true
	l.mu.Unlock()
	if alreadyClosed {
		return nil
	}
	close(l.closeEntered)
	<-l.releaseClose
	close(l.closeCh)
	close(l.doneCh)
	return nil
}

func (l *barrierListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

// barrierConn is a connection that first delivers one framed DNS query, then
// blocks until it is closed. That lets a handler reach the resolver and park
// there while the test holds the teardown open.
type barrierConn struct {
	closeOnce sync.Once
	closedCh  chan struct{}
	pending   []byte
}

func newBarrierConn(query []byte) *barrierConn {
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)
	return &barrierConn{closedCh: make(chan struct{}), pending: framed}
}

func (c *barrierConn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	<-c.closedCh
	return 0, net.ErrClosed
}

func (c *barrierConn) Write(b []byte) (int, error) { return len(b), nil }

func (c *barrierConn) Close() error {
	c.closeOnce.Do(func() { close(c.closedCh) })
	return nil
}

func (c *barrierConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *barrierConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *barrierConn) SetDeadline(time.Time) error      { return nil }
func (c *barrierConn) SetReadDeadline(time.Time) error  { return nil }
func (c *barrierConn) SetWriteDeadline(time.Time) error { return nil }

// TestServerServe_JoinsListenerTeardownAndHandlersBeforeReturning is the
// deterministic ordering oracle for the shutdown race: Serve's caller owns the
// packet device the listener writes into, so Serve must not return while its
// listener teardown, accept loop or connection handlers are still running.
//
// The barrier makes both sides deterministic (no sleeps decide the outcome):
// the connection handler is parked inside the resolver and the listener's Close
// is parked on an explicit release channel. Any ordering that returns early is
// detected before the releases are given.
func TestServerServe_JoinsListenerTeardownAndHandlersBeforeReturning(t *testing.T) {
	handlerEntered := make(chan struct{}, 1)
	handlerRelease := make(chan struct{})

	res := &mockResolver{
		exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			// Deliberately ignore ctx: the handler must stay in flight until the
			// test releases it, so "did Serve return early?" is unambiguous.
			select {
			case handlerEntered <- struct{}{}:
			default:
			}
			<-handlerRelease
			resp := new(mdns.Msg)
			resp.SetReply(req)
			return resp, nil
		},
	}

	srv, err := NewServer(ServerConfig{Gateway: netip.MustParseAddrPort("10.0.0.1:53")}, res, &staticPolicySource{})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	ln := newBarrierListener()

	query := new(mdns.Msg)
	query.SetQuestion("barrier.example.com.", mdns.TypeA)
	queryBytes, err := query.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}
	conn := newBarrierConn(queryBytes)

	ctx, cancel := context.WithCancel(context.Background())
	scope := NewScopeHandle(ctx, policy.Scope{SessionID: "sess-barrier", OwnershipEpoch: 1}, nil, &mockReplyWriter{})

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(scope.Context(), scope, nil, ln) }()

	// Deliver one connection to the accept loop and wait until its handler is
	// parked inside the resolver.
	select {
	case ln.acceptCh <- conn:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptor never consumed the test connection")
	}
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("connection handler never reached the resolver")
	}

	// Begin teardown; the listener's Close parks inside the barrier.
	cancel()
	select {
	case <-ln.closeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("listener teardown never started")
	}

	// With a handler still in flight and listener teardown unfinished, Serve
	// must not have returned.
	var returnedEarly bool
	select {
	case <-serveDone:
		returnedEarly = true
	case <-time.After(250 * time.Millisecond):
	}

	// Always release both barriers so a failure cannot strand goroutines.
	close(handlerRelease)
	close(ln.releaseClose)

	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after teardown barriers were released")
	}
	if returnedEarly {
		t.Fatal("Serve returned before listener teardown and the in-flight connection handler finished")
	}

	// Post-conditions: the producer finished, so the listener really is closed
	// and Serve's teardown removed the scope's limiter state.
	select {
	case <-ln.doneCh:
	default:
		t.Error("listener Close did not complete")
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("expected listener to be closed, got %v", err)
	}
	if active := srv.ActiveSessionLimiters(); active != 0 {
		t.Errorf("expected Serve teardown to retire the scope's limiter state, %d remain", active)
	}
}

// TestGatewayTransport_CloseJoinsServeBeforeClosingDevice proves the gateway
// transport does not close the netstack device while the Serve goroutine (which
// emits packets through that device during listener teardown) is still running.
func TestGatewayTransport_CloseJoinsServeBeforeClosingDevice(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	gwAddrPort := netip.AddrPortFrom(gwIP, 53)
	clientIP := netip.MustParseAddr("10.8.0.2")

	handlerEntered := make(chan struct{}, 1)
	handlerRelease := make(chan struct{})

	res := &mockResolver{
		exchange: func(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
			select {
			case handlerEntered <- struct{}{}:
			default:
			}
			<-handlerRelease
			resp := new(mdns.Msg)
			resp.SetReply(req)
			return resp, nil
		},
	}

	srv, err := NewServer(ServerConfig{Gateway: gwAddrPort, QueryTimeout: 5 * time.Second}, res, &staticPolicySource{})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	gw, err := NewGateway(GatewayConfig{Gateway: gwAddrPort}, srv)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer gw.Close()

	writer := &mockReplyWriter{}
	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-join", OwnershipEpoch: 1}, nil, writer)
	defer scope.Retire()

	// Client stack: submits every outbound packet to the gateway.
	clientVT, clientTnet, err := netstack.CreateNetTUN([]netip.Addr{clientIP}, nil, 1500)
	if err != nil {
		t.Fatalf("failed to create client netstack: %v", err)
	}

	writer.onPacket = func(packet []byte) { _, _ = clientVT.Write([][]byte{packet}, 0) }

	stopReader := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		buf := make([][]byte, 1)
		buf[0] = make([]byte, 1500)
		sizes := make([]int, 1)
		for {
			select {
			case <-stopReader:
				return
			default:
			}
			n, err := clientVT.Read(buf, sizes, 0)
			if err != nil {
				return
			}
			if n > 0 && sizes[0] > 0 {
				pkt := make([]byte, sizes[0])
				copy(pkt, buf[0][:sizes[0]])
				_, _ = gw.TrySubmit(scope, pkt)
			}
		}
	}()
	// The reader parks inside the device Read, so the device must be closed to
	// unblock it; only then can the reader be joined. Detach the reply writer
	// first (under its own lock) so any gateway reader goroutine still draining
	// cannot write into the device after this point.
	defer func() {
		writer.mu.Lock()
		writer.onPacket = nil
		writer.mu.Unlock()
		close(stopReader)
		_ = clientVT.Close()
		readerWG.Wait()
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := clientTnet.DialContextTCPAddrPort(dialCtx, gwAddrPort)
	if err != nil {
		t.Fatalf("client failed to dial TCP to gateway: %v", err)
	}
	defer conn.Close()

	req := new(mdns.Msg)
	req.SetQuestion("join.example.com.", mdns.TypeA)
	req.Id = 5566
	dnsBytes, err := req.Pack()
	if err != nil {
		t.Fatalf("failed to pack query: %v", err)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(dnsBytes)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		t.Fatalf("failed to write length: %v", err)
	}
	if _, err := conn.Write(dnsBytes); err != nil {
		t.Fatalf("failed to write query: %v", err)
	}

	select {
	case <-handlerEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("TCP query handler never reached the resolver")
	}

	// Capture the transport before Close removes it from the registry.
	gw.mu.Lock()
	tr := gw.transports[scope.Scope]
	gw.mu.Unlock()
	if tr == nil {
		t.Fatal("expected a transport to be registered for the scope")
	}

	// Close the transport while its query handler is still in flight. The
	// device close must wait for Serve to join that handler.
	closeDone := make(chan struct{})
	go func() {
		gw.Close()
		close(closeDone)
	}()

	var closedEarly bool
	select {
	case <-closeDone:
		closedEarly = true
	case <-time.After(250 * time.Millisecond):
	}

	close(handlerRelease)

	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway.Close did not return after the query handler was released")
	}
	if closedEarly {
		t.Fatal("Gateway.Close closed the netstack device while Serve was still producing packets")
	}

	// The Serve goroutine must be joined (not merely signalled) by the time
	// Close returns; that is what orders listener teardown before device close.
	select {
	case <-tr.serveDone:
	default:
		t.Error("transport Close returned before its Serve goroutine finished")
	}
	if !tr.closed.Load() {
		t.Error("expected transport to be marked closed")
	}
}

// TestGatewayTransport_InjectionAfterCloseIsDropped proves a submit racing an
// already-closed transport is dropped instead of writing into a closed device
// (which would panic on the device's outbound packet channel).
func TestGatewayTransport_InjectionAfterCloseIsDropped(t *testing.T) {
	gwIP := netip.MustParseAddr("10.8.0.1")
	gwAddrPort := netip.AddrPortFrom(gwIP, 53)

	srv, err := NewServer(ServerConfig{Gateway: gwAddrPort}, &mockResolver{}, &staticPolicySource{})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	gw, err := NewGateway(GatewayConfig{Gateway: gwAddrPort}, srv)
	if err != nil {
		t.Fatalf("failed to create gateway: %v", err)
	}
	defer gw.Close()

	scope := NewScopeHandle(context.Background(), policy.Scope{SessionID: "sess-drop", OwnershipEpoch: 1}, nil, &mockReplyWriter{})

	// Minimal IPv4/TCP packet addressed to the gateway on port 53.
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], []byte{10, 8, 0, 2})
	copy(pkt[16:20], []byte{10, 8, 0, 1})
	binary.BigEndian.PutUint16(pkt[20:22], 40000)
	binary.BigEndian.PutUint16(pkt[22:24], 53)

	handled, err := gw.TrySubmit(scope, pkt)
	if err != nil || !handled {
		t.Fatalf("expected first submit to create the transport, handled=%v err=%v", handled, err)
	}

	gw.mu.Lock()
	tr := gw.transports[scope.Scope]
	gw.mu.Unlock()
	if tr == nil {
		t.Fatal("expected a transport to be registered")
	}
	tr.Close()

	// Injecting into the closed transport must be a drop, not a device write.
	handled, err = gw.TrySubmit(scope, pkt)
	if err != nil || !handled {
		t.Fatalf("expected submit on closed transport to be handled and dropped, handled=%v err=%v", handled, err)
	}
}
