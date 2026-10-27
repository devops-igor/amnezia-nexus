package streambridge

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildTCPPacket creates an IPv4 TCP SYN packet addressed to the given destination.
func buildTCPPacket(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8], pkt[9] = 64, 6
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:12], tcpChecksum(pkt[:20]))

	tcpHeader := pkt[20:]
	binary.BigEndian.PutUint16(tcpHeader[:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], 12345)
	tcpHeader[12], tcpHeader[13] = 0x50, 0x02 // SYN
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	pseudo := append([]byte{}, pkt[12:20]...)
	pseudo = append(pseudo, 0, 6, 0, 20)
	pseudo = append(pseudo, tcpHeader...)
	binary.BigEndian.PutUint16(tcpHeader[16:18], tcpChecksum(pseudo))
	return pkt
}

// TestFlows_CloseDuringInFlightTCPHandshakeRegistration explicitly pauses execution
// at the endpoint-registration boundary (between the closed check and r.CreateEndpoint(&wq)),
// triggers Device.Close(), and verifies that Close() completes promptly without stalling
// when the client handshake ACK never arrives.
func TestFlows_CloseDuringInFlightTCPHandshakeRegistration(t *testing.T) {
	out, peer := net.Pipe()
	defer peer.Close()
	dev, err := New(Config{}, funcDialer(func(context.Context, string, string) (net.Conn, error) {
		return out, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	hookEntered := make(chan struct{})
	hookRelease := make(chan struct{})

	dev.setBeforeCreateEndpointHookForTest(func() {
		close(hookEntered)
		<-hookRelease
	})

	pkt := buildTCPPacket(net.ParseIP("192.0.2.10"), 25000, net.ParseIP("198.51.100.1"), 8080)
	if _, err := dev.Write(pkt); err != nil {
		t.Fatal(err)
	}

	// Wait until onTCP has passed the closed check and paused at the registration boundary.
	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hook entry at registration boundary")
	}

	// Trigger Device.Close() while onTCP is paused at the boundary.
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- dev.Close()
	}()

	// Allow Close() to execute d.cancel() and its initial RegisteredEndpoints snapshot.
	time.Sleep(30 * time.Millisecond)

	// Release onTCP to call r.CreateEndpoint(&wq); deliberately never send client ACK.
	close(hookRelease)

	// Close() must complete promptly without stalling.
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close did not return promptly within 500ms when TCP handshake registered after shutdown began")
	}
}

// TestFlows_CloseDuringUnacknowledgedTCPHandshake_UncoordinatedRace runs multiple
// uncoordinated trials where Device.Close() races against an in-flight SYN packet
// whose client ACK is deliberately never sent.
func TestFlows_CloseDuringUnacknowledgedTCPHandshake_UncoordinatedRace(t *testing.T) {
	const iterations = 50
	rng := rand.New(rand.NewSource(633))

	for i := 0; i < iterations; i++ {
		out, peer := net.Pipe()
		dev, err := New(Config{}, funcDialer(func(context.Context, string, string) (net.Conn, error) {
			return out, nil
		}))
		if err != nil {
			peer.Close()
			t.Fatal(err)
		}

		pkt := buildTCPPacket(net.ParseIP("192.0.2.10"), uint16(20000+i), net.ParseIP("198.51.100.1"), 8080)
		if _, err := dev.Write(pkt); err != nil {
			dev.Close()
			peer.Close()
			t.Fatal(err)
		}

		if d := time.Duration(rng.Intn(300)) * time.Microsecond; d > 0 {
			time.Sleep(d)
		}

		done := make(chan error, 1)
		go func() {
			done <- dev.Close()
		}()

		select {
		case err := <-done:
			if err != nil {
				peer.Close()
				t.Fatalf("iteration %d: Close failed: %v", i, err)
			}
		case <-time.After(500 * time.Millisecond):
			peer.Close()
			t.Fatalf("iteration %d: Close stalled beyond 500ms during uncoordinated handshake race", i)
		}

		peer.Close()
	}
}

// TestDevice_MaxFlowsCeiling verifies that MaxFlows is clamped to MaxFlowsPerBackend (4096)
// when configured with values exceeding 4096 (e.g. 4097, 100000) or non-positive values.
func TestDevice_MaxFlowsCeiling(t *testing.T) {
	testCases := []struct {
		name     string
		maxFlows int
		wantCap  int
	}{
		{name: "above ceiling 4097", maxFlows: 4097, wantCap: MaxFlowsPerBackend},
		{name: "large excess 100000", maxFlows: 100000, wantCap: MaxFlowsPerBackend},
		{name: "zero default", maxFlows: 0, wantCap: MaxFlowsPerBackend},
		{name: "negative default", maxFlows: -1, wantCap: MaxFlowsPerBackend},
		{name: "exact ceiling 4096", maxFlows: 4096, wantCap: MaxFlowsPerBackend},
		{name: "valid below ceiling 500", maxFlows: 500, wantCap: 500},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dev, err := New(Config{MaxFlows: tc.maxFlows}, dummyDialer{})
			if err != nil {
				t.Fatalf("New error: %v", err)
			}
			defer dev.Close()

			if cap(dev.slots) != tc.wantCap {
				t.Errorf("cap(dev.slots) = %d, want %d", cap(dev.slots), tc.wantCap)
			}
			if dev.cfg.MaxFlows != tc.wantCap {
				t.Errorf("dev.cfg.MaxFlows = %d, want %d", dev.cfg.MaxFlows, tc.wantCap)
			}
		})
	}
}

// nonDeadlineBlockingConn simulates a net.Conn from an outbound dialer that returns an
// error on SetReadDeadline and blocks on Read until Close is called.
type nonDeadlineBlockingConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newNonDeadlineBlockingConn() *nonDeadlineBlockingConn {
	return &nonDeadlineBlockingConn{
		closed: make(chan struct{}),
	}
}

func (c *nonDeadlineBlockingConn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *nonDeadlineBlockingConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (c *nonDeadlineBlockingConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *nonDeadlineBlockingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (c *nonDeadlineBlockingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (c *nonDeadlineBlockingConn) SetDeadline(t time.Time) error {
	return errors.New("deadline not supported")
}

func (c *nonDeadlineBlockingConn) SetReadDeadline(t time.Time) error {
	return errors.New("read deadline not supported")
}

func (c *nonDeadlineBlockingConn) SetWriteDeadline(t time.Time) error {
	return errors.New("write deadline not supported")
}

// TestFlows_TCPHalfCloseReapingTimeout_NonDeadlineConn verifies that a half-closed TCP flow
// whose outbound connection rejects read deadlines is reliably reaped by the timer and releases
// its semaphore slot within TCPHalfCloseTimeout.
func TestFlows_TCPHalfCloseReapingTimeout_NonDeadlineConn(t *testing.T) {
	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return newNonDeadlineBlockingConn(), nil
	})

	const halfCloseTimeout = 50 * time.Millisecond
	cfg := Config{
		DialTimeout:         1 * time.Second,
		TCPHalfCloseTimeout: halfCloseTimeout,
	}
	dev, err := New(cfg, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := tc.DialTCP(ctx, "198.51.100.1:8080")
	if err != nil {
		t.Fatalf("DialTCP error: %v", err)
	}
	defer conn.Close()

	// Write data to establish flow
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if active := dev.FlowStats().Active; active != 1 {
		t.Fatalf("Active = %d, want 1", active)
	}

	// Client sends FIN via CloseWrite. Upstream dialer conn rejects read deadlines and blocks.
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite error: %v", err)
	}

	// Verify that the flow is reaped and slot released within TCPHalfCloseTimeout window.
	if !waitFor(t, func() bool { return dev.FlowStats().Active == 0 }) {
		t.Fatalf("slot not reaped after TCPHalfCloseTimeout on non-deadline conn: Active = %d", dev.FlowStats().Active)
	}
}

// TestDevice_ConcurrentCloseSynchronizedWaiting verifies that concurrent Close() callers
// block until the primary shutdown has fully completed.
func TestDevice_ConcurrentCloseSynchronizedWaiting(t *testing.T) {
	var dialStartedOnce sync.Once
	dialStarted := make(chan struct{})
	dialBlock := make(chan struct{})

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		dialStartedOnce.Do(func() {
			close(dialStarted)
		})
		select {
		case <-dialBlock:
			return nil, errors.New("aborted")
		case <-ctx.Done():
			<-dialBlock
			return nil, ctx.Err()
		}
	})

	dev, err := New(Config{}, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	pkt := buildTCPPacket(net.ParseIP("192.0.2.10"), 25001, net.ParseIP("198.51.100.1"), 8080)
	if _, err := dev.Write(pkt); err != nil {
		t.Fatalf("dev.Write: %v", err)
	}

	select {
	case <-dialStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dialer invocation")
	}

	var primaryFinished atomic.Bool
	primaryDone := make(chan error, 1)
	go func() {
		err := dev.Close()
		primaryFinished.Store(true)
		primaryDone <- err
	}()

	// Wait briefly to ensure primary Close() has acquired the gate and entered shutdown
	time.Sleep(50 * time.Millisecond)

	const concurrentCallers = 5
	secondaryDone := make(chan error, concurrentCallers)
	for i := 0; i < concurrentCallers; i++ {
		go func() {
			secondaryDone <- dev.Close()
		}()
	}

	// Verify that secondary callers are blocked and do NOT return while shutdown is in flight
	select {
	case <-secondaryDone:
		t.Fatal("secondary Close() returned before primary Close() completed shutdown")
	case <-time.After(100 * time.Millisecond):
		// Expected: all callers are waiting for primary Close() to complete
	}

	// Release dialer to let shutdown proceed
	close(dialBlock)

	select {
	case err := <-primaryDone:
		if err != nil {
			t.Fatalf("primary Close error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("primary Close did not complete after unblocking dialer")
	}

	for i := 0; i < concurrentCallers; i++ {
		select {
		case err := <-secondaryDone:
			if err != nil {
				t.Fatalf("secondary Close[%d] error: %v", i, err)
			}
			if !primaryFinished.Load() {
				t.Fatalf("secondary Close[%d] returned before primary shutdown finished", i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("secondary Close[%d] timed out waiting for shutdown completion", i)
		}
	}

	// Verify that a subsequent Close() after complete shutdown returns immediately
	if err := dev.Close(); err != nil {
		t.Fatalf("subsequent Close() returned error: %v", err)
	}
}
