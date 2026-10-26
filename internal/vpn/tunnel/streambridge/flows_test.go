package streambridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type funcDialer func(ctx context.Context, network, address string) (net.Conn, error)

func (f funcDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp echo: %v", err)
	}
	var wg sync.WaitGroup
	closed := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-closed:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	cleanup := func() {
		close(closed)
		_ = l.Close()
		wg.Wait()
	}
	return l.Addr().String(), cleanup
}

func startUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	var wg sync.WaitGroup
	closed := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				select {
				case <-closed:
					return
				default:
					return
				}
			}
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()

	cleanup := func() {
		close(closed)
		_ = conn.Close()
		wg.Wait()
	}
	return conn.LocalAddr().String(), cleanup
}

func TestFlows_TCPEchoAndHalfClose(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoServer(t)
	defer stopEcho()

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoAddr)
	})

	cfg := Config{
		DialTimeout:         2 * time.Second,
		TCPHalfCloseTimeout: 1 * time.Second,
	}
	dev, err := New(cfg, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := tc.DialTCP(ctx, "198.51.100.1:8080")
	if err != nil {
		t.Fatalf("DialTCP error: %v", err)
	}
	defer conn.Close()

	// 1. Send and receive 256 KiB random payload
	const payloadSize = 256 * 1024
	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read error: %v", err)
	}

	recvBuf := make([]byte, payloadSize)
	errCh := make(chan error, 2)

	// Sender goroutine
	go func() {
		_, writeErr := conn.Write(payload)
		errCh <- writeErr
	}()

	// Receiver goroutine
	go func() {
		_, readErr := io.ReadFull(conn, recvBuf)
		errCh <- readErr
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("payload transfer error: %v", err)
		}
	}

	if !bytes.Equal(payload, recvBuf) {
		t.Fatal("echoed payload mismatch!")
	}

	// 2. Test half-close propagation
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite error: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	extraBuf := make([]byte, 16)
	n, readErr := conn.Read(extraBuf)
	if n != 0 || !errors.Is(readErr, io.EOF) {
		t.Fatalf("expected EOF after CloseWrite, got n=%d, err=%v", n, readErr)
	}

	_ = conn.Close()

	if !waitFor(t, func() bool { return dev.FlowStats().Active == 0 }) {
		t.Fatalf("slot not released: Active = %d", dev.FlowStats().Active)
	}

	if dev.LastHandshakeTime().IsZero() {
		t.Fatal("expected non-zero LastHandshakeTime after successful dial")
	}
}

func TestFlows_TCPHalfCloseReapingTimeout(t *testing.T) {
	// Start an upstream server that reads client data to EOF but never closes the connection.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer l.Close()

	var wg sync.WaitGroup
	serverDone := make(chan struct{})
	defer func() {
		close(serverDone)
		wg.Wait()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		// Read until client closes write (EOF), but do NOT close or send FIN.
		_, _ = io.Copy(io.Discard, conn)

		// Wait until test teardown or peer disconnect.
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
		}
	}()

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", l.Addr().String())
	})

	const halfCloseTimeout = 200 * time.Millisecond
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

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if active := dev.FlowStats().Active; active != 1 {
		t.Fatalf("Active = %d, want 1", active)
	}

	// Client sends FIN via CloseWrite. Upstream reads EOF and stays open.
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite error: %v", err)
	}

	// Verify that the flow is terminated and Active returns to 0 within timeout window.
	if !waitFor(t, func() bool { return dev.FlowStats().Active == 0 }) {
		t.Fatalf("slot not reaped after TCPHalfCloseTimeout: Active = %d", dev.FlowStats().Active)
	}
}

func TestFlows_UDPEchoAndMultiFlow(t *testing.T) {
	echoAddr, stopEcho := startUDPEchoServer(t)
	defer stopEcho()

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", echoAddr)
	})

	cfg := Config{
		UDPIdleTimeout: 300 * time.Millisecond,
	}
	dev, err := New(cfg, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	// Flow 1 from local port 20001
	conn1, err := tc.DialUDPWithBind(20001, "198.51.100.1:53")
	if err != nil {
		t.Fatalf("DialUDP 1 error: %v", err)
	}
	defer conn1.Close()

	msg1 := []byte("udp-payload-1")
	if _, err := conn1.Write(msg1); err != nil {
		t.Fatalf("conn1 Write error: %v", err)
	}

	resp1 := make([]byte, 1024)
	_ = conn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n1, err := conn1.Read(resp1)
	if err != nil {
		t.Fatalf("conn1 Read error: %v", err)
	}
	if string(resp1[:n1]) != string(msg1) {
		t.Fatalf("conn1 response mismatch: got %q, want %q", resp1[:n1], msg1)
	}

	// Flow 2 from local port 20002
	conn2, err := tc.DialUDPWithBind(20002, "198.51.100.1:53")
	if err != nil {
		t.Fatalf("DialUDP 2 error: %v", err)
	}
	defer conn2.Close()

	msg2 := []byte("udp-payload-2")
	if _, err := conn2.Write(msg2); err != nil {
		t.Fatalf("conn2 Write error: %v", err)
	}

	resp2 := make([]byte, 1024)
	_ = conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, err := conn2.Read(resp2)
	if err != nil {
		t.Fatalf("conn2 Read error: %v", err)
	}
	if string(resp2[:n2]) != string(msg2) {
		t.Fatalf("conn2 response mismatch: got %q, want %q", resp2[:n2], msg2)
	}

	// Two distinct 4-tuples must produce Total == 2
	stats := dev.FlowStats()
	if stats.Total != 2 {
		t.Errorf("FlowStats.Total = %d, want 2", stats.Total)
	}

	// Wait for UDP idle reaping (configured to 300ms)
	time.Sleep(500 * time.Millisecond)
	if !waitFor(t, func() bool { return dev.FlowStats().Active == 0 }) {
		t.Errorf("expected UDP flows to be reaped, got Active = %d", dev.FlowStats().Active)
	}
}

func TestFlows_CapUnderPressure(t *testing.T) {
	echoAddr, stopEcho := startTCPEchoServer(t)
	defer stopEcho()

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoAddr)
	})

	const maxFlows = 8
	cfg := Config{
		MaxFlows:            maxFlows,
		DialTimeout:         1 * time.Second,
		TCPHalfCloseTimeout: 1 * time.Second,
	}
	dev, err := New(cfg, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	// 1. Establish and hold 8 flows
	heldConns := make([]*gonet.TCPConn, maxFlows)
	for i := 0; i < maxFlows; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := tc.DialTCP(ctx, net.JoinHostPort("198.51.100.1", "8080"))
		cancel()
		if err != nil {
			t.Fatalf("held flow %d dial error: %v", i, err)
		}
		heldConns[i] = conn
	}

	if active := dev.FlowStats().Active; active != maxFlows {
		t.Fatalf("Active flows = %d, want %d", active, maxFlows)
	}

	// 2. Launch 200 concurrent SYNs against the saturated device
	const floodCount = 200
	var wg sync.WaitGroup
	var peakActive atomic.Int64
	peakActive.Store(int64(maxFlows))

	for i := 0; i < floodCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()

			c, err := tc.DialTCP(ctx, "198.51.100.1:8080")
			cur := int64(dev.FlowStats().Active)
			for {
				old := peakActive.Load()
				if cur <= old || peakActive.CompareAndSwap(old, cur) {
					break
				}
			}
			if err == nil {
				_ = c.Close()
			}
		}()
	}
	wg.Wait()

	stats := dev.FlowStats()
	if peak := peakActive.Load(); peak > maxFlows {
		t.Errorf("peak active flows = %d, exceeded cap of %d", peak, maxFlows)
	}
	if stats.Rejected < floodCount {
		t.Errorf("Rejected = %d, want >= %d", stats.Rejected, floodCount)
	}

	// 3. Release held conns and verify active drops to 0
	for _, c := range heldConns {
		_ = c.Close()
	}

	if !waitFor(t, func() bool { return dev.FlowStats().Active == 0 }) {
		t.Fatalf("slots not released after closing held conns: Active = %d", dev.FlowStats().Active)
	}
}

func TestFlows_DialFailure(t *testing.T) {
	failingDialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("upstream connection refused")
	})

	cfg := Config{
		DialTimeout: 500 * time.Millisecond,
	}
	dev, err := New(cfg, failingDialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	tc := newTestClient(t, dev)
	defer tc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := tc.DialTCP(ctx, "198.51.100.1:8080")
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected dial error when upstream dialer fails, got nil")
	}

	stats := dev.FlowStats()
	if stats.DialFailures != 1 {
		t.Errorf("DialFailures = %d, want 1", stats.DialFailures)
	}
	if stats.Active != 0 {
		t.Errorf("Active = %d, want 0 after failure", stats.Active)
	}
}

func TestFlows_HangingDialerClose(t *testing.T) {
	baseGoroutines := runtime.NumGoroutine()

	dialerStarted := make(chan struct{})
	hangingDialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		close(dialerStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	})

	cfg := Config{
		DialTimeout: 5 * time.Second, // Long timeout: Close must abort it earlier
	}
	dev, err := New(cfg, hangingDialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	tc := newTestClient(t, dev)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = tc.DialTCP(ctx, "198.51.100.1:8080")
	}()

	select {
	case <-dialerStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("dialer did not start")
	}

	closeStart := time.Now()
	_ = dev.Close()
	tc.Close()
	closeDuration := time.Since(closeStart)

	if closeDuration > 1*time.Second {
		t.Errorf("Close took %v, want < 1s", closeDuration)
	}

	if !waitFor(t, func() bool {
		return runtime.NumGoroutine() <= baseGoroutines+2
	}) {
		t.Errorf("goroutine leak after hanging dialer close: base=%d, current=%d", baseGoroutines, runtime.NumGoroutine())
	}
}

func TestFlows_CapAtMaxFlowsPerBackend(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 4,200 flow test in short mode")
	}

	dialer := funcDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, errors.New("refused")
	})

	cfg := Config{
		MaxFlows: MaxFlowsPerBackend, // 4096
	}
	dev, err := New(cfg, dialer)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	// Fill all 4096 slots
	for i := 0; i < MaxFlowsPerBackend; i++ {
		if !dev.acquire() {
			t.Fatalf("failed to acquire slot %d", i)
		}
	}

	// 4097th attempt must be rejected
	if dev.acquire() {
		t.Fatal("expected 4097th slot acquisition to fail, but it succeeded")
	}

	stats := dev.FlowStats()
	if stats.Active != MaxFlowsPerBackend {
		t.Errorf("Active = %d, want %d", stats.Active, MaxFlowsPerBackend)
	}
	if stats.Rejected != 1 {
		t.Errorf("Rejected = %d, want 1", stats.Rejected)
	}

	// Release all slots
	for i := 0; i < MaxFlowsPerBackend; i++ {
		dev.release()
	}

	if dev.FlowStats().Active != 0 {
		t.Errorf("Active = %d, want 0 after release", dev.FlowStats().Active)
	}
}
