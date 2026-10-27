package streambridge

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/devops-igor/amnezia-nexus/internal/vpn"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// Static assertion that Device satisfies both PacketDevice and BackendDevice.
var (
	_ tunnel.PacketDevice = (*Device)(nil)
	_ vpn.BackendDevice   = (*Device)(nil)
)

type dummyDialer struct{}

func (dummyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("dummyDialer: not implemented")
}

func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestDevice_NewValidation(t *testing.T) {
	_, err := New(Config{}, nil)
	if err == nil {
		t.Fatal("expected error when dialer is nil, got nil")
	}

	dev, err := New(Config{}, dummyDialer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer dev.Close()

	if dev.cfg.MTU != DefaultMTU {
		t.Errorf("MTU = %d, want default %d", dev.cfg.MTU, DefaultMTU)
	}
	if dev.cfg.MaxFlows != DefaultMaxFlows {
		t.Errorf("MaxFlows = %d, want default %d", dev.cfg.MaxFlows, DefaultMaxFlows)
	}
	if dev.cfg.QueueLen != DefaultQueueLen {
		t.Errorf("QueueLen = %d, want default %d", dev.cfg.QueueLen, DefaultQueueLen)
	}
	if dev.cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("DialTimeout = %v, want default %v", dev.cfg.DialTimeout, DefaultDialTimeout)
	}
	if dev.cfg.UDPIdleTimeout != DefaultUDPIdleTimeout {
		t.Errorf("UDPIdleTimeout = %v, want default %v", dev.cfg.UDPIdleTimeout, DefaultUDPIdleTimeout)
	}
	if dev.cfg.TCPHalfCloseTimeout != DefaultTCPHalfCloseTimeout {
		t.Errorf("TCPHalfCloseTimeout = %v, want default %v", dev.cfg.TCPHalfCloseTimeout, DefaultTCPHalfCloseTimeout)
	}

	if dev.IsClosed() {
		t.Error("new device should not be closed")
	}
	if time.Since(dev.CreatedAt()) > 5*time.Second {
		t.Errorf("unexpected CreatedAt: %v", dev.CreatedAt())
	}
	if !dev.LastHandshakeTime().IsZero() {
		t.Errorf("expected zero LastHandshakeTime, got %v", dev.LastHandshakeTime())
	}
	stats := dev.FlowStats()
	if stats.Active != 0 || stats.Rejected != 0 || stats.DialFailures != 0 || stats.Total != 0 {
		t.Errorf("expected zero FlowStats, got %+v", stats)
	}
}

func TestDevice_WritePacketBoundary(t *testing.T) {
	dev, err := New(Config{}, dummyDialer{})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	// 1. Packet too short (< 20 bytes)
	shortPkt := []byte{0x45, 0x00, 0x00}
	n, err := dev.Write(shortPkt)
	if err != nil {
		t.Fatalf("Write short packet returned error: %v", err)
	}
	if n != len(shortPkt) {
		t.Fatalf("Write short packet returned n = %d, want %d", n, len(shortPkt))
	}
	if drops := dev.DroppedPackets(); drops != 1 {
		t.Errorf("DroppedPackets = %d, want 1 for short packet", drops)
	}

	// 2. Non-IPv4 packet (IPv6 version nibble 6)
	ipv6Pkt := make([]byte, 40)
	ipv6Pkt[0] = 0x60
	n, err = dev.Write(ipv6Pkt)
	if err != nil {
		t.Fatalf("Write IPv6 packet returned error: %v", err)
	}
	if n != len(ipv6Pkt) {
		t.Fatalf("Write IPv6 packet returned n = %d, want %d", n, len(ipv6Pkt))
	}
	if drops := dev.DroppedPackets(); drops != 2 {
		t.Errorf("DroppedPackets = %d, want 2 for non-IPv4", drops)
	}
}

func TestDevice_CloseIdempotencyAndUnblock(t *testing.T) {
	dev, err := New(Config{}, dummyDialer{})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		_, readErr := dev.Read(buf)
		readDone <- readErr
	}()

	// Allow goroutine to block in ReadContext
	time.Sleep(50 * time.Millisecond)

	// Close the device concurrently from 3 goroutines
	var wg sync.WaitGroup
	errs := make([]error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = dev.Close()
		}(i)
	}
	wg.Wait()

	for i, closeErr := range errs {
		if closeErr != nil {
			t.Errorf("Close[%d] returned error: %v", i, closeErr)
		}
	}

	if !dev.IsClosed() {
		t.Error("expected IsClosed to be true after Close")
	}

	// Verify blocked Read was unblocked and returned net.ErrClosed
	select {
	case readErr := <-readDone:
		if !errors.Is(readErr, net.ErrClosed) {
			t.Errorf("Read unblocked with error %v, want net.ErrClosed", readErr)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Read did not unblock within 1s after Close")
	}

	// Subsequent Read and Write must return net.ErrClosed
	buf := make([]byte, 2048)
	if _, err := dev.Read(buf); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read after close returned %v, want net.ErrClosed", err)
	}

	dummyIPv4 := make([]byte, 20)
	dummyIPv4[0] = 0x45
	if _, err := dev.Write(dummyIPv4); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after close returned %v, want net.ErrClosed", err)
	}
}

func TestDevice_ReadOversizeDrop(t *testing.T) {
	dev, err := New(Config{}, dummyDialer{})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer dev.Close()

	// Inject a 100-byte outbound packet directly into the endpoint's channel
	pkts := stack.PacketBufferList{}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(make([]byte, 100)),
	})
	pkts.PushBack(pkt)
	_, tcpipErr := dev.ep.WritePackets(pkts)
	pkt.DecRef()
	if tcpipErr != nil {
		t.Fatalf("WritePackets error: %v", tcpipErr)
	}

	// Read with a 20-byte buffer (undersized for a 100-byte packet)
	tinyBuf := make([]byte, 20)
	n, err := dev.Read(tinyBuf)
	if err != nil {
		t.Fatalf("Read on oversize packet returned error: %v (MUST return nil error)", err)
	}
	if n != 0 {
		t.Fatalf("Read on oversize packet returned n = %d, want 0", n)
	}

	if drops := dev.DroppedPackets(); drops != 1 {
		t.Fatalf("DroppedPackets = %d, want 1 for oversize drop", drops)
	}
}

func TestDevice_GoroutineLeak(t *testing.T) {
	baseGoroutines := runtime.NumGoroutine()

	for i := 0; i < 5; i++ {
		dev, err := New(Config{}, dummyDialer{})
		if err != nil {
			t.Fatalf("New[%d] error: %v", i, err)
		}
		_ = dev.Close()
	}

	if !waitFor(t, func() bool {
		return runtime.NumGoroutine() <= baseGoroutines+1
	}) {
		t.Fatalf("goroutine leak: base=%d, current=%d", baseGoroutines, runtime.NumGoroutine())
	}
}
