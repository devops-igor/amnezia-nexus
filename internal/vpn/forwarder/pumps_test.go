package forwarder

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type pumpsTestDevice struct {
	mu       sync.Mutex
	pkts     [][]byte
	notifyCh chan struct{}
	closed   bool
}

func newPumpsTestDevice() *pumpsTestDevice {
	return &pumpsTestDevice{
		notifyCh: make(chan struct{}, 100),
	}
}

func (d *pumpsTestDevice) Read(p []byte) (int, error) {
	return 0, nil
}

func (d *pumpsTestDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	cp := make([]byte, len(p))
	copy(cp, p)
	d.pkts = append(d.pkts, cp)
	d.mu.Unlock()
	select {
	case d.notifyCh <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (d *pumpsTestDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	return nil
}

func (d *pumpsTestDevice) packetCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pkts)
}

func (d *pumpsTestDevice) waitForPacket(timeout time.Duration) bool {
	select {
	case <-d.notifyCh:
		return true
	case <-time.After(timeout):
		return false
	}
}

func testPumpsIPv4Packet(src, dst string, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 17 // UDP
	srcAddr := netip.MustParseAddr(src)
	dstAddr := netip.MustParseAddr(dst)
	src4 := srcAddr.As4()
	dst4 := dstAddr.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	copy(pkt[20:], payload)
	return pkt
}

func TestBackendDeviceLifecycleAndReattachment(t *testing.T) {
	t.Run("attach and detach without pumps", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		dev := newPumpsTestDevice()

		// Initial attach
		f.AttachBackendDevice(1, dev)
		f.mu.RLock()
		if f.backendDevices[1] != dev {
			f.mu.RUnlock()
			t.Fatal("backend device was not registered")
		}
		if _, ok := f.backendQueues[1]; !ok {
			f.mu.RUnlock()
			t.Fatal("backend queue was not created")
		}
		f.mu.RUnlock()

		// Idempotent attach
		f.AttachBackendDevice(1, dev)

		// Detach
		f.DetachBackendDevice(1)
		f.mu.RLock()
		if _, ok := f.backendDevices[1]; ok {
			f.mu.RUnlock()
			t.Fatal("backend device should be removed after detach")
		}
		f.mu.RUnlock()

		// Idempotent detach does not panic
		f.DetachBackendDevice(1)
	})

	t.Run("reattachment stops old pump and delivers to new device", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		dev1 := newPumpsTestDevice()
		f.AttachBackendDevice(10, dev1)
		f.StartPumps(ctx)
		defer f.StopPumps()

		peerKey := "peer-reattach-test"
		f.RegisterSession("s1", "c1", peerKey, "10.100.0.5", 10)

		pkt1 := testPumpsIPv4Packet("10.100.0.5", "1.1.1.1", []byte("hello-dev1"))
		if err := f.RouteClientToBackend(peerKey, pkt1); err != nil {
			t.Fatalf("RouteClientToBackend failed: %v", err)
		}
		if !dev1.waitForPacket(500 * time.Millisecond) {
			t.Fatal("dev1 timed out waiting for packet")
		}
		if dev1.packetCount() != 1 {
			t.Fatalf("dev1 got %d packets, want 1", dev1.packetCount())
		}

		// Reattach new device to backend 10
		dev2 := newPumpsTestDevice()
		f.AttachBackendDevice(10, dev2)

		pkt2 := testPumpsIPv4Packet("10.100.0.5", "1.1.1.1", []byte("hello-dev2"))
		if err := f.RouteClientToBackend(peerKey, pkt2); err != nil {
			t.Fatalf("RouteClientToBackend failed: %v", err)
		}
		if !dev2.waitForPacket(500 * time.Millisecond) {
			t.Fatal("dev2 timed out waiting for packet")
		}
		if dev2.packetCount() != 1 {
			t.Fatalf("dev2 got %d packets, want 1", dev2.packetCount())
		}
		// dev1 should NOT have received pkt2
		if dev1.packetCount() != 1 {
			t.Fatalf("dev1 received packet after detachment: got %d, want 1", dev1.packetCount())
		}

		// Detach backend device 10
		f.DetachBackendDevice(10)
		f.mu.RLock()
		if _, exists := f.backendDevices[10]; exists {
			f.mu.RUnlock()
			t.Fatal("backend device 10 should not exist after detach")
		}
		f.mu.RUnlock()
	})

	t.Run("attach with nil device clears registration", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		dev := newPumpsTestDevice()

		f.AttachBackendDevice(20, dev)
		f.AttachBackendDevice(20, nil)

		f.mu.RLock()
		defer f.mu.RUnlock()
		if _, ok := f.backendDevices[20]; ok {
			t.Fatal("expected backend 20 to be deleted when nil dev attached")
		}
	})
}

func TestPumpsLifecycle(t *testing.T) {
	t.Run("idempotent start and stop", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		ctx := t.Context()

		// Double start
		f.StartPumps(ctx)
		f.StartPumps(ctx)

		f.mu.RLock()
		running := f.pumpsRunning
		f.mu.RUnlock()
		if !running {
			t.Fatal("expected pumpsRunning to be true")
		}

		// Double stop
		f.StopPumps()
		f.StopPumps()

		f.mu.RLock()
		running = f.pumpsRunning
		f.mu.RUnlock()
		if running {
			t.Fatal("expected pumpsRunning to be false after StopPumps")
		}
	})

	t.Run("graceful shutdown without goroutine leaks", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		dev := newPumpsTestDevice()
		f.AttachBackendDevice(1, dev)

		for i := 0; i < 5; i++ {
			peer := "peer-lifecycle-" + string(rune('a'+i))
			ip := "10.100.0." + string(rune('2'+i))
			f.RegisterSession("s", "c", peer, ip, 1)
		}

		f.StartPumps(t.Context())

		// Route some traffic
		pkt := testPumpsIPv4Packet("10.100.0.2", "1.1.1.1", []byte("payload"))
		_ = f.RouteClientToBackend("peer-lifecycle-a", pkt)

		// StopPumps should terminate all pump goroutines and return cleanly
		f.StopPumps()

		f.mu.RLock()
		defer f.mu.RUnlock()
		if f.pumpsRunning {
			t.Fatal("pumpsRunning should be false after StopPumps")
		}
		for peer, route := range f.routesByPeer {
			if route.pumpStarted {
				t.Fatalf("route %s pumpStarted should be reset to false", peer)
			}
		}
	})

	t.Run("start pumps adopts existing routes and recovers after stop", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.RegisterSession("s1", "c1", "p1", "10.100.0.2", 1)

		f.StartPumps(t.Context())

		f.mu.RLock()
		r1 := f.routesByPeer["p1"]
		if !r1.pumpStarted {
			f.mu.RUnlock()
			t.Fatal("expected route p1 to be adopted by StartPumps")
		}
		f.mu.RUnlock()

		// Stop and restart
		f.StopPumps()
		f.StartPumps(t.Context())

		f.mu.RLock()
		if !r1.pumpStarted {
			f.mu.RUnlock()
			t.Fatal("expected route p1 to be adopted again after restart")
		}
		f.mu.RUnlock()

		f.StopPumps()
	})
}

func TestRouteClientToBackend(t *testing.T) {
	t.Run("successful routing to backend queue", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil) // creates backend queue for 1
		peer := "peer-ok"
		f.RegisterSession("s1", "c1", peer, "10.100.0.10", 1)

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		if err := f.RouteClientToBackend(peer, pkt); err != nil {
			t.Fatalf("RouteClientToBackend failed: %v", err)
		}

		ch, ok := f.GetBackendPacketChannel(1)
		if !ok {
			t.Fatal("missing backend channel")
		}
		select {
		case received := <-ch:
			if !bytes.Equal(received, pkt) {
				t.Fatalf("received packet %v, want %v", received, pkt)
			}
		default:
			t.Fatal("no packet found on backend queue")
		}

		rx, _, _ := f.GetStats()
		if rx != int64(len(pkt)) {
			t.Fatalf("rx bytes = %d, want %d", rx, len(pkt))
		}
	})

	t.Run("unregistered peer returns ErrSessionNotRegistered", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		err := f.RouteClientToBackend("unregistered-peer", pkt)
		if !errors.Is(err, ErrSessionNotRegistered) {
			t.Fatalf("got err %v, want ErrSessionNotRegistered", err)
		}
	})

	t.Run("missing backend queue returns ErrBackendNotFound and increments drop counters", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		peer := "peer-nobackend"
		f.RegisterSession("s1", "c1", peer, "10.100.0.10", 999)
		f.SetBackendQueueForTest(999, nil) // remove backend queue to simulate missing backend queue

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		err := f.RouteClientToBackend(peer, pkt)
		if !errors.Is(err, ErrBackendNotFound) {
			t.Fatalf("got err %v, want ErrBackendNotFound", err)
		}

		_, _, noBackendDrops, totalClientDrops := f.ClientDropStats()
		if noBackendDrops != 1 || totalClientDrops != 1 {
			t.Fatalf("client drop stats = (total: %d, noBackend: %d), want (1, 1)", totalClientDrops, noBackendDrops)
		}
	})

	t.Run("spoofed source IP returns ErrSpoofedSourceIP", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)
		peer := "peer-spoof"
		f.RegisterSession("s1", "c1", peer, "10.100.0.10", 1)

		// Packet claims to be from 10.100.0.99
		pkt := testPumpsIPv4Packet("10.100.0.99", "8.8.8.8", []byte("spoofed"))
		err := f.RouteClientToBackend(peer, pkt)
		if !errors.Is(err, ErrSpoofedSourceIP) {
			t.Fatalf("got err %v, want ErrSpoofedSourceIP", err)
		}
		if f.spoofedRebinds.Load() != 1 {
			t.Fatalf("spoofedRebinds = %d, want 1", f.spoofedRebinds.Load())
		}
	})

	t.Run("rate limit exceeded returns ErrRateLimitExceeded", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)
		peer := "peer-ratelimit"
		f.RegisterSession("s1", "c1", peer, "10.100.0.10", 1)

		// Set very low upload rate limit: 10 bytes/sec
		if err := f.SetPeerRateLimit(peer, 0, 10); err != nil {
			t.Fatalf("SetPeerRateLimit failed: %v", err)
		}

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", make([]byte, 100))
		err := f.RouteClientToBackend(peer, pkt)
		if !errors.Is(err, ErrRateLimitExceeded) {
			t.Fatalf("got err %v, want ErrRateLimitExceeded", err)
		}

		_, rateLimitedDrops, _, totalClientDrops := f.ClientDropStats()
		if rateLimitedDrops != 1 || totalClientDrops != 1 {
			t.Fatalf("client drop stats = (rateLimited: %d, total: %d), want (1, 1)", rateLimitedDrops, totalClientDrops)
		}
	})

	t.Run("backend queue full returns ErrQueueFull", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)

		// Replace backend queue with capacity 1
		ch := make(chan []byte, 1)
		f.SetBackendQueueForTest(1, ch)

		peer := "peer-qfull"
		f.RegisterSession("s1", "c1", peer, "10.100.0.10", 1)

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("p1"))
		if err := f.RouteClientToBackend(peer, pkt); err != nil {
			t.Fatalf("first packet failed: %v", err)
		}

		// Second packet overflows backend queue
		err := f.RouteClientToBackend(peer, pkt)
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("overflow packet got err %v, want ErrQueueFull", err)
		}

		queueFullDrops, _, _, totalClientDrops := f.ClientDropStats()
		if queueFullDrops != 1 || totalClientDrops != 1 {
			t.Fatalf("client drop stats = (qFull: %d, total: %d), want (1, 1)", queueFullDrops, totalClientDrops)
		}
	})
}

func TestRouteClientToBackendWithReturnPath(t *testing.T) {
	t.Run("nil return path returns ErrReturnPathClosed", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		err := f.RouteClientToBackendWithReturnPath("peer", pkt, nil)
		if !errors.Is(err, ErrReturnPathClosed) {
			t.Fatalf("got err %v, want ErrReturnPathClosed", err)
		}
	})

	t.Run("closed return path returns ErrReturnPathClosed", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		path := NewReturnPath(func(peer, ip string, p []byte) (int, error) { return len(p), nil })
		path.Close()

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		err := f.RouteClientToBackendWithReturnPath("peer", pkt, path)
		if !errors.Is(err, ErrReturnPathClosed) {
			t.Fatalf("got err %v, want ErrReturnPathClosed", err)
		}
	})

	t.Run("return path mismatch returns ErrSessionNotRegistered", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)
		path1 := NewReturnPath(func(peer, ip string, p []byte) (int, error) { return len(p), nil })
		path2 := NewReturnPath(func(peer, ip string, p []byte) (int, error) { return len(p), nil })

		peer := "peer-rp-mismatch"
		if _, err := f.TryRegisterSessionWithReturnPath("s1", "c1", peer, "10.100.0.10", 1, 0, 0, path1); err != nil {
			t.Fatalf("registration failed: %v", err)
		}

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		err := f.RouteClientToBackendWithReturnPath(peer, pkt, path2)
		if !errors.Is(err, ErrSessionNotRegistered) {
			t.Fatalf("got err %v, want ErrSessionNotRegistered", err)
		}
	})

	t.Run("matching return path routes successfully", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)
		path := NewReturnPath(func(peer, ip string, p []byte) (int, error) { return len(p), nil })

		peer := "peer-rp-match"
		if _, err := f.TryRegisterSessionWithReturnPath("s1", "c1", peer, "10.100.0.10", 1, 0, 0, path); err != nil {
			t.Fatalf("registration failed: %v", err)
		}

		pkt := testPumpsIPv4Packet("10.100.0.10", "8.8.8.8", []byte("ping"))
		if err := f.RouteClientToBackendWithReturnPath(peer, pkt, path); err != nil {
			t.Fatalf("RouteClientToBackendWithReturnPath failed: %v", err)
		}

		ch, _ := f.GetBackendPacketChannel(1)
		select {
		case received := <-ch:
			if !bytes.Equal(received, pkt) {
				t.Fatalf("received %v, want %v", received, pkt)
			}
		default:
			t.Fatal("packet not found in backend queue")
		}
	})
}

func TestRouteBackendToClient(t *testing.T) {
	t.Run("successful packet delivery to client route queue", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(2, nil)
		peer := "peer-downstream"
		destIP := "10.100.0.25"
		f.RegisterSession("s1", "c1", peer, destIP, 2)

		pkt := testPumpsIPv4Packet("8.8.8.8", destIP, []byte("reply"))
		if err := f.RouteBackendToClient(2, pkt, destIP); err != nil {
			t.Fatalf("RouteBackendToClient failed: %v", err)
		}

		ch, ok := f.GetClientPacketChannel(peer)
		if !ok {
			t.Fatal("missing client packet channel")
		}
		select {
		case received := <-ch:
			if !bytes.Equal(received, pkt) {
				t.Fatalf("received %v, want %v", received, pkt)
			}
		default:
			t.Fatal("packet not found in client queue")
		}

		_, tx, _ := f.GetStats()
		if tx != int64(len(pkt)) {
			t.Fatalf("tx bytes = %d, want %d", tx, len(pkt))
		}
	})

	t.Run("unregistered destination IP returns ErrSessionNotRegistered and drops", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		pkt := testPumpsIPv4Packet("8.8.8.8", "10.100.0.99", []byte("reply"))
		err := f.RouteBackendToClient(1, pkt, "10.100.0.99")
		if !errors.Is(err, ErrSessionNotRegistered) {
			t.Fatalf("got err %v, want ErrSessionNotRegistered", err)
		}

		_, noRoute, total := f.DropStats()
		if noRoute != 1 || total != 1 {
			t.Fatalf("drop stats = (noRoute: %d, total: %d), want (1, 1)", noRoute, total)
		}
	})

	t.Run("return path ownership mismatch on backend tunnel returns ErrReturnRouteMismatch", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)
		f.AttachBackendDevice(2, nil)
		path := NewReturnPath(func(peer, ip string, p []byte) (int, error) { return len(p), nil })

		peer := "peer-be-mismatch"
		destIP := "10.100.0.30"
		if _, err := f.TryRegisterSessionWithReturnPath("s1", "c1", peer, destIP, 1, 0, 0, path); err != nil {
			t.Fatalf("registration failed: %v", err)
		}

		// Arrives from backend 2 instead of 1
		pkt := testPumpsIPv4Packet("8.8.8.8", destIP, []byte("reply"))
		err := f.RouteBackendToClient(2, pkt, destIP)
		if !errors.Is(err, ErrReturnRouteMismatch) {
			t.Fatalf("got err %v, want ErrReturnRouteMismatch", err)
		}
	})

	t.Run("malformed packet destination returns ErrReturnRouteMismatch", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		f.AttachBackendDevice(1, nil)
		path := NewReturnPath(func(peer, ip string, p []byte) (int, error) { return len(p), nil })

		peer := "peer-malformed"
		destIP := "10.100.0.35"
		if _, err := f.TryRegisterSessionWithReturnPath("s1", "c1", peer, destIP, 1, 0, 0, path); err != nil {
			t.Fatalf("registration failed: %v", err)
		}

		// Truncated packet
		badPkt := []byte{0x45, 0x00, 0x00, 0x05}
		err := f.RouteBackendToClient(1, badPkt, destIP)
		if !errors.Is(err, ErrReturnRouteMismatch) {
			t.Fatalf("got err %v, want ErrReturnRouteMismatch", err)
		}
	})

	t.Run("packet exceeding maximum client queue size returns ErrPacketTooLarge", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		peer := "peer-oversized"
		destIP := "10.100.0.40"
		f.RegisterSession("s1", "c1", peer, destIP, 1)

		oversized := make([]byte, MaxClientQueuePacketBytes+1)
		err := f.RouteBackendToClient(1, oversized, destIP)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("got err %v, want ErrPacketTooLarge", err)
		}

		if f.dropsPacketTooLarge.Load() != 1 {
			t.Fatalf("dropsPacketTooLarge = %d, want 1", f.dropsPacketTooLarge.Load())
		}
	})

	t.Run("downstream rate limit exceeded returns ErrRateLimitExceeded", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 10)
		peer := "peer-down-ratelimit"
		destIP := "10.100.0.45"
		f.RegisterSession("s1", "c1", peer, destIP, 1)

		// Set downlink rate limit: 10 bytes/sec
		if err := f.SetPeerRateLimit(peer, 10, 0); err != nil {
			t.Fatalf("SetPeerRateLimit failed: %v", err)
		}

		pkt := testPumpsIPv4Packet("8.8.8.8", destIP, make([]byte, 100))
		err := f.RouteBackendToClient(1, pkt, destIP)
		if !errors.Is(err, ErrRateLimitExceeded) {
			t.Fatalf("got err %v, want ErrRateLimitExceeded", err)
		}
	})

	t.Run("client queue full returns ErrQueueFull and records drops", func(t *testing.T) {
		f := NewForwarder(nil, "10.100.0.0/16", 1) // buffer size = 1
		peer := "peer-client-qfull"
		destIP := "10.100.0.50"
		f.RegisterSession("s1", "c1", peer, destIP, 1)

		pkt := testPumpsIPv4Packet("8.8.8.8", destIP, []byte("pkt1"))
		if err := f.RouteBackendToClient(1, pkt, destIP); err != nil {
			t.Fatalf("first packet failed: %v", err)
		}

		// Second packet overflows client queue
		err := f.RouteBackendToClient(1, pkt, destIP)
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("overflow packet got err %v, want ErrQueueFull", err)
		}

		qDrops, _, total := f.DropStats()
		if qDrops != 1 || total != 1 {
			t.Fatalf("drop stats = (qDrops: %d, total: %d), want (1, 1)", qDrops, total)
		}

		stats, ok := f.RouteQueueStats(peer)
		if !ok {
			t.Fatal("missing RouteQueueStats")
		}
		if stats.QueueFullDrops != 1 {
			t.Fatalf("RouteQueueStats.QueueFullDrops = %d, want 1", stats.QueueFullDrops)
		}
	})
}
