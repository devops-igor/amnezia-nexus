package forwarder

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// failingPacketDev is an attached backend device whose asynchronous writes
// always fail, standing in for a closed or unreachable backend socket. The
// write is performed by the egress pump, not by the routing call, so this is
// the attached-but-failing-device boundary.
type failingPacketDev struct {
	mu    sync.Mutex
	wrote int
}

func (d *failingPacketDev) Read([]byte) (int, error) { return 0, nil }

func (d *failingPacketDev) Write(p []byte) (int, error) {
	d.mu.Lock()
	d.wrote++
	d.mu.Unlock()
	return 0, errors.New("backend device write failed")
}

func (d *failingPacketDev) Close() error { return nil }

func (d *failingPacketDev) writeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wrote
}

// proxyAccountingFwd is intentionally absent: every test below builds its own
// forwarder so the lifecycle step under test (attach, detach, re-attach, pump
// start) stays explicit.

// TestProxyAccounting_DetachDrainsAbandonedProxyQueue pins stale-owner
// isolation: packets already queued for a backend that goes away are discarded
// and counted, and are never handed to the device a later re-attach installs.
func TestProxyAccounting_DetachDrainsAbandonedProxyQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, _, wanDev, rc := setupForwarderWithPBR(t)
	fwd.Start(ctx)
	// No pumps yet: the queue keeps whatever is admitted, so the drain is
	// observable instead of racing the egress pump.
	defer func() { _ = fwd.Stop() }()

	const (
		peerKey   = "peer-drain"
		sessionID = "sess-drain"
		clientIP  = "10.100.0.62"
		backendID = int64(413)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "conn-drain", peerKey, clientIP, backendID, capPath.path)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionID, targetIP, policy.Proxy)
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 41002, 80, 0x02, []byte("drain"))

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("attached backend must admit the proxy packet: %v", err)
	}
	if got := proxyAccountingQueueLen(fwd, backendID); got != 1 {
		t.Fatalf("expected the admitted packet to be queued, got %d", got)
	}
	if got := fwd.ProxyDrops(); got != 0 {
		t.Fatalf("admitted packet must not count a drop, got %d", got)
	}

	fwd.DetachBackendDevice(backendID)

	if got := proxyAccountingQueueLen(fwd, backendID); got != 0 {
		t.Fatalf("detach must discard the abandoned proxy queue, %d packet(s) left", got)
	}
	if got := fwd.ProxyDrops(); got != 1 {
		t.Fatalf("abandoned proxy packet must be counted as a drop, got %d", got)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("abandoned proxy packet leaked to DIRECT: %d", got)
	}

	// Re-attach a fresh device and start the pump: the stale packet must not
	// be delivered to it.
	newDev := newMockPacketDev()
	fwd.AttachBackendDevice(backendID, newDev)
	fwd.StartPumps(ctx)
	time.Sleep(100 * time.Millisecond)
	if got := len(newDev.getPackets()); got != 0 {
		t.Fatalf("stale packet was delivered to the re-attached device: %d", got)
	}
}

// TestProxyAccounting_ReattachRestoresProxyDelivery covers ordinary recovery:
// once a backend device is attached again, proxy-required traffic is admitted
// and delivered, and the earlier drop is not re-counted.
func TestProxyAccounting_ReattachRestoresProxyDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, _, wanDev, rc := setupForwarderWithPBR(t)
	fwd.Start(ctx)
	fwd.StartPumps(ctx)
	defer func() { _ = fwd.Stop() }()

	const (
		peerKey   = "peer-reattach-proxy"
		sessionID = "sess-reattach-proxy"
		clientIP  = "10.100.0.63"
		backendID = int64(414)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "conn-reattach-proxy", peerKey, clientIP, backendID, capPath.path)

	oldDev := newMockPacketDev()
	fwd.AttachBackendDevice(backendID, oldDev)

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionID, targetIP, policy.Proxy)
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 41003, 80, 0x02, []byte("reattach"))

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("attached backend must admit the proxy packet: %v", err)
	}
	proxyAccountingWaitFor(t, "old device to receive the packet", func() bool {
		return len(oldDev.getPackets()) == 1
	})

	fwd.DetachBackendDevice(backendID)
	if err := fwd.RouteClientToBackend(peerKey, pkt); !errors.Is(err, ErrBackendNotFound) {
		t.Fatalf("detached backend must refuse the proxy packet, got %v", err)
	}
	dropsWhileDetached := fwd.ProxyDrops()

	newDev := newMockPacketDev()
	fwd.AttachBackendDevice(backendID, newDev)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("re-attached backend must admit the proxy packet: %v", err)
	}
	proxyAccountingWaitFor(t, "new device to receive the packet", func() bool {
		return len(newDev.getPackets()) == 1
	})
	if got := fwd.ProxyDrops(); got != dropsWhileDetached {
		t.Fatalf("recovery must not add drops: %d -> %d", dropsWhileDetached, got)
	}
	if got := len(oldDev.getPackets()); got != 1 {
		t.Fatalf("detached device received traffic after detach: %d", got)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("proxy traffic leaked to DIRECT: %d", got)
	}
}

// TestProxyAccounting_AttachedDeviceWriteFailureCountsDrop covers the
// attached-but-failing-device boundary at the asynchronous writer: the packet
// is admitted at enqueue time, the pump's write fails, and the loss is counted
// as a proxy drop instead of being discarded silently.
func TestProxyAccounting_AttachedDeviceWriteFailureCountsDrop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, _, wanDev, rc := setupForwarderWithPBR(t)
	fwd.Start(ctx)
	fwd.StartPumps(ctx)
	defer func() { _ = fwd.Stop() }()

	const (
		peerKey   = "peer-write-fail"
		sessionID = "sess-write-fail"
		clientIP  = "10.100.0.64"
		backendID = int64(415)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "conn-write-fail", peerKey, clientIP, backendID, capPath.path)

	failDev := &failingPacketDev{}
	fwd.AttachBackendDevice(backendID, failDev)

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionID, targetIP, policy.Proxy)
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 41004, 80, 0x02, []byte("write-fail"))

	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("an attached backend admits the packet before the writer runs: %v", err)
	}
	proxyAccountingWaitFor(t, "the failing writer to run", func() bool {
		return failDev.writeCount() == 1
	})
	proxyAccountingWaitFor(t, "the writer failure to be counted", func() bool {
		return fwd.ProxyDrops() == 1
	})
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("writer failure leaked %d packet(s) to DIRECT", got)
	}

	// Recovery: a healthy device on the same backend keeps serving traffic.
	goodDev := newMockPacketDev()
	fwd.AttachBackendDevice(backendID, goodDev)
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("healthy re-attached backend must admit the proxy packet: %v", err)
	}
	proxyAccountingWaitFor(t, "healthy device to receive the packet", func() bool {
		return len(goodDev.getPackets()) == 1
	})
	if got := fwd.ProxyDrops(); got != 1 {
		t.Fatalf("healthy delivery must not add drops, got %d", got)
	}
}

// TestProxyAccounting_RecreatedQueueAfterDetachStillRefuses pins the reason the
// availability state cannot be inferred from queue presence: registering a new
// session for the detached tunnel re-creates its backend queue, and the proxy
// path must still refuse and count instead of parking packets in it.
func TestProxyAccounting_RecreatedQueueAfterDetachStillRefuses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, _, wanDev, rc := setupForwarderWithPBR(t)
	fwd.Start(ctx)
	fwd.StartPumps(ctx)
	defer func() { _ = fwd.Stop() }()

	const backendID = int64(416)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("sess-before", "conn-before", "peer-before", "10.100.0.65", backendID, capPath.path)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())
	fwd.DetachBackendDevice(backendID)

	// A late session registration re-creates backendQueues[backendID].
	fwd.RegisterSessionWithReturnPath("sess-after", "conn-after", "peer-after", "10.100.0.66", backendID, capPath.path)
	if got := proxyAccountingQueueLen(fwd, backendID); got != 0 {
		t.Fatalf("expected a freshly re-created empty queue, got %d", got)
	}

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set("sess-after", targetIP, policy.Proxy)
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr("10.100.0.66"), targetIP, 41005, 80, 0x02, []byte("late-session"))

	err := fwd.RouteClientToBackend("peer-after", pkt)
	if !errors.Is(err, ErrBackendNotFound) {
		t.Fatalf("proxy packet for a detached backend must be refused, got %v", err)
	}
	if got := fwd.ProxyDrops(); got != 1 {
		t.Fatalf("refusal must be counted once, got %d", got)
	}
	if got := proxyAccountingQueueLen(fwd, backendID); got != 0 {
		t.Fatalf("refused packet was queued into the re-created queue: %d", got)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Fatalf("refusal leaked %d packet(s) to DIRECT", got)
	}
}

// TestProxyAccounting_LegacyPathKeepsBufferedPacketsAcrossDetach pins the
// preserved PBR-off behavior: the legacy client path does not consult the
// detached-backend marker, so a packet admitted before detach stays buffered and
// is delivered by the pump of a re-attached device, and no proxy drop is
// counted. This is pre-existing legacy semantics retained deliberately.
func TestProxyAccounting_LegacyPathKeepsBufferedPacketsAcrossDetach(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd := NewForwarder(nil, "10.100.0.0/16", 100) // PBR off by default
	fwd.Start(ctx)
	defer func() { _ = fwd.Stop() }()

	const (
		peerKey   = "peer-legacy-buffer"
		clientIP  = "10.100.0.67"
		backendID = int64(417)
	)
	fwd.RegisterSession("sess-legacy-buffer", "conn-legacy-buffer", peerKey, clientIP, backendID)
	fwd.AttachBackendDevice(backendID, newMockPacketDev())

	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), netip.MustParseAddr("93.184.216.34"), 41006, 80, 0x02, []byte("legacy-buffer"))
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("legacy path must admit the packet: %v", err)
	}

	fwd.DetachBackendDevice(backendID)
	if got := proxyAccountingQueueLen(fwd, backendID); got != 1 {
		t.Fatalf("legacy path must keep its buffered packet across detach, got %d", got)
	}
	if got := fwd.ProxyDrops(); got != 0 {
		t.Fatalf("legacy path must not count proxy drops, got %d", got)
	}

	newDev := newMockPacketDev()
	fwd.AttachBackendDevice(backendID, newDev)
	fwd.StartPumps(ctx)
	proxyAccountingWaitFor(t, "re-attached device to receive the buffered packet", func() bool {
		return len(newDev.getPackets()) == 1
	})
	if got := fwd.ProxyDrops(); got != 0 {
		t.Fatalf("legacy delivery must not count proxy drops, got %d", got)
	}
}
