package forwarder

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// proxyAccountingWaitFor polls cond until it is true or the deadline expires.
func proxyAccountingWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// proxyAccountingQueueLen reads one backend queue's occupancy under the
// routing-table lock, so the observation does not race a concurrent pump or
// attach/detach mutation.
func proxyAccountingQueueLen(f *Forwarder, backendID int64) int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.backendQueues[backendID])
}

// TestProxyAccounting_DetachedBackendRefusesAndCounts is the drop-and-count
// oracle for a proxy-required packet whose assigned backend has gone away.
//
// The packet is routed through the real production lifecycle: a PBR route with
// a proxy-required destination, a backend attached with a real packet device,
// the background egress pump running, and the backend then detached exactly the
// way DisableBackend detaches it. The assertion is that the proxy path refuses
// the packet, counts it as a proxy drop, and does not inflate admitted proxy
// throughput — while legitimate traffic to the attached backend is unaffected
// and never falls back to DIRECT.
func TestProxyAccounting_DetachedBackendRefusesAndCounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fwd, _, wanDev, rc := setupForwarderWithPBR(t)
	fwd.Start(ctx)
	fwd.StartPumps(ctx)
	defer func() { _ = fwd.Stop() }()

	const (
		peerKey   = "peer-proxy-loss"
		sessionID = "sess-proxy-loss"
		clientIP  = "10.100.0.60"
		backendID = int64(411)
	)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath(sessionID, "conn-proxy-loss", peerKey, clientIP, backendID, capPath.path)

	dev := newMockPacketDev()
	fwd.AttachBackendDevice(backendID, dev)

	targetIP := netip.MustParseAddr("93.184.216.34")
	rc.Set(sessionID, targetIP, policy.Proxy)
	pkt := buildTestIPv4TCPPacket(netip.MustParseAddr(clientIP), targetIP, 41001, 80, 0x02, []byte("proxy-loss"))

	// Phase 1: the attached backend carries the proxy-required packet.
	if err := fwd.RouteClientToBackend(peerKey, pkt); err != nil {
		t.Fatalf("attached backend must accept the proxy packet: %v", err)
	}
	proxyAccountingWaitFor(t, "attached backend to receive the packet", func() bool {
		return len(dev.getPackets()) == 1
	})
	if got := fwd.ProxyDrops(); got != 0 {
		t.Fatalf("attached backend must not count a proxy drop, got %d", got)
	}
	admittedAfterAttached := fwd.ProxiedBytes()
	if admittedAfterAttached != int64(len(pkt)) {
		t.Fatalf("attached backend admitted %d proxy bytes, want %d", admittedAfterAttached, len(pkt))
	}

	// Phase 2: the backend goes away (the call DisableBackend makes).
	fwd.DetachBackendDevice(backendID)

	// All phase-2 assertions report rather than abort, so one run documents
	// every accounting fact of the refusal (or of its absence).
	err := fwd.RouteClientToBackend(peerKey, pkt)
	if !errors.Is(err, ErrBackendNotFound) {
		t.Errorf("proxy packet for a detached backend must be refused with ErrBackendNotFound, got %v", err)
	}
	if got := fwd.ProxyDrops(); got != 1 {
		t.Errorf("detached backend must count exactly one proxy drop, got %d", got)
	}
	if got := fwd.ProxiedBytes(); got != admittedAfterAttached {
		t.Errorf("refused proxy packet inflated admitted proxy bytes: %d -> %d", admittedAfterAttached, got)
	}
	if got := proxyAccountingQueueLen(fwd, backendID); got != 0 {
		t.Errorf("refused proxy packet was queued toward the detached backend: queue holds %d", got)
	}
	if got := len(wanDev.getPackets()); got != 0 {
		t.Errorf("proxy refusal leaked %d packet(s) to DIRECT", got)
	}
}
