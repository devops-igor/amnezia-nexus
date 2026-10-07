package forwarder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/virtualtun"
)

func returnPacket(destination string) []byte {
	p := make([]byte, 28)
	p[0] = 0x45
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 28)
	ip := netip.MustParseAddr(destination).As4()
	copy(p[16:20], ip[:])
	return p
}

func TestReturnPathRoutesOnlyMatchingBackendAndDestination(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	received := make(chan string, 4)
	path := NewReturnPath(func(peer, ip string, p []byte) (int, error) { received <- peer + ":" + ip; return len(p), nil })
	for _, r := range []struct {
		key, ip string
		backend int64
	}{{"a", "10.100.0.2", 11}, {"b", "10.100.0.3", 12}, {"c", "10.100.0.4", 13}} {
		if _, err := f.TryRegisterSessionWithReturnPath(r.key, r.key, r.key, r.ip, r.backend, 0, 0, path); err != nil {
			t.Fatal(err)
		}
	}
	f.StartPumps(t.Context())
	t.Cleanup(f.StopPumps)
	for _, bad := range []struct {
		be int64
		p  []byte
		ip string
	}{{12, returnPacket("10.100.0.2"), "10.100.0.2"}, {11, returnPacket("10.100.0.3"), "10.100.0.2"}, {11, []byte{1}, "10.100.0.2"}} {
		if err := f.RouteBackendToClient(bad.be, bad.p, bad.ip); !errors.Is(err, ErrReturnRouteMismatch) {
			t.Fatalf("invalid return accepted: %v", err)
		}
	}
	if err := f.RouteBackendToClient(11, returnPacket("10.100.0.99"), "10.100.0.99"); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatal(err)
	}
	for _, r := range []struct {
		be         int64
		ip, expect string
	}{{11, "10.100.0.2", "a:10.100.0.2"}, {12, "10.100.0.3", "b:10.100.0.3"}, {13, "10.100.0.4", "c:10.100.0.4"}} {
		if err := f.RouteBackendToClient(r.be, returnPacket(r.ip), r.ip); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-received:
			if got != r.expect {
				t.Fatalf("wrong route %s", got)
			}
		case <-time.After(time.Second):
			t.Fatal("no upstream return")
		}
	}
	_, tx, _ := f.GetStats()
	if tx != 3*28 {
		t.Fatalf("invalid returns were accounted: tx=%d", tx)
	}
}

func TestReturnPathBindingRetiresOldWriterAndPreservesReuse(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 4)
	started := make(chan struct{})
	release := make(chan struct{})
	old := NewReturnPath(func(_, _ string, p []byte) (int, error) { close(started); <-release; return len(p), nil })
	if _, err := f.TryRegisterSessionWithReturnPath("s", "c", "a", "10.100.0.2", 1, 10, 10, old); err != nil {
		t.Fatal(err)
	}
	// Disable throttling for this short test; bucket identity is still checked.
	f.routesByPeer["a"].limitDownBps = 0
	f.routesByPeer["a"].tbDown = nil
	f.StartPumps(t.Context())
	t.Cleanup(f.StopPumps)
	if err := f.RouteBackendToClient(1, returnPacket("10.100.0.2"), "10.100.0.2"); err != nil {
		t.Fatal(err)
	}
	<-started
	delivered := make(chan struct{}, 1)
	next := NewReturnPath(func(_, _ string, p []byte) (int, error) { delivered <- struct{}{}; return len(p), nil })
	retirement, err := f.BindSessionReturnPath("s", "c", "a", "10.100.0.2", 1, next)
	if err != nil {
		t.Fatal(err)
	}
	route := f.routesByPeer["a"]
	if _, err := f.BindSessionReturnPath("s", "c", "a", "10.100.0.2", 1, next); err != nil {
		t.Fatal(err)
	}
	if f.routesByPeer["a"] != route {
		t.Fatal("healthy reuse replaced route")
	}
	joined := make(chan struct{})
	go func() { retirement.Wait(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("retirement did not join old write")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("retirement stuck")
	}
	if err := f.RouteBackendToClient(1, returnPacket("10.100.0.2"), "10.100.0.2"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivered:
	case <-time.After(time.Second):
		t.Fatal("new writer missing")
	}
	if _, err := f.BindSessionReturnPath("stale", "c", "a", "10.100.0.2", 1, old); !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatal("stale bind accepted")
	}
}

func TestReturnPathClosedAndTUNPressureIsBounded(t *testing.T) {
	vt, err := virtualtun.New(virtualtun.Config{Name: "return-test", MTU: 1280, InboundCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vt.Close() })
	path := NewReturnPath(func(_, _ string, p []byte) (int, error) {
		if err := vt.InjectInbound(p); err != nil {
			return 0, err
		}
		return len(p), nil
	})
	writer := routeWriter{path: path, peerKey: "a", assignedIP: "10.100.0.2"}
	packet := returnPacket("10.100.0.2")
	if _, err := writer.Write(packet); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(packet); !errors.Is(err, virtualtun.ErrQueueFull) {
		t.Fatalf("queue pressure: %v", err)
	}
	if vt.Stats().DropsQueueFull != 1 {
		t.Fatalf("missing TUN drop: %+v", vt.Stats())
	}
	f := NewForwarder(nil, "10.100.0.0/16", 2)
	if _, err := f.TryRegisterSessionWithReturnPath("s", "c", "a", "10.100.0.2", 1, 0, 0, path); err != nil {
		t.Fatal(err)
	}
	path.Close()
	if _, err := writer.Write(packet); !errors.Is(err, ErrReturnPathClosed) {
		t.Fatalf("closed writer: %v", err)
	}
	if _, err := f.TryRegisterSessionWithReturnPath("s2", "c2", "a2", "10.100.0.3", 1, 0, 0, path); !errors.Is(err, ErrReturnPathClosed) {
		t.Fatalf("expected ErrReturnPathClosed for new registration on closed path, got %v", err)
	}
	f.StartPumps(t.Context())
	t.Cleanup(f.StopPumps)
	if err := f.RouteBackendToClient(1, packet, "10.100.0.2"); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for f.DeviceWriteSnapshot().Errors == 0 {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("closed write not observed")
		}
	}
}

func TestReturnPathCloseJoinsConcurrentWrites(t *testing.T) {
	var writes atomic.Uint64
	path := NewReturnPath(func(_, _ string, p []byte) (int, error) { writes.Add(1); return len(p), nil })
	done := make(chan struct{})
	go func() {
		defer close(done)
		w := routeWriter{path: path, assignedIP: "10.100.0.2"}
		for range 1000 {
			_, _ = w.Write(returnPacket("10.100.0.2"))
		}
	}()
	path.Close()
	atClose := writes.Load()
	<-done
	if writes.Load() != atClose {
		t.Fatal("callback entered after Close")
	}
}

func TestReturnRetirementClassification(t *testing.T) {
	f := NewForwarder(nil, "", 10)
	f.RegisterSession("s", "c", "peer", "192.0.2.1", 1)
	if err := f.SetPeerRateLimit("peer", 1000, 0); err != nil {
		t.Fatal(err)
	}
	var classified atomic.Uint64
	var lastReason ReturnRejectReason
	f.SetReturnRejectClassifier(func(r ReturnRejectReason) {
		lastReason = r
		classified.Add(1)
	})
	bucket := f.routesByPeer["peer"].tbDown
	bucket.mu.Lock()
	result := make(chan error, 1)
	go func() { result <- f.RouteBackendToClient(1, returnPacket("192.0.2.1"), "192.0.2.1") }()
	stack := make([]byte, 65536)
	waiting := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(stack, true)
		if strings.Contains(string(stack[:n]), "forwarder.(*TokenBucket).Allow") {
			waiting = true
			break
		}
		runtime.Gosched()
	}
	if !waiting {
		bucket.mu.Unlock()
		t.Fatal("writer did not reach the controlled rate-limit boundary")
	}
	f.UnregisterSession("peer")
	bucket.mu.Unlock()
	if err := <-result; !errors.Is(err, ErrSessionNotRegistered) {
		t.Fatalf("want route-retirement rejection, got %v", err)
	}
	q, unrouted, total := f.DropStats()
	t.Logf("retirement rejection: queue_full=%d no_route=%d internal_total=%d engine_classifications=%d", q, unrouted, total, classified.Load())
	if total != 1 || unrouted != 1 {
		t.Fatalf("expected 1 unrouted drop, got total=%d unrouted=%d", total, unrouted)
	}
	if classified.Load() != 1 {
		t.Fatalf("expected 1 classified rejection, got %d", classified.Load())
	}
	if lastReason != ReturnRejectedUnrouted {
		t.Fatalf("expected ReturnRejectedUnrouted (%v), got %v", ReturnRejectedUnrouted, lastReason)
	}
}
