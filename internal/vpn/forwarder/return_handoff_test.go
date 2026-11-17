package forwarder

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Asynchronous PROXY return handoff controls (issue #861, R19).
//
// The reply is matched and queued BEFORE the caller-visible replacement, and the client
// writer is blocked when that replacement happens. The queued packet carries the evidence
// block of the incarnation that admitted it, so the delayed outcome must stay with that
// block and never appear on the successor that now owns the same tuple.

// controllableReturnPath is a real ReturnPath whose write blocks, fails or short-writes on
// demand. It is the client-writer boundary, not a mock of the pump.
type controllableReturnPath struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once

	mu       sync.Mutex
	failNext bool
	shortBy  int
	writes   int
}

func newControllableReturnPath(t *testing.T) *controllableReturnPath {
	t.Helper()
	c := &controllableReturnPath{entered: make(chan struct{}, 4), release: make(chan struct{})}
	t.Cleanup(c.releaseWriter)
	return c
}

func (c *controllableReturnPath) releaseWriter() { c.once.Do(func() { close(c.release) }) }

func (c *controllableReturnPath) failNextWrite() { c.mu.Lock(); c.failNext = true; c.mu.Unlock() }
func (c *controllableReturnPath) shortWrite(by int) {
	c.mu.Lock()
	c.shortBy = by
	c.mu.Unlock()
}

func (c *controllableReturnPath) path() *ReturnPath {
	return NewReturnPath(func(_, _ string, packet []byte) (int, error) {
		select {
		case c.entered <- struct{}{}:
		default:
		}
		<-c.release
		c.mu.Lock()
		defer c.mu.Unlock()
		c.writes++
		if c.failNext {
			c.failNext = false
			return 0, errors.New("client writer refused")
		}
		if c.shortBy > 0 {
			return len(packet) - c.shortBy, nil
		}
		return len(packet), nil
	})
}

func (c *controllableReturnPath) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func returnWait(t *testing.T, fwd *Forwarder, sessionID, remote string, port uint16, done func(SessionFlow) bool) SessionFlow {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		flow := returnEvidenceOf(t, fwd, sessionID, remote, port)
		if done(flow) {
			return flow
		}
		time.Sleep(2 * time.Millisecond)
	}
	return returnEvidenceOf(t, fwd, sessionID, remote, port)
}

// assertReturnConserves pins the counting contract of the observed label: every matched
// reply was either admitted or dropped, and every admitted reply was either delivered or
// failed once the writer has run.
func assertReturnConserves(t *testing.T, flow SessionFlow, writerRan bool) {
	t.Helper()
	if flow.ReturnMatched != flow.ReturnAdmitted+flow.ReturnDropped {
		t.Errorf("matched %d != admitted %d + dropped %d", flow.ReturnMatched, flow.ReturnAdmitted, flow.ReturnDropped)
	}
	if writerRan && flow.ReturnAdmitted != flow.ReturnDelivered+flow.ReturnFailed {
		t.Errorf("admitted %d != delivered %d + failed %d", flow.ReturnAdmitted, flow.ReturnDelivered, flow.ReturnFailed)
	}
}

// TestProxyReturnQueuedBeforeReplacementIsNotCreditedToTheSuccessor is the same-tuple
// control at the ordering that is actually reachable.
//
// A replacement cannot happen while a client write is in flight: session registration
// waits on the retiring route's in-flight work, which is the production contract. What IS
// reachable is the reply matched and queued before the replacement and dequeued after it.
// That reply must not be handed to the successor's writer, and the successor must not
// inherit its arrival or handoff.
func TestProxyReturnQueuedBeforeReplacementIsNotCreditedToTheSuccessor(t *testing.T) {
	writer := newControllableReturnPath(t)
	writer.releaseWriter()
	fwd, _, peer, sessionID := proxyReturnFixtureWithPath(t, writer.path())
	fwd.StopPumps() // the reply stays queued: no pump dequeues it

	const remote, port, clientPort = "9.9.9.9", uint16(443), uint16(45000)
	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
		clientPort, port, 0x02, nil)); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
	if err := fwd.RouteBackendToClient(31, proxyReply(remote, port, clientPort, []byte("late")), "10.100.0.7"); err != nil {
		t.Fatalf("return refused: %v", err)
	}
	queued := returnEvidenceOf(t, fwd, sessionID, remote, port)
	if queued.ReturnMatched != 1 || queued.ReturnAdmitted != 1 {
		t.Fatalf("pre-replacement state = matched %d / admitted %d, want 1/1", queued.ReturnMatched, queued.ReturnAdmitted)
	}
	assertReturnConserves(t, queued, false)

	// Real replacement on the SAME tuple, with the reply still queued.
	fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", peer, "10.100.0.7", 31, newTestCaptureReturnPath().path)
	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
		clientPort, port, 0x02, nil)); err != nil {
		t.Fatalf("successor dispatch: %v", err)
	}

	// Let the successor's pumps run: the queued pre-replacement reply must not be handed
	// to any writer on the successor's behalf.
	fwd.StartPumps(t.Context())
	time.Sleep(100 * time.Millisecond)

	successor := returnEvidenceOf(t, fwd, sessionID, remote, port)
	if successor.ReturnMatched != 0 || successor.ReturnAdmitted != 0 {
		t.Errorf("successor inherited arrival: matched %d / admitted %d",
			successor.ReturnMatched, successor.ReturnAdmitted)
	}
	if successor.ReturnDelivered != 0 || successor.ReturnFailed != 0 {
		t.Errorf("successor inherited handoff: delivered %d / failed %d",
			successor.ReturnDelivered, successor.ReturnFailed)
	}
	if got := writer.writeCount(); got != 0 {
		t.Errorf("the retired route's queued reply reached the client writer %d times", got)
	}
}

// TestProxyReturnWriterBoundaryOutcomes covers the outcomes that reach the writer for a
// live route: a completed write, a writer error and a short write.
func TestProxyReturnWriterBoundaryOutcomes(t *testing.T) {
	cases := []struct {
		name       string
		configure  func(*controllableReturnPath)
		delivered  uint64
		failed     uint64
		token      string
		writerRuns int
	}{
		{"Completed", func(*controllableReturnPath) {}, 1, 0, "", 1},
		{"WriterError", func(c *controllableReturnPath) { c.failNextWrite() }, 0, 1, FlowReturnWriteFailed, 1},
		{"ShortWrite", func(c *controllableReturnPath) { c.shortWrite(4) }, 0, 1, FlowReturnShortWrite, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writer := newControllableReturnPath(t)
			writer.releaseWriter()
			tc.configure(writer)
			fwd, _, peer, sessionID := proxyReturnFixtureWithPath(t, writer.path())

			const remote, port, clientPort = "4.4.4.4", uint16(8443), uint16(45001)
			if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
				netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
				clientPort, port, 0x02, nil)); err != nil {
				t.Fatalf("client dispatch: %v", err)
			}
			if err := fwd.RouteBackendToClient(31, proxyReply(remote, port, clientPort, []byte("payload")), "10.100.0.7"); err != nil {
				t.Fatalf("return refused: %v", err)
			}

			flow := returnWait(t, fwd, sessionID, remote, port, func(f SessionFlow) bool {
				return f.ReturnDelivered+f.ReturnFailed > 0
			})
			if flow.ReturnDelivered != tc.delivered || flow.ReturnFailed != tc.failed {
				t.Errorf("delivered/failed = %d/%d, want %d/%d", flow.ReturnDelivered, flow.ReturnFailed, tc.delivered, tc.failed)
			}
			if flow.ReturnFailure != tc.token {
				t.Errorf("failure token = %q, want %q", flow.ReturnFailure, tc.token)
			}
			assertReturnConserves(t, flow, true)
			if got := writer.writeCount(); got != tc.writerRuns {
				t.Errorf("client writer ran %d times, want %d", got, tc.writerRuns)
			}
		})
	}
}

// proxyReturnFixtureWithPath is proxyReturnFixture with a caller-supplied return path, so
// the client-writer boundary itself is controllable.
func proxyReturnFixtureWithPath(t *testing.T, path *ReturnPath) (*Forwarder, *testCaptureReturnPath, string, string) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetPBREnabled(true)
	fwd.SetDirectEgress(NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:    netip.MustParseAddr("203.0.113.1"),
		GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
		WANDevice:    newMockPacketDev(),
	}, fwd))
	fwd.SetRouteCache(newTestRouteCache())
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("sess-return", "conn-1", "peer-return", "10.100.0.7", 31, path)
	fwd.StartPumps(t.Context())
	t.Cleanup(fwd.StopPumps)
	return fwd, capPath, "peer-return", "sess-return"
}

// TestProxyReturnRefusalsBeforeTheQueueHaveTokens covers the size and rate refusals through
// the real return path: arrival is recorded, the reply is dropped, and the counts conserve.
func TestProxyReturnRefusalsBeforeTheQueueHaveTokens(t *testing.T) {
	t.Run("RateLimited", func(t *testing.T) {
		// A one-bit-per-second downstream bucket, so the first reply is over budget and the
		// refusal is the real token bucket's, not a simulated one.
		fwd, peer, sessionID := proxyReturnRateLimitedFixture(t, 1)
		fwd.StopPumps()
		const remote, port, clientPort = "3.3.3.3", uint16(443), uint16(45002)

		if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
			netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
			clientPort, port, 0x02, nil)); err != nil {
			t.Fatalf("client dispatch: %v", err)
		}
		err := fwd.RouteBackendToClient(31, proxyReply(remote, port, clientPort, []byte("over budget")), "10.100.0.7")
		if !errors.Is(err, ErrRateLimitExceeded) {
			t.Fatalf("return = %v, want ErrRateLimitExceeded", err)
		}
		flow := returnEvidenceOf(t, fwd, sessionID, remote, port)
		if flow.ReturnMatched != 1 || flow.ReturnAdmitted != 0 || flow.ReturnDropped != 1 {
			t.Errorf("rate refusal = matched %d / admitted %d / dropped %d, want 1/0/1",
				flow.ReturnMatched, flow.ReturnAdmitted, flow.ReturnDropped)
		}
		if flow.ReturnFailure != FlowReturnRateLimited {
			t.Errorf("failure token = %q, want %q", flow.ReturnFailure, FlowReturnRateLimited)
		}
		assertReturnConserves(t, flow, false)
	})

	t.Run("Oversized", func(t *testing.T) {
		fwd, _, peer, sessionID := proxyReturnFixture(t, 8)
		fwd.StopPumps()
		const remote, port, clientPort = "3.3.3.4", uint16(443), uint16(45003)

		if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
			netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
			clientPort, port, 0x02, nil)); err != nil {
			t.Fatalf("client dispatch: %v", err)
		}
		big := proxyReply(remote, port, clientPort, make([]byte, MaxClientQueuePacketBytes+64))
		if err := fwd.RouteBackendToClient(31, big, "10.100.0.7"); !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("oversized reply = %v, want ErrPacketTooLarge", err)
		}
		flow := returnEvidenceOf(t, fwd, sessionID, remote, port)
		if flow.ReturnMatched != 1 || flow.ReturnAdmitted != 0 || flow.ReturnDropped != 1 {
			t.Errorf("oversize refusal = matched %d / admitted %d / dropped %d, want 1/0/1",
				flow.ReturnMatched, flow.ReturnAdmitted, flow.ReturnDropped)
		}
		if flow.ReturnFailure != FlowReturnOversized {
			t.Errorf("failure token = %q, want %q", flow.ReturnFailure, FlowReturnOversized)
		}
		assertReturnConserves(t, flow, false)
	})
}

// proxyReturnRateLimitedFixture registers the route with a downstream bit rate, so the
// return path's real token bucket refuses traffic over it.
func proxyReturnRateLimitedFixture(t *testing.T, limitDownBps int64) (*Forwarder, string, string) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetPBREnabled(true)
	fwd.SetDirectEgress(NewDirectEgressManager(DirectEgressConfig{
		HostWANIP:    netip.MustParseAddr("203.0.113.1"),
		GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
		WANDevice:    newMockPacketDev(),
	}, fwd))
	fwd.SetRouteCache(newTestRouteCache())
	fwd.BeginRegisterSessionWithLimit("sess-rate", "conn-1", "peer-rate", "10.100.0.7", 31, limitDownBps, 0).Wait()
	return fwd, "peer-rate", "sess-rate"
}
