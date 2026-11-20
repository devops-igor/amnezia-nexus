package forwarder

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Real producer controls for PROXY backend device-write completion (issue #861,
// R15/R16).
//
// Each case drives a packet through RouteClientToBackend into the bounded backend
// queue, runs the real pump against a controlled device, and reads the admitting
// flow's evidence. Nothing here sets a counter by hand: the numbers under test are
// produced by the enqueue and by the device write.

// blockingDevice holds every write until released, so queue admission can be observed
// before completion.
type blockingDevice struct {
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	writes  int
}

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{entered: make(chan struct{}, 1), release: make(chan struct{})}
}

// releaseWrites is idempotent and is registered as cleanup by every fixture that uses
// this device. A t.Fatal before the test releases the writer would otherwise leave the
// pump blocked inside Write, and the pump join in StopPumps would wait forever.
func (d *blockingDevice) releaseWrites() {
	d.once.Do(func() { close(d.release) })
}

func (d *blockingDevice) Read(_ []byte) (int, error) { return 0, nil }

func (d *blockingDevice) Write(p []byte) (int, error) {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-d.release
	d.mu.Lock()
	d.writes++
	d.mu.Unlock()
	return len(p), nil
}

func (d *blockingDevice) Close() error { return nil }

// scriptedDevice returns a fixed (n, err) per write.
type scriptedDevice struct {
	mu  sync.Mutex
	n   int
	err error
	saw int
}

func (d *scriptedDevice) Read(_ []byte) (int, error) { return 0, nil }

func (d *scriptedDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.saw++
	n := d.n
	if n < 0 || n > len(p) {
		n = len(p)
	}
	return n, d.err
}

func (d *scriptedDevice) Close() error { return nil }

// proxyQueueFixture builds a policy-active forwarder whose backend queue is pumped by
// the real pump into dev.
func proxyQueueFixture(t *testing.T, dev PacketDevice) (*Forwarder, *testRouteCache, string, string) {
	t.Helper()
	fwd := NewForwarder(nil, "10.100.0.0/16", 8)
	fwd.SetPBREnabled(true)
	fwd.AttachBackendDevice(31, dev)
	dem := NewDirectEgressManager(DirectEgressConfig{
		HostWANIP: netip.MustParseAddr("203.0.113.1"),
		WANDevice: newMockPacketDev(),
	}, fwd)
	fwd.SetDirectEgress(dem)
	// The manager owns a WAN reader; the test that created it retires it, including
	// when an assertion fails before the case reaches its own teardown.
	t.Cleanup(func() { _ = dem.Close() })
	rc := newTestRouteCache()
	fwd.SetRouteCache(rc)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("sess-backend", "conn-1", "peer-backend", "10.100.0.7", 31, capPath.path)
	fwd.StartPumps(t.Context())
	t.Cleanup(fwd.StopPumps)
	// Cleanups run last-registered-first, so the release MUST be registered after the
	// pump join: otherwise an early t.Fatal leaves the pump blocked inside Write and the
	// join waits forever. The watchdog test below pins this ordering.
	if blocker, ok := dev.(interface{ releaseWrites() }); ok {
		t.Cleanup(blocker.releaseWrites)
	}
	return fwd, rc, "peer-backend", "sess-backend"
}

func proxyPacket(dst string, port uint16) []byte {
	return buildTestIPv4TCPPacket(netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(dst), 44000, port, 0x02, nil)
}

func flowEvidenceFor(t *testing.T, fwd *Forwarder, sessionID, dst string, port uint16) SessionFlow {
	t.Helper()
	list := fwd.DirectEgress().SnapshotSessionFlows(sessionID, 0, time.Now(), 0)
	for _, flow := range list.Flows {
		if flow.DstIP.String() == dst && flow.DstPort == port {
			return flow
		}
	}
	t.Fatalf("no flow for %s:%d in %+v", dst, port, list.Flows)
	return SessionFlow{}
}

// TestBackendWriteCompletionIsSeparateFromAdmission is the primary control: a flow
// whose packet is admitted but whose device write is still blocked reports queue
// admission and NO completion; releasing the writer completes it.
func TestBackendWriteCompletionIsSeparateFromAdmission(t *testing.T) {
	dev := newBlockingDevice()
	fwd, _, peer, sessionID := proxyQueueFixture(t, dev)

	if err := fwd.RouteClientToBackend(peer, proxyPacket("8.8.4.4", 443)); err != nil {
		t.Fatalf("RouteClientToBackend: %v", err)
	}
	select {
	case <-dev.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the pump never reached the device write")
	}

	// Admitted, write in flight: admission is visible and completion is not.
	held := flowEvidenceFor(t, fwd, sessionID, "8.8.4.4", 443)
	if held.ForwardPackets != 1 {
		t.Errorf("admitted packets = %d, want the queue admission", held.ForwardPackets)
	}
	if held.BackendWrites != 0 || held.BackendWriteFailed != 0 {
		t.Errorf("backend write = %d ok / %d failed while blocked, want no completion yet",
			held.BackendWrites, held.BackendWriteFailed)
	}

	dev.releaseWrites()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if flowEvidenceFor(t, fwd, sessionID, "8.8.4.4", 443).BackendWrites == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	done := flowEvidenceFor(t, fwd, sessionID, "8.8.4.4", 443)
	if done.BackendWrites != 1 || done.BackendWriteFailed != 0 || done.BackendWriteFailure != "" {
		t.Errorf("backend write = %d ok / %d failed (%q), want one full write",
			done.BackendWrites, done.BackendWriteFailed, done.BackendWriteFailure)
	}
	if done.ForwardPackets != 1 {
		t.Errorf("admitted packets moved to %d after the write; admission is not retroactive", done.ForwardPackets)
	}
}

// TestBackendWriteFailureAndShortWriteAreDistinct covers a refused write and a cut
// write: different tokens, neither of them a completion.
func TestBackendWriteFailureAndShortWriteAreDistinct(t *testing.T) {
	cases := []struct {
		name  string
		dev   PacketDevice
		token string
	}{
		{"DeviceError", &scriptedDevice{n: -1, err: errors.New("backend write refused")}, FlowBackendWriteFailed},
		{"ShortWrite", &scriptedDevice{n: 10}, FlowBackendWriteShort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fwd, _, peer, sessionID := proxyQueueFixture(t, tc.dev)
			if err := fwd.RouteClientToBackend(peer, proxyPacket("9.9.9.9", 8443)); err != nil {
				t.Fatalf("RouteClientToBackend: %v", err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				// The failure count and its reason are independent atomics, so one
				// snapshot can show the count before the reason is published. Wait for
				// the settled pair the assertions below describe, not for the count
				// alone.
				settled := flowEvidenceFor(t, fwd, sessionID, "9.9.9.9", 8443)
				if settled.BackendWriteFailed == 1 && settled.BackendWriteFailure != "" {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			flow := flowEvidenceFor(t, fwd, sessionID, "9.9.9.9", 8443)
			if flow.BackendWriteFailed != 1 || flow.BackendWriteFailure != tc.token {
				t.Errorf("backend write = %d failed/%q, want 1/%q", flow.BackendWriteFailed, flow.BackendWriteFailure, tc.token)
			}
			if flow.BackendWrites != 0 {
				t.Errorf("completed writes = %d, want 0", flow.BackendWrites)
			}
			if flow.ForwardPackets != 1 {
				t.Errorf("admitted packets = %d, want the admission preserved on failure", flow.ForwardPackets)
			}
		})
	}
}

// blockedWriteDevice blocks its FIRST write until released and then either fails it
// or completes it; later writes complete immediately. It is what makes a write that is
// still in flight across a caller-visible replacement observable.
type blockedWriteDevice struct {
	entered   chan struct{}
	release   chan struct{}
	failFirst bool
	once      sync.Once

	mu    sync.Mutex
	wrote int
}

func newBlockedWriteDevice(failFirst bool) *blockedWriteDevice {
	return &blockedWriteDevice{entered: make(chan struct{}, 1), release: make(chan struct{}), failFirst: failFirst}
}

func (d *blockedWriteDevice) Read(_ []byte) (int, error) { return 0, nil }

func (d *blockedWriteDevice) Write(p []byte) (int, error) {
	select {
	case d.entered <- struct{}{}:
	default:
	}
	<-d.release
	d.mu.Lock()
	d.wrote++
	first := d.wrote == 1
	d.mu.Unlock()
	if first && d.failFirst {
		return 0, errors.New("first write refused")
	}
	return len(p), nil
}

func (d *blockedWriteDevice) Close() error { return nil }

// releaseWrites is idempotent and registered as cleanup at fixture construction, so an
// early failure can never leave the pump blocked inside Write.
func (d *blockedWriteDevice) releaseWrites() {
	d.once.Do(func() { close(d.release) })
}

// TestBackendWriteDelayedOutcomeAcrossReplacement is the real delayed-ownership control:
// the device write that belongs to the admitting flow is still BLOCKED when the session
// is replaced (new session, or a same-session rekey), and only then completes or fails.
// The successor's own work is queued behind it.
//
// The assertion is on the successor: its counters must show exactly its own write and
// none of the retired incarnation's outcome. Resolving the owner at write time instead of
// carrying it from admission would credit the successor and fail here.
func TestBackendWriteDelayedOutcomeAcrossReplacement(t *testing.T) {
	cases := []struct {
		name        string
		failFirst   bool
		replacement string
	}{
		{"DelayedSuccessNewSession", false, "new_session"},
		{"DelayedFailureNewSession", true, "new_session"},
		{"DelayedSuccessRekey", false, "rekey"},
		{"DelayedFailureRekey", true, "rekey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dev := newBlockedWriteDevice(tc.failFirst)
			fwd, _, peer, firstSession := proxyQueueFixture(t, dev)
			const dst, port = "44.44.44.44", uint16(443)

			if err := fwd.RouteClientToBackend(peer, proxyPacket(dst, port)); err != nil {
				t.Fatalf("first dispatch: %v", err)
			}
			select {
			case <-dev.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("the pump never reached the first device write")
			}

			// The write is blocked, so the admitting flow is still visible. Replace the
			// incarnation NOW, while that write is genuinely in flight.
			switch tc.replacement {
			case "new_session":
				fwd.RegisterSessionWithReturnPath("sess-backend-2", "conn-2", peer, "10.100.0.7", 31, newTestCaptureReturnPath().path)
			case "rekey":
				fwd.RegisterSessionWithReturnPath(firstSession, "conn-1", peer, "10.100.0.7", 31, newTestCaptureReturnPath().path)
			}

			// The successor's own packet is admitted behind the blocked write.
			if err := fwd.RouteClientToBackend(peer, proxyPacket(dst, port)); err != nil {
				t.Fatalf("successor dispatch: %v", err)
			}

			// Release the blocked write: the retired incarnation's outcome lands now.
			dev.releaseWrites()

			successorSession := "sess-backend-2"
			if tc.replacement == "rekey" {
				successorSession = firstSession
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				list := fwd.DirectEgress().SnapshotSessionFlows(successorSession, 0, time.Now(), 0)
				if len(list.Flows) == 1 && list.Flows[0].BackendWrites > 0 {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}

			list := fwd.DirectEgress().SnapshotSessionFlows(successorSession, 0, time.Now(), 0)
			if len(list.Flows) != 1 {
				t.Fatalf("successor flows = %d, want exactly its own", len(list.Flows))
			}
			got := list.Flows[0]
			if got.BackendWrites != 1 {
				t.Errorf("successor completions = %d, want exactly its own one", got.BackendWrites)
			}
			if got.BackendWriteFailed != 0 {
				t.Errorf("successor failures = %d (%q), want 0: the retired incarnation's outcome was credited to it",
					got.BackendWriteFailed, got.BackendWriteFailure)
			}
			if got.ForwardPackets != 1 {
				t.Errorf("successor admissions = %d, want only its own packet", got.ForwardPackets)
			}
		})
	}
}

// TestBlockedWriterFixtureCleanupIsBounded proves the fixture's own teardown, not a
// process-wide escape hatch: a test that ends while the device write is still blocked
// must still release it, so the pump join cannot wait forever. The inner subtest
// deliberately never releases; the outer test bounds how long that may take.
func TestBlockedWriterFixtureCleanupIsBounded(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		done <- t.Run("blocked_without_release", func(t *testing.T) {
			dev := newBlockedWriteDevice(false)
			fwd, _, peer, _ := proxyQueueFixture(t, dev)
			if err := fwd.RouteClientToBackend(peer, proxyPacket("77.77.77.77", 443)); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			select {
			case <-dev.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("the pump never reached the device write")
			}
			// No manual release on purpose: the fixture cleanup owns it.
		})
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("the blocked-writer subtest failed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the fixture did not release a blocked writer before the pump join: teardown ordering is broken")
	}
}

// TestBackendWriteAfterDetachAttributesNothing proves drained pending work does not
// invent a write result: detaching the backend drops the queued packet, and no flow
// records a completion or a failure.
func TestBackendWriteAfterDetachAttributesNothing(t *testing.T) {
	dev := &scriptedDevice{n: -1}
	fwd, _, peer, sessionID := proxyQueueFixture(t, dev)

	// Stop the pump first, so the admitted packet stays queued and is then dropped
	// by the detach rather than written.
	fwd.StopPumps()
	if err := fwd.RouteClientToBackend(peer, proxyPacket("8.8.8.8", 53)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	fwd.DetachBackendDevice(31)

	flow := flowEvidenceFor(t, fwd, sessionID, "8.8.8.8", 53)
	if flow.BackendWrites != 0 || flow.BackendWriteFailed != 0 {
		t.Errorf("detached work reported write = %d/%d, want no write observation",
			flow.BackendWrites, flow.BackendWriteFailed)
	}
}
