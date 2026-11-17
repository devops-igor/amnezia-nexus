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
	writes  int
}

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{entered: make(chan struct{}, 1), release: make(chan struct{})}
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
		HostWANIP:    netip.MustParseAddr("203.0.113.1"),
		GatewayDNSIP: netip.MustParseAddr("10.100.0.1"),
		WANDevice:    newMockPacketDev(),
	}, fwd)
	fwd.SetDirectEgress(dem)
	rc := newTestRouteCache()
	fwd.SetRouteCache(rc)
	capPath := newTestCaptureReturnPath()
	fwd.RegisterSessionWithReturnPath("sess-backend", "conn-1", "peer-backend", "10.100.0.7", 31, capPath.path)
	fwd.StartPumps(t.Context())
	t.Cleanup(fwd.StopPumps)
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

	close(dev.release)
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
				if flowEvidenceFor(t, fwd, sessionID, "9.9.9.9", 8443).BackendWriteFailed == 1 {
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

// TestBackendWriteCreditsTheAdmittingIncarnation is the wrong-incarnation control:
// a write outcome belongs to the flow that admitted the packet. A same-peer
// replacement purges the admitting flow, so the late outcome must be credited to
// nobody — never to the successor that now owns the same tuple.
func TestBackendWriteCreditsTheAdmittingIncarnation(t *testing.T) {
	dev := &firstWriteFailsDevice{}
	fwd, _, peer, firstSession := proxyQueueFixture(t, dev)

	if err := fwd.RouteClientToBackend(peer, proxyPacket("1.1.1.1", 80)); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	// Wait for the first (failing) write, then replace the session on the same peer.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && dev.sawWrites() < 1 {
		time.Sleep(2 * time.Millisecond)
	}
	if dev.sawWrites() < 1 {
		t.Fatal("the first write never happened")
	}
	fwd.RegisterSessionWithReturnPath("sess-backend-2", "conn-2", peer, "10.100.0.7", 31, newTestCaptureReturnPath().path)

	// The admitting flow was purged with its peer: its evidence is gone, which is why
	// the outcome cannot be inherited.
	if list := fwd.DirectEgress().SnapshotSessionFlows(firstSession, 0, time.Now(), 0); len(list.Flows) != 0 {
		t.Fatalf("admitting session still holds %d flows after replacement, want 0", len(list.Flows))
	}

	// The successor's own packet gets its own outcome, and only its own.
	if err := fwd.RouteClientToBackend(peer, proxyPacket("1.1.1.1", 80)); err != nil {
		t.Fatalf("successor dispatch: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if flowEvidenceFor(t, fwd, "sess-backend-2", "1.1.1.1", 80).BackendWrites == 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	successor := flowEvidenceFor(t, fwd, "sess-backend-2", "1.1.1.1", 80)
	if successor.BackendWriteFailed != 0 {
		t.Errorf("successor failure count = %d, want 0: the retired incarnation's failure was credited to it",
			successor.BackendWriteFailed)
	}
	if successor.BackendWrites != 1 {
		t.Errorf("successor writes = %d, want exactly its own one", successor.BackendWrites)
	}
	if successor.ForwardPackets != 1 {
		t.Errorf("successor admissions = %d, want only its own packet", successor.ForwardPackets)
	}
}

// firstWriteFailsDevice fails the first write and completes later ones, so a retired
// incarnation's failure can be distinguished from a successor's success.
type firstWriteFailsDevice struct {
	mu    sync.Mutex
	wrote int
}

func (d *firstWriteFailsDevice) Read(_ []byte) (int, error) { return 0, nil }

func (d *firstWriteFailsDevice) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wrote++
	if d.wrote == 1 {
		return 0, errors.New("first write refused")
	}
	return len(p), nil
}

func (d *firstWriteFailsDevice) Close() error { return nil }

func (d *firstWriteFailsDevice) sawWrites() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.wrote
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
