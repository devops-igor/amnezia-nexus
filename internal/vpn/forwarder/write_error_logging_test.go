package forwarder

import (
	"bytes"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// errDevice is a PacketDevice whose Write always fails. It models the
// production failure mode seen on the issue #43 return leg: the backend
// device rejects frames with e.g. "no transport keys for peer" while the
// route stays registered and the forwarder keeps enqueueing packets.
type errDevice struct {
	mu     sync.Mutex
	err    error
	writes int
}

func (e *errDevice) Read(p []byte) (int, error) { return 0, nil }
func (e *errDevice) Close() error               { return nil }
func (e *errDevice) Write(p []byte) (int, error) {
	e.mu.Lock()
	e.writes++
	e.mu.Unlock()
	return 0, e.err
}
func (e *errDevice) writeCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.writes
}

// TestPumpClientQueueLogsWriteErrors pins issue #43 visibility requirement:
// a failed dev.Write on the return leg (client queue -> client device) must
// be LOGGED (throttled to ~1 line/second like the queue-full drop counters),
// never silently discarded. Before this test a "no transport keys for peer"
// error on the return path vanished, leaving missing-reply incidents
// undiagnosable.
func TestPumpClientQueueLogsWriteErrors(t *testing.T) {
	f := NewForwarder(nil, 8)
	defer f.StopPumps()

	dev := &errDevice{err: errors.New("no transport keys for peer")}
	f.AttachPeerDevice("peer-a", dev)
	f.StartPumps(t.Context())
	f.RegisterSession("sess-1", "conn-1", "peer-a", "10.100.0.3", 1)

	// Capture the standard logger for the duration of the burst.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	pkt := ipv4Packet([4]byte{10, 100, 0, 3})
	const n = 5
	// The 8-slot client queue plus a possibly-lagging pump means ErrQueueFull
	// drops are expected and BY DESIGN under a tight burst; keep sending until
	// the pump has attempted the expected number of device writes.
	attempts := 0
	for attempts = 0; attempts < 200 && dev.writeCount() < n; attempts++ {
		_ = f.RouteBackendToClient(1, pkt, "10.100.0.3")
		time.Sleep(2 * time.Millisecond)
	}

	// Wait for the pump to attempt every write, then give the throttled
	// logger a moment to flush.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.writeCount() < n {
		time.Sleep(10 * time.Millisecond)
	}
	if dev.writeCount() < n {
		t.Fatalf("pump attempted only %d/%d writes", dev.writeCount(), n)
	}
	time.Sleep(150 * time.Millisecond)

	logs := buf.String()
	if !strings.Contains(logs, "return-path device write error") {
		t.Fatalf("expected a throttled return-path write-error log line, got none; captured logs: %q", logs)
	}
	if !strings.Contains(logs, "no transport keys for peer") {
		t.Fatalf("write-error log must include the underlying error, got: %q", logs)
	}
	if !strings.Contains(logs, "peer-a") {
		t.Fatalf("write-error log must identify the peer, got: %q", logs)
	}

	// Throttle: a tight burst must produce a bounded number of lines
	// (~1/sec), not one per packet. Keep feeding until 60 more writes were
	// attempted (queue-full drops are by-design under bursts); allow up to
	// 3 lines for a pathologically stalled runner.
	for i := 0; i < 300 && dev.writeCount() < n+60; i++ {
		_ = f.RouteBackendToClient(1, pkt, "10.100.0.3")
		time.Sleep(2 * time.Millisecond)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.writeCount() < n+60 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := strings.Count(buf.String(), "return-path device write error"); got > 3 {
		t.Fatalf("write-error logging not throttled: %d lines for %d packets", got, n+60)
	}
}
