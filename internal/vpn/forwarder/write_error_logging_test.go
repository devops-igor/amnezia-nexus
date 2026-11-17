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

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestPumpClientQueueLogsWriteErrors pins issue #43 visibility requirement:
// a failed dev.Write on the return leg (client queue -> client device) must
// be LOGGED (throttled to ~1 line/second like the queue-full drop counters),
// never silently discarded. Before this test a "no transport keys for peer"
// error on the return path vanished, leaving missing-reply incidents
// undiagnosable.
func TestPumpClientQueueLogsWriteErrors(t *testing.T) {
	f := NewForwarder(nil, "10.100.0.0/16", 8)
	defer f.StopPumps()

	dev := &errDevice{err: errors.New("no transport keys for peer")}
	path := NewReturnPath(func(_, _ string, p []byte) (int, error) { return dev.Write(p) })
	f.StartPumps(t.Context())
	f.RegisterSessionWithReturnPath("sess-1", "conn-1", "peer-a", "10.100.0.3", 1, path)

	// Capture the standard logger for the duration of the burst.
	var buf syncBuffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	pkt := ipv4Packet([4]byte{10, 100, 0, 3})
	// The throttle's unit is a wall-clock second (production stores
	// writeErrLogUntil = now+1s after each emitted line), so every bound below is
	// derived from the burst's measured duration rather than from a fixed total
	// that would silently assume a fast, unloaded runner.
	burstStart := time.Now()
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

	// Throttle: a tight burst must produce a bounded number of lines (~1/sec),
	// not one per packet. The bound follows the measured burst duration because
	// that is the throttle's own unit: one line per distinct wall-clock second.
	// A burst that a loaded or race-instrumented runner stretches across more
	// seconds legitimately emits one more line per second it touched, and a fixed
	// total would fail such a run while the throttle was working correctly.
	for i := 0; i < 300 && dev.writeCount() < n+60; i++ {
		_ = f.RouteBackendToClient(1, pkt, "10.100.0.3")
		time.Sleep(2 * time.Millisecond)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && dev.writeCount() < n+60 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)

	elapsed := time.Since(burstStart)
	got := strings.Count(buf.String(), "return-path device write error")
	// A burst spanning E seconds can touch at most floor(E)+2 distinct one-second
	// buckets: the bucket it started in, one per whole second thereafter, and the
	// bucket it ended in when the end falls just past a boundary.
	allowed := int(elapsed.Seconds()) + 2
	t.Logf("write-error throttle: %d line(s) for %d attempted writes in %.2fs (one line per second allows at most %d)",
		got, n+60, elapsed.Seconds(), allowed)
	if got > allowed {
		t.Fatalf("write-error logging not throttled: %d lines for %d packets in %.2fs; one line per second allows at most %d",
			got, n+60, elapsed.Seconds(), allowed)
	}
}
