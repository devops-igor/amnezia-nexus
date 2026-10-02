package virtualtun

// Coverage for the test-only read-suspension gate added for issue #424 round 3,
// finding 1.
//
// The gate exists because the upstream engine starts its TUN reader goroutine
// inside device.NewDevice and the upstream Down() cannot stop it (downLocked
// only closes the bind and stops the peers). Without a seam, a test that
// injects into the inbound queue and then asserts its occupancy, its peak, or
// that a later Close drains it races that reader: it passes when the
// assertions run first and fails when the reader runs first, which is exactly
// what a loaded, coverage-instrumented CI runner produces.
//
// These tests pin the four properties the diagnostics tests depend on:
// suspension really holds the queue, it accounts for nothing, Close still
// unblocks a suspended Read, and resume restores delivery.

import (
	"errors"
	"testing"
	"time"
)

// readBuf allocates a one-packet read destination the way the upstream reader
// does.
func readBuf() (bufs [][]byte, sizes []int) {
	return [][]byte{make([]byte, 64)}, make([]int, 1)
}

// TestSuspendReadsForTestHoldsInboundQueue is the core property: while reads
// are suspended, the inbound queue keeps its packets and its counters.
func TestSuspendReadsForTestHoldsInboundQueue(t *testing.T) {
	vt := mustNew(t, Config{Name: "suspend", MTU: 1280, InboundCapacity: 2})

	vt.SuspendReadsForTest()

	if err := vt.InjectInbound([]byte("one")); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}

	// A reader goroutine, exactly as the upstream engine runs one, must not
	// consume the packet while reads are suspended.
	bufs, sizes := readBuf()
	readDone := make(chan error, 1)
	go func() {
		_, err := vt.Read(bufs, sizes, 0)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		t.Fatalf("a suspended Read returned early (err=%v); it must block without dequeuing", err)
	case <-time.After(150 * time.Millisecond):
	}

	s := vt.Stats()
	if s.InboundDepth != 1 {
		t.Errorf("InboundDepth: expected the packet to stay queued at 1, got %d", s.InboundDepth)
	}
	if s.InboundPeak != 1 {
		t.Errorf("InboundPeak: expected 1, got %d", s.InboundPeak)
	}
	if s.InboundDrops != 0 || s.DropsTotal != 0 {
		t.Errorf("suspension must not account any loss: inbound=%d total=%d",
			s.InboundDrops, s.DropsTotal)
	}

	// Resume releases the blocked Read and the packet is delivered intact.
	vt.ResumeReadsForTest()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("resumed Read returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ResumeReadsForTest did not release the blocked Read")
	}
	if sizes[0] != len("one") {
		t.Errorf("delivered size: expected %d, got %d", len("one"), sizes[0])
	}
	if got := string(bufs[0][:sizes[0]]); got != "one" {
		t.Errorf("delivered payload: expected %q, got %q", "one", got)
	}
	if s := vt.Stats(); s.InboundDepth != 0 {
		t.Errorf("InboundDepth after delivery: expected 0, got %d", s.InboundDepth)
	}
}

// TestSuspendReadsForTestCloseStillUnblocks pins that suspension cannot wedge
// shutdown: a Read blocked on the gate must return once Close fires, and Close
// must still drain and account the queued packets as shutdown drops.
func TestSuspendReadsForTestCloseStillUnblocks(t *testing.T) {
	vt, err := New(Config{Name: "suspend-close", MTU: 1280, InboundCapacity: 2})
	if err != nil {
		t.Fatal(err)
	}
	vt.SuspendReadsForTest()
	if err := vt.InjectInbound([]byte("queued")); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}

	bufs, sizes := readBuf()
	readDone := make(chan error, 1)
	go func() {
		_, err := vt.Read(bufs, sizes, 0)
		readDone <- err
	}()
	time.Sleep(50 * time.Millisecond)

	if err := vt.Close(); err != nil {
		t.Fatalf("Close with a suspended Read in flight: %v", err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("a suspended Read released by Close must report ErrClosed, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not release the suspended Read; shutdown would hang")
	}

	s := vt.Stats()
	if s.InboundDrops != 1 {
		t.Errorf("Close must still account the queued packet as a shutdown drop, got %d", s.InboundDrops)
	}
	if s.DropsShutdown != 1 {
		t.Errorf("DropsShutdown: expected 1, got %d", s.DropsShutdown)
	}
}

// TestSuspendReadsForTestIsIdempotentAndReversible pins that repeated
// suspend/resume cycles neither deadlock nor leak a gate, and that delivery
// works again after each cycle.
func TestSuspendReadsForTestIsIdempotentAndReversible(t *testing.T) {
	vt := mustNew(t, Config{Name: "suspend-cycle", MTU: 1280, InboundCapacity: 4})

	for i := 0; i < 3; i++ {
		vt.SuspendReadsForTest()
		vt.SuspendReadsForTest() // repeated suspend must be safe
		payload := []byte{byte(i)}
		if err := vt.InjectInbound(payload); err != nil {
			t.Fatalf("cycle %d InjectInbound: %v", i, err)
		}
		if s := vt.Stats(); s.InboundDepth != 1 {
			t.Fatalf("cycle %d: expected the packet to stay queued, got depth %d", i, s.InboundDepth)
		}
		vt.ResumeReadsForTest()
		vt.ResumeReadsForTest() // repeated resume must be safe

		bufs, sizes := readBuf()
		delivered := make(chan error, 1)
		go func() {
			_, err := vt.Read(bufs, sizes, 0)
			delivered <- err
		}()
		select {
		case err := <-delivered:
			if err != nil {
				t.Fatalf("cycle %d: resumed Read returned %v", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("cycle %d: resume did not release the Read", i)
		}
		if sizes[0] != 1 || bufs[0][0] != payload[0] {
			t.Fatalf("cycle %d: delivered the wrong packet: sizes=%d buf=%v", i, sizes[0], bufs[0][:1])
		}
	}
}

// TestNewSuspendedForTestArmsBeforeAnyReader pins the property the
// diagnostics tests actually depend on: a device built by
// NewSuspendedForTest reports the gate armed, so a reader goroutine started
// afterwards blocks on its FIRST Read and can never drain the queue.
//
// This is the non-vacuity proof for the fixture. Suspending a device AFTER a
// reader is already parked inside Read does not reach it, which is precisely
// why arming at construction time is required.
func TestNewSuspendedForTestArmsBeforeAnyReader(t *testing.T) {
	cfg := Config{Name: "suspend-at-birth", MTU: 1280, InboundCapacity: 2}
	vt, err := NewSuspendedForTest(cfg)
	if err != nil {
		t.Fatalf("NewSuspendedForTest: %v", err)
	}
	if !vt.ReadsSuspendedForTest() {
		t.Fatal("NewSuspendedForTest returned a device whose gate is NOT armed")
	}

	// A reader goroutine started after construction, exactly as the upstream
	// engine starts one, must block without dequeuing.
	if err := vt.InjectInbound([]byte("held")); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	bufs, sizes := readBuf()
	readDone := make(chan error, 1)
	go func() {
		_, err := vt.Read(bufs, sizes, 0)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		t.Fatalf("the first Read after construction returned early (err=%v); "+
			"the queue is not deterministic", err)
	case <-time.After(150 * time.Millisecond):
	}
	if s := vt.Stats(); s.InboundDepth != 1 || s.InboundPeak != 1 {
		t.Errorf("depth/peak = %d/%d, want 1/1: the reader drained the queue",
			s.InboundDepth, s.InboundPeak)
	}

	// Read is genuinely waiting on the gate, not merely slow: resuming it
	// releases the very packet injected above.
	vt.ResumeReadsForTest()
	if vt.ReadsSuspendedForTest() {
		t.Error("ReadsSuspendedForTest still reports armed after ResumeReadsForTest")
	}
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("resumed Read returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ResumeReadsForTest did not release the Read blocked at birth")
	}
}

// TestNewDoesNotSuspendReads pins the production invariant for the
// constructor itself: New, the only constructor a production path uses, must
// never arm the gate.
func TestNewDoesNotSuspendReads(t *testing.T) {
	vt := mustNew(t, Config{Name: "new-not-suspended", MTU: 1280, InboundCapacity: 2})
	if vt.ReadsSuspendedForTest() {
		t.Fatal("New armed the test-only read gate; production reads would stall")
	}
}

// TestReadsAreNotSuspendedByDefault pins the production invariant: a device
// nobody suspended delivers immediately, so the gate can never silently
// disable the reader for real traffic.
func TestReadsAreNotSuspendedByDefault(t *testing.T) {
	vt := mustNew(t, Config{Name: "no-suspend", MTU: 1280, InboundCapacity: 2})
	if err := vt.InjectInbound([]byte("live")); err != nil {
		t.Fatalf("InjectInbound: %v", err)
	}
	bufs, sizes := readBuf()
	delivered := make(chan error, 1)
	go func() {
		_, err := vt.Read(bufs, sizes, 0)
		delivered <- err
	}()
	select {
	case err := <-delivered:
		if err != nil {
			t.Fatalf("default Read returned %v", err)
		}
		if sizes[0] != len("live") {
			t.Errorf("default Read delivered %d bytes, expected %d", sizes[0], len("live"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a device nobody suspended must deliver without any Resume call")
	}
}
