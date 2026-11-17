package forwarder

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestReplacementBeginsWhileOldWriteIsBlockedAndWaitsToComplete settles the handoff
// contract precisely.
//
// A replacement can BEGIN while the previous generation's client write is still blocked:
// registration returns a retirement handle immediately. What waits is the retirement's
// completion, which cannot finish until that write ends. Neither fact is claimed to make
// overlapping operations impossible, and no deadlock is needed to observe them.
func TestReplacementBeginsWhileOldWriteIsBlockedAndWaitsToComplete(t *testing.T) {
	writer := newControllableReturnPath(t)
	fwd, _, peer, _ := proxyReturnFixtureWithPath(t, writer.path())
	// Registered after the pump join, so it runs BEFORE it: an early failure must not
	// leave the pump blocked in the writer while teardown waits.
	t.Cleanup(writer.releaseWriter)

	const remote, port, clientPort = "9.9.9.9", uint16(443), uint16(46000)
	if err := fwd.RouteClientToBackend(peer, buildTestIPv4TCPPacket(
		netip.MustParseAddr("10.100.0.7"), netip.MustParseAddr(remote),
		clientPort, port, 0x02, nil)); err != nil {
		t.Fatalf("client dispatch: %v", err)
	}
	if err := fwd.RouteBackendToClient(31, proxyReply(remote, port, clientPort, []byte("reply")), "10.100.0.7"); err != nil {
		t.Fatalf("return refused: %v", err)
	}
	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the pump never reached the client writer")
	}

	// The replacement BEGINS now, while that write is still blocked.
	retirement, err := fwd.TryRegisterSessionWithReturnPath(
		"sess-return", "conn-2", peer, "10.100.0.7", 31, 0, 0, newTestCaptureReturnPath().path)
	if err != nil {
		t.Fatalf("replacement did not begin while a write was in flight: %v", err)
	}

	// Its completion waits for the admitted write, and says so rather than blocking.
	waitCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := retirement.WaitContext(waitCtx); err == nil {
		t.Fatal("retirement completed while the old generation's write was still blocked")
	}

	writer.releaseWriter()
	doneCtx, doneCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer doneCancel()
	if err := retirement.WaitContext(doneCtx); err != nil {
		t.Fatalf("retirement did not complete after the write ended: %v", err)
	}
}
