package naive

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The echo fixture is shared by many tests in this package. Its cleanup used to
// signal a shutdown channel that nothing selected on, close the listener and
// then call WaitGroup.Wait. A connection returning from Accept could still
// reach WaitGroup.Add after Wait had observed the counter at zero, and an idle
// peer could hold Wait in a handler parked in io.Copy. The controls below pin
// the lifecycle contract: handler registration is complete before cleanup
// waits, and cleanup releases the connections the fixture owns.

// scriptedListener models a connection that was already queued for Accept when
// the fixture is closed: the first Accept observing the close returns that
// connection and later calls report the listener as closed.
type scriptedListener struct {
	conn   net.Conn
	closed chan struct{}
	once   sync.Once
	taken  atomic.Bool
}

func newScriptedListener(conn net.Conn) *scriptedListener {
	return &scriptedListener{conn: conn, closed: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	<-l.closed
	if l.taken.CompareAndSwap(false, true) {
		return l.conn, nil
	}
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return scriptedAddr("scripted") }

type scriptedAddr string

func (scriptedAddr) Network() string { return "scripted" }

func (a scriptedAddr) String() string { return string(a) }

// waitCleanup calls cleanup in its own goroutine and reports whether it
// returned within the assertion bound. The bound only turns an indefinite
// block into a test failure; it does not alter fixture deadlines.
func waitCleanup(t *testing.T, cleanup func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		cleanup()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("fixture cleanup did not return")
	}
}

// TestTCPEchoFixture_EchoRoundTripAndCloseBehaviour is the positive control:
// the fixture still echoes payloads, and the address no longer accepts a
// connection once cleanup has returned.
func TestTCPEchoFixture_EchoRoundTripAndCloseBehaviour(t *testing.T) {
	addr, cleanup := setupTCPEchoServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial echo fixture: %v", err)
	}
	defer func() { _ = conn.Close() }()

	payload := []byte("naive-echo-fixture-round-trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed payload mismatch: got %q want %q", got, payload)
	}

	cleanup()

	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		_ = c.Close()
		t.Fatal("echo fixture accepted a connection after cleanup")
	}
}

// TestTCPEchoFixture_CleanupDrainsIdlePeer is the negative control for the
// handler drain: a peer that connects and sends nothing leaves the handler
// parked in io.Copy, and cleanup must still release the owned connection
// instead of waiting on a peer that is under test control.
func TestTCPEchoFixture_CleanupDrainsIdlePeer(t *testing.T) {
	addr, cleanup := setupTCPEchoServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial echo fixture: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	waitCleanup(t, cleanup)

	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("idle peer connection was not closed by cleanup")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("cleanup returned without draining the idle peer connection")
	}
}

// TestTCPEchoFixture_CleanupAccountsForConnAcceptedDuringClose is the negative
// control for the accept window: a connection handed back by Accept while the
// fixture is closing must be accounted for before cleanup waits, and closed as
// an owned resource.
func TestTCPEchoFixture_CleanupAccountsForConnAcceptedDuringClose(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	ln := newScriptedListener(server)
	_, cleanup := serveTCPEcho(t, ln)

	waitCleanup(t, cleanup)

	_, err := client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("connection accepted during close was not closed by cleanup")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("cleanup returned without accounting for the connection accepted during close")
	}
	if !ln.taken.Load() {
		t.Fatal("scripted accept never handed the queued connection to the fixture")
	}
}
