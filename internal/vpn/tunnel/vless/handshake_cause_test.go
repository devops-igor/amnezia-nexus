//go:build with_utls

package vless

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// cancelOwner identifies which party registered a context cancellation callback
// while (*Dialer).handshake builds a REALITY session.
type cancelOwner int

const (
	// ownerSocketCloser is the dialer's own context.AfterFunc(raw.Close).
	ownerSocketCloser cancelOwner = iota
	// ownerTLSInterrupter is the TLS library's child-context propagation, which
	// arms its interrupter goroutine to close the socket and report the cause.
	ownerTLSInterrupter
	// ownerTransport is the standard library's connect-time callback.
	ownerTransport
)

func (o cancelOwner) String() string {
	switch o {
	case ownerSocketCloser:
		return "dialer socket closer"
	case ownerTLSInterrupter:
		return "TLS library interrupter"
	default:
		return "transport"
	}
}

// orderedCallback is one registered cancellation callback plus its owner.
type orderedCallback struct {
	fn    func()
	owner cancelOwner
	fired bool
}

// orderedCancelCtx is a context whose cancellation callbacks are delivered by the
// test in a chosen order instead of by the scheduler.
//
// It implements the unexported AfterFunc extension point that context.AfterFunc
// and context.WithCancel both honour, so the production owners register here in
// their real order:
//
//	#0 transport connect callback, #1 dialer context.AfterFunc(raw.Close),
//	#2 TLS library child-context propagation (which arms its interrupter).
//
// Registration order is what makes the defect schedulable: because the parent
// implements AfterFunc, a derived context is not wired to the parent's Done
// channel directly, so propagation reaches the library only when the test runs
// that callback. Running the socket closer first is therefore a legal delivery
// order, and the one a loaded runner can produce.
type orderedCancelCtx struct {
	mu   sync.Mutex
	cbs  []*orderedCallback
	done chan struct{}
	err  error
}

func newOrderedCancelCtx() *orderedCancelCtx {
	return &orderedCancelCtx{done: make(chan struct{})}
}

func (c *orderedCancelCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *orderedCancelCtx) Done() <-chan struct{}       { return c.done }
func (c *orderedCancelCtx) Value(any) any               { return nil }

func (c *orderedCancelCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// AfterFunc records the callback and reports which owner registered it. The
// returned stop reports "nothing to stop", matching a callback that has not run
// yet; the recorded function is still fired explicitly by the test.
func (c *orderedCancelCtx) AfterFunc(f func()) func() bool {
	owner := registrationOwner()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cbs = append(c.cbs, &orderedCallback{fn: f, owner: owner})
	return func() bool { return true }
}

// registrationOwner classifies the caller by stack frame. The markers are the
// innermost frames actually present at registration: the TLS library frames for
// its child-context propagation, net's connect path for the transport callback,
// and otherwise the dialer's own AfterFunc.
func registrationOwner() cancelOwner {
	pcs := make([]uintptr, 24)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	for {
		frame, more := frames.Next()
		switch {
		case strings.Contains(frame.Function, "metacubex/utls"):
			return ownerTLSInterrupter
		case strings.Contains(frame.Function, "net.(*netFD)"):
			return ownerTransport
		}
		if !more {
			return ownerSocketCloser
		}
	}
}

// expire marks the context finished without delivering any callback.
func (c *orderedCancelCtx) expire(cause error) {
	c.mu.Lock()
	c.err = cause
	c.mu.Unlock()
	close(c.done)
}

// waitForOwners waits until both production owners have registered.
func (c *orderedCancelCtx) waitForOwners(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.mu.Lock()
		var closers, interrupters int
		for _, cb := range c.cbs {
			switch cb.owner {
			case ownerSocketCloser:
				closers++
			case ownerTLSInterrupter:
				interrupters++
			}
		}
		c.mu.Unlock()
		if closers > 0 && interrupters > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancellation owners not registered: %d socket closer(s), %d interrupter(s)", closers, interrupters)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fireOwner runs the first not-yet-fired callback of the given owner.
func (c *orderedCancelCtx) fireOwner(t *testing.T, owner cancelOwner) {
	t.Helper()
	c.mu.Lock()
	var fn func()
	for _, cb := range c.cbs {
		if cb.owner == owner && !cb.fired {
			cb.fired = true
			fn = cb.fn
			break
		}
	}
	c.mu.Unlock()
	if fn == nil {
		t.Fatalf("%s callback not registered or already fired", owner)
	}
	fn()
}

// owners returns the registration order of the recorded callbacks.
func (c *orderedCancelCtx) owners() []cancelOwner {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]cancelOwner, 0, len(c.cbs))
	for _, cb := range c.cbs {
		out = append(out, cb.owner)
	}
	return out
}

// runOrderedHandshakeFailure drives the real (*Dialer).handshake against a real
// blackhole listener and delivers the end-of-context callbacks in a chosen order.
//
// socketCloserFirst=true reproduces the loaded-runner interleaving: the dialer's
// socket closer runs before the TLS library observes the cancellation, so the
// blocked read fails with a closed-connection error while the context has already
// finished.
func runOrderedHandshakeFailure(t *testing.T, cause error, socketCloserFirst bool) (error, []cancelOwner) {
	t.Helper()
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	blackholeAddr, cleanup := startBlackholeListener(t)
	defer cleanup()

	d, err := New(blackholeAddr, fixture.Params)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	oc := newOrderedCancelCtx()
	out := make(chan error, 1)
	go func() {
		tc, _, handshakeErr := d.handshake(oc)
		if tc != nil {
			_ = tc.Close()
		}
		out <- handshakeErr
	}()

	oc.waitForOwners(t)
	order := oc.owners()
	// Let the handshake reach its blocking read before the context ends.
	time.Sleep(50 * time.Millisecond)

	oc.expire(cause)
	if socketCloserFirst {
		oc.fireOwner(t, ownerSocketCloser)
		time.Sleep(100 * time.Millisecond)
		oc.fireOwner(t, ownerTLSInterrupter)
	} else {
		oc.fireOwner(t, ownerTLSInterrupter)
		time.Sleep(100 * time.Millisecond)
		oc.fireOwner(t, ownerSocketCloser)
	}

	select {
	case handshakeErr := <-out:
		return handshakeErr, order
	case <-time.After(10 * time.Second):
		t.Fatal("handshake did not return after the context ended")
		return nil, order
	}
}

// TestAttributeContextCause covers the decision table of the attribution helper
// directly, so each branch has a behavioral assertion independent of the loaded
// handshake ordering.
func TestAttributeContextCause(t *testing.T) {
	baseErr := errors.New("use of closed network connection")

	t.Run("nil error stays nil", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got := attributeContextCause(ctx, nil); got != nil {
			t.Fatalf("want nil, got %v", got)
		}
	})

	t.Run("live context leaves the error untouched", func(t *testing.T) {
		ctx := context.Background()
		got := attributeContextCause(ctx, baseErr)
		if got != baseErr {
			t.Fatalf("want the original error, got %v", got)
		}
		if errors.Is(got, context.DeadlineExceeded) || errors.Is(got, context.Canceled) {
			t.Fatalf("live context introduced a cause: %v", got)
		}
	})

	t.Run("expired context adds the cause and keeps the original", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		<-ctx.Done()

		got := attributeContextCause(ctx, baseErr)
		if !errors.Is(got, context.DeadlineExceeded) {
			t.Fatalf("missing deadline cause: %v", got)
		}
		if !errors.Is(got, baseErr) {
			t.Fatalf("original error dropped from the chain: %v", got)
		}
	})

	t.Run("error already carrying the cause is not re-wrapped", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		already := fmt.Errorf("handshake: %w", context.Canceled)

		got := attributeContextCause(ctx, already)
		if got != already {
			t.Fatalf("already-attributed error was re-wrapped: %v", got)
		}
	})
}

// TestDialer_HandshakeContextCause pins the error classification of a REALITY
// handshake that ends with the caller's context.
//
// The deadline and cancellation cases fail without the cause attribution in
// (*Dialer).handshake: the returned error is the socket close error and
// errors.Is finds no context cause. The remaining pieces are controls that must
// hold both before and after that change.
func TestDialer_HandshakeContextCause(t *testing.T) {
	t.Run("deadline survives socket close first", func(t *testing.T) {
		err, order := runOrderedHandshakeFailure(t, context.DeadlineExceeded, true)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline cause lost: %v (registration order: %v)", err, order)
		}
		// The underlying transport failure must stay in the chain, not be replaced.
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("underlying close error lost: %v", err)
		}
		if got := err.Error(); !strings.Contains(got, "context deadline exceeded") {
			t.Fatalf("error text does not name the deadline: %s", got)
		}
	})

	t.Run("cancellation survives socket close first", func(t *testing.T) {
		err, order := runOrderedHandshakeFailure(t, context.Canceled, true)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation cause lost: %v (registration order: %v)", err, order)
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("underlying close error lost: %v", err)
		}
	})

	t.Run("interrupter first keeps the deadline", func(t *testing.T) {
		err, order := runOrderedHandshakeFailure(t, context.DeadlineExceeded, false)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline cause lost: %v (registration order: %v)", err, order)
		}
	})
}

// TestDialer_HandshakeLiveContextControl proves the attribution does not reach a
// handshake that failed for its own reasons: the peer closes immediately and the
// context is still live, so no context cause is attached.
func TestDialer_HandshakeLiveContextControl(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	d, err := New(ln.Addr().String(), fixture.Params)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err = d.handshake(ctx)
	if err == nil {
		t.Fatal("expected an error from a peer that closes immediately, got nil")
	}
	if ctx.Err() != nil {
		t.Fatalf("control invalid: context already finished: %v", ctx.Err())
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("live-context remote failure misclassified as a context cause: %v", err)
	}
	if errors.Is(err, net.ErrClosed) {
		t.Fatalf("live-context remote failure reported as a local close: %v", err)
	}
	t.Logf("remote failure with live context: %v", err)
}

// TestDialer_HandshakeSuccessControl proves a handshake that completes before its
// context ends still yields a usable stream.
func TestDialer_HandshakeSuccessControl(t *testing.T) {
	fixture := setupTestServer(t, "", 0)
	defer fixture.ServerClose()

	echoAddr, cleanup := startTCPEchoServer(t)
	defer cleanup()

	d, err := New(fixture.Endpoint, fixture.Params)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	payload := []byte("handshake cause regression payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
	if ctx.Err() != nil {
		t.Fatalf("context ended during a successful handshake: %v", ctx.Err())
	}
}
