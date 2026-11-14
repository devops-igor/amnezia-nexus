package vpn

// Lifetime contract for the response-direction flush writer used by the shared H2
// CONNECT test fixture (setupE2ETestH2Server).
//
// The fixture's handler copies the upstream response into the handler's
// http.ResponseWriter from a goroutine of its own while ServeHTTP owns that writer.
// x/net/http2 flushes and pools the response state in handlerDone AFTER ServeHTTP
// returns, so a copier write that outlives the handler is a real data race on the
// response writer's bufio.Writer (observed in CI: e2eFlushWriter.Write ->
// responseWriter.Flush vs responseWriter.handlerDone -> bufio.Writer.Flush).
//
// The contract proven here is the one the handler relies on when it calls
// fw.Close(): on return, no copier write/flush can still be in progress, and no
// later write may reach the ResponseWriter at all.

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// flushRecorder is a minimal http.ResponseWriter stand-in. Flush blocks until
// release is closed so a copier can be observed genuinely mid-Flush while the
// handler would be returning — the window the race detector caught.
type flushRecorder struct {
	mu      sync.Mutex
	writes  int
	flushes int

	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{entered: make(chan struct{}), release: make(chan struct{})}
}

func (r *flushRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.writes++
	r.mu.Unlock()
	return len(p), nil
}

func (r *flushRecorder) Flush() {
	r.enteredOnce.Do(func() { close(r.entered) })
	<-r.release
	r.mu.Lock()
	r.flushes++
	r.mu.Unlock()
}

func (r *flushRecorder) counts() (writes, flushes int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writes, r.flushes
}

// TestE2EFlushWriterWritesAreFencedByClose asserts that Close joins an in-flight
// response write and permanently fences later ones, so calling it before ServeHTTP
// returns leaves nothing that can touch the ResponseWriter afterwards.
func TestE2EFlushWriterWritesAreFencedByClose(t *testing.T) {
	rec := newFlushRecorder()
	fw := &e2eFlushWriter{w: rec, f: rec}

	copierDone := make(chan error, 1)
	go func() {
		_, err := fw.Write([]byte("response-body"))
		copierDone <- err
	}()

	// Wait until the copier is inside the ResponseWriter's Flush: this is exactly
	// where the CI race read bufio.Writer.n while handlerDone wrote it.
	<-rec.entered

	closeDone := make(chan error, 1)
	go func() { closeDone <- fw.Close() }()

	// Close must not complete while a response write is in flight, otherwise
	// ServeHTTP can return and handlerDone can flush/pool the same buffer underneath
	// the copier. The flush is held open by this test until rec.release, so a Close
	// that returns here is unambiguously not waiting on the writer.
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned (err=%v) while a response write was still in flight: "+
			"ServeHTTP could return here and race http2 handlerDone", err)
	case <-time.After(50 * time.Millisecond):
	}

	// Let the in-flight flush finish so both sides can complete.
	close(rec.release)

	if err := <-copierDone; err != nil {
		t.Fatalf("in-flight response write must succeed, got %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A write that starts after Close returned must never reach the ResponseWriter:
	// ServeHTTP has returned by then and http2's handlerDone owns the buffer state.
	if _, err := fw.Write([]byte("after-close")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close = %v, want net.ErrClosed (it would race handlerDone)", err)
	}

	writes, flushes := rec.counts()
	if writes != 1 || flushes != 1 {
		t.Fatalf("ResponseWriter touched after Close: writes=%d flushes=%d, want 1 and 1", writes, flushes)
	}
}

// TestE2EFlushWriterStillFlushesBeforeClose is the negative control for the fence
// above: the writer must remain a real flushing copier, not a no-op that trivially
// satisfies the lifetime test. A stubbed non-flushing writer would silently stop
// both proxy fixtures from exercising streamed responses.
func TestE2EFlushWriterStillFlushesBeforeClose(t *testing.T) {
	rec := newFlushRecorder()
	close(rec.release) // never block: this test is only about normal streaming
	fw := &e2eFlushWriter{w: rec, f: rec}

	for i := 0; i < 3; i++ {
		n, err := fw.Write([]byte("chunk"))
		if err != nil {
			t.Fatalf("write %d: %v", i+1, err)
		}
		if n != len("chunk") {
			t.Fatalf("write %d wrote %d bytes, want %d", i+1, n, len("chunk"))
		}
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	writes, flushes := rec.counts()
	if writes != 3 || flushes != 3 {
		t.Fatalf("writes=%d flushes=%d, want every write flushed exactly once", writes, flushes)
	}

	// Close is idempotent: a repeated call must not report a failure.
	if err := fw.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
