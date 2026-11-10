package gigahost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"
)

// The plain-HTTP fixtures in timing_test.go never exercise the HTTP/2 path.
// Under HTTP/2 the standard library runs WroteRequest and GotFirstResponseByte
// from its own stream-write and connection read-loop goroutines, so the recorder
// is written concurrently and then read by finish on the request goroutine.
// These tests drive that real path with the callback enabled and assert the
// published record, which is what makes the unsynchronised version fail under
// -race instead of only in production.
//
// The oracle stays outside the recorder wherever possible: a failed assertion
// here is about the record the sink received, not about the synchronisation
// mechanism itself.

// newH2TimingClient starts an HTTP/2-only TLS fixture and returns a client whose
// callback is enabled. The server advertises h2 through ALPN, so a negotiated
// h2 is proven rather than assumed.
func newH2TimingClient(t *testing.T, h http.Handler, onCall func(CallTiming), timeout time.Duration) Client {
	t.Helper()

	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tr := ownedTransportOf(t, mustDefaultClient(t)).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots}

	c, err := NewClient(Config{
		BaseURL:   server.URL,
		APIKey:    testAPIKey,
		Transport: tr,
		Timeout:   timeout,
		OnCall:    onCall,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// serveEmptyOK answers a successful documented empty inventory.
const emptyServersDoc = `[]`

func serveEmptyOK(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(emptyServersDoc))
}

// TestTimingHTTP2CallRecordsPhasesAndProtocol is the regression: a successful
// call over a negotiated h2 connection records every phase, the status and the
// protocol, and publishes exactly one record. On the unsynchronised recorder the
// race detector reports this test.
func TestTimingHTTP2CallRecordsPhasesAndProtocol(t *testing.T) {
	s := &sink{}
	c := newH2TimingClient(t, http.HandlerFunc(serveEmptyOK), s.collect, 5*time.Second)

	if _, err := c.GetServers(context.Background()); err != nil {
		t.Fatalf("GetServers over h2: %v", err)
	}

	records := s.all()
	if len(records) != 1 {
		t.Fatalf("records = %d, want exactly 1", len(records))
	}
	r := records[0]
	if r.Proto != "h2" {
		t.Fatalf("proto = %q, want h2 (the fixture must negotiate HTTP/2 for this test to mean anything)", r.Proto)
	}
	if r.Outcome != OutcomeOK {
		t.Errorf("outcome = %q, want %q", r.Outcome, OutcomeOK)
	}
	if r.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", r.Status)
	}
	if r.Operation != "servers_get" {
		t.Errorf("operation = %q, want servers_get", r.Operation)
	}
	if r.GetConnMS == phaseNotReached || r.ConnectMS == phaseNotReached ||
		r.RequestWrittenMS == phaseNotReached || r.FirstByteMS == phaseNotReached {
		t.Errorf("expected connection and response phases reached over h2, got %+v", r)
	}
	if r.LastPhase != phaseFirstByte {
		t.Errorf("last phase = %q, want %q after a served response", r.LastPhase, phaseFirstByte)
	}
	if err := ValidateTiming(r); err != nil {
		t.Errorf("record failed its own validation: %v", err)
	}
}

// TestTimingHTTP2TimeoutAndCancellation publishes one classifiable record per
// interrupted call over h2, where the callbacks keep arriving on connection
// goroutines while the request goroutine is already unwinding.
func TestTimingHTTP2TimeoutAndCancellation(t *testing.T) {
	stall := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	t.Run("client timeout", func(t *testing.T) {
		s := &sink{}
		c := newH2TimingClient(t, stall, s.collect, 150*time.Millisecond)

		if _, err := c.GetServers(context.Background()); err == nil {
			t.Fatal("expected a client timeout")
		}
		records := s.all()
		if len(records) != 1 {
			t.Fatalf("records = %d, want exactly 1", len(records))
		}
		r := records[0]
		if r.Outcome != OutcomeClientTimeout {
			t.Errorf("outcome = %q, want %q", r.Outcome, OutcomeClientTimeout)
		}
		if r.Status != 0 {
			t.Errorf("status = %d, want 0 (no response)", r.Status)
		}
		if r.FirstByteMS != phaseNotReached {
			t.Errorf("first byte = %d, want the not-reached sentinel", r.FirstByteMS)
		}
		if err := ValidateTiming(r); err != nil {
			t.Errorf("record failed its own validation: %v", err)
		}
	})

	t.Run("caller cancellation", func(t *testing.T) {
		s := &sink{}
		c := newH2TimingClient(t, stall, s.collect, 10*time.Second)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		defer cancel()

		if _, err := c.GetServers(ctx); err == nil {
			t.Fatal("expected a cancellation error")
		}
		records := s.all()
		if len(records) != 1 {
			t.Fatalf("records = %d, want exactly 1", len(records))
		}
		if got := records[0].Outcome; got != OutcomeCallerCanceled {
			t.Errorf("outcome = %q, want %q", got, OutcomeCallerCanceled)
		}
		if err := ValidateTiming(records[0]); err != nil {
			t.Errorf("record failed its own validation: %v", err)
		}
	})
}

// TestTimingHTTP2ConcurrentRequestsOwnOneRecordEach proves that concurrent
// requests sharing one client keep independent records: N calls produce N
// records, none duplicated and none interleaved. A recorder shared between
// requests would show up here as a count or a phase mismatch.
func TestTimingHTTP2ConcurrentRequestsOwnOneRecordEach(t *testing.T) {
	const calls = 8

	s := &sink{}
	c := newH2TimingClient(t, http.HandlerFunc(serveEmptyOK), s.collect, 5*time.Second)

	var wg sync.WaitGroup
	errs := make([]error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.GetServers(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	records := s.all()
	if len(records) != calls {
		t.Fatalf("records = %d, want %d (one per request)", len(records), calls)
	}
	for i, r := range records {
		if r.Outcome != OutcomeOK || r.Operation != "servers_get" {
			t.Errorf("record %d = %+v, want a successful servers_get", i, r)
		}
		if r.Proto != "h2" {
			t.Errorf("record %d proto = %q, want h2", i, r.Proto)
		}
		if err := ValidateTiming(r); err != nil {
			t.Errorf("record %d failed its own validation: %v", i, err)
		}
	}
}

// traceCallbackFirer returns a function that fires every trace callback for a
// recorder, so a test can drive the concurrent-write path deterministically
// instead of relying on transport scheduling.
func traceCallbackFirer(tr *httptraceTraceAdapter) func() {
	return func() {
		tr.GetConn("tcp")
		tr.GotConn(true)
		tr.DNSStart()
		tr.DNSDone()
		tr.ConnectStart()
		tr.ConnectDone()
		tr.TLSHandshakeStart()
		tr.TLSHandshakeDone(tls.ConnectionState{NegotiatedProtocol: "h2"})
		tr.WroteRequest()
		tr.GotFirstResponseByte()
	}
}

// httptraceTraceAdapter drives a recorder's ClientTrace callbacks by name, which
// keeps the deterministic tests readable and independent of callback ordering.
type httptraceTraceAdapter struct {
	trace *httptrace.ClientTrace
}

func (a *httptraceTraceAdapter) GetConn(addr string) { a.trace.GetConn(addr) }
func (a *httptraceTraceAdapter) GotConn(reused bool) {
	a.trace.GotConn(httptrace.GotConnInfo{Reused: reused})
}
func (a *httptraceTraceAdapter) DNSStart()          { a.trace.DNSStart(httptrace.DNSStartInfo{}) }
func (a *httptraceTraceAdapter) DNSDone()           { a.trace.DNSDone(httptrace.DNSDoneInfo{}) }
func (a *httptraceTraceAdapter) ConnectStart()      { a.trace.ConnectStart("tcp", "127.0.0.1:443") }
func (a *httptraceTraceAdapter) ConnectDone()       { a.trace.ConnectDone("tcp", "127.0.0.1:443", nil) }
func (a *httptraceTraceAdapter) TLSHandshakeStart() { a.trace.TLSHandshakeStart() }
func (a *httptraceTraceAdapter) TLSHandshakeDone(s tls.ConnectionState) {
	a.trace.TLSHandshakeDone(s, nil)
}
func (a *httptraceTraceAdapter) WroteRequest()         { a.trace.WroteRequest(httptrace.WroteRequestInfo{}) }
func (a *httptraceTraceAdapter) GotFirstResponseByte() { a.trace.GotFirstResponseByte() }

// TestTimingLateCallbacksCannotMutatePublishedRecord is the lifecycle control:
// callbacks that arrive after finish must not change the record already handed
// to the sink, and must not publish a second one.
func TestTimingLateCallbacksCannotMutatePublishedRecord(t *testing.T) {
	var published []CallTiming
	recorder := newTimingRecorder(http.MethodGet, "/servers")
	trace := &httptraceTraceAdapter{trace: recorder.clientTrace()}
	fire := traceCallbackFirer(trace)

	fire()
	recorder.finish(context.Background(), func(t CallTiming) { published = append(published, t) }, http.StatusOK, nil)

	before := published[len(published)-1]
	fire() // late callbacks after the record was published
	recorder.finish(context.Background(), func(t CallTiming) { published = append(published, t) }, http.StatusOK, nil)

	if len(published) != 1 {
		t.Fatalf("published %d records, want exactly 1 per request", len(published))
	}
	if published[0] != before {
		t.Errorf("published record changed after late callbacks:\n got %+v\nwant %+v", published[0], before)
	}
}

// TestTimingConcurrentCallbacksAndFinishPublishOneRecord drives callbacks and
// finish from separate goroutines without going through a transport at all. This
// is the deterministic exposure of the original defect: unsynchronised field
// writes against the finish snapshot are reported here on every run under -race.
func TestTimingConcurrentCallbacksAndFinishPublishOneRecord(t *testing.T) {
	const (
		writers = 4
		rounds  = 200
	)

	for round := 0; round < rounds; round++ {
		var published []CallTiming
		recorder := newTimingRecorder(http.MethodGet, "/servers")
		fire := traceCallbackFirer(&httptraceTraceAdapter{trace: recorder.clientTrace()})

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				fire()
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			recorder.finish(context.Background(), func(rec CallTiming) {
				published = append(published, rec)
			}, http.StatusOK, nil)
		}()
		close(start)
		wg.Wait()

		if len(published) != 1 {
			t.Fatalf("round %d: published %d records, want 1", round, len(published))
		}
		if err := ValidateTiming(published[0]); err != nil {
			t.Fatalf("round %d: published record is not a valid record: %v", round, err)
		}
	}
}

// TestTimingBlockingSinkDoesNotBlockCallbacks pins that the sink is invoked
// outside the recorder's lock: a slow observer must not stall the transport's
// trace callbacks, which would otherwise serialise the request behind logging.
func TestTimingBlockingSinkDoesNotBlockCallbacks(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	recorder := newTimingRecorder(http.MethodGet, "/servers")
	trace := &httptraceTraceAdapter{trace: recorder.clientTrace()}
	fire := traceCallbackFirer(trace)

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		recorder.finish(context.Background(), func(CallTiming) {
			close(entered)
			<-release
		}, http.StatusOK, nil)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("finish never reached the sink")
	}

	// While the sink is blocked, a trace callback must still return promptly.
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		fire()
	}()
	select {
	case <-callbackDone:
	case <-time.After(2 * time.Second):
		t.Fatal("a trace callback blocked while the sink was running; the lock is held across the sink call")
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("finish did not return after the sink was released")
	}
}

// TestTimingHTTP2CompleteCallLeavesNoLateCallbackRace runs the full real-h2 path
// repeatedly with a sink that records after a hand-off delay, so the request
// goroutine reaches finish while the connection goroutines may still be running
// callbacks. It is the end-to-end form of the exposure above.
func TestTimingHTTP2CompleteCallLeavesNoLateCallbackRace(t *testing.T) {
	const calls = 6

	var mu sync.Mutex
	var published []CallTiming
	s := &sink{}
	collect := func(rec CallTiming) {
		// Hand off to another goroutine and touch the record there, so a
		// not-yet-closed recorder would be visibly mutated after publication.
		go func() {
			time.Sleep(time.Millisecond)
			mu.Lock()
			published = append(published, rec)
			mu.Unlock()
			s.collect(rec)
		}()
	}

	c := newH2TimingClient(t, http.HandlerFunc(serveEmptyOK), collect, 5*time.Second)
	for i := 0; i < calls; i++ {
		if _, err := c.GetServers(context.Background()); err != nil {
			t.Fatalf("call %d over h2: %v", i, err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(published)
		mu.Unlock()
		if n == calls {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("collected %d records, want %d", n, calls)
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i, r := range s.all() {
		if err := ValidateTiming(r); err != nil {
			t.Errorf("record %d failed its own validation: %v", i, err)
		}
	}
}
