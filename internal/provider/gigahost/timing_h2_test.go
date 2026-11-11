package gigahost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
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
	return newH2TimingClientWithTransport(t, h, onCall, timeout, nil)
}

// newH2TimingClientWithTransport is newH2TimingClient with the fixture's h2
// transport optionally wrapped, so a control can intervene in the real
// transport path without rebuilding the fixture.
func newH2TimingClientWithTransport(t *testing.T, h http.Handler, onCall func(CallTiming), timeout time.Duration, wrap func(*http.Transport) http.RoundTripper) Client {
	t.Helper()

	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tr := ownedTransportOf(t, mustDefaultClient(t)).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots}

	var transport http.RoundTripper = tr
	if wrap != nil {
		transport = wrap(tr)
	}

	c, err := NewClient(Config{
		BaseURL:   server.URL,
		APIKey:    testAPIKey,
		Transport: transport,
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

// servedH2RecordViolations lists every way a record from a successful call over
// a negotiated h2 connection fails the served-response contract. An acceptable
// record yields an empty list.
//
// RequestWrittenMS is deliberately optional. The standard library documents that
// trace hooks "may be called concurrently from different goroutines and some may
// be called after the request has completed or failed", and h2 traces the
// response byte from the connection read loop while it reports the write from
// the per-stream goroutine. A fast server can therefore answer before that
// goroutine reports, so demanding the offset asserts an ordering the transport
// does not provide. What the record must not do is blur the two facts: when the
// phase was reached its offset is a real measurement, and when it was not it
// stays the not-reached sentinel instead of a fabricated zero.
//
// The offsets are not compared against TotalMS. finish samples the total before
// it takes the recorder's lock, so a callback that lands in that window stores an
// offset a few milliseconds past the total the record carries; asserting
// offset <= TotalMS would fail for a legal interleaving. ValidateTiming already
// bounds every offset by the record's own duration limit, which is a bound the
// recorder does guarantee.
func servedH2RecordViolations(r CallTiming) []string {
	var violations []string

	if r.Proto != "h2" {
		violations = append(violations, fmt.Sprintf("proto = %q, want h2", r.Proto))
	}
	if r.Outcome != OutcomeOK {
		violations = append(violations, fmt.Sprintf("outcome = %q, want %q", r.Outcome, OutcomeOK))
	}
	if r.Status != http.StatusOK {
		violations = append(violations, fmt.Sprintf("status = %d, want 200", r.Status))
	}
	if r.Operation != "servers_get" {
		violations = append(violations, fmt.Sprintf("operation = %q, want servers_get", r.Operation))
	}
	for _, reached := range []struct {
		name   string
		offset int64
	}{
		{"get_conn", r.GetConnMS},
		{"connect", r.ConnectMS},
		{"first_byte", r.FirstByteMS},
	} {
		if reached.offset == phaseNotReached {
			violations = append(violations, reached.name+" phase not reached")
		}
	}
	if r.LastPhase != phaseFirstByte {
		violations = append(violations, fmt.Sprintf("last phase = %q, want %q after a served response", r.LastPhase, phaseFirstByte))
	}
	if err := ValidateTiming(r); err != nil {
		violations = append(violations, "record failed its own validation: "+err.Error())
	}
	return violations
}

// requireServedH2Record applies that oracle. The live test and its controls share
// this one call, so a control cannot pass against a laxer assertion than the one
// guarding the real transport.
func requireServedH2Record(t *testing.T, r CallTiming) {
	t.Helper()
	for _, violation := range servedH2RecordViolations(r) {
		t.Errorf("published record: %s (record %+v)", violation, r)
	}
}

// TestTimingHTTP2CallRecordsPhasesAndProtocol is the regression: a successful
// call over a negotiated h2 connection records the phases it reached, the status
// and the protocol, and publishes exactly one immutable record. On the
// unsynchronised recorder the race detector reports this test.
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
	requireServedH2Record(t, r)
}

// h2WroteRequestGate wraps the fixture's transport and installs an observer
// trace on the request context. httptrace composes a newer trace ahead of the
// existing one, so this hook runs before the recorder's hook for the same
// event: holding it here holds the transport's real WroteRequest callback
// without inventing, replaying or timestamping a mark.
type h2WroteRequestGate struct {
	base    http.RoundTripper
	entered chan<- struct{}
	release <-chan struct{}
	wrote   chan<- struct{}
}

func (g *h2WroteRequestGate) RoundTrip(req *http.Request) (*http.Response, error) {
	trace := &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) {
			// WroteRequest may be called more than once for a retried request;
			// the sends must never block, or a retry would deadlock the fixture.
			select {
			case g.entered <- struct{}{}:
			default:
			}
			<-g.release
			select {
			case g.wrote <- struct{}{}:
			default:
			}
		},
	}
	return g.base.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
}

// awaitOrFail waits for one value on ch, failing the test with msg if the
// control's own bounded wait expires. Each waiting step in the controls below is
// a hard precondition, so a settled step and a hang must not share an assertion.
func awaitOrFail[T any](t *testing.T, ch <-chan T, wait time.Duration, msg string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(wait):
		t.Fatal(msg)
		var zero T
		return zero
	}
}

// TestTimingHTTP2RequestWrittenAfterPublicationKeepsTruthfulRecord is the
// deterministic control for the optional phase, driven through the real h2
// transport.
//
// The request headers are flushed before the transport traces the write, so the
// server answers, the read loop traces the first response byte and the request
// goroutine publishes the record while WroteRequest is still held. This is the
// ordering the earlier strict assertion could not survive: the record legitimately
// carries the not-reached sentinel for a phase the transport reports later than
// the response. The shared oracle must accept that record, and the callback that
// resumes afterwards must not reach it.
func TestTimingHTTP2RequestWrittenAfterPublicationKeepsTruthfulRecord(t *testing.T) {
	const wait = 5 * time.Second

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	wrote := make(chan struct{}, 1)

	// Released on every exit path so a failed assertion cannot strand the
	// transport's stream goroutine and block fixture teardown.
	var releaseOnce sync.Once
	releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseGate()

	published := make(chan CallTiming, 1)
	s := &sink{}
	collect := func(rec CallTiming) {
		s.collect(rec)
		published <- rec
	}

	c := newH2TimingClientWithTransport(t, http.HandlerFunc(serveEmptyOK), collect, wait,
		func(tr *http.Transport) http.RoundTripper {
			return &h2WroteRequestGate{base: tr, entered: entered, release: release, wrote: wrote}
		})

	callErr := make(chan error, 1)
	go func() {
		_, err := c.GetServers(context.Background())
		callErr <- err
	}()

	awaitOrFail(t, entered, wait,
		"the h2 transport never traced WroteRequest: the control did not reach the write path")
	record := awaitOrFail(t, published, wait,
		"no record was published while WroteRequest was held: publication is waiting on the write callback")

	// The strict assertion this control exists for required this offset. Stating
	// it as a fact about the record is what makes the control sensitive to it.
	if record.RequestWrittenMS != phaseNotReached {
		t.Fatalf("request written = %d ms, want the not-reached sentinel: the control did not produce the late-callback ordering",
			record.RequestWrittenMS)
	}
	if record.LastPhase != phaseFirstByte {
		t.Errorf("last phase = %q, want %q", record.LastPhase, phaseFirstByte)
	}
	requireServedH2Record(t, record)

	// Release the held callback: it must actually resume on the real transport,
	// which is what makes it a late callback rather than one that never fired.
	releaseGate()
	awaitOrFail(t, wrote, wait,
		"the held WroteRequest callback never resumed on the real h2 transport")
	if err := awaitOrFail(t, callErr, wait,
		"GetServers did not return after the write callback was released"); err != nil {
		t.Fatalf("GetServers over h2: %v", err)
	}

	// The assertions below hold whichever way the resumed callback races the
	// request goroutine: finish is closed, so it can neither append a record nor
	// alter the copy already handed to the sink.
	records := s.all()
	if len(records) != 1 {
		t.Fatalf("records = %d, want exactly 1", len(records))
	}
	if records[0] != record {
		t.Errorf("the late request-written callback mutated the published record:\n got %+v\nwant %+v", records[0], record)
	}
}

// TestServedH2RecordOracleRejectsUnreachedOrInvalidPhases is the sensitivity
// control for the shared oracle: each case must fail for its own stated reason,
// so an empty violation list means the record was examined rather than ignored.
// These are records assembled in memory to probe the oracle, not transport claims.
func TestServedH2RecordOracleRejectsUnreachedOrInvalidPhases(t *testing.T) {
	// A record with request_written absent, which is the ordering the transport
	// is allowed to produce and the one the live control publishes.
	served := CallTiming{
		Method: "GET", Operation: "servers_get", Outcome: OutcomeOK,
		Status: http.StatusOK, TotalMS: 20, LastPhase: phaseFirstByte, Proto: "h2",
		GetConnMS: 1, DNSMS: 2, ConnectMS: 3, TLSMS: 4,
		RequestWrittenMS: phaseNotReached, FirstByteMS: 10,
	}
	if violations := servedH2RecordViolations(served); len(violations) != 0 {
		t.Fatalf("oracle rejected a valid served record: %v (record %+v)", violations, served)
	}

	// The same record with the phase measured: also acceptable, so the absent
	// offset is tolerated rather than required.
	onTime := served
	onTime.RequestWrittenMS = 8
	if violations := servedH2RecordViolations(onTime); len(violations) != 0 {
		t.Fatalf("oracle rejected a valid record with a measured write offset: %v (record %+v)", violations, onTime)
	}

	cases := []struct {
		name   string
		mutate func(*CallTiming)
		want   string
	}{
		{"first byte never reached", func(c *CallTiming) { c.FirstByteMS = phaseNotReached }, "first_byte phase not reached"},
		{"connection never reached", func(c *CallTiming) { c.GetConnMS = phaseNotReached }, "get_conn phase not reached"},
		{"connect never reached", func(c *CallTiming) { c.ConnectMS = phaseNotReached }, "connect phase not reached"},
		{"write offset below the sentinel", func(c *CallTiming) { c.RequestWrittenMS = -2 }, "phase offset out of bounds"},
		{"first byte offset above the duration limit", func(c *CallTiming) { c.FirstByteMS = maxCallDurationMS + 1 }, "phase offset out of bounds"},
		{"write offset above the duration limit", func(c *CallTiming) { c.RequestWrittenMS = maxCallDurationMS + 1 }, "phase offset out of bounds"},
		{"total above the duration limit", func(c *CallTiming) { c.TotalMS = maxCallDurationMS + 1 }, "duration"},
		{"last phase behind the response", func(c *CallTiming) { c.LastPhase = phaseRequestWritten }, "last phase"},
		{"last phase outside the closed set", func(c *CallTiming) { c.LastPhase = "/deploy/servers" }, "not allowlisted"},
		{"protocol not negotiated", func(c *CallTiming) { c.Proto = "http/1.1" }, "proto"},
		{"outcome not successful", func(c *CallTiming) { c.Outcome = OutcomeHTTPStatus }, "outcome"},
		{"status not successful", func(c *CallTiming) { c.Status = http.StatusBadGateway }, "status"},
		{"operation not the fixed label", func(c *CallTiming) { c.Operation = "other" }, "operation"},
	}
	for _, tc := range cases {
		record := served
		tc.mutate(&record)
		violations := servedH2RecordViolations(record)
		if len(violations) == 0 {
			t.Errorf("%s: oracle accepted an invalid record %+v", tc.name, record)
			continue
		}
		if !strings.Contains(strings.Join(violations, "; "), tc.want) {
			t.Errorf("%s: violations = %v, want one mentioning %q", tc.name, violations, tc.want)
		}
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
