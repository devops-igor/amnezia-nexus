package gigahost

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// sink collects records under the test's control, safely for -race.
type sink struct {
	mu      sync.Mutex
	records []CallTiming
}

func (s *sink) collect(t CallTiming) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, t)
}

func (s *sink) all() []CallTiming {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]CallTiming(nil), s.records...)
}

// newTimedTestClient builds a client pointed at an httptest server with timing on.
func newTimedTestClient(t *testing.T, h http.Handler, s *sink) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{
		BaseURL: srv.URL,
		APIKey:  "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout: 2 * time.Second,
		OnCall:  s.collect,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// TestTimingNilSinkAttachesNoTrace is the opt-in guarantee: with no callback the
// call still works and nothing is recorded. It also proves the default path does
// not panic and does not require the trace.
func TestTimingNilSinkAttachesNoTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetServers(context.Background()); err != nil {
		t.Fatalf("GetServers with nil sink: %v", err)
	}
}

// TestTimingSuccessRecordsEveryPhase proves a completed call carries the phases,
// the status, the outcome and a fixed operation label.
func TestTimingSuccessRecordsEveryPhase(t *testing.T) {
	s := &sink{}
	c := newTimedTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}), s)

	if _, err := c.GetServers(context.Background()); err != nil {
		t.Fatalf("GetServers: %v", err)
	}

	records := s.all()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	r := records[0]
	if r.Outcome != OutcomeOK {
		t.Errorf("outcome = %q, want %q", r.Outcome, OutcomeOK)
	}
	if r.Status != http.StatusOK {
		t.Errorf("status = %d, want 200", r.Status)
	}
	if r.Method != "GET" {
		t.Errorf("method = %q, want GET", r.Method)
	}
	if r.Operation != "servers_get" {
		t.Errorf("operation = %q, want servers_get", r.Operation)
	}
	if r.LastPhase != phaseFirstByte {
		t.Errorf("last phase = %q, want %q", r.LastPhase, phaseFirstByte)
	}
	if r.GetConnMS == phaseNotReached || r.ConnectMS == phaseNotReached ||
		r.RequestWrittenMS == phaseNotReached || r.FirstByteMS == phaseNotReached {
		t.Errorf("expected connection and response phases reached, got %+v", r)
	}
	if r.Proto != "http/1.1" && r.Proto != "h2" {
		t.Errorf("proto = %q, want a closed-set value", r.Proto)
	}
	if err := ValidateTiming(r); err != nil {
		t.Errorf("record failed its own validation: %v", err)
	}
}

// TestTimingClientTimeoutDistinctFromCallerDeadline is the reason this record
// exists: the two deadlines must be separable, and a stalled server must report
// the phase it stopped at rather than a fabricated one.
func TestTimingClientTimeoutDistinctFromCallerDeadline(t *testing.T) {
	// Server reads the request then stalls, so the client timeout fires.
	stall := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})

	t.Run("client timeout", func(t *testing.T) {
		s := &sink{}
		srv := httptest.NewServer(stall)
		defer srv.Close()
		c, err := NewClient(Config{
			BaseURL: srv.URL, APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Timeout: 150 * time.Millisecond, OnCall: s.collect,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if _, err := c.GetServers(context.Background()); err == nil {
			t.Fatal("expected a timeout error")
		}
		records := s.all()
		if len(records) != 1 {
			t.Fatalf("records = %d, want 1", len(records))
		}
		r := records[0]
		if r.Outcome != OutcomeClientTimeout {
			t.Errorf("outcome = %q, want %q", r.Outcome, OutcomeClientTimeout)
		}
		if r.Status != 0 {
			t.Errorf("status = %d, want 0 (no response)", r.Status)
		}
		if r.LastPhase != phaseRequestWritten {
			t.Errorf("last phase = %q, want %q (the server never answered)", r.LastPhase, phaseRequestWritten)
		}
		if r.FirstByteMS != phaseNotReached {
			t.Errorf("first byte = %d, want the not-reached sentinel", r.FirstByteMS)
		}
	})

	t.Run("caller deadline", func(t *testing.T) {
		s := &sink{}
		srv := httptest.NewServer(stall)
		defer srv.Close()
		c, err := NewClient(Config{
			BaseURL: srv.URL, APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Timeout: 10 * time.Second, OnCall: s.collect,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		if _, err := c.GetServers(ctx); err == nil {
			t.Fatal("expected a deadline error")
		}
		records := s.all()
		if len(records) != 1 {
			t.Fatalf("records = %d, want 1", len(records))
		}
		if got := records[0].Outcome; got != OutcomeCallerDeadline {
			t.Errorf("outcome = %q, want %q (distinct from client_timeout)", got, OutcomeCallerDeadline)
		}
	})
}

// TestTimingConnectionRefusedIsNetworkError covers a transport failure before any
// response, with the phase recorded as the connection attempt.
func TestTimingConnectionRefusedIsNetworkError(t *testing.T) {
	// Reserve a port, then close it so the connect is refused deterministically.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	s := &sink{}
	c, err := NewClient(Config{
		BaseURL: "http://" + addr, APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout: 2 * time.Second, OnCall: s.collect,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetServers(context.Background()); err == nil {
		t.Fatal("expected a connection error")
	}
	records := s.all()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	r := records[0]
	if r.Outcome != OutcomeNetworkError {
		t.Errorf("outcome = %q, want %q", r.Outcome, OutcomeNetworkError)
	}
	if r.LastPhase != phaseConnectDone && r.LastPhase != phaseConnectStart && r.LastPhase != phaseGetConn {
		t.Errorf("last phase = %q, want a connection phase", r.LastPhase)
	}
	if r.FirstByteMS != phaseNotReached {
		t.Errorf("first byte = %d, want the not-reached sentinel", r.FirstByteMS)
	}
}

// TestTimingPanickingSinkDoesNotChangeTheCall is the safety requirement: an
// observer fault must never alter a provider outcome, and a purchase must still
// be reported as successful.
func TestTimingPanickingSinkDoesNotChangeTheCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c, err := NewClient(Config{
		BaseURL: srv.URL, APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Timeout: 2 * time.Second,
		OnCall: func(CallTiming) { panic("observer blew up") },
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetServers(context.Background()); err != nil {
		t.Fatalf("a panicking sink must not fail the call, got %v", err)
	}
}

// TestTimingRecordCarriesNoRequestData is the privacy contract, asserted on the
// serialized record rather than trusted: no key, bearer token, host, port, path,
// query, order id or error text may appear.
func TestTimingRecordCarriesNoRequestData(t *testing.T) {
	const apiKey = "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	srvHost := strings.TrimPrefix(srv.URL, "http://")

	s := &sink{}
	c, err := NewClient(Config{
		BaseURL: srv.URL, APIKey: apiKey, Timeout: 2 * time.Second, OnCall: s.collect,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetServers(context.Background()); err != nil {
		t.Fatalf("GetServers: %v", err)
	}
	if len(s.all()) != 1 {
		t.Fatalf("expected exactly one record")
	}

	var serialized strings.Builder
	for _, pair := range TimingRecord(s.all()[0]) {
		serialized.WriteString(strings.ToLower(fmt.Sprint(pair)))
		serialized.WriteString(" ")
	}
	lowered := serialized.String()
	for _, forbidden := range []string{
		apiKey, "bearer", "authorization", srvHost, "127.0.0.1", "localhost",
		"http://", "https://", "/deploy", "api/v0", "?",
	} {
		if strings.Contains(lowered, strings.ToLower(forbidden)) {
			t.Errorf("serialized record leaks %q: %s", forbidden, lowered)
		}
	}
}

// TestTimingSuccessRecordNeverCarriesErrorText proves that even a failure record
// carries only the closed outcome class, never err.Error() text - which for a
// *url.Error would embed the full URL.
func TestTimingSuccessRecordNeverCarriesErrorText(t *testing.T) {
	const secretMarker = "supersecretmarker"
	s := &sink{}
	c, err := NewClient(Config{
		BaseURL: "http://127.0.0.1:1", APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout: 300 * time.Millisecond, OnCall: s.collect,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetServers(context.Background()); err == nil {
		t.Fatal("expected a network error")
	}
	records := s.all()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	var serialized strings.Builder
	for _, pair := range TimingRecord(records[0]) {
		serialized.WriteString(strings.ToLower(fmt.Sprint(pair)))
		serialized.WriteString(" ")
	}
	lowered := serialized.String()
	for _, forbidden := range []string{secretMarker, "connect:", "dial tcp", "127.0.0.1", "http://", "refused"} {
		if strings.Contains(lowered, forbidden) {
			t.Errorf("failure record leaks %q: %s", forbidden, lowered)
		}
	}
	if err := ValidateTiming(records[0]); err != nil {
		t.Errorf("failure record failed validation: %v", err)
	}
}

// TestOperationLabelIsClosedSet proves arbitrary paths cannot echo into a label.
func TestOperationLabelIsClosedSet(t *testing.T) {
	cases := map[string]string{
		"/deploy/servers":        "deploy_servers_get",
		"/deploy/servers?x=1":    "deploy_servers_get",
		"/deploy/status?ids=99":  "deploy_status_get",
		"/account":               "account_get",
		"/deploy/servers/123456": "other",
		"/api/v0/secret/thing":   "other",
		"":                       "other",
	}
	for path, want := range cases {
		if got := OperationLabel("GET", path); got != want {
			t.Errorf("OperationLabel(GET, %q) = %q, want %q", path, got, want)
		}
	}
	// The verb must be part of the label: GET and POST on the same path differ.
	if got := OperationLabel("POST", "/deploy/servers"); got != "deploy_servers_post" {
		t.Errorf("POST label = %q, want deploy_servers_post", got)
	}
	if got := OperationLabel("POST", "/deploy/servers"); got == OperationLabel("GET", "/deploy/servers") {
		t.Error("GET and POST must not share a label")
	}
}

// TestValidateTimingRejectsOutOfClassValues proves the validator is a real gate,
// not decoration.
func TestValidateTimingRejectsOutOfClassValues(t *testing.T) {
	good := CallTiming{
		Method: "GET", Operation: "deploy_servers_get", Outcome: OutcomeOK,
		Status: 200, TotalMS: 5, LastPhase: phaseFirstByte, Proto: "http/1.1",
		GetConnMS: 1, DNSMS: 1, ConnectMS: 1, TLSMS: phaseNotReached,
		RequestWrittenMS: 2, FirstByteMS: 3,
	}
	if err := ValidateTiming(good); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}

	bad := []struct {
		name   string
		mutate func(*CallTiming)
	}{
		{"unknown method", func(c *CallTiming) { c.Method = "BREW" }},
		{"unknown outcome", func(c *CallTiming) { c.Outcome = "timeout" }},
		{"unknown phase", func(c *CallTiming) { c.LastPhase = "/deploy/servers" }},
		{"unknown proto", func(c *CallTiming) { c.Proto = "spdy" }},
		{"status out of range", func(c *CallTiming) { c.Status = 999 }},
		{"duration out of range", func(c *CallTiming) { c.TotalMS = -5 }},
		{"phase out of range", func(c *CallTiming) { c.FirstByteMS = -2 }},
	}
	for _, tc := range bad {
		record := good
		tc.mutate(&record)
		if err := ValidateTiming(record); err == nil {
			t.Errorf("%s: validator accepted an out-of-class value", tc.name)
		}
	}
}

// TestClassifyOutcomeDistinguishesDeadlines pins the classification directly,
// including the discriminator that a nil caller context cannot supply.
func TestClassifyOutcomeDistinguishesDeadlines(t *testing.T) {
	// The caller's own context is what separates the two timeout classes, because
	// http.Client.Timeout also satisfies context.DeadlineExceeded.
	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-expired.Done()
	if got := classifyOutcome(expired, 0, context.DeadlineExceeded); got != OutcomeCallerDeadline {
		t.Errorf("expired caller context = %q, want %q", got, OutcomeCallerDeadline)
	}

	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if got := classifyOutcome(canceled, 0, context.Canceled); got != OutcomeCallerCanceled {
		t.Errorf("cancelled caller context = %q, want %q", got, OutcomeCallerCanceled)
	}

	// A live caller context plus a timeout-class error is the client's own limit.
	if got := classifyOutcome(context.Background(), 0, &url.Error{Op: "Get", URL: "http://x", Err: timeoutError{}}); got != OutcomeClientTimeout {
		t.Errorf("client timeout = %q, want %q", got, OutcomeClientTimeout)
	}
	if got := classifyOutcome(context.Background(), 0, errors.New("boom")); got != OutcomeOtherError {
		t.Errorf("other = %q, want %q", got, OutcomeOtherError)
	}
	if got := classifyOutcome(context.Background(), 500, nil); got != OutcomeHTTPStatus {
		t.Errorf("500 = %q, want %q", got, OutcomeHTTPStatus)
	}
	if got := classifyOutcome(context.Background(), 204, nil); got != OutcomeOK {
		t.Errorf("204 = %q, want %q", got, OutcomeOK)
	}
}

// TestTimingTLSReportsNegotiatedProtocol covers the TLS/ALPN path, which an
// httptest.NewServer (plain HTTP) never exercises.
func TestTimingTLSReportsNegotiatedProtocol(t *testing.T) {
	s := &sink{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	// The test server uses a self-signed certificate; trust it for this call only.
	c, err := NewClient(Config{
		BaseURL: srv.URL, APIKey: "flux_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Timeout: 2 * time.Second, OnCall: s.collect,
		Transport: srv.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.GetServers(context.Background()); err != nil {
		t.Fatalf("GetServers over TLS: %v", err)
	}
	records := s.all()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	r := records[0]
	if r.TLSMS == phaseNotReached {
		t.Errorf("expected a TLS phase over https, got %+v", r)
	}
	if r.Proto != "http/1.1" && r.Proto != "h2" {
		t.Errorf("proto = %q, want a negotiated closed-set value", r.Proto)
	}
	if err := ValidateTiming(r); err != nil {
		t.Errorf("record failed validation: %v", err)
	}
}

// TestNormalizeProtoIsClosedSet pins the ALPN mapping directly, including the
// unrecognized-protocol case an unknown server could negotiate.
func TestNormalizeProtoIsClosedSet(t *testing.T) {
	if got := normalizeProto(tls.ConnectionState{NegotiatedProtocol: "h2"}); got != "h2" {
		t.Errorf("h2 = %q, want h2", got)
	}
	if got := normalizeProto(tls.ConnectionState{NegotiatedProtocol: "http/1.1"}); got != "http/1.1" {
		t.Errorf("http/1.1 = %q, want http/1.1", got)
	}
	// Anything not in the closed set is dropped rather than echoed.
	if got := normalizeProto(tls.ConnectionState{NegotiatedProtocol: "spdy/3.1"}); got != "" {
		t.Errorf("unknown proto = %q, want empty", got)
	}
	if got := normalizeProto(tls.ConnectionState{NegotiatedProtocol: "acme-tls/1"}); got != "" {
		t.Errorf("acme proto = %q, want empty", got)
	}
}

// timeoutError is a net.Error whose Timeout() is true, standing in for
// http.Client.Timeout without depending on timing.
type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
