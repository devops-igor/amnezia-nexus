package gigahost

// Opt-in call timing for the Gigahost provider client.
//
// The panel has observed order calls failing after roughly 30 seconds, but the
// only existing collection path is unstructured stdout, so the failing phase is
// unknown. This record answers exactly that question and nothing else: which
// fixed operation was slow, at which HTTP phase it stopped, and whether the
// caller's deadline or the client's own timeout ended it.
//
// Every field is a closed set, a bounded integer or a boolean. The record never
// carries the URL, host, address, path, query, order id, request/response
// header or body, API key, or err.Error() text — a *url.Error embeds the full
// URL, which is precisely what must not be published.
//
// Timing is opt-in: with no sink configured, no httptrace client is attached and
// the request path is byte-for-byte unchanged.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
)

// phaseNotReached marks a phase that was never reached, so "reached at 0 ms"
// stays distinguishable from "not reached". Using 0 for both would silently
// turn missing evidence into a measured zero.
const phaseNotReached int64 = -1

// CallOutcome classifies why a provider call ended. The two deadline cases are
// deliberately separate: they produce near-identical error text today, and
// telling them apart is the whole point of the record.
type CallOutcome string

const (
	// OutcomeOK means the call completed and a response was received.
	OutcomeOK CallOutcome = "ok"
	// OutcomeHTTPStatus means a response arrived with a non-2xx status.
	OutcomeHTTPStatus CallOutcome = "http_status"
	// OutcomeCallerDeadline means the caller's context deadline expired.
	OutcomeCallerDeadline CallOutcome = "caller_deadline"
	// OutcomeCallerCanceled means the caller's context was canceled.
	OutcomeCallerCanceled CallOutcome = "caller_canceled"
	// OutcomeClientTimeout means http.Client.Timeout ended the call.
	OutcomeClientTimeout CallOutcome = "client_timeout"
	// OutcomeNetworkError means a transport/network failure.
	OutcomeNetworkError CallOutcome = "network_error"
	// OutcomeOtherError is the fallback class; it carries no error text.
	OutcomeOtherError CallOutcome = "other_error"
)

// CallTiming is one bounded, allowlisted provider call record.
//
// Phase offsets are milliseconds since the call started, or phaseNotReached.
// LastPhase is the name of the last phase that completed, never a URL.
type CallTiming struct {
	// Method is one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, other.
	Method string
	// Operation is a fixed label such as deploy_servers_get; never a path.
	Operation string
	// Outcome is the closed-set result class.
	Outcome CallOutcome
	// Status is the HTTP status code, or 0 when no response arrived.
	Status int
	// TotalMS is the wall duration of the call in milliseconds.
	TotalMS int64
	// LastPhase names the last completed phase, or "" when none completed.
	LastPhase string
	// Reused reports whether the connection was reused.
	Reused bool
	// Proto is the negotiated ALPN protocol: "", http/1.1 or h2.
	Proto string

	// Phase offsets in milliseconds from call start, or phaseNotReached.
	GetConnMS        int64
	DNSMS            int64
	ConnectMS        int64
	TLSMS            int64
	RequestWrittenMS int64
	FirstByteMS      int64
}

// Phase names used for LastPhase. Fixed strings, no request data.
const (
	phaseGetConn        = "get_conn"
	phaseDNSStart       = "dns_start"
	phaseDNSDone        = "dns_done"
	phaseConnectStart   = "connect_start"
	phaseConnectDone    = "connect_done"
	phaseTLSStart       = "tls_start"
	phaseTLSDone        = "tls_done"
	phaseRequestWritten = "request_written"
	phaseFirstByte      = "first_byte"
)

// callPhaseNames is the closed set of LastPhase values.
var callPhaseNames = map[string]bool{
	"":                  true,
	phaseGetConn:        true,
	phaseDNSStart:       true,
	phaseDNSDone:        true,
	phaseConnectStart:   true,
	phaseConnectDone:    true,
	phaseTLSStart:       true,
	phaseTLSDone:        true,
	phaseRequestWritten: true,
	phaseFirstByte:      true,
}

// callMethods is the closed set of Method values.
var callMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true, "other": true,
}

// callProtos is the closed set of Proto values.
var callProtos = map[string]bool{"": true, "http/1.1": true, "h2": true}

// callOutcomes is the closed set of Outcome values.
var callOutcomes = map[CallOutcome]bool{
	OutcomeOK: true, OutcomeHTTPStatus: true, OutcomeCallerDeadline: true,
	OutcomeCallerCanceled: true, OutcomeClientTimeout: true,
	OutcomeNetworkError: true, OutcomeOtherError: true,
}

// NormalizeMethod maps an arbitrary HTTP method to the closed set.
func NormalizeMethod(method string) string {
	upper := strings.ToUpper(strings.TrimSpace(method))
	if callMethods[upper] {
		return upper
	}
	return "other"
}

// OperationLabel maps a provider request path to a fixed operation label.
//
// The label is the path with its variable segments removed, so no order id,
// server id or query string can reach a record. An unrecognized path collapses
// to "other" rather than echoing its content.
func OperationLabel(method, path string) string {
	verb := strings.ToLower(NormalizeMethod(method))
	if verb == "other" {
		return "other"
	}
	clean := path
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	switch {
	case clean == "/deploy/servers":
		return "deploy_servers_" + verb
	case clean == "/deploy/status":
		return "deploy_status_" + verb
	case clean == "/servers":
		return "servers_" + verb
	case clean == "/account":
		return "account_" + verb
	default:
		return "other"
	}
}

// timingRecorder accumulates httptrace phase marks for one call.
//
// The request goroutine is not the only writer. Under HTTP/2 the transport runs
// WroteRequest and GotFirstResponseByte from its own stream-write and connection
// read-loop goroutines, so the mutable record is guarded by mu: every trace
// callback and the finish-time snapshot take it, which is what orders the
// callbacks against each other and against finish. The lock is only ever held to
// copy a few integers — never across the sink call, which may block or panic.
//
// finish closes the recorder. One call yields exactly one record, and a callback
// that arrives afterwards is dropped instead of mutating a record that has
// already been handed to the sink.
type timingRecorder struct {
	start time.Time

	mu       sync.Mutex
	timing   CallTiming
	finished bool
}

func newTimingRecorder(method, path string) *timingRecorder {
	return &timingRecorder{
		start: time.Now(),
		timing: CallTiming{
			Method:           NormalizeMethod(method),
			Operation:        OperationLabel(method, path),
			GetConnMS:        phaseNotReached,
			DNSMS:            phaseNotReached,
			ConnectMS:        phaseNotReached,
			TLSMS:            phaseNotReached,
			RequestWrittenMS: phaseNotReached,
			FirstByteMS:      phaseNotReached,
		},
	}
}

// elapsedMS returns milliseconds since the call started, clamped at 0.
//
// start is written once at construction and never mutated, so reading it needs
// no lock.
func (r *timingRecorder) elapsedMS() int64 {
	delta := time.Since(r.start).Milliseconds()
	if delta < 0 {
		return 0
	}
	return delta
}

// update applies fn to the accumulated record under the lock. Once finish has
// closed the record, the update is dropped.
func (r *timingRecorder) update(fn func(*CallTiming)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finished {
		return
	}
	fn(&r.timing)
}

// markPhase records that phase completed now, storing its offset through set
// when the phase carries one. The phase name and its offset land in the same
// critical section, so a finished record can never hold one without the other.
func (r *timingRecorder) markPhase(phase string, set func(*CallTiming, int64)) {
	at := r.elapsedMS()
	r.update(func(t *CallTiming) {
		t.LastPhase = phase
		if set != nil {
			set(t, at)
		}
	})
}

// clientTrace builds the httptrace.ClientTrace for this call.
//
// Every callback writes through the recorder's locked helpers: the standard
// library invokes these from whichever goroutine owns the connection, and that
// is not always the goroutine that started the request.
func (r *timingRecorder) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) {
			r.markPhase(phaseGetConn, func(t *CallTiming, at int64) { t.GetConnMS = at })
		},
		GotConn: func(info httptrace.GotConnInfo) {
			r.update(func(t *CallTiming) { t.Reused = info.Reused })
		},
		DNSStart: func(httptrace.DNSStartInfo) {
			r.markPhase(phaseDNSStart, nil)
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			r.markPhase(phaseDNSDone, func(t *CallTiming, at int64) { t.DNSMS = at })
		},
		ConnectStart: func(string, string) {
			r.markPhase(phaseConnectStart, nil)
		},
		ConnectDone: func(string, string, error) {
			r.markPhase(phaseConnectDone, func(t *CallTiming, at int64) { t.ConnectMS = at })
		},
		TLSHandshakeStart: func() {
			r.markPhase(phaseTLSStart, nil)
		},
		TLSHandshakeDone: func(state tls.ConnectionState, _ error) {
			proto := normalizeProto(state)
			r.markPhase(phaseTLSDone, func(t *CallTiming, at int64) {
				t.TLSMS = at
				t.Proto = proto
			})
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			r.markPhase(phaseRequestWritten, func(t *CallTiming, at int64) { t.RequestWrittenMS = at })
		},
		GotFirstResponseByte: func() {
			r.markPhase(phaseFirstByte, func(t *CallTiming, at int64) { t.FirstByteMS = at })
		},
	}
}

// normalizeProto maps TLS state to the closed ALPN set.
func normalizeProto(state tls.ConnectionState) string {
	if callProtos[state.NegotiatedProtocol] {
		return state.NegotiatedProtocol
	}
	return ""
}

// finish completes the record with the outcome and hands it to the sink.
//
// The snapshot is taken under the lock and the recorder closed in the same
// critical section, so exactly one record is produced per call and no late
// callback can mutate it afterwards. The sink runs after the lock is released:
// a blocking observer must not stall an in-flight callback, and a panicking one
// must never change a purchase outcome, so the call is guarded. A sink failure
// is the caller's business; it cannot propagate here.
func (r *timingRecorder) finish(ctx context.Context, sink func(CallTiming), status int, err error) {
	total := r.elapsedMS()
	outcome := classifyOutcome(ctx, status, err)

	r.mu.Lock()
	if r.finished {
		// One record per request: a second finish (the error and body-read
		// paths are exclusive, but the guard keeps that a property of the
		// recorder rather than of its call sites) must not publish again.
		r.mu.Unlock()
		return
	}
	r.finished = true
	r.timing.TotalMS = total
	r.timing.Status = status
	r.timing.Outcome = outcome
	if r.timing.Proto == "" {
		// h1 has no ALPN; report the explicit value rather than "" so an
		// unnamed protocol is not confused with a failed handshake.
		r.timing.Proto = "http/1.1"
	}
	record := r.timing
	r.mu.Unlock()

	safeInvoke(sink, record)
}

// safeInvoke calls the sink with panic containment.
func safeInvoke(sink func(CallTiming), timing CallTiming) {
	if sink == nil {
		return
	}
	defer func() {
		// A panicking observer must not fail the provider call.
		_ = recover()
	}()
	sink(timing)
}

// callerOutcome reports whether the caller's own context ended the call.
//
// This is the discriminator that makes the deadline distinction possible:
// http.Client.Timeout enforces its limit through an internal context deadline,
// so a client timeout also satisfies errors.Is(err, context.DeadlineExceeded)
// and the error alone cannot tell the two apart.
func callerOutcome(ctx context.Context) (CallOutcome, bool) {
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return OutcomeCallerDeadline, true
	case context.Canceled:
		return OutcomeCallerCanceled, true
	default:
		return "", false
	}
}

// classifyOutcome maps the call result to the closed outcome set.
//
// Only the error's class is inspected; its text is never recorded.
func classifyOutcome(ctx context.Context, status int, err error) CallOutcome {
	if err == nil {
		if status < 200 || status > 299 {
			return OutcomeHTTPStatus
		}
		return OutcomeOK
	}
	if outcome, ended := callerOutcome(ctx); ended {
		return outcome
	}
	if errors.Is(err, context.Canceled) {
		return OutcomeCallerCanceled
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return OutcomeClientTimeout
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return OutcomeNetworkError
	}
	return OutcomeOtherError
}

// CallTimingMarker prefixes every provider call timing record. It is the anchor
// the offline collector searches for, so the record's keys/values are the only
// thing that ever leaves the panel.
const CallTimingMarker = "gigahost_call"

// TimingRecord describes a CallTiming as ordered key/value pairs for structured
// logging. Fixed keys, fixed value classes: nothing here can carry request data.
func TimingRecord(t CallTiming) []any {
	return []any{
		"method", t.Method,
		"op", t.Operation,
		"outcome", string(t.Outcome),
		"status", t.Status,
		"total_ms", t.TotalMS,
		"last_phase", t.LastPhase,
		"reused", t.Reused,
		"proto", t.Proto,
		"get_conn_ms", t.GetConnMS,
		"dns_ms", t.DNSMS,
		"connect_ms", t.ConnectMS,
		"tls_ms", t.TLSMS,
		"request_written_ms", t.RequestWrittenMS,
		"first_byte_ms", t.FirstByteMS,
	}
}

// phaseOffsets returns the record's phase offsets in a fixed order. The
// collector mirrors these names in the same order.
func phaseOffsets(t CallTiming) []int64 {
	return []int64{
		t.GetConnMS, t.DNSMS, t.ConnectMS, t.TLSMS, t.RequestWrittenMS, t.FirstByteMS,
	}
}

// ValidateTiming checks that a record contains only allowlisted classes and
// bounded values. It exists so a caller (and its tests) can assert the privacy
// contract directly instead of trusting construction.
func ValidateTiming(t CallTiming) error {
	enums := []struct {
		ok   bool
		what string
	}{
		{callMethods[t.Method], "method"},
		{callOutcomes[t.Outcome], "outcome"},
		{callPhaseNames[t.LastPhase], "last phase"},
		{callProtos[t.Proto], "proto"},
		{t.Status >= 0 && t.Status <= 599, "status"},
		{t.TotalMS >= 0 && t.TotalMS <= maxCallDurationMS, "duration"},
	}
	for _, e := range enums {
		if !e.ok {
			return fmt.Errorf("timing: %s not allowlisted or out of bounds", e.what)
		}
	}
	for _, phase := range phaseOffsets(t) {
		if phase < phaseNotReached || phase > maxCallDurationMS {
			return errors.New("timing: phase offset out of bounds")
		}
	}
	return nil
}

// maxCallDurationMS bounds every duration in a record (10 minutes).
const maxCallDurationMS int64 = 600000
