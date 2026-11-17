package gatewaydns

import (
	"context"
	"errors"
	"net"
	"time"

	mdns "github.com/miekg/dns"
)

// Terminal query events (issue #861, R9).
//
// One event is emitted per client DNS query that this build can observe, after the
// reply has been written (or refused). The event states what actually happened to
// that query: the client transport, the times, the response code, whether the
// answer was shaped truncated, whether it was delivered, and, when the query never
// reached an upstream answer, why.
//
// Two boundaries matter and are not blurred:
//
//   - An event is DIAGNOSTIC HISTORY. It never creates route evidence. The route
//     cache is still written only by ObserveResponseWithSessionID, which requires a
//     non-truncated NOERROR answer and runs the classifier once. A failed, refused,
//     truncated or non-A query can therefore never become trusted because it was
//     recorded here.
//   - "Transport" is the CLIENT transport (UDP or TCP as the client sent it). The
//     upstream hop's transport and identity are not guessed; when they matter they
//     are reported as unknown.

// Terminal event kinds. They are tokens: the API and UI translate them.
const (
	// QueryEventAnswered means a response with at least one answer record was
	// delivered to the client.
	QueryEventAnswered = "answered"
	// QueryEventNoAnswer means a NOERROR response carried no answer records (for
	// example AAAA for a name with only A records). It is not an error.
	QueryEventNoAnswer = "no_answer"
	// QueryEventNXDomain means the upstream answered NXDOMAIN.
	QueryEventNXDomain = "nxdomain"
	// QueryEventAdmissionRefused means the server refused the query before asking
	// an upstream: the per-session or global inflight budget was exhausted.
	QueryEventAdmissionRefused = "admission_refused"
	// QueryEventUpstreamError means the upstream exchange failed (timeout,
	// refusal or transport error), so the client received SERVFAIL.
	QueryEventUpstreamError = "upstream_error"
	// QueryEventInvalidQuery means the query was rejected before resolution
	// (unsupported opcode or type such as AXFR/ANY).
	QueryEventInvalidQuery = "invalid_query"
	// QueryEventTruncated means the response was shaped truncated because it
	// exceeded the client's UDP size, so the client must retry over TCP.
	QueryEventTruncated = "truncated"
	// QueryEventDeliveryFailed means a response was produced but the reply could
	// not be written to the client. The query was not observed by any consumer.
	QueryEventDeliveryFailed = "delivery_failed"
)

// Upstream error classes. They describe the exchange that failed, not the client.
const (
	UpstreamErrorTimeout = "timeout"
	UpstreamErrorRefused = "refused"
	UpstreamErrorOther   = "error"
)

// QueryOutcome is what the server did with one query, before the transport handler
// shapes and delivers the reply.
type QueryOutcome struct {
	// Kind is one of the QueryEvent* tokens, except the transport-level ones
	// (truncated, delivery_failed) which the transport handler decides.
	Kind string
	// UpstreamError classifies a failed exchange, empty when none failed.
	UpstreamError string
}

// QueryEvent is one terminal client DNS query, as the router actually saw it.
type QueryEvent struct {
	SessionID     string
	Transport     string
	Name          string
	QType         uint16
	RCode         int
	Kind          string
	UpstreamError string
	Truncated     bool
	Delivered     bool
	ReceivedAt    time.Time
	AnsweredAt    time.Time
	// RouteGeneration is the incarnation registered when the QUERY ARRIVED, not
	// when the event was emitted. A successor that reused the session id must never
	// inherit the record.
	RouteGeneration uint64
	// IncarnationKnown reports whether that incarnation could be established.
	IncarnationKnown bool
	// PolicyGeneration is the published generation at receipt.
	PolicyGeneration string
}

// QueryEventObserver records terminal query events. It is optional: a server
// without one records nothing, and the trust path does not depend on it.
type QueryEventObserver interface {
	ObserveDNSQueryEvent(event QueryEvent)
}

// QueryReceiptBinder stamps the incarnation a query arrived under, AT RECEIPT.
//
// A terminal event is emitted after the reply has been produced and written, which
// can be long after the query arrived. Resolving the incarnation at emit time would
// credit whatever session owns the id by then — a successor that reused it — so the
// lookup happens once at receipt and travels with the event. Implementations must be
// read-only and must not allocate a scope.
type QueryReceiptBinder interface {
	BindQueryIncarnation(sessionID string) (generation uint64, known bool)
}

// QueryReceipt is the session lifetime a query was received under, captured once at
// receipt and carried by everything that query later produces: its terminal event and its
// answer observation. A delayed handler therefore attributes its result to the lifetime
// that received the query, not to one that reused the session id in the meantime.
//
// Known is false when no incarnation was established at receipt. Such a receipt carries
// no lifetime authority, and a consumer must not replace it with the generation that
// happens to be registered when the delayed write runs.
type QueryReceipt struct {
	Generation uint64
	Known      bool
}

// queryReceipt resolves the receipt authority for one query, once, before the exchange.
func (s *Server) queryReceipt(observer QueryEventObserver, sessionID string) QueryReceipt {
	generation, known := s.bindQueryIncarnation(observer, sessionID)
	return QueryReceipt{Generation: generation, Known: known}
}

// bindQueryIncarnation asks the installed observer for the receipt incarnation, or
// reports that it cannot be established. It is a no-op without a binder.
func (s *Server) bindQueryIncarnation(observer QueryEventObserver, sessionID string) (uint64, bool) {
	if observer == nil || sessionID == "" {
		return 0, false
	}
	binder, ok := observer.(QueryReceiptBinder)
	if !ok {
		return 0, false
	}
	return binder.BindQueryIncarnation(sessionID)
}

// classifyUpstreamError names the class of a failed upstream exchange without
// guessing at the resolver's internal state: a deadline is a timeout, a refused
// connection is a refusal, everything else is an error.
func classifyUpstreamError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), isTimeout(err):
		return UpstreamErrorTimeout
	case errors.Is(err, net.ErrClosed), errors.Is(err, errors.ErrUnsupported):
		return UpstreamErrorRefused
	default:
		return UpstreamErrorOther
	}
}

// isTimeout reports whether the error implements the net timeout interface.
func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// queryEventKind classifies a response the server produced, before the transport
// handler knows whether it was delivered.
//
// It measures ONE thing: whether the answer section is empty. It does not compare
// the records' type to the question, and it must not pretend to: an HTTPS query
// answered with an SVCB record is `answered`, a query whose answer section is empty
// is `no_answer`, and neither statement says anything about A evidence. Whether a
// response may become route evidence is the classifier's decision, not this one's.
func queryEventKind(resp *mdns.Msg) string {
	if resp == nil {
		return QueryEventUpstreamError
	}
	switch resp.Rcode {
	case mdns.RcodeNameError:
		return QueryEventNXDomain
	case mdns.RcodeSuccess:
		if len(resp.Answer) == 0 {
			return QueryEventNoAnswer
		}
		return QueryEventAnswered
	default:
		return QueryEventUpstreamError
	}
}
