package gigahost

// Progress semantics of CallTiming.LastPhase.
//
// httptrace promises no ordering between its hooks: the standard library calls
// them from whichever goroutine owns the connection. Over HTTP/2 the request is
// written on the per-stream write goroutine while the response headers are read
// on the connection's read loop, so a fast server can deliver the first response
// byte before the request has been reported as fully written. The record must
// still describe the furthest phase the call reached, because that is the
// question the record exists to answer when a call stalls or fails.
//
// These tests fix the callback arrival order deterministically and drive the
// production recorder, its client trace and its finish path. The oracle stays
// outside the recorder: every assertion is about the published record.

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"
)

// phaseStepGap separates the fixed arrivals so each phase carries a
// distinguishable millisecond offset.
const phaseStepGap = 10 * time.Millisecond

// firePhase drives one named trace callback through the recorder's own
// ClientTrace, so a test controls arrival order without a transport.
func firePhase(t *testing.T, trace *httptrace.ClientTrace, phase string) {
	t.Helper()
	switch phase {
	case phaseGetConn:
		trace.GetConn("127.0.0.1:443")
	case phaseRequestWritten:
		trace.WroteRequest(httptrace.WroteRequestInfo{})
	case phaseFirstByte:
		trace.GotFirstResponseByte()
	default:
		t.Fatalf("firePhase: unsupported phase %q", phase)
	}
}

// publishCall fires the named phases in exactly this order, with a measurable
// gap between them, then publishes the record through the production finish
// path. It also fires both response callbacks after publication and repeats
// finish, which pins the lifecycle contract: exactly one immutable record.
func publishCall(t *testing.T, order ...string) CallTiming {
	t.Helper()

	var published []CallTiming
	recorder := newTimingRecorder(http.MethodGet, "/servers")
	trace := recorder.clientTrace()
	for _, phase := range order {
		firePhase(t, trace, phase)
		time.Sleep(phaseStepGap)
	}

	sink := func(record CallTiming) { published = append(published, record) }
	recorder.finish(context.Background(), sink, http.StatusOK, nil)
	if len(published) != 1 {
		t.Fatalf("published %d records, want exactly 1", len(published))
	}
	before := published[0]

	// Callbacks keep arriving from connection goroutines after the request
	// goroutine has published; none of them may reach the record.
	trace.WroteRequest(httptrace.WroteRequestInfo{})
	trace.GotFirstResponseByte()
	recorder.finish(context.Background(), sink, http.StatusOK, nil)

	if len(published) != 1 {
		t.Fatalf("published %d records after late callbacks, want exactly 1", len(published))
	}
	if published[0] != before {
		t.Fatalf("published record changed after late callbacks:\n got %+v\nwant %+v", published[0], before)
	}
	return published[0]
}

// requireResponsePhases fails when a record lost a response phase that did fire.
func requireResponsePhases(t *testing.T, record CallTiming) {
	t.Helper()
	if record.RequestWrittenMS == phaseNotReached || record.FirstByteMS == phaseNotReached {
		t.Fatalf("expected both response phases in the record, got %+v", record)
	}
}

// TestTimingReversedResponseArrivalStillReportsFirstByte is the retained
// counterexample. A served response whose first byte is traced before the
// request-written callback must still publish first_byte as the furthest phase,
// with both measured offsets intact and in their real arrival order.
func TestTimingReversedResponseArrivalStillReportsFirstByte(t *testing.T) {
	record := publishCall(t, phaseGetConn, phaseFirstByte, phaseRequestWritten)
	requireResponsePhases(t, record)

	if record.FirstByteMS >= record.RequestWrittenMS {
		t.Errorf("offsets = first_byte %d ms, request_written %d ms; each offset must keep its own measurement",
			record.FirstByteMS, record.RequestWrittenMS)
	}
	if record.LastPhase != phaseFirstByte {
		t.Errorf("last phase = %q, want %q after a served response", record.LastPhase, phaseFirstByte)
	}
	if err := ValidateTiming(record); err != nil {
		t.Errorf("record failed its own validation: %v", err)
	}
}

// TestTimingProtocolOrderArrivalReportsFirstByte is the positive control: when
// the callbacks do arrive in protocol order the same assertion holds, so the
// correction is not reaching the answer by fiat.
func TestTimingProtocolOrderArrivalReportsFirstByte(t *testing.T) {
	record := publishCall(t, phaseGetConn, phaseRequestWritten, phaseFirstByte)
	requireResponsePhases(t, record)

	if record.RequestWrittenMS >= record.FirstByteMS {
		t.Errorf("offsets = request_written %d ms, first_byte %d ms; each offset must keep its own measurement",
			record.RequestWrittenMS, record.FirstByteMS)
	}
	if record.LastPhase != phaseFirstByte {
		t.Errorf("last phase = %q, want %q after a served response", record.LastPhase, phaseFirstByte)
	}
	if err := ValidateTiming(record); err != nil {
		t.Errorf("record failed its own validation: %v", err)
	}
}

// TestTimingNeverReportsAPhaseThatWasNotReached is the counterweight to the
// counterexample: progress must not be manufactured. A phase that never fired
// stays absent from both LastPhase and its offset, whatever order the other
// callbacks arrived in. The stall and failure paths depend on this - "the
// furthest phase reached" is only useful if it can still name an early one.
func TestTimingNeverReportsAPhaseThatWasNotReached(t *testing.T) {
	t.Run("response first byte never arrived", func(t *testing.T) {
		record := publishCall(t, phaseGetConn, phaseRequestWritten)

		if record.LastPhase != phaseRequestWritten {
			t.Errorf("last phase = %q, want %q (the server never answered)", record.LastPhase, phaseRequestWritten)
		}
		if record.FirstByteMS != phaseNotReached {
			t.Errorf("first byte = %d, want the not-reached sentinel", record.FirstByteMS)
		}
		if err := ValidateTiming(record); err != nil {
			t.Errorf("record failed its own validation: %v", err)
		}
	})

	t.Run("request written never arrived", func(t *testing.T) {
		record := publishCall(t, phaseGetConn, phaseFirstByte)

		if record.LastPhase != phaseFirstByte {
			t.Errorf("last phase = %q, want %q", record.LastPhase, phaseFirstByte)
		}
		if record.RequestWrittenMS != phaseNotReached {
			t.Errorf("request written = %d, want the not-reached sentinel", record.RequestWrittenMS)
		}
		if err := ValidateTiming(record); err != nil {
			t.Errorf("record failed its own validation: %v", err)
		}
	})

	t.Run("neither response phase arrived", func(t *testing.T) {
		record := publishCall(t, phaseGetConn)

		if record.LastPhase != phaseGetConn {
			t.Errorf("last phase = %q, want %q", record.LastPhase, phaseGetConn)
		}
		if record.FirstByteMS != phaseNotReached || record.RequestWrittenMS != phaseNotReached {
			t.Errorf("response phases = first_byte %d, request_written %d, want both not reached",
				record.FirstByteMS, record.RequestWrittenMS)
		}
	})

	t.Run("no phase arrived", func(t *testing.T) {
		record := publishCall(t)

		if record.LastPhase != "" {
			t.Errorf("last phase = %q, want the empty value when nothing completed", record.LastPhase)
		}
		if err := ValidateTiming(record); err != nil {
			t.Errorf("record failed its own validation: %v", err)
		}
	})
}
