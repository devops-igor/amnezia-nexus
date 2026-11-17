package gatewaydns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// Unit coverage for the terminal-event emitter and its classification
// (issue #861, R9).
//
// The producer-level tests live in the vpn package, where a real client packet
// reaches the server. These cases pin the emitter's own rules: which kind is derived
// from a response, which overrides apply, and that an uninstalled observer records
// nothing at all.

// recordingEventObserver is both the route observer and the event observer, like the
// production cache: installing it wires both channels.
type recordingEventObserver struct {
	events []QueryEvent
	seen   int
}

func (o *recordingEventObserver) ObserveDNSResponse(string, *mdns.Msg, *mdns.Msg) error {
	o.seen++
	return nil
}

func (o *recordingEventObserver) ObserveDNSQueryEvent(event QueryEvent) {
	o.events = append(o.events, event)
}

func queryFor(name string, qtype uint16) *mdns.Msg {
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), qtype)
	return req
}

func scopeWithSession(sessionID string) *ScopeHandle {
	return &ScopeHandle{Scope: policy.Scope{SessionID: sessionID, OwnershipEpoch: 1}}
}

func answeredMessage(t *testing.T, name string) *mdns.Msg {
	t.Helper()
	req := queryFor(name, mdns.TypeA)
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &mdns.A{
		Hdr: mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
		A:   net.IPv4(93, 184, 216, 34),
	})
	return resp
}

func TestBuildQueryEventKinds(t *testing.T) {
	now := time.Now()
	session := scopeWithSession("sess-1")
	empty := new(mdns.Msg)
	empty.SetReply(queryFor("plain.example", mdns.TypeAAAA))
	nx := new(mdns.Msg)
	nx.SetRcode(queryFor("missing.example", mdns.TypeA), mdns.RcodeNameError)

	cases := []struct {
		name      string
		req       *mdns.Msg
		resp      *mdns.Msg
		outcome   QueryOutcome
		truncated bool
		delivered bool
		wantKind  string
		wantOK    bool
	}{
		{"Answered", queryFor("plain.example", mdns.TypeA), answeredMessage(t, "plain.example"), QueryOutcome{Kind: QueryEventAnswered}, false, true, QueryEventAnswered, true},
		{"NoAnswer", queryFor("plain.example", mdns.TypeAAAA), empty, QueryOutcome{Kind: QueryEventNoAnswer}, false, true, QueryEventNoAnswer, true},
		{"NXDomain", queryFor("missing.example", mdns.TypeA), nx, QueryOutcome{Kind: QueryEventNXDomain}, false, true, QueryEventNXDomain, true},
		{"Truncated", queryFor("plain.example", mdns.TypeA), answeredMessage(t, "plain.example"), QueryOutcome{Kind: QueryEventTruncated}, true, true, QueryEventTruncated, true},
		{"DeliveryFailed", queryFor("plain.example", mdns.TypeA), answeredMessage(t, "plain.example"), QueryOutcome{Kind: QueryEventAnswered}, false, false, QueryEventDeliveryFailed, true},
		{"AdmissionRefusedIsNotDeliveryFailure", queryFor("plain.example", mdns.TypeA), new(mdns.Msg), QueryOutcome{Kind: QueryEventAdmissionRefused}, false, false, QueryEventAdmissionRefused, true},
		{"InvalidQueryIsNotDeliveryFailure", queryFor("plain.example", mdns.TypeA), new(mdns.Msg), QueryOutcome{Kind: QueryEventInvalidQuery}, false, false, QueryEventInvalidQuery, true},
		{"NoQuestion", new(mdns.Msg), answeredMessage(t, "plain.example"), QueryOutcome{Kind: QueryEventAnswered}, false, true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event, ok := buildQueryEvent(session, tc.req, tc.resp, tc.outcome, "udp", tc.truncated, tc.delivered, now, now)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if event.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", event.Kind, tc.wantKind)
			}
			if event.SessionID != "sess-1" {
				t.Errorf("session = %q, want the scope's session", event.SessionID)
			}
			if event.Transport != "udp" {
				t.Errorf("transport = %q, want udp", event.Transport)
			}
			if event.Name == "" || event.ReceivedAt.IsZero() || event.AnsweredAt.IsZero() {
				t.Errorf("event = %+v, want a name and both instants", event)
			}
		})
	}
}

func TestEmitQueryEventWithoutAnObserverIsInert(t *testing.T) {
	server := &Server{}
	if server.QueryEventObserver() != nil {
		t.Fatal("a fresh server has an event observer")
	}
	server.emitQueryEvent(scopeWithSession("s"), queryFor("plain.example", mdns.TypeA), new(mdns.Msg), QueryOutcome{Kind: QueryEventAnswered}, "udp", false, true, time.Now(), time.Now(), 7, true)
	// Nothing to assert beyond not panicking: the absence of an observer is the
	// contract, and it is checked above.
}

func TestSetObserverInstallsBothChannels(t *testing.T) {
	server := &Server{}
	observer := &recordingEventObserver{}
	server.SetObserver(observer)
	if server.QueryEventObserver() == nil {
		t.Fatal("installing the route observer did not install the event observer")
	}
	server.emitQueryEvent(nil, queryFor("plain.example", mdns.TypeA), new(mdns.Msg), QueryOutcome{Kind: QueryEventAnswered}, "tcp", false, true, time.Now(), time.Now(), 0, false)
	if len(observer.events) != 1 {
		t.Fatalf("events = %d, want the one emitted query", len(observer.events))
	}
	if observer.events[0].Transport != "tcp" || observer.events[0].SessionID != "" {
		t.Errorf("event = %+v, want tcp with no session", observer.events[0])
	}
	if observer.events[0].IncarnationKnown {
		t.Error("an unknown receipt incarnation was reported as known")
	}

	// Clearing the observer clears both channels.
	server.SetObserver(nil)
	if server.QueryEventObserver() != nil {
		t.Error("clearing the route observer left the event observer installed")
	}
}

func TestClassifyUpstreamError(t *testing.T) {
	cases := map[string]error{
		"":                   nil,
		UpstreamErrorTimeout: context.DeadlineExceeded,
		UpstreamErrorRefused: net.ErrClosed,
		UpstreamErrorOther:   errors.New("boom"),
	}
	for want, err := range cases {
		if got := classifyUpstreamError(err); got != want {
			t.Errorf("classifyUpstreamError(%v) = %q, want %q", err, got, want)
		}
	}
	if got := classifyUpstreamError(timeoutErr{}); got != UpstreamErrorTimeout {
		t.Errorf("a timeout error classified as %q, want %q", got, UpstreamErrorTimeout)
	}
}

// timeoutErr implements the net timeout interface without being context.Deadline.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
