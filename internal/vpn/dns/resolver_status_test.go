package gatewaydns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
)

// answerHandler answers every query with one A record holding ip.
func answerHandler(t *testing.T, ip string) mdns.Handler {
	t.Helper()
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip).To4(),
		})
		_ = w.WriteMsg(m)
	})
}

// slowHandler never answers within the attempt deadline: it sleeps first and
// then writes, so the query can only end in a timeout.
func slowHandler(delay time.Duration) mdns.Handler {
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		time.Sleep(delay)
		m := new(mdns.Msg)
		m.SetReply(req)
		_ = w.WriteMsg(m)
	})
}

func servfailHandler(hits *atomic.Int32) mdns.Handler {
	return mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		if hits != nil {
			hits.Add(1)
		}
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Rcode = mdns.RcodeServerFailure
		_ = w.WriteMsg(m)
	})
}

func testQuery(name string) *mdns.Msg {
	req := new(mdns.Msg)
	req.SetQuestion(name, mdns.TypeA)
	req.Id = 4242
	return req
}

// TestResolver_PrimaryTimeoutThenAlternateSuccess pins the per-attempt budget:
// the primary is abandoned inside its own deadline and the alternate answers the
// same query.
func TestResolver_PrimaryTimeoutThenAlternateSuccess(t *testing.T) {
	slow := startMockServer(t, slowHandler(300*time.Millisecond))
	alternate := startMockServer(t, answerHandler(t, "203.0.113.10"))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(slow.udpAddr), upstreamOf(alternate.udpAddr)},
		QueryTimeout:          3 * time.Second,
		AttemptTimeout:        80 * time.Millisecond,
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	start := time.Now()
	resp, err := r.Exchange(context.Background(), testQuery("failover.example."))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1 from the alternate", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.10" {
		t.Fatalf("answer = %v, want the alternate's 203.0.113.10", resp.Answer[0])
	}
	if elapsed < 60*time.Millisecond {
		t.Fatalf("primary was abandoned after %v, shorter than the per-attempt deadline", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("failover took %v, longer than the per-attempt deadline allows", elapsed)
	}

	status := r.Status()
	if status.LastUpstream != alternate.udpAddr.String() {
		t.Fatalf("last upstream = %q, want the alternate %q", status.LastUpstream, alternate.udpAddr.String())
	}
	if status.LastFailure != "" || status.LastFailureKind != "" {
		t.Fatalf("a successful exchange reported a failure: %+v", status)
	}
}

// TestResolver_TransportFailureIsNotAnEmptyAnswer proves a failing transport is
// an error, never a valid empty answer that the caller could treat as NODATA.
func TestResolver_TransportFailureIsNotAnEmptyAnswer(t *testing.T) {
	slow := startMockServer(t, slowHandler(300*time.Millisecond))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(slow.udpAddr)},
		QueryTimeout:          3 * time.Second,
		AttemptTimeout:        40 * time.Millisecond,
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	resp, err := r.Exchange(context.Background(), testQuery("blocked.example."))
	if err == nil {
		t.Fatal("Exchange() = nil error, want a transport failure")
	}
	if resp != nil {
		t.Fatalf("Exchange() returned a message (%v) on a transport failure", resp)
	}
}

// TestResolver_StatusRecordsTimeoutKind is the operator-facing half of the
// bug: a blocked provider must be reported as a failure with a kind, not as an
// absence of evidence.
func TestResolver_StatusRecordsTimeoutKind(t *testing.T) {
	slow := startMockServer(t, slowHandler(300*time.Millisecond))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(slow.udpAddr)},
		QueryTimeout:          3 * time.Second,
		AttemptTimeout:        40 * time.Millisecond,
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	if _, err := r.Exchange(context.Background(), testQuery("blocked.example.")); err == nil {
		t.Fatal("Exchange() = nil error, want a timeout")
	}

	status := r.Status()
	if status.LastFailureKind != FailureTimeout {
		t.Fatalf("failure kind = %q, want %q", status.LastFailureKind, FailureTimeout)
	}
	if status.LastFailure != slow.udpAddr.String() {
		t.Fatalf("failing upstream = %q, want %q", status.LastFailure, slow.udpAddr.String())
	}
	if status.LastUpstream != "" {
		t.Fatalf("last upstream = %q, want empty before any accepted answer", status.LastUpstream)
	}
}

// TestResolver_StatusSuccessClearsFailure covers the recovery direction: after a
// failure, one good answer clears the failure and names the upstream that served.
func TestResolver_StatusSuccessClearsFailure(t *testing.T) {
	slow := startMockServer(t, slowHandler(300*time.Millisecond))
	good := startMockServer(t, answerHandler(t, "203.0.113.11"))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(slow.udpAddr)},
		QueryTimeout:          3 * time.Second,
		AttemptTimeout:        40 * time.Millisecond,
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	if _, err := r.Exchange(context.Background(), testQuery("before.example.")); err == nil {
		t.Fatal("Exchange() = nil error, want a timeout")
	}
	if got := r.Status().LastFailureKind; got != FailureTimeout {
		t.Fatalf("failure kind = %q, want %q", got, FailureTimeout)
	}

	if err := r.SetUpstreams([]policy.Upstream{upstreamOf(good.udpAddr)}); err != nil {
		t.Fatalf("SetUpstreams: %v", err)
	}
	if _, err := r.Exchange(context.Background(), testQuery("after.example.")); err != nil {
		t.Fatalf("Exchange after recovery failed: %v", err)
	}

	status := r.Status()
	if status.LastFailure != "" || status.LastFailureKind != "" {
		t.Fatalf("a successful exchange left the failure state set: %+v", status)
	}
	if status.LastUpstream != good.udpAddr.String() {
		t.Fatalf("last upstream = %q, want %q", status.LastUpstream, good.udpAddr.String())
	}
}

// TestResolver_ServfailWithoutAlternateIsATerminalAnswer preserves the existing
// SERVFAIL semantic: with no alternate left it is answered to the client, not
// turned into an error, and the surviving upstream is named.
func TestResolver_ServfailWithoutAlternateIsATerminalAnswer(t *testing.T) {
	var hits atomic.Int32
	primary := startMockServer(t, servfailHandler(&hits))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(primary.udpAddr)},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	resp, err := r.Exchange(context.Background(), testQuery("servfail.example."))
	if err != nil {
		t.Fatalf("Exchange() = %v, want the SERVFAIL answer", err)
	}
	if resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("rcode = %v, want SERVFAIL", resp.Rcode)
	}
	if hits.Load() != 1 {
		t.Fatalf("primary hits = %d, want 1", hits.Load())
	}
}

// TestResolver_RejectsNonPlainTransport is the no-downgrade shape for the
// encrypted transports: an entry configured for DoT or DoH is refused, so the
// plain path can never be used for it.
func TestResolver_RejectsNonPlainTransport(t *testing.T) {
	for _, transport := range []policy.UpstreamTransport{policy.TransportDoT, policy.TransportDoH} {
		t.Run(string(transport), func(t *testing.T) {
			_, err := NewUpstreamResolver(ResolverConfig{
				Upstreams: []policy.Upstream{{Address: "94.140.14.14", Port: 53, Transport: transport}},
			})
			if err == nil {
				t.Fatalf("NewUpstreamResolver accepted transport %q", transport)
			}
			if !errors.Is(err, ErrUnsupportedTransport) {
				t.Fatalf("error = %v, want it to wrap ErrUnsupportedTransport", err)
			}
		})
	}
}

// TestResolver_AcceptsHostnameAndIPv6Targets covers the address shapes the plain
// transport permits. No exchange is attempted, so this needs no network.
func TestResolver_AcceptsHostnameAndIPv6Targets(t *testing.T) {
	_, err := NewUpstreamResolver(ResolverConfig{
		Upstreams: []policy.Upstream{
			{Address: "dns.example.com", Port: 53},
			{Address: "2001:db8::53", Port: 53},
		},
	})
	if err != nil {
		t.Fatalf("NewUpstreamResolver(hostname, ipv6) = %v, want nil", err)
	}
}

// TestResolver_SetUpstreamsSwapsList proves a live configuration change takes
// effect without rebuilding the resolver.
func TestResolver_SetUpstreamsSwapsList(t *testing.T) {
	first := startMockServer(t, answerHandler(t, "203.0.113.20"))
	second := startMockServer(t, answerHandler(t, "203.0.113.21"))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(first.udpAddr)},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	if _, err := r.Exchange(context.Background(), testQuery("one.example.")); err != nil {
		t.Fatalf("Exchange before swap failed: %v", err)
	}
	if got := r.Status().LastUpstream; got != first.udpAddr.String() {
		t.Fatalf("last upstream before swap = %q, want %q", got, first.udpAddr.String())
	}

	if err := r.SetUpstreams([]policy.Upstream{upstreamOf(second.udpAddr)}); err != nil {
		t.Fatalf("SetUpstreams: %v", err)
	}
	upstreams := r.Upstreams()
	if len(upstreams) != 1 || upstreams[0].Address != second.udpAddr.Addr().String() {
		t.Fatalf("Upstreams() = %v, want only %v", upstreams, second.udpAddr)
	}

	resp, err := r.Exchange(context.Background(), testQuery("two.example."))
	if err != nil {
		t.Fatalf("Exchange after swap failed: %v", err)
	}
	if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.21" {
		t.Fatalf("answer after swap = %v, want 203.0.113.21", resp.Answer[0])
	}
	if got := r.Status().LastUpstream; got != second.udpAddr.String() {
		t.Fatalf("last upstream after swap = %q, want %q", got, second.udpAddr.String())
	}
}

// TestResolver_SetUpstreamsRejectsInvalidWithoutPublishing proves a rejected
// change leaves the working upstream list in place.
func TestResolver_SetUpstreamsRejectsInvalidWithoutPublishing(t *testing.T) {
	good := startMockServer(t, answerHandler(t, "203.0.113.30"))
	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(good.udpAddr)},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	if err := r.SetUpstreams(nil); !errors.Is(err, ErrNoUpstreams) {
		t.Fatalf("SetUpstreams(nil) = %v, want ErrNoUpstreams", err)
	}
	if err := r.SetUpstreams([]policy.Upstream{{Address: "224.0.0.1", Port: 53}}); !errors.Is(err, ErrInvalidUpstream) {
		t.Fatalf("SetUpstreams(multicast) = %v, want ErrInvalidUpstream", err)
	}

	upstreams := r.Upstreams()
	if len(upstreams) != 1 || upstreams[0].Address != good.udpAddr.Addr().String() {
		t.Fatalf("Upstreams() = %v, want the previous working list", upstreams)
	}
	if _, err := r.Exchange(context.Background(), testQuery("still-works.example.")); err != nil {
		t.Fatalf("Exchange after a rejected change failed: %v", err)
	}
}

// TestResolver_EnvelopeMismatchFailsOver covers the reply that must never reach
// the client: a response whose question does not match the query is an invalid
// answer, so the resolver fails over to the alternate and, with no alternate
// left, reports a transport-class failure instead of returning it.
func TestResolver_EnvelopeMismatchFailsOver(t *testing.T) {
	mismatched := startMockServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(req)
		m.Question[0].Name = "other.example."
		m.Answer = append(m.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: "other.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.50").To4(),
		})
		_ = w.WriteMsg(m)
	}))
	alternate := startMockServer(t, answerHandler(t, "203.0.113.51"))

	r, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(mismatched.udpAddr), upstreamOf(alternate.udpAddr)},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	resp, err := r.Exchange(context.Background(), testQuery("mismatch.example."))
	if err != nil {
		t.Fatalf("Exchange failed instead of failing over: %v", err)
	}
	if a, ok := resp.Answer[0].(*mdns.A); !ok || a.A.String() != "203.0.113.51" {
		t.Fatalf("answer = %v, want the alternate's 203.0.113.51", resp.Answer[0])
	}
	if got := r.Status().LastUpstream; got != alternate.udpAddr.String() {
		t.Fatalf("last upstream = %q, want %q", got, alternate.udpAddr.String())
	}

	// With no alternate left the mismatched reply is a failure, never an answer.
	solo, err := NewUpstreamResolver(ResolverConfig{
		Upstreams:             []policy.Upstream{upstreamOf(mismatched.udpAddr)},
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}
	if resp, err := solo.Exchange(context.Background(), testQuery("mismatch.example.")); err == nil || resp != nil {
		t.Fatalf("Exchange() = (%v, %v), want an error and no answer", resp, err)
	}
}
