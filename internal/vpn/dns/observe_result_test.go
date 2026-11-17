package gatewaydns

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// Coverage for the observation result (issue #861, slice 2).
//
// The result is what a DNS record is built from, so the property that matters is
// that it reports exactly what the observation path did: the same evidence
// ObserveResponse returns, the classifier's own verdict, and a cache refusal when
// the evidence could not be stored. It must never be a second opinion.

type observeFixture struct {
	snapshot *policy.Snapshot
	session  *policy.SessionCache
	rc       *policy.RouteCache
}

func newObserveFixture(t *testing.T, name string) *observeFixture {
	t.Helper()
	rc, err := policy.NewRouteCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("NewRouteCache: %v", err)
	}
	rc.SetPolicyGeneration("gen-1")
	rules := policy.ParsedRules{}
	if name != "" {
		parsed, _, err := policy.Parse(context.Background(), strings.NewReader(name+"\n"), policy.Source{
			ID:             "test",
			Format:         policy.FormatDomains,
			BareDomainMode: policy.DomainModeInclusiveSuffix,
		}, policy.DefaultParseLimits())
		if err != nil {
			t.Fatalf("policy Parse: %v", err)
		}
		rules = parsed
	}
	snapshot, err := policy.CompileSnapshot(1, "gen-1", []policy.SourceParsedRules{
		{SourceID: "test", Rules: rules},
	})
	if err != nil {
		t.Fatalf("CompileSnapshot: %v", err)
	}
	session, err := rc.Open(policy.Scope{SessionID: "sess-1", OwnershipEpoch: 1})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return &observeFixture{snapshot: snapshot, session: session, rc: rc}
}

func queryA(name string) *mdns.Msg {
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	return req
}

func answerA(req *mdns.Msg, addresses ...string) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	for _, address := range addresses {
		ip := netip.MustParseAddr(address)
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   ip.AsSlice(),
		})
	}
	return resp
}

func TestObserveResponseResultMatchesTheLegacyReturn(t *testing.T) {
	now := time.Now()
	req := queryA("plain.example")
	resp := answerA(req, "93.184.216.34")

	first := newObserveFixture(t, "")
	second := newObserveFixture(t, "")

	result, err := ObserveResponseResult(req, resp, first.snapshot, first.session, now, time.Hour)
	if err != nil {
		t.Fatalf("ObserveResponseResult: %v", err)
	}
	legacy, legacyErr := ObserveResponse(req, resp, second.snapshot, second.session, now, time.Hour)
	if (legacyErr == nil) != (err == nil) {
		t.Fatalf("legacy error = %v, result error = %v", legacyErr, err)
	}
	if len(result.Observations) != len(legacy) || len(legacy) != 1 {
		t.Fatalf("result observations = %d, legacy = %d, want 1 each", len(result.Observations), len(legacy))
	}
	if result.Observations[0] != legacy[0] {
		t.Errorf("result observation %+v, legacy %+v: the two paths must report the same evidence", result.Observations[0], legacy[0])
	}
	if !result.ExpiresAt.Equal(result.Observations[0].ExpiresAt) || result.ExpiresAt.IsZero() {
		t.Errorf("expires at = %v, want the written deadline %v", result.ExpiresAt, result.Observations[0].ExpiresAt)
	}
	if !result.Classification.Valid || len(result.Classification.Names) != 1 || result.Classification.Names[0] != "plain.example" {
		t.Errorf("classification = %+v, want a valid answer for plain.example", result.Classification)
	}
	if result.QName != "plain.example." || result.QType != mdns.TypeA || result.RCode != mdns.RcodeSuccess {
		t.Errorf("envelope = %q/%d/%d, want the query as received", result.QName, result.QType, result.RCode)
	}
	if !result.RecvTime.Equal(now) {
		t.Errorf("recv time = %v, want the caller's instant", result.RecvTime)
	}
	if result.CacheErr != nil {
		t.Errorf("cache error = %v, want the evidence accepted", result.CacheErr)
	}
	// The evidence really was written: the session can answer for the address.
	if got := first.session.Lookup(netip.MustParseAddr("93.184.216.34"), "gen-1", now); got != policy.Direct {
		t.Errorf("stored decision = %v, want DIRECT", got)
	}
}

func TestObserveResponseResultAppliesDomainRules(t *testing.T) {
	now := time.Now()
	req := queryA("blocked.example")
	resp := answerA(req, "93.184.216.34")

	f := newObserveFixture(t, "blocked.example")
	result, err := ObserveResponseResult(req, resp, f.snapshot, f.session, now, time.Hour)
	if err != nil {
		t.Fatalf("ObserveResponseResult: %v", err)
	}
	if len(result.Observations) != 1 {
		t.Fatalf("observations = %d, want 1", len(result.Observations))
	}
	if result.Observations[0].Decision != policy.Proxy {
		t.Errorf("decision = %v, want PROXY for a name a rule matches", result.Observations[0].Decision)
	}
}

func TestObserveResponseResultReportsRejectedAnswers(t *testing.T) {
	now := time.Now()

	t.Run("NonAQuery", func(t *testing.T) {
		req := new(mdns.Msg)
		req.SetQuestion(mdns.Fqdn("plain.example"), mdns.TypeAAAA)
		resp := new(mdns.Msg)
		resp.SetReply(req)

		f := newObserveFixture(t, "")
		result, err := ObserveResponseResult(req, resp, f.snapshot, f.session, now, time.Hour)
		if err != nil {
			t.Fatalf("ObserveResponseResult: %v", err)
		}
		if result.Classification.Valid || result.Classification.Reason == "" {
			t.Errorf("classification = %+v, want invalid with a reason", result.Classification)
		}
		if len(result.Observations) != 0 || !result.ExpiresAt.IsZero() {
			t.Error("a rejected answer must produce no evidence and no deadline")
		}
		if result.QType != mdns.TypeAAAA {
			t.Errorf("qtype = %d, want the queried type %d", result.QType, mdns.TypeAAAA)
		}
		if result.QName != "plain.example." {
			t.Errorf("qname = %q, want the queried name (the answer itself names nothing)", result.QName)
		}
	})

	t.Run("NoAddresses", func(t *testing.T) {
		req := queryA("empty.example")
		resp := new(mdns.Msg)
		resp.SetReply(req)

		f := newObserveFixture(t, "")
		result, _ := ObserveResponseResult(req, resp, f.snapshot, f.session, now, time.Hour)
		if !result.Classification.Valid {
			t.Errorf("an empty answer is a valid answer, got reason %q", result.Classification.Reason)
		}
		if len(result.Observations) != 0 {
			t.Error("an answer with no address must write no evidence")
		}
		if len(result.Classification.Names) != 1 {
			t.Errorf("names = %v, want the queried name to stay reported", result.Classification.Names)
		}
	})
}

func TestObserveResponseResultReportsCacheRefusal(t *testing.T) {
	now := time.Now()
	req := queryA("plain.example")
	resp := answerA(req, "93.184.216.34")

	f := newObserveFixture(t, "")
	f.session.Invalidate()

	result, err := ObserveResponseResult(req, resp, f.snapshot, f.session, now, time.Hour)
	if err == nil || result.CacheErr == nil {
		t.Fatalf("a retired scope must report its refusal: err=%v cacheErr=%v", err, result.CacheErr)
	}
	// The observations are still reported: they describe what the observation
	// path decided, and the record keeps that verdict instead of hiding it.
	if len(result.Observations) != 1 {
		t.Errorf("observations = %d, want the decision that was refused", len(result.Observations))
	}
	if got := f.session.Lookup(netip.MustParseAddr("93.184.216.34"), "gen-1", now); got != policy.Unknown {
		t.Errorf("a retired scope answered %v, want Unknown", got)
	}
}

func TestObserveResponseResultWithoutSessionOrSnapshot(t *testing.T) {
	now := time.Now()
	req := queryA("plain.example")
	resp := answerA(req, "93.184.216.34")

	f := newObserveFixture(t, "")
	for name, call := range map[string]func() (ObservedAnswer, error){
		"NoSession": func() (ObservedAnswer, error) {
			return ObserveResponseResult(req, resp, f.snapshot, nil, now, time.Hour)
		},
		"NoSnapshot": func() (ObservedAnswer, error) {
			return ObserveResponseResult(req, resp, nil, f.session, now, time.Hour)
		},
	} {
		result, err := call()
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(result.Observations) != 0 {
			t.Errorf("%s: observations = %d, want none", name, len(result.Observations))
		}
		if result.QName == "" || result.QType != mdns.TypeA {
			t.Errorf("%s: envelope = %q/%d, want it reported anyway", name, result.QName, result.QType)
		}
	}
}
