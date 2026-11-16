package vpn

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
)

// These tests cover the elapsed evidence age of issue #825, acceptance criterion
// 3. Age is measured from the instant the observation was recorded; the
// remaining lifetime (expires_in_seconds) keeps its meaning.

func ageQuery(name string) *mdns.Msg {
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	return q
}

func explainAddressAge(t *testing.T, deps policyExplainDeps, ip string) PolicyExplanation {
	t.Helper()
	out, err := explainPolicy(context.Background(), deps, PolicyExplainRequest{
		Value: ip, Addresses: []netip.Addr{netip.MustParseAddr(ip)}, SessionID: "session-1",
	})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	return out
}

func hasLimit(limits []string, want string) bool {
	for _, l := range limits {
		if l == want {
			return true
		}
	}
	return false
}

// TestExplainPolicyReportsElapsedEvidenceAge observes through the production
// writer, advances the evaluation clock by a controlled interval and requires the
// reported age to equal it, with the remaining lifetime unchanged in meaning.
func TestExplainPolicyReportsElapsedEvidenceAge(t *testing.T) {
	snap, _, scope, _, t0 := explainTestSnapshot(t)
	resp := explainAnswer(t, "unlisted.example", nil, []string{"198.51.201.60"}) // A TTL 120s
	if _, err := gatewaydns.ObserveResponse(ageQuery("unlisted.example"), resp, snap, scope, t0, time.Hour); err != nil {
		t.Fatalf("observe: %v", err)
	}

	const elapsed = 37 * time.Second
	out := explainAddressAge(t, policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: scope, Clock: fixedClock(t0.Add(elapsed)),
	}, "198.51.201.60")

	if out.Decision != string(policy.ActionDirect) || out.Reason != string(policy.CauseFreshEvidenceDirect) {
		t.Fatalf("action = %s/%s, want DIRECT/%s", out.Decision, out.Reason, policy.CauseFreshEvidenceDirect)
	}
	ev := out.Evidence
	if ev == nil || ev.AgeSeconds == nil || ev.AgeUnavailableReason != "" {
		t.Fatalf("evidence = %+v, want a reported age and no unavailable reason", ev)
	}
	if *ev.AgeSeconds != 37 {
		t.Errorf("age_seconds = %d, want exactly the %v elapsed since the observation", *ev.AgeSeconds, elapsed)
	}
	// Remaining lifetime keeps its meaning: deadline (TTL 120s) minus the
	// evaluation instant. It is a different number from the age.
	if ev.ExpiresInSeconds != 120-37 {
		t.Errorf("expires_in_seconds = %d, want remaining lifetime %d", ev.ExpiresInSeconds, 120-37)
	}
	if hasLimit(out.Limitations, PolicyLimitNoEvidenceAge) {
		t.Errorf("limitations = %v, must not claim the age is unrecorded when it was", out.Limitations)
	}
	if len(out.Addresses) != 1 || out.Addresses[0].Evidence == nil || out.Addresses[0].Evidence.AgeSeconds == nil ||
		*out.Addresses[0].Evidence.AgeSeconds != 37 {
		t.Errorf("per-address evidence = %+v, want the same age as the headline", out.Addresses)
	}
}

// TestExplainPolicyEvidenceAgeFollowsTheRealClock drives the production DNS
// observer, which stamps the observation from the wall clock, sleeps, and
// explains with the real clock. The age must lie between the elapsed time
// bracketed from outside the observation call: no fixed tolerance is needed.
func TestExplainPolicyEvidenceAgeFollowsTheRealClock(t *testing.T) {
	mem := NewMemoryRouteCache()
	snap := mem.PolicyMatcher().Current()
	resp := explainAnswer(t, "unlisted.example", nil, []string{"198.51.201.61"})

	before := time.Now()
	if err := mem.ObserveDNSResponse("session-1", ageQuery("unlisted.example"), resp); err != nil {
		t.Fatalf("observe: %v", err)
	}
	after := time.Now()
	time.Sleep(1100 * time.Millisecond)

	var evaluatedAt time.Time
	out := explainAddressAge(t, policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: mem.SessionScope("session-1"),
		Clock: func() time.Time { evaluatedAt = time.Now(); return evaluatedAt },
	}, "198.51.201.61")

	ev := out.Evidence
	if ev == nil || ev.AgeSeconds == nil {
		t.Fatalf("evidence = %+v, want a reported age", ev)
	}
	// The observation instant is somewhere in [before, after].
	lo := int64(evaluatedAt.Sub(after) / time.Second)
	hi := int64(evaluatedAt.Sub(before) / time.Second)
	if *ev.AgeSeconds < lo || *ev.AgeSeconds > hi || *ev.AgeSeconds < 1 {
		t.Fatalf("age_seconds = %d, want within [%d, %d] and at least the 1s slept", *ev.AgeSeconds, lo, hi)
	}
}

// TestExplainPolicyReportsNoAgeForARecordWithoutAnInstant covers a fresh record
// that was stored without an observation instant. It must carry no age, give the
// reason, and keep its remaining lifetime, so a TTL is never presented as an age.
func TestExplainPolicyReportsNoAgeForARecordWithoutAnInstant(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	legacy := &policy.Evidence{
		State: policy.EvidenceFresh, Decision: policy.Direct, Generation: "gen-11",
		ExpiresAt: now.Add(90 * time.Second),
	}

	got := policyExplainEvidence(legacy, now)
	if got.AgeSeconds != nil {
		t.Fatalf("age_seconds = %d, want no age for a record without an instant", *got.AgeSeconds)
	}
	if got.AgeUnavailableReason != string(policy.AgeInstantNotRecorded) {
		t.Errorf("age_unavailable_reason = %q, want %q", got.AgeUnavailableReason, policy.AgeInstantNotRecorded)
	}
	if got.ExpiresInSeconds != 90 {
		t.Errorf("expires_in_seconds = %d, want the unchanged remaining lifetime 90", got.ExpiresInSeconds)
	}

	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(wire, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := fields["age_seconds"]; present {
		t.Errorf("wire = %s, want no age_seconds key (neither 0 nor a TTL-derived value)", wire)
	}

	out := PolicyExplanation{Evidence: got, Limitations: []string{}}
	policyExplainAgeLimitation(&out)
	if !hasLimit(out.Limitations, PolicyLimitNoEvidenceAge) {
		t.Errorf("limitations = %v, want %q", out.Limitations, PolicyLimitNoEvidenceAge)
	}
}

// TestExplainPolicyAgeIsAbsentWithTheReasonWhenNotFresh pins every state that
// reports no age, and that a just-observed record reports an age of zero rather
// than none.
func TestExplainPolicyAgeIsAbsentWithTheReasonWhenNotFresh(t *testing.T) {
	snap, _, scope, gen, t0 := explainTestSnapshot(t)
	observe := func(ip string, ttl time.Duration) {
		if err := scope.Observe(gen, []policy.Observation{{
			IP: netip.MustParseAddr(ip), Decision: policy.Direct, ExpiresAt: t0.Add(ttl),
		}}, t0); err != nil {
			t.Fatalf("observe %s: %v", ip, err)
		}
	}
	observe("198.51.201.70", time.Hour)
	observe("198.51.201.71", 10*time.Second)

	cases := []struct {
		name       string
		ip         string
		at         time.Duration
		scope      *policy.SessionCache
		wantAge    *int64
		wantReason string
	}{
		{"fresh at the instant it was observed", "198.51.201.70", 0, scope, ptr64(0), ""},
		{"expired", "198.51.201.71", time.Minute, scope, nil, string(policy.AgeNotFresh)},
		{"no entry", "198.51.201.72", time.Minute, scope, nil, string(policy.AgeNoEvidence)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := explainAddressAge(t, policyExplainDeps{
				Enabled: true, Snapshot: snap, SessionScope: tc.scope, Clock: fixedClock(t0.Add(tc.at)),
			}, tc.ip)
			ev := out.Evidence
			if ev == nil {
				t.Fatal("want an evidence object")
			}
			if !reflect.DeepEqual(ev.AgeSeconds, tc.wantAge) || ev.AgeUnavailableReason != tc.wantReason {
				t.Fatalf("age = %v reason = %q, want %v / %q", ev.AgeSeconds, ev.AgeUnavailableReason, tc.wantAge, tc.wantReason)
			}
		})
	}

	t.Run("no session scope selects no evidence at all", func(t *testing.T) {
		out := explainAddressAge(t, policyExplainDeps{
			Enabled: true, Snapshot: snap, Clock: fixedClock(t0),
		}, "198.51.201.70")
		if out.Evidence != nil || out.Addresses[0].Evidence != nil {
			t.Fatalf("evidence = %+v, want none without a session scope", out.Evidence)
		}
		if hasLimit(out.Limitations, PolicyLimitNoEvidenceAge) {
			t.Errorf("limitations = %v, want no age caveat when no evidence is read", out.Limitations)
		}
	})
	t.Run("disabled policy reads no evidence", func(t *testing.T) {
		out := explainAddressAge(t, policyExplainDeps{
			Enabled: false, Snapshot: snap, SessionScope: scope, Clock: fixedClock(t0),
		}, "198.51.201.70")
		if out.Evidence != nil {
			t.Fatalf("evidence = %+v, want none when policy routing is disabled", out.Evidence)
		}
		if hasLimit(out.Limitations, PolicyLimitNoEvidenceAge) {
			t.Errorf("limitations = %v, want no age caveat when no evidence is read", out.Limitations)
		}
	})
}

func ptr64(v int64) *int64 { return &v }

// policyExplainBeforeAgeFixture is the complete response, captured from the
// revision that preceded evidence-age recording, for a session holding fresh
// DIRECT, expired DIRECT, fresh PROXY and absent evidence evaluated 30s after the
// observations were written. The only differences the age change may introduce
// are the age fields on evidence objects and the removal of the
// evidence_age_not_recorded limitation, which was the disclosure for exactly the
// gap this change closes.
const policyExplainBeforeAgeFixture = `{"input":{"value":"198.51.201.50","kind":"address","session":"session-1"},"policy":{"enabled":true,"generation_id":"gen-11","version":11,"domain_rules":1,"cidr_rules":1},"decision":"PROXY","reason":"expired_evidence","summary":"most_restrictive","prospective":{"matched":false},"addresses":[{"address":"198.51.201.50","decision":"DIRECT","reason":"fresh_evidence_direct","evidence":{"state":"fresh","decision":"DIRECT","generation":"gen-11","expires_in_seconds":3570,"source":"intercepted_plain_dns"}},{"address":"198.51.201.51","decision":"PROXY","reason":"expired_evidence","evidence":{"state":"expired","decision":"DIRECT","generation":"gen-11","expires_in_seconds":-20,"source":"intercepted_plain_dns"}},{"address":"198.51.201.52","decision":"PROXY","reason":"cached_proxy_evidence","evidence":{"state":"fresh","decision":"PROXY","generation":"gen-11","expires_in_seconds":270,"source":"intercepted_plain_dns"}},{"address":"198.51.201.53","decision":"PROXY","reason":"no_trusted_evidence","evidence":{"state":"absent","generation":"gen-11","expires_in_seconds":0,"source":""}}],"evidence":{"state":"expired","decision":"DIRECT","generation":"gen-11","expires_in_seconds":-20,"source":"intercepted_plain_dns"},"resolution":{"method":"caller_supplied","addresses":["198.51.201.50","198.51.201.51","198.51.201.52","198.51.201.53"]},"evaluated_at":"2026-11-16T12:00:30Z","limitations":["encrypted_dns_not_observed","ad_hoc_resolution_is_not_evidence","ipv6_not_supported","domain_rules_require_a_name","evidence_age_not_recorded"],"read_only":true}`

// TestExplainPolicyAgeChangesNoOtherField proves the decision, reasons, summary,
// remaining lifetimes, limitations and every other field are what they were
// before age was recorded: stripping the age fields from the current answer must
// reproduce the captured response exactly.
func TestExplainPolicyAgeChangesNoOtherField(t *testing.T) {
	snap, _, scope, gen, start := explainTestSnapshot(t)
	seed := func(ip string, d policy.Decision, ttl time.Duration) {
		if err := scope.Observe(gen, []policy.Observation{{
			IP: netip.MustParseAddr(ip), Decision: d, ExpiresAt: start.Add(ttl),
		}}, start); err != nil {
			t.Fatalf("seed %s: %v", ip, err)
		}
	}
	seed("198.51.201.50", policy.Direct, time.Hour)
	seed("198.51.201.51", policy.Direct, 10*time.Second)
	seed("198.51.201.52", policy.Proxy, 5*time.Minute)

	var addrs []netip.Addr
	for _, ip := range []string{"198.51.201.50", "198.51.201.51", "198.51.201.52", "198.51.201.53"} {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	out, err := explainPolicy(context.Background(), policyExplainDeps{
		Enabled: true, Snapshot: snap, SessionScope: scope, Clock: fixedClock(start.Add(30 * time.Second)),
	}, PolicyExplainRequest{Value: "198.51.201.50", Addresses: addrs, SessionID: "session-1"})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}

	stripped := stripAgeFields(t, out)
	var want any
	if err := json.Unmarshal([]byte(policyExplainBeforeAgeFixture), &want); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	wantMap := want.(map[string]any)
	wantMap["limitations"] = withoutString(wantMap["limitations"].([]any), PolicyLimitNoEvidenceAge)
	if !reflect.DeepEqual(stripped, wantMap) {
		got, _ := json.MarshalIndent(stripped, "", " ")
		exp, _ := json.MarshalIndent(wantMap, "", " ")
		t.Fatalf("response changed beyond the age fields\n got: %s\nwant: %s", got, exp)
	}
}

func stripAgeFields(t *testing.T, out PolicyExplanation) map[string]any {
	t.Helper()
	wire, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(wire, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	strip := func(v any) {
		if ev, ok := v.(map[string]any); ok {
			delete(ev, "age_seconds")
			delete(ev, "age_unavailable_reason")
		}
	}
	strip(m["evidence"])
	for _, a := range m["addresses"].([]any) {
		strip(a.(map[string]any)["evidence"])
	}
	return m
}

func withoutString(in []any, drop string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}
