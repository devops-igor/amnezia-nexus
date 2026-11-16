package vpn

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
)

// Regressions for repair round 2 of issue #825 (PR #844):
//
//   - TestExplainPolicyDoesNotWriteResolverHealth proves a dry run leaves the
//     live resolver's operator-visible health status untouched, using the real
//     UpstreamResolver and a real UDP exchange (review finding HIGH-01).
//   - TestExplainClassificationMatchesObservationPath proves the explainer accepts
//     and classifies an answer exactly as the observation path does, including the
//     answers the observation path rejects (review finding HIGH-03).

// startExplainDNSServer serves one fixed A record over real UDP loopback DNS and
// returns the port it listens on.
func startExplainDNSServer(t *testing.T, answer string) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	ip := net.ParseIP(answer)
	if ip == nil {
		t.Fatalf("invalid fixture address %q", answer)
	}
	server := &mdns.Server{
		PacketConn: conn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			reply := new(mdns.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
				A:   ip.To4(),
			})
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// closedLoopbackPort returns a loopback UDP port nothing is listening on.
func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// explainTestUpstream is the loopback fixture entry the resolver accepts only
// with AllowLoopbackUpstream, which is the resolver-test convention.
func explainTestUpstream(t *testing.T, port int) policy.Upstream {
	t.Helper()
	return policy.Upstream{Address: "127.0.0.1", Port: port, Transport: policy.TransportPlain}
}

// TestExplainPolicyDoesNotWriteResolverHealth drives the real resolver: a real
// failure is recorded through the production Exchange, then a successful dry run
// must not clear it, and a failing dry run must not add another one.
func TestExplainPolicyDoesNotWriteResolverHealth(t *testing.T) {
	snap, _, _, _, now := explainTestSnapshot(t)
	workingPort := startExplainDNSServer(t, "198.51.201.10")
	failingPort := closedLoopbackPort(t)

	resolver, err := gatewaydns.NewUpstreamResolver(gatewaydns.ResolverConfig{
		Upstreams:             []policy.Upstream{explainTestUpstream(t, failingPort)},
		QueryTimeout:          300 * time.Millisecond,
		AttemptTimeout:        150 * time.Millisecond,
		AllowLoopbackUpstream: true,
	})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}

	// 1. Record a genuine failure through the production entry point.
	probe := new(mdns.Msg)
	probe.SetQuestion("probe.example.", mdns.TypeA)
	if _, err := resolver.Exchange(context.Background(), probe); err == nil {
		t.Fatal("the failing upstream did not fail; the fixture is wrong")
	}
	recorded := resolver.Status()
	if recorded.LastFailure == "" || recorded.LastFailureKind == "" {
		t.Fatalf("production Exchange did not record the failure: %+v", recorded)
	}

	explain := func(name string) PolicyExplanation {
		t.Helper()
		out, err := explainPolicy(context.Background(), policyExplainDeps{
			Enabled: true, Snapshot: snap, Resolver: resolver, Clock: fixedClock(now),
		}, PolicyExplainRequest{Name: name, Value: name, SessionID: "session-1"})
		if err != nil {
			t.Fatalf("explain %s: %v", name, err)
		}
		return out
	}

	// 2. A successful dry run must not clear the recorded failure.
	if err := resolver.SetUpstreams([]policy.Upstream{explainTestUpstream(t, workingPort)}); err != nil {
		t.Fatalf("set working upstreams: %v", err)
	}
	success := explain("healthy.example")
	if success.Resolution.Error != "" {
		t.Fatalf("the working upstream should have answered: %v", success.Resolution.Error)
	}
	if got := resolver.Status(); got != recorded {
		t.Fatalf("a successful dry run rewrote resolver health: %+v → %+v", recorded, got)
	}

	// 3. A failing dry run must not add a failure either.
	if err := resolver.SetUpstreams([]policy.Upstream{explainTestUpstream(t, failingPort)}); err != nil {
		t.Fatalf("set failing upstreams: %v", err)
	}
	failed := explain("unreachable.example")
	if failed.Resolution.Error == "" {
		t.Fatal("the failing upstream should have produced a resolution error")
	}
	if got := resolver.Status(); got != recorded {
		t.Fatalf("a failed dry run rewrote resolver health: %+v → %+v", recorded, got)
	}
	// The production entry point still records, so the suppression is specific to
	// the dry run rather than the status being dead.
	if _, err := resolver.Exchange(context.Background(), probe); err == nil {
		t.Fatal("expected the production exchange to fail too")
	}
	if got := resolver.Status(); got.LastFailure == "" {
		t.Fatalf("production Exchange stopped recording failures: %+v", got)
	}
}

// TestExplainClassificationMatchesObservationPath is the parity table: for every
// crafted answer the explainer must accept, reject and classify exactly as the
// observation path does, so it can never explain a destination from an answer
// that cannot become trusted evidence.
func TestExplainClassificationMatchesObservationPath(t *testing.T) {
	const queried = "www.example."

	answerOf := func(records ...mdns.RR) *mdns.Msg {
		resp := new(mdns.Msg)
		resp.SetQuestion(queried, mdns.TypeA)
		resp.Response = true
		resp.Answer = records
		return resp
	}
	aRecord := func(name, addr string, ttl uint32) *mdns.A {
		return &mdns.A{
			Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(addr).To4(),
		}
	}
	cnameRecord := func(name, target string, ttl uint32) *mdns.CNAME {
		return &mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: ttl},
			Target: target,
		}
	}

	cases := []struct {
		name   string
		resp   *mdns.Msg
		wantOK bool
		// wantIPs are the resolved destinations the explainer must evaluate;
		// wantEvidence is the narrower set production may record as evidence.
		wantIPs      []string
		wantEvidence []string
	}{
		{
			name: "clean chain",
			resp: answerOf(
				cnameRecord(queried, "edge.cdn.example.", 300),
				aRecord("edge.cdn.example.", "198.51.201.10", 300),
				aRecord("edge.cdn.example.", "198.51.201.11", 120),
			),
			wantOK:       true,
			wantIPs:      []string{"198.51.201.10", "198.51.201.11"},
			wantEvidence: []string{"198.51.201.10", "198.51.201.11"},
		},
		{
			name: "CNAME cycle",
			resp: answerOf(
				cnameRecord(queried, "a.example.", 300),
				cnameRecord("a.example.", queried, 300),
			),
			wantOK: false,
		},
		{
			name: "ambiguous CNAMEs for one name",
			resp: answerOf(
				cnameRecord(queried, "a.example.", 300),
				cnameRecord(queried, "b.example.", 300),
				aRecord("a.example.", "198.51.201.20", 300),
			),
			wantOK: false,
		},
		{
			name: "combined CNAME and A for one name",
			resp: answerOf(
				cnameRecord(queried, "a.example.", 300),
				aRecord(queried, "198.51.201.21", 300),
			),
			wantOK: false,
		},
		{
			name: "invalid intermediate name",
			resp: answerOf(
				cnameRecord(queried, "bad_name.example.", 300),
				aRecord("bad_name.example.", "198.51.201.22", 300),
			),
			wantOK: false,
		},
		{
			name: "truncated answer",
			resp: func() *mdns.Msg {
				resp := answerOf(aRecord(queried, "198.51.201.23", 300))
				resp.Truncated = true
				return resp
			}(),
			wantOK: false,
		},
		{
			name: "servfail",
			resp: func() *mdns.Msg {
				resp := answerOf()
				resp.Rcode = mdns.RcodeServerFailure
				return resp
			}(),
			wantOK: false,
		},
		{
			name:   "valid answer with no A record",
			resp:   answerOf(),
			wantOK: true,
		},
		{
			name: "private address is evaluated but never evidence",
			resp: answerOf(aRecord(queried, "10.0.0.5", 300)),
			// The explainer still evaluates the destination production drops.
			wantOK:  true,
			wantIPs: []string{"10.0.0.5"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := new(mdns.Msg)
			query.SetQuestion(queried, mdns.TypeA)

			// Production classification (the code the observation path runs).
			classified := gatewaydns.ClassifyAnswer(query, tc.resp, time.Hour)

			// Production evidence path, over a real snapshot and session cache.
			snap, err := policy.CompileSnapshot(1, "gen-parity", []policy.SourceParsedRules{{
				SourceID: "custom-1",
			}})
			if err != nil {
				t.Fatalf("compile snapshot: %v", err)
			}
			cache, err := policy.NewRouteCache(policy.CacheConfig{})
			if err != nil {
				t.Fatalf("new cache: %v", err)
			}
			cache.SetPolicyGeneration("gen-parity")
			scope, err := cache.Open(policy.Scope{SessionID: "parity", OwnershipEpoch: 1})
			if err != nil {
				t.Fatalf("open scope: %v", err)
			}
			now := time.Now()
			observations, err := gatewaydns.ObserveResponse(query, tc.resp, snap, scope, now, time.Hour)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}

			// Explanation path, through the real compose step.
			resolver := &fakeExplainResolver{resp: tc.resp}
			out, err := explainPolicy(context.Background(), policyExplainDeps{
				Enabled: true, Snapshot: snap, Resolver: resolver, Clock: fixedClock(now),
			}, PolicyExplainRequest{Name: "www.example", Value: "www.example"})
			if err != nil {
				t.Fatalf("explain: %v", err)
			}
			// "Rejected" means the answer was unusable, not that it carried no
			// address: a valid empty answer still has a named outcome.
			explainedRejected := strings.HasPrefix(out.Resolution.Error, policyExplainIgnoredAnswerPrefix)
			explainedOK := !explainedRejected

			if classified.Valid != tc.wantOK {
				t.Fatalf("production classification = %v (%s), want %v",
					classified.Valid, classified.Reason, tc.wantOK)
			}
			if explainedOK != classified.Valid {
				t.Fatalf("explainer accepted=%v but production classification accepted=%v (%s)",
					explainedOK, classified.Valid, classified.Reason)
			}
			// Evidence is produced exactly when the evidence-eligible set is not
			// empty, never merely because the answer resolved to an address.
			if gotEvidence := len(observations) > 0; gotEvidence != (len(tc.wantEvidence) > 0) {
				t.Fatalf("production evidence = %v, want %v (observations %d)",
					gotEvidence, len(tc.wantEvidence) > 0, len(observations))
			}
			if got := addrStrings(classified.EvidenceAddresses); !sameStrings(got, tc.wantEvidence) {
				t.Fatalf("evidence-eligible addresses = %v, want %v", got, tc.wantEvidence)
			}

			if got := out.Resolution.Addresses; !sameStrings(got, tc.wantIPs) {
				t.Fatalf("explained addresses = %v, want %v", got, tc.wantIPs)
			}
			if explainedOK {
				if !sameStrings(explainedNames(out), classified.Names) {
					t.Fatalf("explained names = %v, production names = %v",
						explainedNames(out), classified.Names)
				}
				if !sameStrings(out.Resolution.Addresses, addrStrings(classified.ResolvedAddresses)) {
					t.Fatalf("explained addresses = %v, resolved addresses = %v",
						out.Resolution.Addresses, addrStrings(classified.ResolvedAddresses))
				}
			}
		})
	}
}

func explainedNames(out PolicyExplanation) []string {
	return out.Resolution.Names
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
