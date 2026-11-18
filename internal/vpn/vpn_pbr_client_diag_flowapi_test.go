package vpn

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// Coupled producer→Service→wire coverage for the flow evidence and the DNS↔flow
// correlation (issue #861, slice 3b).
//
// The chain is the real one: a client DNS query produces a retained answer, a
// client packet produces a flow whose branch records the decision, the packet is
// dispatched to the WAN device or the backend queue, and the reply path admits the
// return. Those records are then read through Service.ClientDiagnosis and the JSON
// the handler returns.

func findFlowEvidence(t *testing.T, flows []ClientDiagnosisFlow, destination string, port uint16) ClientDiagnosisFlow {
	t.Helper()
	for _, flow := range flows {
		if flow.DestinationIP == destination && flow.DestinationPort == port {
			return flow
		}
	}
	t.Fatalf("no flow for %s:%d; flows=%+v", destination, port, flows)
	return ClientDiagnosisFlow{}
}

// TestClientDiagnosisReportsRecordedFlowEvidence is the primary coupled control:
// the decision the branch took, the dispatch outcome the enqueue or device write
// produced, and the return evidence the reply path admitted all reach the wire.
func TestClientDiagnosisReportsRecordedFlowEvidence(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 55001)
	f.queryIP(t, "proxy.example", 55002)
	f.sendTCP(t, f.example, 41100, 443) // DIRECT: evidence chose it
	f.sendTCP(t, f.proxyIP, 41101, 443) // PROXY: cached PROXY evidence chose it

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}

	direct := findFlowEvidence(t, answer.Flows.Entries, f.example.String(), 443)
	if direct.Choice != forwarder.EgressChoiceDirect.String() {
		t.Fatalf("direct flow choice = %q, want DIRECT", direct.Choice)
	}
	if direct.DecisionReason != string(forwarder.EgressReasonEvidenceDirect) {
		t.Errorf("decision reason = %q, want the branch that ran (%q)", direct.DecisionReason, forwarder.EgressReasonEvidenceDirect)
	}
	if direct.DecisionTime == ClientDiagnosisTokenNotRecorded || direct.DecisionTime == "" {
		t.Error("decision time must be the recorded instant, not the not_recorded token")
	} else if _, err := time.Parse(time.RFC3339, direct.DecisionTime); err != nil {
		t.Errorf("decision time %q is not an instant: %v", direct.DecisionTime, err)
	}
	if direct.PolicyGeneration == ClientDiagnosisTokenNotRecorded {
		t.Errorf("policy generation = %q, want the generation the decision was taken against", direct.PolicyGeneration)
	}
	if direct.Dispatch.State != "written_to_wan" {
		t.Errorf("dispatch = %+v, want written_to_wan for a DIRECT flow", direct.Dispatch)
	}
	if direct.Forward.Packets != 1 || direct.Forward.Failed != 0 || direct.Forward.Bytes == 0 {
		t.Errorf("forward = %+v, want one successful WAN write with bytes", direct.Forward)
	}
	if direct.Return.Evidence != "not_observed" {
		t.Errorf("return = %+v, want not_observed before any reply", direct.Return)
	}
	if direct.NamesMatch != FlowCorrelationUnique || len(direct.Names) != 1 || direct.Names[0] != "plain.example" {
		t.Errorf("names = %q %v, want the single retained name that preceded the decision", direct.NamesMatch, direct.Names)
	}
	if direct.BackendTunnelID != nil {
		t.Errorf("direct flow backend = %v, want none", *direct.BackendTunnelID)
	}

	proxied := findFlowEvidence(t, answer.Flows.Entries, f.proxyIP.String(), 443)
	if proxied.DecisionReason != string(forwarder.EgressReasonProxyCachedEvidence) {
		t.Errorf("proxy decision reason = %q, want the cached-evidence branch", proxied.DecisionReason)
	}
	if proxied.Dispatch.State != "queued_to_backend" {
		t.Errorf("proxy dispatch = %+v, want queue acceptance, not a device write", proxied.Dispatch)
	}
	if proxied.BackendTunnelID == nil {
		t.Error("proxy flow must state the backend the decision selected")
	}
	if proxied.Return.Evidence != "not_measured" {
		t.Errorf("proxy return = %+v, want explicitly not_measured", proxied.Return)
	}
	if proxied.NamesMatch != FlowCorrelationUnique || len(proxied.Names) != 1 || proxied.Names[0] != "proxy.example" {
		t.Errorf("proxy names = %q %v, want its own retained name", proxied.NamesMatch, proxied.Names)
	}
}

// TestClientDiagnosisCorrelationPreservesAmbiguityAndTime covers the correlation
// rules that a matching address alone cannot answer: several names on one address,
// an answer that arrived after the decision, and an answer that had expired before
// it.
func TestClientDiagnosisCorrelationPreservesAmbiguityAndTime(t *testing.T) {
	t.Run("SharedAddressIsAmbiguous", func(t *testing.T) {
		f := newClientDiagFixture(t)
		f.queryIP(t, "plain.example", 55101)
		f.queryIP(t, "shared.example", 55102)
		f.sendTCP(t, f.example, 41110, 443)

		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		flow := findFlowEvidence(t, answer.Flows.Entries, f.example.String(), 443)
		if flow.NamesMatch != FlowCorrelationAmbiguous {
			t.Fatalf("names match = %q, want ambiguous for two names on one address", flow.NamesMatch)
		}
		if len(flow.Names) != 2 {
			t.Errorf("names = %v, want both candidates", flow.Names)
		}
		for _, want := range []string{"plain.example", "shared.example"} {
			if !clientDiagHas(flow.Names, want) {
				t.Errorf("candidate %q missing from %v", want, flow.Names)
			}
		}
		if len(flow.NameCandidates) != 2 {
			t.Errorf("candidates = %d, want one entry per name", len(flow.NameCandidates))
		}
		for _, candidate := range flow.NameCandidates {
			if candidate.Seq == 0 || candidate.ObservedAt == "" || candidate.ExpiresAt == "" {
				t.Errorf("candidate %+v must carry its own record identity and instants", candidate)
			}
		}
	})

	t.Run("AnswerAfterTheDecisionDoesNotExplainIt", func(t *testing.T) {
		f := newClientDiagFixture(t)
		// The flow is decided with no evidence for the address (PROXY default), and
		// the answer that names that address arrives AFTERWARDS. That answer cannot
		// explain the earlier choice.
		f.sendTCP(t, f.example, 41111, 443)
		f.queryIP(t, "plain.example", 55103)

		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		flow := findFlowEvidence(t, answer.Flows.Entries, f.example.String(), 443)
		if flow.NamesMatch != FlowCorrelationNone {
			t.Fatalf("names match = %q, want none: the answer came after the decision", flow.NamesMatch)
		}
		if flow.NamesReason != CorrelationReasonAnswerAfterDecision {
			t.Errorf("names reason = %q, want answer_after_decision", flow.NamesReason)
		}
		if flow.NamesConsidered != 1 {
			t.Errorf("considered = %d, want the late record counted even though it cannot explain the flow", flow.NamesConsidered)
		}
		// The record itself is retained and correlates to nothing for this flow:
		// the history is not rewritten by the rejection.
		if len(answer.DNS.Records) != 1 {
			t.Errorf("dns records = %d, want the retained answer", len(answer.DNS.Records))
		}
	})

	t.Run("ExpiredBeforeTheDecisionIsNotACause", func(t *testing.T) {
		f := newClientDiagFixture(t)
		f.queryIP(t, "short.example", 55104)
		// The one-second answer expires before the flow is decided.
		time.Sleep(1100 * time.Millisecond)
		f.sendTCP(t, netip.MustParseAddr("93.184.216.77"), 41112, 443)

		answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
		if err != nil {
			t.Fatalf("ClientDiagnosis: %v", err)
		}
		flow := findFlowEvidence(t, answer.Flows.Entries, "93.184.216.77", 443)
		if flow.NamesMatch != FlowCorrelationNone {
			t.Fatalf("names match = %q, want none: the evidence had expired", flow.NamesMatch)
		}
		if flow.NamesReason != CorrelationReasonExpiredBeforeDecision {
			t.Errorf("names reason = %q, want expired_before_decision", flow.NamesReason)
		}
		if flow.NamesConsidered != 1 {
			t.Errorf("considered = %d, want the matching record counted even though it cannot explain the flow", flow.NamesConsidered)
		}
		// The retained record is still in the history, labelled expired: the
		// correlation refuses the claim, the record itself is not deleted.
		record := findDNSRecord(t, answer.DNS.Records, "short.example")
		if record.State != "expired" {
			t.Errorf("record state = %q, want expired", record.State)
		}
	})
}

// TestClientDiagnosisFlowEvidenceIsPerIncarnation proves a retained flow keeps the
// decision and the names of the incarnation that made it: after a rekey the DNS
// history survives but the old flow's recorded facts do not move.
func TestClientDiagnosisFlowEvidenceIsPerIncarnation(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 55201)
	f.sendTCP(t, f.example, 41120, 443)
	sessionID := f.sessionID(t)
	firstGeneration := f.generation(t)

	first, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	original := findFlowEvidence(t, first.Flows.Entries, f.example.String(), 443)

	// A same-session rekey purges the flows; the DNS history stays.
	f.fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", f.peerKey, f.clientIP.String(), 11, f.returnPath)
	if f.generation(t) == firstGeneration {
		t.Fatal("rekey did not advance the generation")
	}
	second, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis after rekey: %v", err)
	}
	if len(second.Flows.Entries) != 0 {
		t.Fatalf("flows = %d after a rekey, want none", len(second.Flows.Entries))
	}
	// The retained DNS answer survives the rekey and still correlates to the
	// destination, but the flow record itself is gone rather than rewritten.
	if len(second.DNS.Records) != 1 {
		t.Errorf("dns records = %d after a rekey, want the retained answer", len(second.DNS.Records))
	}
	if original.RouteGeneration != firstGeneration {
		t.Errorf("original flow generation = %d, want %d", original.RouteGeneration, firstGeneration)
	}
}

// TestClientDiagnosisFlowEvidenceIsNotWrittenByReads proves the read path neither
// refreshes the flow's activity nor moves any evidence or counter.
func TestClientDiagnosisFlowEvidenceIsNotWrittenByReads(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 55301)
	f.sendTCP(t, f.example, 41130, 443)
	sessionID := f.sessionID(t)

	first, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	second, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	a := findFlowEvidence(t, first.Flows.Entries, f.example.String(), 443)
	b := findFlowEvidence(t, second.Flows.Entries, f.example.String(), 443)
	if a.LastSeen != b.LastSeen || a.LastSeenAgeSeconds != b.LastSeenAgeSeconds {
		t.Errorf("a read refreshed activity: %q/%d -> %q/%d", a.LastSeen, a.LastSeenAgeSeconds, b.LastSeen, b.LastSeenAgeSeconds)
	}
	if a.Forward != b.Forward || a.Return != b.Return || a.DecisionTime != b.DecisionTime {
		t.Errorf("a read changed the evidence: %+v -> %+v", a, b)
	}
	if first.Flows.Scanned != second.Flows.Scanned {
		t.Errorf("scan size moved between reads: %d -> %d", first.Flows.Scanned, second.Flows.Scanned)
	}
	// The counters are live samples of the packet path, not a conserved total:
	// the answer says so rather than implying exactness.
	if !clientDiagHas(first.Limitations, ClientDiagnosisLimitFlowCountersSampled) {
		t.Errorf("limitations must state that the flow counters are live samples: %v", first.Limitations)
	}
	// Both producer gaps this used to list — the backend write and non-TCP flows — are
	// recorded per flow and shown in the table, so neither may be claimed as missing.
	for _, stale := range []string{"proxy_backend_write_not_attributed", "non_tcp_udp_flows_not_recorded"} {
		if clientDiagHas(first.Limitations, stale) {
			t.Errorf("limitations still claim %q although the flow table records it: %v",
				stale, first.Limitations)
		}
	}
}

// TestClientDiagnosisFlowWireShapeIsExplicit pins the wire keys the shipped UI
// reads and the tokens that mark unknown values, so a missing producer shows up as
// an explicit token instead of a zero.
// TestClientDiagnosisFlowWithoutDispatchSaysSo pins the unmeasured dispatch state:
// a flow installed by a path that records no dispatch outcome reports
// not_recorded instead of an implied success.
func TestClientDiagnosisFlowWithoutDispatchSaysSo(t *testing.T) {
	f := newClientDiagFixture(t)
	// The legacy recorder installs a flow entry without a dispatch decision or
	// outcome, which is exactly the shape this branch has to state.
	if err := f.dem.RecordFlow(f.peerKey, f.sessionID(t), f.generation(t),
		buildTestPBRTCPPacket(f.clientIP, netip.MustParseAddr("93.184.216.90"), 41200, 443, []byte("x")),
		forwarder.EgressChoiceProxy); err != nil {
		t.Fatalf("RecordFlow: %v", err)
	}

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	flow := findFlowEvidence(t, answer.Flows.Entries, "93.184.216.90", 443)
	if flow.Dispatch.State != ClientDiagnosisTokenNotRecorded {
		t.Errorf("dispatch = %+v, want not_recorded for a flow with no recorded dispatch", flow.Dispatch)
	}
	if flow.DecisionTime != ClientDiagnosisTokenNotRecorded || flow.DecisionReason != ClientDiagnosisTokenNotRecorded {
		t.Errorf("legacy flow decision = %q/%q, want explicit not_recorded", flow.DecisionTime, flow.DecisionReason)
	}
	if flow.NamesMatch != FlowCorrelationNotRecorded {
		t.Errorf("names match = %q, want not_recorded: the decision instant is unknown", flow.NamesMatch)
	}
	if flow.NamesReason != CorrelationReasonDecisionTimeUnknown {
		t.Errorf("names reason = %q, want decision_time_not_recorded", flow.NamesReason)
	}
}

func TestClientDiagnosisFlowWireShapeIsExplicit(t *testing.T) {
	f := newClientDiagFixture(t)
	f.sendTCP(t, netip.MustParseAddr("1.1.1.1"), 41140, 443) // no evidence: PROXY default

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	raw, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{
		`"decision_time"`, `"decision_reason"`, `"policy_generation"`,
		`"dispatch"`, `"forward"`, `"return"`, `"names_match"`, `"names_reason"`,
		`"names_considered"`, `"name_candidates"`, `"name_attempts"`,
	} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("wire answer is missing %s", key)
		}
	}
	flow := findFlowEvidence(t, answer.Flows.Entries, "1.1.1.1", 443)
	if flow.DecisionReason != string(forwarder.EgressReasonNoTrustedEvidence) {
		t.Errorf("decision reason = %q, want the fail-closed default", flow.DecisionReason)
	}
	if flow.NamesMatch != FlowCorrelationNone {
		t.Errorf("names match = %q, want none for a destination no answer named", flow.NamesMatch)
	}
	if flow.Return.Evidence != "not_measured" {
		t.Errorf("return = %q, want not_measured for PROXY", flow.Return.Evidence)
	}
	if strings.Contains(string(raw), f.peerKey) {
		t.Errorf("the answer carries the peer key: %s", raw)
	}
}

func TestFlowNameAttemptsAreBoundedUnresolvedAndPreDecision(t *testing.T) {
	decided := time.Date(2026, 11, 17, 9, 10, 0, 0, time.UTC)
	flow := forwarder.SessionFlow{Generation: 7, DecidedAt: decided}
	events := []dnsledger.Event{
		{Name: "nx.example", Kind: gatewaydns.QueryEventNXDomain, ReceivedAt: decided.Add(-time.Minute), Seq: 5, RouteGeneration: 7, RouteGenerationKnown: true},
		{Name: "noanswer.example", Kind: gatewaydns.QueryEventNoAnswer, ReceivedAt: decided.Add(-2 * time.Minute), Seq: 4, RouteGeneration: 7, RouteGenerationKnown: true},
		{Name: "answered.example", Kind: gatewaydns.QueryEventAnswered, ReceivedAt: decided.Add(-time.Minute), Seq: 6},
		{Name: "truncated.example", Kind: gatewaydns.QueryEventTruncated, ReceivedAt: decided.Add(-time.Minute), Seq: 7},
		{Name: "after.example", Kind: gatewaydns.QueryEventUpstreamError, ReceivedAt: decided.Add(time.Second), Seq: 8},
		{Name: "old.example", Kind: gatewaydns.QueryEventNXDomain, ReceivedAt: decided.Add(-6 * time.Minute), Seq: 9},
		{Name: "othergen.example", Kind: gatewaydns.QueryEventNXDomain, ReceivedAt: decided.Add(-time.Minute), Seq: 10, RouteGeneration: 6, RouteGenerationKnown: true},
		{Name: "unknowngen.example", Kind: gatewaydns.QueryEventUpstreamError, ReceivedAt: decided.Add(-90 * time.Second), Seq: 11},
		{Name: "third.example", Kind: gatewaydns.QueryEventInvalidQuery, ReceivedAt: decided.Add(-30 * time.Second), Seq: 12},
	}
	got := flowNameAttempts(flow, events)
	want := []struct {
		name string
		kind string
	}{
		{"third.example", gatewaydns.QueryEventInvalidQuery},
		{"nx.example", gatewaydns.QueryEventNXDomain},
		{"unknowngen.example", gatewaydns.QueryEventUpstreamError},
	}
	if len(got) != len(want) {
		t.Fatalf("attempts = %d, want %d (newest first, max 3): %+v", len(got), len(want), got)
	}
	for i, expected := range want {
		if got[i].Name != expected.name || got[i].Kind != expected.kind {
			t.Errorf("attempt %d = %s/%s, want %s/%s", i, got[i].Name, got[i].Kind, expected.name, expected.kind)
		}
	}

	if attempts := flowNameAttempts(forwarder.SessionFlow{Generation: 7}, events); attempts != nil {
		t.Errorf("a flow without a decision instant produced attempts: %+v", attempts)
	}
}

func TestClientDiagnosisFlowExposesAttemptedNames(t *testing.T) {
	f := newClientDiagFixture(t)
	f.sendTCP(t, netip.MustParseAddr("1.1.1.1"), 41150, 443) // no evidence: PROXY default

	sessionID := f.sessionID(t)
	generation, known := f.routeCache.BindQueryIncarnation(sessionID)
	received := time.Now().Add(-time.Minute).UTC()
	f.routeCache.ObserveDNSQueryEvent(gatewaydns.QueryEvent{
		SessionID:        sessionID,
		Transport:        "udp",
		Name:             "missing.example",
		QType:            1,
		Kind:             gatewaydns.QueryEventNXDomain,
		ReceivedAt:       received,
		AnsweredAt:       received,
		RouteGeneration:  generation,
		IncarnationKnown: known,
	})

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	flow := findFlowEvidence(t, answer.Flows.Entries, "1.1.1.1", 443)
	if flow.NamesMatch != FlowCorrelationNone {
		t.Fatalf("names match = %q, want none for a destination no answer named", flow.NamesMatch)
	}
	if len(flow.NameAttempts) != 1 {
		t.Fatalf("attempts = %+v, want the unresolved query near the decision", flow.NameAttempts)
	}
	attempt := flow.NameAttempts[0]
	if attempt.Name != "missing.example" || attempt.Kind != gatewaydns.QueryEventNXDomain || attempt.QType != "A" {
		t.Fatalf("attempt = %+v, want missing.example/A/nxdomain", attempt)
	}
	if attempt.ReceivedAt == "" || attempt.ReceivedAt == ClientDiagnosisTokenNotRecorded {
		t.Fatalf("attempt received_at = %q, want the query instant", attempt.ReceivedAt)
	}
}
