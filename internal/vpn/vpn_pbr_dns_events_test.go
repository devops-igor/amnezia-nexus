package vpn

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
	mdns "github.com/miekg/dns"
)

// Producer→ledger coverage for terminal client DNS queries (issue #861, R9).
//
// Every event asserted here is produced by the real chain: a client DNS packet
// enters RouteClientToBackend, the intercepted handler forwards it, the gateway
// calls the real DNS server, the server applies its own admission budget and
// classifier, the reply is written back to the client, and the gateway emits one
// terminal event through the installed observer into the bounded store.
//
// The negative control that matters is here too: recording a terminal event must
// never create route evidence.

// findQueryEvent selects a terminal event by name AND type: one name legitimately
// produces several events (A, AAAA, failures), and picking the first by name would
// assert against the wrong query.
func findQueryEvent(t *testing.T, events []dnsledger.Event, name string, qtype uint16) dnsledger.Event {
	t.Helper()
	for _, event := range events {
		if event.Name == name && event.QType == qtype {
			return event
		}
	}
	t.Fatalf("no terminal event for %q/%d; events=%+v", name, qtype, events)
	return dnsledger.Event{}
}

// TestClientDiagnosisRecordsTerminalQueryEvents is the first real producer result of
// this checkpoint: a delivered A answer, an NXDOMAIN, a no-answer AAAA response and a
// failed upstream exchange each produce their own terminal event, with the client
// transport and both instants, while the trust path is unchanged.
func TestClientDiagnosisRecordsTerminalQueryEvents(t *testing.T) {
	f := newClientDiagFixture(t)

	f.queryIP(t, "plain.example", 56001)                  // delivered A answer
	f.queryType(t, "nx.example", mdns.TypeA, 56002)       // NXDOMAIN
	f.queryType(t, "plain.example", mdns.TypeAAAA, 56003) // no answer of that type
	f.queryType(t, "fail.example", mdns.TypeA, 56004)     // upstream failure -> SERVFAIL

	sessionID := f.sessionID(t)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()
	if ledger == nil {
		t.Fatal("the fixture has no DNS ledger")
	}
	snapshot := ledger.SnapshotEvents(sessionID, 0)
	if snapshot.Total != 4 || len(snapshot.Events) != 4 {
		t.Fatalf("events = %d (total %d), want the four queries", len(snapshot.Events), snapshot.Total)
	}

	answered := findQueryEvent(t, snapshot.Events, "plain.example", mdns.TypeA)
	if answered.Kind != gatewaydns.QueryEventAnswered {
		t.Fatalf("answered kind = %q, want %q", answered.Kind, gatewaydns.QueryEventAnswered)
	}
	if answered.Transport != "udp" {
		t.Errorf("transport = %q, want the client transport udp", answered.Transport)
	}
	if !answered.Delivered {
		t.Error("a delivered answer must report delivery")
	}
	if answered.ReceivedAt.IsZero() || answered.AnsweredAt.IsZero() {
		t.Errorf("instants = %v/%v, want both recorded", answered.ReceivedAt, answered.AnsweredAt)
	}
	if answered.AnsweredAt.Before(answered.ReceivedAt) {
		t.Error("answered time is before the query time")
	}
	if answered.QType != mdns.TypeA || answered.RCode != mdns.RcodeSuccess {
		t.Errorf("qtype/rcode = %d/%d, want A/NOERROR", answered.QType, answered.RCode)
	}
	if !answered.RouteGenerationKnown || answered.RouteGeneration == 0 {
		t.Error("the event must carry the route generation that was registered when the query arrived")
	}

	nx := findQueryEvent(t, snapshot.Events, "nx.example", mdns.TypeA)
	if nx.Kind != gatewaydns.QueryEventNXDomain || nx.RCode != mdns.RcodeNameError {
		t.Errorf("nxdomain event = %q/%d, want %q/NXDOMAIN", nx.Kind, nx.RCode, gatewaydns.QueryEventNXDomain)
	}

	aaaa := findQueryEvent(t, snapshot.Events, "plain.example", mdns.TypeAAAA)
	if aaaa.Kind != gatewaydns.QueryEventNoAnswer || aaaa.RCode != mdns.RcodeSuccess {
		t.Errorf("AAAA event = %q/%d, want %q/NOERROR: a no-answer response is not an error",
			aaaa.Kind, aaaa.RCode, gatewaydns.QueryEventNoAnswer)
	}

	failed := findQueryEvent(t, snapshot.Events, "fail.example", mdns.TypeA)
	if failed.Kind != gatewaydns.QueryEventUpstreamError {
		t.Errorf("failed event kind = %q, want %q", failed.Kind, gatewaydns.QueryEventUpstreamError)
	}
	if failed.UpstreamError != gatewaydns.UpstreamErrorTimeout {
		t.Errorf("upstream error class = %q, want timeout", failed.UpstreamError)
	}
	if failed.RCode != mdns.RcodeServerFailure {
		t.Errorf("failed rcode = %d, want SERVFAIL as the client received it", failed.RCode)
	}

	// The negative controls. The answer history has two entries: the delivered A
	// answer, and the AAAA query recorded AS SEEN with no addresses because the
	// observation path rejected it. Route evidence, which is the trust boundary, has
	// exactly one entry: the A answer. A rejected query is history, never evidence.
	records := ledger.Snapshot(sessionID, 0)
	if records.Total != 2 {
		t.Errorf("answer records = %d, want the delivered answer plus the rejected one", records.Total)
	}
	withAddresses := 0
	for _, record := range records.Records {
		if len(record.Addresses) > 0 {
			withAddresses++
		} else if record.ClassificationValid {
			t.Errorf("record %q has no addresses but is marked valid", record.Name)
		}
	}
	if withAddresses != 1 {
		t.Errorf("records carrying addresses = %d, want only the delivered A answer", withAddresses)
	}
	if got := f.routeCache.SessionScope(sessionID).Count(); got != 1 {
		t.Errorf("retained evidence entries = %d, want exactly the one delivered A answer", got)
	}
	if got := f.routeCache.Lookup(sessionID, netip.MustParseAddr("93.184.216.34")); got != policy.Direct {
		t.Errorf("the delivered answer's evidence = %v, want DIRECT", got)
	}
}

// TestClientDiagnosisExposesTerminalEvents is the API half of the producer proof:
// the terminal history reaches the diagnosis answer with its kind, transport, times
// and delivery, and the answer states whether a collector was consulted at all.
func TestClientDiagnosisExposesTerminalEvents(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 56301)            // answered
	f.queryType(t, "nx.example", mdns.TypeA, 56302) // nxdomain

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if !answer.DNS.EventsAvailable {
		t.Fatal("events_available = false with a live collector")
	}
	if answer.DNS.EventsTotal != 2 || len(answer.DNS.Events) != 2 {
		t.Fatalf("events = %d (total %d), want the two queries", len(answer.DNS.Events), answer.DNS.EventsTotal)
	}
	byKind := map[string]ClientDiagnosisDNSQueryEvent{}
	for _, event := range answer.DNS.Events {
		byKind[event.Kind] = event
	}
	answered, ok := byKind[gatewaydns.QueryEventAnswered]
	if !ok {
		t.Fatalf("no answered event in %+v", answer.DNS.Events)
	}
	if answered.Transport != "udp" || !answered.Delivered || answered.QType != "A" || answered.RCode != "NOERROR" {
		t.Errorf("answered event = %+v, want udp/delivered/A/NOERROR", answered)
	}
	if answered.ReceivedAt == "" || answered.AnsweredAt == "" {
		t.Errorf("answered event instants = %q/%q, want both", answered.ReceivedAt, answered.AnsweredAt)
	}
	if answered.Count != 1 || answered.FirstSeen == "" || answered.LastSeen == "" {
		t.Errorf("answered event counts = %d/%q/%q, want one observation", answered.Count, answered.FirstSeen, answered.LastSeen)
	}
	if !answered.IncarnationKnown || answered.RouteGeneration == nil {
		t.Error("the event must state the route generation it arrived under")
	}
	nx, ok := byKind[gatewaydns.QueryEventNXDomain]
	if !ok || nx.RCode != "NXDOMAIN" {
		t.Errorf("nxdomain event = %+v, want rcode NXDOMAIN", nx)
	}

	// Ordering: the newest query is first, so the operator sees the latest state of
	// the session without re-reading.
	if answer.DNS.Events[0].Name != "nx.example" {
		t.Errorf("first event = %q, want the newest query", answer.DNS.Events[0].Name)
	}
	if answer.DNS.EventCoverage.Limits.EventsPerSession == 0 || answer.DNS.EventCoverage.Limits.EventsTotal == 0 ||
		answer.DNS.EventCoverage.Limits.MaxAgeSeconds == 0 {
		t.Errorf("coverage limits = %+v, want the bounds in force", answer.DNS.EventCoverage.Limits)
	}
	if answer.DNS.EventCoverage.Written != 2 {
		t.Errorf("written = %d, want both queries", answer.DNS.EventCoverage.Written)
	}
	if len(answer.DNS.EventCoverage.NotRecorded) == 0 {
		t.Error("event coverage must state its gaps")
	}
}

// TestClientDiagnosisRecordsTruncatedQuery proves a response the server shaped
// truncated is recorded as such, delivered, and kept out of route evidence: the
// client received a cut answer, which is a fact about the reply and not a reason to
// trust it.
func TestClientDiagnosisRecordsTruncatedQuery(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "big.example", 56201)

	sessionID := f.sessionID(t)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()
	events := ledger.SnapshotEvents(sessionID, 0)
	if events.Total != 1 {
		t.Fatalf("events = %d, want the one query", events.Total)
	}
	event := events.Events[0]
	if event.Kind != gatewaydns.QueryEventTruncated {
		t.Fatalf("kind = %q, want %q for an oversized UDP answer", event.Kind, gatewaydns.QueryEventTruncated)
	}
	if !event.Truncated || !event.Delivered {
		t.Errorf("truncated/delivered = %v/%v, want the cut reply recorded as delivered", event.Truncated, event.Delivered)
	}
	if event.QType != mdns.TypeA || event.RCode != mdns.RcodeSuccess {
		t.Errorf("qtype/rcode = %d/%d, want A/NOERROR", event.QType, event.RCode)
	}

	// Trust control: the truncated answer produced no route evidence at all, even
	// though it is a valid A answer, because the client never received the whole
	// answer.
	if got := f.routeCache.SessionScope(sessionID).Count(); got != 0 {
		t.Errorf("evidence entries = %d, want none from a truncated reply", got)
	}
	if got := ledger.Snapshot(sessionID, 0).Total; got != 0 {
		t.Errorf("answer records = %d, want none from a truncated reply", got)
	}
}

// TestClientDiagnosisBindsTheReceiptIncarnation is the retired-callback control: a
// query arrives under one incarnation, the session is replaced while the upstream
// lookup is still running, and the terminal event must carry the incarnation that
// RECEIVED the query — never the successor's.
func TestClientDiagnosisBindsTheReceiptIncarnation(t *testing.T) {
	f := newClientDiagFixture(t)
	sessionID := f.sessionID(t)
	receiptGeneration := f.generation(t)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()

	// The query starts and blocks inside the upstream exchange.
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.queryIP(t, "slow.example", 56401)
	}()
	select {
	case <-f.slowEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("the query never reached the upstream exchange")
	}

	// The session is replaced while the lookup is in flight: same session id, a new
	// route generation, exactly what a rekey does.
	f.fwd.RegisterSessionWithReturnPath(sessionID, "conn-1", f.peerKey, f.clientIP.String(), 11, f.returnPath)
	successorGeneration := f.generation(t)
	if successorGeneration == receiptGeneration {
		t.Fatal("the replacement did not advance the incarnation")
	}

	close(f.slowRelease)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the query did not complete after the release")
	}

	events := ledger.SnapshotEvents(sessionID, 0).Events
	if len(events) != 1 {
		t.Fatalf("events = %d, want the one query", len(events))
	}
	event := events[0]
	if !event.RouteGenerationKnown {
		t.Fatal("the event lost its incarnation")
	}
	if event.RouteGeneration != receiptGeneration {
		t.Errorf("event incarnation = %d, want the receipt incarnation %d (the successor is %d)",
			event.RouteGeneration, receiptGeneration, successorGeneration)
	}
}

// TestClientDiagnosisSameIncarnationCallbackStaysAttributed is the legitimate
// positive beside the retired-callback control: with no replacement, the event
// carries the same incarnation the session still reports.
func TestClientDiagnosisSameIncarnationCallbackStaysAttributed(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 56402)

	sessionID := f.sessionID(t)
	current := f.generation(t)
	events := f.svc.clientDiagnosisRouteCache().DNSLedger().SnapshotEvents(sessionID, 0).Events
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if !events[0].RouteGenerationKnown || events[0].RouteGeneration != current {
		t.Errorf("event incarnation = %d/%v, want the current %d", events[0].RouteGeneration, events[0].RouteGenerationKnown, current)
	}
}

// TestClientDiagnosisRecordsHTTPSAnswer pins the non-A answer semantics: an HTTPS
// (SVCB) answer is an ANSWERED query with no A trust, and the kind measures "did the
// response carry answer records", not "did it carry records of the queried type".
func TestClientDiagnosisRecordsHTTPSAnswer(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryType(t, "https.example", mdns.TypeHTTPS, 56501)

	sessionID := f.sessionID(t)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()
	events := ledger.SnapshotEvents(sessionID, 0).Events
	if len(events) != 1 {
		t.Fatalf("events = %d, want the one query", len(events))
	}
	event := events[0]
	if event.QType != mdns.TypeHTTPS {
		t.Errorf("qtype = %d, want HTTPS (%d)", event.QType, mdns.TypeHTTPS)
	}
	if event.Kind != gatewaydns.QueryEventAnswered {
		t.Errorf("kind = %q, want answered: the response carried an SVCB record", event.Kind)
	}
	if event.RCode != mdns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", event.RCode)
	}

	// No A trust: an SVCB answer produced no route evidence and no answer record.
	if got := f.routeCache.SessionScope(sessionID).Count(); got != 0 {
		t.Errorf("evidence entries = %d, want none from an HTTPS answer", got)
	}
	// The answer HISTORY records the query as seen, with no addresses because the
	// observation path rejected it; route evidence stays empty.
	records := ledger.Snapshot(sessionID, 0)
	if records.Total != 1 {
		t.Fatalf("answer records = %d, want the one query recorded as seen", records.Total)
	}
	if len(records.Records[0].Addresses) != 0 {
		t.Errorf("record addresses = %+v, want none from an SVCB answer", records.Records[0].Addresses)
	}
	if records.Records[0].ClassificationValid {
		t.Error("an SVCB answer was recorded as a valid A classification")
	}
}

// TestClientDiagnosisRecordsAdmissionRefusal induces a GENUINE refusal through the
// real limiter: one in-flight query holds the only per-session slot, the next is
// refused before any upstream attempt, receives SERVFAIL, is attributed as a refusal
// (not an upstream failure), creates no trust, and the session recovers.
func TestClientDiagnosisRecordsAdmissionRefusal(t *testing.T) {
	f := newClientDiagFixtureWithInflight(t, 1)
	sessionID := f.sessionID(t)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()

	// The first query blocks inside the upstream exchange and holds the slot.
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.queryIP(t, "slow.example", 56601)
	}()
	select {
	case <-f.slowEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("the blocking query never reached the upstream exchange")
	}

	// The second query must be refused by the limiter, before any upstream attempt.
	refusedPacket := buildTestPBRUDPPacket(f.clientIP, f.gwDNS, 56602, 53, packEventQuery(t, "plain.example", mdns.TypeA))
	if err := f.fwd.RouteClientToBackend(f.peerKey, refusedPacket); err != nil {
		t.Fatalf("refused query dispatch: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if events := ledger.SnapshotEvents(sessionID, 0).Events; len(events) >= 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	events := ledger.SnapshotEvents(sessionID, 0).Events
	var refused *dnsledger.Event
	for i := range events {
		if events[i].Kind == gatewaydns.QueryEventAdmissionRefused {
			refused = &events[i]
		}
	}
	if refused == nil {
		t.Fatalf("no admission_refused event in %+v", events)
	}
	if refused.RCode != mdns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL as the client received it", refused.RCode)
	}
	if refused.UpstreamError != "" {
		t.Errorf("upstream class = %q, want none: the query never reached an upstream", refused.UpstreamError)
	}
	if refused.Name != "plain.example" {
		t.Errorf("refused query name = %q, want the refused query", refused.Name)
	}
	if got := f.routeCache.SessionScope(sessionID).Count(); got != 0 {
		t.Errorf("evidence entries = %d, want none from a refused query", got)
	}

	// Recovery: once the blocking query finishes, the same session is served.
	close(f.slowRelease)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the blocking query did not complete")
	}
	f.queryIP(t, "plain.example", 56603)
	var answered *dnsledger.Event
	for _, event := range ledger.SnapshotEvents(sessionID, 0).Events {
		candidate := event
		if candidate.Kind == gatewaydns.QueryEventAnswered && candidate.QType == mdns.TypeA {
			answered = &candidate
		}
	}
	if answered == nil {
		t.Error("the session did not recover: no answered event after the refusal")
	}
}

// packEventQuery packs one query into UDP payload bytes for the refusal control.
func packEventQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), qtype)
	req.Id = 0x7777
	raw, err := req.Pack()
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	return raw
}

// TestClientDiagnosisTerminalEventsLeaveWithTheSession proves the event history is
// released with the session and never leaks to a successor.
func TestClientDiagnosisTerminalEventsLeaveWithTheSession(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryType(t, "nx.example", mdns.TypeA, 56101)
	sessionID := f.sessionID(t)
	ledger := f.svc.clientDiagnosisRouteCache().DNSLedger()
	if got := ledger.SnapshotEvents(sessionID, 0).Total; got != 1 {
		t.Fatalf("events before retirement = %d, want 1", got)
	}

	f.fwd.UnregisterSession(f.peerKey)
	if got := ledger.SnapshotEvents(sessionID, 0).Total; got != 0 {
		t.Errorf("events after retirement = %d, want none: the history leaves with the session", got)
	}
}
