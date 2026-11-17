package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	mdns "github.com/miekg/dns"
)

// TestCacheVerdictTokenNamesEveryRefusal pins the mapping from the route cache's
// answer to the token a record carries, so a refused write is never reported as
// "ok".
func TestCacheVerdictTokenNamesEveryRefusal(t *testing.T) {
	cases := map[string]error{
		"ok":                  nil,
		"session_retired":     policy.ErrSessionRetired,
		"generation_mismatch": policy.ErrGenerationMismatch,
		"quarantined":         policy.ErrCapacityExceeded,
		"error":               errors.New("something else"),
	}
	for want, err := range cases {
		if got := cacheVerdictToken(err); got != want {
			t.Errorf("cacheVerdictToken(%v) = %q, want %q", err, got, want)
		}
	}
	// A wrapped policy error keeps its class rather than falling through to
	// "error".
	wrapped := fmt.Errorf("observe: %w", policy.ErrSessionRetired)
	if got := cacheVerdictToken(wrapped); got != "session_retired" {
		t.Errorf("wrapped refusal token = %q, want session_retired", got)
	}
}

// Producer-to-service coverage for the DNS observation records (issue #861,
// slice 2).
//
// Every record asserted here is produced by the real chain: a client DNS query
// enters RouteClientToBackend, the intercepted handler forwards it to the
// gateway, the gateway's server classifies the answer, writes evidence into the
// session's route cache and calls the registered observer, which is the only
// writer of these records. The assertions then describe what ClientDiagnosis
// reports, so a change anywhere in that chain shows up here.

func findDNSRecord(t *testing.T, records []ClientDiagnosisDNSRecord, name string) ClientDiagnosisDNSRecord {
	t.Helper()
	for _, record := range records {
		if record.Name == name {
			return record
		}
	}
	t.Fatalf("no DNS record for %q; records=%+v", name, records)
	return ClientDiagnosisDNSRecord{}
}

// TestClientDiagnosisReportsObservedDNSAnswers is the primary positive control:
// what the client asked, what the answer carried and which decision was written
// are all reported, with the instant, deadline and incarnation of that write.
func TestClientDiagnosisReportsObservedDNSAnswers(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 54001)
	f.queryIP(t, "proxy.example", 54002)

	sessionID := f.sessionID(t)
	generation := f.generation(t)
	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if !answer.DNS.Available || !answer.DNS.RecordsAvailable {
		t.Fatalf("dns = %+v, want both sections available", answer.DNS)
	}
	if answer.DNS.RecordsTotal != 2 || len(answer.DNS.Records) != 2 {
		t.Fatalf("records = %d (total %d), want the two queries", len(answer.DNS.Records), answer.DNS.RecordsTotal)
	}

	direct := findDNSRecord(t, answer.DNS.Records, "plain.example")
	if direct.QType != "A" || direct.RCode != "NOERROR" {
		t.Errorf("qtype/rcode = %q/%q, want the observed exchange", direct.QType, direct.RCode)
	}
	if direct.Classification != "valid" || direct.ClassificationReason != "" {
		t.Errorf("classification = %q/%q, want a valid answer", direct.Classification, direct.ClassificationReason)
	}
	if direct.CacheWrite != "ok" {
		t.Errorf("cache write = %q, want ok", direct.CacheWrite)
	}
	if len(direct.Addresses) != 1 || direct.Addresses[0].Address != f.example.String() || direct.Addresses[0].Decision != policy.Direct.String() {
		t.Errorf("addresses = %+v, want the DIRECT decision that was written", direct.Addresses)
	}
	if direct.ObservedAt == "" || direct.ExpiresAt == "" || direct.ExpiresInSeconds <= 0 {
		t.Errorf("instants = %q/%q/%d, want a recorded observation and deadline", direct.ObservedAt, direct.ExpiresAt, direct.ExpiresInSeconds)
	}
	if direct.State != "active" {
		t.Errorf("state = %q, want active", direct.State)
	}
	if !direct.IncarnationKnown || direct.RouteGeneration == nil || *direct.RouteGeneration != generation {
		t.Errorf("incarnation = %v/%v, want the registered generation %d", direct.RouteGeneration, direct.IncarnationKnown, generation)
	}
	if direct.PolicyGeneration == "" && answer.Selection.PolicyGeneration != "" {
		t.Errorf("policy generation missing from the record but known to the selection")
	}
	if direct.Transport != ClientDiagnosisTokenNotRecorded || direct.ReceivedAt != ClientDiagnosisTokenNotRecorded {
		t.Errorf("transport/received = %q/%q, want explicit not_recorded tokens", direct.Transport, direct.ReceivedAt)
	}
	if direct.Count != 1 || direct.FirstSeen == "" || direct.LastSeen == "" {
		t.Errorf("count/first/last = %d/%q/%q, want one observation", direct.Count, direct.FirstSeen, direct.LastSeen)
	}
	if len(direct.Aliases) != 0 {
		t.Errorf("aliases = %v, want none for an answer without a CNAME", direct.Aliases)
	}

	proxied := findDNSRecord(t, answer.DNS.Records, "proxy.example")
	if len(proxied.Addresses) != 1 || proxied.Addresses[0].Decision != policy.Proxy.String() {
		t.Errorf("proxy answer addresses = %+v, want the PROXY decision", proxied.Addresses)
	}

	// The section states the gaps of this observation boundary instead of
	// implying completeness.
	for _, want := range []string{
		ClientDiagnosisLimitDNSTransport,
		ClientDiagnosisLimitDNSFailures,
		ClientDiagnosisLimitDNSNonAQueries,
		ClientDiagnosisLimitDNSReceiveTime,
	} {
		if !clientDiagHas(answer.DNS.RecordCoverage.NotRecorded, want) {
			t.Errorf("record coverage is missing %q: %v", want, answer.DNS.RecordCoverage.NotRecorded)
		}
	}
	if !clientDiagHas(answer.Limitations, ClientDiagnosisLimitDNSCoverage) {
		t.Errorf("answer limitations must state that DNS coverage is partial: %v", answer.Limitations)
	}
	if answer.DNS.RecordCoverage.Limits.RecordsPerSession == 0 || answer.DNS.RecordCoverage.Limits.MaxAgeSeconds == 0 {
		t.Errorf("record limits = %+v, want the bounds in force", answer.DNS.RecordCoverage.Limits)
	}
	if answer.DNS.RecordCoverage.StartedAt == "" {
		t.Error("the collector must report when it began")
	}

	// The wire shape is what the browser receives.
	raw, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"records"`, `"record_coverage"`, `"records_available"`, `"aliases"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("wire answer is missing %s", key)
		}
	}
	if strings.Contains(string(raw), f.peerKey) {
		t.Errorf("the answer carries the peer key: %s", raw)
	}
}

// TestClientDiagnosisReportsValidatedAliases proves a CNAME chain is reported as
// the chain the classifier validated, not as a second name lookup.
func TestClientDiagnosisReportsValidatedAliases(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "alias.example", 54101)

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	record := findDNSRecord(t, answer.DNS.Records, "alias.example")
	if len(record.Aliases) != 1 || record.Aliases[0] != "plain.example" {
		t.Errorf("aliases = %v, want the validated CNAME target", record.Aliases)
	}
	if len(record.Addresses) != 1 || record.Addresses[0].Address != f.example.String() {
		t.Errorf("addresses = %+v, want the terminal address of the chain", record.Addresses)
	}
}

// TestClientDiagnosisRecordsRejectedAndRepeatedQueries covers the two shapes a
// record can take besides a plain valid answer: an answer the observation path
// rejected, and a repeat of the same answer.
func TestClientDiagnosisRecordsRejectedAndRepeatedQueries(t *testing.T) {
	f := newClientDiagFixture(t)

	// A non-A query: the observation path does not evaluate it, so it produces no
	// evidence, and the record states exactly that.
	f.queryType(t, "plain.example", mdns.TypeAAAA, 54201)
	// The same valid answer twice: one record, counted.
	f.queryIP(t, "plain.example", 54202)
	f.queryIP(t, "plain.example", 54203)

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}

	var aaaa *ClientDiagnosisDNSRecord
	var a *ClientDiagnosisDNSRecord
	for i := range answer.DNS.Records {
		record := answer.DNS.Records[i]
		if record.QType == "AAAA" {
			aaaa = &answer.DNS.Records[i]
		}
		if record.QType == "A" {
			a = &answer.DNS.Records[i]
		}
	}
	if aaaa == nil {
		t.Fatalf("no AAAA record in %+v", answer.DNS.Records)
	}
	if aaaa.Classification != "invalid" || aaaa.ClassificationReason == "" {
		t.Errorf("AAAA classification = %q/%q, want invalid with a reason", aaaa.Classification, aaaa.ClassificationReason)
	}
	if len(aaaa.Addresses) != 0 {
		t.Errorf("AAAA record addresses = %+v, want none: the observation path did not evaluate it", aaaa.Addresses)
	}
	if aaaa.State != ClientDiagnosisTokenNotRecorded {
		t.Errorf("AAAA state = %q, want not_recorded for an answer with no deadline", aaaa.State)
	}

	if a == nil {
		t.Fatal("no A record for the repeated query")
	}
	if a.Count != 2 {
		t.Errorf("A record count = %d, want the two identical answers collapsed", a.Count)
	}
	// The non-A query must not have produced evidence for the cache.
	for _, entry := range answer.DNS.Entries {
		if entry.Address == f.example.String() && entry.Decision != policy.Direct.String() {
			t.Errorf("the AAAA query changed the evidence for %s: %+v", f.example, entry)
		}
	}
}

// TestClientDiagnosisDNSRecordsAreIsolatedAndRetired proves one client's history
// never appears for another, and that retirement removes it. The second client's OWN
// history is asserted first: without that positive, the absence below would also hold if
// that client's query had never reached the collector at all.
func TestClientDiagnosisDNSRecordsAreIsolatedAndRetired(t *testing.T) {
	f := newClientDiagFixture(t)
	const primaryPort = uint16(54301)
	f.queryIP(t, "plain.example", primaryPort)
	firstSession := f.sessionID(t)

	// A second client with its own session, its own route and its own return path.
	otherIP := netip.MustParseAddr("10.100.0.11")
	otherPeer := "peer-client-diag-dns"
	otherSession, otherGeneration := f.registerSecondClient(t, "user-2", otherPeer, otherIP, "tablet")
	otherPlan := dnsQueryPlan{
		name: "proxy.example", qtype: mdns.TypeA, srcPort: 54302, id: 0x5555,
		clientIP: otherIP, peerKey: otherPeer,
	}

	// The first client's reply is already captured. It carries this question, port and
	// DNS id, so only the client address can tell the two clients apart: a wait for the
	// second client must not adopt it before the second query is even sent.
	wrongClient := dnsQueryPlan{
		name: "plain.example", qtype: mdns.TypeA, srcPort: primaryPort, id: 0x1234,
		clientIP: otherIP,
	}
	if reply, ok := f.awaitReply(newQueryWatch(wrongClient, otherSession, otherGeneration, nil), 100*time.Millisecond); ok {
		t.Fatalf("the first client's reply satisfied the second client's wait (%d bytes)", len(reply))
	}

	// The second client's query is followed to its own reply AND its own terminal
	// publication; nothing about the first client's already captured reply stands in.
	if _, err := f.query(otherPlan); err != nil {
		t.Fatalf("the second client's query did not settle on its own publications: %v", err)
	}

	// Positive: the second client's history really contains its own query.
	otherAnswer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: otherSession})
	if err != nil {
		t.Fatalf("ClientDiagnosis for the second client: %v", err)
	}
	otherHasQuery := false
	for _, record := range otherAnswer.DNS.Records {
		if record.Name == "proxy.example" && record.QType == "A" {
			otherHasQuery = true
		}
		if record.Name == "plain.example" {
			t.Errorf("the second client's history contains the first client's query: %+v", record)
		}
	}
	if !otherHasQuery {
		t.Fatalf("the second client's own history does not contain its query: %+v", otherAnswer.DNS.Records)
	}

	// Negative, and only now that the other client's record is known to exist: the first
	// client's history does not contain it.
	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: firstSession})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	for _, record := range answer.DNS.Records {
		if record.Name == "proxy.example" {
			t.Error("the first client's history contains the other client's query")
		}
	}
	if len(answer.DNS.Records) != 1 {
		t.Errorf("records = %d, want only this client's query", len(answer.DNS.Records))
	}

	// Ownership: retiring the second client releases its record, and the first client's
	// record does not move with it.
	f.fwd.UnregisterSession(otherPeer)
	retiredOther, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: otherSession})
	if err != nil {
		t.Fatalf("ClientDiagnosis for the second client after retirement: %v", err)
	}
	if retiredOther.Selection.State == ClientDiagnosisStateLive {
		t.Fatalf("a retired second client was reported live")
	}
	if len(retiredOther.DNS.Records) != 0 {
		t.Errorf("retired second client returned %d records, want none", len(retiredOther.DNS.Records))
	}
	if snapshot, ok := f.svc.clientDiagnosisDNSRecords(otherSession, 0); ok && snapshot.Total != 0 {
		t.Errorf("the collector still holds %d records for the retired second client", snapshot.Total)
	}
	stillOwned, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: firstSession})
	if err != nil {
		t.Fatalf("ClientDiagnosis for the first client after the other client's retirement: %v", err)
	}
	if len(stillOwned.DNS.Records) != 1 {
		t.Errorf("the first client's record left with another client's retirement: %d records",
			len(stillOwned.DNS.Records))
	}

	// Retirement releases the record with the session's scope.
	f.fwd.UnregisterSession(f.peerKey)
	retired, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: firstSession})
	if err != nil {
		t.Fatalf("ClientDiagnosis after retirement: %v", err)
	}
	if retired.Selection.State == ClientDiagnosisStateLive {
		t.Fatalf("a retired session was reported live")
	}
	if len(retired.DNS.Records) != 0 {
		t.Errorf("retired session returned %d records, want none", len(retired.DNS.Records))
	}
	// The collector holds nothing for it either: a fresh read of the store
	// through the service must agree.
	if snapshot, ok := f.svc.clientDiagnosisDNSRecords(firstSession, 0); ok && snapshot.Total != 0 {
		t.Errorf("the collector still holds %d records for the retired session", snapshot.Total)
	}
}

// TestClientDiagnosisDNSRecordsKeepTheirIncarnation proves a record states the
// route generation that was registered when the answer arrived, including across
// a same-session rekey.
func TestClientDiagnosisDNSRecordsKeepTheirIncarnation(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 54401)
	firstGeneration := f.generation(t)

	// A same-session rekey: the session keeps its DNS history but gets a new
	// route generation.
	f.fwd.RegisterSessionWithReturnPath(f.sessionID(t), "conn-1", f.peerKey, f.clientIP.String(), 11, f.returnPath)
	secondGeneration := f.generation(t)
	if secondGeneration == firstGeneration {
		t.Fatal("rekey did not advance the route generation")
	}
	f.queryIP(t, "proxy.example", 54402)

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if len(answer.DNS.Records) != 2 {
		t.Fatalf("records = %d, want both queries: DNS history survives a rekey", len(answer.DNS.Records))
	}
	for _, record := range answer.DNS.Records {
		if !record.IncarnationKnown || record.RouteGeneration == nil {
			t.Errorf("record %q has no established incarnation", record.Name)
			continue
		}
		want := firstGeneration
		if record.Name == "proxy.example" {
			want = secondGeneration
		}
		if *record.RouteGeneration != want {
			t.Errorf("record %q generation = %d, want %d", record.Name, *record.RouteGeneration, want)
		}
	}
	// The flow half of a rekey is purged, so the flow section stays empty; the
	// DNS half must not be.
	if len(answer.Flows.Entries) != 0 {
		t.Errorf("flows = %d after a rekey, want 0", len(answer.Flows.Entries))
	}
}

// TestClientDiagnosisDNSReadDoesNotMoveTheCollector is the read-only control for
// the new store: repeated diagnoses report identical records and identical
// collector counters.
func TestClientDiagnosisDNSReadDoesNotMoveTheCollector(t *testing.T) {
	f := newClientDiagFixture(t)
	f.queryIP(t, "plain.example", 54501)
	f.queryIP(t, "proxy.example", 54502)
	sessionID := f.sessionID(t)

	first, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	second, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}

	if len(first.DNS.Records) != len(second.DNS.Records) {
		t.Fatalf("record count moved between reads: %d -> %d", len(first.DNS.Records), len(second.DNS.Records))
	}
	for i := range first.DNS.Records {
		a, b := first.DNS.Records[i], second.DNS.Records[i]
		if a.Seq != b.Seq || a.Name != b.Name || a.Count != b.Count || a.LastSeen != b.LastSeen {
			t.Errorf("record %d moved between reads: %+v -> %+v", i, a, b)
		}
	}
	if first.DNS.RecordCoverage.Written != second.DNS.RecordCoverage.Written ||
		first.DNS.RecordCoverage.Collapsed != second.DNS.RecordCoverage.Collapsed ||
		first.DNS.RecordCoverage.RecordsStored != second.DNS.RecordCoverage.RecordsStored ||
		first.DNS.RecordCoverage.AgedOut != second.DNS.RecordCoverage.AgedOut {
		t.Errorf("collector counters moved between reads: %+v -> %+v", first.DNS.RecordCoverage, second.DNS.RecordCoverage)
	}
	// And the evidence section is unchanged too: the read touched neither store.
	if len(first.DNS.Entries) != len(second.DNS.Entries) {
		t.Errorf("evidence entries moved between reads: %d -> %d", len(first.DNS.Entries), len(second.DNS.Entries))
	}
}

// TestClientDiagnosisWithoutACollectorSaysNotRecorded pins the unavailable case:
// a service whose policy runtime has no ledger must not report an empty history
// as if nothing had been observed.
func TestClientDiagnosisWithoutACollectorSaysNotRecorded(t *testing.T) {
	f := newClientDiagFixture(t)
	// Detach the collector from the cache the service reads.
	routeCache := f.svc.clientDiagnosisRouteCache()
	if routeCache == nil {
		t.Fatal("fixture has no route cache")
	}
	routeCache.dnsRecordsMu.Lock()
	detached := routeCache.dnsRecords
	routeCache.dnsRecords = nil
	routeCache.dnsRecordsMu.Unlock()
	t.Cleanup(func() {
		routeCache.dnsRecordsMu.Lock()
		routeCache.dnsRecords = detached
		routeCache.dnsRecordsMu.Unlock()
	})

	f.queryIP(t, "plain.example", 54601)
	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.DNS.RecordsAvailable {
		t.Error("records_available = true without a collector")
	}
	if len(answer.DNS.Records) != 0 {
		t.Errorf("records = %d, want none", len(answer.DNS.Records))
	}
	if !clientDiagHas(answer.DNS.RecordCoverage.NotRecorded, ClientDiagnosisLimitDNSFailures) {
		t.Errorf("an unread collector must still state its gaps: %v", answer.DNS.RecordCoverage.NotRecorded)
	}
}

// TestClientDiagnosisDNSRecordBoundsAreReported proves the page bound is visible:
// a history larger than the page is truncated, not silently cut.
func TestClientDiagnosisDNSRecordBoundsAreReported(t *testing.T) {
	f := newClientDiagFixture(t)
	// The ledger default page is the per-session cap, so drive the service with an
	// explicit smaller page through the request.
	f.queryIP(t, "plain.example", 54701)
	f.queryIP(t, "proxy.example", 54702)

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{
		SessionID:      f.sessionID(t),
		DNSRecordLimit: 1,
	})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if len(answer.DNS.Records) != 1 || !answer.DNS.RecordsTruncated || answer.DNS.RecordsTotal != 2 {
		t.Fatalf("page = %d (total %d, truncated %v), want 1 of 2 truncated",
			len(answer.DNS.Records), answer.DNS.RecordsTotal, answer.DNS.RecordsTruncated)
	}
	if answer.DNS.Records[0].Name != "proxy.example" {
		t.Errorf("page starts with %q, want the newest answer", answer.DNS.Records[0].Name)
	}
}
