package vpn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestClientDiagnosisWithoutACollectorSaysNotRecorded pins the intermediate state
// this build ships in: the panel records no DNS evidence, so a live selection must
// report the record history as unavailable rather than as an empty history. A
// client that has observed nothing and a build that records nothing are different
// statements, and the section may only make the second one.
func TestClientDiagnosisWithoutACollectorSaysNotRecorded(t *testing.T) {
	f := newClientDiagFixture(t)

	if rc := f.svc.clientDiagnosisRouteCache(); rc != nil && rc.DNSLedger() != nil {
		t.Fatal("fixture still carries a DNS ledger: this build installs no collector")
	}

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.Selection.State != ClientDiagnosisStateLive {
		t.Fatalf("selection state = %q, want live", answer.Selection.State)
	}
	if answer.DNS.RecordsAvailable {
		t.Error("records_available = true without a collector")
	}
	if len(answer.DNS.Records) != 0 {
		t.Errorf("records = %d, want none", len(answer.DNS.Records))
	}
	// The unread state is stated by the availability flag, and the section claims no
	// per-store gap it cannot see.
	if len(answer.DNS.RecordCoverage.NotRecorded) != 0 {
		t.Errorf("an unread collector claimed gaps: %v", answer.DNS.RecordCoverage.NotRecorded)
	}
	if answer.DNS.RecordCoverage.StartedAt != "" {
		t.Errorf("a collector that was never consulted reported a start instant: %q", answer.DNS.RecordCoverage.StartedAt)
	}

	// The section is still present with its shape: every list member exists in the
	// wire answer, so a client never has to distinguish an absent key from "not
	// recorded". The shipped panel reads each list through `|| []`, so an empty
	// list is the only shape it has to handle either way.
	raw, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"entries"`, `"records"`, `"events"`, `"records_available"`, `"events_available"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("wire answer is missing %s", key)
		}
	}
}
