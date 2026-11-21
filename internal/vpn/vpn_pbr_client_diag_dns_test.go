package vpn

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"testing"
)

// This build records no client DNS evidence: the producer, the route cache and
// the history store that carried it are deleted. The wire answer must therefore
// carry no DNS member at all. Shipping an empty `dns` object would tell a client
// that the section exists and happens to be empty, which is a different claim
// from "this build has no such section", and the panel would have to keep a
// renderer for a history nothing can produce.
//
// The check is structural: every object key of the decoded answer is collected,
// so a section re-added under another spelling is still caught.
func TestClientDiagnosisWireCarriesNoDNSMember(t *testing.T) {
	f := newClientDiagFixture(t)
	// One real flow, so the per-flow field checks below are not vacuous.
	f.sendTCP(t, netip.MustParseAddr("1.1.1.1"), 41200, 443)

	answer, err := f.svc.ClientDiagnosis(context.Background(), ClientDiagnosisRequest{SessionID: f.sessionID(t)})
	if err != nil {
		t.Fatalf("ClientDiagnosis: %v", err)
	}
	if answer.Selection.State != ClientDiagnosisStateLive {
		t.Fatalf("selection state = %q, want live", answer.Selection.State)
	}
	if len(answer.Flows.Entries) == 0 {
		t.Fatal("the fixture produced no flow; the per-flow checks would prove nothing")
	}

	raw, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := jsonKeys(decoded)

	for _, forbidden := range []string{"dns", "records", "events", "records_available", "events_available", "record_coverage", "event_coverage"} {
		if keys[forbidden] {
			t.Errorf("wire answer carries %q, which this build cannot produce", forbidden)
		}
	}
	// The surviving sections are still present and named, so the absence above is
	// a deletion and not an accidentally empty answer.
	for _, wanted := range []string{"selection", "coverage", "flows", "drops", "limitations", "evaluated_at", "read_only"} {
		if !keys[wanted] {
			t.Errorf("wire answer is missing the surviving section %q", wanted)
		}
	}
	for _, name := range flowNameKeys(decoded) {
		t.Errorf("flow record still carries the per-flow name field %q", name)
	}
}

// jsonKeys flattens every object key of a decoded JSON value.
func jsonKeys(value any) map[string]bool {
	keys := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				keys[key] = true
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return keys
}

// flowNameKeys reports the name-bearing keys the flow section still carries, in
// a stable order so the failure message is readable.
func flowNameKeys(decoded map[string]any) []string {
	flows, _ := decoded["flows"].(map[string]any)
	entries, _ := flows["entries"].([]any)
	found := map[string]bool{}
	for _, entry := range entries {
		record, _ := entry.(map[string]any)
		for key := range record {
			switch key {
			case "names", "names_match", "names_reason", "names_considered", "name_candidates", "name_attempts":
				found[key] = true
			}
		}
	}
	out := make([]string, 0, len(found))
	for key := range found {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
