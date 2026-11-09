package gigahostbudget

// Coverage for the operator-facing "proof needed" text and for the recovery
// proposal's retained list carrying it.
//
// The point of these tests is not the wording; it is that every kept reservation
// names an observation that provider evidence can actually supply, and that no
// kept reservation ever names an operator note, a synthetic local identifier, an
// omission or a waitlist order as the thing that would release it.

import (
	"strings"
	"testing"
)

// TestProofNeededNamesAProviderFact asserts that every unresolved reason this
// package produces is described by a concrete provider observation.
func TestProofNeededNamesAProviderFact(t *testing.T) {
	tests := []struct {
		name    string
		entry   Entry
		verdict Verdict
		want    []string
		deny    []string
	}{
		{
			name:    "synthetic id points at a real identity",
			entry:   entry(1, "intent_1700000000000000000", 0, "unknown", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: "synthetic_order_id"},
			want:    []string{"real provider order id or server id", "intent_1700000000000000000"},
			deny:    []string{"note", "acknowledge"},
		},
		{
			name:    "missing identity asks for an identity",
			entry:   entry(1, "", 0, "pending", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: "missing_identity"},
			want:    []string{"provider order id or provider server id"},
		},
		{
			name:    "failed query asks for a successful read",
			entry:   entry(1, "10001", 0, "ready", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: "provider_unreachable"},
			want:    []string{"successful provider read", "proves nothing"},
		},
		{
			name:    "resource-only status asks for a billing-relevant status",
			entry:   entry(1, "10001", 7, "ready", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: "provider_status_not_billability"},
			want:    []string{"terminated/deleted", "resource state only"},
		},
		{
			name:    "status-less answer asks for a status",
			entry:   entry(1, "10001", 0, "ready", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: "provider_order_status_absent"},
			want:    []string{"deployment status", "does not establish"},
		},
		{
			name:    "stored cancellation asks for the post-cancellation terminal state",
			entry:   entry(1, "10001", 7, "cancelled", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: reasonLocalCancelledUnsupported},
			want:    []string{"terminated or deleted", "still bills"},
		},
		{
			name:    "unidentifiable price asks for the order-time contract",
			entry:   entry(1, "10001", 0, "ready", 202, 0),
			verdict: Verdict{State: StateUnresolved, Reason: "price_unidentifiable"},
			want:    []string{"order-time price contract", "exactly one monthly amount"},
		},
		{
			name:    "unrecognized local status asks for a recognized state or provider answer",
			entry:   entry(1, "10001", 7, "mystery", 202, 0.057),
			verdict: Verdict{State: StateUnresolved, Reason: "unrecognized_local_status"},
			want:    []string{"recognized local status", "provider answer"},
		},
		{
			name:    "stale release marker asks for a new terminal fact",
			entry:   entry(1, "10001", 7, "ready", 202, 0.057),
			verdict: Verdict{State: StateActive, Reason: "released_but_provider_live"},
			want:    []string{"ending the obligation again", "stale"},
		},
		{
			name:    "a live waitlist order asks for a terminal server fact",
			entry:   entry(1, "10001", 0, "pending", 202, 0.057),
			verdict: Verdict{State: StateActive, Reason: "provider_waitlist_pending"},
			want:    []string{"terminated or deleted", "waitlist or running order stays counted"},
			deny:    []string{"waitlist order is proof"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ProofNeeded(tc.entry, tc.verdict)
			if got == "" {
				t.Fatal("a kept reservation must say what proof it needs")
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("proof text %q does not mention %q", got, want)
				}
			}
			for _, deny := range tc.deny {
				if strings.Contains(got, deny) {
					t.Errorf("proof text %q must not claim %q", got, deny)
				}
			}
		})
	}
}

// TestProposeRetainedCarriesProofAndNoProofForReleases pins the split: a proposed
// release already rests on conclusive evidence and needs no further proof, while
// every kept reservation names one.
func TestProposeRetainedCarriesProofAndNoProofForReleases(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	entries := []Entry{
		entry(1, "intent_1", 0, "unknown", 202, 0.057),
		entry(2, "10001", 7, "ready", 202, 0.057),
		entry(3, "20002", 8, "waiting", 202, 0.057),
	}
	in := Input{
		CapNOK:  200,
		Plans:   catalog,
		Entries: entries,
		Evidence: map[int64]Evidence{
			2: {ServerFound: true, ServerStatus: "terminated"},
			3: {ProviderOrderFound: true, ProviderOrderStatus: "waitlist"},
		},
	}
	p, err := Propose(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Changes) != 1 || p.Changes[0].RecordID != 2 {
		t.Fatalf("changes = %+v, want exactly the terminated record 2", p.Changes)
	}
	if p.Changes[0].ProofNeeded != "" {
		t.Errorf("a proposed release must not also ask for proof: %q", p.Changes[0].ProofNeeded)
	}
	if len(p.Retained) != 2 {
		t.Fatalf("retained = %+v, want the synthetic row and the waitlist order", p.Retained)
	}
	for _, r := range p.Retained {
		if r.ProofNeeded == "" {
			t.Errorf("retained record %d does not name the proof it needs", r.RecordID)
		}
	}
	// The waitlist row must not be described as releasable by any waitlist fact.
	for _, r := range p.Retained {
		if r.RecordID != 3 {
			continue
		}
		if strings.Contains(r.ProofNeeded, "waitlist") && !strings.Contains(r.ProofNeeded, "stays counted") {
			t.Errorf("the waitlist row's proof text must not suggest the waitlist itself releases it: %q", r.ProofNeeded)
		}
	}
}

// TestProposeInventoryRetentionPointsAtTheInventoryRow proves the retained text
// for an inventory-counted commitment does not pretend to be a ledger row.
func TestProposeInventoryRetentionPointsAtTheInventoryRow(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	in := Input{
		CapNOK: 100,
		Plans:  catalog,
		Servers: []Server{
			{ID: 7, OrderID: "10001", PlanID: 202, Status: "ready", Hourly: true},
		},
	}
	p, err := Propose(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Retained) != 1 {
		t.Fatalf("retained = %+v, want the live inventory server", p.Retained)
	}
	got := p.Retained[0].ProofNeeded
	if !strings.Contains(got, "inventory row") || !strings.Contains(got, "terminated or deleted") {
		t.Errorf("inventory retention proof = %q, want it to name the inventory row and the terminal status", got)
	}
}

// TestProofNeededNeverMentionsAnOperatorWaiver is the guard against reintroducing
// the acknowledgement path the approved scope forbids.
func TestProofNeededNeverMentionsAnOperatorWaiver(t *testing.T) {
	reasons := []string{
		"provider_unreachable", "provider_status_not_billability", "provider_order_status_absent",
		"synthetic_order_id", "missing_identity",
		"unrecognized_local_status", "price_unidentifiable", "released_but_provider_live",
		"terminal_local_status", "committed", "provider_resource_running", "provider_order_live",
		"provider_waitlist_pending", "released", "unheard_of_reason",
	}
	e := entry(1, "10001", 7, "ready", 202, 0.057)
	for _, reason := range reasons {
		got := ProofNeeded(e, Verdict{Reason: reason})
		if got == "" {
			t.Errorf("reason %q has no proof text", reason)
			continue
		}
		lower := strings.ToLower(got)
		for _, banned := range []string{"note from", "operator confirms", "declare it", "waive", "assume"} {
			if strings.Contains(lower, banned) {
				t.Errorf("reason %q proof text invites a waiver (%q): %q", reason, banned, got)
			}
		}
	}
}
