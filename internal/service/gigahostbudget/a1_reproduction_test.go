package gigahostbudget

// Reproduction and refutation oracles for the A1 intake findings.
//
// These are deliberately written as executable counterexamples against the
// public provider contract: https://gigahost.no/en/api-dokumentasjon
// Each test describes the contract fact it protects. A test that fails before
// the A1 correction and passes after it is the reproduction; a test that passes
// both before and after
// is the refutation of an intake claim.

import (
	"testing"
)

// TestA1_CancelledServerStillBilled is intake finding 1, confirmed.
//
// Contract E2: `cancelled` on a server is a PENDING
// cancellation. The server keeps running until termination_date and the hourly
// billing continues. Releasing on it drops a live commitment, which can let a
// second VPS be bought on budget the first one is still consuming.
func TestA1_CancelledServerStillBilled(t *testing.T) {
	e := entry(1, "10001", 7, "ready", 202, 0.057)
	for _, status := range []string{"cancelled", "canceled", "CANCELLED"} {
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: status})
		if v.State == StateObsolete || v.Releasable {
			t.Errorf("provider status %q released a pending cancellation: state=%q releasable=%v (%s)",
				status, v.State, v.Releasable, v.Explanation)
		}
		if v.State != StateUnresolved {
			t.Errorf("provider status %q: state = %q, want %q (still billed until termination_date)",
				status, v.State, StateUnresolved)
		}
	}
}

// TestA1_UndocumentedTerminalLabelsAreNotProof is intake finding 1, confirmed.
//
// Contract E3: the documentation gives no billing semantics for stopped,
// expired or refunded. An undocumented label cannot prove a charge does not
// exist, so it must not release spend.
func TestA1_UndocumentedTerminalLabelsAreNotProof(t *testing.T) {
	e := entry(1, "10001", 7, "ready", 202, 0.057)
	for _, status := range []string{"stopped", "expired", "refunded", "suspended", "offline", ""} {
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: status})
		if v.Releasable {
			t.Errorf("undocumented provider status %q was treated as proof of no charge", status)
		}
	}
}

// TestA1_DeployStatusOmissionIsNotProof is intake finding 1, confirmed.
//
// Contract E1: GET /deploy/status deliberately omits cancelled and
// deleted orders, so absence cannot distinguish "never existed" from "served and
// billed". A real provider order id that the endpoint omits must therefore NOT
// release the reservation.
func TestA1_DeployStatusOmissionIsNotProof(t *testing.T) {
	e := entry(1, "10001", 7, "ready", 202, 0.057)

	// Both the "not found" and "answered with no status" observations are
	// represented by the same zero-valued provider-order half of Evidence: the
	// corrected model gives the query no way to assert absence at all, and this
	// test proves that an observation which cannot assert it releases nothing.
	cases := []struct {
		name string
		ev   Evidence
	}{
		{"order omitted from deploy status", Evidence{}},
		{"order answered with no status", Evidence{ProviderOrderFound: true, ProviderOrderStatus: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(e, tc.ev)
			if v.Releasable {
				t.Fatalf("a deploy-status omission released a reservation (%s); contract E1 says the list omits cancelled orders too", v.Explanation)
			}
			// The reservation must stay counted. Whether it is reported active or
			// unresolved depends on other evidence, and either way the spend is
			// preserved.
			if !v.State.Counts() {
				t.Errorf("state = %q: an omission must never remove the commitment from the budget", v.State)
			}
		})
	}
}

// TestA1_RetainedConclusivePositives is the negative control for the
// correction: the two contract-supported release evidences must still work, so
// A1 cannot be "fixed" by refusing to release anything.
func TestA1_RetainedConclusivePositives(t *testing.T) {
	t.Run("terminated server ends the recurring commitment", func(t *testing.T) {
		e := entry(1, "10001", 7, "ready", 202, 0.057)
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: "terminated"})
		if v.State != StateObsolete || !v.Releasable || v.Reason != "provider_terminated" {
			t.Fatalf("state=%q releasable=%v reason=%q, want obsolete+releasable provider_terminated",
				v.State, v.Releasable, v.Reason)
		}
	})
	t.Run("deleted server ends the recurring commitment", func(t *testing.T) {
		e := entry(1, "10001", 7, "ready", 202, 0.057)
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: "deleted"})
		if v.State != StateObsolete || !v.Releasable || v.Reason != "provider_deleted" {
			t.Fatalf("state=%q releasable=%v reason=%q, want obsolete+releasable provider_deleted",
				v.State, v.Releasable, v.Reason)
		}
	})
	t.Run("waitlist reservation is contractually not billed", func(t *testing.T) {
		e := entry(1, "10001", 0, "waitlist", 202, 0.057)
		v := Classify(e, Evidence{ProviderOrderStatus: "waitlist", ProviderOrderFound: true})
		if v.State != StateObsolete || !v.Releasable || v.Reason != "provider_waitlist_not_billed" {
			t.Fatalf("state=%q releasable=%v reason=%q, want obsolete+releasable provider_waitlist_not_billed",
				v.State, v.Releasable, v.Reason)
		}
	})
	t.Run("a live ready server is still a commitment", func(t *testing.T) {
		e := entry(1, "10001", 7, "ready", 202, 0.057)
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: "ready", ProviderOrderFound: true, ProviderOrderStatus: "ready"})
		if v.State != StateActive || v.Releasable {
			t.Fatalf("state=%q releasable=%v, want active and not releasable", v.State, v.Releasable)
		}
	})
}

// TestA1_LocalLabelDoesNotOutrankContradictingProviderEvidence is intake
// finding 1, confirmed.
//
// The local row said "failed" but the provider reports the server as ready and
// running. Trusting the stale local label released a live commitment.
func TestA1_LocalLabelDoesNotOutrankContradictingProviderEvidence(t *testing.T) {
	e := entry(1, "10001", 7, "failed", 202, 0.057)
	v := Classify(e, Evidence{ServerFound: true, ServerStatus: "ready"})
	if v.State == StateObsolete || v.Releasable {
		t.Fatalf("a stale local 'failed' label released a server the provider reports as ready: %s", v.Explanation)
	}
}

// TestA1_UnknownLocalStatusStaysCounted is intake finding 1, confirmed.
//
// An unrecognised local label was treated as "not active", which silently
// dropped the reservation from the committed total. Only labels that the
// provider contract makes terminal may end a reservation.
func TestA1_UnknownLocalStatusStaysCounted(t *testing.T) {
	for _, status := range []string{"", "queued", "archived", "needs_review", "SOMETHING_NEW"} {
		e := entry(1, "10001", 7, status, 202, 0.057)
		v := Classify(e, Evidence{})
		if !v.State.Counts() {
			t.Errorf("unrecognised local status %q dropped a reservation from the committed total", status)
		}
		if v.State != StateUnresolved {
			t.Errorf("local status %q: state = %q, want %q", status, v.State, StateUnresolved)
		}
	}
}

// TestA1_LocalTerminalLabelDoesNotHideProviderContradiction proves the same rule
// in the direction that matters most: a locally terminal row whose provider
// server is demonstrably alive stays counted.
func TestA1_LocalTerminalLabelDoesNotHideProviderContradiction(t *testing.T) {
	e := entry(1, "10001", 7, "cancelled", 202, 0.057)
	v := Classify(e, Evidence{ServerFound: true, ServerStatus: "ready"})
	if !v.State.Counts() {
		t.Fatalf("a locally cancelled row whose server is still running was released: %s", v.Explanation)
	}
}

// TestA1_OperatorNoteIsNotReleaseProof is intake finding 2, confirmed.
//
// The approved scope forbids an administrator waiver in place of authoritative
// reconciliation. Evidence carrying only an operator note and a confirmation
// flag must never release spend.
func TestA1_OperatorNoteIsNotReleaseProof(t *testing.T) {
	e := entry(1, "intent_1700000000000000000", 0, "unknown", 202, 0.057)
	// Evidence cannot carry an operator assertion at all in the corrected
	// model: the waiver path was removed, so this is the strongest thing a
	// caller could construct for that record.
	v := Classify(e, Evidence{})
	if v.Releasable || v.State == StateObsolete {
		t.Fatalf("a free-text operator note released spend: state=%q releasable=%v", v.State, v.Releasable)
	}
	if v.State != StateUnresolved {
		t.Errorf("state = %q, want %q: an acknowledgement cannot establish the financial outcome", v.State, StateUnresolved)
	}
}

// TestA1_IPAloneIsNotIdentity is intake finding 3, confirmed.
//
// Contract E5: a routed IP "can be moved between your servers". Addresses are
// therefore reusable and cannot bind two records to one commitment.
func TestA1_IPAloneIsNotIdentity(t *testing.T) {
	t.Run("matching address does not pair a ledger row with a server", func(t *testing.T) {
		e := Entry{RecordID: 1, OrderID: "intent_1", Status: "unknown", PlanID: 202, AssignedIP: "192.0.2.10"}
		s := Server{ID: 7, PlanID: 202, Status: "ready", Hourly: true}
		if EntryMatchesServer(e, s) {
			t.Fatal("an assigned address alone paired two records; the provider documents that addresses move between servers")
		}
	})
	t.Run("two records sharing an address are still two commitments", func(t *testing.T) {
		catalog := []Plan{plan(202, 666, 0.057, 41)}
		entries := []Entry{
			{RecordID: 1, OrderID: "a", Status: "ready", PlanID: 202, AssignedIP: "192.0.2.10", HourlyPriceNOK: 0.057},
			{RecordID: 2, OrderID: "b", Status: "ready", PlanID: 202, AssignedIP: "192.0.2.10", HourlyPriceNOK: 0.057},
		}
		res, err := Evaluate(Input{CapNOK: 1000, Plans: catalog, Entries: entries})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.CommittedNOK != 82 {
			t.Fatalf("committed = %v, want 82: two distinct orders on one address are two commitments", res.CommittedNOK)
		}
	})
}

// TestA1_ConflictingIdentitiesKeepTheCommitment is intake finding 3, confirmed.
//
// The intake's concrete claim: a ledger row whose provider server id matches an
// inventory row was paired even when its non-empty provider order id named a
// different order. That drops or merges a distinct commitment.
func TestA1_ConflictingIdentitiesKeepTheCommitment(t *testing.T) {
	t.Run("matching server id with a conflicting order id does not pair", func(t *testing.T) {
		e := Entry{RecordID: 1, OrderID: "10001", ServerID: 7, Status: "ready", PlanID: 202, HourlyPriceNOK: 0.057}
		s := Server{ID: 7, OrderID: "20002", PlanID: 202, Status: "ready", Hourly: true}
		if EntryMatchesServer(e, s) {
			t.Fatal("a conflicting non-empty order id was ignored in favour of a matching server id")
		}
	})
	t.Run("the conflicting row still counts, and the inventory row counts too", func(t *testing.T) {
		catalog := []Plan{plan(202, 666, 0.057, 41)}
		entries := []Entry{{RecordID: 1, OrderID: "10001", ServerID: 7, Status: "ready", PlanID: 202, HourlyPriceNOK: 0.057}}
		servers := []Server{{ID: 7, OrderID: "20002", PlanID: 202, Status: "ready", Hourly: true}}
		res, err := Evaluate(Input{CapNOK: 1000, Plans: catalog, Servers: servers, Entries: entries})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.CommittedNOK != 82 {
			t.Fatalf("committed = %v, want 82: two contradictory identities are two possible commitments, not one", res.CommittedNOK)
		}
	})
}

// TestA1_PartialIdentityDedupStillWorks is the positive control that A1 must not
// break: a provider record with no order id, linked only by its server id, still
// deduplicates exactly once.
func TestA1_PartialIdentityDedupStillWorks(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	entries := []Entry{{RecordID: 1, OrderID: "known_local", ServerID: 7, Status: "ready", PlanID: 202, HourlyPriceNOK: 0.057}}
	servers := []Server{{ID: 7, PlanID: 202, Status: "ready", Hourly: true}}
	res, err := Evaluate(Input{CapNOK: 1000, Plans: catalog, Servers: servers, Entries: entries})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CommittedNOK != 41 {
		t.Fatalf("committed = %v, want 41: a server-id-only link must still deduplicate", res.CommittedNOK)
	}
}

// TestA1_SamePlanIsNotIdentity is the other required positive control: distinct
// VPS on the same plan and price must both count.
func TestA1_SamePlanIsNotIdentity(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	entries := []Entry{
		{RecordID: 1, OrderID: "a", Status: "ready", PlanID: 202, HourlyPriceNOK: 0.057},
		{RecordID: 2, OrderID: "b", Status: "ready", PlanID: 202, HourlyPriceNOK: 0.057},
	}
	res, err := Evaluate(Input{CapNOK: 1000, Plans: catalog, Entries: entries})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CommittedNOK != 82 {
		t.Fatalf("committed = %v, want 82: two orders on one plan are two commitments", res.CommittedNOK)
	}
}
