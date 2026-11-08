package gigahostbudget

// A1b reproduction oracles for the financial-lifecycle counterexample.
//
// A1 treated a waitlist reservation as "not billed, therefore over". The provider
// Public contract: https://gigahost.no/en/api-dokumentasjon
// The contract says the opposite: a waitlist reservation is a HELD order that deploys
// automatically:
//
//	"Reservations are held orders that deploy automatically when capacity frees up
//	 anywhere in the region ... Nothing is billed while a reservation waits."
//
//	"waitlist - reserved on the waitlist, deploys automatically once capacity
//	 frees up"
//
// Temporary non-billing is not final obsolescence. Releasing on it writes an
// irreversible marker, and that marker then suppressed both the count and the
// duplicate guard. These tests pin the corrected lifetime classification.

import (
	"testing"
)

// TestA1b_WaitlistIsAPendingCommitmentNotAnObsoleteOne is the primary
// counterexample.
//
// A waitlist order is unbilled *so far* but is a valid, still-armed commitment to
// buy; it activates without any new budget check. It must count, and it must never
// be releasable.
func TestA1b_WaitlistIsAPendingCommitment(t *testing.T) {
	e := entry(1, "10001", 0, "pending", 202, 0.057)
	v := Classify(e, Evidence{ProviderOrderFound: true, ProviderOrderStatus: "waitlist"})

	if v.Releasable {
		t.Fatalf("a waitlist reservation was releasable: %s", v.Explanation)
	}
	if v.State != StateActive {
		t.Fatalf("state = %q, want %q: a held order that deploys automatically is a live commitment", v.State, StateActive)
	}
	if v.Reason != "provider_waitlist_pending" {
		t.Errorf("reason = %q, want provider_waitlist_pending", v.Reason)
	}
	if v.Explanation == "" {
		t.Error("a verdict must explain itself")
	}
}

// TestA1b_WaitlistSpendIsCountedInTheTotal proves the counterexample's financial
// effect: the waitlist reservation occupies budget, so a second order that would
// exceed the cap is refused.
func TestA1b_WaitlistSpendIsCountedInTheTotal(t *testing.T) {
	catalog := []Plan{plan(101, 555, 0.15, 59), plan(202, 666, 0.057, 41)}
	waitlistEntry := entry(1, "10001", 0, "pending", 202, 0.057)

	res, err := Evaluate(Input{
		CapNOK:  90,
		Plans:   catalog,
		Entries: []Entry{waitlistEntry},
		Evidence: map[int64]Evidence{
			1: {ProviderOrderFound: true, ProviderOrderStatus: "waitlist"},
		},
		Request: &Request{PlanID: 101, PriceID: 555},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CommittedNOK != 41 {
		t.Fatalf("committed = %v, want 41: a waitlist reservation is a pending commitment", res.CommittedNOK)
	}
	if res.Allowed {
		t.Fatal("41 + 59 exceeds the 90 cap: the request must be refused while the waitlist order can still deploy")
	}
	if res.Reason != ReasonBudgetExceeded {
		t.Errorf("reason = %q, want %q", res.Reason, ReasonBudgetExceeded)
	}
}

// TestA1b_WaitlistIsNotProposedForRelease proves the recovery proposal also
// refuses it, so the operator path cannot perform what the classifier forbids.
func TestA1b_WaitlistIsNotProposedForRelease(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	in := Input{
		CapNOK:  100,
		Plans:   catalog,
		Entries: []Entry{entry(1, "10001", 0, "pending", 202, 0.057)},
		Evidence: map[int64]Evidence{
			1: {ProviderOrderFound: true, ProviderOrderStatus: "waitlist"},
		},
	}
	p, err := Propose(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Changes) != 0 {
		t.Fatalf("a waitlist reservation was proposed for release: %+v", p.Changes)
	}
	if p.CommittedBefore != 41 || p.CommittedAfter != 41 {
		t.Errorf("totals = %v -> %v, want 41 -> 41", p.CommittedBefore, p.CommittedAfter)
	}
}

// TestA1b_ReleasedMarkerCannotHideANewlyLiveObligation is the adjacent lifecycle
// defect the intake named.
//
// A row released while the order was on the waitlist is later deployed by the
// provider. The marker must not silently erase the now-live commitment: the
// provider's current answer wins, and the obligation is counted again.
func TestA1b_ReleasedMarkerCannotHideANewlyLiveObligation(t *testing.T) {
	released := Entry{
		RecordID: 1, OrderID: "10001", ServerID: 7, Status: "ready", PlanID: 202,
		HourlyPriceNOK: 0.057, ReleasedAt: "2026-11-01T00:00:00Z",
		ReleaseReason: "provider_waitlist_not_billed",
	}

	cases := []struct {
		name string
		ev   Evidence
		live bool
	}{
		{"provider reports the server running", Evidence{ServerFound: true, ServerStatus: "ready"}, true},
		{"provider reports the order ready", Evidence{ProviderOrderFound: true, ProviderOrderStatus: "ready"}, true},
		{"provider reports it installing", Evidence{ProviderOrderFound: true, ProviderOrderStatus: "installing"}, true},
		{"provider reports it terminated", Evidence{ServerFound: true, ServerStatus: "terminated"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(released, tc.ev)
			if tc.live {
				if v.State != StateActive {
					t.Fatalf("state = %q, want %q: a released marker must not hide a live obligation", v.State, StateActive)
				}
				if v.Reason != "released_but_provider_live" {
					t.Errorf("reason = %q, want released_but_provider_live", v.Reason)
				}
				if !v.State.Counts() {
					t.Error("a live obligation must count")
				}
				return
			}
			if v.State.Counts() {
				t.Errorf("state = %q: a terminally released reservation must not count", v.State)
			}
		})
	}
}

// TestA1b_ReleasedMarkerStillCountsAsReleasedWithoutEvidence keeps the pre-existing
// release semantics for the ordinary case: with no contradicting provider
// statement, a release marker stands.
func TestA1b_ReleasedMarkerStillCountsAsReleasedWithoutEvidence(t *testing.T) {
	released := Entry{
		RecordID: 1, OrderID: "10001", ServerID: 7, Status: "ready", PlanID: 202,
		ReleasedAt: "2026-11-01T00:00:00Z", ReleaseReason: "provider_terminated",
	}
	v := Classify(released, Evidence{})
	if v.State != StateReleased {
		t.Fatalf("state = %q, want %q", v.State, StateReleased)
	}
	if v.State.Counts() {
		t.Error("an unrebutted release must not count")
	}
}

// TestA1b_WaitlistDeployedStillCountsThroughTheLedger proves the whole lifetime
// in one pass: the same row observed as waitlist and then as a running server is
// counted in both phases, so the interval before the server is visible cannot be
// used to buy a second commitment.
func TestA1b_WaitlistDeployedStillCountsThroughTheLedger(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	rows := []Entry{entry(1, "10001", 0, "pending", 202, 0.057)}

	phases := []struct {
		name string
		ev   Evidence
	}{
		{"waitlisted", Evidence{ProviderOrderFound: true, ProviderOrderStatus: "waitlist"}},
		{"deploying", Evidence{ProviderOrderFound: true, ProviderOrderStatus: "deploying"}},
		{"server visible", Evidence{ServerFound: true, ServerStatus: "ready"}},
	}
	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			res, err := Evaluate(Input{
				CapNOK:   100,
				Plans:    catalog,
				Entries:  rows,
				Evidence: map[int64]Evidence{1: phase.ev},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.CommittedNOK != 41 {
				t.Fatalf("committed = %v, want 41 in phase %q", res.CommittedNOK, phase.name)
			}
		})
	}
}

// TestA1b_TerminationIsStillConclusive is the negative control that A1b must not
// break: a genuinely finished obligation is still released.
func TestA1b_TerminationIsStillConclusive(t *testing.T) {
	e := entry(1, "10001", 7, "ready", 202, 0.057)
	for status, want := range map[string]string{
		"terminated": "provider_terminated",
		"deleted":    "provider_deleted",
	} {
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: status})
		if !v.Releasable || v.State != StateObsolete || v.Reason != want {
			t.Errorf("status %q: state=%q releasable=%v reason=%q, want obsolete+releasable+%q",
				status, v.State, v.Releasable, v.Reason, want)
		}
	}
}

// TestA1b_OmissionAndWaiverRemainClosed guards the A1 corrections against A1b
// accidentally reopening them.
func TestA1b_OmissionAndWaiverRemainClosed(t *testing.T) {
	e := entry(1, "10001", 7, "ready", 202, 0.057)
	if v := Classify(e, Evidence{OrderOmittedFromDeployStatus: true}); v.Releasable {
		t.Error("a deploy-status omission became release evidence again")
	}
	if v := Classify(e, Evidence{OrderQueryFailed: true}); v.Releasable {
		t.Error("a failed provider query became release evidence again")
	}
}
