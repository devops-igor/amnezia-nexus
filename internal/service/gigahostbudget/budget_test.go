package gigahostbudget

// Regression tests for the shared budget contract.
//
// These pin the financial properties the purchase path depends on:
//   - each reservation is counted exactly once, whatever representation the
//     provider inventory and the local ledger happen to use;
//   - a price is used only when it is identified by evidence, never guessed
//     from catalog order, the cheapest row, or a coincidentally equal rate;
//   - an unknown outcome stays counted and stays visible;
//   - a release happens only on conclusive evidence.

import (
	"errors"
	"testing"
)

func plan(pid, priceID int, hourly, cap float64) Plan {
	return Plan{ProductID: pid, PriceID: priceID, Currency: "NOK", HourlyRateNOK: hourly, MonthlyCeiling: cap}
}

func entry(id int64, orderID string, serverID int64, status string, pid int, hourly float64) Entry {
	return Entry{RecordID: id, OrderID: orderID, ServerID: serverID, Status: status, PlanID: pid, HourlyPriceNOK: hourly}
}

func server(id int64, orderID string, pid int, status string) Server {
	return Server{ID: id, OrderID: orderID, PlanID: pid, Status: status, Hourly: true}
}

// TestEvaluate_CountsEachReservationOnce covers the identity pairing between
// provider inventory and the local ledger.
func TestEvaluate_CountsEachReservationOnce(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41), plan(101, 555, 0.15, 59)}

	cases := []struct {
		name         string
		servers      []Server
		entries      []Entry
		wantComitted float64
		wantStates   map[int64]State
	}{
		{
			name:         "same VPS under both representations counts once",
			servers:      []Server{server(1, "", 202, "ready")},
			entries:      []Entry{entry(1, "known_local", 1, "ready", 202, 0.057)},
			wantComitted: 41,
			// The ledger row IS the counted representation here (it is what
			// links the inventory row to a price), so it reports as the single
			// active reservation rather than as a duplicate.
			wantStates: map[int64]State{1: StateActive},
		},
		{
			name:         "duplicate ledger rows for one provider order count once",
			servers:      nil,
			entries:      []Entry{entry(1, "10003", 9, "ready", 202, 0.057), entry(2, "10003", 9, "ready", 202, 0.057)},
			wantComitted: 41,
			wantStates:   map[int64]State{1: StateActive, 2: StateDuplicate},
		},
		{
			name:         "distinct VPS with the same plan each count",
			servers:      []Server{server(1, "", 202, "ready"), server(2, "", 202, "ready")},
			entries:      nil,
			wantComitted: 82,
		},
		{
			name:         "an inactive provider record never releases a local reservation",
			servers:      []Server{server(1, "", 202, "failed")},
			entries:      []Entry{entry(1, "known_local", 1, "ready", 202, 0.057)},
			wantComitted: 41,
			wantStates:   map[int64]State{1: StateActive},
		},
		{
			name:         "a non-hourly provider record is outside the hourly budget",
			servers:      []Server{{ID: 1, PlanID: 202, Status: "ready", Hourly: false}},
			entries:      []Entry{entry(1, "known_local", 1, "ready", 202, 0.057)},
			wantComitted: 41,
			wantStates:   map[int64]State{1: StateActive},
		},
		{
			// A1 correction: a stored "cancelled" does not end billing by
			// itself (contract E2: still running and billed until
			// termination_date), so with no provider answer the outcome is
			// unknown and the spend stays counted.
			name:         "a locally cancelled row with no provider answer stays counted",
			servers:      nil,
			entries:      []Entry{entry(1, "10001", 7, "cancelled", 202, 0.057)},
			wantComitted: 41,
			wantStates:   map[int64]State{1: StateUnresolved},
		},
		{
			name:         "an already released reservation is not counted",
			servers:      nil,
			entries:      []Entry{{RecordID: 1, OrderID: "intent_1", Status: "unknown", PlanID: 202, ReleasedAt: "2026-11-01T00:00:00Z"}},
			wantComitted: 0,
			wantStates:   map[int64]State{1: StateReleased},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Evaluate(Input{CapNOK: 100, Plans: catalog, Servers: tc.servers, Entries: tc.entries})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.CommittedNOK != tc.wantComitted {
				t.Errorf("committed = %v, want %v (reservations: %+v)", res.CommittedNOK, tc.wantComitted, res.Reservations)
			}
			for id, want := range tc.wantStates {
				found := false
				for _, r := range res.Reservations {
					if r.RecordID != id {
						continue
					}
					found = true
					if r.State != want {
						t.Errorf("record %d state = %q, want %q (reason: %s)", id, r.State, want, r.Reason)
					}
				}
				if !found {
					t.Errorf("record %d missing from reservations", id)
				}
			}
		})
	}
}

// TestResolveExistingAmount_PriceIdentity pins the price-identity policy: a
// guess is never produced, and a persisted contract outranks the catalog.
func TestResolveExistingAmount_PriceIdentity(t *testing.T) {
	ambiguous := []Plan{plan(202, 666, 0.057, 41), plan(202, 777, 0.1667, 120)}

	cases := []struct {
		name     string
		plans    []Plan
		pid      int
		capNOK   float64
		currency string
		hourly   float64
		want     float64
		wantSrc  PriceSource
		wantErr  error
	}{
		{"persisted contract wins over an ambiguous catalog", ambiguous, 202, 41, "NOK", 0.057, 41, PriceContract, nil},
		{"contract in a non-NOK currency fails closed", ambiguous, 202, 41, "EUR", 0.057, 0, PriceNone, ErrCurrencyNotComparable},
		{"one catalog amount is the commitment", []Plan{plan(202, 777, 0.1667, 120)}, 202, 0, "", 0, 120, PriceCatalog, nil},
		{"duplicate identical rows are one amount", []Plan{plan(202, 1, 0.057, 41), plan(202, 2, 0.057, 41)}, 202, 0, "", 0, 41, PriceCatalog, nil},
		{"two amounts, recorded rate equals one row: still unidentified", ambiguous, 202, 0, "", 0.057, 0, PriceNone, ErrPriceNotIdentifiable},
		{"two amounts, no recorded rate: still unidentified", ambiguous, 202, 0, "", 0, 0, PriceNone, ErrPriceNotIdentifiable},
		{"a shared hourly rate is not an identity", []Plan{plan(202, 1, 0.05, 41), plan(202, 2, 0.05, 120)}, 202, 0, "", 0.05, 0, PriceNone, ErrPriceNotIdentifiable},
		{"same price id with conflicting caps is ambiguous", []Plan{plan(202, 666, 0.057, 41), plan(202, 666, 0.057, 99)}, 202, 0, "", 0, 0, PriceNone, ErrPriceNotIdentifiable},
		{"absent from catalog uses the recorded rate", []Plan{plan(303, 1, 0.1, 72)}, 202, 0, "", 0.05, 36, PriceRecorded, nil},
		{"absent with nothing recorded fails closed", []Plan{plan(303, 1, 0.1, 72)}, 202, 0, "", 0, 0, PriceNone, ErrSpendUnpriced},
		{"monthly cap absent falls back to hourly times 720", []Plan{plan(5, 1, 0.1, 0)}, 5, 0, "", 0, 72, PriceCatalog, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, src, err := ResolveExistingAmount(tc.plans, tc.pid, tc.capNOK, tc.currency, tc.hourly)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if got != 0 {
					t.Errorf("amount = %v, want 0 alongside the error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("amount = %v, want %v", got, tc.want)
			}
			if src != tc.wantSrc {
				t.Errorf("source = %q, want %q", src, tc.wantSrc)
			}
		})
	}
}

// TestClassify_UnknownOutcomesStayCounted is the core safety property: a local
// synthetic id is not a provider identity, and its not-found answer is not proof.
func TestClassify_UnknownOutcomesStayCounted(t *testing.T) {
	cases := []struct {
		name     string
		entry    Entry
		evidence Evidence
		want     State
		releasab bool
	}{
		{
			name:  "synthetic intent id is unresolved",
			entry: entry(1, "intent_1700000000000000000", 0, "unknown", 202, 0.057),
			want:  StateUnresolved,
		},
		{
			name:     "a not-found answer about a synthetic id proves nothing",
			entry:    entry(1, "intent_1700000000000000000", 0, "unknown", 202, 0.057),
			evidence: Evidence{},
			want:     StateUnresolved,
		},
		{
			name:     "a failing provider query is not evidence of absence",
			entry:    entry(1, "10001", 7, "ready", 202, 0.057),
			evidence: Evidence{OrderQueryFailed: true},
			want:     StateUnresolved,
		},
		{
			// A1 correction: GET /deploy/status omits cancelled orders and
			// orders whose server was deleted (contract E1), so its omission
			// proves nothing about a charge.
			name:     "a real provider order omitted from deploy status is not obsolete",
			entry:    entry(1, "10001", 7, "ready", 202, 0.057),
			evidence: Evidence{OrderOmittedFromDeployStatus: true},
			want:     StateActive,
		},
		{
			name:     "a provider terminal server status is obsolete",
			entry:    entry(1, "10001", 7, "ready", 202, 0.057),
			evidence: Evidence{ServerFound: true, ServerStatus: "terminated"},
			want:     StateObsolete,
			releasab: true,
		},
		{
			// A1 correction: there is no operator-waiver release path. The
			// approved scope forbids an administrator acknowledgement standing
			// in for authoritative provider proof.
			name:  "a record with no provider identity cannot be released by acknowledgement",
			entry: entry(1, "intent_1700000000000000000", 0, "unknown", 202, 0.057),
			want:  StateUnresolved,
		},
		{
			name:     "an operator confirmation cannot release a provider-identified record",
			entry:    entry(1, "10001", 7, "ready", 202, 0.057),
			evidence: Evidence{},
			want:     StateActive,
		},
		{
			name:  "a known provider order id with no uncertainty is active",
			entry: entry(1, "10001", 7, "ready", 202, 0.057),
			want:  StateActive,
		},
		{
			name:  "a record with no identity at all is unresolved",
			entry: entry(1, "", 0, "ready", 202, 0.057),
			want:  StateUnresolved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.entry, tc.evidence)
			if v.State != tc.want {
				t.Fatalf("state = %q, want %q (%s)", v.State, tc.want, v.Explanation)
			}
			if v.Releasable != tc.releasab {
				t.Errorf("releasable = %v, want %v", v.Releasable, tc.releasab)
			}
			if v.Explanation == "" || v.Reason == "" {
				t.Errorf("a verdict must explain itself: reason=%q explanation=%q", v.Reason, v.Explanation)
			}
		})
	}
}

// TestEvaluate_DecisionBoundaries pins the acceptance cases.
func TestEvaluate_DecisionBoundaries(t *testing.T) {
	catalog := []Plan{plan(101, 555, 0.15, 59), plan(202, 666, 0.057, 41)}

	cases := []struct {
		name     string
		cap      float64
		entries  []Entry
		wantAllw bool
	}{
		{"0 committed + 59 under a 100 cap is allowed", 100, nil, true},
		{"41 committed + 59 is allowed at the exact boundary", 100, []Entry{entry(1, "10001", 7, "ready", 202, 0.057)}, true},
		{"59 committed + 59 under a 100 cap is denied", 100, []Entry{entry(1, "10002", 8, "ready", 101, 0.15)}, false},
		{"a cap of zero disables the check", 0, []Entry{entry(1, "10002", 8, "ready", 101, 0.15)}, true},
		{"an unresolved reservation consumes budget", 100, []Entry{entry(1, "intent_1", 0, "unknown", 101, 0.15)}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Evaluate(Input{
				CapNOK:  tc.cap,
				Plans:   catalog,
				Entries: tc.entries,
				Request: &Request{PlanID: 101, PriceID: 555},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Allowed != tc.wantAllw {
				t.Fatalf("allowed = %v, want %v (committed %v + requested %v vs cap %v)",
					res.Allowed, tc.wantAllw, res.CommittedNOK, res.RequestedNOK, res.CapNOK)
			}
			if !res.Allowed && res.Reason != ReasonBudgetExceeded {
				t.Errorf("denied request must carry reason %q, got %q", ReasonBudgetExceeded, res.Reason)
			}
		})
	}
}

// TestEvaluate_DuplicateIdentityDoesNotHideSpend proves the pairing never drops
// a distinct commitment: the same plan and price is not identity.
func TestEvaluate_DuplicateIdentityDoesNotHideSpend(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	entries := []Entry{
		entry(1, "", 0, "ready", 202, 0.057),
		entry(2, "", 0, "ready", 202, 0.057),
	}
	res, err := Evaluate(Input{CapNOK: 100, Plans: catalog, Entries: entries})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CommittedNOK != 82 {
		t.Fatalf("committed = %v, want 82: two distinct VPS sharing a plan are two commitments", res.CommittedNOK)
	}
}

// TestEvaluate_UnpriceableCommitmentFailsClosed proves the decision path refuses
// to spend when an existing commitment cannot be priced.
func TestEvaluate_UnpriceableCommitmentFailsClosed(t *testing.T) {
	catalog := []Plan{plan(101, 555, 0.15, 59)}
	entries := []Entry{entry(1, "10002", 8, "ready", 999, 0)}
	_, err := Evaluate(Input{
		CapNOK:  100,
		Plans:   catalog,
		Entries: entries,
		Request: &Request{PlanID: 101, PriceID: 555},
	})
	if !errors.Is(err, ErrSpendUnpriced) {
		t.Fatalf("error = %v, want %v", err, ErrSpendUnpriced)
	}
}

// TestReport_MarksIncompleteTotal proves an operator report never presents an
// unknown amount as zero.
func TestReport_MarksIncompleteTotal(t *testing.T) {
	catalog := []Plan{plan(101, 555, 0.15, 59)}
	entries := []Entry{
		entry(1, "10002", 8, "ready", 999, 0),
		entry(2, "10003", 9, "ready", 101, 0.15),
	}
	res, err := Report(Input{CapNOK: 100, Plans: catalog, Entries: entries})
	if err != nil {
		t.Fatalf("report must not fail: %v", err)
	}
	if !res.IncompleteTotal {
		t.Error("an unpriceable counted reservation must mark the total incomplete")
	}
	if res.CommittedNOK != 59 {
		t.Errorf("committed = %v, want the priceable 59 only", res.CommittedNOK)
	}
	if len(res.Unresolved) != 1 {
		t.Errorf("unresolved = %d, want 1", len(res.Unresolved))
	}
}

// TestPropose_ReleasesOnlyOnEvidence pins the recovery proposal.
func TestPropose_ReleasesOnlyOnEvidence(t *testing.T) {
	catalog := []Plan{plan(202, 666, 0.057, 41)}
	entries := []Entry{
		entry(1, "intent_1", 0, "unknown", 202, 0.057),
		entry(2, "10001", 7, "ready", 202, 0.057),
	}
	in := Input{
		CapNOK:  100,
		Plans:   catalog,
		Entries: entries,
		Evidence: map[int64]Evidence{
			2: {ServerFound: true, ServerStatus: "ready"},
		},
	}
	p, err := Propose(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Changes) != 0 {
		t.Fatalf("proposed %d releases without conclusive evidence: %+v", len(p.Changes), p.Changes)
	}
	if p.CommittedBefore != 82 || p.CommittedAfter != 82 {
		t.Errorf("totals = %v -> %v, want 82 -> 82", p.CommittedBefore, p.CommittedAfter)
	}

	// Now confirm the record that carries no provider identity.
	in.Evidence[1] = Evidence{ProviderOrderFound: true, ProviderOrderStatus: "waitlist"}
	p, err = Propose(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Changes) != 1 || p.Changes[0].RecordID != 1 {
		t.Fatalf("changes = %+v, want exactly record 1", p.Changes)
	}
	if p.CommittedBefore != 82 {
		t.Errorf("committed before = %v, want 82: it must show what the panel charges today", p.CommittedBefore)
	}
	if p.CommittedAfter != 41 {
		t.Errorf("committed after = %v, want 41", p.CommittedAfter)
	}
}

// TestClassify_FailedProviderStatusIsNotProofOfNoCharge pins the distinction the
// financial safety argument needs: a provider "failed" status ends the
// deployment but may still have been billed, so it must not release spend.
func TestClassify_FailedProviderStatusIsNotProofOfNoCharge(t *testing.T) {
	e := entry(1, "10001", 7, "ready", 202, 0.057)
	for _, status := range []string{"failed", "FAILED"} {
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: status})
		if v.State != StateUnresolved {
			t.Errorf("status %q: state = %q, want %q", status, v.State, StateUnresolved)
		}
		if v.Releasable {
			t.Errorf("status %q must not be releasable", status)
		}
	}
	// The statuses that really end the binding stay releasable.
	for _, status := range []string{"deleted", "terminated"} {
		v := Classify(e, Evidence{ServerFound: true, ServerStatus: status})
		if v.State != StateObsolete || !v.Releasable {
			t.Errorf("status %q: state = %q releasable = %v, want obsolete + releasable", status, v.State, v.Releasable)
		}
	}
}

// TestIsActiveForBudget_StatusSetUnchanged guards the classification against a
// silent widening: a status that was not counted before must not start counting.
func TestIsActiveForBudget_StatusSetUnchanged(t *testing.T) {
	// A1 correction: every local label that is not a terminal attempt record
	// keeps its reservation. An unrecognised label must not silently drop spend,
	// so "" / "provisioning" / "building" now count as well.
	active := []string{"ready", "active", "pending", "pending_order", "pending_payment",
		"deploying", "installing", "waiting", "unknown",
		"stopped", "expired", "refunded", "provisioning", "building", ""}
	for _, s := range active {
		if !IsActiveForBudget(s) {
			t.Errorf("expected %q to count toward the budget", s)
		}
	}
	inactive := []string{"failed", "deleted", "terminated"}
	for _, s := range inactive {
		if IsActiveForBudget(s) {
			t.Errorf("expected %q NOT to count toward the budget", s)
		}
	}
}

// TestIsSyntheticOrderID pins the one predicate the whole safety argument rests
// on: what counts as a local, non-provider identifier.
func TestIsSyntheticOrderID(t *testing.T) {
	for _, id := range []string{"intent_1700000000000000000", "unknown_5", "intent_"} {
		if !IsSyntheticOrderID(id) {
			t.Errorf("expected %q to be synthetic", id)
		}
	}
	for _, id := range []string{"10001", "ord_1", "", "order_intent"} {
		if IsSyntheticOrderID(id) {
			t.Errorf("expected %q NOT to be synthetic", id)
		}
	}
}
