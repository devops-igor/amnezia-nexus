package gigahostbudget

import (
	"fmt"
	"sort"
)

// ActionRelease marks a reservation the recovery procedure proposes to release.
const ActionRelease = "release"

// ActionNone marks a reservation the procedure keeps.
const ActionNone = "none"

// ProposedChange is one line of the recovery proposal. It is exported so the
// operator tool and any admin surface render the same reasoning the purchase
// path used.
type ProposedChange struct {
	RecordID    int64
	OrderID     string
	Status      string
	Identity    string
	State       State
	Action      string
	Reason      string
	Evidence    string
	Explanation string
	AmountNOK   float64
}

// Proposal is the ordered set of changes a recovery run would make, with the
// totals before and after so an operator can see the financial effect before
// approving them.
type Proposal struct {
	CapNOK float64
	// CommittedBefore is the total the panel currently charges against the cap,
	// computed from the stored ledger alone. It is what the operator must
	// recognize before approving a change.
	CommittedBefore float64
	// CommittedAfter is CommittedBefore minus the amounts this proposal would
	// release.
	CommittedAfter float64
	Changes        []ProposedChange
	// Retained lists counted reservations the procedure deliberately keeps,
	// including every unresolved one and why it cannot be released.
	Retained []ProposedChange
	// IncompleteTotal reports that a counted reservation has no identifiable
	// price, so CommittedBefore is a lower bound rather than a total.
	IncompleteTotal bool
}

// Propose derives the recovery proposal from the same classification the
// purchase path uses, so the two can never disagree.
//
// A change is proposed ONLY for a reservation the classification marks
// Releasable, which requires conclusive evidence: a terminal provider status for
// a matching server, the provider reporting that it does not own a real provider
// order id, or an explicit operator acknowledgement for a record that carries no
// provider identity at all. A synthetic local id is never evidence of absence,
// and an unreachable or unanswered provider leaves the reservation exactly where
// it is.
//
// CommittedBefore is computed WITHOUT the release evidence, because it must show
// what the panel charges today; CommittedAfter subtracts exactly the released
// amounts. Reporting the post-release total as "before" would hide the effect of
// the very change being approved.
func Propose(in Input) (Proposal, error) {
	before := Input{CapNOK: in.CapNOK, Plans: in.Plans, Servers: in.Servers, Entries: in.Entries}
	asRecorded, err := Report(before)
	if err != nil {
		return Proposal{}, err
	}
	withEvidence, err := Report(in)
	if err != nil {
		return Proposal{}, err
	}

	amountOf := make(map[int64]float64, len(asRecorded.Reservations))
	for _, r := range asRecorded.Reservations {
		amountOf[r.RecordID] = r.AmountNOK
	}

	p := Proposal{
		CapNOK:          asRecorded.CapNOK,
		CommittedBefore: asRecorded.CommittedNOK,
		CommittedAfter:  asRecorded.CommittedNOK,
		IncompleteTotal: asRecorded.IncompleteTotal,
	}
	for _, r := range withEvidence.Reservations {
		change := ProposedChange{
			RecordID:    r.RecordID,
			Status:      r.Status,
			Identity:    r.Identity,
			State:       r.State,
			Reason:      r.Reason,
			Explanation: r.Explanation,
			AmountNOK:   amountOf[r.RecordID],
		}
		if r.RecordID > 0 {
			change.OrderID = orderIDFor(in.Entries, r.RecordID)
		}
		switch {
		case r.RecordID > 0 && verdictReleasable(in, r):
			change.Action = ActionRelease
			change.Evidence = evidenceSummary(in.Evidence[r.RecordID])
			p.CommittedAfter -= change.AmountNOK
			p.Changes = append(p.Changes, change)
		case r.State.Counts():
			change.Action = ActionNone
			change.AmountNOK = amountOf[r.RecordID]
			p.Retained = append(p.Retained, change)
		default:
			// Not counted and not releasable: nothing to do.
			continue
		}
	}
	sort.SliceStable(p.Changes, func(i, j int) bool { return p.Changes[i].RecordID < p.Changes[j].RecordID })
	sort.SliceStable(p.Retained, func(i, j int) bool { return p.Retained[i].RecordID < p.Retained[j].RecordID })
	if p.CommittedAfter < 0 {
		p.CommittedAfter = 0
	}
	return p, nil
}

// verdictReleasable re-derives the classification for one ledger row so the
// proposal cannot release something the classification would keep.
func verdictReleasable(in Input, r Reservation) bool {
	if r.Source != "ledger" {
		return false
	}
	for _, e := range in.Entries {
		if e.RecordID != r.RecordID {
			continue
		}
		return Classify(e, in.Evidence[e.RecordID]).Releasable
	}
	return false
}

// ReleaseReasonFor returns the audit reason a verdict justifies, or "" when the
// evidence does not justify a release.
func ReleaseReasonFor(v Verdict) string {
	if !v.Releasable {
		return ""
	}
	return v.Reason
}

func orderIDFor(entries []Entry, recordID int64) string {
	for _, e := range entries {
		if e.RecordID == recordID {
			return e.OrderID
		}
	}
	return ""
}

// evidenceSummary describes the observed evidence without adding the provider's
// own words, so an operator can audit what the decision rested on.
func evidenceSummary(ev Evidence) string {
	switch {
	case ev.OperatorConfirmed:
		if ev.OperatorNote != "" {
			return "operator verification: " + ev.OperatorNote
		}
		return "operator verification: no charge exists for this attempt"
	case ev.ServerFound && ev.ServerStatus != "":
		return "provider reports the matching server as " + ev.ServerStatus
	case ev.OrderNotFound && ev.OrderQueried:
		return "provider reports no such order"
	case ev.OrderEnded && ev.OrderQueried:
		return "provider reports no live order for this id"
	case ev.OrderQueryFailed:
		return "provider query failed; no conclusion"
	case ev.ServerFound:
		return "provider inventory contains the matching server"
	default:
		return "no provider observation recorded"
	}
}

// ValidateObservation rejects an observation that must never justify a release.
// It exists so an operator mistake cannot become a financial decision: a
// not-found answer for a synthetic local id proves nothing, because the provider
// never issued that id.
func ValidateObservation(orderID string, ev Evidence) error {
	if ev.OrderNotFound && IsSyntheticOrderID(orderID) {
		return fmt.Errorf("order %s: a not-found answer for a synthetic local id is not evidence that no charge exists", orderID)
	}
	return nil
}
