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
	CapNOK          float64
	CommittedBefore float64
	CommittedAfter  float64
	Changes         []ProposedChange
	// Retained lists counted reservations the procedure deliberately keeps,
	// including every unresolved one and why it cannot be released.
	Retained []ProposedChange
}

// Propose derives the recovery proposal from the same Evaluate/Classify
// calculation the purchase path uses, so the two can never disagree.
//
// A change is proposed ONLY for a reservation the classification marks
// Releasable, which requires conclusive evidence: a terminal provider status
// for a matching server, or the provider reporting that it does not own a real
// provider order id. A synthetic local id is never evidence of absence, and an
// unreachable or unanswered provider leaves the reservation exactly where it is.
func Propose(in Input) (Proposal, error) {
	evaluated, err := Evaluate(Input{
		CapNOK:   in.CapNOK,
		Plans:    in.Plans,
		Servers:  in.Servers,
		Entries:  in.Entries,
		Evidence: in.Evidence,
	})
	if err != nil {
		return Proposal{}, err
	}

	p := Proposal{
		CapNOK:          evaluated.CapNOK,
		CommittedBefore: evaluated.CommittedNOK,
		CommittedAfter:  evaluated.CommittedNOK,
	}
	for _, r := range evaluated.Reservations {
		change := ProposedChange{
			RecordID:    r.RecordID,
			Status:      r.Status,
			Identity:    r.Identity,
			State:       r.State,
			Reason:      r.Reason,
			Explanation: r.Explanation,
			AmountNOK:   r.AmountNOK,
		}
		if r.RecordID > 0 {
			change.OrderID = orderIDFor(in.Entries, r.RecordID)
		}
		switch {
		case r.RecordID > 0 && verdictReleasable(in, r):
			change.Action = ActionRelease
			change.Evidence = evidenceSummary(in.Evidence[r.RecordID])
			p.CommittedAfter -= r.AmountNOK
			p.Changes = append(p.Changes, change)
		case r.State.Counts():
			change.Action = ActionNone
			p.Retained = append(p.Retained, change)
		default:
			// Already obsolete or duplicate: nothing to do and nothing to keep.
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

// verdictReleasable re-derives the classification for one counted ledger row so
// the proposal cannot release something the classification would keep.
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
	case ev.ServerFound && ev.ServerStatus != "":
		return "provider reports the matching server as " + ev.ServerStatus
	case ev.OrderNotFound && ev.OrderQueried:
		return "provider reports no such order"
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
