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
	// ProofNeeded names the exact observation that would resolve a retained
	// reservation. It is empty for a proposed release, which already has its
	// conclusive evidence recorded.
	ProofNeeded string
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
// Releasable. Exactly one kind of observation can establish that: a
// contract-supported provider terminal status (terminated/deleted) for a server
// whose identity matches the ledger row. A waitlist reservation is NOT release
// evidence - it is unbilled only while it waits and deploys automatically, so
// Classify keeps it counted. A synthetic local id is never evidence of absence,
// a deploy-status omission is not evidence of absence, and an unreachable or
// unanswered provider leaves the reservation exactly where it is.
//
// There is deliberately NO operator-acknowledgement path. The approved scope
// forbids an administrator waiver in place of authoritative proof, and a
// free-text note is not proof of anything. A reservation whose outcome is
// genuinely unknowable is reported as unresolved instead of being waived.
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
		p.addReservation(in, r, amountOf)
	}
	sort.SliceStable(p.Changes, func(i, j int) bool { return p.Changes[i].RecordID < p.Changes[j].RecordID })
	sort.SliceStable(p.Retained, func(i, j int) bool { return p.Retained[i].RecordID < p.Retained[j].RecordID })
	if p.CommittedAfter < 0 {
		p.CommittedAfter = 0
	}
	return p, nil
}

// addReservation records one evaluated reservation in the proposal.
//
// It is a separate step because it is the whole decision per row: release only
// when the classification (re-derived, not trusted from the report) says the
// evidence is conclusive; keep every counted row and name the proof it needs;
// and say nothing about a row that neither counts nor can be released.
func (p *Proposal) addReservation(in Input, r Reservation, amountOf map[int64]float64) {
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
		change.ProofNeeded = proofFor(in.Entries, r)
		p.Retained = append(p.Retained, change)
	}
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

// reasonLocalCancelledUnsupported is the classifier's stable token for a stored
// cancellation the provider contract does not tie to billing.
//
//nolint:misspell // "cancelled" is the spelling this panel stores and classify.go reports
const reasonLocalCancelledUnsupported = "local_cancelled_unsupported"

// proofText is the fixed next-step sentence for one stable reason token. A table
// rather than a long switch keeps the wording reviewable in one place and keeps
// the dispatcher trivial. The one reason that must quote the row's own
// identifier is handled in ProofNeeded.
var proofText = map[string]string{
	"provider_unreachable":            "a successful provider read for this order id; a failed or timed-out call proves nothing",
	"provider_status_not_billability": "a provider server status that the contract ties to billing (a terminated/deleted server ends the commitment); the current status is a resource state only",
	"provider_order_status_absent":    "a provider deployment status for this order id; an answer without a status does not establish whether a charge exists",
	reasonLocalCancelledUnsupported:   "the matching provider server reported as terminated or deleted after the pending cancellation completes; until then the cancellation still bills",
	"missing_identity":                "a provider order id or provider server id for this record; without one the commitment cannot be asked about",
	"unrecognized_local_status":       "a recognized local status plus a provider identity, or a provider answer for the existing identity",
	"price_unidentifiable":            "the order-time price contract for this record (price id, monthly cap, hourly rate, currency), or a catalog that offers exactly one monthly amount for its plan; more than one amount with no recorded contract is not a price",
	"released_but_provider_live":      "a provider fact ending the obligation again; the existing release marker is stale",
	"terminal_local_status":           "no further proof is needed for the attempt record, but a matching live provider server would put the commitment back in the total",
	"committed":                       countedCommitmentProof,
	"provider_resource_running":       countedCommitmentProof,
	"provider_order_live":             countedCommitmentProof,
	"provider_waitlist_pending":       countedCommitmentProof,
	"released":                        "nothing: the reservation is already released and no live obligation was observed for it",
}

// countedCommitmentProof is the next step for a reservation that is currently
// counted: the only observation that un-counts it is the provider ending it.
const countedCommitmentProof = "a provider server reported as terminated or deleted for the matching identity; a waitlist or running order stays counted"

// ProofNeeded names the exact observation that would resolve one kept ledger
// row, so the operator report says what to look up instead of only that the row
// is unresolved.
//
// It deliberately does not invent extra powers: every answer is either a
// provider fact this application can observe on its own (a matching server's
// status, a deployment answer for a real provider order id) or an order-time
// price contract that only the provider or a single unambiguous catalog amount
// can supply. Nothing here can be satisfied by an operator note.
func ProofNeeded(e Entry, v Verdict) string {
	if v.Reason == "synthetic_order_id" {
		return "a real provider order id or server id for this record: " + strOrUnknown(e.OrderID) +
			" is a local identifier the provider never issued, so no provider answer about it is meaningful"
	}
	if text, ok := proofText[v.Reason]; ok {
		return text
	}
	return "a provider observation this application can record for the row's own order id or server id"
}

func orderIDFor(entries []Entry, recordID int64) string {
	for _, e := range entries {
		if e.RecordID == recordID {
			return e.OrderID
		}
	}
	return ""
}

// proofFor names the observation that would resolve one kept reservation. It is
// source-aware: an inventory-counted commitment is not a ledger row and must not
// be described as one.
func proofFor(entries []Entry, r Reservation) string {
	if r.Source != "ledger" {
		return "the provider's own inventory row for " + r.Identity +
			": it stops counting only when the provider reports that server as terminated or deleted"
	}
	for _, e := range entries {
		if e.RecordID != r.RecordID {
			continue
		}
		return ProofNeeded(e, Verdict{State: r.State, Reason: r.Reason, Explanation: r.Explanation})
	}
	return ""
}

// evidenceSummary describes the observed evidence without adding the provider's
// own words, so an operator can audit what the decision rested on.
func evidenceSummary(ev Evidence) string {
	switch {
	case ev.ProviderOrderFound && ev.ProviderOrderStatus != "":
		return "provider reports this order as " + ev.ProviderOrderStatus
	case ev.ServerFound && ev.ServerStatus != "":
		return "provider reports the matching server as " + ev.ServerStatus
	case ev.OrderQueryFailed:
		return "provider query failed; no conclusion"
	case ev.ServerFound:
		return "provider inventory contains the matching server"
	default:
		return "no provider observation recorded"
	}
}

// ValidateObservation rejects an observation that must never justify a release.
// It exists so a caller mistake cannot become a financial decision: the provider
// contract states GET /deploy/status omits canceled orders, so a not-found
// answer for an order id proves nothing about a charge, whether the id is local
// or real.
func ValidateObservation(orderID string, ev Evidence) error {
	if ev.OrderQueryFailed && ev.ProviderOrderFound {
		return fmt.Errorf("order %s: a failed query cannot also report the order as found", orderID)
	}
	return nil
}
