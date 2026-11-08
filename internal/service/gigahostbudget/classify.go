package gigahostbudget

// Accounting classification of one ledger row, derived from the provider
// contract rather than from convenient-looking labels.
//
//nolint:misspell // this file quotes the provider's own status spelling ("cancelled")
//
// The distinction this file exists to protect is between
//
//	(a) "the deployment is not running right now" (a resource or deployment
//	    state), and
//	(b) "the provider states no further charge accrues for this order"
//	    (authoritative non-billability).
//
// Only (b) may release a reservation. Conflating the two is how a still-billed
// server gets removed from the committed total, which then lets a second VPS be
// bought against budget the first one is still consuming.
//
// Provider contract reference: https://gigahost.no/en/api-dokumentasjon
// The relevant contract facts are:
//
//	E1  GET /deploy/status omits canceled orders and orders whose server was
//	    deleted, and silently ignores orders that are not yours. Its omission is
//	    therefore not proof of anything, even for a real provider order id.
//	E2  `cancelled` on a server is a PENDING cancellation: the server keeps
//	    running until termination_date and hourly billing continues.
//	E3  A terminated/deleted server is not a running pay-as-you-go service, so
//	    its recurring commitment ends (hours already used are billed on the next
//	    invoice, which is a past cost, not a reservation). stopped, expired and
//	    refunded have no documented billing meaning at all.
//	E4  A waitlist reservation is explicitly "not billed while a reservation
//	    waits".
//	E5  A routed IP can be moved between servers, so an address is not identity.

import (
	"strings"
)

// Evidence is what the caller actually observed at the provider for one local
// ledger row. The caller performs every provider call; this package only
// interprets the observation, so a wrong inference cannot be introduced by
// adding I/O here.
//
// The zero value means "nothing observed", which is never conclusive.
type Evidence struct {
	// ServerFound reports that the provider inventory contains a server whose
	// identity matches the ledger row.
	ServerFound bool
	// ServerStatus is that server's status as the provider reports it.
	ServerStatus string

	// ProviderOrderFound reports that GET /deploy/status returned this order.
	ProviderOrderFound bool
	// ProviderOrderStatus is the deployment status the provider reports.
	ProviderOrderStatus string
	// OrderOmittedFromDeployStatus reports that the order id WAS queried and the
	// provider's list did not contain it. This is kept as a distinct
	// observation precisely because it proves nothing: the contract states the
	// endpoint omits canceled orders and orders whose server was deleted, and
	// silently ignores orders that are not yours (E1).
	OrderOmittedFromDeployStatus bool

	// OrderQueryFailed is a communication failure or an unknown outcome. It is
	// explicitly NOT evidence of absence.
	OrderQueryFailed bool
}

// Verdict is the accounting classification of one ledger row.
type Verdict struct {
	State State
	// Reason is a stable machine token for the UI and the recovery report.
	Reason string
	// Explanation is an operator-readable sentence.
	Explanation string
	// Releasable reports that the evidence conclusively shows no further charge
	// accrues for this row, so the release marker may be written.
	Releasable bool
}

// locallyTerminalStatuses are local ledger labels that end a reservation attempt
// by themselves. The documentation gives them an unambiguous meaning here: the
// order attempt failed, or the resource is gone.
//
// This set is deliberately NOT the place to add convenience labels. A local label
// can never be more than an attempt record, and a recognized live provider server
// contradicts it (see Classify).
var locallyTerminalStatuses = map[string]bool{
	"failed":     true,
	"deleted":    true,
	"terminated": true,
}

// releaseConclusiveServerStatuses are the provider server statuses that end the
// recurring commitment, with the contract basis quoted above.
//
// The cancellation label is deliberately ABSENT: it is a *pending* cancellation and the
// server is still billed (E2). "stopped", "expired" and "refunded" are absent
// because the documentation assigns them no billing meaning (E3).
//
// Residual obligation, stated rather than waived. Releasing on termination is the
// behavior the approved scope requires ("proven obsolete auto release"), but the
// contract also says of an hourly order: "the server is billed per hour at
// rate_hourly, never more than monthly_cap per month" and that a
// terminated hourly server's "final hours are billed on the next monthly invoice".
// So an order terminated mid-month can still bill up to its own
// monthly_cap *within that month*. Counting it as zero for the rest of the month
// therefore under-counts real spend by at most one order's monthly_cap.
//
// That residual is a genuine product-policy choice, not a derivation:
//
//	(a) release on termination (approved scope, current behavior) and accept a
//	    bounded under-count of at most one monthly_cap per order terminated in the
//	    current month, or
//	(b) keep a terminated order counted until its billing month ends, which would
//	    need a billing-period anchor this ledger does not carry and would contradict
//	    the approved "proven obsolete auto release" regression.
//
// (a) is kept because the approved scope chose it explicitly. This comment is the
// record of the limit; it is not permission to present the monthly cap as an exact
// bound on hourly spend.
var releaseConclusiveServerStatuses = map[string]string{
	"deleted":    "provider_deleted",
	"terminated": "provider_terminated",
}

// waitlistStatus is a HELD order, not a finished one. The contract states it is
// unbilled *while it waits* AND that it "deploys automatically once capacity
// frees up" (lines 5748, 5840). Temporary non-billing is therefore not final
// obsolescence: the commitment is still armed and will activate without any new
// budget check, so it must count.
const waitlistStatus = "waitlist"

// providerLiveStatuses are statuses that mean the provider has the order or the
// resource in hand, so the obligation is live.
var providerLiveStatuses = map[string]bool{
	"ready":        true,
	"active":       true,
	"rescue":       true,
	"iso":          true,
	"installing":   true,
	"deploying":    true,
	"waiting":      true,
	"provisioning": true,
	"pending":      true,
}

// recognizedLocalStatuses are the ledger states this application writes
// deliberately. A status outside this set is not a statement about billing, so
// the reservation stays counted and is reported as unresolved.
var recognizedLocalStatuses = map[string]bool{
	"pending":         true,
	"pending_order":   true,
	"pending_payment": true,
	"waiting":         true,
	"deploying":       true,
	"installing":      true,
	"ready":           true,
	"active":          true,
	"unknown":         true,
	"failed":          true,
	"deleted":         true,
	"terminated":      true,
	//nolint:misspell // "cancelled" is the panel's own stored spelling
	"cancelled": true,
	"canceled":  true,
}

// IsSyntheticOrderID reports a local application identifier that is NOT a
// provider identity. The order path writes "intent_<nanoseconds>" before it
// contacts the provider, and legacy rows may carry "unknown_<...>". Neither can
// be resolved by asking the provider, so a not-found answer for such a value
// proves nothing.
func IsSyntheticOrderID(id string) bool {
	return strings.HasPrefix(id, "intent_") || strings.HasPrefix(id, "unknown_")
}

// IsLocallyTerminal reports a local label that ends a reservation attempt on its
// own.
func IsLocallyTerminal(status string) bool {
	return locallyTerminalStatuses[strings.ToLower(strings.TrimSpace(status))]
}

// obligationIsLive reports whether the provider's current observation shows a
// live obligation, and why. It is used to decide whether a stored release marker
// still describes reality.
//
// Only a positive statement about the resource or the order counts as live: a
// failed query, an omission, an absent status and an unknown label are not
// evidence either way, and must not be used to resurrect or to suppress spend.
func obligationIsLive(ev Evidence) (bool, string) {
	if ev.OrderQueryFailed {
		return false, ""
	}
	if ev.ServerFound {
		status := strings.ToLower(strings.TrimSpace(ev.ServerStatus))
		if _, conclusive := releaseConclusiveServerStatuses[status]; conclusive {
			return false, ""
		}
		if providerLiveStatuses[status] || status == waitlistStatus {
			return true, "the provider reports the matching server as " + strOrUnknown(ev.ServerStatus)
		}
		return false, ""
	}
	if ev.ProviderOrderFound && strings.TrimSpace(ev.ProviderOrderStatus) != "" {
		status := strings.ToLower(strings.TrimSpace(ev.ProviderOrderStatus))
		return true, "the provider reports this order as " + status
	}
	return false, ""
}

// IsActiveForBudget reports whether a local ledger label can represent a
// commitment.
//
// Every label that is not locally terminal counts, so an unrecognized or
// unexpected local label keeps its reservation instead of silently vanishing
// from the committed total. Whether the money is real is decided by Classify.
func IsActiveForBudget(status string) bool {
	return !IsLocallyTerminal(status)
}

// IsServerActiveForBudget reports whether a provider inventory record can be a
// commitment. Anything the contract does not say is over counts, except the
// contractually unbilled waitlist.
func IsServerActiveForBudget(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	if _, conclusive := releaseConclusiveServerStatuses[s]; conclusive {
		return false
	}
	return s != waitlistStatus
}

// EntryMatchesServer reports whether a ledger row and a provider inventory row
// describe the same VPS.
//
// Two rules, both required by contract E5 and by the intake counterexample:
//
//  1. Only a provider order id or a provider server id can establish
//     equivalence. A shared plan, price, region, hourly rate or assigned address
//     never can, because distinct VPS routinely share all of them and a routed
//     address moves between servers.
//  2. When both sides carry a non-empty provider order id and those ids differ,
//     the records are NOT the same reservation whatever else matches. Merging two
//     commitments into one hides spend.
func EntryMatchesServer(e Entry, s Server) bool {
	if e.OrderID != "" && s.OrderID != "" && e.OrderID != s.OrderID {
		return false
	}
	if s.OrderID != "" && e.OrderID == s.OrderID {
		return true
	}
	return s.ID > 0 && e.ServerID == s.ID
}

// Classify decides the accounting state of one ledger row from its own fields
// and the provider evidence the caller collected for it.
//
// Provider evidence about a real identity is evaluated before the local label,
// because the provider's current answer outranks a stale attempt record. A local
// label can keep a reservation counted, and can end one the provider is silent
// about; it can never release a reservation the provider shows alive.
func Classify(e Entry, ev Evidence) Verdict {
	// A release marker is a record of a past decision, not a statement about the
	// provider's current state. It must not suppress a live obligation:
	//
	//   "Reservations are held orders that deploy automatically when capacity
	//    frees up"
	//
	// A reservation released while it was merely unbilled can activate later with
	// no new budget check. The provider's current answer therefore outranks the
	// marker, and the obligation is counted again. Only a terminal observation (or
	// no observation at all) lets the marker stand.
	if e.ReleasedAt != "" {
		if live, why := obligationIsLive(ev); live {
			return Verdict{
				State:  StateActive,
				Reason: "released_but_provider_live",
				Explanation: "this reservation was released on evidence that is no longer current: " + why +
					"; the release marker does not erase the live obligation",
			}
		}
		return Verdict{
			State:       StateReleased,
			Reason:      "released",
			Explanation: "already released" + releaseNote(e.ReleaseReason),
		}
	}
	if ev.OrderQueryFailed {
		return Verdict{
			State:       StateUnresolved,
			Reason:      "provider_unreachable",
			Explanation: "the provider could not be asked about this order; the reservation stays reserved",
		}
	}

	// 1. A recognized provider server describes the resource itself.
	if ev.ServerFound {
		status := strings.ToLower(strings.TrimSpace(ev.ServerStatus))
		if reason, conclusive := releaseConclusiveServerStatuses[status]; conclusive {
			return Verdict{
				State:  StateObsolete,
				Reason: reason,
				Explanation: "the provider reports the matching server as " + strOrUnknown(ev.ServerStatus) +
					", so it is no longer a running pay-as-you-go service",
				Releasable: true,
			}
		}
		if providerLiveStatuses[status] {
			return Verdict{
				State:  StateActive,
				Reason: "provider_resource_running",
				Explanation: "the provider reports the matching server as " + strOrUnknown(ev.ServerStatus) +
					", so the commitment is live",
			}
		}
		// Any other recognized server status is a resource state the
		// documentation does not tie to billing (a pending cancellation, a stop,
		// a suspension, an unknown label). It keeps the reservation counted and
		// unresolved rather than releasing spend.
		return Verdict{
			State:  StateUnresolved,
			Reason: "provider_status_not_billability",
			Explanation: "the provider reports the matching server as " + strOrUnknown(ev.ServerStatus) +
				", which is a resource state the provider contract does not tie to billing",
		}
	}

	// 2. A deployment-level answer.
	if ev.ProviderOrderFound {
		status := strings.ToLower(strings.TrimSpace(ev.ProviderOrderStatus))
		if status == waitlistStatus {
			// Debited nothing YET, but still an armed commitment that deploys by
			// itself. Counting it is what keeps a later automatic deployment
			// inside the cap and inside duplicate protection.
			return Verdict{
				State:  StateActive,
				Reason: "provider_waitlist_pending",
				Explanation: "the provider reports this order as a waitlist reservation: nothing is billed while it waits, " +
					"but it deploys automatically once capacity frees up, so the commitment is pending, not over",
			}
		}
		if status != "" {
			return Verdict{
				State:  StateActive,
				Reason: "provider_order_live",
				Explanation: "the provider reports this order as " + strOrUnknown(ev.ProviderOrderStatus) +
					", so the deployment exists and is billed",
			}
		}
		return Verdict{
			State:       StateUnresolved,
			Reason:      "provider_order_status_absent",
			Explanation: "the provider listed this order without a status, which does not establish whether a charge exists",
		}
	}
	// A not-found answer from GET /deploy/status is deliberately handled
	// nowhere: the contract states that endpoint omits canceled orders and
	// orders whose server was deleted, and silently ignores orders that are not
	// yours (E1), so its omission cannot release a reservation.

	// 3. A locally terminal attempt record, with no contradicting provider
	// answer above.
	if IsLocallyTerminal(e.Status) {
		return Verdict{
			State:       StateObsolete,
			Reason:      "terminal_local_status",
			Explanation: "local status " + strOrUnknown(e.Status) + " ends the order attempt",
		}
	}
	// A stored cancellation label is a real state this panel writes, but the provider
	// contract shows a cancellation does not by itself end billing (E2). With no
	// provider answer the financial outcome is therefore unknown, and the
	// reservation stays counted rather than being treated as either active or
	// over.
	//nolint:misspell // "cancelled" is the spelling this panel stores
	if s := strings.ToLower(strings.TrimSpace(e.Status)); s == "cancelled" || s == "canceled" {
		return Verdict{
			State:  StateUnresolved,
			Reason: "local_cancelled_unsupported",
			Explanation: "local status " + strOrUnknown(e.Status) +
				" is recorded, but the provider contract shows a cancellation still bills until termination, so no provider server is available to confirm the outcome",
		}
	}

	// 4. No identity that could be resolved, and no terminal evidence.
	if IsSyntheticOrderID(e.OrderID) {
		return Verdict{
			State:  StateUnresolved,
			Reason: "synthetic_order_id",
			Explanation: "the local order id is an application identifier, not a provider identity: " +
				"whether the provider received the request and charged for it is unknown",
		}
	}
	if e.OrderID == "" && e.ServerID == 0 {
		return Verdict{
			State:       StateUnresolved,
			Reason:      "missing_identity",
			Explanation: "no provider order id and no provider server id; the commitment cannot be identified",
		}
	}
	// 5. A recognized local label with a provider identity behind it. The label
	// must be one this application writes deliberately; anything else is an
	// unknown state and stays unresolved rather than being assumed active.
	status := strings.ToLower(strings.TrimSpace(e.Status))
	if !recognizedLocalStatuses[status] {
		return Verdict{
			State:  StateUnresolved,
			Reason: "unrecognized_local_status",
			Explanation: "local status " + strOrUnknown(e.Status) +
				" is not a state this application writes, so whether the commitment is live is unknown",
		}
	}
	return Verdict{
		State:       StateActive,
		Reason:      "committed",
		Explanation: "active reservation with a known provider identity and a recognized local state",
	}
}

func strOrUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(empty)"
	}
	return s
}

func releaseNote(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	return ": " + reason
}

// serverIdentity describes a provider inventory row without exposing anything
// the row does not already carry.
func serverIdentity(s Server) string {
	if s.OrderID != "" {
		return "provider order " + s.OrderID
	}
	if s.ID > 0 {
		return "provider server " + itoa(s.ID)
	}
	return "provider inventory row"
}

// entryIdentity describes a ledger row by its strongest identifier.
func entryIdentity(e Entry) string {
	if e.OrderID != "" {
		return "order " + e.OrderID
	}
	if e.ServerID > 0 {
		return "provider server " + itoa(e.ServerID)
	}
	return "local record " + itoa(e.RecordID)
}

// serverIdentityKey is the dedupe key for a counted provider record.
func serverIdentityKey(s Server) string {
	switch {
	case s.OrderID != "":
		return "order:" + s.OrderID
	case s.ID > 0:
		return "server:" + itoa(s.ID)
	default:
		return ""
	}
}

// entryIdentityKey is the dedupe key for a ledger row, or "" when the row has no
// identity another row could legitimately share.
//
// An assigned address is NOT an identity key: the provider documents that a
// routed address can move between servers, so two records sharing an address are
// still two possible commitments.
func entryIdentityKey(e Entry) string {
	if e.OrderID != "" && !IsSyntheticOrderID(e.OrderID) {
		return "order:" + e.OrderID
	}
	if e.ServerID > 0 {
		return "server:" + itoa(e.ServerID)
	}
	return ""
}

// itoa formats a small integer without importing strconv at every call site.
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
