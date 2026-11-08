package gigahostbudget

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
	// ServerStatus is the status the provider inventory reports for a server
	// whose identity matches the ledger row.
	ServerStatus string
	// ServerFound reports that the provider inventory contains such a server.
	ServerFound bool
	// OrderQueried reports that GET /deploy/status was answered for a REAL
	// provider order id. Only real ids are ever queried.
	OrderQueried bool
	// OrderNotFound is the provider's conclusive answer that the queried order
	// id does not exist.
	OrderNotFound bool
	// OrderEnded is the provider's answer, for a real order id it issued, that
	// no live order exists any more (a terminated/cancelled order has no status
	// to report). It is conclusive because the id is the provider's own.
	OrderEnded bool
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
	// Releasable reports that the evidence conclusively shows no commitment is
	// left for this row, so the release marker may be written.
	Releasable bool
}

// Local statuses that mean the reservation carries no commitment any more.
// The set matches the pre-existing budget classification exactly, so a state
// that was already excluded stays excluded.
var obsoleteLocalStatuses = map[string]bool{
	"failed":     true,
	"cancelled":  true,
	"canceled":   true,
	"deleted":    true,
	"terminated": true,
	"stopped":    true,
	"expired":    true,
	"refunded":   true,
}

// activeLocalStatuses that consume budget when the financial outcome is known.
// The set is exactly the pre-existing budget classification: adding a status
// here would silently start counting spend that was not counted before.
var activeLocalStatuses = map[string]bool{
	"ready":           true,
	"active":          true,
	"pending":         true,
	"pending_order":   true,
	"pending_payment": true,
	"deploying":       true,
	"installing":      true,
	"waiting":         true,
	"unknown":         true,
}

// IsSyntheticOrderID reports a local application identifier that is NOT a
// provider identity. The order path writes "intent_<nanoseconds>" before it
// contacts the provider, and legacy rows may carry "unknown_<...>". Neither can
// be resolved by asking the provider, so a not-found answer for such a value
// proves nothing.
func IsSyntheticOrderID(id string) bool {
	return strings.HasPrefix(id, "intent_") || strings.HasPrefix(id, "unknown_")
}

// IsTerminalStatus reports a status that ends a reservation.
func IsTerminalStatus(status string) bool {
	return obsoleteLocalStatuses[strings.ToLower(strings.TrimSpace(status))]
}

// IsActiveForBudget reports whether a local ledger status consumes budget,
// independently of whether its financial outcome is known.
func IsActiveForBudget(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	if IsTerminalStatus(s) {
		return false
	}
	return activeLocalStatuses[s]
}

// IsServerActiveForBudget reports whether a provider inventory record is an
// active commitment. Kept identical to the pre-existing budget scope so no
// existing decision changes.
func IsServerActiveForBudget(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ready", "active", "deploying", "pending", "waiting", "installing":
		return true
	default:
		return false
	}
}

// EntryMatchesServer reports whether a ledger row and a provider inventory row
// describe the same VPS.
//
// Only identities that actually establish equivalence are used: the provider
// order id, a positive provider server id, or - as the weakest form - an equal
// assigned public IP when that IP is the ledger row's only identifier and the
// row's outcome is already known. A shared plan id, region, hourly rate or
// price is never evidence: distinct VPS routinely share all of them.
func EntryMatchesServer(e Entry, s Server) bool {
	if s.OrderID != "" && e.OrderID == s.OrderID {
		return true
	}
	if s.ID > 0 && e.ServerID == s.ID {
		return true
	}
	if s.IP == "" || e.AssignedIP == "" || s.IP != e.AssignedIP {
		return false
	}
	// IP reuse over time is possible, so an address match is only accepted when
	// nothing stronger is recorded locally and the row is not an unresolved
	// attempt whose outcome must stay visible.
	if e.ServerID > 0 {
		return false
	}
	if e.OrderID != "" && !IsSyntheticOrderID(e.OrderID) {
		return false
	}
	return !isUncertainStatus(e.Status)
}

// isUncertainStatus reports a state whose financial outcome is unknown.
func isUncertainStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "unknown", "pending_order":
		return true
	default:
		return false
	}
}

// Classify decides the accounting state of one ledger row from its own fields
// and the provider evidence the caller collected for it.
func Classify(e Entry, ev Evidence) Verdict {
	if e.ReleasedAt != "" {
		return Verdict{
			State:       StateReleased,
			Reason:      "released",
			Explanation: "already released" + releaseNote(e.ReleaseReason),
		}
	}
	if IsTerminalStatus(e.Status) {
		return Verdict{
			State:       StateObsolete,
			Reason:      "terminal_local_status",
			Explanation: "local status " + strOrUnknown(e.Status) + " ends the reservation",
		}
	}
	if ev.ServerFound && IsTerminalStatus(ev.ServerStatus) {
		return Verdict{
			State:       StateObsolete,
			Reason:      "provider_terminal_status",
			Explanation: "the provider reports the matching server as " + strOrUnknown(ev.ServerStatus),
			Releasable:  true,
		}
	}
	if ev.OrderQueryFailed {
		return Verdict{
			State:       StateUnresolved,
			Reason:      "provider_unreachable",
			Explanation: "the provider could not be asked about this order; the reservation stays reserved",
		}
	}
	if ev.OrderNotFound && ev.OrderQueried && e.OrderID != "" && !IsSyntheticOrderID(e.OrderID) {
		return Verdict{
			State:       StateObsolete,
			Reason:      "provider_order_not_found",
			Explanation: "the provider owns its order ids and reports no such order",
			Releasable:  true,
		}
	}
	if ev.OrderEnded && ev.OrderQueried && e.OrderID != "" && !IsSyntheticOrderID(e.OrderID) && !ev.ServerFound {
		return Verdict{
			State:       StateObsolete,
			Reason:      "provider_order_ended",
			Explanation: "the provider owns this order id and reports no live order for it",
			Releasable:  true,
		}
	}
	if !IsActiveForBudget(e.Status) {
		return Verdict{
			State:       StateObsolete,
			Reason:      "inactive_status",
			Explanation: "status " + strOrUnknown(e.Status) + " is not an active reservation",
		}
	}
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
	return Verdict{
		State:       StateActive,
		Reason:      "committed",
		Explanation: "active reservation with a known provider identity",
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
	if s.IP != "" {
		return "provider server at " + s.IP
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
	if e.AssignedIP != "" {
		return "server at " + e.AssignedIP
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
	case s.IP != "":
		return "ip:" + s.IP
	default:
		return ""
	}
}

// entryIdentityKey is the dedupe key for a ledger row, or "" when the row has
// no identity that another row could legitimately share.
func entryIdentityKey(e Entry) string {
	if e.OrderID != "" && !IsSyntheticOrderID(e.OrderID) {
		return "order:" + e.OrderID
	}
	if e.ServerID > 0 {
		return "server:" + itoa(e.ServerID)
	}
	if e.AssignedIP != "" && !isUncertainStatus(e.Status) {
		return "ip:" + e.AssignedIP
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
