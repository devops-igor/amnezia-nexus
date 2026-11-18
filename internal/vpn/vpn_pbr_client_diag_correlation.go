package vpn

import (
	"sort"
	"time"

	gatewaydns "github.com/devops-igor/amnezia-nexus/internal/vpn/dns"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// DNS↔flow correlation (issue #861, slice 3b).
//
// A flow's destination address is not a name. The route cache is keyed by
// address and merged PROXY-wins, and several names can legitimately share one
// address (CDNs, hosting ranges), so "this flow went to 93.184.216.34 and one
// retained answer named that address" is all the evidence there is. This file
// therefore reports a match CLASS and the candidates, never a single invented
// domain.
//
// The temporal rule is what makes the match meaningful: an answer that arrived
// after the flow was decided cannot have caused that decision. The comparison uses
// the flow's own decision instant and each record's own observation and expiry
// instants, so neither a later DNS answer nor the current policy can overwrite the
// history of what happened.

const (
	// FlowCorrelationUnique means exactly one name could explain the destination.
	FlowCorrelationUnique = "unique"
	// FlowCorrelationAmbiguous means more than one retained answer named the
	// destination; all of them are reported and none is chosen.
	FlowCorrelationAmbiguous = "ambiguous"
	// FlowCorrelationNone means no retained answer named the destination.
	FlowCorrelationNone = "none"
	// FlowCorrelationNotRecorded means the flow's decision instant or the
	// collector is unknown, so no temporal claim can be made at all.
	FlowCorrelationNotRecorded = "not_recorded"

	// Correlation reasons, used only when no candidate explains the destination.
	CorrelationReasonAnswerAfterDecision   = "answer_after_decision"
	CorrelationReasonExpiredBeforeDecision = "expired_before_decision"
	CorrelationReasonNoRetainedAnswer      = "no_retained_answer"
	CorrelationReasonDecisionTimeUnknown   = "decision_time_not_recorded"
	CorrelationReasonNoCollector           = "dns_records_not_recorded"
)

// DNSNameCandidate is one retained answer that named the flow's destination at the
// time the flow was decided.
type DNSNameCandidate struct {
	Name       string
	Seq        uint64
	ObservedAt time.Time
	ExpiresAt  time.Time
	// AnswerObservedAt is the record's own observation instant; it is the same
	// instant as ObservedAt and is named here so the wire shape can state what it
	// compares against the decision.
}

// FlowCorrelation is the correlation verdict for one flow.
type FlowCorrelation struct {
	Match  string
	Reason string
	Names  []DNSNameCandidate
	// Considered counts the retained records that named the destination at all,
	// including ones that cannot explain this decision. It makes the "none"
	// verdict auditable instead of an empty list with no context.
	Considered int
}

// correlateFlowDestination reports which retained answers could have produced this
// flow's destination at the instant the flow was decided.
//
// A candidate must have been observed at or before the decision and must still have
// been usable (not expired) at that instant: an answer that arrived later cannot
// explain an earlier choice, and one whose evidence had already expired was not
// usable by the packet path. Both cases are reported as the reason for a "none"
// verdict instead of being hidden.
func correlateFlowDestination(flow forwarder.SessionFlow, records []dnsledger.Record, collectorRead bool) FlowCorrelation {
	if !collectorRead {
		return FlowCorrelation{Match: FlowCorrelationNotRecorded, Reason: CorrelationReasonNoCollector}
	}
	if flow.DecidedAt.IsZero() {
		// Without the decision instant there is no temporal rule to apply, so no
		// record can be called the cause.
		return FlowCorrelation{Match: FlowCorrelationNotRecorded, Reason: CorrelationReasonDecisionTimeUnknown}
	}

	byName, considered, sawAfterDecision, sawExpired := collectNameCandidates(records, flow.DstIP.String(), flow.DecidedAt)

	names := make([]DNSNameCandidate, 0, len(byName))
	for _, candidate := range byName {
		names = append(names, candidate)
	}
	// Newest observation first, then name, so the list is stable across reads.
	sort.Slice(names, func(i, j int) bool {
		if !names[i].ObservedAt.Equal(names[j].ObservedAt) {
			return names[i].ObservedAt.After(names[j].ObservedAt)
		}
		return names[i].Name < names[j].Name
	})

	switch len(names) {
	case 0:
		reason := CorrelationReasonNoRetainedAnswer
		switch {
		case sawAfterDecision:
			reason = CorrelationReasonAnswerAfterDecision
		case sawExpired:
			reason = CorrelationReasonExpiredBeforeDecision
		}
		return FlowCorrelation{Match: FlowCorrelationNone, Reason: reason, Considered: considered}
	case 1:
		return FlowCorrelation{Match: FlowCorrelationUnique, Names: names, Considered: considered}
	default:
		return FlowCorrelation{Match: FlowCorrelationAmbiguous, Names: names, Considered: considered}
	}
}

// flowNameAttemptLookback bounds how far before a flow decision an unresolved
// query can be shown as an attempted name. It is a diagnostic hint, not proof
// that the query caused the flow: a failed query has no answer to map to the IP.
const flowNameAttemptLookback = 5 * time.Minute

// maxFlowNameAttempts bounds the attempted names shown for one flow.
const maxFlowNameAttempts = 3

// flowNameAttempts returns the terminal queries that produced no usable answer
// shortly before the flow was decided. They are reported as "tried" names, never
// as the flow's name.
func flowNameAttempts(flow forwarder.SessionFlow, events []dnsledger.Event) []dnsledger.Event {
	if flow.DecidedAt.IsZero() || len(events) == 0 {
		return nil
	}
	earliest := flow.DecidedAt.Add(-flowNameAttemptLookback)
	out := make([]dnsledger.Event, 0, maxFlowNameAttempts)
	for _, event := range events {
		if usableNameAttempt(flow, event, earliest) {
			out = append(out, event)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		left := nameAttemptTime(flow, out[i])
		right := nameAttemptTime(flow, out[j])
		if !left.Equal(right) {
			return left.After(right)
		}
		return out[i].Seq > out[j].Seq
	})
	if len(out) > maxFlowNameAttempts {
		out = out[:maxFlowNameAttempts]
	}
	return out
}

// nameAttemptTime is the instant at which the event's latest occurrence can be
// attributed to the flow. The ledger collapses identical queries: ReceivedAt is
// the first occurrence and LastSeen the latest, so a query first tried before the
// lookback but retried inside it must still count. A repeat after the decision
// cannot prove an earlier attempt, so that case falls back to the first
// occurrence the ledger definitely recorded.
func nameAttemptTime(flow forwarder.SessionFlow, event dnsledger.Event) time.Time {
	latest := event.LastSeen
	if latest.IsZero() {
		latest = event.ReceivedAt
	}
	if latest.After(flow.DecidedAt) {
		return event.ReceivedAt
	}
	return latest
}

// usableNameAttempt applies the temporal, incarnation and outcome rules to one
// terminal query before it can be shown as an attempted name.
func usableNameAttempt(flow forwarder.SessionFlow, event dnsledger.Event, earliest time.Time) bool {
	attempted := nameAttemptTime(flow, event)
	if attempted.IsZero() || attempted.After(flow.DecidedAt) || attempted.Before(earliest) {
		return false
	}
	if event.RouteGenerationKnown && flow.Generation != 0 && event.RouteGeneration != flow.Generation {
		return false
	}
	return unresolvedQueryKind(event.Kind)
}

// unresolvedQueryKind reports whether a terminal query kind means the client did
// not get a usable answer. Answered and truncated queries are not attempts.
func unresolvedQueryKind(kind string) bool {
	switch kind {
	case gatewaydns.QueryEventNXDomain,
		gatewaydns.QueryEventNoAnswer,
		gatewaydns.QueryEventUpstreamError,
		gatewaydns.QueryEventAdmissionRefused,
		gatewaydns.QueryEventInvalidQuery,
		gatewaydns.QueryEventDeliveryFailed:
		return true
	default:
		return false
	}
}

// collectNameCandidates walks the retained answers once and returns the names that
// could explain the destination at the decision instant, plus the two reasons a
// matching answer could not: it arrived later, or its evidence had expired.
func collectNameCandidates(records []dnsledger.Record, address string, decided time.Time) (map[string]DNSNameCandidate, int, bool, bool) {
	byName := make(map[string]DNSNameCandidate)
	considered := 0
	sawAfterDecision := false
	sawExpired := false

	for _, record := range records {
		if !recordNamesAddress(record, address) {
			continue
		}
		considered++
		if record.ObservedAt.After(decided) {
			sawAfterDecision = true
			continue
		}
		if !record.ExpiresAt.After(decided) {
			sawExpired = true
			continue
		}
		candidate, seen := byName[record.Name]
		if !seen || record.ObservedAt.After(candidate.ObservedAt) {
			byName[record.Name] = DNSNameCandidate{
				Name:       record.Name,
				Seq:        record.Seq,
				ObservedAt: record.ObservedAt,
				ExpiresAt:  record.ExpiresAt,
			}
		}
	}
	return byName, considered, sawAfterDecision, sawExpired
}

// recordNamesAddress reports whether one stored answer carried the address. The
// record stores the addresses whose decisions were written, so this is an exact
// comparison against what the router recorded, not a re-resolution.
func recordNamesAddress(record dnsledger.Record, address string) bool {
	for _, decision := range record.Addresses {
		if decision.Address.String() == address {
			return true
		}
	}
	return false
}
