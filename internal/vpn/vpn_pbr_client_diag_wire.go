package vpn

import (
	"strconv"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// This file turns the read-only copies into the wire shape. It is pure: no
// store is touched, so every helper can be read as "given these copies and this
// instant, what does the operator see?".
//
// The age vocabulary is the one the dry run already publishes
// (policy.AgeNotFresh and friends), so an evidence age means the same thing on
// both endpoints instead of being re-invented here.

// clientDiagnosisTokenRecorded marks a section that was actually read.
const clientDiagnosisTokenRecorded = "recorded"

// clientDiagnosisTime renders an instant for the wire, or "" for the zero value
// so a caller can tell "no instant stored" from an instant.
func clientDiagnosisTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// clientDiagnosisNotCovered lists the facts no router-side store retains. They
// are facts about the world, not about this slice: a later slice may move one
// into NotRecorded.
func clientDiagnosisNotCovered() []string {
	return []string{
		ClientDiagnosisLimitApplication,
		ClientDiagnosisLimitProxyReturn,
		ClientDiagnosisLimitIPv6,
		ClientDiagnosisLimitEncryptedDNS,
	}
}

// clientDiagnosisLimitations lists what this slice's own stores cannot state.
func clientDiagnosisLimitations() []string {
	return []string{
		ClientDiagnosisLimitNamesNotRecorded,
		ClientDiagnosisLimitQuestionsNotRecorded,
		ClientDiagnosisLimitDecisionTimeUnknown,
		ClientDiagnosisLimitDecisionReason,
		ClientDiagnosisLimitFlowOutcomes,
		ClientDiagnosisLimitDrops,
		ClientDiagnosisLimitSingleSnapshot,
	}
}

// clientDiagnosisCoverage states what was read and what was not, against the
// sampled instant used by the rest of the answer.
func clientDiagnosisCoverage(fwd *forwarder.Forwarder, now time.Time) ClientDiagnosisCoverage {
	return ClientDiagnosisCoverage{
		PolicyRoutingEnabled: fwd != nil && fwd.PBREnabled(),
		SampledAt:            clientDiagnosisTime(now),
		EvidenceSource:       clientDiagnosisEvidenceSource,
		NotCovered:           clientDiagnosisNotCovered(),
		NotRecorded: []string{
			ClientDiagnosisLimitNamesNotRecorded,
			ClientDiagnosisLimitQuestionsNotRecorded,
			ClientDiagnosisLimitDecisionTimeUnknown,
			ClientDiagnosisLimitDecisionReason,
			ClientDiagnosisLimitFlowOutcomes,
			ClientDiagnosisLimitDrops,
		},
	}
}

// clientDiagnosisEmptyDNS is the section a non-live selection returns: the shape
// is present so a client never has to distinguish "absent key" from "no
// evidence".
func clientDiagnosisEmptyDNS() ClientDiagnosisDNS {
	return ClientDiagnosisDNS{
		Available: false,
		State:     ClientDiagnosisTokenNotRecorded,
		Names:     ClientDiagnosisNamesMatch{Match: ClientDiagnosisNamesNotRecorded, Reason: ClientDiagnosisLimitNamesNotRecorded},
		Entries:   []ClientDiagnosisEntry{},
	}
}

// clientDiagnosisEmptyFlows is the flow section for a non-live selection.
func clientDiagnosisEmptyFlows() ClientDiagnosisFlows {
	return ClientDiagnosisFlows{
		Available: false,
		State:     ClientDiagnosisTokenNotRecorded,
		Entries:   []ClientDiagnosisFlow{},
	}
}

// clientDiagnosisApplyRecords fills the two record sections from the copies the
// read path took. A policy-active forwarder without a direct-egress manager
// leaves the flow section at its not_recorded default: nothing was read, and
// claiming a store this answer never consulted would be a false statement.
func clientDiagnosisApplyRecords(out *ClientDiagnosisResponse, entries policy.SessionEntryList, generation string, flows forwarder.SessionFlowList, flowsAvailable bool, now time.Time) {
	out.DNS = clientDiagnosisDNSFromEntries(entries, generation, now)
	if !flowsAvailable {
		return
	}
	out.Flows = clientDiagnosisFlowsFromSnapshot(flows, now)
	if !out.Flows.ScanComplete {
		// The flow listing visits a bounded window of the table, so the record
		// count is a lower bound. Saying so keeps "total" from being read as an
		// absolute count.
		out.Limitations = append(out.Limitations, ClientDiagnosisLimitFlowScanPartial)
	}
}

// clientDiagnosisDNSFromEntries renders the retained address evidence.
func clientDiagnosisDNSFromEntries(list policy.SessionEntryList, generation string, now time.Time) ClientDiagnosisDNS {
	out := ClientDiagnosisDNS{
		Available:  true,
		State:      string(list.State),
		Generation: list.Generation,
		Names:      ClientDiagnosisNamesMatch{Match: ClientDiagnosisNamesNotRecorded, Reason: ClientDiagnosisLimitNamesNotRecorded},
		Entries:    make([]ClientDiagnosisEntry, 0, len(list.Entries)),
		Total:      list.Total,
		Truncated:  list.Truncated,
	}
	if generation != "" && out.Generation == "" {
		out.Generation = generation
	}
	if list.State == policy.EvidenceQuarantined {
		out.QuarantinedUntil = clientDiagnosisTime(list.QuarantinedUntil)
	}
	for _, entry := range list.Entries {
		out.Entries = append(out.Entries, clientDiagnosisEntry(entry, now))
	}
	return out
}

// clientDiagnosisEntry renders one retained decision.
func clientDiagnosisEntry(entry policy.SessionEntry, now time.Time) ClientDiagnosisEntry {
	out := ClientDiagnosisEntry{
		Address:    entry.Address.String(),
		Decision:   entry.Decision.String(),
		ObservedAt: clientDiagnosisTime(entry.ObservedAt),
		ExpiresAt:  clientDiagnosisTime(entry.ExpiresAt),
		State:      string(entry.State),
		Names:      []string{},
		NamesMatch: ClientDiagnosisNamesNotRecorded,
	}
	if !entry.ExpiresAt.IsZero() {
		out.ExpiresInSeconds = int64(entry.ExpiresAt.Sub(now) / time.Second)
	}
	age, reason := clientDiagnosisEntryAge(entry, now)
	out.AgeSeconds = age
	out.AgeUnavailableReason = reason
	return out
}

// clientDiagnosisEntryAge states the elapsed age of fresh evidence from its
// recorded instant, never from its deadline. A non-fresh entry has no usable
// age: reporting one would describe evidence the packet path ignores.
func clientDiagnosisEntryAge(entry policy.SessionEntry, now time.Time) (*int64, string) {
	if entry.State != policy.EvidenceFresh {
		return nil, string(policy.AgeNotFresh)
	}
	if entry.ObservedAt.IsZero() {
		return nil, string(policy.AgeInstantNotRecorded)
	}
	seconds := int64(max(now.Sub(entry.ObservedAt), 0) / time.Second)
	return &seconds, ""
}

// clientDiagnosisFlowsFromSnapshot renders the live-flow section.
func clientDiagnosisFlowsFromSnapshot(list forwarder.SessionFlowList, now time.Time) ClientDiagnosisFlows {
	out := ClientDiagnosisFlows{
		Available:    true,
		State:        clientDiagnosisTokenRecorded,
		Scanned:      list.Scanned,
		ScanComplete: list.ScanComplete,
		Total:        list.Total,
		Truncated:    list.Truncated,
		Entries:      make([]ClientDiagnosisFlow, 0, len(list.Flows)),
	}
	for _, flow := range list.Flows {
		out.Entries = append(out.Entries, clientDiagnosisFlow(flow, now))
	}
	return out
}

// clientDiagnosisFlow renders one flow record. DecisionTime, DecisionReason and
// the name match are stated as unknown rather than derived from lastSeen or
// from the current policy.
func clientDiagnosisFlow(flow forwarder.SessionFlow, now time.Time) ClientDiagnosisFlow {
	out := ClientDiagnosisFlow{
		Protocol:        clientDiagnosisProtocol(flow.Protocol),
		ClientSrcPort:   flow.SrcPort,
		DestinationIP:   flow.DstIP.String(),
		DestinationPort: flow.DstPort,
		Choice:          flow.Choice.String(),
		RouteGeneration: flow.Generation,
		LastSeen:        clientDiagnosisTime(flow.LastSeen),
		Expired:         flow.Expired,
		CloseSeen:       flow.CloseSeen,
		DecisionTime:    ClientDiagnosisTokenNotRecorded,
		DecisionReason:  ClientDiagnosisTokenNotRecorded,
		Names:           []string{},
		NamesMatch:      ClientDiagnosisNamesNotRecorded,
	}
	if !flow.LastSeen.IsZero() {
		out.LastSeenAgeSeconds = int64(max(now.Sub(flow.LastSeen), 0) / time.Second)
	}
	return out
}

// clientDiagnosisProtocol names the transport a flow record carries. A protocol
// outside TCP/UDP is not recorded by the flow table at all, so the decimal
// fallback is only a defensive rendering and never a supported value.
func clientDiagnosisProtocol(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.Itoa(int(proto))
	}
}
