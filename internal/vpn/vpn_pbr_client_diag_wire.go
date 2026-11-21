package vpn

import (
	"strconv"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

// This file turns the read-only copies into the wire shape. It is pure: no
// store is touched, so every helper can be read as "given these copies and this
// instant, what does the operator see?".
//
// Only the two surviving sections are rendered here: the live flows the packet
// path recorded, and the drop ledger. The DNS section this file used to build is
// gone with its producer and its stores, so no helper below can emit a record,
// a query event or a correlated name.

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
		ClientDiagnosisLimitReturnTupleAssociation,
		ClientDiagnosisLimitIPv6,
	}
}

// clientDiagnosisLimitations lists what this build's own stores still cannot state.
//
// It is deliberately short. A fact the panel now records — a flow's decision time and
// reason, its forwarding and backend-write outcomes, a per-client drop — is not a
// limitation, and a token claiming otherwise would contradict the row beside it.
func clientDiagnosisLimitations() []string {
	return []string{
		ClientDiagnosisLimitFlowEvidenceInstall,
		ClientDiagnosisLimitSingleSnapshot,
		ClientDiagnosisLimitFlowCountersSampled,
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
			ClientDiagnosisLimitFlowEvidenceInstall,
		},
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

// clientDiagnosisReads is everything the read path copied for one answer.
type clientDiagnosisReads struct {
	flows          forwarder.SessionFlowList
	flowsAvailable bool
}

// clientDiagnosisApplyRecords fills the record sections from the copies the read
// path took. A store that was not consulted keeps its not_recorded default:
// claiming one this answer never read would be a false statement.
func clientDiagnosisApplyRecords(out *ClientDiagnosisResponse, reads clientDiagnosisReads, now time.Time) {
	if !reads.flowsAvailable {
		return
	}
	out.Flows = clientDiagnosisFlowsFromSnapshot(reads.flows, now)
	if !out.Flows.ScanComplete {
		// The flow listing visits a bounded window of the table, so the record
		// count is a lower bound. Saying so keeps "total" from being read as an
		// absolute count.
		out.Limitations = append(out.Limitations, ClientDiagnosisLimitFlowScanPartial)
	}
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
// the policy generation are stated as unknown rather than derived from lastSeen
// or from the current policy.
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
	}
	if !flow.LastSeen.IsZero() {
		out.LastSeenAgeSeconds = int64(max(now.Sub(flow.LastSeen), 0) / time.Second)
	}

	// The decision the branch recorded. A zero instant or an empty reason is
	// stated as not recorded rather than filled in from the current policy.
	out.DecisionTime = ClientDiagnosisTokenNotRecorded
	if !flow.DecidedAt.IsZero() {
		out.DecisionTime = clientDiagnosisTime(flow.DecidedAt)
	}
	out.DecisionReason = ClientDiagnosisTokenNotRecorded
	if flow.DecisionReason != "" {
		out.DecisionReason = string(flow.DecisionReason)
	}
	out.PolicyGeneration = ClientDiagnosisTokenNotRecorded
	if flow.PolicyGeneration != "" {
		out.PolicyGeneration = flow.PolicyGeneration
	}
	if flow.Choice == forwarder.EgressChoiceProxy && flow.BackendTunnelID != 0 {
		backend := flow.BackendTunnelID
		out.BackendTunnelID = &backend
	}

	out.Dispatch = clientDiagnosisFlowDispatch(flow)
	out.Forward = ClientDiagnosisFlowForward{
		Packets:             flow.ForwardPackets,
		Bytes:               flow.ForwardBytes,
		Failed:              flow.ForwardFailed,
		Failure:             flow.ForwardFailure,
		BackendWrites:       flow.BackendWrites,
		BackendWriteFailed:  flow.BackendWriteFailed,
		BackendWriteFailure: flow.BackendWriteFailure,
	}
	out.Return = clientDiagnosisFlowReturn(flow)
	return out
}

// clientDiagnosisFlowDispatch states what the dispatch path did with the flow's
// packets. Queue acceptance and a device write are different outcomes and are
// reported as such; a flow with no dispatch outcome yet says so.
func clientDiagnosisFlowDispatch(flow forwarder.SessionFlow) ClientDiagnosisFlowDispatch {
	switch {
	case flow.ForwardFailed > 0:
		// A refusal is the most recent measured outcome; the counts stay separate
		// so an earlier accepted dispatch is not hidden by it.
		return ClientDiagnosisFlowDispatch{State: "failed", Reason: flow.ForwardFailure}
	case flow.ForwardPackets > 0 && flow.Choice == forwarder.EgressChoiceDirect:
		return ClientDiagnosisFlowDispatch{State: "written_to_wan"}
	case flow.ForwardPackets > 0:
		return ClientDiagnosisFlowDispatch{State: "queued_to_backend"}
	default:
		return ClientDiagnosisFlowDispatch{State: ClientDiagnosisTokenNotRecorded}
	}
}

// clientDiagnosisFlowReturn states the return evidence. A PROXY flow whose reply was
// never matched says not_measured; one that was matched states arrival, queue admission
// and handoff as separate counters, so none of them can be read as the next.
func clientDiagnosisFlowReturn(flow forwarder.SessionFlow) ClientDiagnosisFlowReturn {
	if flow.Choice == forwarder.EgressChoiceProxy {
		if !flow.PROXYReturnMeasured {
			return ClientDiagnosisFlowReturn{Evidence: "not_measured"}
		}
		return ClientDiagnosisFlowReturn{
			Evidence:  "observed",
			Authority: "current_tuple_association",
			Matched:   flow.ReturnMatched,
			Admitted:  flow.ReturnAdmitted,
			Dropped:   flow.ReturnDropped,
			Delivered: flow.ReturnDelivered,
			Failed:    flow.ReturnFailed,
			Failure:   flow.ReturnFailure,
		}
	}
	out := ClientDiagnosisFlowReturn{
		Evidence: "not_observed",
		Packets:  flow.ReturnPackets,
		Bytes:    flow.ReturnBytes,
		FirstAt:  clientDiagnosisTime(flow.ReturnFirst),
		LastAt:   clientDiagnosisTime(flow.ReturnLast),
	}
	if flow.ReturnObserved {
		out.Evidence = "observed"
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
