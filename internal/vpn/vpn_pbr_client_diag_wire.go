package vpn

import (
	"strconv"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/devops-igor/amnezia-nexus/internal/policy"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/dnsledger"
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
		ClientDiagnosisLimitReturnTupleAssociation,
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
		ClientDiagnosisLimitFlowCountersSampled,
		ClientDiagnosisLimitFlowBackendWrite,
		ClientDiagnosisLimitFlowNonTCP,
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
			ClientDiagnosisLimitFlowOutcomes,
			ClientDiagnosisLimitDrops,
			ClientDiagnosisLimitFlowBackendWrite,
			ClientDiagnosisLimitFlowNonTCP,
		},
	}
}

// clientDiagnosisEmptyDNS is the section a non-live selection returns: the shape
// is present so a client never has to distinguish "absent key" from "no
// evidence".
func clientDiagnosisEmptyDNS() ClientDiagnosisDNS {
	return ClientDiagnosisDNS{
		Available:        false,
		State:            ClientDiagnosisTokenNotRecorded,
		Names:            ClientDiagnosisNamesMatch{Match: ClientDiagnosisNamesNotRecorded, Reason: ClientDiagnosisLimitNamesNotRecorded},
		Entries:          []ClientDiagnosisEntry{},
		Records:          []ClientDiagnosisDNSRecord{},
		RecordsAvailable: false,
		RecordCoverage:   clientDiagnosisEmptyRecordCoverage(false),
		EventsAvailable:  false,
		Events:           []ClientDiagnosisDNSQueryEvent{},
		EventCoverage: ClientDiagnosisDNSQueryEventCoverage{
			StartedAt:   "",
			Limits:      ClientDiagnosisEventLimits{EventsPerSession: dnsledger.MaxEventsPerSession, EventsTotal: dnsledger.MaxEventsTotal, MaxAgeSeconds: int64(dnsledger.MaxRecordAge / time.Second)},
			NotRecorded: clientDiagnosisDNSRecordGaps(),
		},
	}
}

// clientDiagnosisEmptyRecordCoverage is the coverage block of a section that was
// not read. Every list stays present so the panel never has to guess a shape.
func clientDiagnosisEmptyRecordCoverage(available bool) ClientDiagnosisDNSRecordCoverage {
	coverage := ClientDiagnosisDNSRecordCoverage{
		Limits: clientDiagnosisRecordLimits(dnsledger.Limits{
			RecordsPerSession:  dnsledger.MaxRecordsPerSession,
			RecordsTotal:       dnsledger.MaxRecordsTotal,
			MaxAgeSeconds:      int64(dnsledger.MaxRecordAge / time.Second),
			BytesTotal:         dnsledger.MaxBytesTotal,
			NamesPerRecord:     dnsledger.MaxNamesPerRecord,
			AddressesPerRecord: dnsledger.MaxAddressesPerRecord,
		}),
		NotRecorded: clientDiagnosisDNSRecordGaps(),
	}
	if !available {
		coverage.StartedAt = ""
	}
	return coverage
}

// clientDiagnosisDNSRecordGaps lists what the observation boundary this build
// records at cannot see. They are reported, never implied by silence: an
// administrator must not read "no record" as "no query".
func clientDiagnosisDNSRecordGaps() []string {
	return []string{
		ClientDiagnosisLimitDNSTransport,
		ClientDiagnosisLimitDNSFailures,
		ClientDiagnosisLimitDNSNonAQueries,
		ClientDiagnosisLimitDNSReceiveTime,
	}
}

// clientDiagnosisRecordLimits renders the collector's bounds.
func clientDiagnosisRecordLimits(limits dnsledger.Limits) ClientDiagnosisRecordLimits {
	return ClientDiagnosisRecordLimits{
		RecordsPerSession:  limits.RecordsPerSession,
		RecordsTotal:       limits.RecordsTotal,
		MaxAgeSeconds:      limits.MaxAgeSeconds,
		BytesTotal:         limits.BytesTotal,
		NamesPerRecord:     limits.NamesPerRecord,
		AddressesPerRecord: limits.AddressesPerRecord,
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
	entries        policy.SessionEntryList
	generation     string
	flows          forwarder.SessionFlowList
	flowsAvailable bool
	dnsRecords     dnsledger.SessionSnapshot
	dnsRecordsRead bool
	dnsEvents      dnsledger.EventSnapshot
}

// clientDiagnosisApplyRecords fills the record sections from the copies the read
// path took. A store that was not consulted keeps its not_recorded default:
// claiming one this answer never read would be a false statement.
func clientDiagnosisApplyRecords(out *ClientDiagnosisResponse, reads clientDiagnosisReads, now time.Time) {
	out.DNS = clientDiagnosisDNSFromEntries(reads.entries, reads.generation, now)
	if reads.dnsRecordsRead {
		clientDiagnosisApplyDNSRecords(&out.DNS, reads.dnsRecords, now)
		clientDiagnosisApplyDNSEvents(&out.DNS, reads.dnsEvents, now)
	}
	if !reads.flowsAvailable {
		return
	}
	var flowRecords []dnsledger.Record
	if reads.dnsRecordsRead {
		flowRecords = reads.dnsRecords.Records
	}
	out.Flows = clientDiagnosisFlowsFromSnapshot(reads.flows, flowRecords, reads.dnsRecordsRead, now)
	if !out.Flows.ScanComplete {
		// The flow listing visits a bounded window of the table, so the record
		// count is a lower bound. Saying so keeps "total" from being read as an
		// absolute count.
		out.Limitations = append(out.Limitations, ClientDiagnosisLimitFlowScanPartial)
	}
}

// clientDiagnosisApplyDNSEvents fills the terminal-query history.
func clientDiagnosisApplyDNSEvents(section *ClientDiagnosisDNS, snapshot dnsledger.EventSnapshot, now time.Time) {
	section.EventsAvailable = true
	section.EventsTotal = snapshot.Total
	section.EventsTruncated = snapshot.Truncated
	section.Events = make([]ClientDiagnosisDNSQueryEvent, 0, len(snapshot.Events))
	for _, event := range snapshot.Events {
		section.Events = append(section.Events, clientDiagnosisDNSEvent(event))
	}
	section.EventCoverage = ClientDiagnosisDNSQueryEventCoverage{
		StartedAt:         clientDiagnosisTime(snapshot.Stats.StartedAt),
		EventsStored:      snapshot.Stats.Events,
		EstimatedBytes:    snapshot.Stats.Bytes,
		Written:           snapshot.Stats.Written,
		Collapsed:         snapshot.Stats.Collapsed,
		EvictedPerSession: snapshot.Stats.EvictedSession,
		EvictedGlobal:     snapshot.Stats.EvictedGlobal,
		AgedOut:           snapshot.Stats.AgedOut,
		RejectedNoRoom:    snapshot.Stats.RejectedNoRoom,
		Limits: ClientDiagnosisEventLimits{
			EventsPerSession: snapshot.Limits.EventsPerSession,
			EventsTotal:      snapshot.Limits.EventsTotal,
			MaxAgeSeconds:    snapshot.Limits.MaxAgeSeconds,
		},
		NotRecorded: clientDiagnosisDNSRecordGaps(),
	}
	_ = now
}

// clientDiagnosisDNSEvent renders one stored terminal query.
func clientDiagnosisDNSEvent(event dnsledger.Event) ClientDiagnosisDNSQueryEvent {
	out := ClientDiagnosisDNSQueryEvent{
		Seq:              event.Seq,
		Name:             event.Name,
		QType:            clientDiagnosisQType(event.QType),
		RCode:            clientDiagnosisRCode(event.RCode),
		Kind:             event.Kind,
		Transport:        event.Transport,
		Delivered:        event.Delivered,
		Truncated:        event.Truncated,
		UpstreamError:    event.UpstreamError,
		ReceivedAt:       clientDiagnosisTime(event.ReceivedAt),
		AnsweredAt:       clientDiagnosisTime(event.AnsweredAt),
		IncarnationKnown: event.RouteGenerationKnown,
		PolicyGeneration: event.PolicyGeneration,
		Count:            event.Count,
		FirstSeen:        clientDiagnosisTime(event.FirstSeen),
		LastSeen:         clientDiagnosisTime(event.LastSeen),
	}
	if event.RouteGenerationKnown {
		generation := event.RouteGeneration
		out.RouteGeneration = &generation
	}
	return out
}

// clientDiagnosisApplyDNSRecords fills the observed-answer history.
func clientDiagnosisApplyDNSRecords(section *ClientDiagnosisDNS, snapshot dnsledger.SessionSnapshot, now time.Time) {
	section.RecordsAvailable = true
	section.RecordsTotal = snapshot.Total
	section.RecordsTruncated = snapshot.Truncated
	section.Records = make([]ClientDiagnosisDNSRecord, 0, len(snapshot.Records))
	for _, record := range snapshot.Records {
		section.Records = append(section.Records, clientDiagnosisDNSRecord(record, now))
	}
	section.RecordCoverage = ClientDiagnosisDNSRecordCoverage{
		StartedAt:          clientDiagnosisTime(snapshot.Stats.StartedAt),
		RecordsStored:      snapshot.Stats.Records,
		EstimatedBytes:     snapshot.Stats.Bytes,
		Sessions:           snapshot.Stats.Sessions,
		Written:            snapshot.Stats.Written,
		Collapsed:          snapshot.Stats.Collapsed,
		EvictedPerSession:  snapshot.Stats.EvictedSession,
		EvictedGlobal:      snapshot.Stats.EvictedGlobal,
		AgedOut:            snapshot.Stats.AgedOut,
		RejectedNoRoom:     snapshot.Stats.RejectedNoRoom,
		WithoutIncarnation: snapshot.Stats.WithoutIncarnate,
		Limits:             clientDiagnosisRecordLimits(snapshot.Limits),
		NotRecorded:        clientDiagnosisDNSRecordGaps(),
	}
}

// clientDiagnosisDNSRecord renders one stored observation. The state is computed
// at the sampled instant and the stored record is not touched: an expired record
// stays in the history and is labeled expired.
func clientDiagnosisDNSRecord(record dnsledger.Record, now time.Time) ClientDiagnosisDNSRecord {
	out := ClientDiagnosisDNSRecord{
		Seq:                  record.Seq,
		Name:                 record.Name,
		QType:                clientDiagnosisQType(record.QType),
		RCode:                clientDiagnosisRCode(record.RCode),
		Aliases:              []string{},
		Addresses:            make([]ClientDiagnosisDNSAddress, 0, len(record.Addresses)),
		ResolvedAddresses:    record.ResolvedAddressCount,
		ObservedAt:           clientDiagnosisTime(record.ObservedAt),
		ReceivedAt:           ClientDiagnosisTokenNotRecorded,
		Transport:            ClientDiagnosisTokenNotRecorded,
		ExpiresAt:            clientDiagnosisTime(record.ExpiresAt),
		State:                clientDiagnosisRecordState(record.ExpiresAt, now),
		PolicyGeneration:     record.PolicyGeneration,
		IncarnationKnown:     record.RouteGenerationKnown,
		Classification:       "invalid",
		ClassificationReason: record.ClassificationReason,
		CacheWrite:           record.CacheVerdict,
		Count:                record.Count,
		FirstSeen:            clientDiagnosisTime(record.FirstSeen),
		LastSeen:             clientDiagnosisTime(record.LastSeen),
	}
	if record.ClassificationValid {
		out.Classification = "valid"
		out.ClassificationReason = ""
	}
	if record.RouteGenerationKnown {
		generation := record.RouteGeneration
		out.RouteGeneration = &generation
	}
	if len(record.Aliases) > 0 {
		out.Aliases = append(out.Aliases, record.Aliases...)
	}
	for _, address := range record.Addresses {
		out.Addresses = append(out.Addresses, ClientDiagnosisDNSAddress{
			Address:  address.Address.String(),
			Decision: address.Decision,
		})
	}
	if !record.ExpiresAt.IsZero() {
		out.ExpiresInSeconds = int64(record.ExpiresAt.Sub(now) / time.Second)
	}
	return out
}

// clientDiagnosisRecordState labels a stored record at the sampled instant.
func clientDiagnosisRecordState(expiresAt, now time.Time) string {
	if expiresAt.IsZero() {
		return ClientDiagnosisTokenNotRecorded
	}
	if expiresAt.After(now) {
		return "active"
	}
	return "expired"
}

// clientDiagnosisQType renders a query type. Only A reaches this boundary today,
// and an unknown value is reported numerically rather than guessed.
func clientDiagnosisQType(qtype uint16) string {
	if name, ok := mdns.TypeToString[qtype]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(qtype))
}

// clientDiagnosisRCode renders a response code.
func clientDiagnosisRCode(rcode int) string {
	if name, ok := mdns.RcodeToString[rcode]; ok {
		return name
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// clientDiagnosisDNSFromEntries renders the retained address evidence.
func clientDiagnosisDNSFromEntries(list policy.SessionEntryList, generation string, now time.Time) ClientDiagnosisDNS {
	out := ClientDiagnosisDNS{
		Available:      true,
		State:          string(list.State),
		Generation:     list.Generation,
		Names:          ClientDiagnosisNamesMatch{Match: ClientDiagnosisNamesNotRecorded, Reason: ClientDiagnosisLimitNamesNotRecorded},
		Entries:        make([]ClientDiagnosisEntry, 0, len(list.Entries)),
		Total:          list.Total,
		Truncated:      list.Truncated,
		Records:        []ClientDiagnosisDNSRecord{},
		RecordCoverage: clientDiagnosisEmptyRecordCoverage(false),
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

// clientDiagnosisFlowsFromSnapshot renders the live-flow section, correlating each
// destination with the session's retained DNS answers.
func clientDiagnosisFlowsFromSnapshot(list forwarder.SessionFlowList, records []dnsledger.Record, recordsRead bool, now time.Time) ClientDiagnosisFlows {
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
		out.Entries = append(out.Entries, clientDiagnosisFlow(flow, records, recordsRead, now))
	}
	return out
}

// clientDiagnosisFlow renders one flow record. DecisionTime, DecisionReason and
// the name match are stated as unknown rather than derived from lastSeen or
// from the current policy.
func clientDiagnosisFlow(flow forwarder.SessionFlow, records []dnsledger.Record, recordsRead bool, now time.Time) ClientDiagnosisFlow {
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
		Names:           []string{},
		NameCandidates:  []ClientDiagnosisFlowNameCandidate{},
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

	correlation := correlateFlowDestination(flow, records, recordsRead)
	out.NamesMatch = correlation.Match
	out.NamesReason = correlation.Reason
	out.NamesConsidered = correlation.Considered
	for _, candidate := range correlation.Names {
		out.Names = append(out.Names, candidate.Name)
		out.NameCandidates = append(out.NameCandidates, ClientDiagnosisFlowNameCandidate{
			Name:       candidate.Name,
			Seq:        candidate.Seq,
			ObservedAt: clientDiagnosisTime(candidate.ObservedAt),
			ExpiresAt:  clientDiagnosisTime(candidate.ExpiresAt),
		})
	}
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
