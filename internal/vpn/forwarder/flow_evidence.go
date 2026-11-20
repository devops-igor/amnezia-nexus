package forwarder

import (
	"errors"
	"sync/atomic"
	"time"
	"unsafe"
)

// This file is the per-flow evidence of issue #861, slice 3a: what the packet
// path actually decided and what it actually did with the packets afterwards.
//
// Design constraints that shaped it:
//
//   - The decision timestamp, the policy generation and the reason are written
//     ONCE, at the branch that decides, by the function that decides. They are
//     never reconstructed from lastSeen (which every packet refreshes) or from
//     the current policy (which may have moved since).
//   - The counters are atomics reached through a pointer already obtained under
//     DirectEgressManager.mu. The forward and return paths therefore gain no lock
//     and no map lookup: they hand the pointer to a value that outlives the
//     critical section. Per-flow state is a value of the existing flow entry, so
//     the existing table bound is also the metadata bound.
//   - A flow entry is created once per (session, route generation, 5-tuple).
//     Retiring it and re-admitting the same tuple creates a new entry with a new
//     evidence block, so a reused tuple is a new incarnation by construction.
//
// What is deliberately NOT captured here: per-flow DROP records (the prohibited
// destination branch runs before any flow exists and only bumps a global
// counter), the PROXY return direction (it needs a per-reply tuple lookup on the
// high-volume direction and is gated separately), and per-flow payload outcomes.

// EgressReason names the branch that selected a flow's route. The values are
// tokens: the API translates them and a test can name the exact branch.
type EgressReason string

const (
	// EgressReasonStickyFlow means an existing flow kept the choice it already
	// had; no new decision was taken for that packet.
	EgressReasonStickyFlow EgressReason = "sticky_flow"
	// EgressReasonEvidenceDirect means fresh client-scoped DNS evidence made the
	// destination DIRECT. The decision path no longer produces it: the address
	// alone decides. It stays defined because a flow recorded before that
	// change still carries the token.
	EgressReasonEvidenceDirect EgressReason = "evidence_direct"
	// EgressReasonProxyCIDRRule means the published policy snapshot's address
	// rule put the destination on the proxy.
	EgressReasonProxyCIDRRule EgressReason = "proxy_cidr_rule"
	// EgressReasonProxyCachedEvidence means the session's own retained PROXY
	// decision put the destination on the proxy. Like the evidence_direct token
	// it is historical only: the decision path no longer produces it.
	EgressReasonProxyCachedEvidence EgressReason = "proxy_cached_evidence"
	// EgressReasonNoTrustedEvidence means the destination was uncovered by the
	// classifier, so the fail-closed default applied.
	EgressReasonNoTrustedEvidence EgressReason = "no_trusted_evidence"
	// EgressReasonNonTCPOrUDP means the protocol cannot be NATed directly.
	EgressReasonNonTCPOrUDP EgressReason = "non_tcp_udp_fallback"
	// EgressReasonAllocationDirect means the destination is inside the Russian
	// allocation and no CDN exclusion applied, so the address alone routed it
	// DIRECT with no DNS evidence (issue #918). The token names allocation
	// membership, never hosting location: the classifier cannot prove where a
	// service runs, only how its address is allocated.
	EgressReasonAllocationDirect EgressReason = "allocation_direct"
	// EgressReasonAllocationCDNExcluded means the destination is inside the
	// Russian allocation but its range belongs to a known multi-region CDN, so
	// it stayed proxied (issue #918).
	EgressReasonAllocationCDNExcluded EgressReason = "allocation_cdn_excluded"
)

// Dispatch outcome and failure tokens. A flow states what happened to the
// packets it dispatched; an unknown outcome is stated as unknown, never as
// success.
const (
	// FlowForwardQueued means the packet was accepted into the backend queue.
	FlowForwardQueued = "queued_to_backend"
	// FlowForwardWritten means the packet was written to the WAN device.
	FlowForwardWritten = "written_to_wan"
	// FlowForwardFailed means the dispatch failed; the reason names which check.
	FlowForwardFailed = "failed"

	FlowFailureReturnPathClosed   = "return_path_closed"
	FlowFailureEgressUnavailable  = "direct_egress_unavailable"
	FlowFailureWrite              = "wan_write_failed"
	FlowFailureBackendUnavailable = "backend_unavailable"
	FlowFailureBackendDetached    = "backend_detached"
	FlowFailureQueueFull          = "backend_queue_full"
	FlowFailureFlowTableFull      = "flow_table_full"
	FlowFailureSessionNotCurrent  = "session_not_current"

	// Backend write outcomes. A full write is a completion; a refusal and a short
	// write are distinct failures, because a cut write is not a refusal.
	FlowBackendWriteCompleted = "backend_write_completed"
	FlowBackendWriteFailed    = "backend_write_failed"
	FlowBackendWriteShort     = "short_write"
)

// flowStats is the evidence block of one flow entry. Immutable fields are written
// while the entry is created under DirectEgressManager.mu; the counters are
// atomics so the packet paths update them without taking that lock again.
type flowStats struct {
	// decidedAt is when the deciding branch chose this flow's route.
	decidedAt time.Time
	// policyGeneration is the published policy generation the decision was taken
	// against.
	policyGeneration string
	// reason is the branch that decided, or empty when the flow was recorded
	// through the legacy path that carries no decision metadata.
	reason EgressReason
	// backendTunnelID is the proxy backend the decision selected, zero for a
	// DIRECT flow.
	backendTunnelID int64

	forwardPackets atomic.Uint64
	forwardBytes   atomic.Uint64
	forwardFailed  atomic.Uint64
	// forwardFailure holds the last refusal token, nil when none happened. The
	// token is stored by pointer so no integer id (and no conversion) is needed.
	forwardFailure atomic.Pointer[string]

	// backendWrites counts packets the backend device actually accepted in full.
	// It is the completion half of the proxy path: queue admission is recorded
	// separately and never implies a completed write.
	backendWrites atomic.Uint64
	// backendWriteFailed counts writes the device refused or cut short, and
	// backendWriteFailure names the last one.
	backendWriteFailed  atomic.Uint64
	backendWriteFailure atomic.Pointer[string]

	returnPackets atomic.Uint64
	returnBytes   atomic.Uint64
	returnFirstNS atomic.Int64
	returnLastNS  atomic.Int64

	// PROXY return arrival and handoff. A matched reply is one whose tuple reversed to
	// this flow and whose session and route generation still agreed; admission is the
	// client-queue enqueue; delivered is the client writer accepting the whole packet.
	// They are separate counters because "matched" and "delivered" fail differently.
	returnMatched   atomic.Uint64
	returnAdmitted  atomic.Uint64
	returnDropped   atomic.Uint64
	returnDelivered atomic.Uint64
	returnFailed    atomic.Uint64
	returnToken     atomic.Pointer[string]
}

// newFlowStats builds the evidence block for a decision. A decision taken through
// the legacy RecordFlow path passes a zero FlowDecision and gets an empty reason,
// which the snapshot reports as not recorded rather than as a guess.
func newFlowStats(decision FlowDecision, now time.Time) *flowStats {
	decided := decision.DecidedAt
	if decided.IsZero() {
		decided = time.Time{}
	}
	return &flowStats{
		decidedAt:        decided,
		policyGeneration: decision.PolicyGeneration,
		reason:           decision.Reason,
		backendTunnelID:  decision.BackendTunnelID,
	}
}

// FlowDecision is the metadata a deciding branch can state about a new flow.
type FlowDecision struct {
	// Reason is the branch that decided. Empty means "not recorded".
	Reason EgressReason
	// PolicyGeneration is the generation the decision was taken against.
	PolicyGeneration string
	// DecidedAt is the instant the branch decided. Zero means "not recorded".
	DecidedAt time.Time
	// BackendTunnelID is the proxy backend for a PROXY decision.
	BackendTunnelID int64
}

// recordForward notes one dispatched packet. It is called after the I/O, through
// the pointer the caller already holds, so it adds no lock to the forward path.
func (s *flowStats) recordForward(bytes int64, err error, failure string) {
	if s == nil {
		return
	}
	if err != nil {
		s.forwardFailed.Add(1)
		if failure != "" {
			s.forwardFailure.Store(&failure)
		}
		return
	}
	s.forwardPackets.Add(1)
	if bytes > 0 {
		s.forwardBytes.Add(uint64(bytes))
	}
}

// recordBackendWrite notes the outcome of one backend device write on the flow that
// ADMITTED the packet. The evidence pointer travels with the queued work, so a write
// that happens after a rekey, a retirement or a tuple reuse credits the incarnation
// that enqueued the packet and never the current owner of the same tuple.
func (s *flowStats) recordBackendWrite(written, total int, err error) {
	if s == nil {
		return
	}
	switch {
	case err != nil:
		s.backendWriteFailed.Add(1)
		token := FlowBackendWriteFailed
		s.backendWriteFailure.Store(&token)
	case written < total:
		s.backendWriteFailed.Add(1)
		token := FlowBackendWriteShort
		s.backendWriteFailure.Store(&token)
	default:
		s.backendWrites.Add(1)
	}
}

// writeFailureToken reads the last backend write failure token, empty when none.
func writeFailureToken(stats *flowStats) string {
	if stats == nil {
		return ""
	}
	if token := stats.backendWriteFailure.Load(); token != nil {
		return *token
	}
	return ""
}

// Counter reads are weak: the return, forward and backend-write counters are independent
// atomics, so one snapshot can show an arrival without its admission, or an admission
// without its handoff, while the reply is still in flight. Conservation
// (matched == admitted + dropped, admitted == delivered + failed) therefore holds for
// settled work only, and a caller that needs it must state that it waited.
//
// recordReturnMatch notes one backend reply that reversed to this flow and whose owner
// still agreed. It is arrival evidence, not delivery.
func (s *flowStats) recordReturnMatch() {
	if s == nil {
		return
	}
	s.returnMatched.Add(1)
}

// recordReturnAdmitted notes that the reply entered the bounded client queue.
func (s *flowStats) recordReturnAdmitted() {
	if s == nil {
		return
	}
	s.returnAdmitted.Add(1)
}

// recordReturnRefused notes where the reply stopped before the client writer: the queue,
// the rate limiter, the size cap or the return path itself.
func (s *flowStats) recordReturnRefused(token string) {
	if s == nil {
		return
	}
	s.returnDropped.Add(1)
	s.setReturnToken(token)
}

// recordReturnDelivered notes the client writer's actual outcome for a matched reply.
func (s *flowStats) recordReturnDelivered(written, total int, err error) {
	if s == nil {
		return
	}
	switch {
	case err != nil:
		s.returnFailed.Add(1)
		s.setReturnToken(FlowReturnWriteFailed)
	case written < total:
		s.returnFailed.Add(1)
		s.setReturnToken(FlowReturnShortWrite)
	default:
		s.returnDelivered.Add(1)
	}
}

// setReturnToken keeps the first refusal visible: a later successful write must not erase
// the reason an earlier reply of the same flow never reached the client.
func (s *flowStats) setReturnToken(token string) {
	if token == "" {
		return
	}
	if s.returnToken.Load() == nil {
		s.returnToken.CompareAndSwap(nil, &token)
	}
}

// returnTokenFor reads the recorded return failure token, empty when none.
func returnTokenFor(stats *flowStats) string {
	if stats == nil {
		return ""
	}
	if token := stats.returnToken.Load(); token != nil {
		return *token
	}
	return ""
}

// recordReturn notes one reply that passed every ownership check and was handed
// to the client path.
func (s *flowStats) recordReturn(bytes int64, now time.Time) {
	if s == nil {
		return
	}
	s.returnPackets.Add(1)
	if bytes > 0 {
		s.returnBytes.Add(uint64(bytes))
	}
	ns := now.UnixNano()
	if s.returnFirstNS.Load() == 0 {
		s.returnFirstNS.CompareAndSwap(0, ns)
	}
	s.returnLastNS.Store(ns)
}

// RecordFlowDecision records the routing decision for a 5-tuple together with the
// metadata of the branch that took it. It has the same shape and the same
// validation as RecordFlow; a caller with no metadata uses RecordFlow.
func (m *DirectEgressManager) RecordFlowDecision(peerKey, sessionID string, generation uint64, packet []byte, choice EgressChoice, decision FlowDecision) error {
	if m == nil {
		return nil
	}
	key, err := flowKeyForPacket(peerKey, packet)
	if err != nil {
		return err
	}
	if decision.DecidedAt.IsZero() {
		decision.DecidedAt = time.Now()
	}
	return m.recordFlowKeyed(key, sessionID, generation, choice, &decision)
}

// RecordProxyDispatch notes the outcome of handing one proxy-required packet to
// the backend queue. The entry is looked up once under the read lock; the
// counters are updated atomically after it is released.
//
// It is called only from the proxy dispatch site, which already knows the flow was
// recorded, so a miss means the flow was retired in between and the outcome is
// simply not attributed (the packet's fate is still counted globally).
func (m *DirectEgressManager) RecordProxyDispatch(peerKey, sessionID string, generation uint64, packet []byte, accepted bool, failure string) {
	if m == nil {
		return
	}
	key, err := flowKeyForPacket(peerKey, packet)
	if err != nil {
		return
	}
	m.mu.RLock()
	entry := m.flows[key]
	var stats *flowStats
	if entry != nil && dispatchBelongsToIncarnation(entry, sessionID, generation) {
		stats = entry.evidence
	}
	m.mu.RUnlock()
	if stats == nil {
		return
	}
	if accepted {
		stats.recordForward(0, nil, "")
		return
	}
	stats.recordForward(0, errors.New("proxy dispatch refused"), failure)
}

// dispatchBelongsToIncarnation reports whether the flow entry found by tuple is
// the incarnation that dispatched the packet. A tuple is reusable: the peer key and
// the 5-tuple alone would let a queued packet from a retired session credit the
// successor that now owns the same tuple, so the session and the route generation
// have to match as well.
func dispatchBelongsToIncarnation(entry *flowEntry, sessionID string, generation uint64) bool {
	if entry == nil {
		return false
	}
	if sessionID != "" && entry.sessionID != sessionID {
		return false
	}
	if generation != 0 && entry.generation != generation {
		return false
	}
	return true
}

// recordDirectForward notes the DIRECT dispatch outcome on the entry the caller
// already holds. Called after the WAN write, never under the manager lock.
func recordDirectForward(stats *flowStats, bytes int64, err error) {
	if err == nil {
		stats.recordForward(bytes, nil, "")
		return
	}
	failure := FlowFailureWrite
	if errors.Is(err, ErrReturnPathClosed) {
		failure = FlowFailureReturnPathClosed
	} else if errors.Is(err, ErrDirectEgressUnavailable) {
		failure = FlowFailureEgressUnavailable
	}
	stats.recordForward(bytes, err, failure)
}

// dispatchEvidence returns the evidence block of the flow that owns this packet on
// the given incarnation, or nil when the tuple belongs to someone else. It is the
// read-only half of RecordProxyDispatch and applies the same guard.
func (m *DirectEgressManager) dispatchEvidence(peerKey, sessionID string, generation uint64, packet []byte) *flowStats {
	if m == nil {
		return nil
	}
	key, err := flowKeyForPacket(peerKey, packet)
	if err != nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry := m.flows[key]
	if entry == nil || !dispatchBelongsToIncarnation(entry, sessionID, generation) {
		return nil
	}
	return entry.evidence
}

// flowKeyForPacket builds the flow key for one IPv4 TCP/UDP packet. It is the
// same key RecordFlow and LookupFlow build; a packet that cannot be keyed is not
// attributable and reports an error instead of a zero key.
func flowKeyForPacket(peerKey string, packet []byte) (FlowKey, error) {
	if len(packet) < 20 || (packet[0]>>4) != 4 {
		return FlowKey{}, ErrInvalidIPv4Packet
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+4 {
		return FlowKey{}, ErrInvalidTransportHdr
	}
	proto := packet[9]
	if proto != 6 && proto != 17 {
		return FlowKey{}, ErrUnsupportedFlowProtocol
	}
	return FlowKey{
		PeerKey:  peerKey,
		Protocol: proto,
		SrcIP:    [4]byte{packet[12], packet[13], packet[14], packet[15]},
		DstIP:    [4]byte{packet[16], packet[17], packet[18], packet[19]},
		SrcPort:  binaryUint16(packet[ihl : ihl+2]),
		DstPort:  binaryUint16(packet[ihl+2 : ihl+4]),
	}, nil
}

// ErrUnsupportedFlowProtocol reports a packet whose protocol the flow table does
// not key (anything but TCP and UDP).
var ErrUnsupportedFlowProtocol = errors.New("forwarder: unsupported protocol for flow evidence")

// flowEvidenceRefBytes is what one flow actually carries: the measured size of the
// evidence struct plus the pointer that reaches it from the flow entry. It is
// derived, not estimated by eye: the struct holds two time instants, a string and
// a reason string, five atomic counters and an atomic token pointer, which a
// by-hand "96 bytes" guess under-counted.
var flowEvidenceRefBytes = int(unsafe.Sizeof(flowStats{})) + int(unsafe.Sizeof((*flowStats)(nil)))

// FlowEvidenceBytesPerFlow is the measured metadata footprint one flow entry
// carries.
func FlowEvidenceBytesPerFlow() int { return flowEvidenceRefBytes }

// FlowEvidenceMaxFlowTableBytes is the worst-case metadata size at the supported
// flow-table capacity. The table bound is the metadata bound: there is no second
// store and no retention after a flow retires.
func FlowEvidenceMaxFlowTableBytes() int { return flowEvidenceRefBytes * 65536 }

// sessionFlowEvidence is the read-only copy of one flow's evidence.
type sessionFlowEvidence struct {
	decidedAt           time.Time
	policyGeneration    string
	reason              EgressReason
	backendTunnelID     int64
	forwardPackets      uint64
	forwardBytes        uint64
	forwardFailed       uint64
	forwardFailure      string
	backendWrites       uint64
	backendWriteFailed  uint64
	backendWriteFailure string
	returnPackets       uint64
	returnBytes         uint64
	returnFirst         time.Time
	returnLast          time.Time
	returnMatched       uint64
	returnAdmitted      uint64
	returnDropped       uint64
	returnDelivered     uint64
	returnFailed        uint64
	returnToken         string
}

// forwardFailureToken reads the last refusal token of a flow, empty when none.
func forwardFailureToken(stats *flowStats) string {
	if stats == nil {
		return ""
	}
	if token := stats.forwardFailure.Load(); token != nil {
		return *token
	}
	return ""
}

// snapshotFlowEvidence copies one evidence block. A nil block (an entry created
// through the legacy path that never carried metadata) answers a zero value, which
// the wire shape reports as not recorded.
func snapshotFlowEvidence(stats *flowStats) sessionFlowEvidence {
	if stats == nil {
		return sessionFlowEvidence{}
	}
	out := sessionFlowEvidence{
		decidedAt:           stats.decidedAt,
		policyGeneration:    stats.policyGeneration,
		reason:              stats.reason,
		backendTunnelID:     stats.backendTunnelID,
		forwardPackets:      stats.forwardPackets.Load(),
		forwardBytes:        stats.forwardBytes.Load(),
		forwardFailed:       stats.forwardFailed.Load(),
		forwardFailure:      forwardFailureToken(stats),
		backendWrites:       stats.backendWrites.Load(),
		backendWriteFailed:  stats.backendWriteFailed.Load(),
		backendWriteFailure: writeFailureToken(stats),
		returnPackets:       stats.returnPackets.Load(),
		returnBytes:         stats.returnBytes.Load(),
		returnMatched:       stats.returnMatched.Load(),
		returnAdmitted:      stats.returnAdmitted.Load(),
		returnDropped:       stats.returnDropped.Load(),
		returnDelivered:     stats.returnDelivered.Load(),
		returnFailed:        stats.returnFailed.Load(),
		returnToken:         returnTokenFor(stats),
	}
	if ns := stats.returnFirstNS.Load(); ns != 0 {
		out.returnFirst = time.Unix(0, ns).UTC()
	}
	if ns := stats.returnLastNS.Load(); ns != 0 {
		out.returnLast = time.Unix(0, ns).UTC()
	}
	return out
}

// binaryUint16 reads a big-endian uint16 without importing encoding/binary into
// this file's callers.
func binaryUint16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}
