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
	// destination DIRECT.
	EgressReasonEvidenceDirect EgressReason = "evidence_direct"
	// EgressReasonProxyCIDRRule means the published policy snapshot's address
	// rule put the destination on the proxy.
	EgressReasonProxyCIDRRule EgressReason = "proxy_cidr_rule"
	// EgressReasonProxyCachedEvidence means the session's own retained PROXY
	// decision put the destination on the proxy.
	EgressReasonProxyCachedEvidence EgressReason = "proxy_cached_evidence"
	// EgressReasonNoTrustedEvidence means there was no usable evidence, so the
	// fail-closed default applied.
	EgressReasonNoTrustedEvidence EgressReason = "no_trusted_evidence"
	// EgressReasonNonTCPOrUDP means the protocol cannot be NATed directly.
	EgressReasonNonTCPOrUDP EgressReason = "non_tcp_udp_fallback"
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

	returnPackets atomic.Uint64
	returnBytes   atomic.Uint64
	returnFirstNS atomic.Int64
	returnLastNS  atomic.Int64
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
	decidedAt        time.Time
	policyGeneration string
	reason           EgressReason
	backendTunnelID  int64
	forwardPackets   uint64
	forwardBytes     uint64
	forwardFailed    uint64
	forwardFailure   string
	returnPackets    uint64
	returnBytes      uint64
	returnFirst      time.Time
	returnLast       time.Time
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
		decidedAt:        stats.decidedAt,
		policyGeneration: stats.policyGeneration,
		reason:           stats.reason,
		backendTunnelID:  stats.backendTunnelID,
		forwardPackets:   stats.forwardPackets.Load(),
		forwardBytes:     stats.forwardBytes.Load(),
		forwardFailed:    stats.forwardFailed.Load(),
		forwardFailure:   forwardFailureToken(stats),
		returnPackets:    stats.returnPackets.Load(),
		returnBytes:      stats.returnBytes.Load(),
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
