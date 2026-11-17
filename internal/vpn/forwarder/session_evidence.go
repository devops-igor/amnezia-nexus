package forwarder

import (
	"cmp"
	"container/heap"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// This file is the read-only session view the per-client diagnosis endpoint
// needs (issue #861), in two halves that answer two questions:
//
//   - SessionRouteStates reports which route generations are registered, so a
//     selection can be bound to one incarnation instead of to a session id that
//     a rekey has already replaced.
//   - SnapshotSessionFlows copies the flow decisions one incarnation owns.
//
// Neither is a packet-path entry point. SnapshotSessionFlows deliberately does
// NOT call LookupFlow: LookupFlow refreshes lastSeen and retires expired flows,
// so using it to read would keep a stale flow alive and move the state the
// caller is trying to observe. This file copies under the existing locks and
// changes nothing: no lastSeen, no retirement, no NAT entry, no counter.
//
// The listing is bounded in time as well as in size. Flows are keyed by 5-tuple,
// so a per-session listing has to filter the whole table; the scan therefore stops
// after SessionFlowScanRecords records and says so, instead of holding the
// direct-egress lock for the length of a full table. Measured cost of that bound
// is in session_evidence_bench_test.go; a per-session index is the structural fix
// and belongs to a later slice.

const (
	// SessionFlowSnapshotDefaultLimit is the flow page size used when a caller
	// does not ask for a smaller one.
	SessionFlowSnapshotDefaultLimit = 128
	// SessionFlowSnapshotMaxLimit bounds one page. A session can own far more
	// records than one response should carry, so the page is capped and the
	// caller reports the truncation instead of receiving an unbounded answer.
	SessionFlowSnapshotMaxLimit = 512
	// SessionFlowScanRecords bounds how many flow records one snapshot VISITS.
	// This — not the page size — is the work bound: flows are keyed by 5-tuple, so
	// a per-session listing filters the table, and at the supported 65536-entry
	// table this visits a quarter of it and reports scan_complete=false with the
	// real count. Measured hold of the direct-egress read lock at that bound:
	// 2.22 ms worst case (every visited record owned by the session) and 0.50 ms
	// when 64 sessions share the table, 144 KB per page. A per-session index is the
	// structural fix; until it exists this bound is the honest one, and the page
	// limit below only bounds the RESPONSE size.
	SessionFlowScanRecords = 16384
)

// SessionRoute is the read-only identity of one registered route generation.
type SessionRoute struct {
	SessionID       string
	ConnectionID    string
	AssignedIP      string
	BackendTunnelID int64
	Generation      uint64
	ConnectedAt     time.Time
}

// SessionFlow is one live flow record's read-only copy.
//
// PeerKey and the client address are deliberately absent: a diagnosis is about a
// selected session, and the peer key is an authentication artifact that must not
// travel in an administrative response.
type SessionFlow struct {
	Protocol   uint8
	SrcPort    uint16
	DstIP      netip.Addr
	DstPort    uint16
	Choice     EgressChoice
	Generation uint64
	LastSeen   time.Time
	// Expired is computed at the caller's instant with the same timeouts the
	// packet path applies. It is reported, not applied: no flow is retired here.
	Expired bool
	// CloseSeen reports that a FIN or RST was already observed for the flow, so
	// its remaining idle allowance is the short close window.
	CloseSeen bool

	// The evidence block of issue #861. A zero value in DecidedAt, Reason or
	// PolicyGeneration means the flow was recorded by a path that carried no
	// decision metadata: it is reported as not recorded, never reconstructed.
	DecidedAt        time.Time
	DecisionReason   EgressReason
	PolicyGeneration string
	BackendTunnelID  int64

	// Forward is what the dispatch path actually did with this flow's packets.
	ForwardPackets uint64
	ForwardBytes   uint64
	ForwardFailed  uint64
	// BackendWrites is how many proxy packets the backend DEVICE accepted in full;
	// BackendWriteFailed is how many it refused or cut short. They are observed by
	// the writer, through the flow identity captured at enqueue.
	BackendWrites       uint64
	BackendWriteFailed  uint64
	BackendWriteFailure string
	// ForwardFailure names the last refusal, empty when none happened.
	ForwardFailure string

	// Return is what the DIRECT reply path actually delivered for this flow.
	// PROXYReturnMeasured is false for every flow: the proxy return direction is
	// not attributable at this checkpoint and the caller must say so.
	ReturnPackets       uint64
	ReturnBytes         uint64
	ReturnFirst         time.Time
	ReturnLast          time.Time
	ReturnObserved      bool
	PROXYReturnMeasured bool
}

// SessionFlowList is a bounded, ordered page of one session's live flows.
type SessionFlowList struct {
	Flows []SessionFlow
	// Total is how many flows matched the selection WITHIN the visited window.
	// It is not the session's absolute total unless ScanComplete is true.
	Total     int
	Truncated bool
	// Scanned is how many flow records the filtered scan visited.
	Scanned int
	// ScanComplete reports that the whole flow table was visited, so Total is the
	// session's real count at that instant.
	ScanComplete bool
}

// SessionRouteStates returns value copies of every registered route.
//
// The slice is sorted by session id and, inside one session, newest generation
// first, so a selection derived from it is deterministic across calls.
func (f *Forwarder) SessionRouteStates() []SessionRoute {
	if f == nil {
		return []SessionRoute{}
	}
	f.mu.RLock()
	out := make([]SessionRoute, 0, len(f.routesByPeer))
	for _, route := range f.routesByPeer {
		if route == nil {
			continue
		}
		out = append(out, SessionRoute{
			SessionID:       route.sessionID,
			ConnectionID:    route.connectionID,
			AssignedIP:      route.assignedIP,
			BackendTunnelID: route.backendTunnelID,
			Generation:      route.generation,
			ConnectedAt:     route.createdAt,
		})
	}
	f.mu.RUnlock()

	slices.SortFunc(out, func(a, b SessionRoute) int {
		if a.SessionID != b.SessionID {
			return strings.Compare(a.SessionID, b.SessionID)
		}
		// Newest generation first inside one session.
		return cmp.Compare(b.Generation, a.Generation)
	})
	return out
}

// SessionRouteGeneration reports the route generation registered for a session,
// or false when the session owns no route. It is read-only and takes the same
// read lock as the other listings; a caller that must not invent an incarnation
// uses it to decide whether one is established.
func (f *Forwarder) SessionRouteGeneration(sessionID string) (uint64, bool) {
	if f == nil || sessionID == "" {
		return 0, false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	generation := uint64(0)
	found := false
	for _, route := range f.routesByPeer {
		if route == nil || route.sessionID != sessionID {
			continue
		}
		if !found || route.generation > generation {
			generation = route.generation
			found = true
		}
	}
	return generation, found
}

// SnapshotSessionFlows copies the flows owned by sessionID and, when generation
// is non-zero, by that route generation, newest activity first, at most limit
// records.
//
// The limit bounds the ANSWER, not the work: the scan visits up to
// SessionFlowScanRecords table entries and reports how many it visited and whether
// that covered the table (Scanned, ScanComplete). Callers must present a page as a
// page and the scan as the cost.
//
// A flow is owned by exactly one session and one generation; a record whose
// generation differs belongs to a previous incarnation and is never returned for
// the current one. An expired record is reported with Expired set and is left in
// the table exactly as it was found.
func (m *DirectEgressManager) SnapshotSessionFlows(sessionID string, generation uint64, now time.Time, limit int) SessionFlowList {
	if limit <= 0 {
		limit = SessionFlowSnapshotDefaultLimit
	}
	if limit > SessionFlowSnapshotMaxLimit {
		limit = SessionFlowSnapshotMaxLimit
	}
	if m == nil || sessionID == "" {
		return SessionFlowList{Flows: []SessionFlow{}, ScanComplete: true}
	}

	page := &sessionFlowPage{limit: limit}
	m.mu.RLock()
	scanned := 0
	for key, entry := range m.flows {
		if scanned >= SessionFlowScanRecords {
			break
		}
		scanned++
		if !sessionFlowMatches(entry, sessionID, generation) {
			continue
		}
		evidence := snapshotFlowEvidence(entry.evidence)
		page.add(SessionFlow{
			Protocol:            key.Protocol,
			SrcPort:             key.SrcPort,
			DstIP:               netip.AddrFrom4(key.DstIP),
			DstPort:             key.DstPort,
			Choice:              entry.choice,
			Generation:          entry.generation,
			LastSeen:            entry.lastSeen,
			Expired:             m.isFlowExpiredLocked(entry, key.Protocol, now),
			CloseSeen:           entry.closeSeen,
			DecidedAt:           evidence.decidedAt,
			DecisionReason:      evidence.reason,
			PolicyGeneration:    evidence.policyGeneration,
			BackendTunnelID:     evidence.backendTunnelID,
			ForwardPackets:      evidence.forwardPackets,
			ForwardBytes:        evidence.forwardBytes,
			ForwardFailed:       evidence.forwardFailed,
			ForwardFailure:      evidence.forwardFailure,
			BackendWrites:       evidence.backendWrites,
			BackendWriteFailed:  evidence.backendWriteFailed,
			BackendWriteFailure: evidence.backendWriteFailure,
			ReturnPackets:       evidence.returnPackets,
			ReturnBytes:         evidence.returnBytes,
			ReturnFirst:         evidence.returnFirst,
			ReturnLast:          evidence.returnLast,
			ReturnObserved:      evidence.returnPackets > 0,
			// PROXY return is not attributed at this checkpoint; a DIRECT flow
			// states what the reply path observed, and nothing states payload
			// success.
			PROXYReturnMeasured: false,
		})
	}
	total := len(m.flows)
	m.mu.RUnlock()

	list := SessionFlowList{
		Flows:        page.sorted(),
		Total:        page.matched,
		Truncated:    page.matched > len(page.heap),
		Scanned:      scanned,
		ScanComplete: scanned >= total,
	}
	return list
}

// sessionFlowMatches reports whether a flow record belongs to the selection. A
// zero generation means "any generation of this session"; a non-zero one pins
// the incarnation, so a record from a previous generation is never returned for
// the current one.
func sessionFlowMatches(entry *flowEntry, sessionID string, generation uint64) bool {
	if entry == nil || entry.sessionID != sessionID {
		return false
	}
	return generation == 0 || entry.generation == generation
}

// sessionFlowPage keeps the `limit` best-ranked flows seen so far in a min-heap
// keyed by the inverse of the ranking, so the worst candidate is always at the
// root and can be replaced in O(log limit). It is what bounds the read's memory
// to one page instead of one slice per matching record.
type sessionFlowPage struct {
	limit   int
	matched int
	heap    sessionFlowHeap
}

// add offers one matching record to the page.
func (p *sessionFlowPage) add(flow SessionFlow) {
	p.matched++
	if len(p.heap) < p.limit {
		heap.Push(&p.heap, flow)
		return
	}
	if compareSessionFlow(flow, p.heap[0]) < 0 {
		p.heap[0] = flow
		heap.Fix(&p.heap, 0)
	}
}

// sorted returns the page in ranking order.
func (p *sessionFlowPage) sorted() []SessionFlow {
	out := make([]SessionFlow, len(p.heap))
	copy(out, p.heap)
	slices.SortFunc(out, compareSessionFlow)
	return out
}

// sessionFlowHeap is the min-heap of the WORST-ranked records: Less reports the
// record that ranks later, which puts the last one at the root.
type sessionFlowHeap []SessionFlow

func (h sessionFlowHeap) Len() int           { return len(h) }
func (h sessionFlowHeap) Less(i, j int) bool { return compareSessionFlow(h[i], h[j]) > 0 }
func (h sessionFlowHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sessionFlowHeap) Push(x any)        { *h = append(*h, x.(SessionFlow)) }
func (h *sessionFlowHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// compareSessionFlow ranks records: newest observed activity first, then by
// destination and ports so a page is a stable prefix rather than an arbitrary
// map slice. A negative result means a ranks before b.
func compareSessionFlow(a, b SessionFlow) int {
	if !a.LastSeen.Equal(b.LastSeen) {
		return b.LastSeen.Compare(a.LastSeen)
	}
	if c := a.DstIP.Compare(b.DstIP); c != 0 {
		return c
	}
	if c := cmp.Compare(a.DstPort, b.DstPort); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Protocol, b.Protocol); c != 0 {
		return c
	}
	return cmp.Compare(a.SrcPort, b.SrcPort)
}
