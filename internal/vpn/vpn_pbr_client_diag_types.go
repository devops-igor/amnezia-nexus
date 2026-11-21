package vpn

// This file holds the wire shape of the per-client diagnosis endpoint (issue
// #861, slice 1). The behavior lives in vpn_pbr_client_diag.go; keeping the
// shape separate keeps each file inside the repository size budget.
//
// Two rules decided this shape:
//
//   - Fields this slice cannot read are PRESENT and say "not_recorded" instead
//     of being omitted. A missing key would let a later slice change the shape,
//     and a client could not tell "the panel does not know" from "the panel's
//     build is older than the server's".
//   - Nothing here is inferred. A recorded flow says which route it was given
//     and why, but not whether the application succeeded. Each unobservable fact
//     is its own field with an explicit unknown token.
//
// There is no DNS section. The panel records no DNS evidence: the producer, the
// route cache and the history store that fed one are deleted, so a member shaped
// like a permanently empty history would describe something this build cannot
// ever report. The section is absent from the answer rather than present and
// empty.

const (
	// ClientDiagnosisStateLive means the selected session and route generation
	// are the ones currently registered, so the records below belong to that
	// incarnation.
	ClientDiagnosisStateLive = "live"
	// ClientDiagnosisStateRouteGenerationReplaced means the session is live but
	// the requested route generation has been replaced (a rekey), so this
	// incarnation's flow records are gone. No record is returned.
	ClientDiagnosisStateRouteGenerationReplaced = "route_generation_replaced"
	// ClientDiagnosisStateRouteAbsent means the session exists but owns no
	// forwarder route, so the data plane holds no flow for it.
	ClientDiagnosisStateRouteAbsent = "route_absent"
	// ClientDiagnosisStateUnknownSession means no live session and no route carry
	// the id. A session that ended cannot be told apart from one that never
	// existed, because nothing retains a terminated session.
	ClientDiagnosisStateUnknownSession = "unknown_session"
	// ClientDiagnosisStatePolicyDisabled means policy routing is off, so no
	// per-client evidence exists to read.
	ClientDiagnosisStatePolicyDisabled = "policy_disabled"
	// ClientDiagnosisStateIdentityUnavailable means the session registry is not
	// available, so no selection can be verified against it.
	ClientDiagnosisStateIdentityUnavailable = "identity_unavailable"
	// ClientDiagnosisStateInconsistent means the selection changed while the
	// answer was being read. The records are withheld instead of being mixed
	// across two incarnations.
	ClientDiagnosisStateInconsistent = "inconsistent"

	// ClientDiagnosisTokenNotRecorded is the value of every field this slice
	// cannot state. It is a token, not a sentence: the UI translates it.
	ClientDiagnosisTokenNotRecorded = "not_recorded"
	// ClientDiagnosisTokenNotObservable marks a fact the panel can never state
	// from router-side evidence, whatever slice is built.
	ClientDiagnosisTokenNotObservable = "not_observable"
)

// Limitation tokens an answer carries. They are fixed identifiers so the UI can
// translate them and a test can name the exact caveat rather than matching
// prose.
const (
	// ClientDiagnosisLimitFlowEvidenceInstall states the one case where a forwarded packet can
	// be missing from the flow list: its decision record could not be installed (the table was
	// full), so no flow evidence exists for it. The packet was still forwarded, so it is NOT a
	// drop and never appears in the drop section.
	ClientDiagnosisLimitFlowEvidenceInstall = "flow_evidence_install_failure_not_recorded"
	ClientDiagnosisLimitApplication         = "application_success_not_observable"
	ClientDiagnosisLimitProxyReturn         = "proxy_return_not_measured"
	// ClientDiagnosisLimitReturnTupleAssociation states the authority behind a return
	// claim: a reply is associated with the flow that currently owns the tuple. A late
	// reply from a replaced incarnation on the same tuple is not distinguishable from a
	// current one by routing state alone.
	ClientDiagnosisLimitReturnTupleAssociation = "return_current_tuple_association"
	ClientDiagnosisLimitSessionEnd             = "session_end_not_distinguishable"
	ClientDiagnosisLimitIPv6                   = "ipv6_not_supported"
	ClientDiagnosisLimitSingleSnapshot         = "not_an_atomic_cross_subsystem_snapshot"
	ClientDiagnosisLimitSelectionChanged       = "selection_changed_during_read"
	ClientDiagnosisLimitFlowScanPartial        = "flow_scan_window_partial"
	// The counter-sampling caveat: the counters are read live, not as a settled total.
	ClientDiagnosisLimitFlowCountersSampled = "flow_counters_are_live_samples"
	ClientDiagnosisLimitIdentitySource      = "session_registry_unavailable"
)

// ClientDiagnosisRequest is one validated diagnosis request.
type ClientDiagnosisRequest struct {
	// SessionID selects the exact session incarnation. It is required: the
	// server never resolves a connection or a user to a session.
	SessionID string
	// RouteGeneration pins the incarnation when the picker supplies one. A
	// different live generation means the requested one was replaced.
	RouteGeneration uint64
	// HasRouteGeneration distinguishes "no generation supplied" from "generation
	// zero supplied", which are different requests.
	HasRouteGeneration bool
	// FlowLimit bounds the flow page. Zero uses the default.
	FlowLimit int
}

// ClientDiagnosisTarget is one selectable session incarnation.
type ClientDiagnosisTarget struct {
	SessionID       string `json:"session_id"`
	ConnectionID    string `json:"connection_id,omitempty"`
	ConnectionName  string `json:"connection_name,omitempty"`
	Username        string `json:"username,omitempty"`
	AssignedIP      string `json:"assigned_ip,omitempty"`
	ConnectedAt     string `json:"connected_at,omitempty"`
	RouteLive       bool   `json:"route_live"`
	RouteGeneration uint64 `json:"route_generation,omitempty"`
}

// ClientDiagnosisTargets is the client picker's answer.
type ClientDiagnosisTargets struct {
	Clients              []ClientDiagnosisTarget `json:"clients"`
	SampledAt            string                  `json:"sampled_at"`
	PolicyRoutingEnabled bool                    `json:"policy_routing_enabled"`
	NotCovered           []string                `json:"not_covered"`
	ReadOnly             bool                    `json:"read_only"`
}

// ClientDiagnosisSelection echoes the incarnation the answer belongs to.
type ClientDiagnosisSelection struct {
	SessionID string `json:"session_id"`
	// State is one of the ClientDiagnosisState* tokens.
	State                    string  `json:"state"`
	RouteGeneration          uint64  `json:"route_generation,omitempty"`
	RequestedRouteGeneration *uint64 `json:"requested_route_generation,omitempty"`
	ConnectionID             string  `json:"connection_id,omitempty"`
	ConnectionName           string  `json:"connection_name,omitempty"`
	Username                 string  `json:"username,omitempty"`
	AssignedIP               string  `json:"assigned_ip,omitempty"`
	ConnectedAt              string  `json:"connected_at,omitempty"`
}

// ClientDiagnosisCoverage states what was read and what was not.
type ClientDiagnosisCoverage struct {
	PolicyRoutingEnabled bool   `json:"policy_routing_enabled"`
	SampledAt            string `json:"sampled_at"`
	// EvidenceSource names the stores the answer was built from.
	EvidenceSource string `json:"evidence_source"`
	// NotCovered lists facts no router-side store retains today.
	NotCovered []string `json:"not_covered"`
	// NotRecorded lists the facts the stores this answer reads cannot state, so a
	// reader can tell "the panel does not record it" from "nothing happened".
	NotRecorded []string `json:"not_recorded"`
}

// ClientDiagnosisFlowDispatch is what the dispatch path did with the flow's
// packets. Queue acceptance, a device write and a reply admission are separate
// facts and are never merged into one "sent".
type ClientDiagnosisFlowDispatch struct {
	// State is queued_to_backend | written_to_wan | failed | not_recorded.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// ClientDiagnosisFlowForward counts dispatches by outcome. The values are read
// live at the sampled instant: they are not a conservation-checked total and can
// be behind the packet path by the packets in flight during the read.
type ClientDiagnosisFlowForward struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Failed  uint64 `json:"failed"`
	Failure string `json:"failure,omitempty"`
	// BackendWrites counts the proxy packets the backend DEVICE accepted in full,
	// and BackendWriteFailed those it refused or cut short. Queue admission is
	// recorded separately in Packets, so "admitted" and "written" stay distinct.
	BackendWrites       uint64 `json:"backend_writes"`
	BackendWriteFailed  uint64 `json:"backend_write_failed"`
	BackendWriteFailure string `json:"backend_write_failure,omitempty"`
}

// ClientDiagnosisFlowReturn is the return direction. DIRECT flows state what the
// reply path admitted. PROXY flows state the observed chain separately: a reply that
// reversed to this flow, the client-queue admission, and the client writer's actual
// handoff. None of them is application success, and a flow that was never matched says
// not_measured rather than appearing as "no traffic".
type ClientDiagnosisFlowReturn struct {
	Evidence string `json:"evidence"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
	FirstAt  string `json:"first_at,omitempty"`
	LastAt   string `json:"last_at,omitempty"`
	// PROXY direction: arrival, queue admission and client handoff are distinct
	// observations, so "admitted" is never rendered as "delivered".
	// Authority names what the match proves. Today it is the current tuple owner; it is
	// not proof of which remote incarnation sent the reply.
	Authority string `json:"authority,omitempty"`
	Matched   uint64 `json:"matched,omitempty"`
	Admitted  uint64 `json:"admitted,omitempty"`
	Dropped   uint64 `json:"dropped,omitempty"`
	Delivered uint64 `json:"delivered,omitempty"`
	Failed    uint64 `json:"failed,omitempty"`
	Failure   string `json:"failure,omitempty"`
}

// ClientDiagnosisFlow is one live flow record.
type ClientDiagnosisFlow struct {
	Protocol        string `json:"protocol"`
	ClientSrcPort   uint16 `json:"client_src_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint16 `json:"destination_port"`
	// Choice is the recorded routing choice for this 5-tuple.
	Choice          string `json:"choice"`
	RouteGeneration uint64 `json:"route_generation"`
	LastSeen        string `json:"last_seen"`
	// LastSeenAgeSeconds is elapsed time since the last packet refreshed the
	// record. It is activity, not the decision time.
	LastSeenAgeSeconds int64 `json:"last_seen_age_seconds"`
	// Expired means the record is past its idle allowance at the sampled
	// instant. The record is reported as found and is not retired by this read.
	Expired   bool `json:"expired"`
	CloseSeen bool `json:"close_seen"`

	// The decision that created the flow, recorded by the branch that took it.
	// "not_recorded" means the flow was installed by a path that carries no
	// metadata; it is never reconstructed from last_seen or from today's policy.
	DecisionTime     string `json:"decision_time"`
	DecisionReason   string `json:"decision_reason"`
	PolicyGeneration string `json:"policy_generation"`
	BackendTunnelID  *int64 `json:"backend_tunnel_id,omitempty"`

	Dispatch ClientDiagnosisFlowDispatch `json:"dispatch"`
	Forward  ClientDiagnosisFlowForward  `json:"forward"`
	Return   ClientDiagnosisFlowReturn   `json:"return"`
}

// ClientDiagnosisFlows is the live-flow section.
type ClientDiagnosisFlows struct {
	Available bool   `json:"available"`
	State     string `json:"state"`
	// Scanned is how many flow records the filtered scan visited, so the cost of
	// the answer is visible instead of promised.
	Scanned int `json:"scanned"`
	// ScanComplete reports that every flow record of THIS selection was visited, so Total is the
	// session's real count at the sampled instant.
	ScanComplete bool `json:"scan_complete"`
	// Total counts the records that matched INSIDE the visited window: it is a
	// lower bound of the session's own total whenever ScanComplete is false.
	Total     int                   `json:"total"`
	Truncated bool                  `json:"truncated"`
	Entries   []ClientDiagnosisFlow `json:"entries"`
}

// ClientDiagnosisDrop is one aggregated drop record. Slice 1 retains none.
type ClientDiagnosisDrop struct {
	// DestinationIP and DestinationPort are present only when the refused packet carried
	// them. HasTuple is false for a packet too malformed to trust, so an empty address is
	// never read as a destination of 0.0.0.0.
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort uint16 `json:"destination_port,omitempty"`
	HasTuple        bool   `json:"has_tuple"`
	Protocol        string `json:"protocol,omitempty"`
	Reason          string `json:"reason"`
	Count           int64  `json:"count"`
	Bytes           uint64 `json:"bytes"`
	FirstSeen       string `json:"first_seen,omitempty"`
	LastSeen        string `json:"last_seen,omitempty"`
}

// ClientDiagnosisDrops is the drop section.
type ClientDiagnosisDrops struct {
	Available bool   `json:"available"`
	State     string `json:"state"`
	Total     int    `json:"total"`
	Truncated bool   `json:"truncated"`
	// Coverage states what the bounded ledger holds and what it lost, so an empty page is
	// never read as "this client was never refused".
	Coverage ClientDiagnosisDropCoverage `json:"coverage"`
	Entries  []ClientDiagnosisDrop       `json:"entries"`
}

// ClientDiagnosisDropCoverage reports the retention state of the pre-flow drop ledger.
type ClientDiagnosisDropCoverage struct {
	StartedAt string `json:"started_at,omitempty"`
	Stored    uint64 `json:"stored"`
	Merged    uint64 `json:"merged"`
	Evicted   uint64 `json:"evicted"`
	Pruned    uint64 `json:"pruned"`
	// Keys is ledger-wide and SessionKeys belongs to the selected incarnation, so a
	// client-scoped page never reports other clients' retention as its own.
	Keys            int    `json:"keys"`
	SessionKeys     int    `json:"session_keys"`
	Generation      uint64 `json:"generation"`
	KeyLimit        int    `json:"key_limit"`
	AgeLimitSeconds int    `json:"age_limit_seconds"`
}

// ClientDiagnosisResponse is the operator-facing answer.
//
// The observed sections (Flows, Drops) carry router-recorded facts only.
// No policy evaluation is merged into them: a policy verdict for a destination is
// a prospective classification and belongs to the separate dry-run endpoint.
//
// There is no dns member: this build records no DNS answer, query event or name
// correlation, so the key is absent rather than present with an empty history.
type ClientDiagnosisResponse struct {
	Selection   ClientDiagnosisSelection `json:"selection"`
	Coverage    ClientDiagnosisCoverage  `json:"coverage"`
	Flows       ClientDiagnosisFlows     `json:"flows"`
	Drops       ClientDiagnosisDrops     `json:"drops"`
	Limitations []string                 `json:"limitations"`
	// EvaluatedAt is the single instant every age and remaining lifetime in this
	// answer was computed against.
	EvaluatedAt string `json:"evaluated_at"`
	// ReadOnly is always true: the endpoint reads stores the packet path writes
	// and writes none of them.
	ReadOnly bool `json:"read_only"`
}
