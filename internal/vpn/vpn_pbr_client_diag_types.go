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
//   - Nothing here is inferred. A retained cache entry says which decision was
//     stored for an address; it does not say which query produced it, when the
//     routing decision was taken, why, or whether the application ever
//     succeeded. Each of those is its own field with an explicit unknown token.

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
	// ClientDiagnosisNamesNotRecorded is the names-match token for this slice:
	// the route cache is keyed by address, so no name is retained anywhere.
	ClientDiagnosisNamesNotRecorded = "not_recorded"
)

// Limitation tokens an answer carries. They are fixed identifiers so the UI can
// translate them and a test can name the exact caveat rather than matching
// prose.
const (
	ClientDiagnosisLimitNamesNotRecorded     = "dns_names_not_retained"
	ClientDiagnosisLimitQuestionsNotRecorded = "dns_questions_not_retained"
	ClientDiagnosisLimitDecisionTimeUnknown  = "flow_decision_time_not_recorded"
	ClientDiagnosisLimitDecisionReason       = "flow_decision_reason_not_recorded"
	ClientDiagnosisLimitFlowOutcomes         = "flow_outcomes_not_recorded"
	ClientDiagnosisLimitApplication          = "application_success_not_observable"
	ClientDiagnosisLimitProxyReturn          = "proxy_return_not_measured"
	ClientDiagnosisLimitEvidenceScope        = "route_cache_evidence_only"
	ClientDiagnosisLimitSessionEnd           = "session_end_not_distinguishable"
	ClientDiagnosisLimitDrops                = "drop_records_not_retained"
	ClientDiagnosisLimitIPv6                 = "ipv6_not_supported"
	ClientDiagnosisLimitEncryptedDNS         = "encrypted_dns_not_observed"
	ClientDiagnosisLimitSingleSnapshot       = "not_an_atomic_cross_subsystem_snapshot"
	ClientDiagnosisLimitSelectionChanged     = "selection_changed_during_read"
	ClientDiagnosisLimitFlowScanPartial      = "flow_scan_window_partial"
	ClientDiagnosisLimitIdentitySource       = "session_registry_unavailable"
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
	// EvidenceLimit bounds the retained-evidence page. Zero uses the default.
	EvidenceLimit int
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
	// EvidenceEntries is how many retained address decisions the session holds.
	// It is a count, never a listing: the picker must stay cheap.
	EvidenceEntries int `json:"evidence_entries"`
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
	// PolicyGeneration is the published policy generation the retained evidence
	// was compared against.
	PolicyGeneration string `json:"policy_generation,omitempty"`
}

// ClientDiagnosisCoverage states what was read and what was not.
type ClientDiagnosisCoverage struct {
	PolicyRoutingEnabled bool   `json:"policy_routing_enabled"`
	SampledAt            string `json:"sampled_at"`
	// EvidenceSource names the stores the answer was built from.
	EvidenceSource string `json:"evidence_source"`
	// NotCovered lists facts no router-side store retains today.
	NotCovered []string `json:"not_covered"`
	// NotRecorded lists facts this slice does not read from a store that will
	// carry them in a later slice.
	NotRecorded []string `json:"not_recorded"`
}

// ClientDiagnosisNamesMatch states whether the retained evidence names the
// destination. Slice 1 always answers ClientDiagnosisNamesNotRecorded: the cache
// keeps addresses, never names.
type ClientDiagnosisNamesMatch struct {
	Match  string `json:"match"`
	Reason string `json:"reason,omitempty"`
}

// ClientDiagnosisEntry is one retained address decision.
type ClientDiagnosisEntry struct {
	Address string `json:"address"`
	// Decision is the decision stored for the address: DIRECT or PROXY. It is
	// the decision the cache holds, not a re-evaluation of the current policy.
	Decision string `json:"decision"`
	// ObservedAt is the instant the stored observation was recorded. It is
	// omitted when the entry carries none, and AgeSeconds says why.
	ObservedAt       string `json:"observed_at,omitempty"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
	// AgeSeconds is elapsed time since ObservedAt, a pointer so a just-observed
	// entry reports 0 instead of being confused with "no age".
	AgeSeconds           *int64 `json:"age_seconds,omitempty"`
	AgeUnavailableReason string `json:"age_unavailable_reason,omitempty"`
	State                string `json:"state"`
	Generation           string `json:"generation,omitempty"`
	// Names and NamesMatch keep the slice-2 shape: an address the cache retained
	// cannot say which query produced it.
	Names      []string `json:"names"`
	NamesMatch string   `json:"names_match"`
}

// ClientDiagnosisDNS is the retained address-evidence section.
type ClientDiagnosisDNS struct {
	Available bool `json:"available"`
	// State is the view state: fresh, absent, quarantined, stale_generation or
	// retired.
	State            string `json:"state"`
	Generation       string `json:"generation,omitempty"`
	QuarantinedUntil string `json:"quarantined_until,omitempty"`
	// Names is this section's answer to "which name produced these addresses?".
	Names     ClientDiagnosisNamesMatch `json:"names"`
	Entries   []ClientDiagnosisEntry    `json:"entries"`
	Total     int                       `json:"total"`
	Truncated bool                      `json:"truncated"`
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
	// DecisionTime, DecisionReason and Names keep the later shape while stating
	// that this slice does not have them.
	DecisionTime   string   `json:"decision_time"`
	DecisionReason string   `json:"decision_reason"`
	Names          []string `json:"names"`
	NamesMatch     string   `json:"names_match"`
}

// ClientDiagnosisFlows is the live-flow section.
type ClientDiagnosisFlows struct {
	Available bool   `json:"available"`
	State     string `json:"state"`
	// Scanned is how many flow records the filtered scan visited, so the cost of
	// the answer is visible instead of promised.
	Scanned int `json:"scanned"`
	// ScanComplete reports that every flow record was visited, so Total is the
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
	DestinationIP   string `json:"destination_ip"`
	DestinationPort uint16 `json:"destination_port"`
	Reason          string `json:"reason"`
	Count           int64  `json:"count"`
	FirstSeen       string `json:"first_seen,omitempty"`
	LastSeen        string `json:"last_seen,omitempty"`
}

// ClientDiagnosisDrops is the drop section.
type ClientDiagnosisDrops struct {
	Available bool                  `json:"available"`
	State     string                `json:"state"`
	Total     int                   `json:"total"`
	Truncated bool                  `json:"truncated"`
	Entries   []ClientDiagnosisDrop `json:"entries"`
}

// ClientDiagnosisResponse is the operator-facing answer.
//
// The observed sections (DNS, Flows, Drops) carry router-recorded facts only.
// No policy evaluation is merged into them: a policy verdict for a destination is
// a prospective classification and belongs to the separate dry-run endpoint.
type ClientDiagnosisResponse struct {
	Selection   ClientDiagnosisSelection `json:"selection"`
	Coverage    ClientDiagnosisCoverage  `json:"coverage"`
	DNS         ClientDiagnosisDNS       `json:"dns"`
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
