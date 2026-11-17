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
	// DNS observation coverage gaps. They are facts about this build's
	// observation boundary, reported rather than implied by silence.
	ClientDiagnosisLimitDNSCoverage      = "dns_coverage_partial"
	ClientDiagnosisLimitDNSTransport     = "dns_transport_not_recorded"
	ClientDiagnosisLimitDNSFailures      = "dns_failures_not_recorded"
	ClientDiagnosisLimitDNSNonAQueries   = "non_a_queries_not_recorded"
	ClientDiagnosisLimitDNSReceiveTime   = "query_receive_time_not_recorded"
	ClientDiagnosisLimitDNSNoIncarnation = "records_without_route_generation"
	// Flow outcome gaps and the counter-sampling caveat.
	ClientDiagnosisLimitFlowBackendWrite    = "proxy_backend_write_not_attributed"
	ClientDiagnosisLimitFlowNonTCP          = "non_tcp_udp_flows_not_recorded"
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
	// EvidenceLimit bounds the retained-evidence page. Zero uses the default.
	EvidenceLimit int
	// DNSRecordLimit bounds the observed-answer history page. Zero uses the
	// collector's per-session default.
	DNSRecordLimit int
	// DNSEventLimit bounds the terminal-query history page. Zero uses the
	// collector's per-session default.
	DNSEventLimit int
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

// ClientDiagnosisDNSAddress is one address an observed answer wrote into the
// route cache, with the decision it wrote.
type ClientDiagnosisDNSAddress struct {
	Address  string `json:"address"`
	Decision string `json:"decision"`
}

// ClientDiagnosisDNSRecord is one client DNS answer the router actually observed.
//
// It is history, not the active route cache: the record survives its evidence
// expiring and is dropped only by age, capacity or session retirement. Fields this
// build's observation boundary cannot see are present with explicit tokens
// (transport, received_at) instead of being guessed.
type ClientDiagnosisDNSRecord struct {
	Seq                  uint64                      `json:"seq"`
	Name                 string                      `json:"name"`
	QType                string                      `json:"qtype"`
	RCode                string                      `json:"rcode"`
	Aliases              []string                    `json:"aliases"`
	Addresses            []ClientDiagnosisDNSAddress `json:"addresses"`
	ResolvedAddresses    int                         `json:"resolved_addresses"`
	ObservedAt           string                      `json:"observed_at"`
	ReceivedAt           string                      `json:"received_at"`
	Transport            string                      `json:"transport"`
	ExpiresAt            string                      `json:"expires_at"`
	ExpiresInSeconds     int64                       `json:"expires_in_seconds"`
	State                string                      `json:"state"`
	PolicyGeneration     string                      `json:"policy_generation,omitempty"`
	RouteGeneration      *uint64                     `json:"route_generation,omitempty"`
	IncarnationKnown     bool                        `json:"route_generation_established"`
	Classification       string                      `json:"classification"`
	ClassificationReason string                      `json:"classification_reason,omitempty"`
	CacheWrite           string                      `json:"cache_write"`
	Count                int                         `json:"count"`
	FirstSeen            string                      `json:"first_seen"`
	LastSeen             string                      `json:"last_seen"`
}

// ClientDiagnosisRecordLimits states the collector's bounds in force.
type ClientDiagnosisRecordLimits struct {
	RecordsPerSession  int   `json:"records_per_session"`
	RecordsTotal       int   `json:"records_total"`
	MaxAgeSeconds      int64 `json:"max_age_seconds"`
	BytesTotal         int   `json:"bytes_total"`
	NamesPerRecord     int   `json:"names_per_record"`
	AddressesPerRecord int   `json:"addresses_per_record"`
}

// ClientDiagnosisDNSRecordCoverage reports what the collector holds and what it
// could not observe.
type ClientDiagnosisDNSRecordCoverage struct {
	StartedAt          string                      `json:"started_at"`
	RecordsStored      int                         `json:"records_stored"`
	EstimatedBytes     int                         `json:"estimated_bytes"`
	Sessions           int                         `json:"sessions"`
	Written            int64                       `json:"written"`
	Collapsed          int64                       `json:"collapsed"`
	EvictedPerSession  int64                       `json:"evicted_per_session"`
	EvictedGlobal      int64                       `json:"evicted_global"`
	AgedOut            int64                       `json:"aged_out"`
	RejectedNoRoom     int64                       `json:"rejected_no_room"`
	WithoutIncarnation int64                       `json:"without_route_generation"`
	Limits             ClientDiagnosisRecordLimits `json:"limits"`
	// NotRecorded lists the observation gaps of this build, so a missing query
	// type or failure is stated instead of read as "nothing happened".
	NotRecorded []string `json:"not_recorded"`
}

// ClientDiagnosisDNSQueryEvent is one terminal client DNS query: an answer, a
// no-answer response, an error, a refusal, a truncated reply or a reply the client
// never received. It is diagnostic history and is never route evidence.
type ClientDiagnosisDNSQueryEvent struct {
	Seq           uint64 `json:"seq"`
	Name          string `json:"name"`
	QType         string `json:"qtype"`
	RCode         string `json:"rcode"`
	Kind          string `json:"kind"`
	Transport     string `json:"transport"`
	Delivered     bool   `json:"delivered"`
	Truncated     bool   `json:"truncated"`
	UpstreamError string `json:"upstream_error,omitempty"`
	ReceivedAt    string `json:"received_at"`
	AnsweredAt    string `json:"answered_at"`
	// RouteGeneration is the registered incarnation when the query arrived, when it
	// could be established.
	RouteGeneration  *uint64 `json:"route_generation,omitempty"`
	IncarnationKnown bool    `json:"route_generation_established"`
	PolicyGeneration string  `json:"policy_generation,omitempty"`
	Count            int     `json:"count"`
	FirstSeen        string  `json:"first_seen"`
	LastSeen         string  `json:"last_seen"`
}

// ClientDiagnosisDNSQueryEventCoverage reports the terminal-event store's counters.
type ClientDiagnosisDNSQueryEventCoverage struct {
	StartedAt         string                     `json:"started_at"`
	EventsStored      int                        `json:"events_stored"`
	EstimatedBytes    int                        `json:"estimated_bytes"`
	Written           int64                      `json:"written"`
	Collapsed         int64                      `json:"collapsed"`
	EvictedPerSession int64                      `json:"evicted_per_session"`
	EvictedGlobal     int64                      `json:"evicted_global"`
	AgedOut           int64                      `json:"aged_out"`
	RejectedNoRoom    int64                      `json:"rejected_no_room"`
	Limits            ClientDiagnosisEventLimits `json:"limits"`
	NotRecorded       []string                   `json:"not_recorded"`
}

// ClientDiagnosisEventLimits states the event store's bounds in force.
type ClientDiagnosisEventLimits struct {
	EventsPerSession int   `json:"events_per_session"`
	EventsTotal      int   `json:"events_total"`
	MaxAgeSeconds    int64 `json:"max_age_seconds"`
}

// ClientDiagnosisDNS is the DNS section: the retained address evidence (what the
// route cache holds right now) and the observed-answer history (what the router
// actually saw).
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
	// Records are the observed answers, newest first. RecordsAvailable reports
	// whether a collector was consulted at all.
	RecordsAvailable bool                             `json:"records_available"`
	Records          []ClientDiagnosisDNSRecord       `json:"records"`
	RecordsTotal     int                              `json:"records_total"`
	RecordsTruncated bool                             `json:"records_truncated"`
	RecordCoverage   ClientDiagnosisDNSRecordCoverage `json:"record_coverage"`
	// Events are the terminal client queries, newest first. They are a separate
	// store from the answers: a query that produced no usable answer still appears
	// here.
	EventsAvailable bool                                 `json:"events_available"`
	Events          []ClientDiagnosisDNSQueryEvent       `json:"events"`
	EventsTotal     int                                  `json:"events_total"`
	EventsTruncated bool                                 `json:"events_truncated"`
	EventCoverage   ClientDiagnosisDNSQueryEventCoverage `json:"event_coverage"`
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
	Matched   uint64 `json:"matched,omitempty"`
	Admitted  uint64 `json:"admitted,omitempty"`
	Dropped   uint64 `json:"dropped,omitempty"`
	Delivered uint64 `json:"delivered,omitempty"`
	Failed    uint64 `json:"failed,omitempty"`
	Failure   string `json:"failure,omitempty"`
}

// ClientDiagnosisFlowNameCandidate is one retained answer that named the flow's
// destination at the instant the flow was decided.
type ClientDiagnosisFlowNameCandidate struct {
	Name       string `json:"name"`
	Seq        uint64 `json:"dns_seq"`
	ObservedAt string `json:"observed_at"`
	ExpiresAt  string `json:"expires_at"`
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

	// Names is the correlated-name verdict for this destination. A matching
	// address alone is not a unique domain, so ambiguous and none are first-class
	// outcomes.
	Names           []string                           `json:"names"`
	NamesMatch      string                             `json:"names_match"`
	NamesReason     string                             `json:"names_reason,omitempty"`
	NamesConsidered int                                `json:"names_considered"`
	NameCandidates  []ClientDiagnosisFlowNameCandidate `json:"name_candidates"`
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
