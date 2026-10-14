package vpn

import (
	"fmt"
	"math"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
)

// Health status states for forwarder and dataplane.
const (
	HealthHealthy     = "HEALTHY"
	HealthDegraded    = "DEGRADED"
	HealthCritical    = "CRITICAL"
	HealthUnavailable = "UNAVAILABLE"
)

// HealthCondition describes an individual condition affecting dataplane health.
type HealthCondition struct {
	Category string `json:"category"` // e.g. "queue_pressure", "latency", "drops", "routing", "peer_sync", "backend"
	Severity string `json:"severity"` // "WARNING", "DEGRADED", "CRITICAL"
	Message  string `json:"message"`
	// MessageKey optionally names the canonical translation key for the
	// condition, so the web renderer can show a localized sentence instead of
	// the English server message. It is additive and omitempty: every
	// condition ever serialized before it existed still decodes byte-for-byte,
	// and a client that does not know the key falls back to Message. The
	// existing conditions predate it and deliberately do not set it —
	// retrofitting keys onto them is a separate, string-by-string decision.
	MessageKey string `json:"message_key,omitempty"`
}

// ActionableProblem describes an actionable, correlated problem affecting a specific
// connection, session, user, or route in the dataplane.
type ActionableProblem struct {
	Severity       string    `json:"severity"` // CRITICAL, DEGRADED, WARNING
	Category       string    `json:"category"` // routing, dataplane, etc.
	Message        string    `json:"message"`
	MessageKey     string    `json:"message_key,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	Username       string    `json:"username,omitempty"`
	SessionID      string    `json:"session_id,omitempty"`
	ConnectionID   string    `json:"connection_id,omitempty"`
	ConnectionName string    `json:"connection_name,omitempty"`
	AssignedIP     string    `json:"assigned_ip,omitempty"`
	BackendID      int64     `json:"backend_id,omitempty"`
	ObservedRate   string    `json:"observed_rate,omitempty"`
	FirstObserved  time.Time `json:"first_observed,omitempty"`
}

// ForwarderHealthAssessment contains the overall rule-based health diagnosis.
type ForwarderHealthAssessment struct {
	Status             string              `json:"status"` // HEALTHY, DEGRADED, CRITICAL, UNAVAILABLE
	Summary            string              `json:"summary"`
	SummaryKey         string              `json:"summary_key,omitempty"`
	Conditions         []HealthCondition   `json:"conditions"`
	ActionableProblems []ActionableProblem `json:"actionable_problems,omitempty"`
}

// TrafficRates tracks instantaneous throughput and moving averages.
type TrafficRates struct {
	Available   bool    `json:"available"`
	RxBps       float64 `json:"rx_bps"`
	TxBps       float64 `json:"tx_bps"`
	RxPps       float64 `json:"rx_pps"`
	TxPps       float64 `json:"tx_pps"`
	DropRatePps float64 `json:"drop_rate_pps"`
	RxBpsAvg5m  float64 `json:"rx_bps_avg_5m"`
	TxBpsAvg5m  float64 `json:"tx_bps_avg_5m"`
	RxBpsAvg1h  float64 `json:"rx_bps_avg_1h"`
	TxBpsAvg1h  float64 `json:"tx_bps_avg_1h"`
}

// QueuePressureDiagnostics contains queue occupancy and saturation duration.
//
// The four duration fields measure dwell from serialized managed queue
// transitions, rounded down to completed seconds. Status polling and traffic-rate
// throttling do not extend a run after a drain. Legacy direct channel drains have
// unknown timing and reset the unobserved run when reconciled.
type QueuePressureDiagnostics struct {
	Occupancy             int     `json:"occupancy"`
	Capacity              int     `json:"capacity"`
	UtilizationPct        float64 `json:"utilization_pct"`
	HighWaterPct          float64 `json:"high_water_pct"`
	TotalSecondsAbove50   int64   `json:"total_seconds_above_50"`
	TotalSecondsAbove80   int64   `json:"total_seconds_above_80"`
	ConsecutiveAbove50Sec int64   `json:"consecutive_above_50_sec"`
	ConsecutiveAbove80Sec int64   `json:"consecutive_above_80_sec"`
	QueueFullDrops        uint64  `json:"queue_full_drops"`
	QueueDropRatePps      float64 `json:"queue_drop_rate_pps"`
}

// ForwardLatencyDiagnostics tracks forward write durations and in-flight operations.
//
// P50MS/P95MS/P99MS are DESCRIPTIVE percentiles over the last 1024 completed
// writes; they do not expire and an operator can still read the historical
// distribution there. The HEALTH decision uses P95HealthMS instead, the p95 over
// writes completed inside P95HealthWindowSec, together with P95HealthSamples,
// the number of writes that window contains. P95HealthSamples == 0 means no
// recent write was observed (an idle server), so latency is UNKNOWN and must not
// degrade health on history alone (issue #424 round 8, finding 4).
type ForwardLatencyDiagnostics struct {
	P50MS             float64 `json:"p50_ms"`
	P95MS             float64 `json:"p95_ms"`
	P99MS             float64 `json:"p99_ms"`
	MaxMS             int64   `json:"max_ms"`
	InFlight          int     `json:"in_flight"`
	OldestInFlightMS  int64   `json:"oldest_in_flight_ms"`
	StallsRecent      uint64  `json:"stalls_recent"`
	StallsWindowSec   float64 `json:"stalls_window_sec"`
	Stalls            uint64  `json:"stalls"`
	WriteErrors       uint64  `json:"write_errors"`
	WriteTotal        uint64  `json:"write_total"`
	WriteErrorRatePps float64 `json:"write_error_rate_pps"`

	P95HealthMS        float64 `json:"p95_health_ms"`
	P95HealthSamples   int     `json:"p95_health_samples"`
	P95HealthWindowSec int64   `json:"p95_health_window_sec"`
}

// DropCategoryBreakdown separates drops by specific root cause without double counting.
type DropCategoryBreakdown struct {
	// Client -> Backend (Ingress to forwarder)
	ClientMalformed        uint64 `json:"client_malformed"`
	ClientUnmappedSource   uint64 `json:"client_unmapped_source"`
	ClientMismatch         uint64 `json:"client_mismatch"`
	ClientRejected         uint64 `json:"client_rejected"`
	ClientBackendQueueFull uint64 `json:"client_backend_queue_full"`
	ClientRateLimited      uint64 `json:"client_rate_limited"`
	ClientNoHealthyBackend uint64 `json:"client_no_healthy_backend"`
	// ClientVirtualTUNDrops counts packets the upstream AWG engine handed to
	// the VirtualTUN outbound queue (Upstream -> Nexus) that never reached
	// Nexus. They belong to the client-side bucket: the upstream device is
	// the egress of the client-originated direction, so a drop there loses
	// client traffic rather than a return reply.
	ClientVirtualTUNDrops        uint64 `json:"client_virtualtun_drops"`
	ClientBackendDeviceQueueFull uint64 `json:"client_backend_device_queue_full"`
	// The backend-device reasons below are the direction x reason breakdown of
	// live backend devices' VirtualTUNs (issue #424 round 3, finding 1).
	// Inbound loss is client-originating traffic, so it belongs here; outbound
	// loss is return traffic and is counted in the return population.
	//
	// ClientBackendDeviceQueueFull is a QUEUE-FULL reason only, never a
	// direction- and reason-agnostic total: before this change it carried
	// VirtualTUN.DroppedPackets(), which spans both directions and all three
	// reasons, so return traffic was reported as client-to-backend queue-full
	// loss and shutdown drains were reported as queue-full loss.
	ClientBackendDeviceOversized uint64 `json:"client_backend_device_oversized"`
	// ClientBackendDeviceShutdown is inbound loss drained and discarded when
	// the device's VirtualTUN was closed.
	ClientBackendDeviceShutdown uint64 `json:"client_backend_device_shutdown"`
	// ClientBackendDeviceExternal is loss an EXTERNAL owner recorded through
	// VirtualTUN.RecordDrop/RecordDropN. The recording API carries no
	// direction and no reason, so these drops are attributed here under their
	// own key rather than spread across buckets the recorder never filled.
	ClientBackendDeviceExternal uint64 `json:"client_backend_device_external"`
	// BackendDeviceUnattributed is lifetime loss on a device that cannot
	// report the breakdown at all. It is DIRECTION-NEUTRAL (issue #429
	// review round 3, blocker 3): it counts toward TotalDrops so the total
	// stays truthful instead of silently shrinking, but toward NEITHER
	// directional total — the device reports no direction, so publishing it
	// under the client key asserted a direction the implementation says is
	// unavailable.
	BackendDeviceUnattributed uint64 `json:"backend_device_unattributed"`

	ClientTotalDrops  uint64  `json:"client_total_drops"`
	ClientDropRatePps float64 `json:"client_drop_rate_pps"`

	// Backend -> Client (Return path)
	ReturnMalformed       uint64 `json:"return_malformed"`
	ReturnUnmapped        uint64 `json:"return_unmapped"`
	ReturnMismatch        uint64 `json:"return_mismatch"`
	ReturnInjectionErrors uint64 `json:"return_injection_errors"`
	ReturnVirtualTUNDrops uint64 `json:"return_virtualtun_drops"`
	// ReturnInjectionTUNDrops is the subset of injection rejections whose
	// loss the VirtualTUN inbound bucket already counted (issue #424 round 2,
	// finding 3). Additive key: it makes the ownership overlap explicit
	// instead of inferred by subtracting aggregate counters.
	ReturnInjectionTUNDrops uint64 `json:"return_injection_tun_drops"`
	ReturnQueueFull         uint64 `json:"return_queue_full"`
	ReturnPacketTooLarge    uint64 `json:"return_packet_too_large"`
	// ReturnBackendDeviceQueueFull and ReturnBackendDeviceShutdown are the
	// return-direction half of the backend-device breakdown: outbound
	// VirtualTUN loss on a backend device, i.e. backend -> Nexus return
	// traffic that never reached the client. They are disjoint from
	// ReturnQueueFull, which is the forwarder's own return-queue refusal.
	// ReturnBackendDeviceQueueFull is outbound VirtualTUN loss to a full
	// outbound queue on a backend device, i.e. return traffic that never
	// reached the client. It carries retired and live loss alike: retirement
	// transfers a loss into this key rather than moving it to another one.
	ReturnBackendDeviceQueueFull uint64 `json:"return_backend_device_queue_full"`
	// ReturnBackendDeviceShutdown is the return-direction half of backend
	// device loss: outbound VirtualTUN loss drained and discarded when the
	// device was closed.
	ReturnBackendDeviceShutdown uint64  `json:"return_backend_device_shutdown"`
	ReturnTotalDrops            uint64  `json:"return_total_drops"`
	ReturnDropRatePps           float64 `json:"return_drop_rate_pps"`

	// Total aggregate drops
	TotalDrops       uint64             `json:"total_drops"`
	TotalDropRatePps float64            `json:"total_drop_rate_pps"`
	ReasonRates      map[string]float64 `json:"reason_rates"`
	RatesAvailable   bool               `json:"rates_available"`
}

// VirtualTUNDirectionalHealth captures directional queue state for VirtualTUN.
type VirtualTUNDirectionalHealth struct {
	Occupancy int    `json:"occupancy"`
	Capacity  int    `json:"capacity"`
	Peak      int    `json:"peak"`
	Drops     uint64 `json:"drops"`
}

// VirtualTUNDiagnostics tracks upstream and downstream VirtualTUN health.
type VirtualTUNDiagnostics struct {
	UpstreamToNexus VirtualTUNDirectionalHealth `json:"upstream_to_nexus"`
	NexusToUpstream VirtualTUNDirectionalHealth `json:"nexus_to_upstream"`
}

// RoutingConsistencyDiagnostics audits routing invariants across sessions and routes.
type RoutingConsistencyDiagnostics struct {
	ActiveSessionsCount    int      `json:"active_sessions_count"`
	ActiveRoutesCount      int      `json:"active_routes_count"`
	ReturnOwnersCount      int      `json:"return_owners_count"`
	SessionsWithoutRoute   []string `json:"sessions_without_route"`
	RoutesWithoutSession   []string `json:"routes_without_session"`
	RoutesWithoutReturn    []string `json:"routes_without_return"`
	DuplicateIPs           []string `json:"duplicate_ips"`
	OwnershipMismatchDrops uint64   `json:"ownership_mismatch_drops"`
	// ClientOwnershipMismatchDrops is the CLIENT-direction (client -> backend)
	// ownership-mismatch counter, the same loss the diagnostics surface already
	// publishes as DropCategoryBreakdown.ClientMismatch and in history. It was
	// counted but never wired into routing health, so a client-direction
	// mismatch was invisible to the headline (issue #424 review round 9,
	// blocker 3). OwnershipMismatchDrops remains the RETURN-direction counter.
	//
	// The two are disjoint populations: a client-direction mismatch is refused
	// at router admission before the forwarder ever sees the packet, and a
	// return-direction mismatch is refused when a backend reply arrives for a
	// backend the route does not own. No packet is refused for an ownership
	// mismatch twice, so summing them counts no loss twice.
	ClientOwnershipMismatchDrops uint64 `json:"client_ownership_mismatch_drops"`
	// OwnershipMismatchDropsRecent is the increase of OwnershipMismatchDrops
	// observed in the last diagnostics sampling window (issue #424 round 2,
	// finding 5). The cumulative value stays exposed as history; only the
	// recent delta gates current health, so a recovered incident no longer
	// pins routing as inconsistent forever.
	OwnershipMismatchDropsRecent uint64 `json:"ownership_mismatch_drops_recent"`
	// ClientOwnershipMismatchDropsRecent is the increase of
	// ClientOwnershipMismatchDrops over the same sampling window. It is a
	// sibling of OwnershipMismatchDropsRecent, not a replacement: the two
	// directions are evaluated independently and both must be non-zero for the
	// routing condition to name both.
	ClientOwnershipMismatchDropsRecent uint64 `json:"client_ownership_mismatch_drops_recent"`
	// OwnershipMismatchWindowSec is the length of the sampling window behind
	// OwnershipMismatchDropsRecent.
	OwnershipMismatchWindowSec float64 `json:"ownership_mismatch_window_sec"`
	// ReturnOwnershipMismatchWindowSec is the length of the sampling window specific
	// to the return-direction ownership mismatch counter (issue #457).
	ReturnOwnershipMismatchWindowSec float64 `json:"return_ownership_mismatch_window_sec,omitempty"`
	// ClientOwnershipMismatchWindowSec is the length of the sampling window specific
	// to the client-direction ownership mismatch counter (issue #457).
	ClientOwnershipMismatchWindowSec float64 `json:"client_ownership_mismatch_window_sec,omitempty"`
	// ReturnOwnershipMismatchConsecutiveHighRateWindows tracks the number of consecutive
	// sampling windows in which the return-direction ownership mismatch drop rate met or
	// exceeded ReturnOwnershipMismatchDegradedRatePPS (issue #457).
	ReturnOwnershipMismatchConsecutiveHighRateWindows int      `json:"return_ownership_mismatch_consecutive_high_rate_windows,omitempty"`
	IsConsistent                                      bool     `json:"is_consistent"`
	InconsistencyDetails                              []string `json:"inconsistency_details,omitempty"`
	// HistoricalDetails carries lifetime observations that are deliberately
	// NOT inconsistencies, so a reader can see the incident without the
	// headline status being pinned by it.
	HistoricalDetails []string `json:"historical_details,omitempty"`
}

// OwnershipMismatchRecentTotal is the number of ownership mismatches observed
// in the current sampling window across BOTH directions. It is the sum of two
// disjoint populations (see ClientOwnershipMismatchDrops), so it counts each
// refused packet exactly once.
//
// It is used across the routing diagnostics and rate calculation to represent
// total ownership mismatches across both directions. Each direction is still
// reported separately in the routing condition and in the JSON payload; this is
// the sum across both directions, and it is never used to attribute a loss to a
// direction.
func (d RoutingConsistencyDiagnostics) OwnershipMismatchRecentTotal() uint64 {
	return d.OwnershipMismatchDropsRecent + d.ClientOwnershipMismatchDropsRecent
}

// OwnershipMismatchRatePPS is the current-window ownership-mismatch rate the
// ROUTING population contributes to the dataplane drop rate, over the whole
// window rather than per-direction.
//
// It is what the aggregate drop-rate condition subtracts, so that a loss
// reported by the routing condition is never also counted by the routine
// drop-rate condition. Deriving it from the windowed deltas rather than from
// ReasonRates keeps the subtraction and the condition reading the SAME
// measurement: routing and the drop breakdown are sampled from the same
// cumulative counters in the same status assembly, and a delta that has gone
// quiet reports zero in both.
//
// A zero or unmeasured window contributes zero. OwnershipMismatchWindowSec is
// zero only on the priming sample, which also reports a zero delta, so the
// division is unreachable with a non-zero numerator.
func (d RoutingConsistencyDiagnostics) OwnershipMismatchRatePPS() float64 {
	if d.OwnershipMismatchWindowSec <= 0 {
		return 0
	}
	return float64(d.OwnershipMismatchRecentTotal()) / d.OwnershipMismatchWindowSec
}

// ReturnOwnershipMismatchRatePPS computes the packet drop rate per second
// specific to the return-direction ownership mismatch counter using its own
// sampling window (issue #457). If ReturnOwnershipMismatchWindowSec is unset,
// it falls back to using OwnershipMismatchWindowSec with return-direction drops.
func (d RoutingConsistencyDiagnostics) ReturnOwnershipMismatchRatePPS() float64 {
	if d.ReturnOwnershipMismatchWindowSec > 0 {
		return float64(d.OwnershipMismatchDropsRecent) / d.ReturnOwnershipMismatchWindowSec
	}
	if d.OwnershipMismatchWindowSec > 0 {
		return float64(d.OwnershipMismatchDropsRecent) / d.OwnershipMismatchWindowSec
	}
	return 0
}

// ClientOwnershipMismatchRatePPS computes the packet drop rate per second
// specific to the client-direction ownership mismatch counter using its own
// sampling window (issue #457). If ClientOwnershipMismatchWindowSec is unset,
// it falls back to using OwnershipMismatchWindowSec.
func (d RoutingConsistencyDiagnostics) ClientOwnershipMismatchRatePPS() float64 {
	if d.ClientOwnershipMismatchWindowSec > 0 {
		return float64(d.ClientOwnershipMismatchDropsRecent) / d.ClientOwnershipMismatchWindowSec
	}
	if d.OwnershipMismatchWindowSec > 0 {
		return float64(d.ClientOwnershipMismatchDropsRecent) / d.OwnershipMismatchWindowSec
	}
	return 0
}

// DirectionalOwnershipMismatchRatePPS computes the sum of directional ownership
// mismatch drop rates per second using each direction's own sampling window
// (issue #457). This prevents dilution of return-direction drops when the client
// window is longer and quiet, and preserves compatibility if directional windows
// are unset.
func (d RoutingConsistencyDiagnostics) DirectionalOwnershipMismatchRatePPS() float64 {
	if d.ReturnOwnershipMismatchWindowSec > 0 || d.ClientOwnershipMismatchWindowSec > 0 {
		return d.ReturnOwnershipMismatchRatePPS() + d.ClientOwnershipMismatchRatePPS()
	}
	return d.OwnershipMismatchRatePPS()
}

// HandshakeFreshnessDiagnostics aggregates peer handshake distribution.
type HandshakeFreshnessDiagnostics struct {
	Under2mCount      int                  `json:"under_2m_count"`
	Between2m5mCount  int                  `json:"between_2m_5m_count"`
	Over5mCount       int                  `json:"over_5m_count"`
	NeverCount        int                  `json:"never_count"`
	TotalPeers        int                  `json:"total_peers"`
	StaleLiveSessions []string             `json:"stale_live_sessions,omitempty"`
	PeerHandshakes    map[string]time.Time `json:"-"`
}

// BackendTelemetryItem captures per-backend operational metrics.
type BackendTelemetryItem struct {
	Enabled             bool    `json:"enabled"`
	Routable            bool    `json:"routable"`
	TrafficAvailable    bool    `json:"traffic_available"`
	TrafficWindowSec    float64 `json:"traffic_window_sec"`
	RxBytesPerSec       float64 `json:"rx_bytes_per_sec"`
	TxBytesPerSec       float64 `json:"tx_bytes_per_sec"`
	RxPps               float64 `json:"rx_pps"`
	TxPps               float64 `json:"tx_pps"`
	RxPackets           uint64  `json:"rx_packets"`
	TxPackets           uint64  `json:"tx_packets"`
	ID                  int64   `json:"id"`
	ServerID            int64   `json:"server_id"`
	ServerName          string  `json:"server_name"`
	HealthState         string  `json:"health_state"`
	ProbeLatencyMS      int64   `json:"probe_latency_ms"`
	ActiveSessions      int     `json:"active_sessions"`
	RxBytes             int64   `json:"rx_bytes"`
	TxBytes             int64   `json:"tx_bytes"`
	DeviceDrops         uint64  `json:"device_drops"`
	LastHandshakeAgeSec int64   `json:"last_handshake_age_sec"`
	LoadSharePct        float64 `json:"load_share_pct"`
}

// BackendsDiagnostics provides an aggregate summary and itemized backend list.
type BackendsDiagnostics struct {
	// EligibilityKnown distinguishes current enabled/routable inventory from legacy callers.
	EligibilityKnown bool                   `json:"eligibility_known"`
	EnabledCount     int                    `json:"enabled_count"`
	DisabledCount    int                    `json:"disabled_count"`
	LatencySamples   int                    `json:"latency_samples"`
	HealthyCount     int                    `json:"healthy_count"`
	TotalCount       int                    `json:"total_count"`
	LatencyP95MS     float64                `json:"latency_p95_ms"`
	LoadSkewPct      float64                `json:"load_skew_pct"`
	TotalDrops       uint64                 `json:"total_drops"`
	Backends         []BackendTelemetryItem `json:"backends"`
}

// RouteReservoirItem holds write latency reservoir stats for drilldown telemetry.
type RouteReservoirItem struct {
	P95MS   float64 `json:"p95_ms"`
	Samples int     `json:"samples"`
	MaxMS   float64 `json:"max_ms"`
}

// ProblemRouteItem represents per-route diagnostics.
type ProblemRouteItem struct {
	SessionID            string                    `json:"session_id,omitempty"`
	ConnectionID         string                    `json:"connection_id,omitempty"`
	UtilizationPct       float64                   `json:"utilization_pct"`
	HighWaterPct         float64                   `json:"high_water_pct"`
	WriteCount           uint64                    `json:"write_count"`
	WriteErrors          uint64                    `json:"write_errors"`
	WriteStalls          uint64                    `json:"write_stalls"`
	WritesInFlight       int                       `json:"writes_in_flight"`
	OldestWriteMS        int64                     `json:"oldest_write_ms"`
	MaxWriteMS           int64                     `json:"max_write_ms"`
	P95WriteSamples      int                       `json:"p95_write_samples"`
	QueueFullDropsRecent uint64                    `json:"queue_full_drops_recent"`
	QueueFullDropRatePPS float64                   `json:"queue_full_drop_rate_pps"`
	WriteErrorsRecent    uint64                    `json:"write_errors_recent"`
	WriteStallsRecent    uint64                    `json:"write_stalls_recent"`
	Traffic              forwarder.TrafficSnapshot `json:"traffic"`
	SessionAgeSec        int64                     `json:"session_age_sec"`
	LastTrafficAgeSec    int64                     `json:"last_traffic_age_sec"`
	PeerKey              string                    `json:"peer_key"`
	AssignedIP           string                    `json:"assigned_ip"`
	BackendID            int64                     `json:"backend_id"`
	Occupancy            int                       `json:"occupancy"`
	Capacity             int                       `json:"capacity"`
	HighWater            int                       `json:"high_water"`
	Drops                uint64                    `json:"drops"`
	P95WriteMS           float64                   `json:"p95_write_ms"`
	QueueDwellP95MS      float64                   `json:"queue_dwell_p95_ms,omitempty"`
	Reservoir            *RouteReservoirItem       `json:"reservoir,omitempty"`
	HasPressure          bool                      `json:"has_pressure"`
	PressureNote         string                    `json:"pressure_note,omitempty"`
}

// RuntimeResources contains process and runtime health counters.
type RuntimeResources struct {
	CPUPercent           float64 `json:"cpu_percent"`
	MemoryAllocBytes     uint64  `json:"memory_alloc_bytes"`
	MemorySysBytes       uint64  `json:"memory_sys_bytes"`
	MemoryLimitBytes     uint64  `json:"memory_limit_bytes"`
	MemoryLimitAvailable bool    `json:"memory_limit_available"`
	MemoryUsagePct       float64 `json:"memory_usage_pct"`
	Goroutines           int     `json:"goroutines"`
	GCPauseP95MS         float64 `json:"gc_pause_p95_ms"`
	OpenFileDesc         int     `json:"open_file_desc"`
	MaxFileDesc          uint64  `json:"max_file_desc"`
}

// HistoryPoint is a single time-series sample for dashboard graphs.
// ForwardP95Samples == 0 marks unavailable current latency; ForwardP95MS alone
// cannot distinguish an idle window from a measured zero-duration write.
type HistoryPoint struct {
	RxPps                 float64               `json:"rx_pps"`
	TxPps                 float64               `json:"tx_pps"`
	TrafficAvailable      bool                  `json:"traffic_available"`
	DropRatesAvailable    bool                  `json:"drop_rates_available"`
	DropReasonRates       map[string]float64    `json:"drop_reason_rates"`
	ActiveRoutes          int                   `json:"routes"`
	BackendLatencySamples int                   `json:"be_latency_samples"`
	Backends              []BackendHistoryPoint `json:"backends"`
	BackendsOmitted       int                   `json:"backends_omitted"`
	Timestamp             int64                 `json:"t"`
	RxBps                 float64               `json:"rx_bps"`
	TxBps                 float64               `json:"tx_bps"`
	QueueUtilPct          float64               `json:"q_pct"`
	TotalDropRate         float64               `json:"drop_rate"`
	ForwardP95Samples     int                   `json:"fwd_p95_samples"`
	ForwardP95MS          float64               `json:"fwd_p95_ms"`
	ActiveSessions        int                   `json:"sessions"`
	BackendP95MS          float64               `json:"be_p95_ms"`
}

// HistoricalSeries contains rolling time-series samples across 6 windows.
type HistoricalSeries struct {
	Window1m  []HistoryPoint `json:"window_1m"`
	Window5m  []HistoryPoint `json:"window_5m"`
	Window15m []HistoryPoint `json:"window_15m"`
	Window1h  []HistoryPoint `json:"window_1h"`
	Window6h  []HistoryPoint `json:"window_6h"`
	Window24h []HistoryPoint `json:"window_24h"`
}

// maxDiagnosticErrorTextLen bounds an upstream error string embedded in a
// health message. A peer sync failure joins every reconciliation error, so
// unbounded text would make the condition message (and the API payload that
// carries it) arbitrarily large.
const maxDiagnosticErrorTextLen = 200

// clampDiagnosticText bounds s to max runes, appending an ellipsis marker when
// anything was removed. It is rune-aware so a multi-byte error string cannot be
// cut mid-rune.
func clampDiagnosticText(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}

// describeLastSuccessfulReconcile renders the reconcile timestamp for a health
// message. The zero value means no reconcile has ever succeeded, which is
// materially different from a stale one and must not be printed as a year 1 date.
func describeLastSuccessfulReconcile(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// collectProblemRoutes converts forwarder RouteInfo slices into ProblemRouteItem diagnostics.
func collectProblemRoutes(routes []forwarder.RouteInfo) []ProblemRouteItem {
	items := make([]ProblemRouteItem, len(routes))
	for i, r := range routes {
		var note string
		if r.HasPressure {
			switch {
			case r.Stats.QueueFullDropsRecent > 0:
				note = fmt.Sprintf("Recent queue drops: %d", r.Stats.QueueFullDropsRecent)
			case r.Stats.Capacity > 0 && float64(r.Stats.Occupancy)/float64(r.Stats.Capacity) >= thresholds.RoutePressureUtilization():
				note = fmt.Sprintf("Queue pressure: %d/%d queued", r.Stats.Occupancy, r.Stats.Capacity)
			case r.Stats.WriteErrorsRecent > 0:
				note = fmt.Sprintf("Recent write errors: %d", r.Stats.WriteErrorsRecent)
			case r.Stats.WriteStallsRecent > 0:
				note = fmt.Sprintf("Recent write stalls: %d", r.Stats.WriteStallsRecent)
			case r.Stats.OldestWriteMS >= forwarder.DeviceWriteStallThreshold.Milliseconds():
				note = fmt.Sprintf("Write in flight: %dms", r.Stats.OldestWriteMS)
			}
		}

		var utilization, highWaterPct float64
		if r.Stats.Capacity > 0 {
			utilization = float64(r.Stats.Occupancy) / float64(r.Stats.Capacity) * 100
			highWaterPct = float64(r.Stats.HighWater) / float64(r.Stats.Capacity) * 100
		}
		var reservoir *RouteReservoirItem
		if r.Stats.P95WriteSamples > 0 || r.Stats.MaxWriteDurationMS > 0 || r.Stats.P95WriteMS > 0 {
			reservoir = &RouteReservoirItem{
				P95MS:   float64(r.Stats.P95WriteMS),
				Samples: r.Stats.P95WriteSamples,
				MaxMS:   float64(r.Stats.MaxWriteDurationMS),
			}
		}
		dropRatePPS := r.Stats.QueueFullDropRatePPS
		items[i] = ProblemRouteItem{
			SessionID:            r.SessionID,
			ConnectionID:         r.ConnectionID,
			Reservoir:            reservoir,
			UtilizationPct:       utilization,
			HighWaterPct:         highWaterPct,
			WriteCount:           r.Stats.WriteCount,
			WriteErrors:          r.Stats.WriteErrors,
			WriteStalls:          r.Stats.WriteStalls,
			WritesInFlight:       r.Stats.WritesInFlight,
			OldestWriteMS:        r.Stats.OldestWriteMS,
			MaxWriteMS:           r.Stats.MaxWriteDurationMS,
			P95WriteSamples:      r.Stats.P95WriteSamples,
			QueueFullDropsRecent: r.Stats.QueueFullDropsRecent,
			QueueFullDropRatePPS: dropRatePPS,
			WriteErrorsRecent:    r.Stats.WriteErrorsRecent,
			WriteStallsRecent:    r.Stats.WriteStallsRecent,
			Traffic:              r.Traffic,
			SessionAgeSec:        r.SessionAgeSec,
			LastTrafficAgeSec:    r.LastTrafficAgeSec,
			// Redacted at the API boundary, not in the UI (issue #424 round 4,
			// item E). The JSON payload IS the disclosure surface: a raw peer
			// public key shipped to a browser, a log shipper or a support
			// bundle is already disclosed even if every template masks it. The
			// value uses ingress.RedactKey, the redaction convention the rest of
			// the system already uses for peer keys, so the diagnostics surface
			// renders keys identically to ingress errors and counters. The key
			// name, presence and non-emptiness are unchanged: an admin still
			// sees a stable per-route identifier.
			PeerKey:      ingress.RedactKey(r.PeerKey),
			AssignedIP:   r.AssignedIP,
			BackendID:    r.BackendTunnelID,
			Occupancy:    r.Stats.Occupancy,
			Capacity:     r.Stats.Capacity,
			HighWater:    r.Stats.HighWater,
			Drops:        r.Stats.QueueFullDrops,
			P95WriteMS:   float64(r.Stats.P95WriteMS),
			HasPressure:  r.HasPressure,
			PressureNote: note,
		}
	}
	return items
}

func (s *Service) collectDropCategories() DropCategoryBreakdown {
	return s.captureDiagnosticsInputs().collectDropCategories()
}

func (inputs diagnosticsInputs) collectDropCategories() DropCategoryBreakdown {
	losses := addIngressLosses(inputs.retiredIngressLosses, engineLossTotals(inputs.ingressEngine))
	routerMalformed := losses.router.MalformedPacketDrops
	routerUnmapped := losses.router.UnmappedSourceIPDrops
	routerMismatch := losses.router.OwnershipMismatchDrops
	routerNoBackend := losses.router.NoActiveBackendDrops
	routerRejected := losses.router.AdmissionRejectedDrops - routerNoBackend + losses.router.RouteRegistrationErrors
	var fwdClientQueueFull, fwdClientRateLimited, fwdClientNoBackend uint64
	if inputs.forwarder != nil {
		fwdClientQueueFull, fwdClientRateLimited, fwdClientNoBackend, _ = inputs.forwarder.ClientDropStats()
	}

	retStats := losses.returns
	// Use live engine queue gauges; retained state contains counters only.
	if inputs.ingressEngine != nil {
		current := inputs.ingressEngine.ReturnStats().TUN
		current.InboundDrops = retStats.TUN.InboundDrops
		current.OutboundDrops = retStats.TUN.OutboundDrops
		retStats.TUN = current
	}

	// Backend-device VirtualTUN loss is attributed per direction AND per reason
	// (issue #424 round 3, finding 1). Inbound loss is client-originating
	// traffic that never reached the backend; outbound loss is backend->Nexus
	// RETURN traffic that never reached the client. Neither is a whole-tunnel
	// total, so nothing here can overlap forwarder admission or backend-queue
	// refusal, which own their own reasons above.
	deviceDrops := inputs.collectBackendDeviceDropStats()
	var returnQueueFull, returnOversized uint64
	if inputs.forwarder != nil {
		returnQueueFull = inputs.forwarder.DropsQueueFull()
		returnOversized = inputs.forwarder.DropsPacketTooLarge()
	}
	fwdClientNoBackend += routerNoBackend

	// Upstream -> Nexus: VirtualTUN.Write feeds the OUTBOUND queue. The upstream
	// AWG engine emits authenticated plaintext it received from the client, so
	// an outbound drop is lost client traffic and belongs in the client bucket
	// (issue #424 round 2, finding 2).
	clientVirtualTUNDrops := retStats.TUN.OutboundDrops
	clientTotal := routerMalformed +
		routerUnmapped +
		routerMismatch +
		routerRejected +
		fwdClientQueueFull +
		fwdClientRateLimited +
		fwdClientNoBackend +
		clientVirtualTUNDrops +
		deviceDrops.ClientQueueFull +
		deviceDrops.ClientOversized +
		deviceDrops.ClientShutdown +
		deviceDrops.ClientExternal

	// Nexus -> Upstream: VirtualTUN.InjectInbound feeds the INBOUND queue, so
	// its drop bucket is the return path's own loss accounting.
	returnTunDrops := retStats.TUN.InboundDrops

	// The overlap between injection errors and inbound VirtualTUN drops is
	// owned by the injection site (returnCounters.injectionTunDrops), not
	// inferred here. InboundDrops also rises on oversized reads and on
	// shutdown drain with no injection error at all, so subtracting the
	// aggregate masked real non-TUN injection failures (issue #424 round 2,
	// finding 3).
	nonTunInjectionErrors := uint64(0)
	if retStats.InjectionErrors > retStats.InjectionTunDrops {
		nonTunInjectionErrors = retStats.InjectionErrors - retStats.InjectionTunDrops
	}
	returnTotal := retStats.MalformedDrops +
		retStats.UnmappedDrops +
		retStats.OwnershipMismatchDrops +
		nonTunInjectionErrors +
		returnTunDrops + returnQueueFull + returnOversized +
		deviceDrops.ReturnQueueFull + deviceDrops.ReturnShutdown

	// The direction-neutral backend-device population is real measured loss,
	// so loss conservation keeps it in the total; it belongs to NEITHER
	// directional total because its device reports no direction (issue #429
	// review round 3, blocker 3).
	totalDrops := clientTotal + returnTotal + deviceDrops.Unattributed

	return DropCategoryBreakdown{
		ClientMalformed:              routerMalformed,
		ClientUnmappedSource:         routerUnmapped,
		ClientMismatch:               routerMismatch,
		ClientRejected:               routerRejected,
		ClientBackendQueueFull:       fwdClientQueueFull,
		ClientRateLimited:            fwdClientRateLimited,
		ClientNoHealthyBackend:       fwdClientNoBackend,
		ClientVirtualTUNDrops:        clientVirtualTUNDrops,
		ClientBackendDeviceQueueFull: deviceDrops.ClientQueueFull,
		ClientBackendDeviceOversized: deviceDrops.ClientOversized,
		ClientBackendDeviceShutdown:  deviceDrops.ClientShutdown,
		ClientBackendDeviceExternal:  deviceDrops.ClientExternal,
		BackendDeviceUnattributed:    deviceDrops.Unattributed,
		ClientTotalDrops:             clientTotal,

		ReturnMalformed:         retStats.MalformedDrops,
		ReturnUnmapped:          retStats.UnmappedDrops,
		ReturnMismatch:          retStats.OwnershipMismatchDrops,
		ReturnInjectionErrors:   nonTunInjectionErrors,
		ReturnVirtualTUNDrops:   returnTunDrops,
		ReturnInjectionTUNDrops: retStats.InjectionTunDrops,
		ReturnTotalDrops:        returnTotal,
		ReturnQueueFull:         returnQueueFull,
		ReturnPacketTooLarge:    returnOversized,

		ReturnBackendDeviceQueueFull: deviceDrops.ReturnQueueFull,
		ReturnBackendDeviceShutdown:  deviceDrops.ReturnShutdown,

		TotalDrops: totalDrops,
	}
}

func (inputs diagnosticsInputs) collectVirtualTUNDiagnostics() VirtualTUNDiagnostics {
	losses := addIngressLosses(inputs.retiredIngressLosses, engineLossTotals(inputs.ingressEngine))
	retStats := losses.returns
	if inputs.ingressEngine != nil {
		current := inputs.ingressEngine.ReturnStats().TUN
		current.InboundDrops = retStats.TUN.InboundDrops
		current.OutboundDrops = retStats.TUN.OutboundDrops
		retStats.TUN = current
	}
	return VirtualTUNDiagnostics{
		UpstreamToNexus: VirtualTUNDirectionalHealth{
			Occupancy: retStats.TUN.OutboundDepth,
			Capacity:  retStats.TUN.OutboundCapacity,
			Peak:      retStats.TUN.OutboundPeak,
			Drops:     retStats.TUN.OutboundDrops,
		},
		NexusToUpstream: VirtualTUNDirectionalHealth{
			Occupancy: retStats.TUN.InboundDepth,
			Capacity:  retStats.TUN.InboundCapacity,
			Peak:      retStats.TUN.InboundPeak,
			Drops:     retStats.TUN.InboundDrops,
		},
	}
}

func (s *Service) populateOperationalDiagnostics(status *Status) {
	s.mu.RLock()
	inputs := s.diagnosticsInputsLocked()
	var routes []forwarder.RouteInfo
	if inputs.forwarder != nil {
		routes = inputs.forwarder.InspectRoutes()
	}
	s.mu.RUnlock()
	s.populateOperationalDiagnosticsFromInputs(status, routes, inputs)
}

// populateOperationalDiagnosticsFromInputs assembles one status response from
// an immutable input snapshot. Both the route snapshot and the sampler inputs
// are captured once by the caller and reused for the whole response: endpoint
// discovery and other status work may take longer than the 200ms recency
// window, so independent reads can make one JSON response disagree with itself
// about whether a just-observed incident is still current.
func (s *Service) populateOperationalDiagnosticsFromInputs(status *Status, routes []forwarder.RouteInfo, inputs diagnosticsInputs) {
	if status == nil {
		return
	}

	var writeErrors uint64
	// 1. Rates, Queue Pressure, Latency
	if inputs.forwarder != nil {
		fRates := inputs.forwarder.Rates()
		status.Rates = TrafficRates{
			Available:   fRates.Available,
			RxBps:       fRates.RxBps,
			TxBps:       fRates.TxBps,
			RxPps:       fRates.RxPps,
			TxPps:       fRates.TxPps,
			DropRatePps: fRates.DropRatePps,
			RxBpsAvg5m:  fRates.RxBpsAvg5m,
			TxBpsAvg5m:  fRates.TxBpsAvg5m,
			RxBpsAvg1h:  fRates.RxBpsAvg1h,
			TxBpsAvg1h:  fRates.TxBpsAvg1h,
		}

		qStats := inputs.forwarder.QueuePressure()
		status.QueuePressure = QueuePressureDiagnostics{
			Occupancy:             qStats.Occupancy,
			Capacity:              qStats.Capacity,
			UtilizationPct:        qStats.UtilizationPct,
			HighWaterPct:          qStats.HighWaterPct,
			TotalSecondsAbove50:   qStats.SecondsAbove50Pct,
			TotalSecondsAbove80:   qStats.SecondsAbove80Pct,
			ConsecutiveAbove50Sec: qStats.ConsecutiveAbove50Sec,
			ConsecutiveAbove80Sec: qStats.ConsecutiveAbove80Sec,
			QueueFullDrops:        qStats.QueueFullDrops,
			QueueDropRatePps:      qStats.QueueFullDropRate,
		}

		writes := inputs.forwarder.DeviceWriteSnapshot()
		writeErrors = writes.Errors
		status.ForwardLatency = ForwardLatencyDiagnostics{
			P50MS:             float64(writes.P50Duration.Microseconds()) / 1000.0,
			P95MS:             float64(writes.P95Duration.Microseconds()) / 1000.0,
			P99MS:             float64(writes.P99Duration.Microseconds()) / 1000.0,
			MaxMS:             writes.MaxDuration.Milliseconds(),
			InFlight:          writes.InFlight,
			OldestInFlightMS:  writes.OldestInFlight.Milliseconds(),
			Stalls:            writes.Stalls,
			WriteErrors:       writes.Errors,
			WriteTotal:        writes.Count,
			WriteErrorRatePps: 0,

			P95HealthMS:        float64(writes.P95HealthDuration.Microseconds()) / 1000.0,
			P95HealthSamples:   writes.P95HealthSamples,
			P95HealthWindowSec: int64(writes.HealthWindow / time.Second),
		}
	}

	// 2. Drop Categories & VirtualTUN
	status.DropCategories = inputs.collectDropCategories()
	status.VirtualTUN = inputs.collectVirtualTUNDiagnostics()

	// The loss sampling pair owns one timestamp and one serialization scope.
	// Both use the generation the inputs snapshot captured (issue #429 review
	// round 4, blocker 1): an in-flight request whose snapshot predates a
	// lifecycle reset cannot advance the new generation's trackers.
	sampleAt := time.Now()
	s.primeHistoryFromDrops(sampleAt, inputs.forwarder, inputs.generation, status.DropCategories)
	status.ForwardLatency.WriteErrorRatePps = s.sampleDropRates(inputs.generation, sampleAt, &status.DropCategories, writeErrors)
	status.Rates.DropRatePps = status.DropCategories.TotalDropRatePps
	status.QueuePressure.QueueDropRatePps = status.DropCategories.ReasonRates[reasonReturnQueueFull]
	stalls := s.diagDeltas.writeStalls.Sample(inputs.generation, sampleAt, status.ForwardLatency.Stalls)
	status.ForwardLatency.StallsRecent = stalls.delta
	status.ForwardLatency.StallsWindowSec = stalls.windowSeconds

	// 3. Routing consistency
	losses := addIngressLosses(inputs.retiredIngressLosses, engineLossTotals(inputs.ingressEngine))
	status.RoutingConsistency = checkRoutingInvariantsWithInputs(s, inputs, routes, losses.returns, losses.router.OwnershipMismatchDrops)

	// 4. Handshake freshness
	status.HandshakeFreshness = inputs.collectHandshakeDiagnostics()

	// 5. Backends
	status.Backends = inputs.collectBackendDiagnostics()

	if inputs.sessionMgr != nil {
		sessions := inputs.sessions
		started := make(map[string]time.Time, len(sessions))
		for _, session := range sessions {
			started[session.PeerPublicKey] = session.ConnectedAt
		}
		for i := range routes {
			if at, ok := started[routes[i].PeerKey]; ok {
				routes[i].SessionAgeSec = int64(time.Since(at) / time.Second)
			}
		}
	}

	// 6. Problem Routes. Filter/rank the SAME snapshot used above so the
	// response is internally consistent even when status assembly is slow.
	if inputs.forwarder != nil {
		status.ProblemRoutes = collectProblemRoutes(forwarder.ProblemRoutesFromSnapshot(routes, 50))
		status.AllRoutes = collectProblemRoutes(routes)
	} else {
		status.ProblemRoutes = []ProblemRouteItem{}
		status.AllRoutes = []ProblemRouteItem{}
	}

	// 7. Runtime Resources
	status.RuntimeResources = collectRuntimeResources()

	// 8. Historical Series
	if inputs.rollingHistory != nil {
		status.HistoricalSeries = inputs.rollingHistory.Snapshot()
	} else {
		status.HistoricalSeries = HistoricalSeries{
			Window1m:  []HistoryPoint{},
			Window5m:  []HistoryPoint{},
			Window15m: []HistoryPoint{},
			Window1h:  []HistoryPoint{},
			Window6h:  []HistoryPoint{},
			Window24h: []HistoryPoint{},
		}
	}

	// 9. Peer sync failure window. The cumulative counters stay untouched as
	// history; only the recent deltas gate health (issue #424 round 2).
	if status.PeerSync != nil {
		now := time.Now()
		syncRate := s.diagDeltas.sampleSyncFailures(inputs.generation, now, status.PeerSync.SyncFailures)
		enqueueRate := s.diagDeltas.sampleEnqueueFailures(inputs.generation, now, status.PeerSync.EnqueueFailures)
		status.PeerSync.SyncFailuresRecent = syncRate.delta
		status.PeerSync.EnqueueFailuresRecent = enqueueRate.delta
		status.PeerSync.FailuresWindowSec = math.Max(syncRate.windowSeconds, enqueueRate.windowSeconds)
	}

	// 10. Centralized Rule-Based Health Assessment
	actionableProblems := s.synthesizeActionableProblems(routes, inputs.sessions, status.HandshakeFreshness.PeerHandshakes)
	status.HealthAssessment = EvaluateForwarderHealth(
		status.ForwarderAvailable,
		status.EngineRunning,
		status.QueuePressure,
		status.ForwardLatency,
		status.DropCategories,
		status.VirtualTUN,
		status.PeerSync,
		status.RoutingConsistency,
		status.HandshakeFreshness,
		status.Backends,
		actionableProblems...,
	)
}
