package vpn

import (
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/ingress"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/session"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/tunnel"
)

// diagnosticsInputs owns Service lifecycle storage for one observation.
// Shared collaborators synchronize their own methods and remain valid after
// retirement. Call them only after releasing Service.mu.
//
// generation is the dataplane incarnation this snapshot belongs to (issue
// #429 review round 4, blocker 1): it is captured atomically together with
// the rest of the snapshot and must be passed to EVERY sampling entry point
// fed from it, so a snapshot can never be sampled against the trackers'
// current generation after a lifecycle reset. The trackers' reset(gen)
// lifecycle is unchanged.
type diagnosticsInputs struct {
	generation                diagGeneration
	sessions                  []Session
	tunnels                   []*models.BackendTunnel
	forwarder                 *forwarder.Forwarder
	ingressEngine             *IngressEngine
	sessionMgr                *session.SessionManager
	pool                      *tunnel.Pool
	rollingHistory            *RollingHistory
	backendDevices            map[int64]BackendDevice
	retiredBackendDeviceDrops backendDeviceDropStats
	retiredIngressLosses      ingressLossTotals
}

func (s *Service) captureDiagnosticsInputs() diagnosticsInputs {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.diagnosticsInputsLocked()
}

// diagnosticsInputsLocked requires Service.mu. Map storage, retired prefixes
// and the diagnostics generation are captured together so an observation
// belongs to exactly one population AND one dataplane incarnation: the
// atomic load cannot straddle a lifecycle transition that the rest of the
// snapshot already crossed, because resetDiagnosticsGeneration bumps the
// generation under diagRatesMu before Service.Start repopulates the
// snapshot's collaborators (and their writers hold s.mu).
func (s *Service) diagnosticsInputsLocked() diagnosticsInputs {
	devices := make(map[int64]BackendDevice, len(s.backendDevices))
	for id, dev := range s.backendDevices {
		devices[id] = dev
	}
	var sessions []Session
	if s.sessionMgr != nil {
		sessions = s.sessionMgr.ListActiveSessionsSnapshot()
	}
	var tunnels []*models.BackendTunnel
	if s.pool != nil {
		tunnels = s.pool.ListTunnels()
	}
	return diagnosticsInputs{
		generation: s.currentDiagGeneration(),
		sessions:   sessions, tunnels: tunnels,
		forwarder: s.forwarder, ingressEngine: s.ingressEngine,
		sessionMgr: s.sessionMgr, pool: s.pool, rollingHistory: s.rollingHistory,
		backendDevices:            devices,
		retiredBackendDeviceDrops: s.retiredBackendDeviceDrops,
		retiredIngressLosses:      s.retiredIngressLosses,
	}
}

// currentDiagGeneration reports the live diagnostics generation. Lock-free on
// purpose (atomic): capture paths hold s.mu, while resetDiagnosticsGeneration
// holds diagRatesMu and takes s.mu for its priming capture — a diagRatesMu
// read here would invert the established lock order and deadlock.
func (s *Service) currentDiagGeneration() diagGeneration {
	return diagGeneration(s.diagGeneration.Load())
}

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

// cpuTracker measures CPU usage via syscall.Getrusage.
type cpuTracker struct {
	mu           sync.Mutex
	lastWallTime time.Time
	lastUserTime time.Duration
	lastSysTime  time.Duration
	lastPercent  float64
}

var globalCPUTracker = &cpuTracker{}

func (ct *cpuTracker) Percent() float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return ct.lastPercent
	}

	userTime := time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond
	sysTime := time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
	now := time.Now()

	if ct.lastWallTime.IsZero() {
		ct.lastWallTime = now
		ct.lastUserTime = userTime
		ct.lastSysTime = sysTime
		return 0.0
	}

	wallDelta := now.Sub(ct.lastWallTime).Seconds()
	if wallDelta < 0.2 {
		return ct.lastPercent
	}

	userDelta := (userTime - ct.lastUserTime).Seconds()
	sysDelta := (sysTime - ct.lastSysTime).Seconds()
	cpuDelta := userDelta + sysDelta

	numCPU := float64(runtime.NumCPU())
	if numCPU <= 0 {
		numCPU = 1.0
	}

	pct := (cpuDelta / wallDelta) * 100.0 / numCPU
	if pct < 0 {
		pct = 0
	} else if pct > 100.0 {
		pct = 100.0
	}

	ct.lastWallTime = now
	ct.lastUserTime = userTime
	ct.lastSysTime = sysTime
	ct.lastPercent = pct
	return pct
}

func getOpenFileDescriptors() (int, uint64) {
	var maxFD uint64 = 1024
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		maxFD = rLimit.Cur
	}

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, maxFD
	}
	return len(entries), maxFD
}

// getMemoryLimit reports a discovered finite cgroup capacity. An absent or
// unlimited cgroup is unknown; Go runtime Sys is not a memory capacity.
func getMemoryLimit() uint64 {
	return readMemoryLimit(os.ReadFile)
}

func readMemoryLimit(readFile func(string) ([]byte, error)) uint64 {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		limit, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err == nil && limit > 0 && limit < 1<<60 {
			return limit
		}
	}
	return 0
}

func collectRuntimeResources() RuntimeResources {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	openFD, maxFD := getOpenFileDescriptors()
	memLimit := getMemoryLimit()

	var memUsagePct float64
	if memLimit > 0 {
		memUsagePct = float64(m.Alloc) / float64(memLimit) * 100.0
		if memUsagePct > 100.0 {
			memUsagePct = 100.0
		}
	}

	// Calculate GC Pause p95
	var gcPauseP95MS float64
	if m.NumGC > 0 {
		n := int(m.NumGC)
		if n > 256 {
			n = 256
		}
		pauses := make([]uint64, 0, n)
		for i := 0; i < n; i++ {
			p := m.PauseNs[(int(m.NumGC)-1-i+256)%256]
			if p > 0 {
				pauses = append(pauses, p)
			}
		}
		if len(pauses) > 0 {
			sort.Slice(pauses, func(i, j int) bool { return pauses[i] < pauses[j] })
			idx := int(float64(len(pauses)-1) * 0.95)
			gcPauseP95MS = float64(pauses[idx]) / 1e6
		}
	}

	return RuntimeResources{
		CPUPercent:           globalCPUTracker.Percent(),
		MemoryAllocBytes:     m.Alloc,
		MemorySysBytes:       m.Sys,
		MemoryLimitBytes:     memLimit,
		MemoryLimitAvailable: memLimit > 0,
		MemoryUsagePct:       memUsagePct,
		Goroutines:           runtime.NumGoroutine(),
		GCPauseP95MS:         gcPauseP95MS,
		OpenFileDesc:         openFD,
		MaxFileDesc:          maxFD,
	}
}

// checkRoutingInvariants verifies integrity across active sessions, forwarder routes, and return paths.
//
// clientOwnershipMismatch is the CLIENT-direction (client -> backend) ownership
// mismatch cumulative counter. It is a parameter rather than being read from
// the engine here because the caller already resolved it through
// addIngressLosses, which folds in losses retained across an engine restart;
// re-reading the engine's own counter here would silently exclude exactly the
// retained losses the retention machinery exists to preserve (issue #424
// review round 9, blocker 3).
func checkRoutingInvariants(s *Service, routes []forwarder.RouteInfo, retStats ReturnStatsSnapshot, clientOwnershipMismatch uint64) RoutingConsistencyDiagnostics {
	return checkRoutingInvariantsWithInputs(s, s.captureDiagnosticsInputs(), routes, retStats, clientOwnershipMismatch)
}

func checkRoutingInvariantsWithInputs(s *Service, inputs diagnosticsInputs, routes []forwarder.RouteInfo, retStats ReturnStatsSnapshot, clientOwnershipMismatch uint64) RoutingConsistencyDiagnostics {
	activeSessions := inputs.sessions
	diag := auditRoutingConsistencyDetails(routes, activeSessions)
	diag.OwnershipMismatchDrops = retStats.OwnershipMismatchDrops
	diag.ClientOwnershipMismatchDrops = clientOwnershipMismatch

	if s != nil {
		now := time.Now()
		mismatchRate := s.diagDeltas.sampleOwnershipMismatch(inputs.generation, now, retStats.OwnershipMismatchDrops)
		clientMismatchRate := s.diagDeltas.sampleClientOwnershipMismatch(inputs.generation, now, clientOwnershipMismatch)
		diag.OwnershipMismatchDropsRecent = mismatchRate.delta
		diag.ClientOwnershipMismatchDropsRecent = clientMismatchRate.delta
		diag.OwnershipMismatchWindowSec = math.Max(mismatchRate.windowSeconds, clientMismatchRate.windowSeconds)
		diag.ReturnOwnershipMismatchConsecutiveHighRateWindows = s.diagDeltas.consecutiveHighRateWindows()

		if diag.OwnershipMismatchRecentTotal() > 0 {
			diag.IsConsistent = false
			diag.InconsistencyDetails = append(diag.InconsistencyDetails,
				describeOwnershipMismatchRecent(&diag))
		} else if diag.OwnershipMismatchDrops > 0 || diag.ClientOwnershipMismatchDrops > 0 {
			diag.HistoricalDetails = append(diag.HistoricalDetails,
				describeOwnershipMismatchHistorical(&diag))
		}
	}

	return diag
}

func auditRoutingConsistencyDetails(routes []forwarder.RouteInfo, activeSessions []Session) RoutingConsistencyDiagnostics {
	diag := RoutingConsistencyDiagnostics{
		ActiveSessionsCount:  len(activeSessions),
		ActiveRoutesCount:    len(routes),
		IsConsistent:         true,
		SessionsWithoutRoute: []string{},
		RoutesWithoutSession: []string{},
		RoutesWithoutReturn:  []string{},
		DuplicateIPs:         []string{},
		HistoricalDetails:    []string{},
	}

	sessionByPeer := make(map[string]Session, len(activeSessions))
	ipSessions := make(map[string][]string)

	for _, sess := range activeSessions {
		sessionByPeer[sess.PeerPublicKey] = sess
		if sess.AssignedIP != "" {
			ipSessions[sess.AssignedIP] = append(ipSessions[sess.AssignedIP], sess.PeerPublicKey)
		}
	}

	routesByPeer := make(map[string]forwarder.RouteInfo, len(routes))
	ipRoutes := make(map[string][]string)

	for _, r := range routes {
		routesByPeer[r.PeerKey] = r
		if r.AssignedIP != "" {
			ipRoutes[r.AssignedIP] = append(ipRoutes[r.AssignedIP], r.PeerKey)
		}
		if r.BackendTunnelID > 0 && r.HasReturnPath && !r.ReturnPathClosed {
			diag.ReturnOwnersCount++
		}
	}

	diag.SessionsWithoutRoute, diag.RoutesWithoutSession = auditUnpairedRoutesAndSessions(sessionByPeer, routesByPeer)
	diag.RoutesWithoutReturn = auditRoutesWithoutReturn(routesByPeer)
	diag.DuplicateIPs = findDuplicateIPs(ipSessions, ipRoutes)

	// Sort FIRST, redact SECOND (issue #424 round 5, item 1a).
	sort.Strings(diag.SessionsWithoutRoute)
	sort.Strings(diag.RoutesWithoutSession)
	sort.Strings(diag.RoutesWithoutReturn)
	redactKeySlice(diag.SessionsWithoutRoute)
	redactKeySlice(diag.RoutesWithoutSession)
	redactKeySlice(diag.RoutesWithoutReturn)

	finalizeRoutingConsistencyIssues(&diag)

	return diag
}

func auditUnpairedRoutesAndSessions(sessionByPeer map[string]Session, routesByPeer map[string]forwarder.RouteInfo) ([]string, []string) {
	var sessionsWithoutRoute []string
	for peerKey, sess := range sessionByPeer {
		r, ok := routesByPeer[peerKey]
		if !ok || (r.SessionID != "" && sess.ID != "" && r.SessionID != sess.ID) {
			sessionsWithoutRoute = append(sessionsWithoutRoute, peerKey)
		}
	}

	var routesWithoutSession []string
	for peerKey, r := range routesByPeer {
		sess, ok := sessionByPeer[peerKey]
		if !ok || (r.SessionID != "" && sess.ID != "" && r.SessionID != sess.ID) {
			routesWithoutSession = append(routesWithoutSession, peerKey)
		}
	}

	return sessionsWithoutRoute, routesWithoutSession
}

func auditRoutesWithoutReturn(routesByPeer map[string]forwarder.RouteInfo) []string {
	var routesWithoutReturn []string
	for peerKey, r := range routesByPeer {
		if r.BackendTunnelID <= 0 || !r.HasReturnPath || r.ReturnPathClosed {
			routesWithoutReturn = append(routesWithoutReturn, peerKey)
		}
	}
	return routesWithoutReturn
}

func finalizeRoutingConsistencyIssues(diag *RoutingConsistencyDiagnostics) {
	if len(diag.SessionsWithoutRoute) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d active session(s) lack a forwarder route", len(diag.SessionsWithoutRoute)))
	}
	if len(diag.RoutesWithoutSession) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d forwarder route(s) have no corresponding active session", len(diag.RoutesWithoutSession)))
	}
	if len(diag.RoutesWithoutReturn) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d route(s) lack an assigned return owner/backend", len(diag.RoutesWithoutReturn)))
	}
	if len(diag.DuplicateIPs) > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d duplicate IP address(es) detected across active routes: %s",
				len(diag.DuplicateIPs), strings.Join(diag.DuplicateIPs, ", ")))
	}
}

// redactKeySlice replaces every element of keys with its ingress.RedactKey
// rendering, in place. It exists because several diagnostics fields are built
// by iterating maps keyed by the raw peer public key: redacting only at one
// call site is what left the rest of the surface disclosing full keys in
// issue #424 round 5. ingress.RedactKey is the single redaction convention in
// this codebase, so this helper deliberately delegates to it rather than
// introducing a second scheme.
func redactKeySlice(keys []string) {
	for i, k := range keys {
		keys[i] = ingress.RedactKey(k)
	}
}

func findDuplicateIPs(ipSessions, ipRoutes map[string][]string) []string {
	dupIPSet := make(map[string]struct{})
	for ip, peers := range ipSessions {
		if len(peers) > 1 {
			dupIPSet[ip] = struct{}{}
		}
	}
	for ip, peers := range ipRoutes {
		if len(peers) > 1 {
			dupIPSet[ip] = struct{}{}
		}
	}
	dups := make([]string, 0, len(dupIPSet))
	for ip := range dupIPSet {
		dups = append(dups, ip)
	}
	sort.Strings(dups)
	return dups
}

// describeOwnershipMismatchRecent renders the current-window ownership-mismatch
// note. Each direction that is contributing is named with its own count, so a
// reader can tell a client-only incident from a return-only one from both, and
// a direction that is quiet is simply absent rather than reported as zero
// (issue #424 review round 9, blocker 3).
func describeOwnershipMismatchRecent(diag *RoutingConsistencyDiagnostics) string {
	parts := make([]string, 0, 2)
	if n := diag.ClientOwnershipMismatchDropsRecent; n > 0 {
		parts = append(parts, fmt.Sprintf("%d client-direction", n))
	}
	if n := diag.OwnershipMismatchDropsRecent; n > 0 {
		parts = append(parts, fmt.Sprintf("%d return-direction", n))
	}
	return fmt.Sprintf("%s ownership mismatch drop(s) in the last %.1fs",
		strings.Join(parts, " and "), diag.OwnershipMismatchWindowSec)
}

// describeOwnershipMismatchHistorical renders the recovered-incident note. It
// names the cumulative total across both directions, and stays a HISTORICAL
// detail: a lifetime counter must not degrade current health (issue #424 round
// 2, finding 5, extended to the client direction in round 9).
func describeOwnershipMismatchHistorical(diag *RoutingConsistencyDiagnostics) string {
	return fmt.Sprintf("%d ownership mismatch drop(s) observed historically (%d client, %d return), none in the last %.1fs",
		diag.ClientOwnershipMismatchDrops+diag.OwnershipMismatchDrops,
		diag.ClientOwnershipMismatchDrops, diag.OwnershipMismatchDrops,
		diag.OwnershipMismatchWindowSec)
}

// collectBackendDiagnostics captures one owned lifecycle observation.
func collectBackendDiagnostics(s *Service) BackendsDiagnostics {
	return s.captureDiagnosticsInputs().collectBackendDiagnostics()
}

func (inputs diagnosticsInputs) collectBackendDiagnostics() BackendsDiagnostics {
	var traffic map[int64]forwarder.TrafficSnapshot
	if inputs.forwarder != nil {
		traffic = inputs.forwarder.BackendTrafficSnapshot()
	}
	return inputs.collectBackendDiagnosticsWithTraffic(traffic)
}

func (inputs diagnosticsInputs) collectBackendDiagnosticsWithTraffic(traffic map[int64]forwarder.TrafficSnapshot) BackendsDiagnostics {
	if inputs.pool == nil {
		return BackendsDiagnostics{
			EligibilityKnown: true,
			TotalDrops:       inputs.totalBackendDeviceDrops(),
			Backends:         []BackendTelemetryItem{},
		}
	}

	tunnels := inputs.tunnels
	diag := BackendsDiagnostics{
		TotalCount:       len(tunnels),
		EligibilityKnown: true,
		Backends:         make([]BackendTelemetryItem, 0, len(tunnels)),
		TotalDrops:       inputs.totalBackendDeviceDrops(),
	}

	totalActiveConns := countBackendEligibility(&diag, tunnels)

	activeLatencies := make([]float64, 0, len(tunnels))
	var maxShare float64

	for _, tun := range tunnels {
		item, loadShare, hasLatencySample := backendTelemetryItem(inputs, tun, traffic, totalActiveConns)
		if loadShare > maxShare {
			maxShare = loadShare
		}
		if hasLatencySample {
			activeLatencies = append(activeLatencies, float64(tun.LatencyMS))
		}
		diag.Backends = append(diag.Backends, item)
	}

	applyBackendFleetStats(&diag, activeLatencies, maxShare, totalActiveConns)

	return diag
}

// totalBackendDeviceDrops sums the drop counters of every live backend device
// onto the retired-device lifetime total. nil map entries are skipped exactly
// as the original inline loops did, so the fleet-wide drop population — and
// therefore the no-pool early-return TotalDrops — is unchanged.
func totalBackendDeviceDrops(s *Service) uint64 {
	return s.captureDiagnosticsInputs().totalBackendDeviceDrops()
}

func (inputs diagnosticsInputs) totalBackendDeviceDrops() uint64 {
	drops := inputs.retiredBackendDeviceDrops.Total()
	for _, dev := range inputs.backendDevices {
		if dev != nil {
			drops += dev.DroppedPackets()
		}
	}
	return drops
}

// countBackendEligibility tallies enabled, disabled, and healthy counts over the
// tunnel list and returns the total active connections across eligible
// backends. Eligibility is the shared "enabled AND active" predicate: a
// disabled tunnel is counted only in the disabled inventory, never in the
// healthy count, and never contributes load share, latency samples, or skew.
func countBackendEligibility(diag *BackendsDiagnostics, tunnels []*models.BackendTunnel) int {
	var totalActiveConns int
	for _, tun := range tunnels {
		if tun.Enabled {
			diag.EnabledCount++
		} else {
			diag.DisabledCount++
		}
		if backendEligible(tun) {
			diag.HealthyCount++
			totalActiveConns += tun.ActiveConnections
		}
	}
	return totalActiveConns
}

// backendEligible reports whether a tunnel carries data: administratively
// enabled and runtime-active. It is the single definition of eligibility shared
// by the healthy count, the per-backend load share, latency sample admission,
// and the emitted Routable flag.
func backendEligible(tun *models.BackendTunnel) bool {
	return tun.Enabled && tun.Status == TunnelStatusActive
}

// backendTelemetryItem builds one BackendTelemetryItem for a tunnel. It returns
// the load share and whether the tunnel contributes a latency sample, so the
// caller can accumulate the fleet p95 population and the max share without
// re-deriving either.
//
// lastHSAge stays at its -1 sentinel when no device exists or the device has
// never completed a handshake, and is clamped at 0 when the handshake timestamp
// is in the future, preserving the original tri-state.
func backendTelemetryItem(
	inputs diagnosticsInputs,
	tun *models.BackendTunnel,
	traffic map[int64]forwarder.TrafficSnapshot,
	totalActiveConns int,
) (BackendTelemetryItem, float64, bool) {
	var drops uint64
	lastHSAge := int64(-1)

	if dev, exists := inputs.backendDevices[tun.ID]; exists && dev != nil {
		drops = dev.DroppedPackets()
		if hs := dev.LastHandshakeTime(); !hs.IsZero() {
			lastHSAge = int64(time.Since(hs).Seconds())
			if lastHSAge < 0 {
				lastHSAge = 0
			}
		}
	}

	eligible := backendEligible(tun)

	var loadShare float64
	if eligible && totalActiveConns > 0 {
		loadShare = float64(tun.ActiveConnections) / float64(totalActiveConns) * 100.0
	}

	// Traffic is read straight from the snapshot: an unsampled backend reports a
	// zero-value entry with TrafficAvailable false, which is distinct from a
	// measured zero and is preserved by not defaulting any field.
	item := BackendTelemetryItem{
		Enabled: tun.Enabled, Routable: eligible,
		TrafficAvailable: traffic[tun.ID].Available, TrafficWindowSec: traffic[tun.ID].WindowSec,
		RxBytes: traffic[tun.ID].RxBytes, TxBytes: traffic[tun.ID].TxBytes,
		RxBytesPerSec: traffic[tun.ID].RxBytesPerSec, TxBytesPerSec: traffic[tun.ID].TxBytesPerSec,
		RxPps: traffic[tun.ID].RxPps, TxPps: traffic[tun.ID].TxPps,
		RxPackets: traffic[tun.ID].RxPackets, TxPackets: traffic[tun.ID].TxPackets,
		ID:                  tun.ID,
		ServerID:            tun.ServerID,
		ServerName:          fmt.Sprintf("Server %d", tun.ServerID),
		HealthState:         tun.Status,
		ProbeLatencyMS:      tun.LatencyMS,
		ActiveSessions:      tun.ActiveConnections,
		DeviceDrops:         drops,
		LastHandshakeAgeSec: lastHSAge,
		LoadSharePct:        loadShare,
	}

	return item, loadShare, eligible && tun.LatencyMS > 0
}

// applyBackendFleetStats fills the fleet-wide latency percentile and load skew
// from the accumulated sample population, max share, and eligible connection
// total.
func applyBackendFleetStats(diag *BackendsDiagnostics, activeLatencies []float64, maxShare float64, totalActiveConns int) {
	// Nearest-rank p95: ceil(0.95*n)-1 over eligible measured probes.
	// Empty has zero samples; singleton and two-value fleets retain their slow tail.
	if len(activeLatencies) > 0 {
		sort.Float64s(activeLatencies)
		diag.LatencySamples = len(activeLatencies)
		idx := int(math.Ceil(float64(len(activeLatencies))*0.95)) - 1
		diag.LatencyP95MS = activeLatencies[idx]
	}

	// Calculate load skew
	if diag.HealthyCount > 1 && totalActiveConns > 0 {
		idealShare := 100.0 / float64(diag.HealthyCount)
		diag.LoadSkewPct = math.Abs(maxShare - idealShare)
	}
}

// collectHandshakeDiagnostics inspects upstream device status and checks for stale active sessions.
func collectHandshakeDiagnostics(s *Service) HandshakeFreshnessDiagnostics {
	return s.captureDiagnosticsInputs().collectHandshakeDiagnostics()
}

func (inputs diagnosticsInputs) collectHandshakeDiagnostics() HandshakeFreshnessDiagnostics {
	diag := HandshakeFreshnessDiagnostics{}
	if inputs.ingressEngine == nil || inputs.ingressEngine.Portal() == nil {
		return diag
	}

	portalStatus, err := inputs.ingressEngine.Portal().Status()
	if err != nil {
		return diag
	}

	now := time.Now()
	diag.TotalPeers = len(portalStatus.Peers)
	peerHandshakes := make(map[string]time.Time, len(portalStatus.Peers))

	for _, p := range portalStatus.Peers {
		peerHandshakes[p.PublicKey] = p.LastHandshake
		if p.LastHandshake.IsZero() {
			diag.NeverCount++
			continue
		}
		age := now.Sub(p.LastHandshake)
		if age < 2*time.Minute {
			diag.Under2mCount++
		} else if age <= 5*time.Minute {
			diag.Between2m5mCount++
		} else {
			diag.Over5mCount++
		}
	}

	// Check active live sessions for stale handshakes (> 3 minutes)
	if inputs.sessionMgr != nil {
		activeSessions := inputs.sessions
		for _, sess := range activeSessions {
			hs, ok := peerHandshakes[sess.PeerPublicKey]
			if !ok || hs.IsZero() || now.Sub(hs) > DefaultHealthThresholds.HandshakeStaleAge {
				// Collected raw, redacted after the sort below (issue #424
				// round 5, item 1b). This value reached /api/vpn/status
				// verbatim as handshake_freshness.stale_live_sessions.
				// ingress.RedactKey keeps the per-session correlation an
				// admin needs while keeping the full key out of the payload.
				diag.StaleLiveSessions = append(diag.StaleLiveSessions, sess.PeerPublicKey)
			}
		}
	}

	// Sort first, redact second, for the same reason as the routing invariant
	// slices: sort.Strings over the raw keys is a total order on the data,
	// whereas sorting the redacted values would order by the 8 character
	// prefix that redaction leaves behind, making the output order a property
	// of the masking scheme instead of the keys.
	sort.Strings(diag.StaleLiveSessions)
	redactKeySlice(diag.StaleLiveSessions)
	diag.PeerHandshakes = peerHandshakes
	return diag
}

// EvaluateForwarderHealth applies deterministic rules to derive the overall dataplane health status.
func EvaluateForwarderHealth(
	fwdAvailable bool,
	engineRunning bool,
	queue QueuePressureDiagnostics,
	latency ForwardLatencyDiagnostics,
	drops DropCategoryBreakdown,
	vtun VirtualTUNDiagnostics,
	peerSync *PeerSyncStatus,
	routing RoutingConsistencyDiagnostics,
	handshake HandshakeFreshnessDiagnostics,
	backends BackendsDiagnostics,
	actionable ...ActionableProblem,
) ForwarderHealthAssessment {
	if !fwdAvailable || !engineRunning {
		return ForwarderHealthAssessment{
			Status:  HealthUnavailable,
			Summary: "Forwarder engine is stopped or unavailable",
			Conditions: []HealthCondition{
				{
					Category: "engine",
					Severity: "CRITICAL",
					Message:  "Forwarder dataplane is not active",
				},
			},
			ActionableProblems: actionable,
		}
	}

	conditions := make([]HealthCondition, 0)
	conditions = append(conditions, evaluateRoutingConditions(routing)...)
	conditions = append(conditions, evaluateQueueConditions(queue)...)
	conditions = append(conditions, evaluateLatencyConditions(latency)...)
	conditions = append(conditions, evaluateVirtualTUNAndDropConditions(vtun, drops, routing, queue.QueueDropRatePps)...)
	conditions = append(conditions, evaluatePeerSyncAndBackendConditions(peerSync, backends, handshake)...)

	status, summary := summarizeHealthConditions(conditions)

	hasCriticalActionable := false
	hasDegradedActionable := false
	for _, p := range actionable {
		switch strings.ToUpper(p.Severity) {
		case HealthCritical:
			hasCriticalActionable = true
		case HealthDegraded:
			hasDegradedActionable = true
		}
	}

	initialStatus := status
	if hasCriticalActionable && status != "DOWN" {
		status = HealthCritical
	} else if hasDegradedActionable && (status == HealthHealthy || status == "WARNING") {
		status = HealthDegraded
	}

	var summaryKey string
	if (initialStatus == HealthHealthy || initialStatus == "WARNING") && status != initialStatus {
		summary = "Active VPN session routing or dataplane issues detected"
		summaryKey = "vpn_diag_summary_actionable_issues"
	}

	return ForwarderHealthAssessment{
		Status:             status,
		Summary:            summary,
		SummaryKey:         summaryKey,
		Conditions:         conditions,
		ActionableProblems: actionable,
	}
}

// evaluateRoutingConditions turns routing invariants into health conditions.
//
// In issue #457, severity is evaluated per condition detail:
//   - Duplicate IPs and unroutable sessions remain CRITICAL.
//   - Client-direction ownership mismatches remain CRITICAL.
//   - Return-direction ownership mismatches classify as CRITICAL if client mismatch
//     is also present, DEGRADED if return drop rate reaches the degraded threshold,
//     and WARNING for routine sparse drops.
//   - Structural routing discrepancies remain DEGRADED.
func evaluateRoutingConditions(routing RoutingConsistencyDiagnostics) []HealthCondition {
	if routing.IsConsistent {
		return nil
	}
	th := defaultHealthThresholds()
	conds := make([]HealthCondition, 0, len(routing.InconsistencyDetails))
	for _, detail := range routing.InconsistencyDetails {
		condSev := "DEGRADED"
		if strings.Contains(detail, "duplicate IP") || strings.Contains(detail, "lack a forwarder route") {
			condSev = "CRITICAL"
		} else if strings.Contains(detail, "client-direction") {
			if routing.ClientOwnershipMismatchDropsRecent >= th.ClientOwnershipMismatchCriticalDrops {
				condSev = "CRITICAL"
			}
		} else if strings.Contains(detail, "return-direction") {
			minConsecutive := th.ReturnOwnershipMismatchDegradedConsecutiveWindows
			if minConsecutive <= 0 {
				minConsecutive = 1
			}
			if routing.ClientOwnershipMismatchDropsRecent >= th.ClientOwnershipMismatchCriticalDrops {
				condSev = "CRITICAL"
			} else if routing.OwnershipMismatchRatePPS() >= th.ReturnOwnershipMismatchDegradedRatePPS &&
				routing.ReturnOwnershipMismatchConsecutiveHighRateWindows >= minConsecutive {
				condSev = "DEGRADED"
			} else if routing.OwnershipMismatchDropsRecent >= th.ReturnOwnershipMismatchWarningDrops {
				condSev = "WARNING"
			}
		}
		conds = append(conds, HealthCondition{
			Category: "routing",
			Severity: condSev,
			Message:  detail,
		})
	}
	return conds
}

func evaluateQueueConditions(queue QueuePressureDiagnostics) []HealthCondition {
	// Read the DERIVED set live, not the package snapshot: the queue-pressure
	// levels are canonical in internal/vpn/forwarder/thresholds and this is
	// their reporting half, so a change there must move this evaluation
	// (issue #424 round 5, finding 4).
	th := defaultHealthThresholds()
	var conds []HealthCondition
	if queue.UtilizationPct >= th.QueueCriticalPct {
		conds = append(conds, HealthCondition{
			Category: "queue_pressure",
			Severity: "CRITICAL",
			Message:  fmt.Sprintf("Queue saturation: Return queue utilization is at %.1f%%", queue.UtilizationPct),
		})
	} else if queue.ConsecutiveAbove80Sec >= th.QueueDegradedSustainedSeconds {
		conds = append(conds, HealthCondition{
			Category: "queue_pressure",
			Severity: "DEGRADED",
			// Consecutive duration is measured from managed queue transitions.
			Message: fmt.Sprintf("Queue pressure: Return queue utilization has been at or above %d%% for %ds",
				int(th.QueueDegradedAbovePct), queue.ConsecutiveAbove80Sec),
		})
	} else if queue.UtilizationPct >= th.QueueWarningPct || queue.ConsecutiveAbove50Sec >= th.QueueWarningSustainedSeconds {
		conds = append(conds, HealthCondition{
			Category: "queue_pressure",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Elevated queue utilization at %.1f%%", queue.UtilizationPct),
		})
	}
	if queue.QueueDropRatePps > th.QueueActiveDropRatePPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "DEGRADED",
			Message:  fmt.Sprintf("Active queue drops: %.1f drops/sec due to full return queues", queue.QueueDropRatePps),
		})
	}
	return conds
}

func evaluateLatencyConditions(latency ForwardLatencyDiagnostics) []HealthCondition {
	th := defaultHealthThresholds()
	var conds []HealthCondition
	if latency.OldestInFlightMS >= th.WriteStallCriticalMS {
		conds = append(conds, HealthCondition{
			Category: "latency",
			Severity: "CRITICAL",
			Message:  fmt.Sprintf("Device write stall: in-flight write blocked for %dms", latency.OldestInFlightMS),
		})
	} else if latency.OldestInFlightMS >= th.WriteStallWarningMS {
		conds = append(conds, HealthCondition{
			Category: "latency",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Slow in-flight write: in progress for %dms", latency.OldestInFlightMS),
		})
	}

	// Latency health uses the RECENT window, not the descriptive percentile.
	// P95MS describes the last 1024 completed writes and never expires, so on a
	// low-volume or idle server one burst of slow writes held DEGRADED until
	// 1024 new writes displaced it. P95HealthSamples == 0 means nothing was
	// written inside the window, which is UNKNOWN latency, not bad latency: the
	// live signals above (an in-flight write blocked right now) still apply
	// (issue #424 round 8, finding 4).
	if latency.P95HealthSamples > 0 {
		if latency.P95HealthMS >= th.WriteLatencyDegradedMS {
			conds = append(conds, HealthCondition{
				Category: "latency",
				Severity: "DEGRADED",
				Message:  fmt.Sprintf("High forward write latency: p95 is %.1fms over the last %ds", latency.P95HealthMS, latency.P95HealthWindowSec),
			})
		} else if latency.P95HealthMS >= th.WriteLatencyWarningMS {
			conds = append(conds, HealthCondition{
				Category: "latency",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Elevated forward write latency: p95 is %.1fms over the last %ds", latency.P95HealthMS, latency.P95HealthWindowSec),
			})
		}
	}

	if latency.WriteErrorRatePps > 0 {
		conds = append(conds, HealthCondition{
			Category: "latency",
			Severity: "DEGRADED",
			Message:  fmt.Sprintf("Active device write errors: %.1f errors/sec detected", latency.WriteErrorRatePps),
		})
	}
	return conds
}

// evaluateVirtualTUNAndDropConditions classifies upstream queue occupancy and
// dataplane loss.
//
// Loss is classified in TWO disjoint populations rather than one aggregate
// (issue #424 review round 9, blocker 3):
//
//  1. CRITICAL reasons, identified by name. A packet refused because ownership
//     could not be verified, or refused at the injection hop after decryption,
//     is a correctness failure at any volume. Deciding that by REASON rather
//     than by aggregate rate is the whole point: previously these losses were
//     summed into TotalDropRatePps and compared against a generic threshold, so
//     a sparse critical reason read as HEALTHY and a large one read as DEGRADED.
//
//  2. The ROUTINE population: everything else. Its rate is the aggregate MINUS
//     the reason-claimed losses, so a loss can never be reported twice — once by
//     reason and once by the aggregate. This is what keeps the two populations
//     disjoint, and it is why lowering the generic thresholds would NOT have
//     been a fix: it would have turned high-volume queue-full churn critical
//     while still misreading a single ownership mismatch.
//
// routing is taken so the ownership-mismatch subtraction reads the same
// windowed measurement the routing condition was decided on, rather than a
// second, independently-sampled view of the same counters.
func evaluateVirtualTUNAndDropConditions(vtun VirtualTUNDiagnostics, drops DropCategoryBreakdown, routing RoutingConsistencyDiagnostics, returnQueueRate float64) []HealthCondition {
	th := defaultHealthThresholds()
	var conds []HealthCondition
	upstreamToNexusUtil := float64(0)
	if vtun.UpstreamToNexus.Capacity > 0 {
		upstreamToNexusUtil = float64(vtun.UpstreamToNexus.Occupancy) / float64(vtun.UpstreamToNexus.Capacity) * 100.0
	}
	nexusToUpstreamUtil := float64(0)
	if vtun.NexusToUpstream.Capacity > 0 {
		nexusToUpstreamUtil = float64(vtun.NexusToUpstream.Occupancy) / float64(vtun.NexusToUpstream.Capacity) * 100.0
	}
	if upstreamToNexusUtil >= th.VirtualTUNDegradedPct || nexusToUpstreamUtil >= th.VirtualTUNDegradedPct {
		conds = append(conds, HealthCondition{
			Category: "virtual_tun",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("VirtualTUN queue saturation: upstream->nexus %.1f%%, nexus->upstream %.1f%%",
				upstreamToNexusUtil, nexusToUpstreamUtil),
		})
	} else if upstreamToNexusUtil >= th.VirtualTUNWarningPct || nexusToUpstreamUtil >= th.VirtualTUNWarningPct {
		conds = append(conds, HealthCondition{
			Category: "virtual_tun",
			Severity: "WARNING",
			Message: fmt.Sprintf("Elevated VirtualTUN queue utilization: upstream->nexus %.1f%%, nexus->upstream %.1f%%",
				upstreamToNexusUtil, nexusToUpstreamUtil),
		})
	}

	// Ownership mismatch in either direction is claimed by the ROUTING
	// condition, not here. Emitting it in both places is precisely the
	// double-counted loss round 5 of this review was about, so the routing
	// contribution is subtracted from the routine population below rather than
	// reported a second time.

	// Injection failures are claimed here. They have no routing invariant, and
	// before this change they were visible only through the aggregate rate, so
	// they could never exceed DEGRADED.
	//
	// The rate comes from criticalLossReasons, the same declaration that names
	// every other critical reason and its owner, so a reason cannot be reported
	// by reason here without also being subtracted from the routine population
	// below.
	//
	// RatesAvailable gates this deliberately: the first sample of the tracker
	// publishes zeros because the interval is not yet known, so treating an
	// unmeasured window as a real rate would fabricate an incident. That is the
	// same rule the write-latency p95 gate uses (P95HealthSamples > 0).
	if drops.RatesAvailable {
		if rate := criticalReasonRatePps(drops, claimDrops); rate > th.InjectionFailureCriticalRatePPS {
			conds = append(conds, HealthCondition{
				Category: "drops",
				Severity: "CRITICAL",
				Message: fmt.Sprintf("Return-path injection failures: %.1f errors/sec; "+
					"decrypted replies are being refused at the client ingress hop", rate),
			})
		}
		// The queue-full gate reads its OWN reason's rate, not the degraded
		// reason sum: backend_device_unattributed now shares the
		// degradedLossReasons map (and the routine-population subtraction) but
		// has its own condition below, so summing here would report one loss
		// twice under two different messages.
		if rate := drops.ReasonRates[reasonClientBackendQueueFull]; rate > th.ClientQueueActiveDropRatePPS {
			conds = append(conds, HealthCondition{
				Category: "drops",
				Severity: "DEGRADED",
				Message:  fmt.Sprintf("Active client queue drops: %.1f drops/sec due to full backend queues", rate),
			})
		}
		// Unattributed backend-device loss is active: drops ARE happening on a
		// device, but that device cannot report the direction x reason
		// breakdown, so nothing can say which traffic or why. Reported by
		// reason (DEGRADED, review item 2) instead of folding into the generic
		// routine aggregate, which the review called not actionable. The same
		// RatesAvailable gate as above applies: an unmeasured window is not an
		// incident. The reason is the direction-NEUTRAL backend_device_unattributed
		// key (issue #429 review round 3, blocker 3): the loss counts toward the
		// total but toward neither directional total. A device WITH detailed
		// attribution publishes a measured zero for this reason and a non-zero
		// rate under a device-specific key, so this condition stays off in both
		// of its firing-exclusion cases (attribution available; drops quiet).
		if rate := drops.ReasonRates[reasonBackendDeviceUnattributed]; rate > th.BackendDeviceUnattributedActiveDropRatePPS {
			conds = append(conds, HealthCondition{
				Category:   "drops",
				Severity:   "DEGRADED",
				MessageKey: vpnDiagConditionBackendDeviceUnattributed,
				Message: fmt.Sprintf("Backend device drops are active but detailed per-direction attribution is unavailable: "+
					"%.1f drops/sec", rate),
			})
		}
	}

	// The ROUTINE population: the aggregate minus every loss already claimed by
	// a reason-specific condition, whichever evaluator owns it. The routing
	// claim is measured through the routing windowed deltas (the same
	// measurement the routing condition was decided on); the drops claim
	// through the reason rates. Clamped at zero because the two are sampled
	// over the same window by independent trackers, so a small negative residue
	// must never be reported as a negative loss rate.
	routineRate := drops.TotalDropRatePps -
		routing.OwnershipMismatchRatePPS() -
		criticalReasonRatePps(drops, claimDrops) -
		degradedReasonRatePps(drops, claimDrops)
	// evaluateQueueConditions owns return-queue refusals. Its rate uses the
	// same reason window as this aggregate in operational status.
	if returnQueueRate > th.QueueActiveDropRatePPS {
		routineRate -= returnQueueRate
	}
	if routineRate < 0 {
		routineRate = 0
	}

	if routineRate >= th.DropRateDegradedPPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("Elevated routine drop rate: %.1f drops/sec across dataplane "+
				"(excluding ownership-mismatch, injection-failure, and queue losses, reported by reason)",
				routineRate),
		})
	} else if routineRate >= th.DropRateWarningPPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "WARNING",
			Message: fmt.Sprintf("Active routine packet drops: %.1f drops/sec across dataplane "+
				"(excluding ownership-mismatch, injection-failure, and queue losses, reported by reason)",
				routineRate),
		})
	}
	return conds
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

// Peer-sync divergence timing thresholds (issue #424 round 4, item F; round 5,
// item B; centralized in HealthThresholds by round 3, finding 4). A
// desired/actual mismatch that resolves inside the next reconcile
// is normal convergence, not an incident; only a PERSISTED mismatch is. The
// age is measured from PeerSync.DivergenceSince, the moment the CURRENT
// mismatch was first observed, which the peerSynchronizer records during
// reconcile. It is deliberately NOT measured from LastSuccessfulReconcile:
// that is when reconciliation last succeeded, which on a long-healthy system
// can be hours before a single new peer fails to be added, and using it made
// a seconds-old divergence report DEGRADED with a multi-hour claim.
//
// The durations themselves live on DefaultHealthThresholds
// (PeerSyncDivergenceWarningAge / PeerSyncDivergenceDegradedAge).

// peerSyncDivergenceCondition returns the health condition for a persisted
// desired/actual mismatch, or nil when there is nothing to report. now is
// injected so the thresholds are exactly observable; the production caller
// passes the wall clock (issue #424 round 4).
//
// known is false when no divergence is being timed, i.e. DivergenceSince is
// zero, which means no reconcile has ever reached the point where both counts
// are known. Two cases produce that, and they are handled differently rather
// than inherited from the previous behavior:
//
//   - The system has never reconciled, so there is genuinely no evidence of
//     when anything happened. The age is stated as unknown and the severity
//     stays WARNING; inventing a large age here would report DEGRADED on a
//     system that has never synchronized at all.
//   - A fresh divergence on a system that has never had a SUCCESSFUL
//     reconcile. Here the synchronizer DID stamp a start on first
//     observation, so DivergenceSince is set and the age is known: the
//     mismatch began when it was first seen, regardless of whether any
//     earlier reconcile succeeded. It is therefore held to the same
//     thresholds as any other divergence, and is NOT reported as "age
//     unknown". This is the explicit decision required for the case where
//     LastSuccessfulReconcile is zero but the counts disagree: a brand new
//     system whose first reconcile installs 3 of 4 peers is a real,
//     just-begun divergence, not an unmeasurable one.
//
// A negative age (DivergenceSince stamped in the future, which a clock step
// backwards can produce) is clamped to zero and treated as younger than the
// warning threshold, so a clock adjustment cannot fabricate an escalation.
func peerSyncDivergenceCondition(peerSync *PeerSyncStatus, now time.Time) *HealthCondition {
	if peerSync.DesiredPeers == peerSync.ActualPeers {
		return nil
	}
	if peerSync.DivergenceSince.IsZero() {
		return &HealthCondition{
			Category: "peer_sync",
			Severity: "WARNING",
			Message: fmt.Sprintf("Peer sync divergence: %d desired vs %d actual peers "+
				"(divergence age unknown: no reconciliation has ever succeeded)",
				peerSync.DesiredPeers, peerSync.ActualPeers),
		}
	}
	age := now.Sub(peerSync.DivergenceSince)
	if age < 0 {
		age = 0
	}
	switch {
	case age > DefaultHealthThresholds.PeerSyncDivergenceDegradedAge:
		return &HealthCondition{
			Category: "peer_sync",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("Peer sync divergence for %s: %d desired vs %d actual peers",
				age.Round(time.Second), peerSync.DesiredPeers, peerSync.ActualPeers),
		}
	case age > DefaultHealthThresholds.PeerSyncDivergenceWarningAge:
		return &HealthCondition{
			Category: "peer_sync",
			Severity: "WARNING",
			Message: fmt.Sprintf("Peer sync divergence for %s: %d desired vs %d actual peers",
				age.Round(time.Second), peerSync.DesiredPeers, peerSync.ActualPeers),
		}
	default:
		// Converging, or younger than the warning threshold: not a condition.
		return nil
	}
}

func evaluatePeerSyncAndBackendConditions(peerSync *PeerSyncStatus, backends BackendsDiagnostics, handshake HandshakeFreshnessDiagnostics) []HealthCondition {
	var conds []HealthCondition
	now := time.Now()
	if peerSync != nil {
		if peerSync.PortalConfigRestartRequired {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message:  "Portal configuration changed; engine restart is required to apply updates",
			})
		}
		// InvalidRows is STICKY (issue #424 round 4, item G), for the same
		// reason LastError is: it is durable STATE, not a rate. Every
		// reconcile re-derives it from the durable rows (peer_sync.go:671), so
		// it goes to 0 the moment the rows are repaired, and a failed durable
		// read returns BEFORE that assignment, so a transient read glitch
		// cannot clear it either. That is what keeps it clear of the round-3
		// trap: the lifetime counters (SyncFailures and friends) only ever
		// grow, so they are exposed as history and gated on their windowed
		// deltas. InvalidRows is not such a counter; it is a level recomputed
		// from durable state on every pass, so gating on it cannot pin health
		// forever and cannot be missed by a delta that has gone quiet.
		//
		// DEGRADED rather than CRITICAL: an invalid row is excluded from the
		// desired set, so its peer is simply not enforced upstream and its
		// traffic is unauthorized and dropped. That is a real, unrecoverable-
		// by-retry service gap for the affected peer, but every other peer
		// still reconciles normally, so the dataplane as a whole keeps serving
		// and CRITICAL would overstate the blast radius.
		if peerSync.InvalidRows > 0 {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message: fmt.Sprintf("%d invalid durable peer row(s) excluded from the desired set; "+
					"those peers are not enforced upstream and their traffic is unauthorized until the rows are repaired",
					peerSync.InvalidRows),
			})
		}
		// An UNRESOLVED reconciliation failure is sticky and is gated on
		// LastError, not on the windowed deltas (issue #424 round 3,
		// finding 2). The deltas are a rate: the tracker reports 0 on its
		// first observation (baseline establishment) and falls back to 0
		// once the cumulative counter stops rising, so a delta-only gate
		// reports HEALTHY while the last reconcile is still failing.
		// LastError is set by peerSynchronizer.fail and cleared ONLY by a
		// successful reconcile (peer_sync.go), which makes it exactly the
		// "degraded until recovery" signal the health surface needs.
		//
		// LastEnqueueError deliberately does NOT gate here: nothing in the
		// peer synchronizer ever clears it, so treating it as sticky would
		// pin DEGRADED permanently after a single transient enqueue
		// failure. Enqueue failures stay gated on their windowed delta.
		if peerSync.LastError != "" {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message: fmt.Sprintf("Unresolved peer sync failure: %s (last successful reconcile %s; "+
					"recent activity: %d sync, %d enqueue failures in the last %.1fs; %d sync, %d enqueue cumulative)",
					clampDiagnosticText(peerSync.LastError, maxDiagnosticErrorTextLen),
					describeLastSuccessfulReconcile(peerSync.LastSuccessfulReconcile),
					peerSync.SyncFailuresRecent, peerSync.EnqueueFailuresRecent, peerSync.FailuresWindowSec,
					peerSync.SyncFailures, peerSync.EnqueueFailures),
			})
		} else if peerSync.SyncFailuresRecent > 0 || peerSync.EnqueueFailuresRecent > 0 {
			conds = append(conds, HealthCondition{
				Category: "peer_sync",
				Severity: "DEGRADED",
				Message: fmt.Sprintf("Active peer sync failures: %d sync, %d enqueue in the last %.1fs "+
					"(%d sync, %d enqueue cumulative)",
					peerSync.SyncFailuresRecent, peerSync.EnqueueFailuresRecent, peerSync.FailuresWindowSec,
					peerSync.SyncFailures, peerSync.EnqueueFailures),
			})
		}
		if divergence := peerSyncDivergenceCondition(peerSync, now); divergence != nil {
			conds = append(conds, *divergence)
		}
	}

	// enabled is the population a FAILURE can be counted against. When eligibility
	// is known, that is the ENABLED count: a backend an operator disabled is an
	// operator decision, not a failure, so it must never contribute to a
	// degradation (issue #424 review round 9, blocker 4).
	//
	// HealthyCount already counts only ELIGIBLE backends (enabled AND active),
	// so HealthyCount < enabled is precisely "enabled backends that are not
	// carrying traffic". The disabled ones are absent from both sides of that
	// comparison, which is what keeps failed and disabled distinguishable
	// without any extra bookkeeping here.
	enabled := backends.TotalCount
	if backends.EligibilityKnown {
		enabled = backends.EnabledCount
	}
	if backends.HealthyCount == 0 && (backends.TotalCount > 0 || backends.EligibilityKnown) {
		message := "No healthy backends available to route traffic"
		if backends.TotalCount == 0 {
			message = "No backends configured to route traffic"
		} else if enabled == 0 {
			message = "All backends are administratively disabled; no traffic can be routed"
		}
		conds = append(conds, HealthCondition{
			Category: "backend",
			Severity: "CRITICAL",
			Message:  message,
		})
	} else if enabled > 0 && backends.HealthyCount < enabled {
		// DEGRADED, not WARNING. #424 specifies DEGRADED for a degraded
		// backend, and summarizeHealthConditions maps WARNING-only to
		// HEALTHY, so a WARNING here reported two enabled backends with one
		// healthy as HEALTHY (issue #424 review round 9, blocker 4).
		//
		// CRITICAL is deliberately reserved for the branch above: with no
		// healthy backend at all there is nowhere to route traffic, which is a
		// categorically different condition from losing part of a fleet that
		// still has somewhere to send packets.
		//
		// The message names the enabled population so the count cannot be
		// misread against TotalCount: a disabled backend is neither healthy nor
		// failed, and an operator seeing "1 of 2" must be able to tell which two.
		conds = append(conds, HealthCondition{
			Category: "backend",
			Severity: "DEGRADED",
			Message: fmt.Sprintf("%d of %d enabled backends are degraded or unavailable "+
				"(%d administratively disabled, not counted as failures)",
				enabled-backends.HealthyCount, enabled, backends.DisabledCount),
		})
	}

	if len(handshake.StaleLiveSessions) > 0 {
		conds = append(conds, HealthCondition{
			Category:   "sessions",
			Severity:   "WARNING",
			MessageKey: "vpn_problem_stale_handshake",
			Message: fmt.Sprintf("%d active live session(s) have stale upstream handshakes (> %s)",
				len(handshake.StaleLiveSessions), DefaultHealthThresholds.HandshakeStaleAge),
		})
	}
	return conds
}

func summarizeHealthConditions(conditions []HealthCondition) (string, string) {
	var criticalCount, degradedCount, warningCount int
	for _, c := range conditions {
		switch c.Severity {
		case "CRITICAL":
			criticalCount++
		case "DEGRADED":
			degradedCount++
		case "WARNING":
			warningCount++
		}
	}

	// firstMessageAtSeverity returns the message of the first condition at the
	// winning severity, so the headline describes the condition that actually
	// set the headline (issue #424 round 2, finding 7).
	firstMessageAtSeverity := func(severity string) string {
		for _, c := range conditions {
			if c.Severity == severity {
				return c.Message
			}
		}
		return ""
	}

	if criticalCount > 0 {
		return HealthCritical, fmt.Sprintf("%d critical issue(s) affecting forwarder health: %s",
			criticalCount, firstMessageAtSeverity("CRITICAL"))
	}
	if degradedCount > 0 {
		return HealthDegraded, fmt.Sprintf("%d degradation condition(s) detected: %s",
			degradedCount, firstMessageAtSeverity("DEGRADED"))
	}
	if warningCount > 0 {
		return HealthHealthy, fmt.Sprintf("Operational with %d warning condition(s): %s",
			warningCount, firstMessageAtSeverity("WARNING"))
	}
	return HealthHealthy, "All forwarder and dataplane components are operating normally"
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

func (s *Service) startRollingHistory() {
	s.mu.Lock()
	if s.rollingHistory == nil {
		s.rollingHistory = NewRollingHistory()
	}
	if s.historyStopCh != nil {
		s.mu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	s.historyStopCh = stopCh
	s.historyDoneCh = doneCh
	fwd := s.forwarder
	s.mu.Unlock()
	s.primeHistory(time.Now(), fwd)

	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				s.sampleRollingHistory()
			}
		}
	}()
}

func (s *Service) stopRollingHistory() {
	s.mu.Lock()
	stopCh := s.historyStopCh
	doneCh := s.historyDoneCh
	s.historyStopCh = nil
	s.historyDoneCh = nil
	s.mu.Unlock()

	if stopCh != nil {
		close(stopCh)
		select {
		case <-doneCh:
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *Service) primeHistory(now time.Time, fwd *forwarder.Forwarder) {
	inputs := s.captureDiagnosticsInputs()
	s.primeHistoryFromDrops(now, fwd, inputs.generation, inputs.collectDropCategories())
}

// historyPrimedForCurrentGenerationLocked reports whether the history
// baselines are already primed FOR THE CURRENT generation. It requires
// s.diagRatesMu. The priming state is keyed to s.diagGeneration (issue #429
// review blocker 1): after a lifecycle reset in Service.Start the generation
// no longer matches, so priming is re-done instead of the sticky flag
// suppressing history for the process lifetime.
func (s *Service) historyPrimedForCurrentGenerationLocked() bool {
	return s.historyPrimed && s.historyPrimedGen == diagGeneration(s.diagGeneration.Load())
}

func (s *Service) primeHistoryFromDrops(now time.Time, fwd *forwarder.Forwarder, gen diagGeneration, drops DropCategoryBreakdown) {
	// Generation rejection happens FIRST, under diagRatesMu, before ANY
	// mutation (issue #429 review round 5, blocker 1). The previous order
	// primed and marked with the tracker-current generation substituted for
	// the observation's and only then ran the stale guard, so a stale
	// pre-restart snapshot resuming between the lifecycle reset and the new
	// generation's first genuine collection re-baselined the new generation
	// from old high totals and its primed-mark suppressed the genuine
	// re-prime.
	//
	// gen != current, not gen < current: priming must record the live
	// generation the baselines actually belong to, so only an observation
	// captured under it may prime or mark. A generation lower than current
	// is a pre-restart snapshot; a higher one cannot legitimately occur (the
	// generation travels inside the snapshot and only resetDiagnostics-
	// Generation bumps it under diagRatesMu), but priming or marking on one
	// would equally suppress the CURRENT generation's genuine re-prime.
	s.diagRatesMu.Lock()
	current := s.currentDiagGeneration()
	if gen != current {
		s.diagRatesMu.Unlock()
		return
	}
	// historyPrimed is NOT a sticky flag: it is the per-generation priming
	// state (accepted gen == current gen && baselines exist), so a new
	// generation from Service.Start re-primes here automatically instead of
	// the call returning early forever (issue #429 review blocker 1, Stop/
	// Start epoch reuse). The per-generation keying matters: after a bump
	// the mark is still true but recorded for the OLD generation, so the
	// first genuine observation of the new one re-primes and re-marks.
	if s.historyPrimedForCurrentGenerationLocked() {
		s.diagRatesMu.Unlock()
		return
	}
	// Prime with the OBSERVATION'S generation. Both checks above ran under
	// this lock hold, so gen == current here: the recorded historyPrimedGen
	// is the live generation and the mark can never stand in for a newer
	// one.
	s.primeHistoryRatesLocked(gen, now, &drops)
	s.historyPrimedGen = gen
	s.historyPrimed = true
	s.diagRatesMu.Unlock()

	// The forwarder's own history baselines carry independent locks, so they
	// prime after the diagRatesMu release — but under the SAME generation
	// decision made above, before any mutation: a rejected snapshot primes
	// nothing, forwarder history included.
	if fwd != nil {
		fwd.PrimeHistoryRates(now)
		fwd.PrimeBackendTrafficHistory(now)
	}
}

func (s *Service) sampleRollingHistory() {
	now := time.Now()

	inputs := s.captureDiagnosticsInputs()
	rh, fwd, sessMgr := inputs.rollingHistory, inputs.forwarder, inputs.sessionMgr
	drops := inputs.collectDropCategories()

	if rh == nil {
		return
	}

	s.diagRatesMu.Lock()
	isPrimed := s.historyPrimedForCurrentGenerationLocked()
	s.diagRatesMu.Unlock()

	if !isPrimed {
		s.primeHistoryFromDrops(now, fwd, inputs.generation, drops)
	}

	// 1. Forwarder traffic rates (independent history baseline)
	var fRates forwarder.TrafficRates
	if fwd != nil {
		fRates = fwd.HistoryRates(now)
	}
	// History samples use the generation the snapshot was captured under
	// (issue #429 review round 4, blocker 1): a snapshot taken before a
	// lifecycle reset can never advance the new generation's baselines.
	s.sampleHistoryDropRates(inputs.generation, now, &drops)

	// 3. Queue utilization
	var queueUtilPct float64
	if fwd != nil {
		occ, cap, _ := fwd.AggregateQueueStats()
		if cap > 0 {
			queueUtilPct = float64(occ) / float64(cap) * 100.0
		}
	}

	// 4. Latency
	var fwdP95MS float64
	var fwdP95Samples int
	if fwd != nil {
		writes := fwd.DeviceWriteSnapshot()
		fwdP95MS = float64(writes.P95HealthDuration.Microseconds()) / 1000.0
		fwdP95Samples = writes.P95HealthSamples
	}

	// 5. Active routes
	activeRoutes := 0
	if fwd != nil {
		activeRoutes = fwd.ActiveRoutesCount()
	}

	// 6. Connected sessions
	activeSessions := 0
	if sessMgr != nil {
		activeSessions = sessMgr.ActiveCount()
	}

	// 7. Backends diagnostics with history traffic snapshot
	var traffic map[int64]forwarder.TrafficSnapshot
	if fwd != nil {
		traffic = fwd.BackendTrafficHistorySnapshot(now)
	}
	beDiag := inputs.collectBackendDiagnosticsWithTraffic(traffic)
	backends, omitted := backendHistory(beDiag.Backends)

	point := HistoryPoint{
		RxPps:                 fRates.RxPps,
		TxPps:                 fRates.TxPps,
		TrafficAvailable:      fRates.Available,
		DropRatesAvailable:    drops.RatesAvailable,
		DropReasonRates:       drops.ReasonRates,
		ActiveRoutes:          activeRoutes,
		BackendLatencySamples: beDiag.LatencySamples,
		Backends:              backends,
		BackendsOmitted:       omitted,
		Timestamp:             now.Unix(),
		RxBps:                 fRates.RxBps,
		TxBps:                 fRates.TxBps,
		QueueUtilPct:          queueUtilPct,
		TotalDropRate:         drops.TotalDropRatePps,
		ForwardP95MS:          fwdP95MS,
		ForwardP95Samples:     fwdP95Samples,
		ActiveSessions:        activeSessions,
		BackendP95MS:          beDiag.LatencyP95MS,
	}

	rh.Add(point)
}

// diagRatesTracker provides thread-safe sampling and independent rate computation
// for device write errors, client drops, return drops, and overall dataplane drops.
//
// Its baseline bookkeeping delegates to the ONE reusable generation-aware
// window primitive (generationWindow, issue #429 review blocker 1): within a
// generation an accepted baseline is monotonic — a stale LOWER observation
// reports zero deltas and never replaces the baseline — and a lifecycle reset
// re-primes instead of inferring a restart from counters that moved backwards.
type diagRatesTracker struct {
	mu sync.Mutex
	// window is generation-aware; priming semantics are unchanged (issue
	// #424 round 8, finding 2): the first sample captures lastSampleTime AND
	// every counter baseline and reports zero rates. primed stays a tracker
	// field on purpose — the round-8 audit pins an unprimed constructor via
	// tk.primed, and it must never be derived from lastSampleTime being zero.
	// The generation travels with the observation (issue #429 review round
	// 4, blocker 1): Sample takes it explicitly instead of reading a
	// tracker-current field, so a snapshot captured before a lifecycle reset
	// can never be sampled against the new generation.
	primed         bool
	window         generationWindow[float64]
	lastSampleTime time.Time

	clientDropRate float64
	returnDropRate float64
	totalDropRate  float64
	writeErrorRate float64
}

// newDiagRatesTracker returns an UNPRIMED tracker. lastSampleTime and every
// counter baseline are captured by the first Sample call, so a counter that has
// been accumulating since process start is never reported as a fresh incident
// (issue #424 round 8, finding 2). Seeding the timestamp here would make the
// priming branch in Sample dead code.
func newDiagRatesTracker() *diagRatesTracker {
	return &diagRatesTracker{}
}

// Sample records the cumulative drop counters and reports the per-second rates
// of the newly accepted window. The generation travels with the observation
// (issue #429 review round 4, blocker 1): callers pass the generation the
// snapshot was captured under, never a tracker-current value. Only
// observations >= the accepted baseline advance it; an older/lower observation
// reports the previous window and leaves the baseline unchanged (issue #429
// review blocker 1).
func (t *diagRatesTracker) Sample(gen diagGeneration, now time.Time, clientDrops, returnDrops, totalDrops, writeErrors uint64) (clientDropRate, returnDropRate, totalDropRate, writeErrorRate float64) {
	if t == nil {
		return 0, 0, 0, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.primed {
		// First sample: prime time AND every counter baseline, report zero.
		t.primed = true
		t.window.sample(gen, now, []uint64{clientDrops, returnDrops, totalDrops, writeErrors})
		t.lastSampleTime = now
		return 0, 0, 0, 0
	}
	if accepted := t.window.sample(gen, now, []uint64{clientDrops, returnDrops, totalDrops, writeErrors}); !accepted {
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate
	}
	deltas, elapsed, _ := t.window.last()

	t.clientDropRate = deltas[0] / elapsed
	t.returnDropRate = deltas[1] / elapsed
	// deltas[2] is the TotalDrops counter (issue #429 review round 4,
	// blocker 2): the total rate must come from the total counter, not the
	// client+return sum — the direction-neutral backend_device_unattributed
	// bucket is in TotalDrops but in neither directional total, so the sum
	// under-reported the conserved total.
	t.totalDropRate = deltas[2] / elapsed
	// deltas[3] is the writeErrors counter.
	t.writeErrorRate = deltas[3] / elapsed
	t.lastSampleTime = now

	return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate
}

// reset re-primes the tracker for a new diagnostics generation: subsequent
// samples are tagged with the generation their snapshot captured, and the
// window re-primes on its next call (issue #429 review blocker 1). A
// generation lower than the accepted one is ignored.
func (t *diagRatesTracker) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.reset(gen) {
		return
	}
	t.primed = false
	t.lastSampleTime = time.Time{}
	t.clientDropRate, t.returnDropRate = 0, 0
	t.totalDropRate, t.writeErrorRate = 0, 0
}

// diagDeltaTracker measures the increase of a single lifetime counter over
// the last sampling window, so a cumulative failure counter can stay visible as
// history without permanently degrading current health (issue #424 round 2,
// finding 5).
//
// Its baseline bookkeeping delegates to the ONE reusable generation-aware
// window primitive (generationWindow, issue #429 review blocker 1): within a
// generation the accepted baseline is monotonic — a stale LOWER observation
// reports zero and never rewinds the baseline — and Reset re-primes on an
// explicit new generation instead of inferring a restart from current<previous.
type diagDeltaTracker struct {
	mu sync.Mutex
	// window owns its own locking; mu guards only the WRAPPER state below
	// (the published snapshot), which Sample reads and reset clears
	// without any other synchronization (issue #429 review round 3,
	// blocker 1 — the "each has its own mutex" claim was false for the
	// wrapper fields). The generation travels with the observation (issue
	// #429 review round 4, blocker 1): Sample takes it explicitly instead
	// of reading a tracker-current field.
	window        generationWindow[uint64]
	delta         uint64
	windowSeconds float64
}

// deltaSnapshot is an immutable read of the tracker's last computed delta.
type deltaSnapshot struct {
	delta         uint64
	windowSeconds float64
}

// Sample records cumulative and returns the increase since the previous
// accepted sample. The generation travels with the observation (issue #429
// review round 4, blocker 1): callers pass the generation the snapshot was
// captured under, never a tracker-current value. The first sample only primes
// the baseline and reports zero, so a counter that has been rising since
// process start is never reported as a fresh incident. Resampling sooner than
// 200ms reuses the previous delta rather than dividing by a near-zero window.
// A stale LOWER observation reports no new loss AND leaves the accepted
// baseline unchanged, so later activity up to the previously accepted value
// can never be replayed as a fresh delta (issue #429 review blocker 1).
func (t *diagDeltaTracker) Sample(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	snap, _ := t.sample(gen, now, cumulative)
	return snap
}

func (t *diagDeltaTracker) sample(gen diagGeneration, now time.Time, cumulative uint64) (deltaSnapshot, bool) {
	if t == nil {
		return deltaSnapshot{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if accepted := t.window.sample(gen, now, []uint64{cumulative}); !accepted {
		return deltaSnapshot{delta: t.delta, windowSeconds: t.windowSeconds}, false
	}
	deltas, elapsed, _ := t.window.last()
	t.delta = deltas[0]
	t.windowSeconds = elapsed
	return deltaSnapshot{delta: t.delta, windowSeconds: t.windowSeconds}, true
}

// reset re-primes the tracker for a new diagnostics generation: subsequent
// samples are tagged with the generation their snapshot captured, and the
// window re-primes on its next call (issue #429 review blocker 1). A
// generation lower than the accepted one is ignored.
func (t *diagDeltaTracker) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.reset(gen) {
		return
	}
	t.delta = 0
	t.windowSeconds = 0
}

// diagDeltaTrackers groups the per-counter windowed delta trackers. Each has
// its own mutex (both the wrapper state and the embedded window are
// synchronized), so a caller needs no outer lock.
type diagDeltaTrackers struct {
	ownershipMismatch diagDeltaTracker
	// clientOwnershipMismatch tracks the CLIENT-direction counterpart. It is a
	// separate tracker, not a second field on the return one, because the two
	// counters rise independently: sharing a tracker would let a burst in one
	// direction mask a quiet window in the other, which is the invisibility
	// blocker 3 exists to remove (issue #424 review round 9).
	clientOwnershipMismatch diagDeltaTracker
	syncFailures            diagDeltaTracker
	enqueueFailures         diagDeltaTracker
	writeStalls             diagDeltaTracker
	reasons                 dropReasonRatesTracker

	returnConsecutiveMu              sync.Mutex
	returnConsecutiveHighRateWindows int
}

func (t *diagDeltaTrackers) sampleOwnershipMismatch(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	if t == nil {
		return deltaSnapshot{}
	}
	snap, accepted := t.ownershipMismatch.sample(gen, now, cumulative)
	t.returnConsecutiveMu.Lock()
	defer t.returnConsecutiveMu.Unlock()
	if accepted {
		th := defaultHealthThresholds()
		var rate float64
		if snap.windowSeconds > 0 {
			rate = float64(snap.delta) / snap.windowSeconds
		}
		if rate >= th.ReturnOwnershipMismatchDegradedRatePPS {
			t.returnConsecutiveHighRateWindows++
		} else {
			t.returnConsecutiveHighRateWindows = 0
		}
	} else if snap.windowSeconds == 0 {
		// Priming sample or generation reset: reset consecutive counter.
		t.returnConsecutiveHighRateWindows = 0
	}
	// A throttled (<200ms) or stale rejected sample leaves returnConsecutiveHighRateWindows
	// unchanged so repeated reads within one collection agree.
	return snap
}

func (t *diagDeltaTrackers) consecutiveHighRateWindows() int {
	if t == nil {
		return 0
	}
	t.returnConsecutiveMu.Lock()
	defer t.returnConsecutiveMu.Unlock()
	return t.returnConsecutiveHighRateWindows
}

func (t *diagDeltaTrackers) sampleClientOwnershipMismatch(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	return t.clientOwnershipMismatch.Sample(gen, now, cumulative)
}

func (t *diagDeltaTrackers) sampleSyncFailures(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	return t.syncFailures.Sample(gen, now, cumulative)
}

func (t *diagDeltaTrackers) sampleEnqueueFailures(gen diagGeneration, now time.Time, cumulative uint64) deltaSnapshot {
	return t.enqueueFailures.Sample(gen, now, cumulative)
}

// reset re-primes every sub-tracker — ownership mismatch (both directions),
// peer-sync failures, enqueue failures, write stalls and the per-reason drop
// rates — for a new diagnostics generation (issue #429 review blocker 1).
func (t *diagDeltaTrackers) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.returnConsecutiveMu.Lock()
	t.returnConsecutiveHighRateWindows = 0
	t.returnConsecutiveMu.Unlock()
	t.ownershipMismatch.reset(gen)
	t.clientOwnershipMismatch.reset(gen)
	t.syncFailures.reset(gen)
	t.enqueueFailures.reset(gen)
	t.writeStalls.reset(gen)
	t.reasons.reset(gen)
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

// problemOnsetTracker retains the original onset timestamp of active actionable problems
// across polling ticks, clearing resolved problems when they recover.
type problemOnsetTracker struct {
	mu     sync.Mutex
	onsets map[string]time.Time
}

// ProblemOnsetTracker is the exported alias for problemOnsetTracker.
type ProblemOnsetTracker = problemOnsetTracker

func newProblemOnsetTracker() *problemOnsetTracker {
	return &problemOnsetTracker{
		onsets: make(map[string]time.Time),
	}
}

// NewProblemOnsetTracker creates a new persistent problem onset tracker.
func NewProblemOnsetTracker() *ProblemOnsetTracker {
	return newProblemOnsetTracker()
}

func (s *Service) getProblemOnsetTracker() *problemOnsetTracker {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.problemOnset == nil {
		s.problemOnset = newProblemOnsetTracker()
	}
	return s.problemOnset
}

// SynthesizeActionableProblems derives per-session/route actionable problem records
// by correlating active routes, route pressure, and active VPN sessions.
func SynthesizeActionableProblems(routes []forwarder.RouteInfo, sessions []Session) []ActionableProblem {
	return SynthesizeActionableProblemsAt(routes, sessions, time.Now().UTC())
}

// SynthesizeActionableProblemsWithTracker derives per-session/route actionable problem records
// using a persistent onset tracker to retain onset across polling ticks.
func SynthesizeActionableProblemsWithTracker(routes []forwarder.RouteInfo, sessions []Session, observedAt time.Time, tracker *ProblemOnsetTracker) []ActionableProblem {
	return SynthesizeActionableProblemsAt(routes, sessions, observedAt, tracker)
}

// SynthesizeActionableProblemsWithHandshakes derives per-session/route actionable problem records
// by correlating active routes, route pressure, active VPN sessions, and peer handshakes.
func SynthesizeActionableProblemsWithHandshakes(routes []forwarder.RouteInfo, sessions []Session, peerHandshakes map[string]time.Time, observedAt time.Time, tracker ...*problemOnsetTracker) []ActionableProblem {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	problems := synthesizeUnroutableSessionProblems(routes, sessions, observedAt)
	for _, r := range routes {
		sess, hasSess := findSessionForRoute(r, sessions)
		problems = append(problems, synthesizeRoutePressureProblems(r, sess, hasSess, observedAt)...)
	}
	problems = append(problems, synthesizeStaleHandshakeProblems(sessions, peerHandshakes, observedAt)...)

	var tr *problemOnsetTracker
	if len(tracker) > 0 && tracker[0] != nil {
		tr = tracker[0]
	}

	if tr != nil {
		activeKeys := make(map[string]struct{}, len(problems))
		tr.mu.Lock()
		for i := range problems {
			p := &problems[i]
			sessID := p.SessionID
			if sessID == "" {
				sessID = p.AssignedIP
			}
			msgKey := p.MessageKey
			if msgKey == "" {
				msgKey = p.Category
			}
			key := fmt.Sprintf("%s:%s:%s:%s:%d", p.Category, msgKey, sessID, p.ConnectionID, p.BackendID)
			activeKeys[key] = struct{}{}
			if existing, ok := tr.onsets[key]; ok && !existing.IsZero() {
				p.FirstObserved = existing
			} else {
				tr.onsets[key] = p.FirstObserved
			}
		}
		for k := range tr.onsets {
			if _, active := activeKeys[k]; !active {
				delete(tr.onsets, k)
			}
		}
		tr.mu.Unlock()
	}

	sortActionableProblems(problems)
	return problems
}

// SynthesizeActionableProblemsAt derives per-session/route actionable problem records
// relative to an explicit observation timestamp, optionally persisting onset via a tracker.
func SynthesizeActionableProblemsAt(routes []forwarder.RouteInfo, sessions []Session, observedAt time.Time, tracker ...*problemOnsetTracker) []ActionableProblem {
	return SynthesizeActionableProblemsWithHandshakes(routes, sessions, nil, observedAt, tracker...)
}

func findSessionForRoute(r forwarder.RouteInfo, sessions []Session) (Session, bool) {
	// Priority 1: Exact Session ID match
	if r.SessionID != "" {
		for _, s := range sessions {
			if s.ID == r.SessionID {
				return s, true
			}
		}
	}

	// Priority 2: Peer key fallback
	// Permitted ONLY when session ID is absent on one/both sides (r.SessionID == "" || s.ID == "").
	// If both provide a session ID and they differ, s is strictly disqualified from matching r.
	if r.PeerKey != "" {
		for _, s := range sessions {
			if s.PeerPublicKey == r.PeerKey {
				if r.SessionID != "" && s.ID != "" && r.SessionID != s.ID {
					continue
				}
				return s, true
			}
		}
	}

	// Priority 3: IP fallback
	// Permitted ONLY when both session ID and peer key are absent on one/both sides.
	// If session IDs contradict, or if peer keys contradict, fallback is strictly forbidden.
	if r.AssignedIP != "" {
		for _, s := range sessions {
			if s.AssignedIP == r.AssignedIP {
				if r.SessionID != "" && s.ID != "" && r.SessionID != s.ID {
					continue
				}
				if r.PeerKey != "" && s.PeerPublicKey != "" && r.PeerKey != s.PeerPublicKey {
					continue
				}
				rAbsent := r.SessionID == "" && r.PeerKey == ""
				sAbsent := s.ID == "" && s.PeerPublicKey == ""
				if rAbsent || sAbsent {
					return s, true
				}
			}
		}
	}
	return Session{}, false
}

func synthesizeUnroutableSessionProblems(routes []forwarder.RouteInfo, sessions []Session, observedAt time.Time) []ActionableProblem {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	routesByPeerWithoutSession := make(map[string]struct{}, len(routes))
	routesBySessionID := make(map[string]struct{}, len(routes))
	untaggedRoutesByIP := make(map[string]struct{}, len(routes))
	for _, r := range routes {
		if r.SessionID != "" {
			routesBySessionID[r.SessionID] = struct{}{}
		} else if r.PeerKey != "" {
			routesByPeerWithoutSession[r.PeerKey] = struct{}{}
		}
		if r.SessionID == "" && r.PeerKey == "" && r.AssignedIP != "" {
			untaggedRoutesByIP[r.AssignedIP] = struct{}{}
		}
	}

	var problems []ActionableProblem
	for _, sess := range sessions {
		if sess.Status != "" && sess.Status != "connected" {
			continue
		}
		hasSess := false
		if sess.ID != "" {
			_, hasSess = routesBySessionID[sess.ID]
		}
		hasPeer := false
		if sess.PeerPublicKey != "" {
			_, hasPeer = routesByPeerWithoutSession[sess.PeerPublicKey]
		}
		hasUntaggedIP := false
		if sess.AssignedIP != "" {
			_, hasUntaggedIP = untaggedRoutesByIP[sess.AssignedIP]
		}
		if !hasSess && !hasPeer && !hasUntaggedIP {
			problems = append(problems, ActionableProblem{
				Severity:       "CRITICAL",
				Category:       "routing",
				Message:        fmt.Sprintf("Active session %s has no forwarder route", sess.ID),
				MessageKey:     "vpn_problem_session_without_route",
				UserID:         sess.UserID,
				SessionID:      sess.ID,
				ConnectionName: sess.ConnectionName,
				AssignedIP:     sess.AssignedIP,
				BackendID:      sess.BackendTunnelID,
				FirstObserved:  observedAt,
			})
		}
	}
	return problems
}

func synthesizeStaleHandshakeProblems(sessions []Session, peerHandshakes map[string]time.Time, observedAt time.Time) []ActionableProblem {
	if peerHandshakes == nil {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	var problems []ActionableProblem
	for _, sess := range sessions {
		if sess.PeerPublicKey == "" {
			continue
		}
		hs, ok := peerHandshakes[sess.PeerPublicKey]
		if !ok || hs.IsZero() || observedAt.Sub(hs) > DefaultHealthThresholds.HandshakeStaleAge {
			problems = append(problems, ActionableProblem{
				Severity:       "WARNING",
				Category:       "sessions",
				Message:        fmt.Sprintf("Upstream handshake stale (> %s)", DefaultHealthThresholds.HandshakeStaleAge),
				MessageKey:     "vpn_problem_stale_handshake",
				SessionID:      sess.ID,
				UserID:         sess.UserID,
				Username:       sess.Username,
				ConnectionID:   sess.ConnectionID,
				ConnectionName: sess.ConnectionName,
				AssignedIP:     sess.AssignedIP,
				BackendID:      sess.BackendTunnelID,
				FirstObserved:  observedAt,
			})
		}
	}
	return problems
}

func synthesizeRoutePressureProblems(r forwarder.RouteInfo, sess Session, hasSess bool, observedAt time.Time) []ActionableProblem {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	var problems []ActionableProblem
	var userID, connName string
	if hasSess {
		userID = sess.UserID
		connName = sess.ConnectionName
	}
	sessionID := r.SessionID
	if sessionID == "" && hasSess {
		sessionID = sess.ID
	}
	connID := r.ConnectionID
	firstObserved := observedAt

	if r.Stats.QueueFullDropsRecent > 0 || r.Stats.QueueFullDropRatePPS > 0 {
		var rate string
		if r.Stats.QueueFullDropRatePPS > 0 {
			rate = fmt.Sprintf("%.1f drops/s", r.Stats.QueueFullDropRatePPS)
		} else if r.Stats.QueueFullDropsRecent > 0 {
			rate = fmt.Sprintf("%d drops/window", r.Stats.QueueFullDropsRecent)
		}
		problems = append(problems, ActionableProblem{
			Severity:       "DEGRADED",
			Category:       "dataplane",
			Message:        fmt.Sprintf("Return queue full drops (%d recent) for %s", r.Stats.QueueFullDropsRecent, r.AssignedIP),
			MessageKey:     "vpn_problem_route_queue_drops",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   rate,
			FirstObserved:  firstObserved,
		})
	}

	if r.Stats.WriteStallsRecent > 0 || r.Stats.OldestWriteMS >= 100 {
		sev := "WARNING"
		if r.Stats.OldestWriteMS >= 2000 {
			sev = "CRITICAL"
		} else if r.Stats.OldestWriteMS >= 500 || r.Stats.WriteStallsRecent > 0 {
			sev = "DEGRADED"
		}
		msg := fmt.Sprintf("Device write stall (%dms) for %s", r.Stats.OldestWriteMS, r.AssignedIP)
		rate := fmt.Sprintf("%dms stall", r.Stats.OldestWriteMS)
		if r.Stats.OldestWriteMS == 0 && r.Stats.WriteStallsRecent > 0 {
			msg = fmt.Sprintf("Device write stalls (%d recent) for %s", r.Stats.WriteStallsRecent, r.AssignedIP)
			rate = fmt.Sprintf("%d stalls", r.Stats.WriteStallsRecent)
		}
		stallFirstObserved := firstObserved
		if r.Stats.OldestWriteMS > 0 {
			stallFirstObserved = firstObserved.Add(-time.Duration(r.Stats.OldestWriteMS) * time.Millisecond)
		}
		if stallFirstObserved.After(firstObserved) {
			stallFirstObserved = firstObserved
		}
		problems = append(problems, ActionableProblem{
			Severity:       sev,
			Category:       "dataplane",
			Message:        msg,
			MessageKey:     "vpn_problem_write_stall",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   rate,
			FirstObserved:  stallFirstObserved,
		})
	}

	if r.Stats.WriteErrorsRecent > 0 {
		problems = append(problems, ActionableProblem{
			Severity:       "DEGRADED",
			Category:       "dataplane",
			Message:        fmt.Sprintf("Device write errors (%d recent) for %s", r.Stats.WriteErrorsRecent, r.AssignedIP),
			MessageKey:     "vpn_problem_write_errors",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   fmt.Sprintf("%d errors", r.Stats.WriteErrorsRecent),
			FirstObserved:  firstObserved,
		})
	}

	if r.HasPressure && r.Stats.QueueFullDropsRecent == 0 && r.Stats.WriteStallsRecent == 0 && r.Stats.WriteErrorsRecent == 0 && r.Stats.OldestWriteMS < 100 {
		pct := 0.0
		if r.Stats.Capacity > 0 {
			pct = float64(r.Stats.Occupancy) / float64(r.Stats.Capacity) * 100
		}
		problems = append(problems, ActionableProblem{
			Severity:       "WARNING",
			Category:       "queue_pressure",
			Message:        fmt.Sprintf("Route queue pressure (%d/%d queued) for %s", r.Stats.Occupancy, r.Stats.Capacity, r.AssignedIP),
			MessageKey:     "vpn_problem_route_queue_pressure",
			UserID:         userID,
			SessionID:      sessionID,
			ConnectionID:   connID,
			ConnectionName: connName,
			AssignedIP:     r.AssignedIP,
			BackendID:      r.BackendTunnelID,
			ObservedRate:   fmt.Sprintf("%d/%d queued (%0.0f%%)", r.Stats.Occupancy, r.Stats.Capacity, pct),
			FirstObserved:  firstObserved,
		})
	}

	return problems
}

func sortActionableProblems(problems []ActionableProblem) {
	problemSeverityRank := func(sev string) int {
		switch strings.ToUpper(sev) {
		case "CRITICAL":
			return 1
		case "DEGRADED":
			return 2
		case "WARNING":
			return 3
		default:
			return 4
		}
	}
	sort.SliceStable(problems, func(i, j int) bool {
		ri, rj := problemSeverityRank(problems[i].Severity), problemSeverityRank(problems[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if problems[i].AssignedIP != problems[j].AssignedIP {
			return problems[i].AssignedIP < problems[j].AssignedIP
		}
		return problems[i].Category < problems[j].Category
	})
}

func (s *Service) fetchPeerIdentityMappings(ctx context.Context, peerKeys []string) (map[string]string, map[string]string) {
	connByPeer := make(map[string]string)
	userByPeer := make(map[string]string)
	if len(peerKeys) == 0 || s == nil || s.db == nil {
		return connByPeer, userByPeer
	}

	pkPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(peerKeys)), ",")
	pkArgs := make([]any, len(peerKeys))
	for i, pk := range peerKeys {
		pkArgs[i] = pk
	}
	query := `SELECT uc.client_id, uc.id, COALESCE(u.username, '')
		FROM user_connections uc
		LEFT JOIN users u ON u.id = uc.user_id
		WHERE uc.client_id IN (` + pkPlaceholders + `)`
	rows, err := s.db.QueryContext(ctx, query, pkArgs...)
	if err != nil {
		return connByPeer, userByPeer
	}
	defer rows.Close()
	for rows.Next() {
		var pk, connID, username string
		if err := rows.Scan(&pk, &connID, &username); err == nil {
			connByPeer[pk] = connID
			userByPeer[pk] = username
		}
	}
	return connByPeer, userByPeer
}

func (s *Service) synthesizeActionableProblems(routes []forwarder.RouteInfo, sessions []Session, peerHandshakes map[string]time.Time) []ActionableProblem {
	var tracker *problemOnsetTracker
	if s != nil {
		tracker = s.getProblemOnsetTracker()
	}
	problems := SynthesizeActionableProblemsWithHandshakes(routes, sessions, peerHandshakes, time.Now().UTC(), tracker)
	if len(problems) == 0 || s == nil || s.db == nil {
		return problems
	}

	return s.enrichActionableProblemsWithDatabase(problems, sessions)
}

func (s *Service) enrichActionableProblemsWithDatabase(problems []ActionableProblem, sessions []Session) []ActionableProblem {
	if len(problems) == 0 || s == nil || s.db == nil {
		return problems
	}

	peerKeys := make([]string, 0, len(sessions))
	for _, sess := range sessions {
		if sess.PeerPublicKey != "" {
			peerKeys = append(peerKeys, sess.PeerPublicKey)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connByPeer, userByPeer := s.fetchPeerIdentityMappings(ctx, peerKeys)

	for i := range problems {
		enrichSingleProblem(&problems[i], sessions, connByPeer, userByPeer)
	}

	return problems
}

func enrichSingleProblem(p *ActionableProblem, sessions []Session, connByPeer, userByPeer map[string]string) {
	if p.Username != "" && p.ConnectionID != "" {
		return
	}

	if p.SessionID != "" {
		if enrichBySessionID(p, sessions, connByPeer, userByPeer) {
			return
		}
	}

	if p.UserID != "" {
		enrichByUserID(p, sessions, connByPeer, userByPeer)
	}
}

func enrichBySessionID(p *ActionableProblem, sessions []Session, connByPeer, userByPeer map[string]string) bool {
	for _, sess := range sessions {
		if sess.ID == p.SessionID {
			if p.Username == "" {
				p.Username = userByPeer[sess.PeerPublicKey]
			}
			if p.ConnectionID == "" {
				p.ConnectionID = connByPeer[sess.PeerPublicKey]
			}
			if p.ConnectionName == "" {
				p.ConnectionName = sess.ConnectionName
			}
			return true
		}
	}
	return false
}

func enrichByUserID(p *ActionableProblem, sessions []Session, connByPeer, userByPeer map[string]string) {
	var matching []Session
	for _, sess := range sessions {
		if sess.UserID == p.UserID {
			matching = append(matching, sess)
		}
	}
	if len(matching) == 1 {
		sess := matching[0]
		if p.Username == "" {
			p.Username = userByPeer[sess.PeerPublicKey]
		}
		if p.ConnectionID == "" {
			p.ConnectionID = connByPeer[sess.PeerPublicKey]
		}
		if p.ConnectionName == "" {
			p.ConnectionName = sess.ConnectionName
		}
	} else if len(matching) > 1 {
		if p.Username == "" {
			for _, sess := range matching {
				if u := userByPeer[sess.PeerPublicKey]; u != "" {
					p.Username = u
					return
				}
			}
		}
	}
}
