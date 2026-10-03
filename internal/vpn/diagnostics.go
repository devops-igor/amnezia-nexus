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
}

// ForwarderHealthAssessment contains the overall rule-based health diagnosis.
type ForwarderHealthAssessment struct {
	Status     string            `json:"status"` // HEALTHY, DEGRADED, CRITICAL, UNAVAILABLE
	Summary    string            `json:"summary"`
	Conditions []HealthCondition `json:"conditions"`
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
	// ClientBackendDeviceUnattributed is live-device loss on a device that
	// cannot report the breakdown at all. Published so TotalDrops stays
	// truthful instead of silently shrinking.
	ClientBackendDeviceUnattributed uint64 `json:"client_backend_device_unattributed"`
	// ClientBackendDeviceRetired is retired CLIENT-DIRECTION loss: the
	// inbound (client -> backend) half of the lifetime accumulator for
	// devices that have left the map, plus the retired half of loss on devices
	// that never reported a direction.
	//
	// Retirement is a TRANSFER of the device's real breakdown, so retired
	// loss is published under the SAME key a live loss uses and its reason
	// survives: retired inbound queue-full loss appears in
	// ClientBackendDeviceQueueFull, not here. This key exists for the one
	// population with no reason to carry — loss attributed to the client
	// population with no direction recorded at all — which is why it is the
	// client-direction figure and not the retired TOTAL. The retired total is
	// the sum of every direction (clientTotal and returnTotal each include
	// their share).
	ClientBackendDeviceRetired uint64  `json:"client_backend_device_retired_drops"`
	ClientTotalDrops           uint64  `json:"client_total_drops"`
	ClientDropRatePps          float64 `json:"client_drop_rate_pps"`

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
	// OwnershipMismatchDropsRecent is the increase of OwnershipMismatchDrops
	// observed in the last diagnostics sampling window (issue #424 round 2,
	// finding 5). The cumulative value stays exposed as history; only the
	// recent delta gates current health, so a recovered incident no longer
	// pins routing as inconsistent forever.
	OwnershipMismatchDropsRecent uint64 `json:"ownership_mismatch_drops_recent"`
	// OwnershipMismatchWindowSec is the length of the sampling window behind
	// OwnershipMismatchDropsRecent.
	OwnershipMismatchWindowSec float64  `json:"ownership_mismatch_window_sec"`
	IsConsistent               bool     `json:"is_consistent"`
	InconsistencyDetails       []string `json:"inconsistency_details,omitempty"`
	// HistoricalDetails carries lifetime observations that are deliberately
	// NOT inconsistencies, so a reader can see the incident without the
	// headline status being pinned by it.
	HistoricalDetails []string `json:"historical_details,omitempty"`
}

// HandshakeFreshnessDiagnostics aggregates peer handshake distribution.
type HandshakeFreshnessDiagnostics struct {
	Under2mCount      int      `json:"under_2m_count"`
	Between2m5mCount  int      `json:"between_2m_5m_count"`
	Over5mCount       int      `json:"over_5m_count"`
	NeverCount        int      `json:"never_count"`
	TotalPeers        int      `json:"total_peers"`
	StaleLiveSessions []string `json:"stale_live_sessions,omitempty"`
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

// ProblemRouteItem represents per-route diagnostics.
type ProblemRouteItem struct {
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
	HasPressure          bool                      `json:"has_pressure"`
	PressureNote         string                    `json:"pressure_note,omitempty"`
}

// RuntimeResources contains process and runtime health counters.
type RuntimeResources struct {
	CPUPercent       float64 `json:"cpu_percent"`
	MemoryAllocBytes uint64  `json:"memory_alloc_bytes"`
	MemorySysBytes   uint64  `json:"memory_sys_bytes"`
	MemoryLimitBytes uint64  `json:"memory_limit_bytes"`
	MemoryUsagePct   float64 `json:"memory_usage_pct"`
	Goroutines       int     `json:"goroutines"`
	GCPauseP95MS     float64 `json:"gc_pause_p95_ms"`
	OpenFileDesc     int     `json:"open_file_desc"`
	MaxFileDesc      uint64  `json:"max_file_desc"`
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

// HistoricalSeries contains rolling time-series samples across 4 windows.
type HistoricalSeries struct {
	Window15m []HistoryPoint `json:"window_15m"`
	Window1h  []HistoryPoint `json:"window_1h"`
	Window6h  []HistoryPoint `json:"window_6h"`
	Window24h []HistoryPoint `json:"window_24h"`
}

type ringBuffer struct {
	points []HistoryPoint
	maxCap int
}

func newRingBuffer(maxCap int) *ringBuffer {
	return &ringBuffer{
		points: make([]HistoryPoint, 0, maxCap),
		maxCap: maxCap,
	}
}

func (rb *ringBuffer) add(p HistoryPoint) {
	if len(rb.points) >= rb.maxCap {
		copy(rb.points, rb.points[1:])
		rb.points[len(rb.points)-1] = p
	} else {
		rb.points = append(rb.points, p)
	}
}

func (rb *ringBuffer) snapshot() []HistoryPoint {
	if len(rb.points) == 0 {
		return []HistoryPoint{}
	}
	out := make([]HistoryPoint, len(rb.points))
	for i, p := range rb.points {
		out[i] = cloneHistoryPoint(p)
	}
	return out
}

// RollingHistory maintains in-memory rolling time-series history.
type RollingHistory struct {
	mu sync.RWMutex

	buf15m *ringBuffer // 10s intervals -> 90 points
	buf1h  *ringBuffer // 1m intervals -> 60 points
	buf6h  *ringBuffer // 5m intervals -> 72 points
	buf24h *ringBuffer // 15m intervals -> 96 points

	last1hTime  time.Time
	last6hTime  time.Time
	last24hTime time.Time
}

// NewRollingHistory constructs a new rolling history buffer.
func NewRollingHistory() *RollingHistory {
	return &RollingHistory{
		buf15m: newRingBuffer(90),
		buf1h:  newRingBuffer(60),
		buf6h:  newRingBuffer(72),
		buf24h: newRingBuffer(96),
	}
}

// Add appends a new point to the rolling history windows according to their resolution.
func (rh *RollingHistory) Add(p HistoryPoint) {
	if rh == nil {
		return
	}
	rh.mu.Lock()
	defer rh.mu.Unlock()

	now := time.Unix(p.Timestamp, 0)
	// Clamp before copying: a small slice of a huge backing array is not bounded storage.
	if len(p.Backends) > MaxHistoryBackends {
		p.BackendsOmitted += len(p.Backends) - MaxHistoryBackends
		p.Backends = p.Backends[:MaxHistoryBackends]
	}
	p = cloneHistoryPoint(p)
	rh.buf15m.add(p)

	if rh.last1hTime.IsZero() || now.Sub(rh.last1hTime) >= 1*time.Minute {
		rh.buf1h.add(p)
		rh.last1hTime = now
	}
	if rh.last6hTime.IsZero() || now.Sub(rh.last6hTime) >= 5*time.Minute {
		rh.buf6h.add(p)
		rh.last6hTime = now
	}
	if rh.last24hTime.IsZero() || now.Sub(rh.last24hTime) >= 15*time.Minute {
		rh.buf24h.add(p)
		rh.last24hTime = now
	}
}

// Snapshot returns a copy of all 4 rolling windows.
func (rh *RollingHistory) Snapshot() HistoricalSeries {
	if rh == nil {
		return HistoricalSeries{
			Window15m: []HistoryPoint{},
			Window1h:  []HistoryPoint{},
			Window6h:  []HistoryPoint{},
			Window24h: []HistoryPoint{},
		}
	}
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	return HistoricalSeries{
		Window15m: rh.buf15m.snapshot(),
		Window1h:  rh.buf1h.snapshot(),
		Window6h:  rh.buf6h.snapshot(),
		Window24h: rh.buf24h.snapshot(),
	}
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

func getMemoryLimit(sysBytes uint64) uint64 {
	// Try cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		str := strings.TrimSpace(string(data))
		if str != "max" {
			if limit, err := strconv.ParseUint(str, 10, 64); err == nil && limit > 0 && limit < (1<<60) {
				return limit
			}
		}
	}
	// Try cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		str := strings.TrimSpace(string(data))
		if limit, err := strconv.ParseUint(str, 10, 64); err == nil && limit > 0 && limit < (1<<60) {
			return limit
		}
	}
	// Fallback to sysBytes * 2
	if sysBytes > 0 {
		return sysBytes * 2
	}
	return 1024 * 1024 * 1024 // 1 GiB safe fallback
}

func collectRuntimeResources() RuntimeResources {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	openFD, maxFD := getOpenFileDescriptors()
	memLimit := getMemoryLimit(m.Sys)

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
		CPUPercent:       globalCPUTracker.Percent(),
		MemoryAllocBytes: m.Alloc,
		MemorySysBytes:   m.Sys,
		MemoryLimitBytes: memLimit,
		MemoryUsagePct:   memUsagePct,
		Goroutines:       runtime.NumGoroutine(),
		GCPauseP95MS:     gcPauseP95MS,
		OpenFileDesc:     openFD,
		MaxFileDesc:      maxFD,
	}
}

// checkRoutingInvariants verifies integrity across active sessions, forwarder routes, and return paths.
func checkRoutingInvariants(s *Service, routes []forwarder.RouteInfo, retStats ReturnStatsSnapshot) RoutingConsistencyDiagnostics {
	var activeSessions []Session
	if s.sessionMgr != nil {
		activeSessions = s.sessionMgr.ListActiveSessionsSnapshot()
	}

	diag := RoutingConsistencyDiagnostics{
		ActiveSessionsCount:    len(activeSessions),
		ActiveRoutesCount:      len(routes),
		OwnershipMismatchDrops: retStats.OwnershipMismatchDrops,
		IsConsistent:           true,
		SessionsWithoutRoute:   []string{},
		RoutesWithoutSession:   []string{},
		RoutesWithoutReturn:    []string{},
		DuplicateIPs:           []string{},
		HistoricalDetails:      []string{},
	}
	mismatchRate := s.diagDeltas.sampleOwnershipMismatch(time.Now(), retStats.OwnershipMismatchDrops)
	diag.OwnershipMismatchDropsRecent = mismatchRate.delta
	diag.OwnershipMismatchWindowSec = mismatchRate.windowSeconds

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

	// 1. Sessions without route
	for peerKey := range sessionByPeer {
		if _, ok := routesByPeer[peerKey]; !ok {
			diag.SessionsWithoutRoute = append(diag.SessionsWithoutRoute, peerKey)
		}
	}

	// 2. Routes without session
	for peerKey := range routesByPeer {
		if _, ok := sessionByPeer[peerKey]; !ok {
			diag.RoutesWithoutSession = append(diag.RoutesWithoutSession, peerKey)
		}
	}

	// 3. Routes without return owner
	for peerKey, r := range routesByPeer {
		if r.BackendTunnelID <= 0 || !r.HasReturnPath || r.ReturnPathClosed {
			diag.RoutesWithoutReturn = append(diag.RoutesWithoutReturn, peerKey)
		}
	}

	diag.DuplicateIPs = findDuplicateIPs(ipSessions, ipRoutes)

	// Sort FIRST, redact SECOND (issue #424 round 5, item 1a). These three
	// slices are built by iterating maps keyed by the RAW peer public key, so
	// the raw value is what reaches the JSON payload. ingress.RedactKey, the
	// convention the rest of the system already uses for peer keys, is applied
	// after the sort on purpose: sort.Strings over raw keys is the ordering
	// this field has always had, and it is a total order on the raw value, so
	// the output order stays deterministic and does not silently change if the
	// redaction truncation is ever revisited. Sorting the REDACTED values would
	// instead be a function of the truncation (redacted keys share an 8
	// character prefix, so they cluster), which makes the ordering a property
	// of the masking scheme rather than of the data.
	sort.Strings(diag.SessionsWithoutRoute)
	sort.Strings(diag.RoutesWithoutSession)
	sort.Strings(diag.RoutesWithoutReturn)
	redactKeySlice(diag.SessionsWithoutRoute)
	redactKeySlice(diag.RoutesWithoutSession)
	redactKeySlice(diag.RoutesWithoutReturn)

	auditRoutingConsistencyDetails(&diag)

	return diag
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

func auditRoutingConsistencyDetails(diag *RoutingConsistencyDiagnostics) {
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
	// A lifetime mismatch counter must not pin routing as inconsistent after
	// recovery: only the recent delta degrades current health, while the
	// cumulative total stays visible as a historical note (issue #424 round 2,
	// finding 5).
	if diag.OwnershipMismatchDropsRecent > 0 {
		diag.IsConsistent = false
		diag.InconsistencyDetails = append(diag.InconsistencyDetails,
			fmt.Sprintf("%d ownership mismatch drop(s) in the last %.1fs of return routing",
				diag.OwnershipMismatchDropsRecent, diag.OwnershipMismatchWindowSec))
	} else if diag.OwnershipMismatchDrops > 0 {
		diag.HistoricalDetails = append(diag.HistoricalDetails,
			fmt.Sprintf("%d ownership mismatch drop(s) observed historically, none in the last %.1fs",
				diag.OwnershipMismatchDrops, diag.OwnershipMismatchWindowSec))
	}
}

// collectBackendDiagnostics gathers operational state across registered backend tunnels.
//
// The function itself is a thin composition of the three helpers below — device
// drop population, eligibility counting, and fleet-wide percentile/skew —
// because each of those encodes a contract worth pinning in isolation. All
// three read the same s fields as the original inline body and none of them
// acquires a lock: drop counters and the tunnel list are read exactly as
// before, and the sampling cadence is unchanged.
func collectBackendDiagnostics(s *Service) BackendsDiagnostics {
	if s.pool == nil {
		return BackendsDiagnostics{
			EligibilityKnown: true,
			TotalDrops:       totalBackendDeviceDrops(s),
			Backends:         []BackendTelemetryItem{},
		}
	}

	tunnels := s.pool.ListTunnels()
	var traffic map[int64]forwarder.TrafficSnapshot
	if s.forwarder != nil {
		traffic = s.forwarder.BackendTrafficSnapshot()
	}
	diag := BackendsDiagnostics{
		TotalCount:       len(tunnels),
		EligibilityKnown: true,
		Backends:         make([]BackendTelemetryItem, 0, len(tunnels)),
		TotalDrops:       totalBackendDeviceDrops(s),
	}

	totalActiveConns := countBackendEligibility(&diag, tunnels)

	activeLatencies := make([]float64, 0, len(tunnels))
	var maxShare float64

	for _, tun := range tunnels {
		item, loadShare, hasLatencySample := backendTelemetryItem(s, tun, traffic, totalActiveConns)
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
	drops := s.retiredBackendDeviceDrops.Total()
	for _, dev := range s.backendDevices {
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
	s *Service,
	tun *models.BackendTunnel,
	traffic map[int64]forwarder.TrafficSnapshot,
	totalActiveConns int,
) (BackendTelemetryItem, float64, bool) {
	var drops uint64
	lastHSAge := int64(-1)

	if dev, exists := s.backendDevices[tun.ID]; exists && dev != nil {
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
	diag := HandshakeFreshnessDiagnostics{}
	if s.ingressEngine == nil || s.ingressEngine.Portal() == nil {
		return diag
	}

	portalStatus, err := s.ingressEngine.Portal().Status()
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
	if s.sessionMgr != nil {
		activeSessions := s.sessionMgr.ListActiveSessionsSnapshot()
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
		}
	}

	conditions := make([]HealthCondition, 0)
	conditions = append(conditions, evaluateRoutingConditions(routing)...)
	conditions = append(conditions, evaluateQueueConditions(queue)...)
	conditions = append(conditions, evaluateLatencyConditions(latency)...)
	conditions = append(conditions, evaluateVirtualTUNAndDropConditions(vtun, drops)...)
	conditions = append(conditions, evaluatePeerSyncAndBackendConditions(peerSync, backends, handshake)...)

	status, summary := summarizeHealthConditions(conditions)

	return ForwarderHealthAssessment{
		Status:     status,
		Summary:    summary,
		Conditions: conditions,
	}
}

func evaluateRoutingConditions(routing RoutingConsistencyDiagnostics) []HealthCondition {
	if routing.IsConsistent {
		return nil
	}
	sev := "DEGRADED"
	if len(routing.DuplicateIPs) > 0 || len(routing.SessionsWithoutRoute) > 0 {
		sev = "CRITICAL"
	}
	conds := make([]HealthCondition, 0, len(routing.InconsistencyDetails))
	for _, detail := range routing.InconsistencyDetails {
		conds = append(conds, HealthCondition{
			Category: "routing",
			Severity: sev,
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

func evaluateVirtualTUNAndDropConditions(vtun VirtualTUNDiagnostics, drops DropCategoryBreakdown) []HealthCondition {
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

	if drops.TotalDropRatePps >= th.DropRateDegradedPPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "DEGRADED",
			Message:  fmt.Sprintf("Elevated drop rate: %.1f drops/sec across dataplane", drops.TotalDropRatePps),
		})
	} else if drops.TotalDropRatePps >= th.DropRateWarningPPS {
		conds = append(conds, HealthCondition{
			Category: "drops",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Active packet drops: %.1f drops/sec across dataplane", drops.TotalDropRatePps),
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
		conds = append(conds, HealthCondition{
			Category: "backend",
			Severity: "WARNING",
			Message: fmt.Sprintf("%d of %d backends are degraded or unavailable",
				enabled-backends.HealthyCount, enabled),
		})
	}

	if len(handshake.StaleLiveSessions) > 0 {
		conds = append(conds, HealthCondition{
			Category: "sessions",
			Severity: "WARNING",
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
		items[i] = ProblemRouteItem{
			UtilizationPct: utilization, HighWaterPct: highWaterPct,
			WriteCount: r.Stats.WriteCount, WriteErrors: r.Stats.WriteErrors, WriteStalls: r.Stats.WriteStalls,
			WritesInFlight: r.Stats.WritesInFlight, OldestWriteMS: r.Stats.OldestWriteMS, MaxWriteMS: r.Stats.MaxWriteDurationMS,
			P95WriteSamples:      r.Stats.P95WriteSamples,
			QueueFullDropsRecent: r.Stats.QueueFullDropsRecent, WriteErrorsRecent: r.Stats.WriteErrorsRecent, WriteStallsRecent: r.Stats.WriteStallsRecent,
			Traffic: r.Traffic, SessionAgeSec: r.SessionAgeSec, LastTrafficAgeSec: r.LastTrafficAgeSec,
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
	s.mu.Unlock()

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

func (s *Service) sampleRollingHistory() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status, err := s.GetStatus(ctx)
	if err != nil || status == nil {
		return
	}

	backends, omitted := backendHistory(status.Backends.Backends)
	point := HistoryPoint{
		RxPps: status.Rates.RxPps, TxPps: status.Rates.TxPps, TrafficAvailable: status.Rates.Available,
		DropRatesAvailable: status.DropCategories.RatesAvailable, DropReasonRates: status.DropCategories.ReasonRates,
		ActiveRoutes: status.RoutingConsistency.ActiveRoutesCount, BackendLatencySamples: status.Backends.LatencySamples,
		Backends: backends, BackendsOmitted: omitted,
		Timestamp:         time.Now().Unix(),
		RxBps:             status.Rates.RxBps,
		TxBps:             status.Rates.TxBps,
		QueueUtilPct:      status.QueuePressure.UtilizationPct,
		TotalDropRate:     status.Rates.DropRatePps,
		ForwardP95MS:      status.ForwardLatency.P95HealthMS,
		ForwardP95Samples: status.ForwardLatency.P95HealthSamples,
		ActiveSessions:    status.ConnectedSessions,
		BackendP95MS:      status.Backends.LatencyP95MS,
	}

	s.mu.RLock()
	rh := s.rollingHistory
	s.mu.RUnlock()

	if rh != nil {
		rh.Add(point)
	}
}

// diagRatesTracker provides thread-safe sampling and independent rate computation
// for device write errors, client drops, return drops, and overall dataplane drops.
type diagRatesTracker struct {
	mu sync.Mutex
	// primed records that the first sample has been taken. It is deliberately
	// NOT derived from lastSampleTime being zero: a constructor that pre-seeds
	// the timestamp makes the priming branch below unreachable, which silently
	// leaves every counter baseline at zero and turns lifetime totals into
	// bogus per-second rates on the first window. Mirrors diagDeltaTracker
	// (issue #424 round 8, finding 2).
	primed          bool
	lastSampleTime  time.Time
	lastClientDrops uint64
	lastReturnDrops uint64
	lastTotalDrops  uint64
	lastWriteErrors uint64

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

func (t *diagRatesTracker) Sample(now time.Time, clientDrops, returnDrops, totalDrops, writeErrors uint64) (clientDropRate, returnDropRate, totalDropRate, writeErrorRate float64) {
	if t == nil {
		return 0, 0, 0, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.primed {
		t.primed = true
		t.lastSampleTime = now
		t.lastClientDrops = clientDrops
		t.lastReturnDrops = returnDrops
		t.lastTotalDrops = totalDrops
		t.lastWriteErrors = writeErrors
		return 0, 0, 0, 0
	}

	elapsed := now.Sub(t.lastSampleTime).Seconds()
	if elapsed < 0.2 { // throttle sub-second sampling calls
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate
	}

	deltaClient := float64(0)
	if clientDrops >= t.lastClientDrops {
		deltaClient = float64(clientDrops - t.lastClientDrops)
	}
	deltaReturn := float64(0)
	if returnDrops >= t.lastReturnDrops {
		deltaReturn = float64(returnDrops - t.lastReturnDrops)
	}
	deltaWriteErrors := float64(0)
	if writeErrors >= t.lastWriteErrors {
		deltaWriteErrors = float64(writeErrors - t.lastWriteErrors)
	}

	t.clientDropRate = deltaClient / elapsed
	t.returnDropRate = deltaReturn / elapsed
	t.totalDropRate = t.clientDropRate + t.returnDropRate
	t.writeErrorRate = deltaWriteErrors / elapsed

	t.lastSampleTime = now
	t.lastClientDrops = clientDrops
	t.lastReturnDrops = returnDrops
	t.lastTotalDrops = totalDrops
	t.lastWriteErrors = writeErrors

	return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate
}

// diagDeltaTracker measures the increase of a single lifetime counter over
// the last sampling window, so a cumulative failure counter can stay visible as
// history without permanently degrading current health (issue #424 round 2,
// finding 5).
type diagDeltaTracker struct {
	mu            sync.Mutex
	lastValue     uint64
	primed        bool
	lastSampleAt  time.Time
	delta         uint64
	windowSeconds float64
}

// deltaSnapshot is an immutable read of the tracker's last computed delta.
type deltaSnapshot struct {
	delta         uint64
	windowSeconds float64
}

// Sample records cumulative and returns the increase since the previous
// accepted sample. The first sample only primes the baseline and reports zero,
// so a counter that has been rising since process start is never reported as a
// fresh incident. Resampling sooner than 200ms reuses the previous delta rather
// than dividing by a near-zero window. A counter that decreased (engine
// restart) is treated as no new loss this window.
func (t *diagDeltaTracker) Sample(now time.Time, cumulative uint64) deltaSnapshot {
	if t == nil {
		return deltaSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.primed {
		t.primed = true
		t.lastValue = cumulative
		t.lastSampleAt = now
		t.delta = 0
		t.windowSeconds = 0
		return deltaSnapshot{}
	}

	elapsed := now.Sub(t.lastSampleAt).Seconds()
	if elapsed < 0.2 {
		return deltaSnapshot{delta: t.delta, windowSeconds: t.windowSeconds}
	}

	if cumulative >= t.lastValue {
		t.delta = cumulative - t.lastValue
	} else {
		t.delta = 0
	}
	t.windowSeconds = elapsed
	t.lastValue = cumulative
	t.lastSampleAt = now

	return deltaSnapshot{delta: t.delta, windowSeconds: t.windowSeconds}
}

// diagDeltaTrackers groups the per-counter windowed delta trackers. Each has
// its own mutex, so a caller needs no outer lock.
type diagDeltaTrackers struct {
	ownershipMismatch diagDeltaTracker
	syncFailures      diagDeltaTracker
	enqueueFailures   diagDeltaTracker
	writeStalls       diagDeltaTracker
	reasons           dropReasonRatesTracker
}

func (t *diagDeltaTrackers) sampleOwnershipMismatch(now time.Time, cumulative uint64) deltaSnapshot {
	return t.ownershipMismatch.Sample(now, cumulative)
}

func (t *diagDeltaTrackers) sampleSyncFailures(now time.Time, cumulative uint64) deltaSnapshot {
	return t.syncFailures.Sample(now, cumulative)
}

func (t *diagDeltaTrackers) sampleEnqueueFailures(now time.Time, cumulative uint64) deltaSnapshot {
	return t.enqueueFailures.Sample(now, cumulative)
}

func (s *Service) populateOperationalDiagnostics(status *Status) {
	var routes []forwarder.RouteInfo
	if s.forwarder != nil {
		routes = s.forwarder.InspectRoutes()
	}
	s.populateOperationalDiagnosticsWithRoutes(status, routes)
}

// populateOperationalDiagnosticsWithRoutes assembles one status response from
// the caller's route snapshot. The snapshot is intentionally reused instead of
// sampling route pressure again: endpoint discovery and other status work may
// take longer than the 200ms recency window, so independent reads can make one
// JSON response disagree with itself about whether a just-observed incident is
// still current.
func (s *Service) populateOperationalDiagnosticsWithRoutes(status *Status, routes []forwarder.RouteInfo) {
	if status == nil {
		return
	}

	var writeErrors uint64
	// 1. Rates, Queue Pressure, Latency
	if s.forwarder != nil {
		fRates := s.forwarder.Rates()
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

		qStats := s.forwarder.QueuePressure()
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

		writes := s.forwarder.DeviceWriteSnapshot()
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
	losses := addIngressLosses(s.retiredIngressLosses, engineLossTotals(s.ingressEngine))
	routerMalformed := losses.router.MalformedPacketDrops
	routerUnmapped := losses.router.UnmappedSourceIPDrops
	routerMismatch := losses.router.OwnershipMismatchDrops
	routerNoBackend := losses.router.NoActiveBackendDrops
	routerRejected := losses.router.AdmissionRejectedDrops - routerNoBackend + losses.router.RouteRegistrationErrors
	var fwdClientQueueFull, fwdClientRateLimited, fwdClientNoBackend uint64
	if s.forwarder != nil {
		fwdClientQueueFull, fwdClientRateLimited, fwdClientNoBackend, _ = s.forwarder.ClientDropStats()
	}

	retStats := losses.returns
	// Use live engine queue gauges; retained state contains counters only.
	if s.ingressEngine != nil {
		current := s.ingressEngine.ReturnStats().TUN
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
	deviceDrops := collectBackendDeviceDropStats(s)
	var returnQueueFull, returnOversized uint64
	if s.forwarder != nil {
		returnQueueFull = s.forwarder.DropsQueueFull()
		returnOversized = s.forwarder.DropsPacketTooLarge()
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
		deviceDrops.ClientExternal +
		deviceDrops.ClientUnattributed +
		deviceDrops.ClientRetired

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

	totalDrops := clientTotal + returnTotal

	status.DropCategories = DropCategoryBreakdown{
		ClientMalformed:                 routerMalformed,
		ClientUnmappedSource:            routerUnmapped,
		ClientMismatch:                  routerMismatch,
		ClientRejected:                  routerRejected,
		ClientBackendQueueFull:          fwdClientQueueFull,
		ClientRateLimited:               fwdClientRateLimited,
		ClientNoHealthyBackend:          fwdClientNoBackend,
		ClientVirtualTUNDrops:           clientVirtualTUNDrops,
		ClientBackendDeviceQueueFull:    deviceDrops.ClientQueueFull,
		ClientBackendDeviceOversized:    deviceDrops.ClientOversized,
		ClientBackendDeviceShutdown:     deviceDrops.ClientShutdown,
		ClientBackendDeviceExternal:     deviceDrops.ClientExternal,
		ClientBackendDeviceUnattributed: deviceDrops.ClientUnattributed,
		ClientBackendDeviceRetired:      deviceDrops.ClientRetired,
		ClientTotalDrops:                clientTotal,

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

	// The loss sampling pair owns one timestamp and one serialization scope.
	sampleAt := time.Now()
	status.ForwardLatency.WriteErrorRatePps = s.sampleDropRates(sampleAt, &status.DropCategories, writeErrors)
	status.Rates.DropRatePps = status.DropCategories.TotalDropRatePps
	stalls := s.diagDeltas.writeStalls.Sample(sampleAt, status.ForwardLatency.Stalls)
	status.ForwardLatency.StallsRecent = stalls.delta
	status.ForwardLatency.StallsWindowSec = stalls.windowSeconds

	// Directional mapping (issue #424 round 2, finding 1):
	//   UpstreamToNexus <- Outbound*  (VirtualTUN.Write, upstream AWG -> Nexus)
	//   NexusToUpstream <- Inbound*  (VirtualTUN.InjectInbound, Nexus -> AWG)
	status.VirtualTUN = VirtualTUNDiagnostics{
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

	// 3. Routing consistency
	status.RoutingConsistency = checkRoutingInvariants(s, routes, retStats)

	// 4. Handshake freshness
	status.HandshakeFreshness = collectHandshakeDiagnostics(s)

	// 5. Backends
	status.Backends = collectBackendDiagnostics(s)

	if s.sessionMgr != nil {
		sessions := s.sessionMgr.ListActiveSessionsSnapshot()
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
	if s.forwarder != nil {
		status.ProblemRoutes = collectProblemRoutes(forwarder.ProblemRoutesFromSnapshot(routes, 50))
		status.AllRoutes = collectProblemRoutes(routes)
	} else {
		status.ProblemRoutes = []ProblemRouteItem{}
		status.AllRoutes = []ProblemRouteItem{}
	}

	// 7. Runtime Resources
	status.RuntimeResources = collectRuntimeResources()

	// 8. Historical Series
	if s.rollingHistory != nil {
		status.HistoricalSeries = s.rollingHistory.Snapshot()
	} else {
		status.HistoricalSeries = HistoricalSeries{
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
		syncRate := s.diagDeltas.sampleSyncFailures(now, status.PeerSync.SyncFailures)
		enqueueRate := s.diagDeltas.sampleEnqueueFailures(now, status.PeerSync.EnqueueFailures)
		status.PeerSync.SyncFailuresRecent = syncRate.delta
		status.PeerSync.EnqueueFailuresRecent = enqueueRate.delta
		status.PeerSync.FailuresWindowSec = math.Max(syncRate.windowSeconds, enqueueRate.windowSeconds)
	}

	// 10. Centralized Rule-Based Health Assessment
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
	)
}
