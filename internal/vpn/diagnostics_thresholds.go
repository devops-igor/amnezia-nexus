package vpn

import "time"

// HealthThresholds is the single, documented owner of every numeric
// threshold the forwarder health evaluator compares against
// (issue #424 round 3, finding 4).
//
// #424 asks for thresholds to be "centralized and documented" and
// "centralized/configurable and calibrated with production telemetry rather
// than scattered". This change is the centralization half, and it is a PURE
// move: every value below is numerically identical to the literal it
// replaced, and the comparison operators (>= vs >) are preserved exactly, so
// no severity boundary moves. Calibration and runtime configurability are
// deliberately NOT built here — they need production telemetry to be worth
// doing, and a knob nobody has measured is worse than an owned constant.
//
// # Severity roles
//
//	CRITICAL  the dataplane is failing now: packets are being refused or
//	          stalled at the top of a threshold.
//	DEGRADED  the dataplane is losing or delaying traffic at a sustained
//	          rate, or is falling behind on a condition that has persisted.
//	WARNING   early notice: elevated, but below the levels that mean loss.
//
// Each field below documents which of those it gates and how the comparison
// is made, so a future calibration knows which boundary it is moving.
type HealthThresholds struct {
	// --- Forwarder return queue (evaluateQueueConditions) ---

	// QueueCriticalPct gates CRITICAL saturation of the managed return
	// queue. Compared with >= against QueuePressureDiagnostics.
	// UtilizationPct (a percentage, 0-100).
	QueueCriticalPct float64

	// QueueDegradedAbovePct is the utilization level the managed queue
	// observer counts as "above" when it measures ConsecutiveAbove80Sec;
	// sustained at that level for QueueDegradedSustainedSeconds it is
	// DEGRADED. The counter itself is produced upstream by the forwarder's
	// queue observer, which owns that constant.
	QueueDegradedAbovePct float64

	// QueueDegradedSustainedSeconds gates DEGRADED on sustained pressure:
	// QueuePressureDiagnostics.ConsecutiveAbove80Sec >= this value.
	QueueDegradedSustainedSeconds int64

	// QueueWarningPct gates WARNING on instantaneous elevated occupancy.
	// Compared with >= against QueuePressureDiagnostics.UtilizationPct.
	QueueWarningPct float64

	// QueueWarningSustainedAbovePct is the utilization level the managed
	// queue observer counts as "above" when it measures
	// ConsecutiveAbove50Sec; sustained at that level for
	// QueueWarningSustainedSeconds it is WARNING even when the
	// instantaneous utilization has already fallen back.
	QueueWarningSustainedAbovePct float64

	// QueueWarningSustainedSeconds gates WARNING on sustained pressure:
	// QueuePressureDiagnostics.ConsecutiveAbove50Sec >= this value.
	QueueWarningSustainedSeconds int64

	// QueueActiveDropRatePPS gates DEGRADED on queue-full drops happening
	// RIGHT NOW. Compared with > against
	// QueuePressureDiagnostics.QueueDropRatePps, so any non-zero rate fires
	// and zero never does.
	QueueActiveDropRatePPS float64

	// --- Forwarder device write latency (evaluateLatencyConditions) ---

	// WriteStallCriticalMS gates CRITICAL on an in-flight device write that
	// has been blocked this long. Compared with >=
	// against ForwardLatencyDiagnostics.OldestInFlightMS.
	WriteStallCriticalMS int64

	// WriteStallWarningMS gates WARNING on a slow in-flight device write.
	// Compared with >= against
	// ForwardLatencyDiagnostics.OldestInFlightMS.
	WriteStallWarningMS int64

	// WriteLatencyDegradedMS gates DEGRADED on the recent-window p95 write
	// duration. Compared with >= against
	// ForwardLatencyDiagnostics.P95HealthMS, and only evaluated when
	// P95HealthSamples > 0: no recent write is UNKNOWN latency, not bad
	// latency, and inventing a severity there would pin DEGRADED on an idle
	// server.
	WriteLatencyDegradedMS float64

	// WriteLatencyWarningMS gates WARNING on the recent-window p95 write
	// duration. Compared with >= against
	// ForwardLatencyDiagnostics.P95HealthMS.
	WriteLatencyWarningMS float64

	// --- Upstream VirtualTUN queues (evaluateVirtualTUNAndDropConditions) ---

	// VirtualTUNDegradedPct gates DEGRADED on either upstream VirtualTUN
	// direction being this full. Compared with >= against the occupancy
	// fraction of the direction's capacity.
	VirtualTUNDegradedPct float64

	// VirtualTUNWarningPct gates WARNING on either upstream VirtualTUN
	// direction being this full. Compared with >= against the occupancy
	// fraction of the direction's capacity.
	VirtualTUNWarningPct float64

	// --- Dataplane drop rate (evaluateVirtualTUNAndDropConditions) ---

	// DropRateDegradedPPS gates DEGRADED on the dataplane-wide drop rate.
	// Compared with >= against
	// DropCategoryBreakdown.TotalDropRatePps.
	DropRateDegradedPPS float64

	// DropRateWarningPPS gates WARNING on the dataplane-wide drop rate.
	// Compared with >= against
	// DropCategoryBreakdown.TotalDropRatePps.
	DropRateWarningPPS float64

	// --- Peer synchronization (peerSyncDivergenceCondition) ---

	// PeerSyncDivergenceDegradedAge gates DEGRADED on a persisted
	// desired/actual peer mismatch. Compared with > against the age measured
	// from PeerSyncStatus.DivergenceSince — STRICTLY greater, not >=: the
	// boundary value itself is not yet an incident.
	PeerSyncDivergenceDegradedAge time.Duration

	// PeerSyncDivergenceWarningAge gates WARNING on a persisted
	// desired/actual peer mismatch. Compared with > against the age from
	// DivergenceSince, with the same strictness as the degraded bound.
	PeerSyncDivergenceWarningAge time.Duration

	// --- Session handshake freshness ---

	// HandshakeStaleAge gates the stale-session WARNING: a live session
	// whose last upstream handshake is older than this. Compared with >
	// against now minus the session's handshake time.
	HandshakeStaleAge time.Duration

	// --- Per-route problem reporting (collectProblemRoutes) ---

	// ProblemRoutePressureRatio gates the "queue pressure" note on a problem
	// route, as a FRACTION of the route queue's capacity (0-1, not a
	// percentage). Compared with >= against occupancy/capacity. It is a
	// classification threshold for a note, not a severity: the severity of a
	// route is decided by the dataplane-wide conditions above.
	ProblemRoutePressureRatio float64
}

// DefaultHealthThresholds is the ONE production threshold set. It is a
// package-level value rather than a per-call-site literal precisely so there
// is exactly one answer to "what does a severity boundary mean": if a second
// set is ever constructed, the effective thresholds stop being derivable from
// the source, which is the state #424 rejected.
//
// Treat it as immutable. A future runtime-configurable threshold layer must
// publish a replacement atomically rather than mutating these fields, so that
// a diagnostics evaluation can never observe a half-applied change.
var DefaultHealthThresholds = HealthThresholds{
	QueueCriticalPct:              95.0,
	QueueDegradedAbovePct:         80.0,
	QueueDegradedSustainedSeconds: 30,
	QueueWarningPct:               80.0,
	QueueWarningSustainedAbovePct: 50.0,
	QueueWarningSustainedSeconds:  60,

	QueueActiveDropRatePPS: 0,

	WriteStallCriticalMS:   1000,
	WriteStallWarningMS:    100,
	WriteLatencyDegradedMS: 100.0,
	WriteLatencyWarningMS:  50.0,

	VirtualTUNDegradedPct: 90.0,
	VirtualTUNWarningPct:  75.0,

	DropRateDegradedPPS: 10.0,
	DropRateWarningPPS:  1.0,

	PeerSyncDivergenceDegradedAge: 60 * time.Second,
	PeerSyncDivergenceWarningAge:  30 * time.Second,

	HandshakeStaleAge: 3 * time.Minute,

	ProblemRoutePressureRatio: 0.8,
}
