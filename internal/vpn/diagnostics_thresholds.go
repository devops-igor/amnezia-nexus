package vpn

import (
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder/thresholds"
)

// HealthThresholds is the single, documented owner of every numeric
// threshold the forwarder health evaluator compares against
// (issue #424 round 3, finding 4).
//
// #424 asks for thresholds to be "centralized and documented" and
// "centralized/configurable and calibrated with production telemetry rather
// than scattered". This change is the centralization half, and it is a PURE
// move: every value below is numerically identical to the literal it
// replaced, and the comparison operators (>= vs >) are preserved exactly, so
// no severity boundary moves. Calibration is deliberately NOT built here — it
// needs production telemetry to be worth doing, and a knob nobody has measured
// is worse than an owned constant.
//
// # Shared values are not authored here at all
//
// The queue-pressure levels that the forwarder MEASURES (its dwell observer,
// its rate tracker and its per-route pressure classifier) live in the leaf
// package internal/vpn/forwarder/thresholds, and the three fields below are
// DERIVED from it by defaultHealthThresholds rather than transcribed. They
// cannot live in this package: internal/vpn already imports
// internal/vpn/forwarder, so the shared values would make the forwarder import
// its own importer. Before this, the levels were authored twice — once here
// for the message and once as literals in the measurement code — so raising
// this value to 85 changed only the message while the measurement kept
// running against 80.
//
// # Runtime configurability
//
// Not implemented, and that is a documented deferral rather than an
// oversight: issue #424's "configurable" wording is narrowed to "centralized
// and documented" by round 5's finding 4, option (b). The canonical thresholds
// are immutable constants shared across measurement and diagnostics evaluation.
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

	// DropRateDegradedPPS gates DEGRADED on the dataplane-wide ROUTINE drop
	// rate. Compared with >= against the routine-population rate, which is
	// TotalDropRatePps MINUS the losses already claimed by a reason-specific
	// condition (issue #424 review round 9, blocker 3). The subtraction is what
	// makes the populations disjoint: a loss reported by reason is never also
	// reported by the aggregate.
	DropRateDegradedPPS float64

	// DropRateWarningPPS gates WARNING on the dataplane-wide ROUTINE drop
	// rate, over the same disjoint population as DropRateDegradedPPS. Compared
	// with >=.
	DropRateWarningPPS float64

	// --- Reason-specific critical loss (issue #424 review round 9, blocker 3) ---

	// ClientOwnershipMismatchCriticalDrops gates CRITICAL on client-direction ownership mismatch.
	ClientOwnershipMismatchCriticalDrops uint64
	// ReturnOwnershipMismatchWarningDrops gates WARNING on routine return-direction ownership mismatch.
	ReturnOwnershipMismatchWarningDrops uint64
	// ReturnOwnershipMismatchDegradedRatePPS gates DEGRADED on sustained return-direction ownership mismatch rate.
	ReturnOwnershipMismatchDegradedRatePPS float64
	// ReturnOwnershipMismatchDegradedConsecutiveWindows gates DEGRADED on sustained return-direction
	// ownership mismatch across consecutive observation windows. A single isolated window with
	// return drop rate >= ReturnOwnershipMismatchDegradedRatePPS remains WARNING; only when high-rate
	// loss persists for at least this many consecutive observation windows does severity escalate
	// to DEGRADED (issue #457).
	ReturnOwnershipMismatchDegradedConsecutiveWindows int

	// OwnershipMismatchCriticalDrops is retained for backward compatibility (issue #457).
	// Directional thresholds should be used instead: ClientOwnershipMismatchCriticalDrops,
	// ReturnOwnershipMismatchWarningDrops, ReturnOwnershipMismatchDegradedRatePPS,
	// and ReturnOwnershipMismatchDegradedConsecutiveWindows.
	OwnershipMismatchCriticalDrops uint64

	// InjectionFailureCriticalRatePPS gates CRITICAL on return-path injection
	// failures. Compared with > against the current-window
	// DropCategoryBreakdown.ReasonRates[reasonReturnInjectionErrors], so any
	// non-zero measured rate fires and a zero rate never does.
	//
	// The value is 0, numerically identical to the `> 0` comparison the
	// evaluator already applied to device write-error telemetry
	// (WriteErrorRatePps > 0) and to QueueActiveDropRatePPS above: both encode
	// "a non-zero CURRENT rate of this failure is an incident", which is the
	// same rule applied to a third failure population.
	InjectionFailureCriticalRatePPS float64

	// --- Reason-specific degraded loss (finding B3, issue #424) ---

	// ClientQueueActiveDropRatePPS gates DEGRADED on client-to-backend queue-full
	// drops happening RIGHT NOW. Compared with > against the current-window
	// DropCategoryBreakdown.ReasonRates[reasonClientBackendQueueFull], so any
	// non-zero measured rate fires and a zero rate never does.
	//
	// The value is 0, matching the `> 0` comparison applied to
	// QueueActiveDropRatePPS, WriteErrorRatePps, and
	// InjectionFailureCriticalRatePPS: all encode "a non-zero CURRENT rate of
	// this failure is an incident".
	ClientQueueActiveDropRatePPS float64

	// BackendDeviceUnattributedActiveDropRatePPS gates DEGRADED on
	// backend-device loss that is active RIGHT NOW on a device that cannot
	// report the direction x reason breakdown (no backendDeviceStatsProvider,
	// so the loader publishes it under the direction-neutral
	// backend_device_unattributed key). Compared with > against the
	// current-window DropCategoryBreakdown.ReasonRates[reasonBackendDeviceUnattributed],
	// so any non-zero measured rate fires and a zero rate never does —
	// including the measured zero a device WITH detailed attribution
	// publishes, which is what keeps this condition off when attribution is
	// available.
	//
	// The value is 0, matching the `> 0` rate idiom of
	// ClientQueueActiveDropRatePPS above.
	BackendDeviceUnattributedActiveDropRatePPS float64

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
var DefaultHealthThresholds = defaultHealthThresholds()

// defaultHealthThresholds builds the production threshold set, reading the
// measurement-linked queue-pressure levels from the canonical leaf package.
//
// Every other field is a literal because it is compared only against a value
// produced here; the three below are different in kind, because the forwarder
// MEASURES the same boundaries independently and the operator-facing message
// names them. Deriving them is what makes the message and the measurement the
// same boundary rather than two values that happen to agree today.
func defaultHealthThresholds() HealthThresholds {
	return HealthThresholds{
		QueueCriticalPct:              95.0,
		QueueDegradedSustainedSeconds: 30,
		QueueWarningPct:               80.0,
		QueueWarningSustainedSeconds:  60,

		// Canonical, in percent because these fields are percent-valued.
		QueueDegradedAbovePct:         thresholds.QueueDwellDegradedPct(),
		QueueWarningSustainedAbovePct: thresholds.QueueDwellWarningPct(),
		ProblemRoutePressureRatio:     thresholds.RoutePressureUtilization(),

		QueueActiveDropRatePPS: 0,

		WriteStallCriticalMS:   1000,
		WriteStallWarningMS:    100,
		WriteLatencyDegradedMS: 100.0,
		WriteLatencyWarningMS:  50.0,

		VirtualTUNDegradedPct: 90.0,
		VirtualTUNWarningPct:  75.0,

		// The ROUTINE population, not the whole dataplane: see
		// DropRateDegradedPPS above. Numeric identity with the literals these
		// two fields replaced is unchanged — only the compared population
		// moved, and it moved by exactly the reason-claimed losses.
		DropRateDegradedPPS: 10.0,
		DropRateWarningPPS:  1.0,

		ClientOwnershipMismatchCriticalDrops:              1,
		ReturnOwnershipMismatchWarningDrops:               1,
		ReturnOwnershipMismatchDegradedRatePPS:            10.0,
		ReturnOwnershipMismatchDegradedConsecutiveWindows: 2,
		// `> 0` on the already-gated mismatch counter, restated as >= 1.
		OwnershipMismatchCriticalDrops: 1, // retained for backward compatibility
		// `> 0`, matching the write-error and queue-drop rate idiom.
		InjectionFailureCriticalRatePPS: 0,
		// `> 0`, matching the queue-drop rate idiom for client backend queues.
		ClientQueueActiveDropRatePPS: 0,
		// `> 0`, matching the client backend queue rate idiom for unattributed
		// backend-device loss.
		BackendDeviceUnattributedActiveDropRatePPS: 0,

		PeerSyncDivergenceDegradedAge: 60 * time.Second,
		PeerSyncDivergenceWarningAge:  30 * time.Second,

		HandshakeStaleAge: 3 * time.Minute,
	}
}
