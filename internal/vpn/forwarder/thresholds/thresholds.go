// Package thresholds is the canonical, single source of truth for the queue
// pressure levels that are MEASURED by the forwarder and REPORTED by the VPN
// health evaluator (issue #424 round 5, finding 4).
//
// # Why a leaf package
//
// Before this package the numbers existed twice: HealthThresholds in
// internal/vpn declared QueueDegradedAbovePct=80 and
// QueueWarningSustainedAbovePct=50 for the human-readable message, while
// internal/vpn/forwarder/queue_dwell.go compared utilization against the
// literals 0.5 and 0.8 to produce the ConsecutiveAbove50Sec /
// ConsecutiveAbove80Sec those messages talk about. Changing the configured
// value to 85 would have changed only the message while the measurement kept
// running against 80: the configuration would have silently lied.
//
// The shared values cannot live in internal/vpn, because internal/vpn already
// imports internal/vpn/forwarder (vpn.go) and putting them there would make the
// forwarder import its own importer — an import cycle. This package is a leaf:
// it imports NOTHING, so both internal/vpn and internal/vpn/forwarder can
// import it without either depending on the other.
//
// # Units
//
// The canonical form is a utilization FRACTION in [0,1], because that is what
// the measurement code compares (occupancy/capacity). The percent-valued
// accessors exist only for the health evaluator's message text and its
// percentage-valued struct fields; they are derived, never authored.
//
// # Runtime configurability
//
// Round 5 recorded these as documented named defaults and explicitly DEFERRED
// runtime configurability (finding 4 option (b)): #424's "configurable"
// wording is narrowed to "centralized and documented" plus this follow-up.
// There is no existing config path for VPN diagnostic thresholds — the VPN
// config plumbing carries no threshold fields at all — so wiring one would mean
// inventing a parallel configuration system rather than reusing an existing
// one, which the spec forbids. The setters below exist so a future
// configuration layer (and the round-5 regressions) can supply a different set
// through the SAME accessors the production path reads; production never calls
// them.
//
// # Concurrency
//
// The values are held in a mutex-guarded struct and every read goes through an
// accessor. The accessors sit on the queue-transition observer's path, not on
// the per-packet path, so the cost is a mutex acquisition per observed queue
// transition, not per packet. Once a configuration layer exists it must publish
// a replacement set through SetCanonical rather than mutating fields, so a
// diagnostics evaluation can never observe a half-applied change.
package thresholds

import "sync"

// QueuePressure holds the canonical queue-pressure levels as utilization
// fractions in [0,1].
type QueuePressure struct {
	// DwellWarningUtilization is the level the managed queue observer counts
	// as "above" when it measures ConsecutiveAbove50Sec. It gates the
	// WARNING-on-sustained-pressure condition.
	DwellWarningUtilization float64

	// DwellDegradedUtilization is the level the managed queue observer counts
	// as "above" when it measures ConsecutiveAbove80Sec. It gates the
	// DEGRADED-on-sustained-pressure condition.
	DwellDegradedUtilization float64

	// RoutePressureUtilization is the occupancy/capacity fraction at or above
	// which a route is classified as under queue pressure. It is a
	// classification threshold for a note, not a severity.
	RoutePressureUtilization float64
}

// Canonical returns a coherent copy of the canonical queue-pressure levels.
//
// A copy, not a pointer into the live set: a caller that reads the levels
// several times must see ONE set, so a concurrent reconfiguration cannot make
// it compare a new warning level against an old degraded one.
func Canonical() QueuePressure {
	mu.Lock()
	defer mu.Unlock()
	return canonical
}

// SetCanonical publishes a replacement set. A future configuration layer calls
// this once per accepted reconfiguration; nothing else may.
func SetCanonical(p QueuePressure) {
	mu.Lock()
	defer mu.Unlock()
	canonical = p
}

// QueueDwellWarningUtilization is the canonical sustained-WARNING level.
func QueueDwellWarningUtilization() float64 { return Canonical().DwellWarningUtilization }

// QueueDwellDegradedUtilization is the canonical sustained-DEGRADED level.
func QueueDwellDegradedUtilization() float64 { return Canonical().DwellDegradedUtilization }

// RoutePressureUtilization is the canonical route-pressure level.
func RoutePressureUtilization() float64 { return Canonical().RoutePressureUtilization }

// QueueDwellWarningPct is QueueDwellWarningUtilization as a percentage, for
// the health evaluator's percent-valued fields and message text.
func QueueDwellWarningPct() float64 { return QueueDwellWarningUtilization() * 100 }

// QueueDwellDegradedPct is QueueDwellDegradedUtilization as a percentage.
func QueueDwellDegradedPct() float64 { return QueueDwellDegradedUtilization() * 100 }

// SetQueueDwellDegradedUtilization moves ONLY the sustained-DEGRADED level.
// It exists so a regression can perturb one level and observe that the
// measurement and the message move together; production never calls it.
func SetQueueDwellDegradedUtilization(v float64) {
	mu.Lock()
	defer mu.Unlock()
	canonical.DwellDegradedUtilization = v
}

// SetRoutePressureUtilization moves ONLY the route-pressure level, for the same
// reason as SetQueueDwellDegradedUtilization.
func SetRoutePressureUtilization(v float64) {
	mu.Lock()
	defer mu.Unlock()
	canonical.RoutePressureUtilization = v
}

var (
	mu sync.Mutex
	// canonical is the ONE production set of queue-pressure levels. Every
	// value is numerically identical to the literal it replaced in
	// internal/vpn/forwarder (queue_dwell.go: 0.5 and 0.8; routes.go: 0.8), so
	// this change is a de-duplication and not a retuning: no severity
	// boundary moves.
	canonical = QueuePressure{
		DwellWarningUtilization:  0.5,
		DwellDegradedUtilization: 0.8,
		RoutePressureUtilization: 0.8,
	}
)
