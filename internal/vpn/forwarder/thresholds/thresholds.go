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
// # Immutability
//
// Thresholds are immutable canonical constants. Speculative runtime setters
// are rejected to avoid runtime synchronization overhead and configuration drift.
package thresholds

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

const (
	dwellWarningUtilization  = 0.5
	dwellDegradedUtilization = 0.8
	routePressureUtilization = 0.8
)

// Canonical returns a coherent copy of the canonical queue-pressure levels.
func Canonical() QueuePressure {
	return QueuePressure{
		DwellWarningUtilization:  dwellWarningUtilization,
		DwellDegradedUtilization: dwellDegradedUtilization,
		RoutePressureUtilization: routePressureUtilization,
	}
}

// QueueDwellWarningUtilization is the canonical sustained-WARNING level.
func QueueDwellWarningUtilization() float64 { return dwellWarningUtilization }

// QueueDwellDegradedUtilization is the canonical sustained-DEGRADED level.
func QueueDwellDegradedUtilization() float64 { return dwellDegradedUtilization }

// RoutePressureUtilization is the canonical route-pressure level.
func RoutePressureUtilization() float64 { return routePressureUtilization }

// QueueDwellWarningPct is QueueDwellWarningUtilization as a percentage, for
// the health evaluator's percent-valued fields and message text.
func QueueDwellWarningPct() float64 { return dwellWarningUtilization * 100 }

// QueueDwellDegradedPct is QueueDwellDegradedUtilization as a percentage.
func QueueDwellDegradedPct() float64 { return dwellDegradedUtilization * 100 }
