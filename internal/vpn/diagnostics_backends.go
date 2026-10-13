package vpn

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/models"
	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
)

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
