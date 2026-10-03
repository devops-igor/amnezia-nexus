package vpn

import (
	"maps"
	"sort"
	"sync"
	"time"
)

// The disjoint reasons use exactly the counter keys in drop_categories.
// return_injection_tun_drops describes overlap, not an additional loss reason.
func dropReasonTotals(d DropCategoryBreakdown) map[string]uint64 {
	return map[string]uint64{
		"client_malformed": d.ClientMalformed, "client_unmapped_source": d.ClientUnmappedSource,
		"client_mismatch": d.ClientMismatch, "client_rejected": d.ClientRejected,
		"client_backend_queue_full": d.ClientBackendQueueFull, "client_rate_limited": d.ClientRateLimited,
		"client_no_healthy_backend": d.ClientNoHealthyBackend, "client_virtualtun_drops": d.ClientVirtualTUNDrops,
		"client_backend_device_queue_full":    d.ClientBackendDeviceQueueFull,
		"client_backend_device_oversized":     d.ClientBackendDeviceOversized,
		"client_backend_device_shutdown":      d.ClientBackendDeviceShutdown,
		"client_backend_device_external":      d.ClientBackendDeviceExternal,
		"client_backend_device_unattributed":  d.ClientBackendDeviceUnattributed,
		"client_backend_device_retired_drops": d.ClientBackendDeviceRetired,
		"return_malformed":                    d.ReturnMalformed, "return_unmapped": d.ReturnUnmapped, "return_mismatch": d.ReturnMismatch,
		"return_injection_errors": d.ReturnInjectionErrors, "return_virtualtun_drops": d.ReturnVirtualTUNDrops,
		"return_queue_full": d.ReturnQueueFull, "return_packet_too_large": d.ReturnPacketTooLarge,
		"return_backend_device_queue_full": d.ReturnBackendDeviceQueueFull,
		"return_backend_device_shutdown":   d.ReturnBackendDeviceShutdown,
	}
}

type dropReasonRatesTracker struct {
	mu        sync.Mutex
	lastAt    time.Time
	baseline  map[string]uint64
	rates     map[string]float64
	available bool
}

func (t *dropReasonRatesTracker) sample(now time.Time, totals map[string]uint64) (map[string]float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastAt.IsZero() {
		t.lastAt = now
		t.baseline = totals
		t.rates = make(map[string]float64, len(totals))
		for key := range totals {
			t.rates[key] = 0
		}
	}
	elapsed := now.Sub(t.lastAt).Seconds()
	if elapsed >= 0.2 {
		for key, total := range totals {
			var delta uint64
			if total >= t.baseline[key] {
				delta = total - t.baseline[key]
			}
			t.rates[key] = float64(delta) / elapsed
		}
		t.lastAt = now
		t.baseline = totals
		t.available = true
	}
	return maps.Clone(t.rates), t.available
}

// MaxHistoryBackends caps the fleet context within each existing fixed ring.
// If a fleet exceeds this limit, samples state the omitted count. Removed
// backend IDs exist only in old ring points, and disappear when those expire.
const MaxHistoryBackends = 128

// BackendHistoryPoint preserves per-backend traffic and probe availability
// independently: an idle measured rate is zero; a missing sample is unknown.
type BackendHistoryPoint struct {
	ID               int64   `json:"id"`
	RxBps            float64 `json:"rx_bps"`
	TxBps            float64 `json:"tx_bps"`
	RxPps            float64 `json:"rx_pps"`
	TxPps            float64 `json:"tx_pps"`
	TrafficAvailable bool    `json:"traffic_available"`
	ProbeLatencyMS   int64   `json:"probe_latency_ms"`
	ProbeAvailable   bool    `json:"probe_available"`
	Routable         bool    `json:"routable"`
}

func backendHistory(backends []BackendTelemetryItem) ([]BackendHistoryPoint, int) {
	// Own the sort: status slices remain caller-owned.
	ordered := append([]BackendTelemetryItem(nil), backends...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	omitted := 0
	if len(ordered) > MaxHistoryBackends {
		omitted = len(ordered) - MaxHistoryBackends
		ordered = ordered[:MaxHistoryBackends]
	}
	out := make([]BackendHistoryPoint, 0, len(ordered))
	for _, b := range ordered {
		out = append(out, BackendHistoryPoint{ID: b.ID, RxBps: b.RxBytesPerSec * 8, TxBps: b.TxBytesPerSec * 8,
			RxPps: b.RxPps, TxPps: b.TxPps, TrafficAvailable: b.TrafficAvailable, ProbeLatencyMS: b.ProbeLatencyMS,
			ProbeAvailable: b.Routable && b.ProbeLatencyMS > 0, Routable: b.Routable})
	}
	return out, omitted
}

func cloneHistoryPoint(p HistoryPoint) HistoryPoint {
	if p.DropReasonRates != nil {
		finite := make(map[string]float64, len(dropReasonTotals(DropCategoryBreakdown{})))
		for key := range dropReasonTotals(DropCategoryBreakdown{}) {
			if rate, ok := p.DropReasonRates[key]; ok {
				finite[key] = rate
			}
		}
		p.DropReasonRates = finite
	}
	owned := make([]BackendHistoryPoint, len(p.Backends))
	copy(owned, p.Backends)
	p.Backends = owned
	return p
}

// sampleDropRates publishes aggregate and reason rates as one operation.
// The existing diagnostics lock prevents concurrent status/history callers
// from returning rates from different intervals; all trackers use the same clock.
func (s *Service) sampleDropRates(at time.Time, drops *DropCategoryBreakdown, writeErrors uint64) float64 {
	s.diagRatesMu.Lock()
	defer s.diagRatesMu.Unlock()
	if s.diagRates == nil {
		s.diagRates = newDiagRatesTracker()
	}
	var writeErrorRate float64
	drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.TotalDropRatePps, writeErrorRate = s.diagRates.Sample(
		at, drops.ClientTotalDrops, drops.ReturnTotalDrops, drops.TotalDrops, writeErrors,
	)
	drops.ReasonRates, drops.RatesAvailable = s.diagDeltas.reasons.sample(at, dropReasonTotals(*drops))
	return writeErrorRate
}
