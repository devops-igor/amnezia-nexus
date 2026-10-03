package vpn

import (
	"maps"
	"sort"
	"sync"
	"time"
)

// lossClaim names the evaluator that OWNS a critical reason's losses. Exactly
// one evaluator may own each reason: an ownership owned twice is a
// double-counted condition, which is the failure mode round 5 of this review
// was entirely about and the one blocker 3 has to avoid reintroducing while
// adding reason-keyed severity.
type lossClaim int

const (
	// claimRouting means the routing consistency evaluator reports the loss
	// (it owns the ownership-mismatch invariants, both directions).
	claimRouting lossClaim = iota
	// claimDrops means this evaluator reports the loss as a reason-keyed
	// condition.
	claimDrops
)

// criticalLossReasons declares, in ONE place, every reason the health
// evaluator classifies by identity rather than by aggregate volume, and which
// evaluator owns each (issue #424 review round 9, blocker 3).
//
// This map is the single source for two things that must never disagree: the
// reason-specific condition that is emitted, and the subtraction from the
// routine population that keeps the same loss out of the aggregate. Adding a
// reason here is therefore the whole change — there is no second list to
// remember, and therefore no way to claim a reason in one place and let the
// aggregate report it in another.
//
//   - Ownership mismatch in either direction is owned by the ROUTING
//     evaluator. #424 treats a packet refused because ownership could not be
//     verified as CRITICAL: it is a correctness failure (a #391 sync gap or a
//     manual database edit desynchronised the resolver from the session store),
//     not congestion, so its severity must not scale with how many packets it
//     refused.
//   - Return-path injection failures are owned by THIS evaluator. The return
//     packet was decrypted and accepted, then refused at the last hop before the
//     client, so the reply is lost outright with no route to retry it.
//
// Note the deliberate absence of queue-full, malformed, and the rest: those are
// CAPACITY or hygiene reasons whose severity legitimately scales with volume,
// and TestB3HighVolumeRoutineQueueFullIsNotCritical pins that they stay that
// way.
//
// Keys are asserted against dropReasonTotals by
// TestB3CriticalReasonKeysArePublishedReasons: a key the tracker does not
// publish could never carry a rate, and its condition could never fire.
const (
	reasonClientOwnershipMismatch = "client_mismatch"
	reasonReturnOwnershipMismatch = "return_mismatch"
	reasonReturnInjectionErrors   = "return_injection_errors"
	reasonClientBackendQueueFull  = "client_backend_queue_full"
	reasonReturnQueueFull         = "return_queue_full"
)

var criticalLossReasons = map[string]lossClaim{
	reasonClientOwnershipMismatch: claimRouting,
	reasonReturnOwnershipMismatch: claimRouting,
	reasonReturnInjectionErrors:   claimDrops,
}

// criticalReasonRatePps sums the current-window rate of every critical reason
// owned by the given evaluator, out of drops.
//
// It returns zero when rates are unavailable: the reason tracker publishes
// zeros for an interval it has not measured yet, so summing them would be
// summing unknowns. Callers that emit a condition must gate on RatesAvailable
// themselves, because a zero here is indistinguishable from "measured and
// quiet".
func criticalReasonRatePps(drops DropCategoryBreakdown, claim lossClaim) float64 {
	if !drops.RatesAvailable {
		return 0
	}
	total := 0.0
	for key, owner := range criticalLossReasons {
		if owner == claim {
			total += drops.ReasonRates[key]
		}
	}
	return total
}

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
