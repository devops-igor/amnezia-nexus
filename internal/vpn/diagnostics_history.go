package vpn

import (
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
	// reasonBackendDeviceUnattributed is the directionless loss key for a
	// backend device that does not implement backendDeviceStatsProvider: the
	// loader can measure the loss but attribute neither direction nor reason.
	// It is deliberately NOT prefixed client_: the device reports no
	// direction, so the loss counts toward TotalDrops but toward NEITHER
	// directional total (issue #429 review round 3, blocker 3). Its DEGRADED
	// condition is the operator-facing "drops are active but detailed
	// attribution is unavailable" signal (issue #424 review round 10,
	// item 2).
	reasonBackendDeviceUnattributed = "backend_device_unattributed"
)

// vpnDiagConditionBackendDeviceUnattributed is the translation key of the
// unattributed-attribution condition's message in web/translations/*.json.
// It lives here, next to the reason keys, so the Go emitter and the five
// locale files cannot drift apart silently: the key the evaluator publishes
// in HealthCondition.MessageKey is exactly the key every locale must define
// (pinned by TestVPNDiagnosticsLocalizationDictionaries on the web side and
// TestBackendDeviceUnattributedHealthCondition* here).
const vpnDiagConditionBackendDeviceUnattributed = "vpn_diag_condition_backend_device_unattributed"

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

// degradedLossReasons declares, in ONE place, every reason the health
// evaluator classifies at DEGRADED severity by identity rather than by
// aggregate volume, and which evaluator owns each (finding B3, issue #424).
//
// Just like criticalLossReasons, this map is the single source for both the
// reason-specific condition emitted and the subtraction from the routine
// population that keeps the same loss out of the generic aggregate.
//
// Queue-loss populations audit (#424):
//   - client_backend_queue_full: owned by THIS evaluator (claimDrops). A full
//     backend queue refusing client packets is client-traffic starvation;
//     its current rate degrades health directly.
//   - return_queue_full: owned by the return queue pressure evaluator
//     (QueuePressureDiagnostics.QueueDropRatePps > th.QueueActiveDropRatePPS),
//     not claimed as a reason-keyed drop here.
//   - client_backend_device_queue_full / return_backend_device_queue_full:
//     device-level capacity drops attributed to the general routine population.
//   - backend_device_unattributed: owned by THIS evaluator (claimDrops), as
//     of the R5-refinement (direction-neutral key as of review round 3,
//     blocker 3). Living in this map is what subtracts the directionless
//     device loss from the routine population — one-loss-one-condition is
//     preserved — and what lets the evaluator report "attribution
//     unavailable" by reason instead of folding the loss back into the
//     generic aggregate the review called not actionable.
var degradedLossReasons = map[string]lossClaim{
	reasonClientBackendQueueFull:    claimDrops,
	reasonBackendDeviceUnattributed: claimDrops,
}

// degradedReasonRatePps sums the current-window rate of every degraded reason
// owned by the given evaluator, out of drops.
//
// It returns zero when rates are unavailable, matching criticalReasonRatePps.
func degradedReasonRatePps(drops DropCategoryBreakdown, claim lossClaim) float64 {
	if !drops.RatesAvailable {
		return 0
	}
	total := 0.0
	for key, owner := range degradedLossReasons {
		if owner == claim {
			total += drops.ReasonRates[key]
		}
	}
	return total
}

// knownDropReasonKeys is the fixed set of drop category keys published by dropReasonTotals.
// Using a static slice avoids heap allocations during history point cloning.
var knownDropReasonKeys = []string{
	"client_malformed",
	"client_unmapped_source",
	"client_mismatch",
	"client_rejected",
	"client_backend_queue_full",
	"client_rate_limited",
	"client_no_healthy_backend",
	"client_virtualtun_drops",
	"client_backend_device_queue_full",
	"client_backend_device_oversized",
	"client_backend_device_shutdown",
	"client_backend_device_external",
	"backend_device_unattributed",
	"return_malformed",
	"return_unmapped",
	"return_mismatch",
	"return_injection_errors",
	"return_virtualtun_drops",
	"return_queue_full",
	"return_packet_too_large",
	"return_backend_device_queue_full",
	"return_backend_device_shutdown",
}

// The disjoint reasons use exactly the counter keys in drop_categories.
// return_injection_tun_drops describes overlap, not an additional loss reason.
func dropReasonTotals(d DropCategoryBreakdown) map[string]uint64 {
	return map[string]uint64{
		"client_malformed": d.ClientMalformed, "client_unmapped_source": d.ClientUnmappedSource,
		"client_mismatch": d.ClientMismatch, "client_rejected": d.ClientRejected,
		"client_backend_queue_full": d.ClientBackendQueueFull, "client_rate_limited": d.ClientRateLimited,
		"client_no_healthy_backend": d.ClientNoHealthyBackend, "client_virtualtun_drops": d.ClientVirtualTUNDrops,
		"client_backend_device_queue_full": d.ClientBackendDeviceQueueFull,
		"client_backend_device_oversized":  d.ClientBackendDeviceOversized,
		"client_backend_device_shutdown":   d.ClientBackendDeviceShutdown,
		"client_backend_device_external":   d.ClientBackendDeviceExternal,
		"backend_device_unattributed":      d.BackendDeviceUnattributed,
		"return_malformed":                 d.ReturnMalformed, "return_unmapped": d.ReturnUnmapped, "return_mismatch": d.ReturnMismatch,
		"return_injection_errors": d.ReturnInjectionErrors, "return_virtualtun_drops": d.ReturnVirtualTUNDrops,
		"return_queue_full": d.ReturnQueueFull, "return_packet_too_large": d.ReturnPacketTooLarge,
		"return_backend_device_queue_full": d.ReturnBackendDeviceQueueFull,
		"return_backend_device_shutdown":   d.ReturnBackendDeviceShutdown,
	}
}

// dropReasonRatesTracker samples per-reason drop totals against independent
// per-reason generation-aware windows (issue #429 review blocker 1): within a
// generation an accepted per-reason baseline is monotonic — a stale LOWER
// total reports a zero rate and never replaces the baseline — and a lifecycle
// reset re-primes instead of inferring a restart from totals that moved
// backwards. The generation travels with the observation (issue #429 review
// round 4, blocker 1): sample takes it explicitly, so a snapshot captured
// before a lifecycle reset can never touch the new generation's windows.
type dropReasonRatesTracker struct {
	mu        sync.Mutex
	windows   *diagCounterWindows
	available bool
	lastRates map[string]float64
}

func (t *dropReasonRatesTracker) sample(gen diagGeneration, now time.Time, totals map[string]uint64) (map[string]float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.windows == nil {
		t.windows = newDiagCounterWindows()
	}
	if accepted := t.windows.sample(gen, now, totals); accepted {
		t.available = true
	}
	rates := make(map[string]float64, len(totals))
	for key := range totals {
		if rate, ok := t.windows.rate(key); ok {
			rates[key] = rate
		} else {
			rates[key] = 0
		}
	}
	if t.available {
		t.lastRates = make(map[string]float64, len(rates))
		for key, rate := range rates {
			t.lastRates[key] = rate
		}
	}
	return rates, t.available
}

// retained returns the previously accepted reason rates snapshot when an observation
// is rejected as stale by the aggregate sampler, preventing individual reason windows
// from advancing independently and fabricating routine loss (issue #457 Rework Round 7).
func (t *dropReasonRatesTracker) retained(totals map[string]uint64) (map[string]float64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rates := make(map[string]float64, len(totals))
	for key := range totals {
		rates[key] = 0
	}
	if t.available && t.lastRates != nil {
		for key, rate := range t.lastRates {
			rates[key] = rate
		}
	}
	return rates, t.available
}

// reset re-primes the per-reason windows for a new diagnostics generation:
// subsequent samples are tagged with the generation their snapshot captured,
// and the windows re-prime on their next call (issue #429 review blocker 1).
func (t *dropReasonRatesTracker) reset(gen diagGeneration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.windows != nil {
		if !t.windows.reset(gen) {
			return
		}
	}
	t.available = false
	t.lastRates = nil
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
		finite := make(map[string]float64, len(knownDropReasonKeys))
		for _, key := range knownDropReasonKeys {
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

// sampleDropRates publishes aggregate and reason rates as one coherent operation
// (issue #457 Rework Round 7). The existing diagnostics lock prevents concurrent
// status/history callers from returning rates from different intervals; all trackers
// use the same clock. The generation travels with the observation (issue #429 review
// round 4, blocker 1): gen is the generation the drop counters were captured under,
// never read back from the trackers.
//
// Both aggregate rates and reason rates derive from the SAME accepted loss window:
// if s.diagRates rejects the observation as stale or throttled (!accepted), reason
// rates retain their previously accepted snapshot rather than letting individual
// keys advance independently to a quiet 0 PPS window.
func (s *Service) sampleDropRates(gen diagGeneration, at time.Time, drops *DropCategoryBreakdown, writeErrors uint64) float64 {
	s.diagRatesMu.Lock()
	defer s.diagRatesMu.Unlock()
	if s.diagRates == nil {
		s.diagRates = newDiagRatesTracker()
	}
	wasPrimed := s.diagRates.isPrimed()
	var writeErrorRate float64
	var accepted bool
	drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.TotalDropRatePps, writeErrorRate, accepted = s.diagRates.SampleWithAcceptance(
		gen, at, drops.ClientTotalDrops, drops.ReturnTotalDrops, drops.TotalDrops, writeErrors,
	)
	if !wasPrimed || accepted {
		drops.ReasonRates, drops.RatesAvailable = s.diagDeltas.reasons.sample(gen, at, dropReasonTotals(*drops))
	} else {
		drops.ReasonRates, drops.RatesAvailable = s.diagDeltas.reasons.retained(dropReasonTotals(*drops))
	}
	return writeErrorRate
}

// sampleHistoryDropRates calculates drop rates for history against independent
// history baselines, ensuring foreground status reads cannot consume deltas.
// Gated on coherent acceptance (issue #457 Rework Round 7).
func (s *Service) sampleHistoryDropRates(gen diagGeneration, at time.Time, drops *DropCategoryBreakdown) {
	s.diagRatesMu.Lock()
	defer s.diagRatesMu.Unlock()
	if s.historyDiagRates == nil {
		s.historyDiagRates = newDiagRatesTracker()
	}
	wasPrimed := s.historyDiagRates.isPrimed()
	var accepted bool
	drops.ClientDropRatePps, drops.ReturnDropRatePps, drops.TotalDropRatePps, _, accepted = s.historyDiagRates.SampleWithAcceptance(
		gen, at, drops.ClientTotalDrops, drops.ReturnTotalDrops, drops.TotalDrops, 0,
	)
	if !wasPrimed || accepted {
		drops.ReasonRates, drops.RatesAvailable = s.historyDropReasons.sample(gen, at, dropReasonTotals(*drops))
	} else {
		drops.ReasonRates, drops.RatesAvailable = s.historyDropReasons.retained(dropReasonTotals(*drops))
	}
}

func (s *Service) primeHistoryRatesLocked(gen diagGeneration, at time.Time, drops *DropCategoryBreakdown) {
	if s.historyDiagRates == nil {
		s.historyDiagRates = newDiagRatesTracker()
	}
	s.historyDiagRates.Sample(gen, at, drops.ClientTotalDrops, drops.ReturnTotalDrops, drops.TotalDrops, 0)
	s.historyDropReasons.sample(gen, at, dropReasonTotals(*drops))
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

	buf1m  *ringBuffer // 10s intervals -> 6 points (1 minute)
	buf5m  *ringBuffer // 10s intervals -> 30 points (5 minutes)
	buf15m *ringBuffer // 10s intervals -> 90 points (15 minutes)
	buf1h  *ringBuffer // 1m intervals -> 60 points (1 hour)
	buf6h  *ringBuffer // 5m intervals -> 72 points (6 hours)
	buf24h *ringBuffer // 15m intervals -> 96 points (24 hours)

	last1hTime  time.Time
	last6hTime  time.Time
	last24hTime time.Time
}

// NewRollingHistory constructs a new rolling history buffer.
func NewRollingHistory() *RollingHistory {
	return &RollingHistory{
		buf1m:  newRingBuffer(6),
		buf5m:  newRingBuffer(30),
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
	if rh.buf1m != nil {
		rh.buf1m.add(p)
	}
	if rh.buf5m != nil {
		rh.buf5m.add(p)
	}
	if rh.buf15m != nil {
		rh.buf15m.add(p)
	}

	if rh.buf1h != nil && (rh.last1hTime.IsZero() || now.Sub(rh.last1hTime) >= 1*time.Minute) {
		rh.buf1h.add(p)
		rh.last1hTime = now
	}
	if rh.buf6h != nil && (rh.last6hTime.IsZero() || now.Sub(rh.last6hTime) >= 5*time.Minute) {
		rh.buf6h.add(p)
		rh.last6hTime = now
	}
	if rh.buf24h != nil && (rh.last24hTime.IsZero() || now.Sub(rh.last24hTime) >= 15*time.Minute) {
		rh.buf24h.add(p)
		rh.last24hTime = now
	}
}

// Snapshot returns a copy of all 6 rolling windows.
func (rh *RollingHistory) Snapshot() HistoricalSeries {
	if rh == nil {
		return HistoricalSeries{
			Window1m:  []HistoryPoint{},
			Window5m:  []HistoryPoint{},
			Window15m: []HistoryPoint{},
			Window1h:  []HistoryPoint{},
			Window6h:  []HistoryPoint{},
			Window24h: []HistoryPoint{},
		}
	}
	rh.mu.RLock()
	defer rh.mu.RUnlock()

	var w1m, w5m, w15m, w1h, w6h, w24h []HistoryPoint
	if rh.buf1m != nil {
		w1m = rh.buf1m.snapshot()
	} else {
		w1m = []HistoryPoint{}
	}
	if rh.buf5m != nil {
		w5m = rh.buf5m.snapshot()
	} else {
		w5m = []HistoryPoint{}
	}
	if rh.buf15m != nil {
		w15m = rh.buf15m.snapshot()
	} else {
		w15m = []HistoryPoint{}
	}
	if rh.buf1h != nil {
		w1h = rh.buf1h.snapshot()
	} else {
		w1h = []HistoryPoint{}
	}
	if rh.buf6h != nil {
		w6h = rh.buf6h.snapshot()
	} else {
		w6h = []HistoryPoint{}
	}
	if rh.buf24h != nil {
		w24h = rh.buf24h.snapshot()
	} else {
		w24h = []HistoryPoint{}
	}

	return HistoricalSeries{
		Window1m:  w1m,
		Window5m:  w5m,
		Window15m: w15m,
		Window1h:  w1h,
		Window6h:  w6h,
		Window24h: w24h,
	}
}
