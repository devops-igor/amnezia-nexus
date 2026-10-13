package vpn

import (
	"sort"
	"sync"
	"time"

	"github.com/devops-igor/amnezia-nexus/internal/vpn/forwarder"
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

// cloneReasonRates returns a detached copy of published reason rates, guaranteeing
// every known reason key is present and caller mutations never corrupt tracker state.
func cloneReasonRates(rates map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(knownDropReasonKeys)+len(rates))
	for _, k := range knownDropReasonKeys {
		out[k] = 0
	}
	for k, v := range rates {
		out[k] = v
	}
	return out
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
// under whole-vector acceptance (issue #457 Rework Round 8). The existing diagnostics
// lock prevents concurrent status/history callers from returning rates from different
// intervals; all trackers use the same clock. The generation travels with the observation
// (issue #429 review round 4, blocker 1): gen is the generation the drop counters were
// captured under, never read back from the trackers.
func (s *Service) sampleDropRates(gen diagGeneration, at time.Time, drops *DropCategoryBreakdown, writeErrors uint64) float64 {
	s.diagRatesMu.Lock()
	defer s.diagRatesMu.Unlock()
	if s.diagRates == nil {
		s.diagRates = newDiagRatesTracker()
	}
	writeErrorRate, _ := s.diagRates.SampleLossVector(gen, at, drops, writeErrors)
	return writeErrorRate
}

// sampleHistoryDropRates calculates drop rates for history against independent
// history baselines, ensuring foreground status reads cannot consume deltas.
// Gated on whole-vector acceptance (issue #457 Rework Round 8).
func (s *Service) sampleHistoryDropRates(gen diagGeneration, at time.Time, drops *DropCategoryBreakdown) {
	s.diagRatesMu.Lock()
	defer s.diagRatesMu.Unlock()
	if s.historyDiagRates == nil {
		s.historyDiagRates = newDiagRatesTracker()
	}
	s.historyDiagRates.SampleLossVector(gen, at, drops, 0)
}

func (s *Service) primeHistoryRatesLocked(gen diagGeneration, at time.Time, drops *DropCategoryBreakdown) {
	if s.historyDiagRates == nil {
		s.historyDiagRates = newDiagRatesTracker()
	}
	s.historyDiagRates.SampleLossVector(gen, at, drops, 0)
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
	gen            diagGeneration
	primed         bool
	window         generationWindow[float64]
	lastSampleTime time.Time

	clientDropRate float64
	returnDropRate float64
	totalDropRate  float64
	writeErrorRate float64

	reasonRates    map[string]float64
	ratesAvailable bool
}

// newDiagRatesTracker returns an UNPRIMED tracker. lastSampleTime and every
// counter baseline are captured by the first Sample call, so a counter that has
// been accumulating since process start is never reported as a fresh incident
// (issue #424 round 8, finding 2). Seeding the timestamp here would make the
// priming branch in Sample dead code.
func newDiagRatesTracker() *diagRatesTracker {
	return &diagRatesTracker{}
}

// SampleWithAcceptance records the cumulative drop counters, reports the per-second
// rates of the newly accepted window, and reports whether the observation was accepted
// (issue #457 Rework Round 7). Callers use acceptance to publish aggregate and reason
// loss rates coherently.
func (t *diagRatesTracker) SampleWithAcceptance(gen diagGeneration, now time.Time, clientDrops, returnDrops, totalDrops, writeErrors uint64) (clientDropRate, returnDropRate, totalDropRate, writeErrorRate float64, accepted bool) {
	if t == nil {
		return 0, 0, 0, 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// R7-H2: Old-generation observations are strict no-ops.
	// Do NOT mutate wrapper priming, timestamp, or published rates.
	if gen < t.gen {
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, false
	}

	if t.primed && t.reasonRates != nil {
		// Tracker is established for whole-vector sampling; alternating vector
		// widths must not silently re-prime an established accepted vector.
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, false
	}

	if gen > t.gen || !t.primed {
		// First sample: prime time AND every counter baseline, report zero.
		t.gen = gen
		t.primed = true
		t.lastSampleTime = now
		t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate = 0, 0, 0, 0
		t.window.reset(gen)
		t.window.sample(gen, now, []uint64{clientDrops, returnDrops, totalDrops, writeErrors})
		return 0, 0, 0, 0, false
	}
	if accepted := t.window.sample(gen, now, []uint64{clientDrops, returnDrops, totalDrops, writeErrors}); !accepted {
		return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, false
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

	return t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate, true
}

func (t *diagRatesTracker) publishRetainedLocked(drops *DropCategoryBreakdown) {
	drops.ClientDropRatePps = t.clientDropRate
	drops.ReturnDropRatePps = t.returnDropRate
	drops.TotalDropRatePps = t.totalDropRate
	drops.ReasonRates = cloneReasonRates(t.reasonRates)
	drops.RatesAvailable = t.ratesAvailable
}

// SampleLossVector records the complete loss-counter vector (aggregates and disjoint reasons),
// reports rates computed from the single accepted window, and preserves all parts of the last
// accepted publication together on rejection (issue #457 Rework Round 8, Round 9).
func (t *diagRatesTracker) SampleLossVector(gen diagGeneration, now time.Time, drops *DropCategoryBreakdown, writeErrors uint64) (writeErrorRate float64, accepted bool) {
	if t == nil || drops == nil {
		return 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if gen < t.gen {
		t.publishRetainedLocked(drops)
		return t.writeErrorRate, false
	}

	// Use the existing whole-vector window, not a second acceptance engine.
	totals := dropReasonTotals(*drops)
	values := make([]uint64, 4+len(knownDropReasonKeys))
	values[0], values[1], values[2], values[3] = drops.ClientTotalDrops, drops.ReturnTotalDrops, drops.TotalDrops, writeErrors
	for i, key := range knownDropReasonKeys {
		values[4+i] = totals[key]
	}
	if gen > t.gen || !t.primed || t.reasonRates == nil {
		t.gen, t.primed, t.lastSampleTime = gen, true, now
		t.window.reset(gen)
		t.clientDropRate, t.returnDropRate, t.totalDropRate, t.writeErrorRate = 0, 0, 0, 0
		t.reasonRates = make(map[string]float64, len(totals))
		t.ratesAvailable = false
	}
	if !t.window.sample(gen, now, values) {
		t.publishRetainedLocked(drops)
		return t.writeErrorRate, false
	}

	deltas, elapsed, _ := t.window.last()
	t.lastSampleTime = now
	t.clientDropRate, t.returnDropRate = deltas[0]/elapsed, deltas[1]/elapsed
	t.totalDropRate, t.writeErrorRate = deltas[2]/elapsed, deltas[3]/elapsed
	rates := make(map[string]float64, len(totals))
	for i, key := range knownDropReasonKeys {
		rates[key] = deltas[4+i] / elapsed
	}
	t.reasonRates, t.ratesAvailable = rates, true
	t.publishRetainedLocked(drops)
	return t.writeErrorRate, true
}

// Sample records the cumulative drop counters and reports the per-second rates
// of the newly accepted window. The generation travels with the observation
// (issue #429 review round 4, blocker 1): callers pass the generation the
// snapshot was captured under, never a tracker-current value. Only
// observations >= the accepted baseline advance it; an older/lower observation
// reports the previous window and leaves the baseline unchanged (issue #429
// review blocker 1).
func (t *diagRatesTracker) Sample(gen diagGeneration, now time.Time, clientDrops, returnDrops, totalDrops, writeErrors uint64) (clientDropRate, returnDropRate, totalDropRate, writeErrorRate float64) {
	clientDropRate, returnDropRate, totalDropRate, writeErrorRate, _ = t.SampleWithAcceptance(gen, now, clientDrops, returnDrops, totalDrops, writeErrors)
	return
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
	if gen < t.gen {
		return
	}
	if gen > t.gen {
		t.gen = gen
	}
	if !t.window.reset(gen) {
		return
	}
	t.primed = false
	t.lastSampleTime = time.Time{}
	t.clientDropRate, t.returnDropRate = 0, 0
	t.totalDropRate, t.writeErrorRate = 0, 0
	t.reasonRates = nil
	t.ratesAvailable = false
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

// returnOwnershipSnapshot is an immutable atomic read of the return-direction
// ownership mismatch delta, sampling window, and consecutive high-rate streak
// (issue #457).
type returnOwnershipSnapshot struct {
	deltaSnapshot
	consecutiveHighRateWindows int
}

// returnOwnershipTracker tracks return-direction ownership mismatch drops across
// sampling windows and maintains generation-scoped persistence for sustained
// high-rate detection. A single mutex synchronizes generation gates, window
// baseline tracking, and streak counting to eliminate split-lock races (issue #457).
type returnOwnershipTracker struct {
	mu                     sync.Mutex
	gen                    diagGeneration
	primed                 bool
	window                 generationWindow[uint64]
	delta                  uint64
	windowSeconds          float64
	consecutiveHighWindows int
}

// Sample records cumulative and returns the coherent delta, window length, and
// consecutive high-rate window streak. If the sample belongs to an older generation,
// it is rejected wholesale without mutating baseline, window, or streak.
// Resampling sooner than 200ms returns the previous accepted snapshot.
func (t *returnOwnershipTracker) Sample(gen diagGeneration, now time.Time, cumulative uint64) returnOwnershipSnapshot {
	if t == nil {
		return returnOwnershipSnapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// If sample is from a stale generation, reject it: leave baseline, window,
	// and streak completely untouched and return current published snapshot.
	if gen < t.gen {
		return returnOwnershipSnapshot{
			deltaSnapshot: deltaSnapshot{
				delta:         t.delta,
				windowSeconds: t.windowSeconds,
			},
			consecutiveHighRateWindows: t.consecutiveHighWindows,
		}
	}

	// If advancing to a newer generation or not yet primed: re-prime into gen.
	if gen > t.gen || !t.primed {
		t.gen = gen
		t.primed = true
		t.delta = 0
		t.windowSeconds = 0
		t.consecutiveHighWindows = 0
		// Re-prime the baseline; window.sample always returns false on re-prime.
		t.window.sample(gen, now, []uint64{cumulative})
		return returnOwnershipSnapshot{}
	}

	accepted := t.window.sample(gen, now, []uint64{cumulative})
	if accepted {
		deltas, elapsed, _ := t.window.last()
		t.delta = deltas[0]
		t.windowSeconds = elapsed

		th := defaultHealthThresholds()
		var rate float64
		if t.windowSeconds > 0 {
			rate = float64(t.delta) / t.windowSeconds
		}
		if rate >= th.ReturnOwnershipMismatchDegradedRatePPS {
			t.consecutiveHighWindows++
		} else {
			t.consecutiveHighWindows = 0
		}
	}
	// A throttled (<200ms) or monotonic-stale rejected sample leaves
	// delta, windowSeconds, and consecutiveHighRateWindows untouched.
	return returnOwnershipSnapshot{
		deltaSnapshot: deltaSnapshot{
			delta:         t.delta,
			windowSeconds: t.windowSeconds,
		},
		consecutiveHighRateWindows: t.consecutiveHighWindows,
	}
}

// reset re-primes the tracker for a new diagnostics generation.
// A generation lower than the accepted one is ignored (no-op, leaving published
// delta and consecutive streak untouched).
func (t *returnOwnershipTracker) reset(gen diagGeneration) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.reset(gen) {
		return false
	}
	t.gen = gen
	t.primed = false
	t.delta = 0
	t.windowSeconds = 0
	t.consecutiveHighWindows = 0
	return true
}

func (t *returnOwnershipTracker) consecutiveHighRateWindows() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.consecutiveHighWindows
}

// diagDeltaTrackers groups the per-counter windowed delta trackers. Each has
// its own mutex (both the wrapper state and the embedded window are
// synchronized), so a caller needs no outer lock.
type diagDeltaTrackers struct {
	ownershipMismatch returnOwnershipTracker
	// clientOwnershipMismatch tracks the CLIENT-direction counterpart. It is a
	// separate tracker, not a second field on the return one, because the two
	// counters rise independently: sharing a tracker would let a burst in one
	// direction mask a quiet window in the other, which is the invisibility
	// blocker 3 exists to remove (issue #424 review round 9).
	clientOwnershipMismatch diagDeltaTracker
	syncFailures            diagDeltaTracker
	enqueueFailures         diagDeltaTracker
	writeStalls             diagDeltaTracker
}

func (t *diagDeltaTrackers) sampleOwnershipMismatch(gen diagGeneration, now time.Time, cumulative uint64) returnOwnershipSnapshot {
	if t == nil {
		return returnOwnershipSnapshot{}
	}
	return t.ownershipMismatch.Sample(gen, now, cumulative)
}

func (t *diagDeltaTrackers) consecutiveHighRateWindows() int {
	if t == nil {
		return 0
	}
	return t.ownershipMismatch.consecutiveHighRateWindows()
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
// peer-sync failures, enqueue failures, and write stalls — for a new
// diagnostics generation (issue #429 review blocker 1).
func (t *diagDeltaTrackers) reset(gen diagGeneration) {
	if t == nil {
		return
	}
	t.ownershipMismatch.reset(gen)
	t.clientOwnershipMismatch.reset(gen)
	t.syncFailures.reset(gen)
	t.enqueueFailures.reset(gen)
	t.writeStalls.reset(gen)
}
