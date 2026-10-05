package forwarder

import (
	"math"
	"sync"
	"time"
)

// TrafficRates captures instantaneous and moving-average throughput and packet rates.
type TrafficRates struct {
	Available      bool    `json:"available"`
	RxBps          float64 `json:"rx_bps"`
	TxBps          float64 `json:"tx_bps"`
	RxPps          float64 `json:"rx_pps"`
	TxPps          float64 `json:"tx_pps"`
	DropRatePps    float64 `json:"drop_rate_pps"`
	RxBpsAvg5m     float64 `json:"rx_bps_avg_5m"`
	TxBpsAvg5m     float64 `json:"tx_bps_avg_5m"`
	RxBpsAvg1h     float64 `json:"rx_bps_avg_1h"`
	TxBpsAvg1h     float64 `json:"tx_bps_avg_1h"`
	TotalRxPackets uint64  `json:"total_rx_packets"`
	TotalTxPackets uint64  `json:"total_tx_packets"`
}

// QueuePressureStats captures queue occupancy pressure duration and rates.
//
// Forwarder.QueuePressure fills the duration fields from serialized occupancy
// transitions, in whole completed seconds. Legacy direct channel drains reset
// an unobserved run during reconciliation rather than inventing a drain time.
type QueuePressureStats struct {
	Occupancy             int     `json:"occupancy"`
	Capacity              int     `json:"capacity"`
	UtilizationPct        float64 `json:"utilization_pct"`
	HighWater             int     `json:"high_water"`
	HighWaterPct          float64 `json:"high_water_pct"`
	SecondsAbove50Pct     int64   `json:"seconds_above_50_pct"`
	SecondsAbove80Pct     int64   `json:"seconds_above_80_pct"`
	ConsecutiveAbove50Sec int64   `json:"consecutive_above_50_sec"`
	ConsecutiveAbove80Sec int64   `json:"consecutive_above_80_sec"`
	QueueFullDrops        uint64  `json:"queue_full_drops"`
	QueueFullDropRate     float64 `json:"queue_full_drop_rate"`
}

// rateTrackerSampleInterval is the minimum spacing between two accepted Rate
// samples. It matches the 200ms floor the diagnostics trackers use.
const rateTrackerSampleInterval = GenerationSampleMinInterval

// RateTracker computes rates and exponential moving averages over time.
//
// Its baselines are generation-aware and monotonic (GenerationSampler): a
// stale lower observation reports zero and never rewinds a baseline, and
// Reset(generation) on a forwarder restart re-primes instead of inferring the
// restart from counters that moved backwards.
type RateTracker struct {
	mu      sync.Mutex
	sampler *GenerationSampler
	// gen is the generation subsequent samples are tagged with. It is
	// adopted from Reset so a forwarder restart's samples land in the new
	// generation instead of being rejected as stale forever (issue #429
	// review blocker 1).
	gen       Generation
	available bool

	currentRxBps   float64
	currentTxBps   float64
	currentRxPps   float64
	currentTxPps   float64
	currentDropPps float64
	queueDropRate  float64

	ewmaRxBps5m float64
	ewmaTxBps5m float64
	ewmaRxBps1h float64
	ewmaTxBps1h float64
}

// NewRateTracker constructs a new RateTracker with unprimed counter baselines.
func NewRateTracker() *RateTracker {
	return &RateTracker{sampler: NewGenerationSampler(6)}
}

// Reset starts a new generation: baselines are cleared so the next sample
// re-primes, and measured rates/availability return to unknown. A generation
// lower than the accepted one is ignored.
func (rt *RateTracker) Reset(gen Generation) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if gen > rt.gen {
		rt.gen = gen
	}
	rt.sampler.Reset(rt.gen)
	rt.available = false
	rt.currentRxBps, rt.currentTxBps = 0, 0
	rt.currentRxPps, rt.currentTxPps = 0, 0
	rt.currentDropPps, rt.queueDropRate = 0, 0
	rt.ewmaRxBps5m, rt.ewmaTxBps5m = 0, 0
	rt.ewmaRxBps1h, rt.ewmaTxBps1h = 0, 0
}

// Sample updates rate tracking using the latest cumulative counters.
//
// rxBytes/txBytes are signed lifetimes. A byte counter that moved backwards
// (generation restart) reports zero for that direction and keeps its accepted
// baseline, so the pre-window value cannot be replayed later.
func (rt *RateTracker) Sample(now time.Time, rxBytes, txBytes int64, rxPackets, txPackets, totalDrops, queueDrops uint64) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Sign-extended into the unsigned domain a byte counter cannot wrap into:
	// a restarting counter only ever travels DOWN from 2^64-k, which compares
	// lower than any real cumulative total, so the monotonic guard reports it
	// as zero delta instead of a two-complement overflow burst.
	rxU := uint64(rxBytes)
	txU := uint64(txBytes)
	deltas, elapsed, accepted := rt.sampler.Sample(rt.gen, now, rateTrackerSampleInterval,
		[]uint64{rxU, txU, rxPackets, txPackets, totalDrops, queueDrops})
	if !accepted {
		return
	}

	deltaRxBytes := deltas[0]
	deltaTxBytes := deltas[1]
	deltaRxPackets := deltas[2]
	deltaTxPackets := deltas[3]
	deltaDrops := deltas[4]
	deltaQueueDrops := deltas[5]

	rt.available = true
	rt.currentRxBps = float64(deltaRxBytes*8) / elapsed
	rt.currentTxBps = float64(deltaTxBytes*8) / elapsed
	rt.currentRxPps = float64(deltaRxPackets) / elapsed
	rt.currentTxPps = float64(deltaTxPackets) / elapsed
	rt.currentDropPps = float64(deltaDrops) / elapsed
	rt.queueDropRate = float64(deltaQueueDrops) / elapsed

	// EWMA with decay factor: alpha = 1 - exp(-elapsed / tau)
	alpha5m := 1.0 - math.Exp(-elapsed/300.0)
	if alpha5m > 1.0 {
		alpha5m = 1.0
	}
	rt.ewmaRxBps5m = alpha5m*rt.currentRxBps + (1.0-alpha5m)*rt.ewmaRxBps5m
	rt.ewmaTxBps5m = alpha5m*rt.currentTxBps + (1.0-alpha5m)*rt.ewmaTxBps5m

	alpha1h := 1.0 - math.Exp(-elapsed/3600.0)
	if alpha1h > 1.0 {
		alpha1h = 1.0
	}
	rt.ewmaRxBps1h = alpha1h*rt.currentRxBps + (1.0-alpha1h)*rt.ewmaRxBps1h
	rt.ewmaTxBps1h = alpha1h*rt.currentTxBps + (1.0-alpha1h)*rt.ewmaTxBps1h
}

// Snapshot returns point-in-time traffic rates.
func (rt *RateTracker) Snapshot(rxPackets, txPackets uint64) TrafficRates {
	if rt == nil {
		return TrafficRates{TotalRxPackets: rxPackets, TotalTxPackets: txPackets}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	return TrafficRates{
		Available:      rt.available,
		RxBps:          rt.currentRxBps,
		TxBps:          rt.currentTxBps,
		RxPps:          rt.currentRxPps,
		TxPps:          rt.currentTxPps,
		DropRatePps:    rt.currentDropPps,
		RxBpsAvg5m:     rt.ewmaRxBps5m,
		TxBpsAvg5m:     rt.ewmaTxBps5m,
		RxBpsAvg1h:     rt.ewmaRxBps1h,
		TxBpsAvg1h:     rt.ewmaTxBps1h,
		TotalRxPackets: rxPackets,
		TotalTxPackets: txPackets,
	}
}

// PressureSnapshot reports current queue gauges and the sampled refusal rate.
// Only Forwarder.QueuePressure adds durations from actual occupancy transitions.
func (rt *RateTracker) PressureSnapshot(occupancy, capacity, highWater int, queueDrops uint64) QueuePressureStats {
	var utilPct, hwPct, rate float64
	if capacity > 0 {
		utilPct = float64(occupancy) / float64(capacity) * 100
		hwPct = float64(highWater) / float64(capacity) * 100
	}
	if rt != nil {
		rt.mu.Lock()
		rate = rt.queueDropRate
		rt.mu.Unlock()
	}
	return QueuePressureStats{
		Occupancy: occupancy, Capacity: capacity,
		UtilizationPct: utilPct, HighWater: highWater, HighWaterPct: hwPct,
		QueueFullDrops: queueDrops, QueueFullDropRate: rate,
	}
}
