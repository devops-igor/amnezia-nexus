package forwarder

import (
	"math"
	"sync"
	"time"
)

// TrafficRates captures instantaneous and moving-average throughput and packet rates.
type TrafficRates struct {
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
// Standalone RateTracker snapshots retain descriptive interpolated estimates;
// those estimates must not drive sustained-pressure health.
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

// RateTracker computes rates and exponential moving averages over time.
type RateTracker struct {
	mu sync.Mutex

	lastSampleTime time.Time
	lastRxBytes    int64
	lastTxBytes    int64
	lastRxPackets  uint64
	lastTxPackets  uint64
	lastTotalDrops uint64
	lastQueueDrops uint64

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

	// Saturation accounting. The durations are accumulated in float seconds
	// because a single accepted sample can be credited only a FRACTION of its
	// interval (see creditAbove). They are rounded once, on read.
	totalSecondsAbove50       float64
	totalSecondsAbove80       float64
	consecutiveSecondsAbove50 float64
	consecutiveSecondsAbove80 float64

	// lastUtilization is the utilization observed at the previous accepted
	// sample. It is the STARTING point of the interval being accounted, so a
	// threshold crossing can be placed inside the interval instead of assuming
	// the whole interval looked like its ending snapshot.
	lastUtilization float64
	// lastUtilizationKnown is false until one real occupancy reading has been
	// accepted, so the first accounted interval is never interpolated from an
	// invented starting point.
	lastUtilizationKnown bool
}

// NewRateTracker constructs a new RateTracker initialized to the current time.
func NewRateTracker() *RateTracker {
	return &RateTracker{}
}

// Sample updates rate and pressure tracking using the latest cumulative counters.
func (rt *RateTracker) Sample(now time.Time, rxBytes, txBytes int64, rxPackets, txPackets, totalDrops, queueDrops uint64, occupancy, capacity int) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.lastSampleTime.IsZero() {
		rt.lastSampleTime = now
		rt.lastRxBytes = rxBytes
		rt.lastTxBytes = txBytes
		rt.lastRxPackets = rxPackets
		rt.lastTxPackets = txPackets
		rt.lastTotalDrops = totalDrops
		rt.lastQueueDrops = queueDrops
		// The priming sample carries a REAL occupancy reading, so it is a
		// legitimate starting point for the first accounted interval. Recording
		// it prevents the first interval from being interpolated from an invented
		// zero occupancy (issue #424 round 8, finding 3).
		rt.lastUtilizationKnown = capacity > 0
		if capacity > 0 {
			rt.lastUtilization = float64(occupancy) / float64(capacity)
		}
		return
	}

	elapsed := now.Sub(rt.lastSampleTime).Seconds()
	if elapsed < 0.2 { // throttle sub-second sampling calls
		return
	}
	rt.lastSampleTime = now

	// Calculate deltas safely
	deltaRxBytes := rxBytes - rt.lastRxBytes
	if deltaRxBytes < 0 {
		deltaRxBytes = 0
	}
	deltaTxBytes := txBytes - rt.lastTxBytes
	if deltaTxBytes < 0 {
		deltaTxBytes = 0
	}

	deltaRxPackets := uint64(0)
	if rxPackets >= rt.lastRxPackets {
		deltaRxPackets = rxPackets - rt.lastRxPackets
	}
	deltaTxPackets := uint64(0)
	if txPackets >= rt.lastTxPackets {
		deltaTxPackets = txPackets - rt.lastTxPackets
	}
	deltaDrops := uint64(0)
	if totalDrops >= rt.lastTotalDrops {
		deltaDrops = totalDrops - rt.lastTotalDrops
	}
	deltaQueueDrops := uint64(0)
	if queueDrops >= rt.lastQueueDrops {
		deltaQueueDrops = queueDrops - rt.lastQueueDrops
	}

	rt.lastRxBytes = rxBytes
	rt.lastTxBytes = txBytes
	rt.lastRxPackets = rxPackets
	rt.lastTxPackets = txPackets
	rt.lastTotalDrops = totalDrops
	rt.lastQueueDrops = queueDrops

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

	// Queue pressure duration tracking.
	//
	// Occupancy is only known at the two ENDS of the interval, so the interval
	// is accounted under an explicit linear-interpolation assumption instead of
	// being backfilled wholesale from the ending reading. Utilization is
	// modeled as moving linearly from the previous accepted reading to this
	// one, and the seconds above a threshold are the exact fraction of the
	// interval for which that model is at or above the threshold. This is a
	// SAMPLED AND INTERPOLATED estimate, not continuous measurement: a brief
	// spike that begins and ends between two samples is invisible to it, and a
	// genuine excursion that starts and ends between two samples is
	// under-counted. It can also over-count if the queue drains between accepted
	// readings. Forwarder.QueuePressure replaces these descriptive estimates
	// with measured queue-transition dwell before any health evaluation.
	util := float64(0)
	if capacity > 0 {
		util = float64(occupancy) / float64(capacity)
	}

	elapsedSec := elapsed
	prevUtil := rt.lastUtilization
	if !rt.lastUtilizationKnown {
		// No observed starting point: assume the queue started this interval
		// empty rather than inventing a reading.
		prevUtil = 0
	}
	rt.lastUtilization = util
	rt.lastUtilizationKnown = capacity > 0

	if capacity > 0 {
		above50 := creditAbove(prevUtil, util, 0.50, elapsedSec)
		above80 := creditAbove(prevUtil, util, 0.80, elapsedSec)
		rt.totalSecondsAbove50 += above50
		rt.totalSecondsAbove80 += above80
		// Consecutive time is measured to the CURRENT reading only: if the
		// queue is below the threshold now, the run is over, whatever the model
		// says about earlier in the interval.
		if util >= 0.50 {
			rt.consecutiveSecondsAbove50 += above50
		} else {
			rt.consecutiveSecondsAbove50 = 0
		}
		if util >= 0.80 {
			rt.consecutiveSecondsAbove80 += above80
		} else {
			rt.consecutiveSecondsAbove80 = 0
		}
	} else {
		rt.consecutiveSecondsAbove50 = 0
		rt.consecutiveSecondsAbove80 = 0
		rt.lastUtilizationKnown = false
	}
}

// creditAbove returns the seconds of an interval during which utilization,
// assumed to move LINEARLY from prev to cur over the interval, was at or above
// threshold. Both endpoints below threshold yields zero, both at or above
// yields the whole interval, and a single crossing in between yields the
// fraction of the interval that lies on the at-or-above side.
func creditAbove(prev, cur, threshold, elapsedSec float64) float64 {
	if elapsedSec <= 0 {
		return 0
	}
	switch {
	case prev >= threshold && cur >= threshold:
		return elapsedSec
	case prev < threshold && cur < threshold:
		return 0
	case prev < threshold: // rising through the threshold
		if cur <= prev {
			return 0
		}
		return elapsedSec * (cur - threshold) / (cur - prev)
	default: // falling through the threshold
		if prev <= cur {
			return 0
		}
		return elapsedSec * (prev - threshold) / (prev - cur)
	}
}

// Snapshot returns point-in-time traffic rates.
func (rt *RateTracker) Snapshot(rxPackets, txPackets uint64) TrafficRates {
	if rt == nil {
		return TrafficRates{TotalRxPackets: rxPackets, TotalTxPackets: txPackets}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	return TrafficRates{
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

// PressureSnapshot returns sampled queue-pressure context. Its interpolated
// durations are descriptive only; Forwarder.QueuePressure supplies measured
// transition dwell for the runtime diagnostics and sustained-health decision.
func (rt *RateTracker) PressureSnapshot(occupancy, capacity, highWater int, queueDrops uint64) QueuePressureStats {
	if rt == nil {
		var utilPct, hwPct float64
		if capacity > 0 {
			utilPct = (float64(occupancy) / float64(capacity)) * 100.0
			hwPct = (float64(highWater) / float64(capacity)) * 100.0
		}
		return QueuePressureStats{
			Occupancy:      occupancy,
			Capacity:       capacity,
			UtilizationPct: utilPct,
			HighWater:      highWater,
			HighWaterPct:   hwPct,
			QueueFullDrops: queueDrops,
		}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var utilPct, hwPct float64
	if capacity > 0 {
		utilPct = (float64(occupancy) / float64(capacity)) * 100.0
		hwPct = (float64(highWater) / float64(capacity)) * 100.0
	}

	return QueuePressureStats{
		Occupancy:             occupancy,
		Capacity:              capacity,
		UtilizationPct:        utilPct,
		HighWater:             highWater,
		HighWaterPct:          hwPct,
		SecondsAbove50Pct:     roundedSeconds(rt.totalSecondsAbove50),
		SecondsAbove80Pct:     roundedSeconds(rt.totalSecondsAbove80),
		ConsecutiveAbove50Sec: roundedSeconds(rt.consecutiveSecondsAbove50),
		ConsecutiveAbove80Sec: roundedSeconds(rt.consecutiveSecondsAbove80),
		QueueFullDrops:        queueDrops,
		QueueFullDropRate:     rt.queueDropRate,
	}
}

// roundedSeconds converts an accumulated fractional duration to whole seconds.
// It never returns a negative value, and it never rounds a value that is at
// least one full second down to zero.
func roundedSeconds(v float64) int64 {
	if v <= 0 {
		return 0
	}
	return int64(math.Round(v))
}
