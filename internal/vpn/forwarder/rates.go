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

	totalSecondsAbove50       int64
	totalSecondsAbove80       int64
	consecutiveSecondsAbove50 int64
	consecutiveSecondsAbove80 int64
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

	// Queue pressure duration tracking
	elapsedSec := int64(math.Round(elapsed))
	if elapsedSec < 1 {
		elapsedSec = 1
	}
	if capacity > 0 {
		util := float64(occupancy) / float64(capacity)
		if util >= 0.50 {
			rt.totalSecondsAbove50 += elapsedSec
			rt.consecutiveSecondsAbove50 += elapsedSec
		} else {
			rt.consecutiveSecondsAbove50 = 0
		}
		if util >= 0.80 {
			rt.totalSecondsAbove80 += elapsedSec
			rt.consecutiveSecondsAbove80 += elapsedSec
		} else {
			rt.consecutiveSecondsAbove80 = 0
		}
	} else {
		rt.consecutiveSecondsAbove50 = 0
		rt.consecutiveSecondsAbove80 = 0
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

// PressureSnapshot returns current queue pressure indicators.
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
		SecondsAbove50Pct:     rt.totalSecondsAbove50,
		SecondsAbove80Pct:     rt.totalSecondsAbove80,
		ConsecutiveAbove50Sec: rt.consecutiveSecondsAbove50,
		ConsecutiveAbove80Sec: rt.consecutiveSecondsAbove80,
		QueueFullDrops:        queueDrops,
		QueueFullDropRate:     rt.queueDropRate,
	}
}
